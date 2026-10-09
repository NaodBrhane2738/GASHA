"""
==============================================================================
FILE: apps/api/tests/unit/test_investigation_response_api.py
OBJECTIVE: Integration tests for Investigation and Response REST API endpoints.
           Verifies end-to-end operational defense workflow:
           Incident -> Investigation -> Proposal -> Approval -> Execution -> Verification -> Audit.
==============================================================================
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_jwt_token
from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.investigation_repository import get_investigation_repository
from app.db.repositories.response_repository import get_response_repository
from app.response.audit import get_audit_trail
from app.response.enforcement import get_target_security_client


@pytest.fixture(autouse=True)
def reset_all_state():
    get_incident_repository().clear()
    get_detection_repository().clear()
    get_investigation_repository().clear()
    get_response_repository().clear()
    get_audit_trail().clear()
    get_target_security_client().clear_all_enforcements()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    token = create_jwt_token({"sub": "analyst-lead", "environmentId": "env-prod", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def dev_auth_headers():
    token = create_jwt_token({"sub": "dev-user", "environmentId": "env-dev", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def staged_incident():
    inc = IncidentResponse(
        id="inc-api-1",
        title="Web Scanning Reconnaissance",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId="asset:web-service:env-prod",
        relatedAssetIds=[],
        detectionEventIds=["det-api-1"],
        attackPathId=None,
        summary="Automated scan detected.",
        environmentId="env-prod",
        correlationKey="probe:env-prod:198.51.100.22",
        createdAt="2026-10-09T10:00:00Z",
        updatedAt="2026-10-09T10:01:00Z"
    )
    det = DetectionEventResponse(
        id="det-api-1",
        rule=DetectionRuleSummarySchema(
            ruleId="RULE-PROBE-002",
            name="Suspicious Web Request Probe",
            description="Web probe",
            severity="HIGH",
            confidence=0.90
        ),
        matchedEventIds=["evt-api-1"],
        primaryAssetId="asset:web-service:env-prod",
        timestamp="2026-10-09T10:00:30Z",
        severity="HIGH",
        confidence=0.90,
        evidenceSummary="XSS probe from 198.51.100.22",
        environmentId="env-prod",
        metadata={
            "environmentId": "env-prod",
            "sourceIp": "198.51.100.22",
            "targetPath": "/search",
            "patternType": "XSS_PROBE"
        }
    )
    get_incident_repository().save_incident(inc)
    get_detection_repository().save_detection(det)
    return inc


def test_investigation_api_run_and_query(client, auth_headers, staged_incident):
    # 1. Run investigation
    res = client.post(f"/api/v1/investigations/{staged_incident.id}/run", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["incidentId"] == staged_incident.id
    assert len(data["attackStory"]["observedFacts"]) > 0
    assert len(data["recommendations"]) == 1
    assert data["recommendations"][0]["actionType"] == "BLOCK_SOURCE"
    assert data["recommendations"][0]["targetIdentifier"] == "198.51.100.22"

    # 2. Get investigation
    res_get = client.get(f"/api/v1/investigations/{staged_incident.id}", headers=auth_headers)
    assert res_get.status_code == 200
    assert res_get.json()["incidentId"] == staged_incident.id

    # 3. Get timeline
    res_tl = client.get(f"/api/v1/investigations/{staged_incident.id}/timeline", headers=auth_headers)
    assert res_tl.status_code == 200
    tl_data = res_tl.json()
    assert tl_data["incidentId"] == staged_incident.id
    assert tl_data["totalEvents"] > 0


def test_investigation_api_cross_environment_rejection(client, dev_auth_headers, staged_incident):
    # User authorized for env-dev cannot query env-prod incident
    res = client.get(f"/api/v1/investigations/{staged_incident.id}", headers=dev_auth_headers)
    assert res.status_code == 404


def test_complete_response_lifecycle_via_api(client, auth_headers, staged_incident):
    # 1. Propose response
    prop_payload = {
        "incidentId": staged_incident.id,
        "actionType": "BLOCK_SOURCE",
        "targetType": "IP_ADDRESS",
        "targetIdentifier": "198.51.100.22",
        "reason": "Perimeter drop of verified attacker IP"
    }
    res_prop = client.post("/api/v1/responses/propose", json=prop_payload, headers=auth_headers)
    assert res_prop.status_code == 200
    prop_data = res_prop.json()
    assert prop_data["status"] == "PENDING_APPROVAL"
    resp_id = prop_data["id"]

    # 2. List responses
    res_list = client.get(f"/api/v1/responses?incidentId={staged_incident.id}", headers=auth_headers)
    assert res_list.status_code == 200
    assert len(res_list.json()) == 1

    # 3. Approve response
    appr_payload = {"decision": "APPROVE", "comment": "Verified by SOC analyst"}
    res_appr = client.post(f"/api/v1/responses/{resp_id}/approve", json=appr_payload, headers=auth_headers)
    assert res_appr.status_code == 200
    assert res_appr.json()["status"] == "APPROVED"

    # 4. Execute approved response
    res_exec = client.post(f"/api/v1/responses/{resp_id}/execute", headers=auth_headers)
    assert res_exec.status_code == 200
    exec_data = res_exec.json()
    assert exec_data["status"] == "SUCCEEDED"
    assert exec_data["verificationStatus"] == "VERIFIED"

    # 5. Query audit trail
    res_audit = client.get("/api/v1/responses/audit", headers=auth_headers)
    assert res_audit.status_code == 200
    audit_entries = res_audit.json()
    assert len(audit_entries) >= 3  # PROPOSAL_CREATED, PROPOSAL_APPROVED, EXECUTION_SUCCEEDED

    # 6. Verify audit trail cryptographic integrity
    res_verify = client.get("/api/v1/responses/audit/verify", headers=auth_headers)
    assert res_verify.status_code == 200
    assert res_verify.json()["verified"] is True


def test_direct_operational_execution_endpoint(client, auth_headers, staged_incident):
    exec_req = {
        "actionType": "BLOCK_SOURCE",
        "targetType": "IP_ADDRESS",
        "targetIdentifier": "198.51.100.22",
        "incidentId": staged_incident.id,
        "reason": "Immediate analyst containment",
        "requestedBy": "ANALYST_MANUAL"
    }
    # 1. Standard non-emergency admin role is rejected to prevent separation-of-duties bypass
    res_rejected = client.post("/api/v1/responses/execute", json=exec_req, headers=auth_headers)
    assert res_rejected.status_code == 403
    assert "Direct single-step execution is restricted to emergency_admin" in res_rejected.json()["detail"]

    # 2. Emergency break-glass role is authorized for direct execution
    emergency_token = create_jwt_token({"sub": "breakglass-admin", "environmentId": "env-prod", "role": "emergency_admin"})
    emergency_headers = {"Authorization": f"Bearer {emergency_token}"}
    res = client.post("/api/v1/responses/execute", json=exec_req, headers=emergency_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["details"]["verificationStatus"] == "VERIFIED"
    assert data["auditId"] is not None
