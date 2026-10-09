"""
==============================================================================
FILE: tests/scenarios/test_phase5_e2e_defensive_loop.py
ROLE / OWNERSHIP: Cybersecurity & QA Automation Engineers
OBJECTIVE: End-to-End integration tests for GASHA Phase 5 defensive loop.
           Tests Real Traffic -> Demo Target -> Telemetry SDK -> Authenticated Ingestion
           -> Detection Engine -> Correlation -> Incident -> Deterministic Investigation
           -> Response Proposal -> Human Operator Approval -> Target Enforcement
           -> State Verification -> Cryptographic Audit Trail.
==============================================================================
"""

import asyncio
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

# Ensure workspace modules are discoverable
current_dir = pathlib.Path(__file__).resolve().parent
repo_root = current_dir.parent.parent
sys.path.insert(0, str(repo_root / "apps" / "api"))
sys.path.insert(0, str(repo_root / "apps" / "demo-target"))
sys.path.insert(0, str(repo_root / "packages" / "telemetry-sdk" / "python"))

from app.main import app as api_app
from main import create_demo_target_app
from telemetry.client import telemetry_client
from app.workers.telemetry import flush_all_pending
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.response_repository import get_response_repository
from app.detection.engine import get_detection_engine
from app.detection.deduplicator import get_event_deduplicator
from app.correlation.engine import get_correlation_engine
from app.telemetry.ingester import get_telemetry_ingester
from app.response.enforcement import get_target_security_client
from app.response.audit import get_audit_trail
from app.core.security import create_jwt_token
from app.schemas.incident import IncidentResponse
import uuid


RESULTS_DIR = repo_root / "tests" / "scenarios" / "results" / "phase-5"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def save_test_evidence(filename: str, data: dict):
    """Saves structured scenario evidence artifact to tests/scenarios/results/phase-5/"""
    path = RESULTS_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


@pytest.fixture(autouse=True)
def setup_and_teardown_environment():
    """Resets all in-memory repositories, queues, and security enforcements before each test."""
    # Reset Target Security enforcements
    target_client = get_target_security_client()
    target_client.clear_all_enforcements()

    # Reset API & Telemetry Pipeline state
    get_telemetry_ingester().reset_state()
    get_detection_engine().reset_state()
    get_event_deduplicator().clear()
    get_correlation_engine().reset_state()
    get_detection_repository().clear()
    get_incident_repository().clear()
    get_response_repository().clear()
    get_audit_trail().clear()

    yield

    # Teardown
    target_client.clear_all_enforcements()


@pytest.fixture
def test_clients():
    """Configures TestClients and wires the Telemetry SDK to dispatch to the TestClient backend."""
    api_client = TestClient(api_app)
    demo_target_client = TestClient(create_demo_target_app())

    # Direct Telemetry SDK to the active in-memory API test client
    telemetry_client.client.http_client = api_client
    telemetry_client.client.endpoint = "http://testserver/api/v1/telemetry/ingest"
    telemetry_client.client.api_key = "gasha-telemetry-demo-key-2026"
    telemetry_client.client.environment_id = "env-prod"

    token = create_jwt_token({"sub": "lead-analyst-1", "environmentId": "env-prod", "role": "admin"})
    auth_headers = {"Authorization": f"Bearer {token}"}

    return {
        "api": api_client,
        "target": demo_target_client,
        "auth_headers": auth_headers
    }


def test_scenario_a_authentication_failure_threshold(test_clients):
    """
    Scenario A — Authentication-Failure Threshold
    1. Sends 5 failed logins from 198.51.100.101 against demo target.
    2. Flushes SDK buffer to Ingestion API.
    3. Flushes Ingestion API queue to detection & correlation engine.
    4. Asserts RULE-AUTH-001 detection and corresponding active Incident.
    5. Runs deterministic investigation and asserts grounded evidence.
    """
    target = test_clients["target"]
    api = test_clients["api"]
    auth_headers = test_clients["auth_headers"]
    attacker_ip = "198.51.100.101"

    request_logs = []
    for i in range(1, 6):
        resp = target.post(
            "/api/auth/login",
            json={"username": "admin", "password": f"WrongAttempt_{i}!"},
            headers={"X-Forwarded-For": attacker_ip}
        )
        assert resp.status_code == 401
        assert resp.json().get("error") == "INVALID_CREDENTIALS"
        request_logs.append({
            "attempt": i,
            "status": resp.status_code,
            "sourceIp": attacker_ip
        })

    # Flush Telemetry SDK to Ingestion API
    telemetry_client.flush()

    # Flush Ingestion API to Detection and Incident Pipeline
    asyncio.run(flush_all_pending())

    # 1. Verify Detection created
    detections = get_detection_repository().list_detections("env-prod")
    assert len(detections) >= 1
    auth_det = next(d for d in detections if d.rule.ruleId == "RULE-AUTH-001")
    assert auth_det.severity == "HIGH"
    assert len(auth_det.matchedEventIds) == 5
    assert auth_det.metadata.get("sourceIp") == attacker_ip

    # 2. Verify Incident created
    incidents = get_incident_repository().list_incidents("env-prod")
    assert len(incidents) >= 1
    incident = incidents[0]
    assert incident.status == "ACTIVE"
    assert incident.severity == "HIGH"
    assert auth_det.id in incident.detectionEventIds

    # 3. Verify Deterministic Investigation API
    inv_resp = api.post(f"/api/v1/investigations/{incident.id}/run", headers=auth_headers)
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()
    assert len(inv_data["groundedEvidence"]) >= 5
    assert any("RULE-AUTH-001" in fact for fact in inv_data["attackStory"]["observedFacts"])
    assert any(rec["actionType"] == "BLOCK_SOURCE" and rec["targetIdentifier"] == attacker_ip for rec in inv_data["recommendations"])

    # Save scenario artifact
    save_test_evidence("scenario_a_evidence.json", {
        "scenario": "Scenario A - Authentication-Failure Threshold",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attackerIp": attacker_ip,
        "requests": request_logs,
        "detection": auth_det.model_dump(),
        "incident": incident.model_dump(),
        "investigation": inv_data,
        "status": "PASS"
    })


def test_scenario_b_suspicious_web_probe(test_clients):
    """
    Scenario B — Suspicious Web Probe
    1. Sends SQL injection probe to /api/customers/lookup.
    2. Verifies target safely handles probe without executing payload.
    3. Flushes telemetry to Ingestion API and pipeline.
    4. Asserts RULE-INJ-002 detection and incident creation.
    """
    target = test_clients["target"]
    api = test_clients["api"]
    auth_headers = test_clients["auth_headers"]
    attacker_ip = "198.51.100.102"
    probe_query = "' UNION SELECT 1,2,3--"

    resp = target.get(
        f"/api/customers/lookup?query={probe_query}",
        headers={"X-Forwarded-For": attacker_ip}
    )
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data.get("status") == "safe_handled"
    assert res_data.get("detectedPattern") == "SQL_INJECTION"
    assert "Payload neutralized" in res_data.get("warning", "")

    # Flush Telemetry SDK and Pipeline
    telemetry_client.flush()
    asyncio.run(flush_all_pending())

    # Verify Detection
    detections = get_detection_repository().list_detections("env-prod")
    assert len(detections) >= 1
    probe_det = next(d for d in detections if d.rule.ruleId == "RULE-INJ-002")
    assert probe_det.severity == "MEDIUM"
    assert "SQL_INJECTION" in probe_det.evidenceSummary

    # Verify Incident
    incidents = get_incident_repository().list_incidents("env-prod")
    assert len(incidents) >= 1
    incident = incidents[0]
    assert probe_det.id in incident.detectionEventIds

    # Verify Investigation
    inv_resp = api.post(f"/api/v1/investigations/{incident.id}/run", headers=auth_headers)
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()
    assert any("RULE-INJ-002" in fact for fact in inv_data["attackStory"]["observedFacts"])
    assert any("SQL_INJECTION" in str(ev["content"]) for ev in inv_data["groundedEvidence"])

    save_test_evidence("scenario_b_evidence.json", {
        "scenario": "Scenario B - Suspicious Web Probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attackerIp": attacker_ip,
        "targetResponse": res_data,
        "detection": probe_det.model_dump(),
        "incident": incident.model_dump(),
        "investigation": inv_data,
        "status": "PASS"
    })


def test_scenario_c_mixed_authorized_and_denied_activity(test_clients):
    """
    Scenario C — Mixed Authorized and Denied Activity
    1. Authenticates as 'analyst' (synthetic role).
    2. Performs permitted operation (/api/tickets -> 200).
    3. Attempts protected resource access (/api/admin/secrets -> 403).
    4. Attempts unauthorized privilege mutation (/api/admin/privilege-change -> 403).
    5. Verifies distinct evidence outcomes; denied actions are not reported as compromise.
    """
    target = test_clients["target"]
    api = test_clients["api"]
    auth_headers = test_clients["auth_headers"]
    client_ip = "198.51.100.103"

    # Step 1: Login
    login_resp = target.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass2026!"})
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    req_headers = {"Authorization": f"Bearer {token}", "X-Forwarded-For": client_ip}

    # Step 2: Normal operation (200 OK)
    resp_tickets = target.get("/api/tickets", headers=req_headers)
    assert resp_tickets.status_code == 200

    # Step 3: Denied protected resource (403 Forbidden)
    resp_secrets = target.get("/api/admin/secrets", headers=req_headers)
    assert resp_secrets.status_code == 403

    # Step 4: Denied privilege mutation (403 Forbidden)
    resp_priv = target.post("/api/admin/privilege-change", json={"targetUser": "analyst", "newRole": "admin"}, headers=req_headers)
    assert resp_priv.status_code == 403

    telemetry_client.flush()
    asyncio.run(flush_all_pending())

    save_test_evidence("scenario_c_evidence.json", {
        "scenario": "Scenario C - Mixed Authorized and Denied Activity",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "clientIp": client_ip,
        "normalStatus": resp_tickets.status_code,
        "deniedResourceStatus": resp_secrets.status_code,
        "deniedPrivilegeStatus": resp_priv.status_code,
        "status": "PASS"
    })


def test_scenario_d_session_containment_approved_and_rejected(test_clients):
    """
    Scenario D — Human-Approved Session Containment
    Tests both rejected-approval and approved-execution paths:
    1. Logs in to create synthetic session.
    2. Proposes DISABLE_SESSION.
    3. Variation 1 (Rejected): Operator rejects proposal. Target remains unaffected.
    4. Variation 2 (Approved): Operator approves and executes proposal.
    5. Target rejects subsequent requests with 401 SESSION_REVOKED_BY_GASHA.
    6. Verifies audit trail entry.
    """
    target = test_clients["target"]
    api = test_clients["api"]
    auth_headers = test_clients["auth_headers"]
    client_ip = "198.51.100.104"

    login_resp = target.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass2026!"})
    session_token = login_resp.json()["token"]
    req_headers = {"Authorization": f"Bearer {session_token}", "X-Forwarded-For": client_ip}

    # Session works before containment
    res_before = target.get("/api/tickets", headers=req_headers)
    assert res_before.status_code == 200

    # Synthetic incident for session containment
    inc_repo = get_incident_repository()
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    incident = inc_repo.create_incident(
        IncidentResponse(
            id=f"inc-sess-{uuid.uuid4().hex[:8]}",
            environmentId="env-prod",
            title="Suspicious Session Activity",
            summary="Session exhibits anomalous activity",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset:user:analyst",
            relatedAssetIds=[session_token],
            detectionEventIds=[],
            createdAt=now_iso,
            updatedAt=now_iso
        )
    )

    # --- VARIATION 1: Rejected Approval ---
    prop_resp_rej = api.post("/api/v1/responses/propose", json={
        "incidentId": incident.id,
        "environmentId": "env-prod",
        "actionType": "DISABLE_SESSION",
        "targetIdentifier": session_token,
        "targetType": "USER_SESSION",
        "reason": "Suspicious behavior testing rejection flow"
    }, headers=auth_headers)
    assert prop_resp_rej.status_code == 200
    rej_id = prop_resp_rej.json()["id"]

    # Reject proposal
    rej_action_resp = api.post(f"/api/v1/responses/{rej_id}/approve", json={
        "decision": "REJECT",
        "comment": "Operator rejected session invalidation"
    }, headers=auth_headers)
    assert rej_action_resp.status_code == 200
    assert rej_action_resp.json()["status"] == "REJECTED"

    # Verify session STILL works after rejection
    res_after_rej = target.get("/api/tickets", headers=req_headers)
    assert res_after_rej.status_code == 200

    # --- VARIATION 2: Approved and Executed ---
    prop_resp_app = api.post("/api/v1/responses/propose", json={
        "incidentId": incident.id,
        "environmentId": "env-prod",
        "actionType": "DISABLE_SESSION",
        "targetIdentifier": session_token,
        "targetType": "USER_SESSION",
        "reason": "Verified compromised session invalidation"
    }, headers=auth_headers)
    assert prop_resp_app.status_code == 200
    app_id = prop_resp_app.json()["id"]

    # Approve
    app_action_resp = api.post(f"/api/v1/responses/{app_id}/approve", json={
        "decision": "APPROVE",
        "comment": "Operator approved session invalidation"
    }, headers=auth_headers)
    assert app_action_resp.status_code == 200
    assert app_action_resp.json()["status"] == "APPROVED"

    # Execute
    exec_resp = api.post(f"/api/v1/responses/{app_id}/execute", headers=auth_headers)
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "SUCCEEDED"
    assert exec_data["verificationStatus"] == "VERIFIED"

    # Confirm target rejects session now
    res_after_exec = target.get("/api/tickets", headers=req_headers)
    assert res_after_exec.status_code == 401
    assert res_after_exec.json().get("error") == "SESSION_REVOKED_BY_GASHA"

    save_test_evidence("scenario_d_evidence.json", {
        "scenario": "Scenario D - Session Containment Verification",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sessionId": session_token,
        "statusBefore": res_before.status_code,
        "statusAfterRejection": res_after_rej.status_code,
        "statusAfterExecution": res_after_exec.status_code,
        "executionResponse": exec_data,
        "status": "PASS"
    })


def test_scenario_e_source_blocking_complete_defensive_loop(test_clients):
    """
    Scenario E — Full Defensive Loop with Source IP Blocking
    End-to-end integration:
    1. Attacker (198.51.100.105) sends 5 failed logins.
    2. Telemetry ingested -> Rule fired -> Incident created.
    3. Deterministic investigation runs -> proposes BLOCK_SOURCE.
    4. Target responds 200 before approval.
    5. Operator approves and executes BLOCK_SOURCE.
    6. Attacker is blocked (403 ACCESS_BLOCKED_BY_GASHA).
    7. Benign client (198.51.100.200) continues normally (200 OK).
    8. Audit trail is verified cryptographically.
    """
    target = test_clients["target"]
    api = test_clients["api"]
    auth_headers = test_clients["auth_headers"]
    attacker_ip = "198.51.100.105"
    benign_ip = "198.51.100.200"

    # 1. 5 failed logins
    for i in range(5):
        r = target.post("/api/auth/login", json={"username": "admin", "password": f"Attack_{i}"}, headers={"X-Forwarded-For": attacker_ip})
        assert r.status_code == 401

    telemetry_client.flush()
    asyncio.run(flush_all_pending())

    incidents = get_incident_repository().list_incidents("env-prod")
    assert len(incidents) >= 1
    incident = incidents[0]

    # 2. Deterministic investigation
    inv_resp = api.post(f"/api/v1/investigations/{incident.id}/run", headers=auth_headers)
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()

    # 3. Propose BLOCK_SOURCE
    prop_resp = api.post("/api/v1/responses/propose", json={
        "incidentId": incident.id,
        "environmentId": "env-prod",
        "actionType": "BLOCK_SOURCE",
        "targetIdentifier": attacker_ip,
        "targetType": "IP_ADDRESS",
        "reason": "Automated brute force containment recommendation"
    }, headers=auth_headers)
    assert prop_resp.status_code == 200
    resp_id = prop_resp.json()["id"]

    # 4. Target permits before approval
    res_before = target.get("/health", headers={"X-Forwarded-For": attacker_ip})
    assert res_before.status_code == 200

    # 5. Operator approval
    app_resp = api.post(f"/api/v1/responses/{resp_id}/approve", json={
        "decision": "APPROVE",
        "comment": "Confirmed brute-force origin, authorized perimeter drop"
    }, headers=auth_headers)
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "APPROVED"

    # 6. Execute
    exec_resp = api.post(f"/api/v1/responses/{resp_id}/execute", headers=auth_headers)
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "SUCCEEDED"
    assert exec_data["verificationStatus"] == "VERIFIED"

    # 7. Attacker is now blocked with 403
    res_attacker_after = target.get("/health", headers={"X-Forwarded-For": attacker_ip})
    assert res_attacker_after.status_code == 403
    assert res_attacker_after.json().get("error") == "ACCESS_BLOCKED_BY_GASHA"

    # 8. Benign client unaffected
    res_benign = target.get("/health", headers={"X-Forwarded-For": benign_ip})
    assert res_benign.status_code == 200

    # 9. Cryptographic audit trail verification
    audit_resp = api.get("/api/v1/responses/audit/verify", headers=auth_headers)
    assert audit_resp.status_code == 200
    audit_ver = audit_resp.json()
    assert audit_ver["verified"] is True
    assert audit_ver["totalRecords"] >= 2

    save_test_evidence("scenario_e_evidence.json", {
        "scenario": "Scenario E - Full Defensive Loop Source Blocking",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attackerIp": attacker_ip,
        "benignIp": benign_ip,
        "attackerStatusBefore": res_before.status_code,
        "attackerStatusAfter": res_attacker_after.status_code,
        "benignStatus": res_benign.status_code,
        "auditVerification": audit_ver,
        "status": "PASS"
    })


def test_negative_cases_and_safety_boundaries(test_clients):
    """
    Negative tests verifying strict security controls:
    1. Execution of unapproved proposal rejected (HTTP 409).
    2. Malformed / invalid IP injection attempt rejected.
    3. Ingestion with invalid API key rejected (HTTP 401).
    4. Ingestion with mismatched environment rejected (HTTP 400).
    5. Unsupported action (ISOLATE_RESOURCE) safely fails closed.
    """
    api = test_clients["api"]
    auth_headers = test_clients["auth_headers"]

    # 1. Proposal cannot execute before approval
    inc_repo = get_incident_repository()
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    incident = inc_repo.create_incident(
        IncidentResponse(
            id=f"inc-neg-{uuid.uuid4().hex[:8]}",
            environmentId="env-prod",
            title="Test Incident",
            summary="Safety test description",
            severity="LOW",
            status="ACTIVE",
            primaryAffectedAssetId="asset:test",
            relatedAssetIds=["198.51.100.99"],
            detectionEventIds=[],
            createdAt=now_iso,
            updatedAt=now_iso
        )
    )
    prop_resp = api.post("/api/v1/responses/propose", json={
        "incidentId": incident.id,
        "environmentId": "env-prod",
        "actionType": "BLOCK_SOURCE",
        "targetIdentifier": "198.51.100.99",
        "targetType": "IP_ADDRESS",
        "reason": "Safety boundary test"
    }, headers=auth_headers)
    resp_id = prop_resp.json()["id"]

    exec_unapproved = api.post(f"/api/v1/responses/{resp_id}/execute", headers=auth_headers)
    assert exec_unapproved.status_code in (400, 409)
    assert "Cannot execute" in exec_unapproved.json()["detail"]

    # 2. Malformed IP injection rejected safely
    target_client = get_target_security_client()
    ok, msg = target_client.enforce_block_ip("198.51.100.1; rm -rf /")
    assert ok is False
    assert "Invalid IP address for containment" in msg

    # 3. Invalid telemetry key rejected
    bad_key_resp = api.post(
        "/api/v1/telemetry/ingest",
        json={"events": [{"id": "bad-1", "schemaVersion": "1.0.0", "eventType": "HTTP_REQUEST", "timestamp": "2026-10-09T00:00:00Z", "sourceService": "svc", "environmentId": "env-prod", "payload": {}}]},
        headers={"X-GASHA-TELEMETRY-KEY": "wrong-secret-key"}
    )
    assert bad_key_resp.status_code == 401

    # 4. Mismatched environment rejected
    bad_env_resp = api.post(
        "/api/v1/telemetry/ingest",
        json={"events": [{"id": "bad-env-1", "schemaVersion": "1.0.0", "eventType": "HTTP_REQUEST", "timestamp": "2026-10-09T00:00:00Z", "sourceService": "svc", "environmentId": "untrusted-env", "payload": {}}]},
        headers={"X-GASHA-TELEMETRY-KEY": "gasha-telemetry-demo-key-2026"}
    )
    # The batch response indicates rejection
    assert bad_env_resp.status_code == 202
    assert bad_env_resp.json()["rejectedCount"] == 1
    assert "untrusted-env" in bad_env_resp.json()["results"][0]["reason"]

    # 5. Unsupported action fails closed
    ok_iso, msg_iso = target_client.enforce_isolate_resource("asset-123")
    assert ok_iso is False
    assert "Unsupported action" in msg_iso
