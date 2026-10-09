"""
==============================================================================
FILE: apps/api/tests/unit/test_response_executor.py
OBJECTIVE: Unit tests for Controlled Response Executor and Verification.
           Verifies enforcement against controlled demo target security modules,
           active state verification probes, and incident containment transitions.
==============================================================================
"""

import pytest

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.response import ResponseProposalRequest, ResponseApprovalRequest
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.response_repository import get_response_repository
from app.response.enforcement import get_target_security_client
from app.response.service import get_response_service


@pytest.fixture(autouse=True)
def reset_all():
    get_incident_repository().clear()
    get_detection_repository().clear()
    get_response_repository().clear()
    get_target_security_client().clear_all_enforcements()


@pytest.fixture
def staged_incident():
    inc = IncidentResponse(
        id="inc-exec-1",
        title="Admin Brute Force",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId="asset:auth-service:env-prod",
        relatedAssetIds=[],
        detectionEventIds=["det-exec-1"],
        attackPathId=None,
        summary="Brute force",
        environmentId="env-prod",
        correlationKey="auth:env-prod:198.51.100.77",
        createdAt="2026-10-09T10:00:00Z",
        updatedAt="2026-10-09T10:01:00Z"
    )
    det = DetectionEventResponse(
        id="det-exec-1",
        rule=DetectionRuleSummarySchema(
            ruleId="RULE-AUTH-001",
            name="Repeated Authentication Failures",
            description="Brute force",
            severity="HIGH",
            confidence=0.90
        ),
        matchedEventIds=["evt-1"],
        primaryAssetId="asset:auth-service:env-prod",
        timestamp="2026-10-09T10:00:30Z",
        severity="HIGH",
        confidence=0.90,
        evidenceSummary="Brute force from 198.51.100.77",
        environmentId="env-prod",
        metadata={
            "environmentId": "env-prod",
            "sourceIp": "198.51.100.77",
            "userId": "admin",
            "sessionId": "sess-admin-99"
        }
    )
    get_incident_repository().save_incident(inc)
    get_detection_repository().save_detection(det)
    return inc


def test_block_source_execution_and_verification(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-admin", "environmentId": "env-prod"}

    # Propose
    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.77",
        reason="Block active attacker IP"
    )
    rec, _ = svc.propose_action(req, user=user)

    # Approve
    appr_rec, _ = svc.review_proposal(rec.id, ResponseApprovalRequest(decision="APPROVE"), user=user)

    # Execute
    exec_rec, ok, msg = svc.execute_approved_action(appr_rec.id, user=user)

    assert ok is True
    assert exec_rec.status == "SUCCEEDED"
    assert exec_rec.verificationStatus == "VERIFIED"
    assert "actively registered in demo target blocklist" in exec_rec.verificationMessage

    # Verify directly with target security client
    client = get_target_security_client()
    is_blocked, ver_msg = client.verify_block_ip("198.51.100.77")
    assert is_blocked is True

    # Verify incident lifecycle transition to CONTAINED
    updated_inc = get_incident_repository().get_incident(staged_incident.id, environment_id="env-prod")
    assert updated_inc.status == "CONTAINED"


def test_disable_session_execution_and_verification(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-admin", "environmentId": "env-prod"}

    # Propose
    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="DISABLE_SESSION",
        targetType="SESSION_ID",
        targetIdentifier="sess-admin-99",
        reason="Revoke hijacked session"
    )
    rec, _ = svc.propose_action(req, user=user)

    # Approve
    appr_rec, _ = svc.review_proposal(rec.id, ResponseApprovalRequest(decision="APPROVE"), user=user)

    # Execute
    exec_rec, ok, msg = svc.execute_approved_action(appr_rec.id, user=user)

    assert ok is True
    assert exec_rec.status == "SUCCEEDED"
    assert exec_rec.verificationStatus == "VERIFIED"

    # Verify directly with target security client
    client = get_target_security_client()
    is_disabled, _ = client.verify_disable_session("sess-admin-99")
    assert is_disabled is True


def test_double_execution_prevention(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-admin", "environmentId": "env-prod"}

    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.77",
        reason="Block active attacker IP"
    )
    rec, _ = svc.propose_action(req, user=user)
    appr_rec, _ = svc.review_proposal(rec.id, ResponseApprovalRequest(decision="APPROVE"), user=user)

    # First execution succeeds
    _, ok1, _ = svc.execute_approved_action(appr_rec.id, user=user)
    assert ok1 is True

    # Second execution attempt is rejected (replay prevention)
    _, ok2, msg2 = svc.execute_approved_action(appr_rec.id, user=user)
    assert ok2 is False
    assert "human approval required" in msg2.lower()
