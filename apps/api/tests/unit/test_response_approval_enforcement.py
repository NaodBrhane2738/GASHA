"""
==============================================================================
FILE: apps/api/tests/unit/test_response_approval_enforcement.py
OBJECTIVE: Unit tests for Server-Enforced Human Approval Workflow.
           Verifies state transitions, operator attribution, replay prevention,
           and gatekeeping before execution.
==============================================================================
"""

import pytest

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.response import ResponseProposalRequest, ResponseApprovalRequest
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.response_repository import get_response_repository
from app.response.service import get_response_service


@pytest.fixture(autouse=True)
def reset_all_repos():
    get_incident_repository().clear()
    get_detection_repository().clear()
    get_response_repository().clear()


@pytest.fixture
def staged_incident():
    inc = IncidentResponse(
        id="inc-appr-1",
        title="Admin Brute Force",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId="asset:auth-service:env-prod",
        relatedAssetIds=[],
        detectionEventIds=["det-appr-1"],
        attackPathId=None,
        summary="Brute force",
        environmentId="env-prod",
        correlationKey="auth:env-prod:198.51.100.15",
        createdAt="2026-10-09T10:00:00Z",
        updatedAt="2026-10-09T10:01:00Z"
    )
    det = DetectionEventResponse(
        id="det-appr-1",
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
        evidenceSummary="Brute force from 198.51.100.15",
        environmentId="env-prod",
        metadata={
            "environmentId": "env-prod",
            "sourceIp": "198.51.100.15",
            "userId": "admin"
        }
    )
    get_incident_repository().save_incident(inc)
    get_detection_repository().save_detection(det)
    return inc


def test_operator_approves_proposal(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-alice", "environmentId": "env-prod", "role": "operator"}

    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.15",
        reason="Block attacker"
    )
    record, err = svc.propose_action(req, user=user)
    assert err is None
    assert record.status == "PENDING_APPROVAL"

    # Approve
    approval = ResponseApprovalRequest(decision="APPROVE", comment="Reviewed and approved by Alice")
    approved_record, err = svc.review_proposal(record.id, approval, user=user)

    assert err is None
    assert approved_record.status == "APPROVED"
    assert approved_record.approvedBy == "analyst-alice"
    assert approved_record.approvedAt is not None


def test_operator_rejects_proposal(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-bob", "environmentId": "env-prod", "role": "operator"}

    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.15",
        reason="Block attacker"
    )
    record, _ = svc.propose_action(req, user=user)

    # Reject
    approval = ResponseApprovalRequest(decision="REJECT", comment="False positive investigation")
    rejected_record, err = svc.review_proposal(record.id, approval, user=user)

    assert err is None
    assert rejected_record.status == "REJECTED"
    assert rejected_record.approvedBy == "analyst-bob"


def test_cannot_approve_already_approved_proposal(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-alice", "environmentId": "env-prod"}

    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.15",
        reason="Block attacker"
    )
    record, _ = svc.propose_action(req, user=user)

    # First approval succeeds
    svc.review_proposal(record.id, ResponseApprovalRequest(decision="APPROVE"), user=user)

    # Second approval attempt fails
    second_record, err = svc.review_proposal(record.id, ResponseApprovalRequest(decision="APPROVE"), user=user)
    assert second_record is None
    assert "cannot review proposal" in err.lower()


def test_executing_unapproved_proposal_fails(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-charlie", "environmentId": "env-prod"}

    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.15",
        reason="Block attacker"
    )
    record, _ = svc.propose_action(req, user=user)

    # Attempt to execute directly without approval
    res_rec, ok, msg = svc.execute_approved_action(record.id, user=user)
    assert ok is False
    assert "human approval required" in msg.lower()


def test_executing_rejected_proposal_fails(staged_incident):
    svc = get_response_service()
    user = {"sub": "analyst-charlie", "environmentId": "env-prod"}

    req = ResponseProposalRequest(
        incidentId=staged_incident.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.15",
        reason="Block attacker"
    )
    record, _ = svc.propose_action(req, user=user)
    svc.review_proposal(record.id, ResponseApprovalRequest(decision="REJECT"), user=user)

    res_rec, ok, msg = svc.execute_approved_action(record.id, user=user)
    assert ok is False
    assert "human approval required" in msg.lower()
