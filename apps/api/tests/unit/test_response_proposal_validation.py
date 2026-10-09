"""
==============================================================================
FILE: apps/api/tests/unit/test_response_proposal_validation.py
OBJECTIVE: Unit tests for Response Proposal Validation.
           Verifies allowlisted actions, syntax validation, evidence grounding,
           and environment boundaries.
==============================================================================
"""

import pytest

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.response import ResponseProposalRequest
from app.response.validator import ResponseProposalValidator


@pytest.fixture
def base_context():
    inc = IncidentResponse(
        id="inc-val-1",
        title="Web Reconnaissance Incident",
        severity="MEDIUM",
        status="ACTIVE",
        primaryAffectedAssetId="asset:web-service:env-prod",
        relatedAssetIds=[],
        detectionEventIds=["det-val-1"],
        attackPathId=None,
        summary="Probe detected.",
        environmentId="env-prod",
        correlationKey="probe:env-prod:203.0.113.195",
        createdAt="2026-10-09T10:00:00Z",
        updatedAt="2026-10-09T10:01:00Z"
    )
    det = DetectionEventResponse(
        id="det-val-1",
        rule=DetectionRuleSummarySchema(
            ruleId="RULE-PROBE-002",
            name="Suspicious Web Request Probe",
            description="Probe detection",
            severity="MEDIUM",
            confidence=0.85
        ),
        matchedEventIds=["evt-probe-1"],
        primaryAssetId="asset:web-service:env-prod",
        timestamp="2026-10-09T10:00:30Z",
        severity="MEDIUM",
        confidence=0.85,
        evidenceSummary="SQLi probe from 203.0.113.195",
        environmentId="env-prod",
        metadata={
            "environmentId": "env-prod",
            "sourceIp": "203.0.113.195",
            "targetPath": "/api/users",
            "patternType": "SQL_INJECTION",
            "mitreTechniqueId": "T1190"
        }
    )
    return inc, [det]


def test_valid_block_source_proposal(base_context):
    inc, dets = base_context
    req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="203.0.113.195",
        reason="Active attacker source IP"
    )
    ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-prod")
    assert ok is True
    assert err is None


def test_unknown_placeholder_target_rejected(base_context):
    inc, dets = base_context
    for placeholder in ["Unknown", "N/A", "none", "", "null"]:
        req = ResponseProposalRequest(
            incidentId=inc.id,
            actionType="BLOCK_SOURCE",
            targetType="IP_ADDRESS",
            targetIdentifier=placeholder,
            reason="Placeholder test"
        )
        ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-prod")
        assert ok is False
        assert "placeholder" in err.lower() or "invalid" in err.lower()


def test_command_injection_target_rejected(base_context):
    inc, dets = base_context
    req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="203.0.113.195; rm -rf /",
        reason="Malicious injection in target"
    )
    ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-prod")
    assert ok is False
    assert "invalid ip address" in err.lower()


def test_target_not_in_evidence_context_rejected(base_context):
    inc, dets = base_context
    req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="10.99.99.99",  # Valid IP, but not in incident evidence
        reason="Unrelated target"
    )
    ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-prod")
    assert ok is False
    assert "not present in incident" in err


def test_wrong_target_type_for_action_rejected(base_context):
    inc, dets = base_context
    req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="BLOCK_SOURCE",
        targetType="SESSION_ID",
        targetIdentifier="203.0.113.195",
        reason="Mismatched target type"
    )
    ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-prod")
    assert ok is False
    assert "requires targettype 'ip_address'" in err.lower()


def test_cross_environment_target_rejected(base_context):
    inc, dets = base_context
    req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="203.0.113.195",
        reason="Valid action, wrong environment"
    )
    ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-dev")
    assert ok is False
    assert "environment mismatch" in err.lower()


def test_isolate_resource_without_enforcement_rejected(base_context):
    inc, dets = base_context
    req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="ISOLATE_RESOURCE",
        targetType="ASSET_ID",
        targetIdentifier="asset:web-service:env-prod",
        reason="Attempting resource isolation"
    )
    ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-prod")
    assert ok is False
    assert "unsupported action" in err.lower()


def test_resolved_incident_cannot_propose_action(base_context):
    inc, dets = base_context
    inc.status = "RESOLVED"
    req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="203.0.113.195",
        reason="Action on resolved incident"
    )
    ok, err = ResponseProposalValidator.validate_proposal(req, inc, dets, caller_env="env-prod")
    assert ok is False
    assert "already resolved" in err.lower()
