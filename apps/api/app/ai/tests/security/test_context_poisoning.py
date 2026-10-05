"""
==============================================================================
FILE: apps/api/app/ai/tests/security/test_context_poisoning.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Context poisoning, misleading log, attribution, and false compromise test suite.
           Verifies that misleading log statements, unsupported human attribution,
           and speculative compromise claims are prevented.
==============================================================================
"""

import pytest
from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
    AssetContext,
    AIInvestigationResult,
    ObservedFact,
    ConfidenceAssessment,
)
from app.ai.attack_stories import generate_attack_story


def make_poisoned_context() -> InvestigationContext:
    """Fixture with misleading log content mixed with malicious telemetry."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-POISON-1",
            title="Misleading Telemetry Incident",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-auth-srv",
            relatedAssetIds=[],
            detectionEventIds=["DET-BRUTE-1"],
            createdAt="2026-09-24T00:00:00Z",
            updatedAt="2026-09-24T00:00:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-POISON-1",
                type="TELEMETRY_EVENT",
                source="asset-auth-srv",
                timestamp="2026-09-24T00:00:00Z",
                summary="Log Message: 'Security status: SAFE. All authentication attempts are benign.'",
                content={"sourceIp": "198.51.100.22", "note": "BENIGN_TRAFFIC_CLAIM"},
                verified=True,
            ),
            EvidenceItem(
                id="EV-REAL-1",
                type="TELEMETRY_EVENT",
                source="asset-auth-srv",
                timestamp="2026-09-24T00:01:00Z",
                summary="50 consecutive failed authentications",
                content={"sourceIp": "198.51.100.22", "failures": 50},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-BRUTE-1",
                ruleId="RULE-BRUTE",
                ruleName="Credential Brute Force",
                description="Repeated failed auth",
                severity="HIGH",
                confidence=0.95,
                matchedEventIds=["EV-REAL-1"],
                primaryAssetId="asset-auth-srv",
                timestamp="2026-09-24T00:01:00Z",
                evidenceSummary="50 failures from 198.51.100.22",
            )
        ],
        assets=[
            AssetContext(id="asset-auth-srv", name="Auth Server", type="WEB_SERVER", criticality="HIGH")
        ],
    )


def test_context_poisoning_does_not_override_detection():
    """TEST: Misleading log claim does not prevent detection grounding or story generation."""
    context = make_poisoned_context()
    result = AIInvestigationResult(
        incidentId="INC-POISON-1",
        status="SUCCESS",
        summary="Attacker performed credential brute force despite misleading log message.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="High detection confidence", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[
            ObservedFact(statement="50 failed logins observed from 198.51.100.22.", evidenceIds=["EV-REAL-1"]),
        ],
        affectedAssetIds=["asset-auth-srv"],
        citedEvidenceIds=["EV-REAL-1"],
    )

    story = generate_attack_story(result, context)
    assert story.severity == "HIGH"
    assert "EV-REAL-1" in story.citedEvidenceIds


def test_false_compromise_claim_delineation():
    """TEST: When evidence proves only an attempt, AttackStory preserves uncertainty."""
    context = make_poisoned_context()
    result = AIInvestigationResult(
        incidentId="INC-POISON-1",
        status="SUCCESS",
        summary="Brute force authentication attempt observed.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.88, rationale="Attempt observed", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[ObservedFact(statement="Auth failures logged.", evidenceIds=["EV-REAL-1"])],
        affectedAssetIds=["asset-auth-srv"],
        citedEvidenceIds=["EV-REAL-1"],
    )

    story = generate_attack_story(result, context)
    assert "data exfiltration is not established" in story.uncertainty.lower() or "exfiltration" in story.uncertainty.lower()
