"""
==============================================================================
FILE: apps/api/app/ai/tests/security/test_cross_incident_isolation.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Cross-incident isolation and closed-world boundary test suite.
           Verifies that evidence, assets, and recommendations from disparate
           incidents cannot contaminate or bleed into each other.
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
    AIRecommendation,
    ConfidenceAssessment,
)
from app.ai.validation import validate_investigation_result
from app.ai.attack_stories import generate_attack_story
from app.ai.recommendations import generate_recommendations


def make_incident_a_context() -> InvestigationContext:
    """Fixture for Incident A."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-A",
            title="Incident A - Web Attack",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-srv-A",
            relatedAssetIds=[],
            detectionEventIds=["DET-A-1"],
            createdAt="2026-09-24T00:00:00Z",
            updatedAt="2026-09-24T00:00:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-A-1",
                type="TELEMETRY_EVENT",
                source="asset-srv-A",
                timestamp="2026-09-24T00:00:00Z",
                summary="Attack from 203.0.113.10",
                content={"sourceIp": "203.0.113.10"},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-A-1",
                ruleId="RULE-A",
                ruleName="Web Rule",
                description="Web detection A",
                severity="HIGH",
                confidence=0.9,
                matchedEventIds=["EV-A-1"],
                primaryAssetId="asset-srv-A",
                timestamp="2026-09-24T00:00:00Z",
                evidenceSummary="Match A",
            )
        ],
        assets=[AssetContext(id="asset-srv-A", name="Server A", type="WEB_SERVER", criticality="HIGH")],
    )


def make_incident_b_context() -> InvestigationContext:
    """Fixture for Incident B."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-B",
            title="Incident B - Database Attack",
            severity="CRITICAL",
            status="ACTIVE",
            primaryAffectedAssetId="asset-srv-B",
            relatedAssetIds=[],
            detectionEventIds=["DET-B-1"],
            createdAt="2026-09-24T01:00:00Z",
            updatedAt="2026-09-24T01:00:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-B-1",
                type="TELEMETRY_EVENT",
                source="asset-srv-B",
                timestamp="2026-09-24T01:00:00Z",
                summary="Attack from 198.51.100.10",
                content={"sourceIp": "198.51.100.10"},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-B-1",
                ruleId="RULE-B",
                ruleName="DB Rule",
                description="DB detection B",
                severity="CRITICAL",
                confidence=0.95,
                matchedEventIds=["EV-B-1"],
                primaryAssetId="asset-srv-B",
                timestamp="2026-09-24T01:00:00Z",
                evidenceSummary="Match B",
            )
        ],
        assets=[AssetContext(id="asset-srv-B", name="Server B", type="DATABASE", criticality="CRITICAL")],
    )


def test_cross_incident_evidence_citation_rejected():
    """TEST: Result for Incident A that cites evidence from Incident B fails validation."""
    context_a = make_incident_a_context()

    # Model hallucinated cross-incident data from Incident B into Incident A
    cross_contaminated_result = AIInvestigationResult(
        incidentId="INC-A",
        status="SUCCESS",
        summary="Merged incident investigation.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[
            ObservedFact(statement="Incident A fact", evidenceIds=["EV-A-1"]),
            ObservedFact(statement="Incident B fact (contaminated)", evidenceIds=["EV-B-1"]),
        ],
        affectedAssetIds=["asset-srv-A"],
        citedEvidenceIds=["EV-A-1", "EV-B-1"],
    )

    outcome = validate_investigation_result(context_a, cross_contaminated_result)
    assert outcome.isValid is False
    assert any("EV-B-1" in err for err in outcome.errors)


def test_cross_incident_asset_citation_rejected():
    """TEST: Result for Incident A claiming affected asset from Incident B fails validation."""
    context_a = make_incident_a_context()

    cross_asset_result = AIInvestigationResult(
        incidentId="INC-A",
        status="SUCCESS",
        summary="Merged incident assets.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[ObservedFact(statement="Fact", evidenceIds=["EV-A-1"])],
        affectedAssetIds=["asset-srv-A", "asset-srv-B"],  # asset-srv-B not in Context A
        citedEvidenceIds=["EV-A-1"],
    )

    outcome = validate_investigation_result(context_a, cross_asset_result)
    assert outcome.isValid is False
    assert any("asset-srv-B" in err for err in outcome.errors)


def test_cross_incident_recommendations_isolated():
    """TEST: Recommendation generator for Incident A discards actions citing Incident B evidence."""
    context_a = make_incident_a_context()

    result_with_foreign_rec = AIInvestigationResult(
        incidentId="INC-A",
        status="SUCCESS",
        summary="Test summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[ObservedFact(statement="Fact", evidenceIds=["EV-A-1"])],
        recommendedActions=[
            AIRecommendation(
                id="rec-foreign",
                actionType="ISOLATE_RESOURCE",
                targetIdentifier="asset-srv-B",  # Foreign asset
                targetType="ASSET_ID",
                rationale="Isolate server B",
                confidence=0.9,
                expectedImpact="Isolation",
                supportingEvidenceIds=["EV-B-1"],  # Foreign evidence
            )
        ],
        affectedAssetIds=["asset-srv-A"],
        citedEvidenceIds=["EV-A-1"],
    )

    valid_recs = generate_recommendations(result_with_foreign_rec, context_a)
    assert all(r.id != "rec-foreign" for r in valid_recs)
    assert all(r.targetIdentifier != "asset-srv-B" for r in valid_recs)
    assert all("EV-B-1" not in r.supportingEvidenceIds for r in valid_recs)

