"""
==============================================================================
FILE: apps/api/app/ai/tests/security/test_confidence.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Confidence calibration, uncertainty metrics, and overconfidence defense test suite.
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
    ConfidenceAssessment,
)
from app.ai.validation import validate_investigation_result, create_fallback_investigation_result


def test_confidence_score_bounds():
    """TEST: Confidence score outside [0.0, 1.0] fails schema validation."""
    with pytest.raises(Exception):
        ConfidenceAssessment(
            score=1.5,  # Out of bounds (> 1.0)
            rationale="Overconfident rationale",
            evidenceCompleteness="HIGH",
        )

    with pytest.raises(Exception):
        ConfidenceAssessment(
            score=-0.2,  # Out of bounds (< 0.0)
            rationale="Negative rationale",
            evidenceCompleteness="LOW",
        )


def test_overconfidence_warning_on_empty_facts():
    """TEST: AI reporting confidence > 0.8 despite zero observed facts triggers validation warning."""
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-CONF-1",
            title="Overconfidence Test",
            severity="MEDIUM",
            status="ACTIVE",
            primaryAffectedAssetId="asset-srv-1",
            createdAt="2026-09-24T00:00:00Z",
            updatedAt="2026-09-24T00:00:00Z",
        ),
        evidence=[EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="asset-srv-1", timestamp="2026-09-24T00:00:00Z", summary="Event 1", content={}, verified=True)],
        detections=[],
        assets=[AssetContext(id="asset-srv-1", name="Server 1", type="WEB_SERVER", criticality="MEDIUM")],
    )

    result = AIInvestigationResult(
        incidentId="INC-CONF-1",
        status="SUCCESS",
        summary="Summary without facts",
        severity="MEDIUM",
        confidence=ConfidenceAssessment(score=0.95, rationale="Unjustified high confidence", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[],  # Empty facts!
        affectedAssetIds=["asset-srv-1"],
        citedEvidenceIds=[],
    )

    outcome = validate_investigation_result(context, result)
    assert any("high confidence" in warn.lower() for warn in outcome.warnings)


def test_fallback_confidence_calibration():
    """TEST: Fallbacks are appropriately calibrated (0.0 for UNAVAILABLE, 0.3 for INVALID)."""
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-CONF-2",
            title="Fallback Calibration Test",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-srv-1",
            createdAt="2026-09-24T00:00:00Z",
            updatedAt="2026-09-24T00:00:00Z",
        ),
        evidence=[],
        detections=[],
    )

    unavailable_fallback = create_fallback_investigation_result(context, status="UNAVAILABLE")
    assert unavailable_fallback.confidence.score == 0.0
    assert unavailable_fallback.confidence.evidenceCompleteness == "INSUFFICIENT"

    invalid_fallback = create_fallback_investigation_result(context, status="INVALID")
    assert invalid_fallback.confidence.score == 0.3
    assert invalid_fallback.confidence.evidenceCompleteness == "INSUFFICIENT"
