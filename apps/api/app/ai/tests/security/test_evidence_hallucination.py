"""
==============================================================================
FILE: apps/api/app/ai/tests/security/test_evidence_hallucination.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Adversarial evidence hallucination test suite for GASHA AI layer.
           Verifies that invented evidence IDs, fabricated asset IDs,
           and hallucinated incident references are strictly caught and rejected.
==============================================================================
"""

import json
import pytest
from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
    AssetContext,
    AIInvestigationResult,
    ObservedFact,
    Inference,
    Unknown,
    AttackProgressionItem,
    AIRecommendation,
    ConfidenceAssessment,
)
from app.ai.validation import validate_investigation_result
from app.ai.service import AIService
from app.ai.pipeline import ProductionInvestigationPipeline
from app.ai.providers.base import AIProvider, AIProviderStatus, ProviderConfig


def make_grounded_context() -> InvestigationContext:
    """Fixture with explicit ground-truth IDs: EV-REAL-1, EV-REAL-2, asset-real-web, asset-real-db."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-GROUND-1",
            title="Grounded Context Incident",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-real-web",
            relatedAssetIds=["asset-real-db"],
            detectionEventIds=["DET-REAL-1"],
            createdAt="2026-09-24T00:00:00Z",
            updatedAt="2026-09-24T00:00:00Z",
        ),
        evidence=[
            EvidenceItem(id="EV-REAL-1", type="TELEMETRY_EVENT", source="asset-real-web", timestamp="2026-09-24T00:00:00Z", summary="Real event 1", content={}, verified=True),
            EvidenceItem(id="EV-REAL-2", type="TELEMETRY_EVENT", source="asset-real-db", timestamp="2026-09-24T00:00:00Z", summary="Real event 2", content={}, verified=True),
        ],
        detections=[
            DetectionContext(
                id="DET-REAL-1",
                ruleId="RULE-REAL",
                ruleName="Real Rule",
                description="Real detection",
                severity="HIGH",
                confidence=0.9,
                matchedEventIds=["EV-REAL-1"],
                primaryAssetId="asset-real-web",
                timestamp="2026-09-24T00:00:00Z",
                evidenceSummary="Real match",
            )
        ],
        assets=[
            AssetContext(id="asset-real-web", name="Real Web", type="WEB_SERVER", criticality="HIGH"),
            AssetContext(id="asset-real-db", name="Real DB", type="DATABASE", criticality="CRITICAL"),
        ],
    )


def test_hallucinated_evidence_in_observed_facts():
    """TEST: ObservedFact citing fabricated evidence ID is rejected."""
    context = make_grounded_context()
    result = AIInvestigationResult(
        incidentId="INC-GROUND-1",
        status="SUCCESS",
        summary="Test summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[
            ObservedFact(statement="Fabricated fact", evidenceIds=["EV-FABRICATED-999"])
        ],
        affectedAssetIds=["asset-real-web"],
        citedEvidenceIds=["EV-FABRICATED-999"],
    )

    outcome = validate_investigation_result(context, result)
    assert outcome.isValid is False
    assert any("EV-FABRICATED-999" in err for err in outcome.errors)


def test_hallucinated_evidence_in_inferences():
    """TEST: Inference citing fabricated evidence ID is rejected."""
    context = make_grounded_context()
    result = AIInvestigationResult(
        incidentId="INC-GROUND-1",
        status="SUCCESS",
        summary="Test summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[ObservedFact(statement="Valid fact", evidenceIds=["EV-REAL-1"])],
        inferences=[
            Inference(statement="Fabricated inference", rationale="No proof", supportingEvidenceIds=["EV-INFERRED-FAKE"], confidence=0.8)
        ],
        affectedAssetIds=["asset-real-web"],
        citedEvidenceIds=["EV-REAL-1", "EV-INFERRED-FAKE"],
    )

    outcome = validate_investigation_result(context, result)
    assert outcome.isValid is False
    assert any("EV-INFERRED-FAKE" in err for err in outcome.errors)


def test_hallucinated_evidence_in_attack_progression():
    """TEST: Attack progression citing non-existent evidence is rejected."""
    context = make_grounded_context()
    result = AIInvestigationResult(
        incidentId="INC-GROUND-1",
        status="SUCCESS",
        summary="Test summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[ObservedFact(statement="Valid fact", evidenceIds=["EV-REAL-1"])],
        attackProgression=[
            AttackProgressionItem(
                stepOrder=1,
                phase="Execution",
                description="Fabricated step",
                evidenceIds=["EV-PROGRESSION-FAKE"],
            )
        ],
        affectedAssetIds=["asset-real-web"],
        citedEvidenceIds=["EV-REAL-1", "EV-PROGRESSION-FAKE"],
    )

    outcome = validate_investigation_result(context, result)
    assert outcome.isValid is False
    assert any("EV-PROGRESSION-FAKE" in err for err in outcome.errors)


def test_hallucinated_asset_ids_rejected():
    """TEST: Claiming affected assets outside supplied context is rejected."""
    context = make_grounded_context()
    result = AIInvestigationResult(
        incidentId="INC-GROUND-1",
        status="SUCCESS",
        summary="Test summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[ObservedFact(statement="Valid fact", evidenceIds=["EV-REAL-1"])],
        affectedAssetIds=["asset-real-web", "asset-fabrication-999"],
        citedEvidenceIds=["EV-REAL-1"],
    )

    outcome = validate_investigation_result(context, result)
    assert outcome.isValid is False
    assert any("asset-fabrication-999" in err for err in outcome.errors)
