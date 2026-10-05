"""
==============================================================================
FILE: apps/api/app/ai/tests/test_final_reliability_fix.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Comprehensive regression test suite for Final Reliability Fixes:
  1. Fact/evidence consistency: SUCCESS cannot become DENIED, DENIED cannot become SUCCESS.
  2. Material evidence completeness: Missing material items (e.g. late AUTH_SUCCESS) are reconciled.
  3. Out-of-order chronology: Timeline is reconstructed from authoritative timestamps.
  4. Temporal anomaly detection: Access before auth is surfaced as anomaly, not rewritten.
  5. Recommendation target safety: Generic 'Unknown' targets are discarded safely.
  6. Out-of-context recommendation targets are rejected.
  7. Conflicting evidence: Contradictions preserved in unknowns/limitations.
  8. Unsupported attack phases: COMMAND_AND_CONTROL normalized.
  9. Unsupported lateral movement: Downgraded to RESOURCE_ACCESS without multi-hop proof.
  10. Identifier drift: Corrupted IPs/session IDs detected.
  11. Timeout: Safe deterministic fallback anchored to ledger.
  12. Cross-incident isolation: Zero cross-contamination between concurrent incidents.
==============================================================================
"""

import pytest
import json
from unittest.mock import AsyncMock, patch
from datetime import datetime

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    AssetContext,
    EvidenceItem,
    DetectionContext,
    AIInvestigationResult,
    AIRecommendation,
    ConfidenceAssessment,
    ObservedFact,
    Inference,
    Unknown,
    AttackProgressionItem,
)
from app.ai.evidence_ledger import EvidenceLedger
from app.ai.validation import validate_investigation_result, create_fallback_investigation_result
from app.ai.semantic_validator import (
    validate_identifier_grounding,
    validate_attack_phases,
    detect_evidence_conflicts,
    validate_recommendation_appropriateness,
    reconcile_investigation_with_ledger,
)
from app.ai.pipeline import investigate_incident, ainvestigate_incident
from app.ai.service import AIService
from app.ai.providers.base import AIProviderTimeoutError


def _make_base_context() -> InvestigationContext:
    incident = IncidentContext(
        id="INC-2026-TEST",
        title="Test Incident",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId="srv-web-01",
        relatedAssetIds=["srv-db-01"],
        createdAt="2026-09-24T10:00:00Z",
        updatedAt="2026-09-24T10:05:00Z",
    )
    assets = [
        AssetContext(id="srv-web-01", name="Web Server", type="WEB_SERVER", ipAddresses=["10.0.1.10"]),
        AssetContext(id="srv-db-01", name="DB Server", type="DATABASE", ipAddresses=["10.0.2.20"]),
    ]
    return InvestigationContext(
        incident=incident,
        assets=assets,
        evidence=[],
        detections=[],
    )


def test_regression_1_evidence_success_cannot_become_denied():
    """Regression 1: Evidence records SUCCESS on /admin/dashboard, model claims DENIED -> Caught & corrected."""
    ctx = _make_base_context()
    ctx.evidence.append(
        EvidenceItem(
            id="EV-0301-03",
            type="TELEMETRY_EVENT",
            source="AdminApp",
            timestamp="2026-09-24T11:02:00Z",
            summary="RESOURCE_ACCESS, /admin/dashboard, SUCCESS",
            content={"path": "/admin/dashboard", "result": "SUCCESS"},
        )
    )

    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="User was denied access to /admin/dashboard.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Grounded"),
        observedFacts=[
            ObservedFact(statement="The /admin/dashboard request was denied (EV-0301-03).", evidenceIds=["EV-0301-03"])
        ],
        inferences=[],
        unknowns=[],
        attackProgression=[
            AttackProgressionItem(
                stepOrder=1,
                phase="RESOURCE_ACCESS",
                timestamp="2026-09-24T11:02:00Z",
                description="Access to /admin/dashboard was denied.",
                isAttemptOnly=True,
                evidenceIds=["EV-0301-03"],
            )
        ],
        affectedAssetIds=["srv-web-01"],
        citedEvidenceIds=["EV-0301-03"],
        recommendedActions=[],
    )

    outcome = validate_investigation_result(ctx, result)
    assert outcome.isValid is True
    validated = outcome.validatedResult
    assert validated is not None
    # Fact statement must be reconciled to SUCCESS
    assert "SUCCESS" in validated.observedFacts[0].statement
    assert validated.attackProgression[0].isAttemptOnly is False


def test_regression_2_late_auth_success_omitted_is_reconciled():
    """Regression 2: Model omitted late AUTH_SUCCESS -> Completeness check detects and injects material fact."""
    ctx = _make_base_context()
    ctx.evidence.extend([
        EvidenceItem(
            id="EV-0301-02",
            type="TELEMETRY_EVENT",
            source="Gateway",
            timestamp="2026-09-24T11:01:05Z",
            summary="AUTH_FAILURE, 203.0.113.120, 401",
            content={"ip": "203.0.113.120", "status": 401},
        ),
        EvidenceItem(
            id="EV-0301-04",
            type="TELEMETRY_EVENT",
            source="IAM",
            timestamp="2026-09-24T11:03:00Z",
            summary="AUTH_SUCCESS, sess-0301-x",
            content={"session": "sess-0301-x"},
        ),
    ])

    # Model cited only EV-0301-02
    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="Authentication failed.",
        severity="MEDIUM",
        confidence=ConfidenceAssessment(score=0.8, rationale="Observed failure"),
        observedFacts=[
            ObservedFact(statement="Authentication failure from 203.0.113.120", evidenceIds=["EV-0301-02"])
        ],
        inferences=[],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["srv-web-01"],
        citedEvidenceIds=["EV-0301-02"],
        recommendedActions=[],
    )

    outcome = validate_investigation_result(ctx, result)
    assert outcome.isValid is True
    validated = outcome.validatedResult
    assert validated is not None
    # EV-0301-04 must be injected into observedFacts and citedEvidenceIds
    assert any("EV-0301-04" in f.evidenceIds for f in validated.observedFacts)
    assert "EV-0301-04" in validated.citedEvidenceIds


def test_regression_3_out_of_order_evidence_chronology_reconstructed():
    """Regression 3: Out-of-order evidence array is ordered chronologically by authoritative timestamps."""
    ctx = _make_base_context()
    ctx.evidence = [
        EvidenceItem(id="EV-3", type="TELEMETRY_EVENT", source="App", timestamp="2026-09-24T11:03:00Z", summary="Step 3", content={}),
        EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="App", timestamp="2026-09-24T11:01:00Z", summary="Step 1", content={}),
        EvidenceItem(id="EV-2", type="TELEMETRY_EVENT", source="App", timestamp="2026-09-24T11:02:00Z", summary="Step 2", content={}),
    ]

    ledger = EvidenceLedger(ctx)
    ordered_ids = [e.evidence_id for e in ledger.entries]
    assert ordered_ids == ["EV-1", "EV-2", "EV-3"]


def test_regression_4_temporal_inconsistency_surfaced_as_unknown():
    """Regression 4: Resource access SUCCESS before AUTH_SUCCESS is flagged as temporal anomaly in unknowns."""
    ctx = _make_base_context()
    ctx.evidence = [
        EvidenceItem(id="EV-0301-03", type="TELEMETRY_EVENT", source="AdminApp", timestamp="2026-09-24T11:02:00Z", summary="RESOURCE_ACCESS, /admin/dashboard, SUCCESS", content={"path": "/admin/dashboard", "result": "SUCCESS"}),
        EvidenceItem(id="EV-0301-04", type="TELEMETRY_EVENT", source="IAM", timestamp="2026-09-24T11:03:00Z", summary="AUTH_SUCCESS, sess-0301-x", content={"session": "sess-0301-x"}),
    ]

    ledger = EvidenceLedger(ctx)
    assert len(ledger.temporal_anomalies) > 0
    assert ledger.temporal_anomalies[0].anomaly_type == "RESOURCE_ACCESS_BEFORE_AUTH"

    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="Test investigation",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Grounded"),
        observedFacts=[
            ObservedFact(statement="Resource access succeeded", evidenceIds=["EV-0301-03"]),
            ObservedFact(statement="Auth succeeded", evidenceIds=["EV-0301-04"]),
        ],
        inferences=[],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["srv-web-01"],
        citedEvidenceIds=["EV-0301-03", "EV-0301-04"],
        recommendedActions=[],
    )

    outcome = validate_investigation_result(ctx, result)
    validated = outcome.validatedResult
    assert validated is not None
    assert any("temporal anomaly" in u.statement.lower() or "preceded" in u.statement.lower() for u in validated.unknowns)


def test_regression_5_recommendation_target_unknown_discarded():
    """Regression 5: Recommendation with targetIdentifier='Unknown' is discarded safely without failing investigation."""
    ctx = _make_base_context()
    ctx.evidence.append(
        EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="WAF", timestamp="2026-09-24T10:00:00Z", summary="Event 1", content={})
    )

    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="Investigation summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Grounded"),
        observedFacts=[ObservedFact(statement="Fact 1", evidenceIds=["EV-1"])],
        inferences=[],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["srv-web-01"],
        citedEvidenceIds=["EV-1"],
        recommendedActions=[
            AIRecommendation(
                id="rec-1",
                actionType="BLOCK_SOURCE",
                targetIdentifier="Unknown",  # Generic unknown target!
                targetType="IP_ADDRESS",
                rationale="Block unknown",
                confidence=0.8,
                expectedImpact="None",
                supportingEvidenceIds=["EV-1"],
            )
        ],
    )

    outcome = validate_investigation_result(ctx, result)
    assert outcome.isValid is True
    validated = outcome.validatedResult
    assert validated is not None
    # The invalid recommendation should be discarded
    assert len(validated.recommendedActions) == 0
    assert any("Discarded invalid recommendation" in w for w in outcome.warnings)


def test_regression_6_recommendation_target_not_in_context_discarded():
    """Regression 6: Recommendation target not present in context is discarded safely."""
    ctx = _make_base_context()
    ctx.evidence.append(
        EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="WAF", timestamp="2026-09-24T10:00:00Z", summary="Event 1 from 10.0.1.10", content={"ip": "10.0.1.10"})
    )

    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="Summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Grounded"),
        observedFacts=[ObservedFact(statement="Fact 1", evidenceIds=["EV-1"])],
        inferences=[],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["srv-web-01"],
        citedEvidenceIds=["EV-1"],
        recommendedActions=[
            AIRecommendation(
                id="rec-1",
                actionType="BLOCK_SOURCE",
                targetIdentifier="198.51.100.99",  # Not in context
                targetType="IP_ADDRESS",
                rationale="Block non-existent IP",
                confidence=0.8,
                expectedImpact="None",
                supportingEvidenceIds=["EV-1"],
            )
        ],
    )

    outcome = validate_investigation_result(ctx, result)
    assert outcome.isValid is True
    assert len(outcome.validatedResult.recommendedActions) == 0


def test_regression_7_conflicting_evidence_preserved_in_unknowns():
    """Regression 7: Contradictory evidence (App success vs DB denied) is surfaced as conflict."""
    ctx = _make_base_context()
    ctx.evidence = [
        EvidenceItem(id="EV-APP", type="TELEMETRY_EVENT", source="App", timestamp="2026-09-24T10:00:00Z", summary="Login status': 'success", content={"session": "sess-test-1"}),
        EvidenceItem(id="EV-DB", type="TELEMETRY_EVENT", source="DB", timestamp="2026-09-24T10:00:10Z", summary="Query denied", content={"session": "sess-test-1"}),
    ]

    conflicts = detect_evidence_conflicts(ctx)
    assert len(conflicts) > 0
    assert conflicts[0].conflict_type == "SUCCESS_VS_DENIED"


def test_regression_8_unsupported_c2_phase_normalized():
    """Regression 8: Invented phase COMMAND_AND_CONTROL is normalized to PERSISTENCE."""
    ctx = _make_base_context()
    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="Summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Grounded"),
        observedFacts=[],
        inferences=[],
        unknowns=[],
        attackProgression=[
            AttackProgressionItem(
                stepOrder=1,
                phase="COMMAND_AND_CONTROL",
                description="Attacker connected",
                evidenceIds=[],
            )
        ],
        affectedAssetIds=["srv-web-01"],
        citedEvidenceIds=[],
        recommendedActions=[],
    )

    warnings, validated = validate_attack_phases(ctx, result)
    assert len(warnings) > 0
    assert validated.attackProgression[0].phase == "PERSISTENCE"


def test_regression_9_unsupported_lateral_movement_downgraded():
    """Regression 9: LATERAL_MOVEMENT without multi-hop traversal proof is downgraded to RESOURCE_ACCESS."""
    ctx = _make_base_context()
    ctx.evidence = [
        EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="App", timestamp="2026-09-24T10:00:00Z", summary="Login srv-web-01", content={}),
        EvidenceItem(id="EV-2", type="TELEMETRY_EVENT", source="App", timestamp="2026-09-24T10:01:00Z", summary="Login srv-db-01", content={}),
    ]

    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="Summary",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Grounded"),
        observedFacts=[],
        inferences=[],
        unknowns=[],
        attackProgression=[
            AttackProgressionItem(
                stepOrder=1,
                phase="LATERAL_MOVEMENT",
                description="Movement between servers",
                evidenceIds=[],
            )
        ],
        affectedAssetIds=["srv-web-01", "srv-db-01"],
        citedEvidenceIds=[],
        recommendedActions=[],
    )

    warnings, validated = validate_attack_phases(ctx, result)
    assert len(warnings) > 0
    assert validated.attackProgression[0].phase == "RESOURCE_ACCESS"


def test_regression_10_identifier_drift_detected():
    """Regression 10: Model hallucinating 203.0.138.88 when context has 203.0.113.88 is flagged."""
    ctx = _make_base_context()
    ctx.evidence.append(
        EvidenceItem(
            id="EV-1",
            type="TELEMETRY_EVENT",
            source="WAF",
            timestamp="2026-09-24T10:00:00Z",
            summary="Traffic from 203.0.113.88",
            content={"ip": "203.0.113.88"},
        )
    )

    result = AIInvestigationResult(
        incidentId="INC-2026-TEST",
        status="SUCCESS",
        summary="Attacker traffic from corrupted IP 203.0.138.88 identified.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Grounded"),
        observedFacts=[],
        inferences=[],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["srv-web-01"],
        citedEvidenceIds=[],
        recommendedActions=[],
    )

    events = validate_identifier_grounding(ctx, result)
    assert len(events) > 0
    assert any(e.value == "203.0.138.88" for e in events)


def test_regression_11_timeout_produces_safe_ledger_fallback():
    """Regression 11: Timeout fallback produces 100% grounded result from EvidenceLedger."""
    ctx = _make_base_context()
    ctx.evidence.extend([
        EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="WAF", timestamp="2026-09-24T10:00:00Z", summary="SQL injection blocked 403", content={"status": 403}),
        EvidenceItem(id="EV-2", type="TELEMETRY_EVENT", source="IAM", timestamp="2026-09-24T10:01:00Z", summary="Role escalated to super_admin", content={"role": "super_admin", "status": 200}),
    ])

    fallback = create_fallback_investigation_result(ctx, status="UNAVAILABLE", reason="Provider timeout after 300s")
    assert fallback.status == "UNAVAILABLE"
    assert fallback.isFallback is True
    assert len(fallback.observedFacts) == 2
    assert fallback.confidence.score == 0.0
    assert fallback.compromiseAssessment == "CONFIRMED"
    assert len(fallback.recommendedActions) == 0


def test_regression_12_cross_incident_isolation():
    """Regression 12: Two separate incidents have zero cross-contamination."""
    ctx_a = InvestigationContext(
        incident=IncidentContext(id="INC-A", title="Incident A", severity="MEDIUM", primaryAffectedAssetId="asset-A", status="ACTIVE", createdAt="2026-09-24T00:00:00Z", updatedAt="2026-09-24T00:00:00Z"),
        assets=[AssetContext(id="asset-A", name="Asset A", type="WEB")],
        evidence=[EvidenceItem(id="EV-A-01", type="TELEMETRY_EVENT", source="WAF", timestamp="2026-09-24T00:00:00Z", summary="Login from 198.51.100.20", content={"ip": "198.51.100.20", "session": "sess-A-001"})],
    )
    ctx_b = InvestigationContext(
        incident=IncidentContext(id="INC-B", title="Incident B", severity="HIGH", primaryAffectedAssetId="asset-B", status="ACTIVE", createdAt="2026-09-24T00:00:00Z", updatedAt="2026-09-24T00:00:00Z"),
        assets=[AssetContext(id="asset-B", name="Asset B", type="API")],
        evidence=[EvidenceItem(id="EV-B-01", type="TELEMETRY_EVENT", source="IAM", timestamp="2026-09-24T00:00:00Z", summary="Auth from 198.51.100.77", content={"ip": "198.51.100.77", "session": "sess-B-009"})],
    )

    ledger_a = EvidenceLedger(ctx_a)
    ledger_b = EvidenceLedger(ctx_b)

    assert "198.51.100.77" not in ledger_a.known_ips
    assert "sess-B-009" not in ledger_a.known_sessions
    assert "asset-B" not in ledger_a.known_assets

    assert "198.51.100.20" not in ledger_b.known_ips
    assert "sess-A-001" not in ledger_b.known_sessions
    assert "asset-A" not in ledger_b.known_assets
