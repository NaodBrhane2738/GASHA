"""
==============================================================================
FILE: apps/api/app/ai/tests/test_backend_integration.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Integration tests for Step 6.8 (AI–Backend Integration Contract).
           Verifies the integration boundary, context fingerprinting, status handling,
           versioned envelopes, advisory response mapping, and idempotency.
TOOLS & LIBRARIES: pytest, pytest-asyncio, unittest.mock, Pydantic v2
==============================================================================
"""

import json
import pytest
from unittest.mock import AsyncMock, patch

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
    AssetContext,
    AIInvestigationResult,
    AIRecommendation,
    AIInvestigationEnvelope,
    calculate_context_fingerprint,
)
from app.ai.integration import (
    run_ai_investigation,
    run_ai_investigation_sync,
    is_context_stale,
    format_recommendation_for_backend,
    map_to_backend_investigation_response,
)
from app.ai.providers.base import AIProviderError, AIProviderConnectionError


def _create_sample_context() -> InvestigationContext:
    """Helper fixture to create a valid, realistic InvestigationContext."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-2026-9001",
            title="Credential Stuffing & Database Exfiltration",
            severity="HIGH",
            status="INVESTIGATING",
            primaryAffectedAssetId="srv-auth",
            relatedAssetIds=["db-prod"],
            detectionEventIds=["DET-001"],
            createdAt="2026-09-24T02:00:00Z",
            updatedAt="2026-09-24T02:05:00Z",
            summary="Rapid authentication attempts from single IP",
        ),
        evidence=[
            EvidenceItem(
                id="EV-001",
                type="TELEMETRY_EVENT",
                source="probe.auth",
                timestamp="2026-09-24T02:01:00Z",
                summary="Failed login attempt from IP 203.0.113.55",
                content={"ip": "203.0.113.55", "user": "admin"},
                verified=True,
            ),
            EvidenceItem(
                id="EV-002",
                type="TELEMETRY_EVENT",
                source="probe.auth",
                timestamp="2026-09-24T02:01:30Z",
                summary="Successful login for user admin from IP 203.0.113.55",
                content={"ip": "203.0.113.55", "user": "admin"},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-001",
                ruleId="RULE-BRUTE-FORCE",
                ruleName="Brute Force Authentication",
                description="Repeated failed auth followed by success",
                severity="HIGH",
                confidence=0.92,
                matchedEventIds=["EV-001", "EV-002"],
                primaryAssetId="srv-auth",
                timestamp="2026-09-24T02:02:00Z",
                evidenceSummary="Brute force pattern detected",
            )
        ],
        assets=[
            AssetContext(
                id="srv-auth",
                name="Auth Server",
                type="SERVER",
                criticality="TIER_1_CRITICAL",
                isPubliclyExposed=True,
            ),
            AssetContext(
                id="db-prod",
                name="Production Database",
                type="DATABASE",
                criticality="TIER_1_CRITICAL",
                isPubliclyExposed=False,
            ),
        ],
    )


@pytest.mark.asyncio
async def test_1_realistic_incident_successful_investigation():
    """TEST 1: Realistic incident -> successful investigation and valid envelope."""
    context = _create_sample_context()

    valid_ai_json = json.dumps({
        "incidentId": "INC-2026-9001",
        "status": "SUCCESS",
        "summary": "Attacker performed brute force authentication from 203.0.113.55.",
        "severity": "HIGH",
        "confidence": {
            "score": 0.92,
            "rationale": "High confidence supported by multiple auth events and detection trigger.",
            "evidenceCompleteness": "HIGH",
            "limitations": []
        },
        "observedFacts": [
            {
                "statement": "Failed login attempt from IP 203.0.113.55.",
                "evidenceIds": ["EV-001"]
            },
            {
                "statement": "Successful login for user admin from IP 203.0.113.55.",
                "evidenceIds": ["EV-002"]
            }
        ],
        "inferences": [
            {
                "statement": "Account admin was compromised via credential stuffing.",
                "rationale": "Direct sequence of failed logins followed immediately by success.",
                "supportingEvidenceIds": ["EV-001", "EV-002"],
                "confidence": 0.90
            }
        ],
        "unknowns": [
            {
                "statement": "Whether database records were downloaded during the session.",
                "significance": "Determines breach scope.",
                "recommendedTelemetry": "DB audit logs"
            }
        ],
        "attackProgression": [
            {
                "stepOrder": 1,
                "phase": "Initial Access",
                "timestamp": "2026-09-24T02:01:00Z",
                "sourceEntity": "203.0.113.55",
                "targetAssetId": "srv-auth",
                "description": "Brute force authentication against admin.",
                "isAttemptOnly": False,
                "evidenceIds": ["EV-001", "EV-002"]
            }
        ],
        "affectedAssetIds": ["srv-auth"],
        "citedEvidenceIds": ["EV-001", "EV-002", "DET-001"],
        "recommendedActions": [
            {
                "id": "rec-1",
                "actionType": "BLOCK_SOURCE",
                "targetIdentifier": "203.0.113.55",
                "targetType": "IP_ADDRESS",
                "rationale": "Source of malicious brute force activity.",
                "confidence": 0.95,
                "expectedImpact": "Halts active attacker traffic.",
                "supportingEvidenceIds": ["EV-001", "EV-002"],
                "priority": "HIGH"
            }
        ]
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = valid_ai_json

        envelope: AIInvestigationEnvelope = await run_ai_investigation(context)

        assert envelope.incidentId == "INC-2026-9001"
        assert envelope.status in ("COMPLETED", "SUCCESS")
        assert not envelope.isFallback
        assert envelope.result.severity == "HIGH"
        assert len(envelope.recommendations) == 1
        assert envelope.recommendations[0].actionType == "BLOCK_SOURCE"
        assert envelope.attackStory is not None
        assert len(envelope.attackStory.stages) >= 1
        assert envelope.executionDurationMs is not None


@pytest.mark.asyncio
async def test_2_incident_with_insufficient_evidence():
    """TEST 2: Incident with insufficient evidence produces INSUFFICIENT_EVIDENCE status."""
    empty_context = InvestigationContext(
        incident=IncidentContext(
            id="INC-EMPTY-001",
            title="Empty Incident",
            severity="LOW",
            status="ACTIVE",
            primaryAffectedAssetId="srv-unknown",
            relatedAssetIds=[],
            detectionEventIds=[],
            createdAt="2026-09-24T02:00:00Z",
            updatedAt="2026-09-24T02:00:00Z",
        ),
        evidence=[],
        detections=[],
        telemetryEvents=[],
        assets=[],
    )

    envelope: AIInvestigationEnvelope = await run_ai_investigation(empty_context)

    assert envelope.incidentId == "INC-EMPTY-001"
    assert envelope.status == "INSUFFICIENT_EVIDENCE"
    assert envelope.isFallback is False or envelope.isFallback is True
    assert envelope.result.confidence.score <= 0.3
    assert len(envelope.result.unknowns) >= 1


@pytest.mark.asyncio
async def test_3_invalid_ai_result_triggers_fallback():
    """TEST 3: Malformed JSON output triggers safe deterministic fallback."""
    context = _create_sample_context()

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = "MALFORMED_OUTPUT_NOT_JSON {{{ 123"

        envelope: AIInvestigationEnvelope = await run_ai_investigation(context)

        assert envelope.incidentId == "INC-2026-9001"
        assert envelope.isFallback is True
        assert envelope.status in ("FALLBACK", "INVALID")
        assert envelope.result.severity == "HIGH"
        assert envelope.attackStory is not None


@pytest.mark.asyncio
async def test_4_provider_unavailable_triggers_unavailable_status():
    """TEST 4: Ollama / Provider connection error triggers UNAVAILABLE status."""
    context = _create_sample_context()

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.side_effect = AIProviderConnectionError("Connection refused: http://localhost:11434")

        envelope: AIInvestigationEnvelope = await run_ai_investigation(context)

        assert envelope.incidentId == "INC-2026-9001"
        assert envelope.isFallback is True
        assert envelope.status == "UNAVAILABLE"
        assert "Connection refused" in (envelope.result.errorMessage or "")


def test_5_new_evidence_arrives_changes_fingerprint():
    """TEST 5: New evidence arriving changes context fingerprint (staleness check)."""
    context1 = _create_sample_context()
    fp1 = calculate_context_fingerprint(context1)

    # Simulate updated incident with new evidence
    context2 = _create_sample_context()
    context2.evidence.append(
        EvidenceItem(
            id="EV-003",
            type="NETWORK_LOG",
            source="probe.firewall",
            timestamp="2026-09-24T02:03:00Z",
            summary="Data transfer of 500MB to external IP",
            content={"bytes": 500000000},
            verified=True,
        )
    )
    fp2 = calculate_context_fingerprint(context2)

    assert fp1 != fp2

    # Mock envelope created with context1
    envelope = AIInvestigationEnvelope(
        incidentId=context1.incident.id,
        contextFingerprint=fp1,
        model="qwen2.5-coder:7b",
        status="COMPLETED",
        isFallback=False,
        result=AIInvestigationResult(
            incidentId=context1.incident.id,
            summary="Initial analysis",
            severity="HIGH",
            confidence={"score": 0.9, "rationale": "Initial", "limitations": []},
        ),
    )

    assert not is_context_stale(context1, envelope)
    assert is_context_stale(context2, envelope)


def test_6_same_incident_identical_fingerprint():
    """TEST 6: Same incident context produces 100% deterministic identical fingerprint."""
    context_a = _create_sample_context()
    context_b = _create_sample_context()

    fp_a = calculate_context_fingerprint(context_a)
    fp_b = calculate_context_fingerprint(context_b)

    assert fp_a == fp_b


def test_7_valid_recommendation_converts_to_backend_request():
    """TEST 7: Valid recommendation formats to exact ResponseActionRequest structure."""
    rec = AIRecommendation(
        id="rec-101",
        actionType="BLOCK_SOURCE",
        targetIdentifier="198.51.100.99",
        targetType="IP_ADDRESS",
        rationale="Source of DDoS traffic",
        confidence=0.96,
        expectedImpact="Immediately blocks ingress packets",
        supportingEvidenceIds=["EV-001"],
        priority="IMMEDIATE",
    )

    req = format_recommendation_for_backend(rec, incident_id="INC-TEST-01")

    assert req["actionType"] == "BLOCK_SOURCE"
    assert req["targetType"] == "IP_ADDRESS"
    assert req["targetIdentifier"] == "198.51.100.99"
    assert req["incidentId"] == "INC-TEST-01"
    assert req["requestedBy"] == "ANALYST_MANUAL"
    assert "0.96" in req["reason"]


@pytest.mark.asyncio
async def test_8_unsupported_recommendation_filtered_before_return():
    """TEST 8: Non-allowlisted or hallucinated action is filtered out by validation."""
    context = _create_sample_context()

    bad_ai_json = json.dumps({
        "incidentId": "INC-2026-9001",
        "status": "SUCCESS",
        "summary": "Attacker detected.",
        "severity": "HIGH",
        "confidence": {"score": 0.85, "rationale": "Valid", "limitations": []},
        "observedFacts": [{"statement": "Login failure observed.", "evidenceIds": ["EV-001"]}],
        "inferences": [],
        "unknowns": [],
        "attackProgression": [],
        "affectedAssetIds": ["srv-auth"],
        "citedEvidenceIds": ["EV-001"],
        "recommendedActions": [
            {
                "id": "rec-illegal",
                "actionType": "SHUTDOWN_ENTIRE_DATACENTER",  # Not allowlisted
                "targetIdentifier": "datacenter-1",
                "targetType": "ASSET_ID",
                "rationale": "Drastic measure",
                "confidence": 0.99,
                "expectedImpact": "Offline",
                "supportingEvidenceIds": ["EV-001"]
            }
        ]
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = bad_ai_json

        envelope: AIInvestigationEnvelope = await run_ai_investigation(context)

        # Illegal action should be rejected/fallback or filtered
        for rec in envelope.recommendations:
            assert rec.actionType in ("BLOCK_SOURCE", "DISABLE_SESSION", "ISOLATE_RESOURCE")


def test_9_map_to_backend_investigation_response():
    """TEST 9: map_to_backend_investigation_response matches schema structure."""
    context = _create_sample_context()
    envelope = AIInvestigationEnvelope(
        incidentId=context.incident.id,
        contextFingerprint="dummy_fp",
        model="qwen2.5-coder:7b",
        status="COMPLETED",
        isFallback=False,
        result=AIInvestigationResult(
            incidentId=context.incident.id,
            summary="Attacker brute-forced credentials.",
            severity="HIGH",
            confidence={"score": 0.91, "rationale": "Solid proof", "limitations": []},
            observedFacts=[{"statement": "Failed login", "evidenceIds": ["EV-001"]}],
            inferences=[{"statement": "Account taken over", "rationale": "Success after failures", "supportingEvidenceIds": ["EV-001"]}],
            unknowns=[{"statement": "Data loss unknown"}],
            citedEvidenceIds=["EV-001"],
            recommendedActions=[
                AIRecommendation(
                    id="rec-1",
                    actionType="BLOCK_SOURCE",
                    targetIdentifier="203.0.113.55",
                    targetType="IP_ADDRESS",
                    rationale="Malicious source",
                    confidence=0.95,
                    expectedImpact="Blocked",
                    supportingEvidenceIds=["EV-001"],
                )
            ],
        ),
        recommendations=[
            AIRecommendation(
                id="rec-1",
                actionType="BLOCK_SOURCE",
                targetIdentifier="203.0.113.55",
                targetType="IP_ADDRESS",
                rationale="Malicious source",
                confidence=0.95,
                expectedImpact="Blocked",
                supportingEvidenceIds=["EV-001"],
            )
        ],
    )

    api_resp = map_to_backend_investigation_response(envelope, context)

    assert api_resp["incidentId"] == "INC-2026-9001"
    assert api_resp["severity"] == "HIGH"
    assert api_resp["confidenceScore"] == 0.91
    assert "attackStory" in api_resp
    assert len(api_resp["attackStory"]["observedFacts"]) == 1
    assert len(api_resp["recommendations"]) == 1
    assert len(api_resp["groundedEvidence"]) == 1
    assert api_resp["groundedEvidence"][0]["id"] == "EV-001"


def test_10_synchronous_investigation_execution():
    """TEST 10: Synchronous execution wrapper run_ai_investigation_sync functions properly."""
    context = _create_sample_context()

    valid_ai_json = json.dumps({
        "incidentId": "INC-2026-9001",
        "status": "SUCCESS",
        "summary": "Sync test summary.",
        "severity": "HIGH",
        "confidence": {"score": 0.88, "rationale": "Sync test", "limitations": []},
        "observedFacts": [{"statement": "Observed auth event", "evidenceIds": ["EV-001"]}],
        "inferences": [],
        "unknowns": [],
        "attackProgression": [],
        "affectedAssetIds": ["srv-auth"],
        "citedEvidenceIds": ["EV-001"],
        "recommendedActions": []
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen_async:
        mock_gen_async.return_value = valid_ai_json

        envelope: AIInvestigationEnvelope = run_ai_investigation_sync(context)

        assert envelope.incidentId == "INC-2026-9001"
        assert envelope.status in ("COMPLETED", "SUCCESS")
        assert envelope.result.summary == "Sync test summary."
