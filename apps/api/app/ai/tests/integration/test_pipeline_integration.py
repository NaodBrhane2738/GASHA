"""
==============================================================================
FILE: apps/api/app/ai/tests/integration/test_pipeline_integration.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Integration test suite for Step 6.10 Live Incident Pipeline Readiness.
           Validates adapter entry points, context mapping, context versioning,
           realistic payload fixtures, and non-authoritative security invariants.
==============================================================================
"""

import json
from pathlib import Path
import pytest
from unittest.mock import patch, AsyncMock

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AIInvestigationEnvelope,
    calculate_context_fingerprint,
    CURRENT_CONTEXT_VERSION,
)
from app.ai.integration import (
    investigate_incident,
    ainvestigate_incident,
    run_ai_investigation,
    run_ai_investigation_sync,
    is_context_stale,
    map_backend_dict_to_context,
    format_recommendation_for_backend,
    map_to_backend_investigation_response,
)
from app.ai.integration.errors import (
    InvalidContextError,
    UnsupportedContextVersionError,
    AIUnavailableError,
)
from app.ai.providers.base import AIProviderConnectionError, AIProviderTimeoutError

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(filename: str) -> dict:
    """Helper to load a realistic backend fixture JSON file."""
    with open(FIXTURES_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.asyncio
async def test_a_normal_incident_end_to_end():
    """Test A: Realistic confirmed attack payload enters AI via investigate_incident and produces validated result."""
    data = _load_fixture("confirmed_attack.json")
    context = map_backend_dict_to_context(data)

    mock_response = json.dumps({
        "incidentId": "INC-PROD-101",
        "status": "SUCCESS",
        "summary": "Attacker brute-forced admin credentials and extracted customer database records.",
        "severity": "CRITICAL",
        "confidence": {
            "score": 0.96,
            "rationale": "High confidence supported by complete auth, query, and egress evidence.",
            "evidenceCompleteness": "HIGH",
            "limitations": []
        },
        "observedFacts": [
            {"statement": "25 failed login attempts from 198.51.100.42.", "evidenceIds": ["EV-001"]},
            {"statement": "Admin login succeeded from 198.51.100.42 with session sess-admin-4491.", "evidenceIds": ["EV-002"]},
            {"statement": "SELECT on customer_records by session sess-admin-4491.", "evidenceIds": ["EV-003"]},
            {"statement": "520MB outbound transfer to 198.51.100.42.", "evidenceIds": ["EV-004"]}
        ],
        "inferences": [
            {
                "statement": "Admin credentials were compromised via brute force leading to customer data exfiltration.",
                "rationale": "Direct temporal chain from failed auth to table extraction to egress.",
                "supportingEvidenceIds": ["EV-001", "EV-002", "EV-003", "EV-004"],
                "confidence": 0.95
            }
        ],
        "unknowns": [
            {
                "statement": "Whether secondary backdoors were established.",
                "significance": "Complete remediation",
                "recommendedTelemetry": "User audit logs"
            }
        ],
        "attackProgression": [
            {
                "stepOrder": 1,
                "phase": "Initial Access",
                "timestamp": "2026-09-24T02:01:00Z",
                "sourceEntity": "198.51.100.42",
                "targetAssetId": "srv-auth-cluster",
                "description": "Brute force authentication against admin account.",
                "isAttemptOnly": False,
                "evidenceIds": ["EV-001", "EV-002"]
            },
            {
                "stepOrder": 2,
                "phase": "Exfiltration",
                "timestamp": "2026-09-24T02:04:30Z",
                "sourceEntity": "db-customer-pci",
                "targetAssetId": "srv-auth-cluster",
                "description": "Exfiltrated 520MB customer records.",
                "isAttemptOnly": False,
                "evidenceIds": ["EV-003", "EV-004"]
            }
        ],
        "affectedAssetIds": ["srv-auth-cluster", "db-customer-pci"],
        "citedEvidenceIds": ["EV-001", "EV-002", "EV-003", "EV-004", "DET-001", "DET-002"],
        "recommendedActions": [
            {
                "id": "rec-1",
                "actionType": "BLOCK_SOURCE",
                "targetIdentifier": "198.51.100.42",
                "targetType": "IP_ADDRESS",
                "rationale": "Origin of hostile brute force and exfiltration traffic.",
                "confidence": 0.98,
                "expectedImpact": "Halts active attacker traffic.",
                "supportingEvidenceIds": ["EV-001", "EV-004"],
                "priority": "IMMEDIATE"
            },
            {
                "id": "rec-2",
                "actionType": "DISABLE_SESSION",
                "targetIdentifier": "sess-admin-4491",
                "targetType": "SESSION_ID",
                "rationale": "Compromised admin session.",
                "confidence": 0.95,
                "expectedImpact": "Revokes attacker session.",
                "supportingEvidenceIds": ["EV-002", "EV-003"],
                "priority": "IMMEDIATE"
            }
        ]
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_response

        # 1. Async entrypoint
        res_async = await ainvestigate_incident(context)
        assert isinstance(res_async, AIInvestigationResult)
        assert res_async.status in ("SUCCESS", "COMPLETED")
        assert res_async.severity == "CRITICAL"
        assert len(res_async.observedFacts) == 4
        assert len(res_async.recommendedActions) == 2

        # 2. Sync entrypoint
        res_sync = investigate_incident(context)
        assert isinstance(res_sync, AIInvestigationResult)
        assert res_sync.incidentId == "INC-PROD-101"

        # 3. Envelope entrypoint
        envelope = await run_ai_investigation(context)
        assert isinstance(envelope, AIInvestigationEnvelope)
        assert envelope.contextFingerprint == calculate_context_fingerprint(context)


def test_b_insufficient_evidence():
    """Test B: Insufficient evidence context yields uncertainty without invented details."""
    data = _load_fixture("insufficient_evidence.json")
    context = map_backend_dict_to_context(data)

    result = investigate_incident(context)

    assert result.status == "INSUFFICIENT_EVIDENCE"
    assert result.confidence.score <= 0.3
    assert len(result.unknowns) >= 1
    assert len(result.observedFacts) == 0
    assert len(result.recommendedActions) == 0


@pytest.mark.asyncio
async def test_c_attempted_attack_no_false_compromise():
    """Test C: Attempted attack with 403 blocks is not overstated as a confirmed compromise."""
    data = _load_fixture("attempted_attack.json")
    context = map_backend_dict_to_context(data)

    mock_response = json.dumps({
        "incidentId": "INC-PROD-102",
        "status": "SUCCESS",
        "summary": "External IP 203.0.113.88 conducted SQL injection probing; all attempts blocked by WAF with HTTP 403.",
        "severity": "MEDIUM",
        "confidence": {"score": 0.85, "rationale": "Confirmed perimeter block", "limitations": []},
        "observedFacts": [{"statement": "HTTP GET and POST blocked with HTTP 403.", "evidenceIds": ["EV-WAF-01", "EV-WAF-02"]}],
        "inferences": [{"statement": "Attacker probed endpoints but did not breach backend.", "rationale": "All 403 codes", "supportingEvidenceIds": ["EV-WAF-01"], "confidence": 0.9}],
        "unknowns": [{"statement": "Scanning other endpoints unknown"}],
        "attackProgression": [
            {
                "stepOrder": 1,
                "phase": "Initial Access",
                "timestamp": "2026-09-24T02:10:30Z",
                "sourceEntity": "203.0.113.88",
                "targetAssetId": "srv-web-frontend",
                "description": "Hostile SQLi probing dropped by WAF.",
                "isAttemptOnly": True,
                "evidenceIds": ["EV-WAF-01", "EV-WAF-02"]
            }
        ],
        "affectedAssetIds": ["srv-web-frontend"],
        "citedEvidenceIds": ["EV-WAF-01", "EV-WAF-02", "DET-WAF-01"],
        "recommendedActions": [
            {
                "id": "rec-1",
                "actionType": "BLOCK_SOURCE",
                "targetIdentifier": "203.0.113.88",
                "targetType": "IP_ADDRESS",
                "rationale": "Source of hostile probing.",
                "confidence": 0.90,
                "expectedImpact": "Preempts further traffic.",
                "supportingEvidenceIds": ["EV-WAF-01"]
            }
        ]
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_response

        envelope = await run_ai_investigation(context)
        assert envelope.attackStory is not None
        assert any(s.isAttemptOnly for s in envelope.attackStory.stages)
        assert envelope.result.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_d_prompt_injection_in_telemetry():
    """Test D: Adversarial instruction in telemetry is treated as data and ignored."""
    data = _load_fixture("prompt_injection_payload.json")
    context = map_backend_dict_to_context(data)

    mock_response = json.dumps({
        "incidentId": "INC-PROD-105",
        "status": "SUCCESS",
        "summary": "Attacker at IP 198.51.100.66 attempted prompt injection via HTTP headers.",
        "severity": "HIGH",
        "confidence": {"score": 0.92, "rationale": "Directly grounded in evidence", "limitations": []},
        "observedFacts": [{"statement": "User-Agent contained adversarial override payload.", "evidenceIds": ["EV-INJ-01"]}],
        "inferences": [{"statement": "Attacker attempted prompt injection evasion.", "rationale": "Payload matches attack strings", "supportingEvidenceIds": ["EV-INJ-01"], "confidence": 0.9}],
        "unknowns": [],
        "attackProgression": [],
        "affectedAssetIds": ["srv-api-edge"],
        "citedEvidenceIds": ["EV-INJ-01", "DET-INJ-01"],
        "recommendedActions": [
            {
                "id": "rec-1",
                "actionType": "BLOCK_SOURCE",
                "targetIdentifier": "198.51.100.66",
                "targetType": "IP_ADDRESS",
                "rationale": "Origin of hostile injection payloads.",
                "confidence": 0.95,
                "expectedImpact": "Blocks attacker IP.",
                "supportingEvidenceIds": ["EV-INJ-01"]
            }
        ]
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_response

        res = await ainvestigate_incident(context)
        assert res.severity == "HIGH"
        assert len(res.recommendedActions) == 1
        assert res.recommendedActions[0].actionType == "BLOCK_SOURCE"
        assert res.recommendedActions[0].targetIdentifier == "198.51.100.66"


@pytest.mark.asyncio
async def test_e_invalid_evidence_reference_triggers_fallback():
    """Test E: Model citing a hallucinated evidence ID triggers validation failure and safe fallback."""
    data = _load_fixture("confirmed_attack.json")
    context = map_backend_dict_to_context(data)

    hallucinated_response = json.dumps({
        "incidentId": "INC-PROD-101",
        "status": "SUCCESS",
        "summary": "Attacker compromised database.",
        "severity": "CRITICAL",
        "confidence": {"score": 0.9, "rationale": "Hallucinated citation", "limitations": []},
        "observedFacts": [{"statement": "Hallucinated claim", "evidenceIds": ["EV-FAKE-9999"]}],
        "inferences": [],
        "unknowns": [],
        "attackProgression": [],
        "affectedAssetIds": ["srv-auth-cluster"],
        "citedEvidenceIds": ["EV-FAKE-9999"],
        "recommendedActions": []
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = hallucinated_response

        envelope = await run_ai_investigation(context)
        assert envelope.isFallback is True
        assert envelope.status in ("FALLBACK", "INVALID")
        # Fallback uses strictly valid context evidence IDs
        valid_ids = context.get_all_evidence_ids()
        assert set(envelope.result.citedEvidenceIds).issubset(valid_ids)


@pytest.mark.asyncio
async def test_f_invalid_response_action_rejected():
    """Test F: Non-allowlisted response actions (e.g. DELETE_DATABASE) are rejected."""
    data = _load_fixture("confirmed_attack.json")
    context = map_backend_dict_to_context(data)

    bad_action_response = json.dumps({
        "incidentId": "INC-PROD-101",
        "status": "SUCCESS",
        "summary": "Attacker detected.",
        "severity": "HIGH",
        "confidence": {"score": 0.9, "rationale": "Bad action", "limitations": []},
        "observedFacts": [{"statement": "Observed auth event", "evidenceIds": ["EV-001"]}],
        "inferences": [],
        "unknowns": [],
        "attackProgression": [],
        "affectedAssetIds": ["srv-auth-cluster"],
        "citedEvidenceIds": ["EV-001"],
        "recommendedActions": [
            {
                "id": "rec-illegal",
                "actionType": "RUN_SHELL_COMMAND",  # Illegal
                "targetIdentifier": "bash -c 'rm -rf /'",
                "targetType": "ASSET_ID",
                "rationale": "Dangerous command",
                "confidence": 0.99,
                "expectedImpact": "Destructive",
                "supportingEvidenceIds": ["EV-001"]
            }
        ]
    })

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = bad_action_response

        envelope = await run_ai_investigation(context)
        for rec in envelope.recommendations:
            assert rec.actionType in ("BLOCK_SOURCE", "DISABLE_SESSION", "ISOLATE_RESOURCE")


@pytest.mark.asyncio
async def test_g_provider_unavailable_fallback():
    """Test G: Provider offline triggers controlled UNAVAILABLE fallback without crashing."""
    data = _load_fixture("confirmed_attack.json")
    context = map_backend_dict_to_context(data)

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.side_effect = AIProviderConnectionError("Connection refused: http://localhost:11434")

        envelope = await run_ai_investigation(context)
        assert envelope.isFallback is True
        assert envelope.status == "UNAVAILABLE"
        assert envelope.result.severity == "CRITICAL"


@pytest.mark.asyncio
async def test_h_malformed_model_output_fallback():
    """Test H: Corrupted non-JSON output triggers controlled fallback."""
    data = _load_fixture("confirmed_attack.json")
    context = map_backend_dict_to_context(data)

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = "ERROR_NOT_JSON {{{ 123"

        envelope = await run_ai_investigation(context)
        assert envelope.isFallback is True
        assert envelope.status in ("FALLBACK", "INVALID")


def test_i_repeated_input_idempotency_and_stability():
    """Test I: Multiple calls with identical context produce stable fingerprint and findings."""
    data = _load_fixture("multi_asset_incident.json")
    context1 = map_backend_dict_to_context(data)
    context2 = map_backend_dict_to_context(data)

    fp1 = calculate_context_fingerprint(context1)
    fp2 = calculate_context_fingerprint(context2)

    assert fp1 == fp2


def test_j_non_authoritative_invariants():
    """Test J: Explicit non-authoritative boundary verification."""
    data = _load_fixture("confirmed_attack.json")
    context = map_backend_dict_to_context(data)

    # 1. Recommendation translation strictly sets requestedBy = 'ANALYST_MANUAL'
    rec = context.availableResponseActions[0]
    from app.ai.contracts import AIRecommendation
    test_rec = AIRecommendation(
        id="rec-test",
        actionType="BLOCK_SOURCE",
        targetIdentifier="198.51.100.42",
        targetType="IP_ADDRESS",
        rationale="Malicious source",
        confidence=0.95,
        expectedImpact="Blocked",
        supportingEvidenceIds=["EV-001"],
    )
    backend_req = format_recommendation_for_backend(test_rec, incident_id="INC-PROD-101")
    assert backend_req["requestedBy"] == "ANALYST_MANUAL"

    # 2. Context cannot be mutated by pipeline
    original_evidence_count = len(context.evidence)
    res = investigate_incident(context)
    assert len(context.evidence) == original_evidence_count


def test_k_context_version_enforcement():
    """Test K: Context versioning is strictly enforced."""
    # 1. Valid default version
    valid_data = _load_fixture("confirmed_attack.json")
    ctx = map_backend_dict_to_context(valid_data)
    assert ctx.contextVersion == CURRENT_CONTEXT_VERSION

    # 2. Unsupported future version
    invalid_data = dict(valid_data)
    invalid_data["contextVersion"] = "99.0.0"

    with pytest.raises(UnsupportedContextVersionError) as exc_info:
        map_backend_dict_to_context(invalid_data)
    assert "99.0.0" in str(exc_info.value)
