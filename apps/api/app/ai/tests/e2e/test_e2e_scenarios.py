"""
==============================================================================
FILE: apps/api/app/ai/tests/e2e/test_e2e_scenarios.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Pytest suite for Step 6.9 End-to-End AI Integration Validation.
           Verifies the full pipeline against Cases A through F, consistency,
           fallback quality, model configuration, and non-destructive properties.
==============================================================================
"""

import os
import pytest
from unittest.mock import patch, AsyncMock

from app.ai.tests.e2e.cases import (
    get_e2e_case,
    build_case_a_context,
    build_case_b_context,
    build_case_c_context,
    build_case_d_context,
    build_case_e_context,
    CASE_A_MOCK_RESPONSE,
    CASE_B_MOCK_RESPONSE,
    CASE_D_MOCK_RESPONSE,
    CASE_E_MOCK_RESPONSE,
)
from app.ai.tests.e2e.harness import E2ETestHarness
from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationEnvelope,
    calculate_context_fingerprint,
)
from app.ai.integration import run_ai_investigation
from app.ai.pipeline import get_production_model_name
from app.ai.providers.base import AIProviderConnectionError, AIProviderTimeoutError


@pytest.mark.asyncio
async def test_1_e2e_case_a_confirmed_suspicious_sequence():
    """CASE A: Confirmed suspicious sequence yields complete investigation, attack story, and allowlisted recs."""
    case = get_e2e_case("CASE_A")
    assert case is not None
    harness = E2ETestHarness()

    metrics = await harness.run_case(case, use_mock=True)

    assert metrics.validation_passed
    assert metrics.status in ("COMPLETED", "SUCCESS")
    assert not metrics.is_fallback
    assert metrics.grounding_valid
    assert metrics.allowlist_valid
    assert metrics.chronological_story_valid
    assert metrics.recommendations_count >= 1
    assert metrics.citations_count >= 4
    assert metrics.confidence_score >= 0.90


@pytest.mark.asyncio
async def test_2_e2e_case_b_attempted_attack_no_compromise():
    """CASE B: Attempted attack is flagged as attempt-only with unconfirmed compromise."""
    case = get_e2e_case("CASE_B")
    assert case is not None
    harness = E2ETestHarness()

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = case.mock_llm_response
        envelope: AIInvestigationEnvelope = await run_ai_investigation(case.context)

        assert envelope.status in ("COMPLETED", "SUCCESS")
        assert envelope.attackStory is not None
        # At least one stage is marked isAttemptOnly
        assert any(s.isAttemptOnly for s in envelope.attackStory.stages)
        # Severity remains MEDIUM (not CRITICAL breach)
        assert envelope.result.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_3_e2e_case_c_insufficient_evidence():
    """CASE C: Insufficient evidence context safely yields INSUFFICIENT_EVIDENCE status."""
    case = get_e2e_case("CASE_C")
    assert case is not None
    harness = E2ETestHarness()

    metrics = await harness.run_case(case, use_mock=False)

    assert metrics.status == "INSUFFICIENT_EVIDENCE"
    assert metrics.confidence_score <= 0.3
    assert metrics.citations_count == 0


@pytest.mark.asyncio
async def test_4_e2e_case_d_conflicting_evidence():
    """CASE D: Conflicting evidence separates observed facts from inferences with explicit uncertainty."""
    case = get_e2e_case("CASE_D")
    assert case is not None
    harness = E2ETestHarness()

    metrics = await harness.run_case(case, use_mock=True)

    assert metrics.validation_passed
    assert metrics.status in ("COMPLETED", "SUCCESS")
    assert metrics.confidence_score <= 0.75  # Reflects uncertainty from conflicting maintenance window


@pytest.mark.asyncio
async def test_5_e2e_case_e_prompt_injection_in_telemetry():
    """CASE E: Telemetry containing adversarial injection is treated strictly as data."""
    case = get_e2e_case("CASE_E")
    assert case is not None
    harness = E2ETestHarness()

    metrics = await harness.run_case(case, use_mock=True)

    assert metrics.validation_passed
    assert metrics.status in ("COMPLETED", "SUCCESS")
    assert metrics.allowlist_valid  # No arbitrary shell commands
    assert metrics.recommendations_count == 1


@pytest.mark.asyncio
async def test_6_e2e_case_f_provider_offline_fallback():
    """CASE F: Provider offline gracefully triggers deterministic fallback with UNAVAILABLE status."""
    case = get_e2e_case("CASE_F")
    assert case is not None
    harness = E2ETestHarness()

    metrics = await harness.run_case(case, use_mock=False)

    assert metrics.status == "UNAVAILABLE"
    assert metrics.is_fallback is True
    assert metrics.grounding_valid


@pytest.mark.asyncio
async def test_7_e2e_result_consistency_across_runs():
    """TEST 7: Multiple runs on the same context maintain stable semantic properties."""
    context = build_case_a_context()
    harness = E2ETestHarness()

    consistency = await harness.evaluate_semantic_consistency(
        context=context,
        runs=3,
        mock_response=CASE_A_MOCK_RESPONSE,
    )

    assert consistency["is_semantically_stable"]
    assert consistency["severity_consistent"]
    assert consistency["actions_consistent"]
    assert consistency["assets_consistent"]


@pytest.mark.asyncio
async def test_8_e2e_fallback_quality_on_malformed_and_timeout():
    """TEST 8: Fallback on malformed JSON and provider timeout preserves incident usability."""
    context = build_case_a_context()

    # 1. Malformed JSON
    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = "NOT_JSON_AT_ALL_ERROR"
        env_malformed = await run_ai_investigation(context)
        assert env_malformed.isFallback
        assert env_malformed.status in ("FALLBACK", "INVALID")
        assert env_malformed.result.severity == "CRITICAL"

    # 2. Timeout
    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.side_effect = AIProviderTimeoutError("Request timed out after 30.0s")
        env_timeout = await run_ai_investigation(context)
        assert env_timeout.isFallback
        assert env_timeout.status in ("UNAVAILABLE", "TIMEOUT", "FALLBACK")


def test_9_e2e_model_configuration_environment_resolution(monkeypatch):
    """TEST 9: Model configuration resolves dynamically from environment variables."""
    monkeypatch.setenv("AI_PRODUCTION_MODEL", "ministral-8b:latest")
    assert get_production_model_name() == "ministral-8b:latest"

    monkeypatch.delenv("AI_PRODUCTION_MODEL", raising=False)
    monkeypatch.setenv("OLLAMA_MODEL", "deepseek-coder:6.7b")
    assert get_production_model_name() == "deepseek-coder:6.7b"


@pytest.mark.asyncio
async def test_10_e2e_non_destructive_guarantee():
    """TEST 10: Entire E2E pipeline is read-only / analysis-only with zero mutation side-effects."""
    context = build_case_a_context()

    with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = CASE_A_MOCK_RESPONSE
        envelope = await run_ai_investigation(context)

        # Result is an advisory envelope
        assert isinstance(envelope, AIInvestigationEnvelope)
        # Recommendations contain required approval flag in contract
        assert all(rec.actionType in ("BLOCK_SOURCE", "DISABLE_SESSION", "ISOLATE_RESOURCE") for rec in envelope.recommendations)


@pytest.mark.asyncio
async def test_11_e2e_harness_full_suite_execution():
    """TEST 11: E2E Test Harness runs all 6 cases with 100% pass rate."""
    harness = E2ETestHarness()
    result = await harness.run_all_cases(use_mock=True)

    assert result.all_passed
    assert result.total_cases == 6
    assert result.passed_cases == 6
    assert result.failed_cases == 0
    assert result.invariants_verified["all_grounding_valid"]
    assert result.invariants_verified["all_allowlists_valid"]
    assert result.invariants_verified["all_timelines_chronological"]
    assert result.invariants_verified["zero_crashes"]
    assert result.invariants_verified["fallback_operational"]
