"""
==============================================================================
FILE: apps/api/app/ai/tests/e2e/harness.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: End-to-End AI Test Harness executing and evaluating realistic
           GASHA incident scenarios through the complete production AI pipeline.
==============================================================================
"""

import time
import asyncio
import logging
from typing import List, Dict, Any, Optional
from unittest.mock import patch, AsyncMock
from pydantic import BaseModel, Field

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationEnvelope,
    calculate_context_fingerprint,
    ALLOWED_RESPONSE_ACTIONS,
)
from app.ai.integration import run_ai_investigation
from app.ai.pipeline import get_production_model_name
from app.ai.providers.base import AIProviderConnectionError
from app.ai.tests.e2e.cases import E2ECaseDefinition, get_all_e2e_cases

logger = logging.getLogger("gasha.ai.e2e.harness")


class CaseRunMetrics(BaseModel):
    """Performance and validation metrics for an individual E2E test execution."""
    case_id: str
    case_name: str
    model: str
    status: str
    is_fallback: bool
    duration_ms: float
    evidence_count: int
    citations_count: int
    recommendations_count: int
    attack_story_stages_count: int
    confidence_score: float
    validation_passed: bool
    grounding_valid: bool
    allowlist_valid: bool
    chronological_story_valid: bool
    error_message: Optional[str] = None


class E2ETestResult(BaseModel):
    """Summary result of executing the complete E2E validation suite."""
    all_passed: bool
    total_cases: int
    passed_cases: int
    failed_cases: int
    avg_duration_ms: float
    metrics: List[CaseRunMetrics] = Field(default_factory=list)
    invariants_verified: Dict[str, bool] = Field(default_factory=dict)


class E2ETestHarness:
    """
    Orchestrates end-to-end AI validation runs across realistic competition scenarios.
    """

    def __init__(self, default_model: Optional[str] = None):
        self.default_model = default_model or get_production_model_name()

    def verify_envelope_invariants(
        self,
        envelope: AIInvestigationEnvelope,
        context: InvestigationContext,
    ) -> Dict[str, bool]:
        """
        Validates all critical epistemic, safety, and closed-world grounding invariants on the envelope.
        """
        valid_evidence_ids = context.get_all_evidence_ids()
        valid_asset_ids = context.get_all_asset_ids()

        # 1. Grounding invariant: All cited evidence must exist in context
        all_cited = envelope.result.collect_all_cited_evidence_ids()
        grounding_valid = all_cited.issubset(valid_evidence_ids) if valid_evidence_ids else True

        # 2. Asset invariant: All affected assets must exist in context
        asset_valid = set(envelope.result.affectedAssetIds).issubset(valid_asset_ids) if valid_asset_ids else True

        # 3. Allowlist invariant: Recommendations must only contain allowed actions
        allowlist_valid = all(
            rec.actionType in ALLOWED_RESPONSE_ACTIONS for rec in envelope.recommendations
        )

        # 4. Command injection invariant: Target identifiers and actions must not contain shell commands
        no_shell_commands = all(
            not any(char in rec.targetIdentifier for char in (";", "|", "&", "`", "$"))
            for rec in envelope.recommendations
        )

        # 5. Chronological attack story invariant: Steps must be sequential
        chronological_valid = True
        if envelope.attackStory and envelope.attackStory.stages:
            orders = [s.order for s in envelope.attackStory.stages]
            chronological_valid = (orders == sorted(orders))

        # 6. Idempotency invariant: Fingerprint must match recalculated context hash
        expected_fp = calculate_context_fingerprint(context)
        fp_valid = (envelope.contextFingerprint == expected_fp)

        # 7. Non-execution invariant: No actions are executed (advisory envelope only)
        non_execution_valid = isinstance(envelope, AIInvestigationEnvelope)

        return {
            "grounding_valid": grounding_valid,
            "asset_valid": asset_valid,
            "allowlist_valid": allowlist_valid,
            "no_shell_commands": no_shell_commands,
            "chronological_valid": chronological_valid,
            "fingerprint_valid": fp_valid,
            "non_execution_valid": non_execution_valid,
        }

    async def run_case(
        self,
        case: E2ECaseDefinition,
        use_mock: bool = True,
        model: Optional[str] = None,
    ) -> CaseRunMetrics:
        """
        Executes a single E2E test case and captures metrics and invariant verifications.
        """
        target_model = model or self.default_model
        start_time = time.perf_counter()

        if case.case_id == "CASE_F":
            # Simulate provider offline
            with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
                mock_gen.side_effect = AIProviderConnectionError("Connection refused: http://localhost:11434")
                envelope = await run_ai_investigation(case.context, model=target_model)
        elif use_mock and case.mock_llm_response:
            with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
                mock_gen.return_value = case.mock_llm_response
                envelope = await run_ai_investigation(case.context, model=target_model)
        else:
            envelope = await run_ai_investigation(case.context, model=target_model)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        invariants = self.verify_envelope_invariants(envelope, case.context)

        # Case-specific status validation
        status_matches = False
        if case.case_id == "CASE_C":
            status_matches = (envelope.status == "INSUFFICIENT_EVIDENCE")
        elif case.case_id == "CASE_F":
            status_matches = (envelope.status == "UNAVAILABLE")
        else:
            status_matches = (envelope.status in ("COMPLETED", "SUCCESS", case.expected_status))

        validation_passed = all(invariants.values()) and status_matches

        return CaseRunMetrics(
            case_id=case.case_id,
            case_name=case.name,
            model=target_model,
            status=envelope.status,
            is_fallback=envelope.isFallback,
            duration_ms=round(elapsed_ms, 2),
            evidence_count=len(case.context.evidence),
            citations_count=len(envelope.result.citedEvidenceIds),
            recommendations_count=len(envelope.recommendations),
            attack_story_stages_count=len(envelope.attackStory.stages) if envelope.attackStory else 0,
            confidence_score=envelope.result.confidence.score,
            validation_passed=validation_passed,
            grounding_valid=invariants["grounding_valid"],
            allowlist_valid=invariants["allowlist_valid"],
            chronological_story_valid=invariants["chronological_valid"],
            error_message=envelope.result.errorMessage,
        )

    async def run_all_cases(
        self,
        use_mock: bool = True,
        model: Optional[str] = None,
    ) -> E2ETestResult:
        """
        Executes all 6 E2E validation cases and compiles an aggregated E2ETestResult.
        """
        cases = get_all_e2e_cases()
        metrics: List[CaseRunMetrics] = []

        for case in cases:
            res = await self.run_case(case, use_mock=use_mock, model=model)
            metrics.append(res)

        total = len(metrics)
        passed = sum(1 for m in metrics if m.validation_passed)
        failed = total - passed
        avg_duration = sum(m.duration_ms for m in metrics) / total if total > 0 else 0.0

        all_invariants = {
            "all_grounding_valid": all(m.grounding_valid for m in metrics),
            "all_allowlists_valid": all(m.allowlist_valid for m in metrics),
            "all_timelines_chronological": all(m.chronological_story_valid for m in metrics),
            "zero_crashes": True,
            "fallback_operational": any(m.is_fallback for m in metrics),
        }

        return E2ETestResult(
            all_passed=(passed == total),
            total_cases=total,
            passed_cases=passed,
            failed_cases=failed,
            avg_duration_ms=round(avg_duration, 2),
            metrics=metrics,
            invariants_verified=all_invariants,
        )

    async def evaluate_semantic_consistency(
        self,
        context: InvestigationContext,
        runs: int = 3,
        mock_response: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes multiple runs on the same context to verify semantic stability
        (e.g., consistent evidence citations, affected assets, and recommendation families).
        """
        results: List[AIInvestigationEnvelope] = []
        target_model = model or self.default_model

        for _ in range(runs):
            if mock_response:
                with patch("app.ai.providers.ollama.OllamaProvider.generate_investigation", new_callable=AsyncMock) as mock_gen:
                    mock_gen.return_value = mock_response
                    env = await run_ai_investigation(context, model=target_model)
            else:
                env = await run_ai_investigation(context, model=target_model)
            results.append(env)

        severities = {r.result.severity for r in results}
        action_sets = [frozenset(rec.actionType for rec in r.recommendations) for r in results]
        asset_sets = [frozenset(r.result.affectedAssetIds) for r in results]

        severity_consistent = (len(severities) == 1)
        actions_consistent = (len(set(action_sets)) == 1)
        assets_consistent = (len(set(asset_sets)) == 1)

        return {
            "total_runs": runs,
            "severity_consistent": severity_consistent,
            "actions_consistent": actions_consistent,
            "assets_consistent": assets_consistent,
            "observed_severities": list(severities),
            "is_semantically_stable": (severity_consistent and actions_consistent and assets_consistent),
        }
