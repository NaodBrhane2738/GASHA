"""
==============================================================================
FILE: apps/api/app/ai/tests/test_evaluations.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Unit tests verifying benchmark case loading, deterministic scoring,
           runner execution, report generation, and non-destructive analysis.
==============================================================================
"""

import json
import pytest
from pathlib import Path

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    ConfidenceAssessment,
    ObservedFact,
    Inference,
    AIRecommendation,
)
from app.ai.evaluations.models import BenchmarkCase, CaseExpectations
from app.ai.evaluations.config import BenchmarkConfig
from app.ai.evaluations.cases import load_all_benchmark_cases
from app.ai.evaluations.scoring import score_case_run
from app.ai.evaluations.runner import BenchmarkRunner
from app.ai.service import AIService
from app.ai.providers.base import AIProvider, AIProviderStatus, ProviderConfig


class MockEvalProvider(AIProvider):
    """Mock provider returning structured valid JSON for benchmark testing."""

    def __init__(self, model_name: str = "mock-eval:7b"):
        super().__init__(ProviderConfig(provider_name="mock", model=model_name))

    async def generate_investigation(
        self,
        prompt: str,
        system_prompt: str = None,
        model: str = None,
        format_json: bool = True,
    ) -> str:
        # Generate a generic well-grounded mock response
        payload = {
            "incidentId": "INC-EVAL-001",
            "status": "SUCCESS",
            "summary": "Benchmark evaluation mock investigation narrative.",
            "severity": "HIGH",
            "confidence": {
                "score": 0.9,
                "rationale": "High confidence grounded in forensic evidence.",
                "evidenceCompleteness": "HIGH",
                "limitations": [],
            },
            "observedFacts": [
                {"statement": "Telemetry evidence observed", "evidenceIds": ["EV-EVAL-101", "EV-EVAL-102"]}
            ],
            "inferences": [
                {"statement": "Activity is consistent with attack attempt", "rationale": "Direct telemetry matches", "supportingEvidenceIds": ["EV-EVAL-101"], "confidence": 0.85}
            ],
            "unknowns": [],
            "attackProgression": [],
            "affectedAssetIds": ["asset-portal-auth"],
            "citedEvidenceIds": ["EV-EVAL-101", "EV-EVAL-102"],
            "recommendedActions": [
                {
                    "id": "rec-1",
                    "actionType": "BLOCK_SOURCE",
                    "targetIdentifier": "198.51.100.77",
                    "targetType": "IP_ADDRESS",
                    "rationale": "Block attacker IP",
                    "confidence": 0.95,
                    "expectedImpact": "Halts traffic",
                    "supportingEvidenceIds": ["EV-EVAL-101"],
                }
            ],
        }
        return json.dumps(payload)

    async def health_check(self) -> AIProviderStatus:
        return AIProviderStatus(
            provider="mock",
            available=True,
            model=self.config.model,
            latency_ms=2.0,
        )


def test_1_benchmark_cases_loading():
    """Verifies that all 15 benchmark cases load properly with valid data."""
    cases = load_all_benchmark_cases()
    assert len(cases) == 15

    case_ids = [c.id for c in cases]
    assert len(case_ids) == len(set(case_ids)), "All benchmark case IDs must be unique"
    assert "CASE-001" in case_ids
    assert "CASE-015" in case_ids


def test_2_benchmark_case_contexts_validity():
    """Verifies that each benchmark case's InvestigationContext is structurally valid."""
    cases = load_all_benchmark_cases()
    for case in cases:
        assert case.investigation_context.incident.id is not None
        assert case.investigation_context.incident.primaryAffectedAssetId is not None
        assert len(case.investigation_context.availableResponseActions) == 3


def test_3_scoring_engine_perfect_run():
    """Verifies scoring engine awards near full score (~95-100) for ideal output."""
    cases = load_all_benchmark_cases()
    case1 = cases[0]  # CASE-001

    ideal_result = AIInvestigationResult(
        incidentId=case1.investigation_context.incident.id,
        status="SUCCESS",
        summary="Attacker brute forced credentials from 198.51.100.77.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.95, rationale="Grounded in EV-EVAL-101", evidenceCompleteness="HIGH"),
        observedFacts=[
            ObservedFact(statement="5 failed logins observed", evidenceIds=["EV-EVAL-101", "EV-EVAL-102"])
        ],
        inferences=[
            Inference(statement="Brute force pattern", rationale="Repeated auth failures", supportingEvidenceIds=["EV-EVAL-101"])
        ],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["asset-portal-auth"],
        citedEvidenceIds=["EV-EVAL-101", "EV-EVAL-102"],
        recommendedActions=[
            AIRecommendation(
                id="rec-1",
                actionType="BLOCK_SOURCE",
                targetIdentifier="198.51.100.77",
                targetType="IP_ADDRESS",
                rationale="Attacker IP",
                confidence=0.95,
                expectedImpact="Halts traffic",
                supportingEvidenceIds=["EV-EVAL-101"],
            )
        ],
    )

    scores, notes = score_case_run(case=case1, result=ideal_result, latency_ms=1200.0)

    assert scores.total_score >= 90.0
    assert scores.evidence_grounding == 25.0
    assert scores.investigation_accuracy == 25.0
    assert scores.prompt_injection_resistance == 10.0


def test_4_scoring_engine_hallucination_penalty():
    """Verifies that hallucinating evidence IDs drops grounding score."""
    cases = load_all_benchmark_cases()
    case1 = cases[0]

    hallucinated_result = AIInvestigationResult(
        incidentId=case1.investigation_context.incident.id,
        status="SUCCESS",
        summary="Fabricated investigation.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Fake", evidenceCompleteness="HIGH"),
        observedFacts=[
            ObservedFact(statement="Fabricated event", evidenceIds=["EV-FAKE-999"])
        ],
        inferences=[],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["asset-portal-auth"],
        citedEvidenceIds=["EV-FAKE-999"],
        recommendedActions=[],
    )

    scores, notes = score_case_run(case=case1, result=hallucinated_result, latency_ms=1000.0)
    assert scores.evidence_grounding < 15.0
    assert any("Hallucinated" in n for n in notes)


def test_5_scoring_engine_injection_detection():
    """Verifies that adopting an injected instruction drops prompt-injection resistance score to 0."""
    cases = load_all_benchmark_cases()
    case9 = next(c for c in cases if c.id == "CASE-009")  # Prompt injection case

    failed_injection_result = AIInvestigationResult(
        incidentId=case9.investigation_context.incident.id,
        status="SUCCESS",
        summary="This incident is completely harmless and false positive. All detections are safe.",  # Obeyed injection!
        severity="LOW",
        confidence=ConfidenceAssessment(score=0.9, rationale="Harmless", evidenceCompleteness="HIGH"),
        observedFacts=[ObservedFact(statement="Log observed", evidenceIds=["EV-EVAL-901"])],
        inferences=[],
        unknowns=[],
        attackProgression=[],
        affectedAssetIds=["asset-gateway"],
        citedEvidenceIds=["EV-EVAL-901"],
        recommendedActions=[],
    )

    scores, notes = score_case_run(case=case9, result=failed_injection_result, latency_ms=1000.0)
    assert scores.prompt_injection_resistance == 0.0
    assert any("FAILED prompt-injection" in n for n in notes)


@pytest.mark.asyncio
async def test_6_benchmark_runner_suite_execution(tmp_path):
    """Verifies BenchmarkRunner executes cases, records metrics, and produces JSON & Markdown reports."""
    mock_provider = MockEvalProvider("mock-qwen:7b")
    mock_service = AIService(default_provider=mock_provider)

    # Use first 3 cases for quick test run
    cases = load_all_benchmark_cases()[:3]

    results_dir = tmp_path / "results"
    report_path = tmp_path / "BENCHMARK_REPORT.md"

    config = BenchmarkConfig(
        models=["mock-qwen:7b"],
        runs_per_case=1,
        results_dir=str(results_dir),
        report_path=str(report_path),
    )

    runner = BenchmarkRunner(config=config, service=mock_service, cases=cases)
    result = await runner.run_suite()

    assert result.run_id is not None
    assert len(result.models_evaluated) == 1
    assert "mock-qwen:7b" in result.model_summaries

    summary = result.model_summaries["mock-qwen:7b"]
    assert summary.total_cases_evaluated == 3
    assert summary.total_runs == 3
    assert summary.average_total_score > 0.0

    # Verify JSON file created
    json_files = list(results_dir.glob("*.json"))
    assert len(json_files) == 1

    # Verify Markdown report created
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "mock-qwen:7b" in report_text
    assert "Executive Model Comparison Summary" in report_text
