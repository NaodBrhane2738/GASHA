"""
==============================================================================
FILE: apps/api/app/ai/evaluations/runner.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Core Benchmark Runner executing synthetic security incident cases
           across local Ollama candidate models and compiling evaluation metrics.
TOOLS & LIBRARIES: asyncio, json, datetime, pathlib, Pydantic v2
KEY FEATURES:
  - BenchmarkRunner: Main evaluation runner for local LLMs.
  - Reuses existing AIService, OllamaProvider, and validation pipeline.
  - Multi-run statistical consistency evaluation per case.
  - Generates machine-readable JSON results and human-readable Markdown reports.
EXPECTED RESULTS / BEHAVIOR:
  - Completely non-destructive (READ/ANALYSIS ONLY).
  - Handles unavailable models gracefully without failing the suite.
==============================================================================
"""

import os
import time
import json
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from app.ai.service import AIService, get_ai_service
from app.ai.providers.ollama import OllamaProvider
from app.ai.evaluations.models import (
    BenchmarkCase,
    CaseRunEvaluation,
    ModelBenchmarkSummary,
    BenchmarkRunResult,
    CategoryScores,
)
from app.ai.evaluations.config import BenchmarkConfig, RESULTS_DIR, REPORT_PATH
from app.ai.evaluations.cases import load_all_benchmark_cases
from app.ai.evaluations.scoring import score_case_run

logger = logging.getLogger("gasha.ai.evaluations.runner")


class BenchmarkRunner:
    """
    Executes the GASHA benchmark evaluation suite against candidate local models.
    """

    def __init__(
        self,
        config: Optional[BenchmarkConfig] = None,
        service: Optional[AIService] = None,
        cases: Optional[List[BenchmarkCase]] = None,
    ):
        self.config = config or BenchmarkConfig()
        self.service = service or get_ai_service()
        self.cases = cases if cases is not None else load_all_benchmark_cases()

    async def run_case_on_model(
        self,
        case: BenchmarkCase,
        model_name: str,
        run_index: int = 1,
    ) -> CaseRunEvaluation:
        """
        Executes a single benchmark case against a specified model and scores the result.
        """
        start_time = time.perf_counter()
        result = await self.service.investigate(
            context=case.investigation_context,
            model=model_name,
        )
        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Determine validation and fallback state
        is_valid_json = result.status != "INVALID"
        passed_validation = result.status == "SUCCESS"
        triggered_fallback = result.status in ("INVALID", "UNAVAILABLE", "INSUFFICIENT_EVIDENCE") and bool(result.errorMessage)

        scores, notes = score_case_run(
            case=case,
            result=result,
            latency_ms=latency_ms,
            weights=self.config.weights,
        )

        return CaseRunEvaluation(
            case_id=case.id,
            case_name=case.name,
            case_category=case.category,
            run_index=run_index,
            model_name=model_name,
            latency_ms=latency_ms,
            is_valid_json=is_valid_json,
            passed_validation=passed_validation,
            triggered_fallback=triggered_fallback,
            fallback_reason=result.errorMessage,
            scores=scores,
            notes=notes,
            output_summary=result.summary[:200] if result.summary else None,
        )

    async def evaluate_model(self, model_name: str) -> ModelBenchmarkSummary:
        """
        Runs all benchmark cases for a specific model across configured runs_per_case.
        """
        logger.info(f"Starting benchmark evaluation for model: '{model_name}' ({len(self.cases)} cases, {self.config.runs_per_case} run(s) each)")

        evaluations: List[CaseRunEvaluation] = []
        for case in self.cases:
            for run_idx in range(1, self.config.runs_per_case + 1):
                logger.debug(f"Evaluating {case.id} (Run {run_idx}) on {model_name}...")
                eval_res = await self.run_case_on_model(case, model_name, run_idx)
                evaluations.append(eval_res)

        # Aggregate metrics
        total_runs = len(evaluations)
        successful_runs = sum(1 for e in evaluations if e.passed_validation and not e.triggered_fallback)
        fallback_runs = sum(1 for e in evaluations if e.triggered_fallback)
        avg_latency = round(sum(e.latency_ms for e in evaluations) / total_runs, 2) if total_runs else 0.0
        avg_total_score = round(sum(e.scores.total_score for e in evaluations) / total_runs, 2) if total_runs else 0.0

        # Category score averages
        cat_acc = round(sum(e.scores.investigation_accuracy for e in evaluations) / total_runs, 2) if total_runs else 0.0
        cat_ground = round(sum(e.scores.evidence_grounding for e in evaluations) / total_runs, 2) if total_runs else 0.0
        cat_fiu = round(sum(e.scores.fact_inference_handling for e in evaluations) / total_runs, 2) if total_runs else 0.0
        cat_rec = round(sum(e.scores.response_recommendation for e in evaluations) / total_runs, 2) if total_runs else 0.0
        cat_struct = round(sum(e.scores.structured_output for e in evaluations) / total_runs, 2) if total_runs else 0.0
        cat_inj = round(sum(e.scores.prompt_injection_resistance for e in evaluations) / total_runs, 2) if total_runs else 0.0
        cat_lat = round(sum(e.scores.latency_operational for e in evaluations) / total_runs, 2) if total_runs else 0.0

        # Failure category counts
        hallucination_failures = sum(1 for e in evaluations if any("Hallucinated" in n for n in e.notes))
        grounding_failures = sum(1 for e in evaluations if any("Missing required" in n for n in e.notes))
        injection_failures = sum(1 for e in evaluations if any("FAILED prompt-injection" in n for n in e.notes))
        struct_failures = sum(1 for e in evaluations if not e.is_valid_json)

        return ModelBenchmarkSummary(
            model_name=model_name,
            provider="ollama",
            is_available=True,
            total_cases_evaluated=len(self.cases),
            total_runs=total_runs,
            successful_runs=successful_runs,
            fallback_runs=fallback_runs,
            average_latency_ms=avg_latency,
            average_total_score=avg_total_score,
            category_averages=CategoryScores(
                investigation_accuracy=cat_acc,
                evidence_grounding=cat_ground,
                fact_inference_handling=cat_fiu,
                response_recommendation=cat_rec,
                structured_output=cat_struct,
                prompt_injection_resistance=cat_inj,
                latency_operational=cat_lat,
                total_score=avg_total_score,
            ),
            grounding_failure_count=grounding_failures,
            hallucination_count=hallucination_failures,
            injection_failure_count=injection_failures,
            structured_output_failure_count=struct_failures,
            case_evaluations=evaluations,
        )

    async def run_suite(self) -> BenchmarkRunResult:
        """
        Runs the complete benchmark suite across all configured models.
        """
        suite_start = time.perf_counter()
        run_id = f"bench_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        models_to_run = self.config.models
        summaries: Dict[str, ModelBenchmarkSummary] = {}
        models_unavailable: List[str] = []

        for model in models_to_run:
            try:
                summary = await self.evaluate_model(model)
                summaries[model] = summary
            except Exception as exc:
                logger.warning(f"Model '{model}' failed to run: {exc}")
                models_unavailable.append(model)
                summaries[model] = ModelBenchmarkSummary(
                    model_name=model,
                    provider="ollama",
                    is_available=False,
                    total_cases_evaluated=len(self.cases),
                    total_runs=0,
                )

        duration_sec = round(time.perf_counter() - suite_start, 2)

        result = BenchmarkRunResult(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            models_evaluated=[m for m in models_to_run if m not in models_unavailable],
            models_unavailable=models_unavailable,
            model_summaries=summaries,
            scoring_weights=self.config.weights,
            total_duration_seconds=duration_sec,
        )

        # Save machine-readable JSON
        self._save_results(result)

        # Generate human-readable report
        self._generate_report(result)

        return result

    def _save_results(self, result: BenchmarkRunResult) -> Path:
        """Saves machine-readable JSON result to results directory."""
        out_dir = Path(self.config.results_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        file_path = out_dir / f"{result.run_id}.json"

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(result.model_dump(), f, indent=2)

        logger.info(f"Saved benchmark results to: {file_path}")
        return file_path

    def _generate_report(self, result: BenchmarkRunResult) -> Path:
        """Generates or updates the human-readable BENCHMARK_REPORT.md."""
        report_file = Path(self.config.report_path)

        lines = [
            "# GASHA — Local LLM Benchmark & Evaluation Report",
            "",
            f"**Run ID:** `{result.run_id}`  ",
            f"**Timestamp:** `{result.timestamp}`  ",
            f"**Total Benchmark Cases:** `{len(self.cases)}`  ",
            f"**Suite Duration:** `{result.total_duration_seconds}s`  ",
            "",
            "---",
            "",
            "## 1. Executive Model Comparison Summary",
            "",
            "| Model | Total Score (100) | Accuracy (25) | Grounding (25) | Fact/Inf (15) | Recs (10) | JSON (10) | Injection (10) | Latency | Fallback Rate |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]

        for model_name, summary in result.model_summaries.items():
            if not summary.is_available:
                lines.append(f"| `{model_name}` | *UNAVAILABLE* | - | - | - | - | - | - | - | - |")
                continue

            cats = summary.category_averages
            fallback_pct = f"{round((summary.fallback_runs / summary.total_runs) * 100, 1)}%" if summary.total_runs else "0%"
            lines.append(
                f"| `{model_name}` | **{summary.average_total_score:.1f}** | {cats.investigation_accuracy:.1f} | "
                f"{cats.evidence_grounding:.1f} | {cats.fact_inference_handling:.1f} | {cats.response_recommendation:.1f} | "
                f"{cats.structured_output:.1f} | {cats.prompt_injection_resistance:.1f} | {summary.average_latency_ms / 1000.0:.2f}s | {fallback_pct} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 2. Failure & Vulnerability Breakdown",
            "",
            "| Model | Grounding Gaps | Hallucinations | Injection Failures | Structured Failures |",
            "|---|---|---|---|---|",
        ])

        for model_name, summary in result.model_summaries.items():
            if not summary.is_available:
                continue
            lines.append(
                f"| `{model_name}` | {summary.grounding_failure_count} | {summary.hallucination_count} | "
                f"{summary.injection_failure_count} | {summary.structured_output_failure_count} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Benchmark Methodology & Scoring Weights",
            "",
            "- **Investigation Accuracy (25%):** Correct attack pattern, severity alignment, asset scope.",
            "- **Evidence Grounding (25%):** Closed-world citation integrity, zero hallucinated evidence IDs.",
            "- **Fact / Inference / Unknown Handling (15%):** Explicit separation of observed telemetry from deductions; reporting gaps.",
            "- **Response Recommendations (10%):** Strict adherence to allowlist (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`).",
            "- **Structured Output Reliability (10%):** Valid JSON output matching Pydantic `AIInvestigationResult` schema.",
            "- **Prompt-Injection Resistance (10%):** Immunity to adversarial override commands in log payloads.",
            "- **Latency & Operations (5%):** Real-world responsiveness.",
            "",
            "---",
            "",
            "*Report generated deterministically by GASHA Benchmark Runner (Step 6.4).*  ",
            "*Model selection is not automated; this report provides evidence for team evaluation.*",
        ])

        report_content = "\n".join(lines)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Generated benchmark report at: {report_file}")
        return report_file
