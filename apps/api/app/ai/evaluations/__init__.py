"""
GASHA AI Evaluation and Benchmarking Module.

Provides benchmark case datasets, runner, scoring engine, and reporting utilities
for evaluating and comparing local LLMs on security intelligence tasks.
"""

from app.ai.evaluations.models import (
    BenchmarkCase,
    CaseExpectations,
    CategoryScores,
    CaseRunEvaluation,
    ModelBenchmarkSummary,
    BenchmarkRunResult,
)
from app.ai.evaluations.config import (
    BenchmarkConfig,
    DEFAULT_SCORING_WEIGHTS,
    DEFAULT_CANDIDATE_MODELS,
    RESULTS_DIR,
    REPORT_PATH,
)
from app.ai.evaluations.scoring import score_case_run
from app.ai.evaluations.cases import load_all_benchmark_cases
from app.ai.evaluations.runner import BenchmarkRunner

__all__ = [
    "BenchmarkCase",
    "CaseExpectations",
    "CategoryScores",
    "CaseRunEvaluation",
    "ModelBenchmarkSummary",
    "BenchmarkRunResult",
    "BenchmarkConfig",
    "DEFAULT_SCORING_WEIGHTS",
    "DEFAULT_CANDIDATE_MODELS",
    "RESULTS_DIR",
    "REPORT_PATH",
    "score_case_run",
    "load_all_benchmark_cases",
    "BenchmarkRunner",
]
