"""
==============================================================================
FILE: apps/api/app/ai/evaluations/config.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Configuration settings, scoring weight distributions, and paths
           for the GASHA Local LLM Benchmark Suite.
TOOLS & LIBRARIES: Pydantic v2, Python standard library (os, pathlib)
KEY FEATURES:
  - BenchmarkConfig: Configurable candidate model list, repeat count, timeouts, and paths.
  - Configurable scoring weights with defaults (Accuracy 25, Grounding 25, etc.).
EXPECTED RESULTS / BEHAVIOR:
  - Enables flexible evaluation tuning without hardcoded scoring constants.
==============================================================================
"""

import os
from pathlib import Path
from typing import List, Dict
from pydantic import BaseModel, Field, ConfigDict

# Base directory for AI module
AI_MODULE_DIR = Path(__file__).resolve().parent.parent
EVALUATIONS_DIR = AI_MODULE_DIR / "evaluations"
RESULTS_DIR = EVALUATIONS_DIR / "results"
REPORT_PATH = EVALUATIONS_DIR / "BENCHMARK_REPORT.md"

# Ensure results directory exists
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_SCORING_WEIGHTS: Dict[str, float] = {
    "investigation_accuracy": 25.0,
    "evidence_grounding": 25.0,
    "fact_inference_handling": 15.0,
    "response_recommendation": 10.0,
    "structured_output": 10.0,
    "prompt_injection_resistance": 10.0,
    "latency_operational": 5.0,
}

# Candidate local models for evaluation
DEFAULT_CANDIDATE_MODELS: List[str] = [
    "qwen2.5-coder:7b",
    "qwen3.5:9b",
    "qwen3:8b",
    "deepseek-r1:8b",
    "ministral-8b:latest",
    "dolphin-llama3:8b",
]


class BenchmarkConfig(BaseModel):
    """Configuration options for a benchmark evaluation run."""
    models: List[str] = Field(
        default_factory=lambda: [os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")],
        description="List of Ollama model identifiers to benchmark",
    )
    runs_per_case: int = Field(
        default=1,
        ge=1,
        le=5,
        description="Number of repeated inference runs per test case to assess consistency",
    )
    timeout_seconds: float = Field(
        default=45.0,
        description="Per-case inference timeout in seconds",
    )
    weights: Dict[str, float] = Field(
        default_factory=lambda: DEFAULT_SCORING_WEIGHTS.copy(),
        description="Scoring weights across the 7 evaluation categories",
    )
    results_dir: str = Field(
        default=str(RESULTS_DIR),
        description="Directory where machine-readable JSON results will be persisted",
    )
    report_path: str = Field(
        default=str(REPORT_PATH),
        description="File path where human-readable markdown benchmark report will be generated",
    )

    model_config = ConfigDict(extra="ignore")
