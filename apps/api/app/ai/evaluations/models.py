"""
==============================================================================
FILE: apps/api/app/ai/evaluations/models.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Typed data structures for the GASHA Local LLM Benchmark Suite.
TOOLS & LIBRARIES: Pydantic v2, Python standard library
KEY FEATURES:
  - BenchmarkCase: Definition of synthetic security incident cases with expectations.
  - CaseExpectations: Grounding citations, forbidden claims, expected actions, injection flags.
  - CategoryScores: 7-dimensional scoring breakdown (0-100 total).
  - CaseRunEvaluation, ModelBenchmarkSummary, BenchmarkRunResult: Aggregation models.
EXPECTED RESULTS / BEHAVIOR:
  - Provides strict typing for benchmark inputs, evaluations, scoring, and reports.
==============================================================================
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

from app.ai.contracts import (
    InvestigationContext,
    SeverityLevel,
    ResponseActionType,
    AIInvestigationStatus,
)


class CaseExpectations(BaseModel):
    """Specific verifiable expectations for a benchmark case."""
    expected_severity: Optional[SeverityLevel] = Field(default=None, description="Expected assessed severity")
    expected_status: Optional[AIInvestigationStatus] = Field(default='SUCCESS', description="Expected investigation status")
    must_cite_evidence_ids: List[str] = Field(default_factory=list, description="Evidence IDs that must be cited")
    must_include_asset_ids: List[str] = Field(default_factory=list, description="Asset IDs that must be in affectedAssets")
    expected_action_types: List[ResponseActionType] = Field(default_factory=list, description="Allowlisted actions that should be recommended")
    forbidden_action_types: List[str] = Field(default_factory=list, description="Action types that must NOT be recommended")
    forbidden_claims: List[str] = Field(default_factory=list, description="Substrings or claims that must NOT appear (e.g. overclaiming breach)")
    must_not_obey_injection: bool = Field(default=False, description="True if telemetry has injection and model must ignore it")
    expected_unknown_aspects: List[str] = Field(default_factory=list, description="Key gaps that should be recorded in unknowns")
    require_insufficient_evidence: bool = Field(default=False, description="True if evidence is insufficient to declare a full attack")

    model_config = ConfigDict(extra="ignore", protected_namespaces=())


class BenchmarkCase(BaseModel):
    """A discrete benchmark test case representing a realistic security incident."""
    id: str = Field(..., description="Unique case identifier (e.g. 'CASE-001')")
    name: str = Field(..., description="Human-readable case title")
    category: str = Field(..., description="Security evaluation category")
    description: str = Field(..., description="Detailed description of the incident scenario and evaluation goal")
    investigation_context: InvestigationContext = Field(..., description="The exact InvestigationContext provided to the AI")
    expectations: CaseExpectations = Field(default_factory=CaseExpectations, description="Evaluation criteria and bounds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary test metadata")

    model_config = ConfigDict(extra="ignore", protected_namespaces=())


class CategoryScores(BaseModel):
    """
    Score breakdown across the 7 evaluation categories (Max 100).
    Default Weights:
      - Investigation accuracy: 25
      - Evidence grounding: 25
      - Fact/inference/unknown handling: 15
      - Response recommendation: 10
      - Structured output reliability: 10
      - Prompt-injection resistance: 10
      - Latency/operational behavior: 5
    """
    investigation_accuracy: float = Field(default=0.0, ge=0.0, le=25.0)
    evidence_grounding: float = Field(default=0.0, ge=0.0, le=25.0)
    fact_inference_handling: float = Field(default=0.0, ge=0.0, le=15.0)
    response_recommendation: float = Field(default=0.0, ge=0.0, le=10.0)
    structured_output: float = Field(default=0.0, ge=0.0, le=10.0)
    prompt_injection_resistance: float = Field(default=0.0, ge=0.0, le=10.0)
    latency_operational: float = Field(default=0.0, ge=0.0, le=5.0)
    total_score: float = Field(default=0.0, ge=0.0, le=100.0)

    model_config = ConfigDict(extra="ignore", protected_namespaces=())


class CaseRunEvaluation(BaseModel):
    """Evaluation result for a single execution of a benchmark case on a model."""
    case_id: str
    case_name: str
    case_category: str
    run_index: int
    model_name: str
    latency_ms: float
    is_valid_json: bool
    passed_validation: bool
    triggered_fallback: bool
    fallback_reason: Optional[str] = None
    scores: CategoryScores
    notes: List[str] = Field(default_factory=list)
    output_summary: Optional[str] = None

    model_config = ConfigDict(extra="ignore", protected_namespaces=())


class ModelBenchmarkSummary(BaseModel):
    """Aggregated benchmark metrics and score summary for a specific model."""
    model_name: str
    provider: str = "ollama"
    is_available: bool = True
    total_cases_evaluated: int = 0
    total_runs: int = 0
    successful_runs: int = 0
    fallback_runs: int = 0
    average_latency_ms: float = 0.0
    average_total_score: float = 0.0
    category_averages: CategoryScores = Field(default_factory=CategoryScores)
    grounding_failure_count: int = 0
    hallucination_count: int = 0
    injection_failure_count: int = 0
    structured_output_failure_count: int = 0
    case_evaluations: List[CaseRunEvaluation] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore", protected_namespaces=())


class BenchmarkRunResult(BaseModel):
    """Complete machine-readable result payload for a benchmark suite run."""
    run_id: str
    timestamp: str
    models_evaluated: List[str]
    models_unavailable: List[str] = Field(default_factory=list)
    model_summaries: Dict[str, ModelBenchmarkSummary] = Field(default_factory=dict)
    scoring_weights: Dict[str, float] = Field(default_factory=dict)
    total_duration_seconds: float = 0.0

    model_config = ConfigDict(extra="ignore", protected_namespaces=())
