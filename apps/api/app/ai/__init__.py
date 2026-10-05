"""
GASHA AI Security Intelligence Module.

Provides input/output contracts, epistemic boundaries, grounding validation,
context builders, normalization, filtering, provider adapters (Ollama),
orchestration services, and local model evaluation benchmarks.
"""

from app.ai.contracts import (
    InvestigationContext,
    EvidenceItem,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    AttackPathContext,
    AttackPathHopContext,
    VulnerabilityContext,
    RiskContext,
    IncidentContext,
    AvailableActionContext,
    AIInvestigationResult,
    ObservedFact,
    Inference,
    Unknown,
    AttackProgressionItem,
    AIRecommendation,
    ConfidenceAssessment,
    AIInvestigationStatus,
    SeverityLevel,
    ResponseActionType,
    ResponseTargetType,
    AIInvestigationEnvelope,
    calculate_context_fingerprint,
)

from app.ai.validation import (
    ValidationOutcome,
    validate_investigation_result,
    check_evidence_citations,
    validate_recommendations,
    validate_asset_consistency,
    create_fallback_investigation_result,
)

from app.ai.context_builder import (
    build_investigation_context,
    ContextBuilderError,
    synthesize_canonical_evidence,
    validate_context_invariants,
)

from app.ai.context_normalizer import (
    normalize_incident,
    normalize_detection,
    normalize_telemetry_event,
    normalize_asset,
    normalize_attack_path,
    normalize_vulnerability,
    normalize_risk,
    normalize_evidence_item,
    scrub_secrets,
)

from app.ai.context_selectors import (
    extract_incident_asset_ids,
    select_relevant_detections,
    select_relevant_telemetry,
    select_relevant_attack_path,
    select_relevant_assets,
    select_relevant_vulnerabilities,
)

from app.ai.context_filters import (
    deduplicate_evidence,
    deduplicate_telemetry,
    filter_background_noise,
    filter_by_time_window,
    cap_and_prioritize_telemetry,
    sort_chronologically,
)

from app.ai.providers.base import (
    AIProvider,
    AIProviderStatus,
    ProviderConfig,
    AIProviderError,
    AIProviderConnectionError,
    AIProviderTimeoutError,
)

from app.ai.providers.ollama import (
    OllamaProvider,
    get_default_ollama_config,
)

from app.ai.providers.registry import (
    ProviderRegistry,
    register_provider,
    get_provider,
    get_default_provider,
)

from app.ai.prompts.investigation import (
    build_investigation_prompt,
    SYSTEM_INVESTIGATION_PROMPT,
)

from app.ai.service import (
    AIService,
    get_ai_service,
    parse_model_output,
    AIParserError,
)

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

from app.ai.pipeline import (
    ProductionInvestigationPipeline,
    get_pipeline,
    ainvestigate_incident,
    investigate_incident,
    run_full_investigation_pipeline,
    get_production_model_name,
    DEFAULT_PRODUCTION_MODEL,
)

from app.ai.attack_stories import (
    generate_attack_story,
    format_attack_story_markdown,
    format_attack_story_summary,
    convert_to_schema_attack_story,
    create_fallback_attack_story,
)

from app.ai.recommendations import (
    generate_recommendations,
    validate_recommendation,
    validate_recommendations_list,
    create_fallback_recommendations,
    format_recommendations_markdown,
)

from app.ai.contracts import (
    CURRENT_CONTEXT_VERSION,
    SUPPORTED_CONTEXT_VERSIONS,
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
    AIIntegrationError,
    InvalidContextError,
    UnsupportedContextVersionError,
    AIUnavailableError,
    AITimeoutError,
    InvalidAIOutputError,
    GroundingFailureError,
)

from app.ai.tests.e2e import (
    E2ETestHarness,
    E2ETestResult,
    CaseRunMetrics,
    get_all_e2e_cases,
)

__all__ = [
    # Contracts - Input
    "InvestigationContext",
    "EvidenceItem",
    "DetectionContext",
    "TelemetryEventContext",
    "AssetContext",
    "AttackPathContext",
    "AttackPathHopContext",
    "VulnerabilityContext",
    "RiskContext",
    "IncidentContext",
    "AvailableActionContext",
    # Contracts - Output
    "AIInvestigationResult",
    "ObservedFact",
    "Inference",
    "Unknown",
    "AttackProgressionItem",
    "AIRecommendation",
    "ConfidenceAssessment",
    "AIInvestigationStatus",
    "SeverityLevel",
    "ResponseActionType",
    "ResponseTargetType",
    # Validation
    "ValidationOutcome",
    "validate_investigation_result",
    "check_evidence_citations",
    "validate_recommendations",
    "validate_asset_consistency",
    "create_fallback_investigation_result",
    # Context Builder
    "build_investigation_context",
    "ContextBuilderError",
    "synthesize_canonical_evidence",
    "validate_context_invariants",
    # Normalizer
    "normalize_incident",
    "normalize_detection",
    "normalize_telemetry_event",
    "normalize_asset",
    "normalize_attack_path",
    "normalize_vulnerability",
    "normalize_risk",
    "normalize_evidence_item",
    "scrub_secrets",
    # Selectors
    "extract_incident_asset_ids",
    "select_relevant_detections",
    "select_relevant_telemetry",
    "select_relevant_attack_path",
    "select_relevant_assets",
    "select_relevant_vulnerabilities",
    # Filters
    "deduplicate_evidence",
    "deduplicate_telemetry",
    "filter_background_noise",
    "filter_by_time_window",
    "cap_and_prioritize_telemetry",
    "sort_chronologically",
    # Providers
    "AIProvider",
    "AIProviderStatus",
    "ProviderConfig",
    "AIProviderError",
    "AIProviderConnectionError",
    "AIProviderTimeoutError",
    "OllamaProvider",
    "get_default_ollama_config",
    "ProviderRegistry",
    "register_provider",
    "get_provider",
    "get_default_provider",
    # Prompts
    "build_investigation_prompt",
    "SYSTEM_INVESTIGATION_PROMPT",
    # Service
    "AIService",
    "get_ai_service",
    "parse_model_output",
    "AIParserError",
    # Evaluations
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
    # Production Pipeline
    "ProductionInvestigationPipeline",
    "get_pipeline",
    "ainvestigate_incident",
    "investigate_incident",
    "run_full_investigation_pipeline",
    "get_production_model_name",
    "DEFAULT_PRODUCTION_MODEL",
    # Attack Stories (Step 6.6)
    "AttackStory",
    "AttackStoryStage",
    "generate_attack_story",
    "format_attack_story_markdown",
    "format_attack_story_summary",
    "convert_to_schema_attack_story",
    "create_fallback_attack_story",
    # Defensive Recommendations (Step 6.6)
    "generate_recommendations",
    "validate_recommendation",
    "validate_recommendations_list",
    "create_fallback_recommendations",
    "format_recommendations_markdown",
    # Backend Integration & Handoff (Step 6.8 & 6.10)
    "CURRENT_CONTEXT_VERSION",
    "SUPPORTED_CONTEXT_VERSIONS",
    "AIInvestigationEnvelope",
    "calculate_context_fingerprint",
    "investigate_incident",
    "ainvestigate_incident",
    "run_ai_investigation",
    "run_ai_investigation_sync",
    "is_context_stale",
    "map_backend_dict_to_context",
    "format_recommendation_for_backend",
    "map_to_backend_investigation_response",
    "AIIntegrationError",
    "InvalidContextError",
    "UnsupportedContextVersionError",
    "AIUnavailableError",
    "AITimeoutError",
    "InvalidAIOutputError",
    "GroundingFailureError",
    # E2E Validation (Step 6.9)
    "E2ETestHarness",
    "E2ETestResult",
    "CaseRunMetrics",
    "get_all_e2e_cases",
]
