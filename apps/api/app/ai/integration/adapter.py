"""
==============================================================================
FILE: apps/api/app/ai/integration/adapter.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Primary production integration adapter for the GASHA AI module.
           Exposes clean investigate_incident() callable, validates context versions,
           and encapsulates internal provider mechanics and grounding validators.
==============================================================================
"""

import time
import uuid
import logging
from typing import Optional, Dict, Any, Union

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AIInvestigationEnvelope,
    AIInvestigationStatus,
    calculate_context_fingerprint,
)
from app.ai.pipeline import (
    get_pipeline,
    get_production_model_name,
)
from app.ai.attack_stories.generator import generate_attack_story
from app.ai.recommendations.generator import generate_recommendations
from app.ai.integration.mapper import map_backend_dict_to_context
from app.ai.integration.errors import (
    InvalidContextError,
    UnsupportedContextVersionError,
    AIUnavailableError,
    AITimeoutError,
)

logger = logging.getLogger("gasha.ai.integration.adapter")


async def ainvestigate_incident(
    context: Union[InvestigationContext, Dict[str, Any]],
    model: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> AIInvestigationResult:
    """
    Primary asynchronous production entry point for the GASHA incident pipeline.

    Signature:
        ainvestigate_incident(context: InvestigationContext) -> AIInvestigationResult

    Workflow:
      1. Validates and maps context payload (enforces supported contextVersion).
      2. Executes production investigation pipeline.
      3. Validates epistemic grounding and response allowlist.
      4. Returns structured, validated AIInvestigationResult.
    """
    canonical_context = map_backend_dict_to_context(context)
    pipeline = get_pipeline()
    return await pipeline.investigate(
        canonical_context,
        model=model or get_production_model_name(),
        provider_name=provider_name,
    )


def investigate_incident(
    context: Union[InvestigationContext, Dict[str, Any]],
    model: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> AIInvestigationResult:
    """
    Primary synchronous production entry point for the GASHA incident pipeline.

    Signature:
        investigate_incident(context: InvestigationContext) -> AIInvestigationResult
    """
    canonical_context = map_backend_dict_to_context(context)
    pipeline = get_pipeline()
    return pipeline.investigate_sync(
        canonical_context,
        model=model or get_production_model_name(),
        provider_name=provider_name,
    )


async def run_ai_investigation(
    context: Union[InvestigationContext, Dict[str, Any]],
    model: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> AIInvestigationEnvelope:
    """
    Full-envelope async integration entry point returning the complete versioned
    AIInvestigationEnvelope with result, attack story, and advisory recommendations.
    """
    canonical_context = map_backend_dict_to_context(context)
    incident_id = canonical_context.incident.id if canonical_context.incident else "UNKNOWN"
    context_fingerprint = calculate_context_fingerprint(canonical_context)
    target_model = model or get_production_model_name()
    inv_id = f"inv-{uuid.uuid4().hex[:12]}"

    start_time = time.perf_counter()
    pipeline = get_pipeline()

    investigation_result = await pipeline.investigate(
        context=canonical_context,
        model=target_model,
        provider_name=provider_name,
    )

    attack_story = generate_attack_story(investigation_result, canonical_context)
    recommendations = generate_recommendations(investigation_result, canonical_context)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    is_fallback = investigation_result.status in (
        "FALLBACK",
        "INVALID",
        "INVALID_OUTPUT",
        "UNAVAILABLE",
        "TIMEOUT",
    )

    status: AIInvestigationStatus = investigation_result.status
    if status == "SUCCESS" and not is_fallback:
        status = "COMPLETED"

    return AIInvestigationEnvelope(
        investigationId=inv_id,
        incidentId=incident_id,
        contextFingerprint=context_fingerprint,
        model=target_model,
        status=status,
        isFallback=is_fallback,
        result=investigation_result,
        attackStory=attack_story,
        recommendations=recommendations,
        executionDurationMs=round(elapsed_ms, 2),
    )


def run_ai_investigation_sync(
    context: Union[InvestigationContext, Dict[str, Any]],
    model: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> AIInvestigationEnvelope:
    """
    Full-envelope synchronous integration entry point.
    """
    canonical_context = map_backend_dict_to_context(context)
    incident_id = canonical_context.incident.id if canonical_context.incident else "UNKNOWN"
    context_fingerprint = calculate_context_fingerprint(canonical_context)
    target_model = model or get_production_model_name()
    inv_id = f"inv-{uuid.uuid4().hex[:12]}"

    start_time = time.perf_counter()
    pipeline = get_pipeline()

    investigation_result = pipeline.investigate_sync(
        context=canonical_context,
        model=target_model,
        provider_name=provider_name,
    )

    attack_story = generate_attack_story(investigation_result, canonical_context)
    recommendations = generate_recommendations(investigation_result, canonical_context)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    is_fallback = investigation_result.status in (
        "FALLBACK",
        "INVALID",
        "INVALID_OUTPUT",
        "UNAVAILABLE",
        "TIMEOUT",
    )

    status: AIInvestigationStatus = investigation_result.status
    if status == "SUCCESS" and not is_fallback:
        status = "COMPLETED"

    return AIInvestigationEnvelope(
        investigationId=inv_id,
        incidentId=incident_id,
        contextFingerprint=context_fingerprint,
        model=target_model,
        status=status,
        isFallback=is_fallback,
        result=investigation_result,
        attackStory=attack_story,
        recommendations=recommendations,
        executionDurationMs=round(elapsed_ms, 2),
    )


def is_context_stale(
    current_context: InvestigationContext,
    existing_envelope: AIInvestigationEnvelope,
) -> bool:
    """
    Idempotency & staleness checker.
    Returns True if current_context has diverged from the fingerprint recorded on existing_envelope.
    """
    current_fingerprint = calculate_context_fingerprint(current_context)
    return current_fingerprint != existing_envelope.contextFingerprint
