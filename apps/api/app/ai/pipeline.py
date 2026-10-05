"""
==============================================================================
FILE: apps/api/app/ai/pipeline.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Production AI Investigation Pipeline for GASHA.
           Coordinates InvestigationContext intake, production model resolution,
           prompt assembly, local provider inference, structured JSON extraction,
           evidence grounding validation, and deterministic safe fallback handling.
TOOLS & LIBRARIES: asyncio, os, time, logging, Pydantic v2
KEY FEATURES:
  - ProductionInvestigationPipeline: Production-grade investigation orchestrator.
  - get_production_model_name(): Resolves operator-chosen model from environment.
  - ainvestigate_incident() / investigate_incident(): Main pipeline entry points.
  - Strict grounding & allowlist validation preventing hallucinations and unapproved actions.
  - Non-destructive execution: Analysis-only, zero state mutation, advisory-only actions.
  - Safe operational logging without leaking telemetry payloads or credentials.
==============================================================================
"""

import os
import time
import asyncio
import logging
from typing import Optional, Dict, Any

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AIInvestigationStatus,
    AttackStory,
    AIRecommendation,
)
from app.ai.service import AIService, get_ai_service
from app.ai.providers.base import AIProviderStatus
from app.ai.validation import create_fallback_investigation_result
from app.ai.attack_stories.generator import generate_attack_story
from app.ai.recommendations.generator import generate_recommendations

logger = logging.getLogger("gasha.ai.pipeline")

# Default production model if not overridden by human operator in environment
DEFAULT_PRODUCTION_MODEL = "qwen2.5-coder:7b"


def get_production_model_name() -> str:
    """
    Resolves the production local model configured by the operator.
    Checks environment variables in order:
      1. AI_PRODUCTION_MODEL (explicit production model setting)
      2. OLLAMA_MODEL (standard Ollama model setting)
      3. AI_MODEL_NAME (generic model setting)
      4. DEFAULT_PRODUCTION_MODEL ("qwen2.5-coder:7b")
    """
    model_name = (
        os.getenv("AI_PRODUCTION_MODEL")
        or os.getenv("OLLAMA_MODEL")
        or os.getenv("AI_MODEL_NAME")
        or DEFAULT_PRODUCTION_MODEL
    )
    return model_name.strip()


class ProductionInvestigationPipeline:
    """
    Production-grade AI Investigation Pipeline.

    Orchestrates the complete lifecycle of an AI-assisted security investigation:
      1. Context Validation: Ensures valid InvestigationContext schema.
      2. Model Resolution: Uses operator-chosen local model.
      3. Prompt Assembly: Formats isolated, injection-resistant prompt pair.
      4. Local Inference: Calls local provider (Ollama) with bounded concurrency.
      5. Structured Parsing: Extracts and parses JSON from raw model text.
      6. Epistemic Validation: Verifies evidence grounding, asset consistency, and action allowlist.
      7. Safe Fallback: Returns deterministic fallback on any error, timeout, or validation failure.
      8. Non-destructive Guarantee: Never mutates state or executes response actions.
    """

    def __init__(
        self,
        ai_service: Optional[AIService] = None,
        max_concurrent_requests: int = 5,
    ):
        self._service = ai_service or get_ai_service()
        self._max_concurrent = max_concurrent_requests

    @property
    def service(self) -> AIService:
        return self._service

    async def investigate(
        self,
        context: InvestigationContext,
        model: Optional[str] = None,
        provider_name: Optional[str] = None,
    ) -> AIInvestigationResult:
        """
        Executes an end-to-end AI investigation for the given incident context.

        Args:
            context: Verified InvestigationContext constructed by context_builder.
            model: Optional model override. Defaults to configured production model.
            provider_name: Optional provider override (e.g. "ollama"). Defaults to default provider.

        Returns:
            Validated AIInvestigationResult or safe deterministic fallback.
        """
        if not isinstance(context, InvestigationContext):
            logger.error("Production pipeline received invalid context type: %s", type(context))
            raise ValueError(f"Expected InvestigationContext, received {type(context).__name__}")

        incident_id = context.incident.id if context.incident else "UNKNOWN"
        target_model = model or get_production_model_name()

        logger.info(
            "Starting production AI investigation for incident '%s' using model '%s'",
            incident_id,
            target_model,
        )
        start_time = time.perf_counter()

        try:
            result = await self._service.investigate(
                context=context,
                model=target_model,
                provider_name=provider_name,
            )
        except Exception as exc:
            logger.exception(
                "Unhandled error in production investigation pipeline for incident '%s': %s",
                incident_id,
                exc,
            )
            result = create_fallback_investigation_result(
                context=context,
                status="UNAVAILABLE",
                reason=f"Pipeline execution failure: {exc}",
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Safe operational logging (no sensitive payload or secret data)
        logger.info(
            "Completed AI investigation for incident '%s' | status=%s | severity=%s | citations=%d | actions=%d | duration=%.1fms",
            incident_id,
            result.status,
            result.severity,
            len(result.citedEvidenceIds),
            len(result.recommendedActions),
            elapsed_ms,
        )

        return result

    def investigate_sync(
        self,
        context: InvestigationContext,
        model: Optional[str] = None,
        provider_name: Optional[str] = None,
    ) -> AIInvestigationResult:
        """
        Synchronous execution entry point for production AI investigation.
        """
        return self._service.investigate_sync(
            context=context,
            model=model or get_production_model_name(),
            provider_name=provider_name,
        )

    async def check_health(self, provider_name: Optional[str] = None) -> AIProviderStatus:
        """
        Checks operational readiness of the underlying AI provider.
        """
        return await self._service.check_health(provider_name=provider_name)


# Global singleton pipeline instance
_pipeline_instance: Optional[ProductionInvestigationPipeline] = None


def get_pipeline() -> ProductionInvestigationPipeline:
    """Returns singleton ProductionInvestigationPipeline instance."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = ProductionInvestigationPipeline()
    return _pipeline_instance


async def ainvestigate_incident(
    context: InvestigationContext,
    model: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> AIInvestigationResult:
    """
    Convenience async function to run production AI investigation.
    """
    pipeline = get_pipeline()
    return await pipeline.investigate(context, model=model, provider_name=provider_name)


def investigate_incident(
    context: InvestigationContext,
    model: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> AIInvestigationResult:
    """
    Convenience synchronous function to run production AI investigation.
    """
    pipeline = get_pipeline()
    return pipeline.investigate_sync(context, model=model, provider_name=provider_name)


async def run_full_investigation_pipeline(
    context: InvestigationContext,
    model: Optional[str] = None,
    provider_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the complete Step 6.6 pipeline:
      InvestigationContext
      -> Validated AIInvestigationResult
      -> Structured AttackStory
      -> Evidence-Grounded Recommendations (Advisory Only)

    Returns dictionary containing all three validated artifacts.
    """
    investigation_result = await ainvestigate_incident(context, model=model, provider_name=provider_name)
    attack_story = generate_attack_story(investigation_result, context)
    recommendations = generate_recommendations(investigation_result, context)

    return {
        "investigationResult": investigation_result,
        "attackStory": attack_story,
        "recommendations": recommendations,
    }

