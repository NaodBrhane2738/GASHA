"""
==============================================================================
FILE: apps/api/app/ai/service.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Core AI orchestration service that coordinates prompt formatting,
           provider inference, structured parsing, grounding validation,
           and deterministic fallback generation.
TOOLS & LIBRARIES: asyncio, json, re, Pydantic v2
KEY FEATURES:
  - AIService: Main orchestration class for AI investigations.
  - parse_model_output(): Robust extraction of JSON from raw model text, handling markdown fences.
  - Bounded concurrency control via asyncio.Semaphore.
  - Strict validation against AIInvestigationResult and validate_investigation_result().
  - Deterministic fallback generation on provider errors, timeouts, or validation failures.
EXPECTED RESULTS / BEHAVIOR:
  - Guarantees that unvalidated or hallucinated model outputs are never returned to downstream callers.
==============================================================================
"""

import re
import json
import time
import asyncio
import logging
from typing import Optional, Dict, Any, Union

from pydantic import ValidationError

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AIInvestigationStatus,
)
from app.ai.validation import (
    validate_investigation_result,
    create_fallback_investigation_result,
    ValidationOutcome,
)
from app.ai.prompts.investigation import build_investigation_prompt
from app.ai.providers.base import (
    AIProvider,
    AIProviderStatus,
    AIProviderError,
    AIProviderConnectionError,
    AIProviderTimeoutError,
)
from app.ai.providers.registry import get_provider, get_default_provider

logger = logging.getLogger("gasha.ai.service")

# Regex to strip markdown code fences: ```json ... ``` or ``` ... ```
JSON_FENCE_REGEX = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)


class AIParserError(ValueError):
    """Raised when model output cannot be extracted or parsed as valid JSON."""
    pass


def parse_model_output(raw_text: str) -> Dict[str, Any]:
    """
    Extracts and parses JSON object from raw model response text.
    Handles raw JSON, markdown code blocks, and embedded JSON objects.
    """
    if not raw_text or not raw_text.strip():
        raise AIParserError("Model returned empty or whitespace-only output.")

    cleaned = raw_text.strip()

    # 1. Try markdown code block extraction
    fence_match = JSON_FENCE_REGEX.search(cleaned)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # 2. Try direct JSON parsing
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # 3. Try finding first '{' and last '}'
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidate = cleaned[first_brace : last_brace + 1]
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError as exc:
            raise AIParserError(f"Failed to parse JSON substring from model output: {exc}") from exc

    raise AIParserError(f"Could not find valid JSON object in model response: '{raw_text[:200]}...'")


class AIService:
    """
    Orchestration service for AI-assisted security investigations in GASHA.
    """

    def __init__(
        self,
        default_provider: Optional[AIProvider] = None,
        max_concurrent_requests: int = 5,
    ):
        self._default_provider = default_provider
        self._semaphore = asyncio.Semaphore(max_concurrent_requests)

    def _get_provider(self, provider_name: Optional[str] = None) -> AIProvider:
        """Resolves target provider instance."""
        if provider_name:
            return get_provider(provider_name)
        if self._default_provider:
            return self._default_provider
        return get_default_provider()

    async def investigate(
        self,
        context: InvestigationContext,
        model: Optional[str] = None,
        provider_name: Optional[str] = None,
    ) -> AIInvestigationResult:
        """
        Executes a complete AI investigation on an InvestigationContext.

        Steps:
        1. Acquire bounded concurrency lock.
        2. Format prompt pair (system, user with delimited context).
        3. Call provider inference.
        4. Parse raw output into structured dictionary.
        5. Validate against Pydantic AIInvestigationResult model.
        6. Apply grounding, allowlist, and safety validation.
        7. Return validated AIInvestigationResult OR deterministic fallback.
        """
        provider = self._get_provider(provider_name)
        target_model = model or provider.default_model

        # Handle empty evidence up front
        if not context.evidence and not context.detections:
            logger.info(
                f"InvestigationContext for incident {context.incident.id} has no evidence/detections; returning insufficient evidence fallback."
            )
            return create_fallback_investigation_result(
                context=context,
                status="INSUFFICIENT_EVIDENCE",
                reason="Incident contains zero telemetry events or detection triggers.",
            )

        t0 = time.perf_counter()
        system_prompt, user_prompt = build_investigation_prompt(context)
        t_prompt_built = time.perf_counter()

        async with self._semaphore:
            try:
                logger.info(
                    f"Dispatching investigation for incident '{context.incident.id}' to provider '{provider.provider_name}' (model: '{target_model}')"
                )
                raw_output = await provider.generate_investigation(
                    prompt=user_prompt,
                    system_prompt=system_prompt,
                    model=target_model,
                    format_json=True,
                )
            except AIProviderConnectionError as exc:
                logger.error(f"Provider connection error for incident {context.incident.id}: {exc}")
                return create_fallback_investigation_result(
                    context=context,
                    status="UNAVAILABLE",
                    reason=f"AI provider connection failed: {exc}",
                )
            except AIProviderTimeoutError as exc:
                logger.error(f"Provider timeout for incident {context.incident.id}: {exc}")
                return create_fallback_investigation_result(
                    context=context,
                    status="UNAVAILABLE",
                    reason=f"AI provider request timed out: {exc}",
                )
            except Exception as exc:
                logger.error(f"Unexpected provider error for incident {context.incident.id}: {exc}")
                return create_fallback_investigation_result(
                    context=context,
                    status="UNAVAILABLE",
                    reason=f"AI inference error: {exc}",
                )

        t_inference_done = time.perf_counter()
        inference_ms = (t_inference_done - t_prompt_built) * 1000.0
        logger.debug(f"Received raw model output in {inference_ms:.1f}ms for incident {context.incident.id}")

        # --------------------------------------------------------------------
        # Parse Structured Output
        # --------------------------------------------------------------------
        try:
            parsed_dict = parse_model_output(raw_output)
        except AIParserError as exc:
            logger.warning(f"JSON parsing failed for incident {context.incident.id}: {exc}")
            return create_fallback_investigation_result(
                context=context,
                status="INVALID",
                reason=f"Model output parsing error: {exc}",
            )

        t_parsed = time.perf_counter()

        # --------------------------------------------------------------------
        # Schema Validation (Pydantic)
        # --------------------------------------------------------------------
        try:
            # Ensure incidentId matches context
            parsed_dict["incidentId"] = context.incident.id
            investigation_result = AIInvestigationResult(**parsed_dict)
        except ValidationError as exc:
            logger.warning(f"Schema validation failed for incident {context.incident.id}: {exc}")
            return create_fallback_investigation_result(
                context=context,
                status="INVALID",
                reason=f"Model output failed schema validation: {exc}",
            )

        # --------------------------------------------------------------------
        # Grounding, Allowlist, & Authoritative Ledger Validation
        # --------------------------------------------------------------------
        outcome = validate_investigation_result(context, investigation_result)
        if not outcome.isValid:
            errors_str = "; ".join(outcome.errors)
            logger.warning(
                f"Grounding validation rejected model result for incident {context.incident.id}: {errors_str}"
            )
            return create_fallback_investigation_result(
                context=context,
                status="INVALID",
                reason=f"Evidence grounding validation failed: {errors_str}",
            )

        final_result = outcome.validatedResult or investigation_result
        total_ms = (time.perf_counter() - t0) * 1000.0
        logger.info(
            f"AI investigation successfully validated for incident '{context.incident.id}' | total={total_ms:.1f}ms | inference={inference_ms:.1f}ms"
        )
        return final_result

    def investigate_sync(
        self,
        context: InvestigationContext,
        model: Optional[str] = None,
        provider_name: Optional[str] = None,
    ) -> AIInvestigationResult:
        """Synchronous wrapper for investigate()."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            # If called within existing running loop, use thread pool runner
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, self.investigate(context, model, provider_name))
                return future.result()
        else:
            return loop.run_until_complete(self.investigate(context, model, provider_name))

    async def check_health(self, provider_name: Optional[str] = None) -> AIProviderStatus:
        """Checks health and model availability for the target provider."""
        provider = self._get_provider(provider_name)
        return await provider.health_check()


# Global default service instance
_service_instance: Optional[AIService] = None


def get_ai_service() -> AIService:
    """Returns singleton AIService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = AIService()
    return _service_instance
