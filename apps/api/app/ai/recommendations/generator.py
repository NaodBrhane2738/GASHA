"""
==============================================================================
FILE: apps/api/app/ai/recommendations/generator.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Core generator for evidence-grounded defensive recommendations.
           Filters, validates, prioritizes, and bounds response actions to the
           smallest justified set adhering strictly to the allowlist.
TOOLS & LIBRARIES: Python standard library, logging
==============================================================================
"""

import logging
from typing import List, Dict, Tuple

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AIRecommendation,
)
from app.ai.recommendations.validator import validate_recommendation
from app.ai.recommendations.fallback import create_fallback_recommendations

logger = logging.getLogger("gasha.ai.recommendations")

MAX_RECOMMENDED_ACTIONS = 3


def generate_recommendations(
    investigation_result: AIInvestigationResult,
    context: InvestigationContext,
) -> List[AIRecommendation]:
    """
    Produces a bounded, verified list of defensive response recommendations
    from a validated AIInvestigationResult and InvestigationContext.

    Principles:
      1. Strict allowlist adherence (BLOCK_SOURCE, DISABLE_SESSION, ISOLATE_RESOURCE).
      2. Minimum necessary action (prefer 1 strong action over multiple weak ones).
      3. Strict evidence grounding (no fabricated IDs, no arbitrary commands).
      4. Advisory-only (never triggers execution; requires human operator approval).
    """
    if not isinstance(investigation_result, AIInvestigationResult) or not isinstance(context, InvestigationContext):
        raise ValueError("Invalid argument types passed to generate_recommendations.")

    # If investigation was not successful, invoke fallback recommendation generator
    if investigation_result.status != "SUCCESS":
        logger.info(
            "InvestigationResult status is '%s'; delegating to fallback recommendation generator.",
            investigation_result.status,
        )
        return create_fallback_recommendations(
            context=context,
            reason=investigation_result.errorMessage or f"Status: {investigation_result.status}",
        )

    raw_recs = investigation_result.recommendedActions or []
    valid_recs: List[AIRecommendation] = []

    # 1. Validate each candidate recommendation
    for rec in raw_recs:
        is_valid, errors = validate_recommendation(rec, context)
        if is_valid:
            valid_recs.append(rec)
        else:
            logger.warning("Rejected ungrounded or invalid recommendation '%s': %s", rec.id, "; ".join(errors))

    # 2. Minimum Necessary Action & De-duplication
    # Deduplicate by targetIdentifier (keep highest confidence)
    target_map: Dict[Tuple[str, str], AIRecommendation] = {}
    for rec in valid_recs:
        key = (rec.actionType, rec.targetIdentifier)
        if key not in target_map or rec.confidence > target_map[key].confidence:
            target_map[key] = rec

    deduped_recs = list(target_map.values())

    # 3. Sort by priority and confidence, bounding to MAX_RECOMMENDED_ACTIONS
    prio_weight = {"IMMEDIATE": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    deduped_recs.sort(
        key=lambda r: (prio_weight.get(r.priority or "HIGH", 2), r.confidence),
        reverse=True,
    )

    final_recs = deduped_recs[:MAX_RECOMMENDED_ACTIONS]

    # If LLM proposed no valid actions, attempt fallback only if high severity
    if not final_recs and context.incident and context.incident.severity in ["HIGH", "CRITICAL"]:
        logger.info("No validated LLM recommendations; attempting deterministic fallback recommendations.")
        final_recs = create_fallback_recommendations(context, reason="No validated LLM actions provided.")

    return final_recs
