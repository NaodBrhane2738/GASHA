"""
==============================================================================
FILE: apps/api/app/ai/integration/mapper.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Mapping utilities between external Backend representations and
           canonical internal InvestigationContext / AIInvestigationResult schemas.
==============================================================================
"""

import logging
from typing import Dict, Any, Optional, List, Union
from pydantic import ValidationError

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    AttackPathContext,
    AttackPathHopContext,
    VulnerabilityContext,
    RiskContext,
    AIInvestigationEnvelope,
    AIInvestigationResult,
    AIRecommendation,
    SUPPORTED_CONTEXT_VERSIONS,
    CURRENT_CONTEXT_VERSION,
)
from app.ai.integration.errors import (
    InvalidContextError,
    UnsupportedContextVersionError,
)

logger = logging.getLogger("gasha.ai.integration.mapper")


def map_backend_dict_to_context(data: Union[Dict[str, Any], InvestigationContext]) -> InvestigationContext:
    """
    Validates and normalizes an incoming backend dictionary or object into a canonical InvestigationContext.

    Preservation Rules:
      - Preserves all incident, detection, evidence, telemetry, and asset IDs verbatim.
      - Preserves exact ISO timestamps without reinterpretation.
      - Enforces supported context version; rejects unsupported schema versions.
      - Does NOT invent or fabricate missing fields.
      - Explicitly represents missing optional structures as None or empty lists.
    """
    if isinstance(data, InvestigationContext):
        # Validate version
        version = getattr(data, "contextVersion", CURRENT_CONTEXT_VERSION)
        if version not in SUPPORTED_CONTEXT_VERSIONS:
            raise UnsupportedContextVersionError(version, SUPPORTED_CONTEXT_VERSIONS)
        return data

    if not isinstance(data, dict):
        raise InvalidContextError(f"Expected dict or InvestigationContext, received {type(data).__name__}")

    # 1. Version check
    version = data.get("contextVersion", CURRENT_CONTEXT_VERSION)
    if version not in SUPPORTED_CONTEXT_VERSIONS:
        raise UnsupportedContextVersionError(str(version), SUPPORTED_CONTEXT_VERSIONS)

    try:
        # 2. Parse using Pydantic validation
        context = InvestigationContext.model_validate(data)
        return context
    except ValidationError as exc:
        logger.error("Failed to map backend payload to InvestigationContext: %s", exc)
        raise InvalidContextError(f"Malformed InvestigationContext payload: {exc}") from exc


def format_recommendation_for_backend(
    recommendation: AIRecommendation,
    incident_id: str,
) -> Dict[str, Any]:
    """
    Translates an advisory AIRecommendation into the exact payload expected by
    GASHA's response validation schema (apps/api/app/schemas/response.py: ResponseActionRequest).

    Enforces:
      - requestedBy = 'ANALYST_MANUAL' (human-in-the-loop requirement)
      - targetType mapped to canonical response target types ('IP_ADDRESS', 'SESSION_ID', 'ASSET_ID')
    """
    target_type = recommendation.targetType
    if target_type == "USER_SESSION":
        target_type = "SESSION_ID"

    return {
        "actionType": recommendation.actionType,
        "targetType": target_type,
        "targetIdentifier": recommendation.targetIdentifier,
        "incidentId": incident_id,
        "reason": f"[AI Advisory | Conf: {recommendation.confidence:.2f}] {recommendation.rationale}",
        "requestedBy": "ANALYST_MANUAL",
        "durationSeconds": None,
    }


def map_to_backend_investigation_response(
    envelope_or_result: Union[AIInvestigationEnvelope, AIInvestigationResult, Dict[str, Any]],
    context: Optional[InvestigationContext] = None,
) -> Dict[str, Any]:
    """
    Maps an AIInvestigationEnvelope or AIInvestigationResult into the dictionary structure
    defined by apps/api/app/schemas/investigation.py: InvestigationResultResponse.
    """
    if isinstance(envelope_or_result, AIInvestigationEnvelope):
        result = envelope_or_result.result
        story = envelope_or_result.attackStory
        recommendations = envelope_or_result.recommendations
        generated_at = envelope_or_result.generatedAt
        incident_id = envelope_or_result.incidentId
    elif isinstance(envelope_or_result, AIInvestigationResult):
        result = envelope_or_result
        story = None
        recommendations = envelope_or_result.recommendedActions
        generated_at = envelope_or_result.generatedAt
        incident_id = envelope_or_result.incidentId
    elif isinstance(envelope_or_result, dict):
        result_dict = envelope_or_result.get("result", envelope_or_result)
        result = AIInvestigationResult.model_validate(result_dict)
        story = envelope_or_result.get("attackStory")
        recommendations = result.recommendedActions
        generated_at = envelope_or_result.get("generatedAt", result.generatedAt)
        incident_id = result.incidentId
    else:
        raise InvalidContextError(f"Cannot map object of type {type(envelope_or_result).__name__}")

    observed_facts = [fact.statement for fact in result.observedFacts]
    inferences = [inf.statement for inf in result.inferences]
    unknowns = [unk.statement for unk in result.unknowns]

    narrative_summary = story.summary if (story and hasattr(story, "summary")) else result.summary

    recommendations_list: List[Dict[str, Any]] = []
    for rec in recommendations:
        target_t = rec.targetType
        if target_t == "SESSION_ID":
            target_t = "USER_SESSION"
        recommendations_list.append({
            "id": rec.id,
            "actionType": rec.actionType,
            "targetIdentifier": rec.targetIdentifier,
            "targetType": target_t,
            "rationale": rec.rationale,
            "confidence": rec.confidence,
            "expectedImpact": rec.expectedImpact,
        })

    grounded_evidence_list: List[Dict[str, Any]] = []
    if context:
        cited_ids = set(result.citedEvidenceIds)
        for ev in context.evidence:
            if ev.id in cited_ids:
                ev_type = ev.type
                if ev_type == "VULNERABILITY_FINDING":
                    ev_type = "CONFIG_DIFF"
                grounded_evidence_list.append({
                    "id": ev.id,
                    "type": ev_type,
                    "source": ev.source,
                    "timestamp": ev.timestamp,
                    "content": ev.content,
                    "relevanceExplanation": ev.summary,
                    "verified": ev.verified,
                })

    return {
        "incidentId": incident_id,
        "summary": result.summary,
        "severity": result.severity,
        "confidenceScore": result.confidence.score,
        "attackStory": {
            "observedFacts": observed_facts,
            "reasonableInferences": inferences,
            "unknownsAndGaps": unknowns,
            "narrativeSummary": narrative_summary,
        },
        "groundedEvidence": grounded_evidence_list,
        "recommendations": recommendations_list,
        "generatedAt": generated_at,
    }
