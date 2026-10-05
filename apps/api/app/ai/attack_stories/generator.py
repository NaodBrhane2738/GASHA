"""
==============================================================================
FILE: apps/api/app/ai/attack_stories/generator.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Core generator for evidence-grounded AttackStory narratives.
           Synthesizes chronologically structured, strictly grounded attack
           stories from validated AIInvestigationResults and InvestigationContexts.
TOOLS & LIBRARIES: Python standard library, Pydantic v2
==============================================================================
"""

import logging
from typing import List, Set, Optional
from datetime import datetime, timezone

from app.ai.semantic_validator import normalize_attack_phase
from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AttackStory,
    AttackStoryStage,
    ObservedFact,
    Inference,
    Unknown,
)
from app.ai.attack_stories.fallback import create_fallback_attack_story

logger = logging.getLogger("gasha.ai.attack_stories")


def generate_attack_story(
    investigation_result: AIInvestigationResult,
    context: InvestigationContext,
) -> AttackStory:
    """
    Generates a structured, evidence-grounded AttackStory from a validated
    AIInvestigationResult and its parent InvestigationContext.

    Guarantees:
      1. Chronological order of attack stages.
      2. 100% evidence citation grounding (no hallucinated IDs).
      3. Strict preservation of facts vs inferences vs unknowns.
      4. Explicit uncertainty declaration for unobserved stages.
      5. Precise distinction between attempted attacks and successful compromises.
    """
    if not isinstance(investigation_result, AIInvestigationResult) or not isinstance(context, InvestigationContext):
        raise ValueError("Invalid argument types passed to generate_attack_story.")

    # If the investigation result is not SUCCESS, return deterministic fallback
    if investigation_result.status != "SUCCESS":
        logger.info(
            "InvestigationResult for incident '%s' has status '%s'; returning fallback attack story.",
            investigation_result.incidentId,
            investigation_result.status,
        )
        return create_fallback_attack_story(
            context=context,
            reason=investigation_result.errorMessage or f"AI investigation status was {investigation_result.status}.",
        )

    valid_evidence_ids = context.get_all_evidence_ids()
    valid_asset_ids = context.get_all_asset_ids()

    # Build evidence timestamp lookup map
    evidence_time_map = {}
    for ev in context.evidence:
        evidence_time_map[ev.id] = ev.timestamp
    for det in context.detections:
        evidence_time_map[det.id] = det.timestamp
    for te in context.telemetryEvents:
        evidence_time_map[te.id] = te.timestamp

    # ------------------------------------------------------------------------
    # 1. Synthesize Chronological Stages
    # ------------------------------------------------------------------------
    stages: List[AttackStoryStage] = []
    cited_story_evidence: Set[str] = set()

    if investigation_result.attackProgression:
        # Sort progression steps by stepOrder
        sorted_steps = sorted(investigation_result.attackProgression, key=lambda s: s.stepOrder)
        for idx, step in enumerate(sorted_steps, start=1):
            # Filter evidence IDs to strictly valid items
            grounded_eids = [eid for eid in step.evidenceIds if eid in valid_evidence_ids]
            cited_story_evidence.update(grounded_eids)

            # Determine timestamp
            ts = step.timestamp
            if not ts and grounded_eids:
                ts = evidence_time_map.get(grounded_eids[0])

            # Determine attempt status
            is_attempt = step.isAttemptOnly or any(
                kw in step.description.lower()
                for kw in [
                    "attempt", "failure", "failed", "denied", "blocked", "forbidden",
                    "probe", "scan", "scanning", "401", "403", "400", "waf", "rejected",
                    "unsuccessful", "adversarial injection", "injection pattern", "injection payload"
                ]
            )
            if investigation_result.compromiseAssessment in ("ATTEMPT_ONLY", "NOT_ESTABLISHED"):
                # If compromise is not established, treat hostile probing steps as attempts
                if any(kw in step.description.lower() for kw in ["injection", "probe", "scan", "auth", "login", "traversal", "attack"]):
                    is_attempt = True

            # Assets
            affected_assets = []
            if step.targetAssetId and step.targetAssetId in valid_asset_ids:
                affected_assets.append(step.targetAssetId)

            stages.append(
                AttackStoryStage(
                    order=idx,
                    timestamp=ts,
                    phase=normalize_attack_phase(step.phase),
                    description=step.description,
                    affectedAssetIds=affected_assets,
                    evidenceIds=grounded_eids,
                    isAttemptOnly=is_attempt,
                )
            )

    # If attackProgression was empty or produced no stages, derive from observedFacts
    if not stages and investigation_result.observedFacts:
        for idx, fact in enumerate(investigation_result.observedFacts, start=1):
            grounded_eids = [eid for eid in fact.evidenceIds if eid in valid_evidence_ids]
            cited_story_evidence.update(grounded_eids)
            ts = evidence_time_map.get(grounded_eids[0]) if grounded_eids else None

            is_attempt = any(
                kw in fact.statement.lower()
                for kw in [
                    "attempt", "failure", "failed", "denied", "blocked", "forbidden",
                    "probe", "scan", "scanning", "401", "403", "400", "waf", "rejected",
                    "unsuccessful", "adversarial injection", "injection pattern", "injection payload"
                ]
            )
            if investigation_result.compromiseAssessment in ("ATTEMPT_ONLY", "NOT_ESTABLISHED"):
                if any(kw in fact.statement.lower() for kw in ["injection", "probe", "scan", "auth", "login", "traversal", "waf", "adversarial"]):
                    is_attempt = True

            stages.append(
                AttackStoryStage(
                    order=idx,
                    timestamp=ts,
                    phase="Observed Activity",
                    description=fact.statement,
                    affectedAssetIds=[],
                    evidenceIds=grounded_eids,
                    isAttemptOnly=is_attempt,
                )
            )

    # ------------------------------------------------------------------------
    # 2. Synthesize Uncertainty and Limitations (Normalized & Deduplicated)
    # ------------------------------------------------------------------------
    raw_uncertainty_points: List[str] = []

    # Check for explicit unknowns
    for unk in investigation_result.unknowns:
        raw_uncertainty_points.append(unk.statement)

    # Check for confidence limitations
    for lim in investigation_result.confidence.limitations:
        raw_uncertainty_points.append(lim)

    # If no exfiltration or compromise proof is present in evidence, state clearly
    has_exfil_evidence = any(
        "exfil" in (ev.summary + " " + str(ev.content)).lower()
        for ev in context.evidence
    )
    if not has_exfil_evidence:
        raw_uncertainty_points.append(
            "Successful compromise or data exfiltration is not established by the supplied evidence."
        )

    # Normalize & Deduplicate uncertainty sentences
    def _norm_statement(s: str) -> str:
        return s.strip().rstrip(".").lower()

    seen_norm = set()
    deduped_uncertainty_points: List[str] = []
    for pt in raw_uncertainty_points:
        norm = _norm_statement(pt)
        if norm and norm not in seen_norm:
            seen_norm.add(norm)
            clean_pt = pt.strip().rstrip(".") + "."
            deduped_uncertainty_points.append(clean_pt)

    uncertainty_str = " ".join(deduped_uncertainty_points) if deduped_uncertainty_points else (
        "Investigation relies strictly on available telemetry; intermediate unlogged traversal steps remain unobserved."
    )

    # ------------------------------------------------------------------------
    # 3. Assemble Title and Summary
    # ------------------------------------------------------------------------
    incident_title = context.incident.title if context.incident else "Security Incident"
    title = f"{incident_title}"
    summary = investigation_result.summary

    # Ensure all cited IDs from facts and inferences are collected
    for fact in investigation_result.observedFacts:
        for eid in fact.evidenceIds:
            if eid in valid_evidence_ids:
                cited_story_evidence.add(eid)

    for inf in investigation_result.inferences:
        for eid in inf.supportingEvidenceIds:
            if eid in valid_evidence_ids:
                cited_story_evidence.add(eid)

    story_affected_assets = [
        aid for aid in investigation_result.affectedAssetIds
        if aid in valid_asset_ids
    ]
    if not story_affected_assets:
        story_affected_assets = list(context.get_all_asset_ids())

    return AttackStory(
        incidentId=investigation_result.incidentId,
        title=title,
        summary=summary,
        severity=investigation_result.severity,
        confidence=investigation_result.confidence.score,
        stages=stages,
        observedFacts=investigation_result.observedFacts,
        inferences=investigation_result.inferences,
        unknowns=investigation_result.unknowns,
        uncertainty=uncertainty_str,
        affectedAssetIds=story_affected_assets,
        citedEvidenceIds=sorted(list(cited_story_evidence)),
        generatedAt=datetime.now(timezone.utc).isoformat(),
        compromiseAssessment=getattr(investigation_result, "compromiseAssessment", "NOT_ESTABLISHED"),
        attributionAssessment=getattr(investigation_result, "attributionAssessment", "UNCONFIRMED"),
    )
