"""
==============================================================================
FILE: apps/api/app/ai/attack_stories/fallback.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Deterministic fallback attack story generation for GASHA.
           Constructs a safe, strictly evidence-grounded narrative directly
           from deterministic detections and telemetry when the LLM is
           unavailable, malformed, or fails grounding validation.
TOOLS & LIBRARIES: Python standard library, Pydantic v2
==============================================================================
"""

from typing import List
from datetime import datetime, timezone

from app.ai.contracts import (
    InvestigationContext,
    AttackStory,
    AttackStoryStage,
    ObservedFact,
    Inference,
    Unknown,
)


def create_fallback_attack_story(
    context: InvestigationContext,
    reason: str = "AI attack story generation fallback.",
) -> AttackStory:
    """
    Constructs a deterministic, evidence-grounded AttackStory strictly
    from canonical detections and telemetry events in context.

    Guarantees that no speculative narratives, hallucinated asset IDs,
    or non-existent evidence IDs are produced.
    """
    incident_id = context.incident.id if context.incident else "UNKNOWN"
    incident_title = context.incident.title if context.incident else "Security Incident"
    severity = context.incident.severity if context.incident else "MEDIUM"

    # Build stages chronologically from detections and evidence
    stages: List[AttackStoryStage] = []
    observed_facts: List[ObservedFact] = []
    cited_ids = set()

    for idx, det in enumerate(context.detections, start=1):
        stage_evidence = [det.id] + [eid for eid in det.matchedEventIds if eid in context.get_all_evidence_ids()]
        cited_ids.update(stage_evidence)

        # Check if detection describes an attempt
        is_attempt = any(
            kw in (det.ruleName + " " + det.description + " " + det.evidenceSummary).lower()
            for kw in ["attempt", "failure", "failed", "denied", "blocked", "forbidden", "401", "403"]
        )

        stages.append(
            AttackStoryStage(
                order=idx,
                timestamp=det.timestamp,
                phase="Detection Event",
                description=f"Detection rule '{det.ruleName}' triggered: {det.evidenceSummary}",
                affectedAssetIds=[det.primaryAssetId] if det.primaryAssetId else [],
                evidenceIds=stage_evidence,
                isAttemptOnly=is_attempt,
            )
        )

        observed_facts.append(
            ObservedFact(
                statement=f"Deterministic detection '{det.ruleName}' observed on asset {det.primaryAssetId or 'unknown'}.",
                evidenceIds=stage_evidence,
            )
        )

    # If no detections exist but telemetry exists, create baseline stages from telemetry
    if not stages and context.telemetryEvents:
        for idx, te in enumerate(context.telemetryEvents[:5], start=1):
            is_attempt = any(
                kw in (te.eventType + " " + te.source).lower()
                for kw in ["attempt", "failure", "failed", "denied", "blocked", "forbidden"]
            )
            stages.append(
                AttackStoryStage(
                    order=idx,
                    timestamp=te.timestamp,
                    phase="Telemetry Event",
                    description=f"Observed event '{te.eventType}' from source '{te.source}'.",
                    affectedAssetIds=[te.assetId] if te.assetId else [],
                    evidenceIds=[te.id] if te.id in context.get_all_evidence_ids() else [],
                    isAttemptOnly=is_attempt,
                )
            )
            if te.id in context.get_all_evidence_ids():
                cited_ids.add(te.id)

    # Uncertainty statement
    uncertainty_statement = (
        f"Detailed attack narrative and root-cause analysis generated via deterministic fallback due to: {reason}. "
        "Analysis was generated without LLM cognitive synthesis. Manual analyst review required to reconstruct unobserved intermediate stages."
    )

    affected_assets = list(context.get_all_asset_ids())

    return AttackStory(
        incidentId=incident_id,
        title=f"Incident Story: {incident_title}",
        summary=(
            f"Deterministic fallback story for incident {incident_id}. "
            f"Observed {len(stages)} stage(s) derived directly from verified detections and telemetry."
        ),
        severity=severity,
        confidence=0.3 if stages else 0.0,
        stages=stages,
        observedFacts=observed_facts,
        inferences=[],
        unknowns=[
            Unknown(
                statement="Cognitive root-cause synthesis and intermediate lateral movement unobserved.",
                significance="Determines whether attacker established persistence.",
            )
        ],
        uncertainty=uncertainty_statement,
        affectedAssetIds=affected_assets,
        citedEvidenceIds=sorted(list(cited_ids)),
        generatedAt=datetime.now(timezone.utc).isoformat(),
    )
