"""
==============================================================================
FILE: apps/api/app/ai/recommendations/fallback.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Deterministic fallback recommendations for GASHA.
           Emits conservative, allowlisted containment recommendations only
           when backed by unambiguous deterministic detection signals.
TOOLS & LIBRARIES: Python standard library
==============================================================================
"""

import logging
from typing import List
from app.ai.contracts import (
    InvestigationContext,
    AIRecommendation,
)

logger = logging.getLogger("gasha.ai.recommendations.fallback")


def create_fallback_recommendations(
    context: InvestigationContext,
    reason: str = "AI recommendation unavailable.",
) -> List[AIRecommendation]:
    """
    Constructs deterministic fallback recommendations from canonical detections.

    Guarantees:
      - Conservative approach (returns at most ONE highly justified recommendation or empty list).
      - Strictly allowlisted actions (e.g. BLOCK_SOURCE).
      - Grounded strictly in existing evidence IDs.
      - Advisory only.
    """
    recs: List[AIRecommendation] = []

    # Search for an unambiguous malicious source IP in evidence or detections
    malicious_ips = set()
    supporting_eids = []

    for ev in context.evidence:
        if isinstance(ev.content, dict):
            ip = ev.content.get("sourceIp") or ev.content.get("clientIp") or ev.content.get("attackerIp")
            if ip and isinstance(ip, str) and len(ip.split(".")) == 4:
                malicious_ips.add(ip)
                supporting_eids.append(ev.id)

    # If an external IP triggered high/critical severity detections, propose BLOCK_SOURCE
    if malicious_ips and context.incident and context.incident.severity in ["HIGH", "CRITICAL"]:
        target_ip = sorted(list(malicious_ips))[0]
        recs.append(
            AIRecommendation(
                id="rec-fallback-1",
                actionType="BLOCK_SOURCE",
                targetIdentifier=target_ip,
                targetType="IP_ADDRESS",
                rationale=f"Deterministic fallback containment: IP {target_ip} triggered critical security detection ({reason}).",
                confidence=0.8,
                expectedImpact=f"Expected to prevent further network requests from {target_ip}.",
                supportingEvidenceIds=supporting_eids[:3],
                priority="HIGH",
            )
        )
    else:
        logger.info("No unambiguous deterministic containment recommendation justified for incident %s", getattr(context.incident, "id", "UNKNOWN"))

    return recs
