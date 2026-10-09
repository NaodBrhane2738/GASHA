"""
==============================================================================
FILE: apps/api/app/investigation/recommendations.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Grounded containment recommendation generator for deterministic investigations.
==============================================================================
"""

import ipaddress
import uuid
from typing import List, Set, Optional

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse
from app.schemas.investigation import RecommendationSchema


def is_valid_ip(ip_str: Optional[str]) -> bool:
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean = ip_str.strip()
    if clean.lower() in ("unknown", "n/a", "none", "", "localhost"):
        return False
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


class GroundedRecommendationGenerator:
    """
    Generates allowlisted containment recommendations strictly based on verified evidence.
    Returns an empty list if no valid, actionable target exists in the evidence.
    """

    @classmethod
    def generate_recommendations(
        cls,
        incident: IncidentResponse,
        detections: List[DetectionEventResponse]
    ) -> List[RecommendationSchema]:
        recommendations: List[RecommendationSchema] = []
        proposed_targets: Set[str] = set()

        for det in detections:
            meta = det.metadata or {}
            source_ip = meta.get("sourceIp")

            # 1. Network / Source Blocking Recommendations (BLOCK_SOURCE)
            if is_valid_ip(source_ip) and source_ip not in proposed_targets:
                rec_id = f"rec-{uuid.uuid4().hex[:8]}"
                proposed_targets.add(source_ip)

                rationale = (
                    f"Direct source IP '{source_ip}' identified in deterministic detection '{det.id}' "
                    f"triggering rule '{det.rule.ruleId}' ({det.rule.name})."
                )
                impact = f"Enforces perimeter block on '{source_ip}', halting inbound attacker requests."

                recommendations.append(RecommendationSchema(
                    id=rec_id,
                    actionType="BLOCK_SOURCE",
                    targetIdentifier=source_ip,
                    targetType="IP_ADDRESS",
                    rationale=rationale,
                    confidence=det.confidence,
                    expectedImpact=impact
                ))

            # 2. Session Revocation Recommendations (DISABLE_SESSION)
            if det.rule.ruleId == "RULE-PRIV-004":
                user_id = meta.get("userId")
                session_id = meta.get("sessionId") or (f"session-{user_id}" if user_id and user_id != "unknown" else None)

                if session_id and session_id not in proposed_targets:
                    rec_id = f"rec-{uuid.uuid4().hex[:8]}"
                    proposed_targets.add(session_id)

                    rationale = (
                        f"Target user account '{user_id or 'unknown'}' was subject to high-privilege mutation or unauthorized "
                        f"role escalation in detection '{det.id}'."
                    )
                    impact = f"Revokes active session tokens for target identity '{session_id}', terminating unauthorized access."

                    recommendations.append(RecommendationSchema(
                        id=rec_id,
                        actionType="DISABLE_SESSION",
                        targetIdentifier=session_id,
                        targetType="USER_SESSION",
                        rationale=rationale,
                        confidence=det.confidence,
                        expectedImpact=impact
                    ))

        return recommendations
