"""
==============================================================================
FILE: apps/api/app/investigation/engine.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Core Deterministic Investigation Engine. Orchestrates evidence synthesis,
           grounded forensic reporting, timeline analysis, and containment planning.
==============================================================================
"""

from typing import List, Optional, Tuple
from datetime import datetime, timezone
import uuid

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse
from app.schemas.investigation import (
    InvestigationResultResponse,
    EvidenceSchema,
    InvestigationTimelineResponse
)
from app.investigation.timeline import TimelineBuilder
from app.investigation.synthesizer import DeterministicFactSynthesizer
from app.investigation.recommendations import GroundedRecommendationGenerator
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.investigation_repository import get_investigation_repository
from app.api.realtime import safe_broadcast_event



class DeterministicInvestigationEngine:
    """
    Analyzes validated incidents without non-deterministic LLMs or external OSINT.
    Produces evidence-grounded findings, deterministic timelines, and validated recommendations.
    """

    def __init__(self):
        self.incident_repo = get_incident_repository()
        self.detection_repo = get_detection_repository()
        self.investigation_repo = get_investigation_repository()

    def investigate_incident(
        self,
        incident_id: str,
        environment_id: str = "env-prod"
    ) -> Tuple[Optional[InvestigationResultResponse], Optional[str]]:
        # 1. Authoritative incident retrieval with strict environment enforcement
        incident = self.incident_repo.get_incident(incident_id, environment_id=environment_id)
        if not incident:
            return None, f"Incident '{incident_id}' not found in environment '{environment_id}'"

        # 2. Retrieve all associated detections belonging to this incident
        detections: List[DetectionEventResponse] = []
        for det_id in incident.detectionEventIds:
            det = self.detection_repo.get_detection(det_id, environment_id=environment_id)
            if det:
                detections.append(det)

        # 3. Construct deterministic chronological timeline
        timeline = TimelineBuilder.build_timeline(incident, detections)
        self.investigation_repo.save_timeline(timeline)

        # 4. Synthesize factual attack story (observed facts, inferences, unknowns)
        attack_story = DeterministicFactSynthesizer.synthesize_attack_story(incident, detections)

        # 5. Assemble grounded evidence items
        grounded_evidence: List[EvidenceSchema] = []
        for det in detections:
            grounded_evidence.append(EvidenceSchema(
                id=det.id,
                type="DETECTION_MATCH",
                source=det.primaryAssetId,
                timestamp=det.timestamp,
                content={
                    "ruleId": det.rule.ruleId,
                    "ruleName": det.rule.name,
                    "severity": det.severity,
                    "confidence": det.confidence,
                    "metadata": det.metadata
                },
                relevanceExplanation=det.evidenceSummary,
                verified=True
            ))

            # Matched raw telemetry event references
            for evt_id in det.matchedEventIds:
                meta = det.metadata or {}
                grounded_evidence.append(EvidenceSchema(
                    id=evt_id,
                    type="TELEMETRY_EVENT",
                    source=meta.get("sourceIp") or "telemetry-stream",
                    timestamp=det.timestamp,
                    content={
                        "detectionId": det.id,
                        "ruleId": det.rule.ruleId,
                        "outcome": meta.get("outcome") or "EVALUATED"
                    },
                    relevanceExplanation=f"Authoritative raw telemetry event contributing to detection '{det.id}'",
                    verified=True
                ))

        # 6. Generate grounded response recommendations
        recommendations = GroundedRecommendationGenerator.generate_recommendations(incident, detections)

        # 7. Compute aggregate confidence
        confidences = [d.confidence for d in detections]
        confidence_score = max(confidences) if confidences else 0.85

        # 8. Construct final InvestigationResultResponse
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        result = InvestigationResultResponse(
            incidentId=incident.id,
            summary=attack_story.narrativeSummary,
            severity=incident.severity,
            confidenceScore=confidence_score,
            attackStory=attack_story,
            groundedEvidence=grounded_evidence,
            recommendations=recommendations,
            generatedAt=now_iso
        )

        # Persist investigation result
        self.investigation_repo.save_investigation(result, environment_id)

        # Update incident status to INVESTIGATING if currently ACTIVE
        if incident.status == "ACTIVE":
            try:
                self.incident_repo.update_status(
                    incident_id,
                    new_status="INVESTIGATING",
                    environment_id=environment_id
                )
            except Exception:
                pass

        # Broadcast realtime event
        safe_broadcast_event(
            event_type="INVESTIGATION_COMPLETED",
            payload={
                "incidentId": incident.id,
                "environmentId": environment_id,
                "severity": incident.severity,
                "recommendationCount": len(recommendations),
                "timestamp": now_iso
            }
        )


        return result, None

    def get_investigation(
        self,
        incident_id: str,
        environment_id: str = "env-prod"
    ) -> Optional[InvestigationResultResponse]:
        return self.investigation_repo.get_investigation(incident_id, environment_id)

    def get_timeline(
        self,
        incident_id: str,
        environment_id: str = "env-prod"
    ) -> Optional[InvestigationTimelineResponse]:
        return self.investigation_repo.get_timeline(incident_id, environment_id)


_default_investigation_engine: Optional[DeterministicInvestigationEngine] = None


def get_investigation_engine() -> DeterministicInvestigationEngine:
    global _default_investigation_engine
    if _default_investigation_engine is None:
        _default_investigation_engine = DeterministicInvestigationEngine()
    return _default_investigation_engine
