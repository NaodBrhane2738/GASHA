"""
==============================================================================
FILE: apps/api/app/investigation/timeline.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Deterministic timeline construction from authoritative incident evidence.
==============================================================================
"""

from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone
import dateutil.parser

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse
from app.schemas.investigation import TimelineEventResponse, InvestigationTimelineResponse


def parse_iso_timestamp(ts: Optional[str]) -> Tuple[datetime, bool]:
    """
    Parses timestamp into UTC datetime.
    Returns (datetime, is_valid).
    """
    if not ts or not isinstance(ts, str):
        return datetime(1970, 1, 1, tzinfo=timezone.utc), False
    try:
        dt = dateutil.parser.isoparse(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc), True
    except Exception:
        return datetime(1970, 1, 1, tzinfo=timezone.utc), False


class TimelineBuilder:
    """
    Constructs a deterministic chronological timeline from actual incident evidence.
    Preserves event outcomes, flags contradictions, and never invents hidden events.
    """

    @classmethod
    def build_timeline(
        cls,
        incident: IncidentResponse,
        detections: List[DetectionEventResponse]
    ) -> InvestigationTimelineResponse:
        events: List[TimelineEventResponse] = []
        notes: List[str] = []
        has_contradictions = False

        # 1. Process detections and extract evidence events
        observed_sources = set()
        observed_outcomes = set()

        for det in detections:
            meta = det.metadata or {}
            source_ip = meta.get("sourceIp") or "unknown"
            observed_sources.add(source_ip)

            # Check detection creation event
            det_dt, det_valid = parse_iso_timestamp(det.timestamp)
            events.append(TimelineEventResponse(
                timestamp=det.timestamp if det_valid else "UNKNOWN_TIMESTAMP",
                eventId=det.id,
                eventType="DETECTION_TRIGGERED",
                source=det.primaryAssetId,
                outcome="DETECTED",
                summary=f"Rule '{det.rule.ruleId}' ({det.rule.name}) fired with severity {det.severity}.",
                details={
                    "ruleId": det.rule.ruleId,
                    "confidence": det.confidence,
                    "matchedEventIds": det.matchedEventIds,
                    "evidenceSummary": det.evidenceSummary,
                    "metadata": det.metadata
                },
                flag=None if det_valid else "MISSING_TIMESTAMP"
            ))

            # If matched events have synthetic or explicit details in metadata
            if det.matchedEventIds:
                for idx, evt_id in enumerate(det.matchedEventIds):
                    # Preserved individual evidence record
                    events.append(TimelineEventResponse(
                        timestamp=det.timestamp if det_valid else "UNKNOWN_TIMESTAMP",
                        eventId=evt_id,
                        eventType=det.rule.ruleId,
                        source=source_ip,
                        outcome=meta.get("outcome") or "EVALUATED",
                        summary=f"Telemetry event {evt_id} contributed to detection {det.id}.",
                        details={
                            "detectionId": det.id,
                            "ruleId": det.rule.ruleId,
                            "sourceIp": source_ip,
                            "targetAsset": det.primaryAssetId,
                            "attemptIndex": idx + 1
                        },
                        flag=None
                    ))
                    if meta.get("outcome"):
                        observed_outcomes.add(meta.get("outcome"))

        # 2. Check for contradictions or anomalies
        if len(observed_sources) > 1 and "unknown" not in observed_sources:
            notes.append(f"Multiple distinct attacker source IPs observed in incident: {sorted(list(observed_sources))}")

        # Check conflicting outcomes (e.g. SUCCESS vs DENIED/FAILED)
        if "SUCCESS" in observed_outcomes and ("DENIED" in observed_outcomes or "FAILED" in observed_outcomes):
            has_contradictions = True
            notes.append("CONTRADICTION DETECTED: Telemetry contains both successful and denied/failed outcomes for this entity.")

        # 3. Sort strictly by timestamp (chronological)
        def sort_key(item: TimelineEventResponse):
            dt, _ = parse_iso_timestamp(item.timestamp)
            return (dt, item.eventId)

        events.sort(key=sort_key)

        return InvestigationTimelineResponse(
            incidentId=incident.id,
            environmentId=incident.environmentId,
            events=events,
            totalEvents=len(events),
            hasContradictions=has_contradictions,
            notes=notes
        )
