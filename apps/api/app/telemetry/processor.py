"""
==============================================================================
FILE: apps/api/app/telemetry/processor.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Processes normalized, validated telemetry events through deduplication,
           deterministic detection rules, correlation into incidents, and realtime dispatch.
TOOLS & LIBRARIES: asyncio, logging
==============================================================================
"""

import logging
from typing import List, Tuple
from app.schemas.telemetry import TelemetryEventSchema
from app.schemas.detection import DetectionEventResponse
from app.schemas.incident import IncidentResponse
from app.detection.deduplicator import get_event_deduplicator, DeduplicationResult
from app.detection.engine import get_detection_engine
from app.correlation.engine import get_correlation_engine
from app.db.repositories.detection_repository import get_detection_repository
from app.api.realtime import broadcast_system_event

logger = logging.getLogger("gasha.telemetry.processor")


async def process_stream(events: List[TelemetryEventSchema]) -> int:
    """
    Main processing pipeline:
    Events -> Deduplication -> Detection Engine -> Correlation Engine -> Incident Store -> Realtime
    """
    if not events:
        return 0

    deduplicator = get_event_deduplicator()
    detection_engine = get_detection_engine()
    correlation_engine = get_correlation_engine()
    detection_repo = get_detection_repository()

    processed_count = 0

    for event in events:
        # 1. Deduplication check with payload fingerprint integrity
        dedup_status, cached_record = deduplicator.check_and_record(event)
        if dedup_status == DeduplicationResult.IS_DUPLICATE:
            logger.debug(f"Event '{event.id}' is duplicate; skipping detection rule evaluation")
            processed_count += 1
            continue
        elif dedup_status == DeduplicationResult.IS_CONFLICT:
            logger.warning(f"Event '{event.id}' payload conflicted with previous entry; rejected")
            continue

        # 2. Evaluate deterministic detection rules
        detections: List[DetectionEventResponse] = detection_engine.evaluate_event(event)
        generated_det_ids = []

        for det in detections:
            # 3. Store detection finding in DetectionRepository
            detection_repo.create_detection(det)
            generated_det_ids.append(det.id)

            # 4. Correlate detection finding into Incident
            incident, is_new = correlation_engine.correlate_detection(det)

            # 5. Broadcast realtime platform state updates
            try:
                await broadcast_system_event("detection.created", det.model_dump())
                event_name = "incident.created" if is_new else "incident.updated"
                await broadcast_system_event(event_name, incident.model_dump())
            except Exception as e:
                logger.debug(f"Non-critical realtime broadcast failure: {e}")

            # 6. Auto-propose containment action for high/critical threats with a source IP
            meta = det.metadata or {}
            source_ip = meta.get("sourceIp")
            sev = (det.severity or "").upper()
            if source_ip and sev in ("HIGH", "CRITICAL"):
                try:
                    import uuid
                    from datetime import datetime, timezone
                    from app.db.repositories.response_repository import get_response_repository
                    from app.schemas.response import ResponseRecordResponse
                    resp_repo = get_response_repository()
                    existing = [
                        r for r in resp_repo.list_responses(det.environmentId)
                        if r.targetIdentifier == source_ip and r.status in ("PROPOSED", "PENDING_APPROVAL")
                    ]
                    if not existing:
                        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                        action_rec = ResponseRecordResponse(
                            id=f"resp-{uuid.uuid4().hex[:8]}",
                            incidentId=incident.id,
                            environmentId=det.environmentId,
                            actionType="BLOCK_SOURCE",
                            targetType="IP_ADDRESS",
                            targetIdentifier=source_ip,
                            status="PROPOSED",
                            proposedBy="GASHA Autonomous CSOC Agent",
                            proposedAt=now_iso,
                            reason=f"Automated threat containment recommendation: {det.evidenceSummary}",
                            supportingEvidenceIds=[det.id]
                        )
                        resp_repo.save_response(action_rec)
                        await broadcast_system_event("response.proposed", action_rec.model_dump())
                except Exception as _resp_err:
                    logger.debug(f"Response auto-proposal non-critical error: {_resp_err}")

            # 7. Recalculate risk score
            try:
                from app.risk.service import get_risk_service
                get_risk_service().recalculate_risk(det.environmentId)
            except Exception:
                pass

        # Record generated detections in deduplicator
        if generated_det_ids:
            deduplicator.record_detections(event, generated_det_ids)

        processed_count += 1

    return processed_count


async def process_single_event(event: TelemetryEventSchema) -> List[DetectionEventResponse]:
    """Single event processor hook returning generated detections."""
    deduplicator = get_event_deduplicator()
    detection_engine = get_detection_engine()
    correlation_engine = get_correlation_engine()
    detection_repo = get_detection_repository()

    dedup_status, _ = deduplicator.check_and_record(event)
    if dedup_status != DeduplicationResult.IS_NEW:
        return []

    detections = detection_engine.evaluate_event(event)
    for det in detections:
        detection_repo.create_detection(det)
        correlation_engine.correlate_detection(det)
    return detections
