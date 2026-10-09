"""
==============================================================================
FILE: apps/api/app/detection/deduplicator.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Bounded LRU deduplication cache with content integrity verification.
           Prevents duplicate events from inflating detection thresholds while
           detecting conflicting replay attacks.
==============================================================================
"""

import time
import hashlib
import json
import logging
from collections import OrderedDict
from typing import Optional, Dict, Any, Tuple
from app.schemas.telemetry import TelemetryEventSchema

logger = logging.getLogger("gasha.detection.deduplicator")


class DeduplicationResult:
    IS_NEW = "NEW"
    IS_DUPLICATE = "DUPLICATE"
    IS_CONFLICT = "CONFLICT"


class EventDeduplicator:
    """
    Tracks processed event IDs within an LRU cache and verifies payload fingerprint
    integrity to ensure duplicate delivery does not inflate thresholds.
    """
    def __init__(self, max_size: int = 5000, ttl_seconds: float = 3600.0):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        # Mapping: compound_key -> {"fingerprint": str, "timestamp": float, "detections": list}
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def _compute_fingerprint(self, event: TelemetryEventSchema) -> str:
        """Computes a deterministic SHA-256 hash of the event's core attributes."""
        core = {
            "id": event.id,
            "eventType": event.eventType,
            "sourceService": event.sourceService,
            "environmentId": event.environmentId,
            "sourceIp": event.payload.sourceIp,
            "httpMethod": event.payload.httpMethod,
            "httpPath": event.payload.httpPath,
            "httpStatusCode": event.payload.httpStatusCode,
            "action": event.payload.action,
            "outcome": event.payload.outcome,
        }
        serialized = json.dumps(core, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def check_and_record(
        self,
        event: TelemetryEventSchema
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Checks if an event is new, an exact duplicate, or a conflicting duplicate.
        Returns:
            (DeduplicationResult, cached_record_if_duplicate)
        """
        now = time.time()
        key = f"{event.environmentId}:{event.id}"
        current_fp = self._compute_fingerprint(event)

        if key in self._cache:
            record = self._cache[key]
            # Verify TTL
            if (now - record["timestamp"]) <= self.ttl_seconds:
                self._cache.move_to_end(key)
                if record["fingerprint"] == current_fp:
                    return DeduplicationResult.IS_DUPLICATE, record
                else:
                    logger.warning(
                        f"Integrity conflict: Duplicate event ID '{event.id}' in environment "
                        f"'{event.environmentId}' received with conflicting payload content."
                    )
                    return DeduplicationResult.IS_CONFLICT, record

        # New event or expired entry
        if len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)

        new_record = {
            "fingerprint": current_fp,
            "timestamp": now,
            "detections": []
        }
        self._cache[key] = new_record
        return DeduplicationResult.IS_NEW, None

    def record_detections(self, event: TelemetryEventSchema, detection_ids: list):
        """Associates generated detection IDs with the cached event record."""
        key = f"{event.environmentId}:{event.id}"
        if key in self._cache:
            self._cache[key]["detections"] = list(detection_ids)

    def clear(self):
        """Clears the cache."""
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


# Global singleton deduplicator
_event_deduplicator: Optional[EventDeduplicator] = None


def get_event_deduplicator() -> EventDeduplicator:
    global _event_deduplicator
    if _event_deduplicator is None:
        _event_deduplicator = EventDeduplicator()
    return _event_deduplicator
