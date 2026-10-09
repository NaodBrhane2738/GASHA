"""
==============================================================================
FILE: apps/api/app/detection/deduplicator.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Bounded LRU deduplication cache with content integrity verification
           and durable SQL persistence across process restarts.
           Prevents duplicate events from inflating detection thresholds while
           detecting conflicting replay attacks.
==============================================================================
"""

import time
import hashlib
import json
import logging
import threading
from collections import OrderedDict
from typing import Optional, Dict, Any, Tuple
from app.schemas.telemetry import TelemetryEventSchema
from app.db.storage_mode import resolve_storage_backend, StorageMode

logger = logging.getLogger("gasha.detection.deduplicator")


class DeduplicationResult:
    IS_NEW = "NEW"
    IS_DUPLICATE = "DUPLICATE"
    IS_CONFLICT = "CONFLICT"


class EventDeduplicator:
    """
    Tracks processed event IDs within an LRU cache and durable SQL persistence,
    verifying payload fingerprint integrity to ensure duplicate delivery does not
    inflate thresholds or generate duplicate incidents across process restarts.
    Thread-safe under concurrent multi-threaded requests.
    """
    def __init__(
        self,
        max_size: int = 5000,
        ttl_seconds: float = 3600.0,
        storage_backend: Optional[str] = None,
        engine: Optional[Any] = None
    ):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        # Mapping: compound_key -> {"fingerprint": str, "timestamp": float, "detections": list}
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._lock = threading.RLock()
        self.backend = resolve_storage_backend(storage_backend)
        self._engine = engine
        if self._engine is None and self.backend == StorageMode.SQL:
            from app.db.sql_engine import get_sql_engine
            self._engine = get_sql_engine()

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
        with self._lock:
            now = time.time()
            key = f"{event.environmentId}:{event.id}"
            current_fp = self._compute_fingerprint(event)

            # 1. Check in-memory LRU cache
            if key in self._cache:
                record = self._cache[key]
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

            # 2. Check durable SQL storage if persistent backend is active
            if self._engine:
                db_record = self._engine.get_dedup_record(key)
                if db_record:
                    if (now - db_record["timestamp"]) <= self.ttl_seconds:
                        self._cache[key] = db_record
                        if db_record["fingerprint"] == current_fp:
                            return DeduplicationResult.IS_DUPLICATE, db_record
                        else:
                            logger.warning(
                                f"Integrity conflict: Replayed event ID '{event.id}' in environment "
                                f"'{event.environmentId}' matches durable key with conflicting fingerprint."
                            )
                            return DeduplicationResult.IS_CONFLICT, db_record

            # 3. New event or expired entry
            if len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)

            new_record = {
                "fingerprint": current_fp,
                "timestamp": now,
                "detections": []
            }
            self._cache[key] = new_record

            if self._engine:
                self._engine.save_dedup_record(
                    dedup_key=key,
                    environment_id=event.environmentId,
                    event_id=event.id,
                    fingerprint=current_fp,
                    timestamp=now,
                    detections=[]
                )

            return DeduplicationResult.IS_NEW, None

    def record_detections(self, event: TelemetryEventSchema, detection_ids: list):
        """Associates generated detection IDs with the cached event record."""
        with self._lock:
            key = f"{event.environmentId}:{event.id}"
            if key in self._cache:
                self._cache[key]["detections"] = list(detection_ids)
            if self._engine:
                self._engine.update_dedup_detections(key, list(detection_ids))

    def clear(self):
        """Clears the cache and durable store."""
        with self._lock:
            self._cache.clear()
            if self._engine:
                self._engine.clear_dedup_records()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


# Global singleton deduplicator
_event_deduplicator: Optional[EventDeduplicator] = None


def get_event_deduplicator(storage_backend: Optional[str] = None) -> EventDeduplicator:
    global _event_deduplicator
    backend = resolve_storage_backend(storage_backend)
    if backend == StorageMode.SQL:
        return EventDeduplicator(storage_backend=StorageMode.SQL)
    if _event_deduplicator is None:
        _event_deduplicator = EventDeduplicator(storage_backend=StorageMode.MEMORY)
    return _event_deduplicator
