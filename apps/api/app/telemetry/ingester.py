"""
==============================================================================
FILE: apps/api/app/telemetry/ingester.py
ROLE / OWNERSHIP: Backend & Telemetry Engineers
OBJECTIVE: Ingests, dedupes, validates, normalizes, and buffers high-throughput
           telemetry from target applications via a bounded in-memory queue.
TOOLS & LIBRARIES: asyncio, collections.OrderedDict, Pydantic v2
==============================================================================
"""

import asyncio
import logging
from collections import OrderedDict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from app.core.config import settings
from app.schemas.telemetry import (
    TelemetryEventSchema,
    TelemetryItemResult,
    TelemetryBatchIngestResponse,
)
from app.telemetry.validator import validate_event
from app.telemetry.normalizer import normalize_telemetry_event

logger = logging.getLogger("gasha.telemetry.ingester")

# Deduplication cache maximum size
DEDUP_CACHE_MAX_SIZE = 5000


class TelemetryIngester:
    """
    Manages bounded telemetry buffering, LRU deduplication,
    and operational ingestion metrics.
    """
    def __init__(self, buffer_capacity: Optional[int] = None):
        capacity = buffer_capacity or getattr(settings, "BUFFER_CAPACITY", 5000)
        self.capacity = capacity
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=capacity)
        self.dedup_cache: OrderedDict = OrderedDict()
        self.metrics = {
            "events_received": 0,
            "events_accepted": 0,
            "events_duplicate": 0,
            "events_rejected": 0,
            "events_dropped_overflow": 0,
            "batches_processed": 0,
            "last_ingested_at": None,
        }

    def _mark_seen(self, event_id: str) -> bool:
        """
        Records an event ID in the LRU deduplication cache.
        Returns True if previously seen, False if new.
        """
        if event_id in self.dedup_cache:
            self.dedup_cache.move_to_end(event_id)
            return True

        self.dedup_cache[event_id] = True
        if len(self.dedup_cache) > DEDUP_CACHE_MAX_SIZE:
            self.dedup_cache.popitem(last=False)
        return False

    async def enqueue_batch(
        self,
        events: List[TelemetryEventSchema],
        authorized_environment: Optional[str] = None
    ) -> TelemetryBatchIngestResponse:
        """
        Validates, normalizes, dedupes, and buffers a batch of telemetry events.
        Guarantees zero blocking of incoming traffic by using non-blocking queue puts.
        """
        results: List[TelemetryItemResult] = []
        accepted_count = 0
        rejected_count = 0
        duplicate_count = 0

        self.metrics["batches_processed"] += 1
        self.metrics["events_received"] += len(events)
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.metrics["last_ingested_at"] = now_iso

        for event in events:
            # 1. Deduplication check
            if self._mark_seen(event.id):
                duplicate_count += 1
                self.metrics["events_duplicate"] += 1
                results.append(
                    TelemetryItemResult(
                        id=event.id,
                        status="duplicate",
                        reason="Event ID already processed recently"
                    )
                )
                continue

            # 2. Validation
            is_valid, error_reason = validate_event(event, authorized_environment)
            if not is_valid:
                rejected_count += 1
                self.metrics["events_rejected"] += 1
                results.append(
                    TelemetryItemResult(
                        id=event.id,
                        status="rejected",
                        reason=error_reason
                    )
                )
                continue

            # 3. Normalization
            normalized_event = normalize_telemetry_event(event)

            # 4. Enqueue into bounded buffer non-blockingly
            try:
                self.queue.put_nowait(normalized_event)
                accepted_count += 1
                self.metrics["events_accepted"] += 1
                results.append(
                    TelemetryItemResult(
                        id=event.id,
                        status="accepted"
                    )
                )
            except asyncio.QueueFull:
                self.metrics["events_dropped_overflow"] += 1
                logger.warning(
                    f"Telemetry ingestion queue buffer saturated ({self.queue.qsize()}/{self.capacity}). "
                    f"Dropped event ID: {event.id}"
                )
                results.append(
                    TelemetryItemResult(
                        id=event.id,
                        status="failed",
                        reason="Buffer queue saturated; event dropped"
                    )
                )

        total_count = len(events)
        if total_count == 0 or accepted_count == total_count:
            overall_status = "ACCEPTED"
        elif accepted_count > 0:
            overall_status = "PARTIALLY_ACCEPTED"
        else:
            overall_status = "REJECTED"

        return TelemetryBatchIngestResponse(
            status=overall_status,
            acceptedCount=accepted_count,
            rejectedCount=rejected_count,
            duplicateCount=duplicate_count,
            totalCount=total_count,
            results=results,
            timestamp=now_iso,
            eventsProcessed=accepted_count
        )

    async def dequeue_batch(self, max_items: int = 100) -> List[TelemetryEventSchema]:
        """
        Drains up to max_items events from the in-memory queue without blocking indefinitely.
        """
        batch: List[TelemetryEventSchema] = []
        for _ in range(max_items):
            try:
                event = self.queue.get_nowait()
                batch.append(event)
                self.queue.task_done()
            except asyncio.QueueEmpty:
                break
        return batch

    def get_metrics(self) -> Dict[str, Any]:
        """Returns observable operational ingestion metrics."""
        return {
            "queue_depth": self.queue.qsize(),
            "buffer_capacity": self.capacity,
            "dedup_cache_size": len(self.dedup_cache),
            **self.metrics
        }

    def reset_state(self):
        """Resets the queue, cache, and metrics (primarily for test isolation)."""
        self.queue = asyncio.Queue(maxsize=self.capacity)
        self.dedup_cache.clear()
        for k in self.metrics:
            if isinstance(self.metrics[k], int):
                self.metrics[k] = 0
            else:
                self.metrics[k] = None


# Global singleton instance
_default_ingester: Optional[TelemetryIngester] = None


def get_telemetry_ingester() -> TelemetryIngester:
    global _default_ingester
    if _default_ingester is None:
        _default_ingester = TelemetryIngester()
    return _default_ingester


async def enqueue_batch(
    events: List[TelemetryEventSchema],
    authorized_environment: Optional[str] = None
) -> TelemetryBatchIngestResponse:
    """Convenience module function for enqueueing batch."""
    ingester = get_telemetry_ingester()
    return await ingester.enqueue_batch(events, authorized_environment)
