"""
Unit tests for GASHA Event Deduplicator.
Verifies exact duplicate suppression, conflicting content detection,
bounded LRU eviction, and environment isolation.
"""
import pytest
from datetime import datetime, timezone

from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema
from app.detection.deduplicator import EventDeduplicator, DeduplicationResult


def make_event(event_id: str, source_ip: str = "192.0.2.1", env_id: str = "env-prod", path: str = "/api") -> TelemetryEventSchema:
    return TelemetryEventSchema(
        id=event_id,
        schemaVersion="1.0.0",
        eventType="HTTP_REQUEST",
        timestamp=datetime.now(timezone.utc).isoformat(),
        sourceService="web",
        environmentId=env_id,
        payload=TelemetryEventPayloadSchema(
            sourceIp=source_ip,
            httpMethod="GET",
            httpPath=path,
            httpStatusCode=200
        )
    )


def test_dedup_exact_duplicate():
    dedup = EventDeduplicator(max_size=100)
    evt = make_event("evt-100")

    status1, record1 = dedup.check_and_record(evt)
    assert status1 == DeduplicationResult.IS_NEW
    assert record1 is None

    status2, record2 = dedup.check_and_record(evt)
    assert status2 == DeduplicationResult.IS_DUPLICATE
    assert record2 is not None


def test_dedup_conflicting_content_detection():
    dedup = EventDeduplicator(max_size=100)
    evt1 = make_event("evt-conflict", source_ip="192.0.2.1", path="/first")
    evt2 = make_event("evt-conflict", source_ip="198.51.100.99", path="/tampered")

    status1, _ = dedup.check_and_record(evt1)
    assert status1 == DeduplicationResult.IS_NEW

    status2, _ = dedup.check_and_record(evt2)
    assert status2 == DeduplicationResult.IS_CONFLICT


def test_dedup_distinct_events_preserved():
    dedup = EventDeduplicator(max_size=100)
    evt1 = make_event("evt-distinct-1")
    evt2 = make_event("evt-distinct-2")

    assert dedup.check_and_record(evt1)[0] == DeduplicationResult.IS_NEW
    assert dedup.check_and_record(evt2)[0] == DeduplicationResult.IS_NEW
    assert len(dedup) == 2


def test_dedup_bounded_cache_lru_eviction():
    dedup = EventDeduplicator(max_size=3)
    dedup.check_and_record(make_event("evt-1"))
    dedup.check_and_record(make_event("evt-2"))
    dedup.check_and_record(make_event("evt-3"))

    assert len(dedup) == 3

    # Add 4th event -> evt-1 evicted
    dedup.check_and_record(make_event("evt-4"))
    assert len(dedup) == 3

    # evt-1 is now treated as new because it was evicted
    status, _ = dedup.check_and_record(make_event("evt-1"))
    assert status == DeduplicationResult.IS_NEW


def test_dedup_environment_isolation():
    dedup = EventDeduplicator(max_size=100)
    # Same event ID across different environments
    evt_prod = make_event("evt-shared", env_id="env-prod")
    evt_dev = make_event("evt-shared", env_id="env-dev")

    status_prod, _ = dedup.check_and_record(evt_prod)
    status_dev, _ = dedup.check_and_record(evt_dev)

    assert status_prod == DeduplicationResult.IS_NEW
    assert status_dev == DeduplicationResult.IS_NEW
    assert len(dedup) == 2
