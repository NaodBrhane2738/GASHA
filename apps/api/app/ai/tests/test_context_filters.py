"""
==============================================================================
FILE: apps/api/app/ai/tests/test_context_filters.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Unit tests for deduplication, noise filtering, time window bounding,
           volume capping, and chronological ordering.
==============================================================================
"""

from app.ai.contracts import TelemetryEventContext, EvidenceItem
from app.ai.context_filters import (
    deduplicate_evidence,
    deduplicate_telemetry,
    filter_background_noise,
    filter_by_time_window,
    cap_and_prioritize_telemetry,
    sort_chronologically,
)


def test_deduplicate_evidence():
    """Verifies that evidence items with duplicate IDs are collapsed into one."""
    ev1 = EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="svc-a", timestamp="2026-09-24T00:00:00Z", summary="Ev 1", content={})
    ev2 = EvidenceItem(id="EV-1", type="TELEMETRY_EVENT", source="svc-a", timestamp="2026-09-24T00:00:00Z", summary="Ev 1 duplicate", content={})
    ev3 = EvidenceItem(id="EV-2", type="DETECTION_MATCH", source="det", timestamp="2026-09-24T00:01:00Z", summary="Ev 2", content={})

    result = deduplicate_evidence([ev1, ev2, ev3])
    assert len(result) == 2
    assert result[0].id == "EV-1"
    assert result[1].id == "EV-2"


def test_filter_background_noise():
    """Filters routine health checks unless explicitly cited as detection evidence."""
    t_health = TelemetryEventContext(id="T-1", eventType="HTTP_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web", httpPath="/health")
    t_ping = TelemetryEventContext(id="T-2", eventType="HTTP_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web", httpPath="/ping")
    t_probe = TelemetryEventContext(id="T-3", eventType="HTTP_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web", userAgent="kube-probe/1.28")
    t_attack = TelemetryEventContext(id="T-4", eventType="AUTH_FAILURE", timestamp="2026-09-24T00:00:00Z", sourceService="auth", httpPath="/api/login")
    t_health_cited = TelemetryEventContext(id="T-5", eventType="HTTP_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web", httpPath="/health")

    # T-5 is explicitly matched by a detection
    explicit_matched = {"T-5"}
    filtered = filter_background_noise([t_health, t_ping, t_probe, t_attack, t_health_cited], explicit_matched)

    ids = [t.id for t in filtered]
    assert "T-1" not in ids
    assert "T-2" not in ids
    assert "T-3" not in ids
    assert "T-4" in ids
    assert "T-5" in ids


def test_filter_by_time_window():
    """Filters events occurring outside the configured pre/post incident time window."""
    anchor = "2026-09-24T12:00:00Z"
    t_early = TelemetryEventContext(id="T-EARLY", eventType="HTTP_REQUEST", timestamp="2026-09-24T10:00:00Z", sourceService="web")  # 2h prior
    t_in_window = TelemetryEventContext(id="T-IN", eventType="AUTH_FAILURE", timestamp="2026-09-24T11:45:00Z", sourceService="web")  # 15m prior
    t_late = TelemetryEventContext(id="T-LATE", eventType="HTTP_REQUEST", timestamp="2026-09-24T14:00:00Z", sourceService="web")  # 2h post
    t_early_cited = TelemetryEventContext(id="T-EARLY-CITED", eventType="HTTP_REQUEST", timestamp="2026-09-24T08:00:00Z", sourceService="web")

    explicit_matched = {"T-EARLY-CITED"}
    filtered = filter_by_time_window(
        [t_early, t_in_window, t_late, t_early_cited],
        anchor_timestamp_str=anchor,
        explicit_matched_ids=explicit_matched,
        pre_window_seconds=3600,  # 1 hr
        post_window_seconds=1800,  # 30 min
    )

    ids = [t.id for t in filtered]
    assert "T-EARLY" not in ids
    assert "T-IN" in ids
    assert "T-LATE" not in ids
    assert "T-EARLY-CITED" in ids


def test_cap_and_prioritize_telemetry():
    """Prioritizes matched and security events when capping total telemetry volume."""
    t_matched = TelemetryEventContext(id="T-MATCH", eventType="HTTP_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web")
    t_sec1 = TelemetryEventContext(id="T-SEC1", eventType="AUTH_FAILURE", timestamp="2026-09-24T00:00:00Z", sourceService="web")
    t_sec2 = TelemetryEventContext(id="T-SEC2", eventType="SUSPICIOUS_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web")
    t_norm1 = TelemetryEventContext(id="T-NORM1", eventType="HTTP_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web")
    t_norm2 = TelemetryEventContext(id="T-NORM2", eventType="HTTP_REQUEST", timestamp="2026-09-24T00:00:00Z", sourceService="web")

    capped = cap_and_prioritize_telemetry(
        [t_norm1, t_sec1, t_norm2, t_sec2, t_matched],
        explicit_matched_ids={"T-MATCH"},
        max_events=3,
    )

    assert len(capped) == 3
    ids = [t.id for t in capped]
    assert "T-MATCH" in ids
    assert "T-SEC1" in ids
    assert "T-SEC2" in ids


def test_sort_chronologically():
    """Orders events in ascending chronological order."""
    t1 = TelemetryEventContext(id="T-1", eventType="AUTH_FAILURE", timestamp="2026-09-24T00:05:00Z", sourceService="web")
    t2 = TelemetryEventContext(id="T-2", eventType="AUTH_FAILURE", timestamp="2026-09-24T00:01:00Z", sourceService="web")
    t3 = TelemetryEventContext(id="T-3", eventType="AUTH_FAILURE", timestamp="2026-09-24T00:10:00Z", sourceService="web")

    sorted_events = sort_chronologically([t1, t2, t3])
    assert [t.id for t in sorted_events] == ["T-2", "T-1", "T-3"]
