"""
==============================================================================
FILE: apps/api/app/ai/context_filters.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Deduplication, noise filtering, time-window bounding, and volume capping
           for the GASHA AI Investigation Context.
TOOLS & LIBRARIES: Python standard library (datetime)
KEY FEATURES:
  - deduplicate_evidence(): Eliminates redundant evidence entries by canonical ID.
  - filter_by_time_window(): Removes background telemetry outside the incident activity window.
  - filter_background_noise(): Discards routine healthcheck / heartbeat events unless cited.
  - cap_and_prioritize_telemetry(): Deterministically limits telemetry volume using security priority tiers.
  - sort_chronologically(): Sorts events and evidence in ascending time order.
EXPECTED RESULTS / BEHAVIOR:
  - Produces a concise, high-signal, chronologically ordered context without losing
    forensic evidence or fabricating intermediate timeline events.
==============================================================================
"""

from datetime import datetime, timezone
from typing import List, Set, Optional, Dict, Any

from app.ai.contracts import (
    TelemetryEventContext,
    EvidenceItem,
    DetectionContext,
    IncidentContext,
)

# Common healthcheck paths / user agents considered background noise
NOISE_PATHS = {"/health", "/healthz", "/ping", "/livez", "/readyz", "/metrics", "/favicon.ico"}
NOISE_USER_AGENTS = {"kube-probe", "ELB-HealthChecker", "Consul Health Check", "Prometheus"}


def parse_timestamp_safe(ts_str: Optional[str]) -> float:
    """Parses ISO timestamp string to epoch seconds for deterministic sorting."""
    if not ts_str:
        return 0.0
    try:
        # Handle trailing Z
        normalized = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


def deduplicate_evidence(
    evidence_list: List[EvidenceItem]
) -> List[EvidenceItem]:
    """
    Deduplicates a list of EvidenceItem objects by their unique ID,
    preserving the first occurrence.
    """
    seen_ids: Set[str] = set()
    deduped: List[EvidenceItem] = []

    for item in evidence_list:
        if item.id and item.id not in seen_ids:
            deduped.append(item)
            seen_ids.add(item.id)

    return deduped


def deduplicate_telemetry(
    telemetry_list: List[TelemetryEventContext]
) -> List[TelemetryEventContext]:
    """
    Deduplicates a list of TelemetryEventContext objects by unique ID.
    """
    seen_ids: Set[str] = set()
    deduped: List[TelemetryEventContext] = []

    for item in telemetry_list:
        if item.id and item.id not in seen_ids:
            deduped.append(item)
            seen_ids.add(item.id)

    return deduped


def filter_background_noise(
    telemetry_list: List[TelemetryEventContext],
    explicit_matched_ids: Set[str]
) -> List[TelemetryEventContext]:
    """
    Filters out routine healthcheck requests unless they were explicitly
    flagged as a matched event in a detection rule.
    """
    filtered: List[TelemetryEventContext] = []

    for tel in telemetry_list:
        # Never filter out explicitly matched evidence events
        if tel.id in explicit_matched_ids:
            filtered.append(tel)
            continue

        # Check path noise
        if tel.httpPath and tel.httpPath.lower() in NOISE_PATHS:
            continue

        # Check user-agent noise
        if tel.userAgent and any(agent.lower() in tel.userAgent.lower() for agent in NOISE_USER_AGENTS):
            continue

        filtered.append(tel)

    return filtered


def filter_by_time_window(
    telemetry_list: List[TelemetryEventContext],
    anchor_timestamp_str: Optional[str],
    explicit_matched_ids: Set[str],
    pre_window_seconds: int = 3600,   # 1 hour prior to incident
    post_window_seconds: int = 1800,  # 30 minutes after incident
) -> List[TelemetryEventContext]:
    """
    Filters telemetry to events within a bounded time window relative to
    the incident anchor time. Events explicitly matched by detections are always preserved.
    """
    if not anchor_timestamp_str:
        return telemetry_list

    anchor_epoch = parse_timestamp_safe(anchor_timestamp_str)
    if anchor_epoch == 0.0:
        return telemetry_list

    min_epoch = anchor_epoch - pre_window_seconds
    max_epoch = anchor_epoch + post_window_seconds

    filtered: List[TelemetryEventContext] = []
    for tel in telemetry_list:
        if tel.id in explicit_matched_ids:
            filtered.append(tel)
            continue

        tel_epoch = parse_timestamp_safe(tel.timestamp)
        if tel_epoch == 0.0 or (min_epoch <= tel_epoch <= max_epoch):
            filtered.append(tel)

    return filtered


def cap_and_prioritize_telemetry(
    telemetry_list: List[TelemetryEventContext],
    explicit_matched_ids: Set[str],
    max_events: int = 50
) -> List[TelemetryEventContext]:
    """
    Deterministically prioritizes and caps telemetry volume to max_events:
    Priority 1: Explicitly matched detection events (never dropped)
    Priority 2: Suspicious/Security events (AUTH_FAILURE, SUSPICIOUS_REQUEST, 4xx/5xx)
    Priority 3: General events touching affected assets
    Priority 4: Other surrounding timeline events
    """
    if len(telemetry_list) <= max_events:
        return telemetry_list

    tier1: List[TelemetryEventContext] = []
    tier2: List[TelemetryEventContext] = []
    tier3: List[TelemetryEventContext] = []
    tier4: List[TelemetryEventContext] = []

    security_event_types = {"AUTH_FAILURE", "SUSPICIOUS_REQUEST", "PRIVILEGE_CHANGE"}

    for tel in telemetry_list:
        if tel.id in explicit_matched_ids:
            tier1.append(tel)
        elif tel.eventType in security_event_types or (tel.httpStatusCode and tel.httpStatusCode in (401, 403, 500)):
            tier2.append(tel)
        elif tel.resourceAccessed or tel.sourceIp:
            tier3.append(tel)
        else:
            tier4.append(tel)

    # Assemble in priority order up to max_events
    result: List[TelemetryEventContext] = []
    for tier in [tier1, tier2, tier3, tier4]:
        for item in tier:
            if len(result) < max_events or item.id in explicit_matched_ids:
                result.append(item)

    return result


def sort_chronologically(
    events: List[Any]
) -> List[Any]:
    """
    Sorts telemetry events, evidence items, or detections chronologically
    in ascending order by their timestamp field.
    """
    return sorted(
        events,
        key=lambda e: parse_timestamp_safe(getattr(e, "timestamp", None))
    )
