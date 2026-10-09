"""
==============================================================================
FILE: apps/api/app/telemetry/validator.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Validates telemetry events against strict schema rules, timestamp sanity,
           environment boundary constraints, and payload boundaries.
TOOLS & LIBRARIES: Pydantic v2, datetime, ipaddress
==============================================================================
"""

import json
import logging
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional, Set

from app.schemas.telemetry import TelemetryEventSchema

logger = logging.getLogger("gasha.telemetry.validator")

# Supported canonical event types
VALID_EVENT_TYPES: Set[str] = {
    "AUTH_FAILURE",
    "AUTH_SUCCESS",
    "HTTP_REQUEST",
    "SUSPICIOUS_REQUEST",
    "RESOURCE_ACCESS",
    "PRIVILEGE_CHANGE",
    "OUTBOUND_CONNECTION",
}

# Timestamp acceptance window
MAX_EVENT_AGE_SECONDS = 7 * 24 * 3600  # 7 days
MAX_FUTURE_DRIFT_SECONDS = 3600        # 1 hour
MAX_PAYLOAD_JSON_BYTES = 65536         # 64 KB per single event payload


def parse_iso_timestamp(ts_str: str) -> Optional[datetime]:
    """Parses ISO-8601 timestamp string into timezone-aware UTC datetime."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        # Standardize 'Z' to '+00:00' for datetime.fromisoformat compatibility
        cleaned = ts_str.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def validate_ip_format(ip_str: Optional[str]) -> bool:
    """Validates if string is a syntactically valid IPv4 or IPv6 address."""
    if not ip_str:
        return True
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_event(
    event: TelemetryEventSchema,
    authorized_environment: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """
    Validates a single telemetry event.
    Returns:
        (True, None) if valid.
        (False, error_reason) if invalid.
    """
    # 1. Event ID validation
    if not event.id or not isinstance(event.id, str) or len(event.id.strip()) == 0:
        return False, "Event ID must be a non-empty string"
    if len(event.id) > 128:
        return False, "Event ID exceeds maximum length of 128 characters"

    # 2. Event Type validation
    if event.eventType not in VALID_EVENT_TYPES:
        return False, f"Unsupported event type: '{event.eventType}'"

    # 3. Source Service validation
    if not event.sourceService or not isinstance(event.sourceService, str) or len(event.sourceService.strip()) == 0:
        return False, "sourceService must be a non-empty string"
    if len(event.sourceService) > 128:
        return False, "sourceService exceeds maximum length of 128 characters"

    # 4. Environment validation
    if not event.environmentId or not isinstance(event.environmentId, str) or len(event.environmentId.strip()) == 0:
        return False, "environmentId must be a non-empty string"
    if len(event.environmentId) > 64:
        return False, "environmentId exceeds maximum length of 64 characters"
    if authorized_environment and event.environmentId != authorized_environment:
        return False, f"environmentId '{event.environmentId}' does not match authorized scope '{authorized_environment}'"

    # 5. Timestamp sanity check
    dt = parse_iso_timestamp(event.timestamp)
    if dt is None:
        return False, f"Invalid ISO-8601 timestamp: '{event.timestamp}'"

    now_utc = datetime.now(timezone.utc)
    age_seconds = (now_utc - dt).total_seconds()

    if age_seconds > MAX_EVENT_AGE_SECONDS:
        return False, f"Event timestamp is too old ({age_seconds:.0f}s > {MAX_EVENT_AGE_SECONDS}s window)"
    if age_seconds < -MAX_FUTURE_DRIFT_SECONDS:
        return False, f"Event timestamp is too far in future ({-age_seconds:.0f}s > {MAX_FUTURE_DRIFT_SECONDS}s drift limit)"

    # 6. Payload validation
    if not event.payload:
        return False, "Event payload is missing"

    if event.payload.sourceIp and not validate_ip_format(event.payload.sourceIp):
        return False, f"Invalid sourceIp address format: '{event.payload.sourceIp}'"

    if event.payload.observedPeerIp and not validate_ip_format(event.payload.observedPeerIp):
        return False, f"Invalid observedPeerIp address format: '{event.payload.observedPeerIp}'"

    if event.payload.metadata:
        try:
            metadata_bytes = len(json.dumps(event.payload.metadata))
            if metadata_bytes > MAX_PAYLOAD_JSON_BYTES:
                return False, f"Event payload metadata exceeds {MAX_PAYLOAD_JSON_BYTES} bytes limit ({metadata_bytes} bytes)"
        except (TypeError, ValueError) as e:
            return False, f"Event metadata cannot be serialized to JSON: {str(e)}"

    return True, None
