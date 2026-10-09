"""
==============================================================================
FILE: apps/api/app/telemetry/normalizer.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Normalizes timestamps, IP formats, header strings, and applies
           defense-in-depth metadata sanitization across telemetry sources.
TOOLS & LIBRARIES: Python datetime, ipaddress, re
==============================================================================
"""

import re
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema

# Sensitive key patterns for server-side defense-in-depth sanitization
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"^.*(pass(word)?|passwd).*$", re.IGNORECASE),
    re.compile(r"^.*(client_secret|client_key|private_key|privkey).*$", re.IGNORECASE),
    re.compile(r"^.*(secret).*$", re.IGNORECASE),
    re.compile(r"^.*(access_token|refresh_token|id_token|bearer_token|auth_token).*$", re.IGNORECASE),
    re.compile(r"^.*(cookie|set_cookie).*$", re.IGNORECASE),
    re.compile(r"^.*(api[_-]?key).*$", re.IGNORECASE),
    re.compile(r"^.*(credit[_-]?card|card[_-]?num(ber)?|cvv|cvc).*$", re.IGNORECASE),
]

EXACT_SENSITIVE_KEYS = {
    "token", "authorization", "auth", "session_secret", "session_token",
    "signature", "sig", "pin", "credential", "credentials", "proxy-authorization"
}

PRESERVED_KEYS = {
    "session_id", "sessionid", "sessionId", "user_id", "userid", "userId",
    "auth_method", "auth_result", "action", "outcome", "target", "resource",
    "resourceAccessed", "endpoint", "path", "source_ip", "sourceip", "sourceIp",
    "client_id", "agent_id", "environment_id", "environmentId", "correlation_id",
    "correlationId", "event_id", "status_code", "http_status", "httpStatusCode",
    "http_method", "httpMethod", "_serverReceivedAt"
}

JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
REDACTED_VALUE = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    stripped = key.strip()
    if stripped in PRESERVED_KEYS or stripped.lower() in PRESERVED_KEYS:
        return False
    lower_key = stripped.lower()
    if lower_key in EXACT_SENSITIVE_KEYS:
        return True
    return any(p.search(lower_key) for p in SENSITIVE_KEY_PATTERNS)


def sanitize_server_value(value: Any) -> Any:
    """Recursively walks nested structures and redacts sensitive data."""
    if isinstance(value, dict):
        sanitized_dict = {}
        for k, v in value.items():
            str_key = str(k)
            if is_sensitive_key(str_key):
                sanitized_dict[k] = REDACTED_VALUE
            else:
                sanitized_dict[k] = sanitize_server_value(v)
        return sanitized_dict
    elif isinstance(value, list):
        return [sanitize_server_value(item) for item in value]
    elif isinstance(value, tuple):
        return tuple(sanitize_server_value(item) for item in value)
    elif isinstance(value, str):
        val_lower = value.strip().lower()
        if val_lower.startswith("bearer ") and len(value) > 7:
            return "Bearer [REDACTED]"
        if val_lower.startswith("basic ") and len(value) > 6:
            return "Basic [REDACTED]"
        if JWT_PATTERN.match(value.strip()):
            return "[REDACTED_JWT]"
        return value
    return value


def normalize_ip_address(ip_str: Optional[str]) -> Optional[str]:
    """
    Normalizes IP string to canonical format.
    Unmaps IPv4-in-IPv6 addresses (e.g. ::ffff:192.168.1.1 -> 192.168.1.1).
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    cleaned = ip_str.strip()
    try:
        parsed = ipaddress.ip_address(cleaned)
        # Check for IPv4-mapped IPv6
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except ValueError:
        return cleaned


def normalize_iso_timestamp(ts_str: str) -> str:
    """Standardizes timestamp into ISO-8601 UTC string."""
    try:
        cleaned = ts_str.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_telemetry_event(event: TelemetryEventSchema) -> TelemetryEventSchema:
    """
    Applies standard normalization and server-side defense-in-depth sanitization:
    - Normalizes timestamp to ISO-8601 UTC 'Z'
    - Canonicalizes client and peer IP addresses
    - Normalizes HTTP methods to uppercase
    - Redacts sensitive secrets from metadata
    - Records server receipt timestamp in metadata
    """
    normalized_ts = normalize_iso_timestamp(event.timestamp)
    norm_source_ip = normalize_ip_address(event.payload.sourceIp)
    norm_peer_ip = normalize_ip_address(event.payload.observedPeerIp)

    norm_http_method = (
        event.payload.httpMethod.strip().upper()
        if event.payload.httpMethod
        else None
    )

    clean_metadata = sanitize_server_value(event.payload.metadata or {})
    if not isinstance(clean_metadata, dict):
        clean_metadata = {}
    clean_metadata["_serverReceivedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    normalized_payload = TelemetryEventPayloadSchema(
        sourceIp=norm_source_ip,
        observedPeerIp=norm_peer_ip,
        userAgent=event.payload.userAgent,
        userId=event.payload.userId,
        sessionId=event.payload.sessionId,
        httpMethod=norm_http_method,
        httpPath=event.payload.httpPath,
        httpStatusCode=event.payload.httpStatusCode,
        resourceAccessed=event.payload.resourceAccessed,
        action=event.payload.action,
        outcome=event.payload.outcome,
        latencyMs=event.payload.latencyMs,
        correlationId=event.payload.correlationId,
        metadata=clean_metadata
    )

    return TelemetryEventSchema(
        id=event.id.strip(),
        schemaVersion=event.schemaVersion or "1.0.0",
        eventType=event.eventType,
        timestamp=normalized_ts,
        sourceService=event.sourceService.strip(),
        environmentId=event.environmentId.strip(),
        payload=normalized_payload
    )
