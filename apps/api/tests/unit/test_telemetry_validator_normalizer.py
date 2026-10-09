"""
Unit tests for GASHA Telemetry Server-Side Validator and Normalizer.
Verifies schema constraints, timestamp bounds, environment boundaries,
IP canonicalization, and defense-in-depth sanitization.
"""
from datetime import datetime, timezone, timedelta
import pytest

from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema
from app.telemetry.validator import validate_event
from app.telemetry.normalizer import (
    normalize_telemetry_event,
    normalize_ip_address,
    normalize_iso_timestamp,
    REDACTED_VALUE,
)


def make_valid_schema_event(
    event_id: str = "evt-valid-01",
    event_type: str = "HTTP_REQUEST",
    timestamp: str = None,
    source_service: str = "order-api",
    environment_id: str = "env-prod",
    source_ip: str = "198.51.100.10",
    metadata: dict = None
) -> TelemetryEventSchema:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return TelemetryEventSchema(
        id=event_id,
        schemaVersion="1.0.0",
        eventType=event_type,
        timestamp=ts,
        sourceService=source_service,
        environmentId=environment_id,
        payload=TelemetryEventPayloadSchema(
            sourceIp=source_ip,
            httpMethod="get",
            httpPath="/orders/123",
            httpStatusCode=200,
            metadata=metadata or {"cart_id": "cart_99"}
        )
    )


def test_validator_accepts_valid_event():
    event = make_valid_schema_event()
    is_valid, reason = validate_event(event)
    assert is_valid is True
    assert reason is None


def test_validator_rejects_empty_id():
    event = make_valid_schema_event(event_id="   ")
    is_valid, reason = validate_event(event)
    assert is_valid is False
    assert "Event ID" in reason


def test_validator_rejects_unsupported_event_type():
    event = make_valid_schema_event()
    # Bypass pydantic validation for testing validator logic directly
    event.__dict__["eventType"] = "UNKNOWN_ATTACK"
    is_valid, reason = validate_event(event)
    assert is_valid is False
    assert "Unsupported event type" in reason


def test_validator_enforces_environment_boundary():
    event = make_valid_schema_event(environment_id="env-staging")
    # Authorized environment is env-prod
    is_valid, reason = validate_event(event, authorized_environment="env-prod")
    assert is_valid is False
    assert "does not match authorized scope" in reason

    # Matches authorized scope
    is_valid, reason = validate_event(event, authorized_environment="env-staging")
    assert is_valid is True


def test_validator_timestamp_sanity_window():
    now_utc = datetime.now(timezone.utc)

    # 8 days ago (exceeds 7-day limit)
    stale_ts = (now_utc - timedelta(days=8)).isoformat()
    event_stale = make_valid_schema_event(timestamp=stale_ts)
    is_valid, reason = validate_event(event_stale)
    assert is_valid is False
    assert "too old" in reason

    # 2 hours in the future (exceeds 1-hour drift limit)
    future_ts = (now_utc + timedelta(hours=2)).isoformat()
    event_future = make_valid_schema_event(timestamp=future_ts)
    is_valid, reason = validate_event(event_future)
    assert is_valid is False
    assert "too far in future" in reason

    # 10 minutes ago (valid)
    valid_ts = (now_utc - timedelta(minutes=10)).isoformat()
    event_ok = make_valid_schema_event(timestamp=valid_ts)
    is_valid, reason = validate_event(event_ok)
    assert is_valid is True


def test_validator_rejects_malformed_ip():
    event = make_valid_schema_event(source_ip="not-an-ip-address")
    is_valid, reason = validate_event(event)
    assert is_valid is False
    assert "Invalid sourceIp" in reason


def test_normalizer_ip_canonicalization():
    assert normalize_ip_address("  192.168.1.1  ") == "192.168.1.1"
    # IPv4-mapped IPv6 unmapping
    assert normalize_ip_address("::ffff:192.0.2.128") == "192.0.2.128"
    assert normalize_ip_address(None) is None


def test_normalizer_timestamp_iso_utc():
    ts = normalize_iso_timestamp("2026-10-09T14:30:00+02:00")
    assert ts.endswith("Z")
    assert ts == "2026-10-09T12:30:00Z"


def test_normalizer_defense_in_depth_sanitization():
    raw_event = make_valid_schema_event(
        metadata={
            "session_id": "sess_preserved_123",
            "user_id": "usr_preserved_456",
            "password": "ServerShouldRedactThis!",
            "client_secret": "SuperSecretToken",
            "auth": "Basic dXNlcjpwYXNz",
            "safe_data": "NormalValue"
        }
    )
    normalized = normalize_telemetry_event(raw_event)

    # HTTP method normalized to uppercase
    assert normalized.payload.httpMethod == "GET"

    # Preserved correlation identifiers
    assert normalized.payload.metadata["session_id"] == "sess_preserved_123"
    assert normalized.payload.metadata["user_id"] == "usr_preserved_456"
    assert normalized.payload.metadata["safe_data"] == "NormalValue"

    # Redacted secrets
    assert normalized.payload.metadata["password"] == REDACTED_VALUE
    assert normalized.payload.metadata["client_secret"] == REDACTED_VALUE
    assert normalized.payload.metadata["auth"] == REDACTED_VALUE

    # Attached server receipt timestamp
    assert "_serverReceivedAt" in normalized.payload.metadata
    assert normalized.payload.metadata["_serverReceivedAt"].endswith("Z")
