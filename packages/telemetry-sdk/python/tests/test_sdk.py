"""
Unit tests for GASHA Telemetry SDK Facade and developer convenience methods.
Validates typed event factories, secret stripping in convenience methods,
and singleton management.
"""
import pytest
from unittest.mock import MagicMock

from gasha_telemetry import GashaTelemetry, init_telemetry, get_telemetry
from models import TelemetryEventType
from sanitizers import REDACTED_VALUE


def test_sdk_convenience_auth_failure():
    sdk = GashaTelemetry(
        endpoint="http://mock-ingest/api/v1/telemetry/ingest",
        api_key="test-key",
        environment_id="env-test",
        service_name="auth-service",
        auto_start=False
    )
    sdk.client = MagicMock()

    sdk.auth_failure(
        user_id="victim_user",
        source_ip="198.51.100.22",
        reason="Bad credentials",
        metadata={"attempt_count": 3, "password_entered": "PlainTextPassword!"}
    )

    assert sdk.client.enqueue.called
    event = sdk.client.enqueue.call_args[0][0]

    assert event.eventType == TelemetryEventType.AUTH_FAILURE
    assert event.payload.userId == "victim_user"
    assert event.payload.sourceIp == "198.51.100.22"
    assert event.payload.action == "LOGIN"
    assert event.payload.outcome == "FAILURE"
    # Verify sensitive data in metadata is redacted
    assert event.payload.metadata["attempt_count"] == 3
    assert event.payload.metadata["password_entered"] == REDACTED_VALUE


def test_sdk_convenience_auth_success():
    sdk = GashaTelemetry(auto_start=False)
    sdk.client = MagicMock()

    sdk.auth_success(
        user_id="alice",
        source_ip="192.0.2.1",
        session_id="sess_xyz987"
    )

    event = sdk.client.enqueue.call_args[0][0]
    assert event.eventType == TelemetryEventType.AUTH_SUCCESS
    assert event.payload.userId == "alice"
    assert event.payload.sessionId == "sess_xyz987"
    assert event.payload.outcome == "SUCCESS"


def test_sdk_convenience_privilege_change():
    sdk = GashaTelemetry(auto_start=False)
    sdk.client = MagicMock()

    sdk.privilege_change(
        target_user_id="bob",
        actor_user_id="admin_1",
        old_role="viewer",
        new_role="admin"
    )

    event = sdk.client.enqueue.call_args[0][0]
    assert event.eventType == TelemetryEventType.PRIVILEGE_CHANGE
    assert event.payload.userId == "bob"
    assert event.payload.metadata["old_role"] == "viewer"
    assert event.payload.metadata["new_role"] == "admin"


def test_sdk_convenience_outbound_connection():
    sdk = GashaTelemetry(auto_start=False)
    sdk.client = MagicMock()

    sdk.outbound_connection(
        target_host="198.51.100.5",
        target_port=443,
        protocol="TCP"
    )

    event = sdk.client.enqueue.call_args[0][0]
    assert event.eventType == TelemetryEventType.OUTBOUND_CONNECTION
    assert event.payload.resourceAccessed == "198.51.100.5:443"
    assert event.payload.metadata["protocol"] == "TCP"


def test_sdk_singleton_management():
    instance = init_telemetry(
        api_key="singleton-key",
        service_name="single-srv",
        auto_start=False
    )
    retrieved = get_telemetry()
    assert retrieved is instance
    assert retrieved.service_name == "single-srv"
