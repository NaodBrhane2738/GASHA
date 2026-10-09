"""
Unit tests for GASHA Telemetry SDK Delivery Client.
Validates non-blocking queueing, background batch delivery,
saturation handling, retry policy, and clean shutdown.
"""
import time
from unittest.mock import patch, MagicMock
import pytest
import httpx

from client import TelemetryClient, TelemetryClientConfig
from models import TelemetryEvent, TelemetryEventType, TelemetryEventPayload


def make_test_event(idx: int = 1) -> TelemetryEvent:
    return TelemetryEvent(
        id=f"test-evt-{idx}",
        eventType=TelemetryEventType.HTTP_REQUEST,
        sourceService="test-srv",
        environmentId="env-test",
        payload=TelemetryEventPayload(
            httpMethod="GET",
            httpPath=f"/api/resource/{idx}",
            httpStatusCode=200
        )
    )


def test_client_enqueue_non_blocking():
    client = TelemetryClient(
        endpoint="http://mock-ingest/api/v1/telemetry/ingest",
        api_key="test-key",
        auto_start=False
    )
    event = make_test_event(1)
    enqueued = client.enqueue(event)
    assert enqueued is True
    assert client.get_queue_depth() == 1

    metrics = client.get_metrics()
    assert metrics.queued_count == 1
    assert metrics.dropped_count == 0


def test_client_buffer_saturation_drop_oldest():
    # Buffer max size of 3
    client = TelemetryClient(
        endpoint="http://mock-ingest/api/v1/telemetry/ingest",
        api_key="test-key",
        max_queue_size=3,
        auto_start=False
    )
    for i in range(5):
        client.enqueue(make_test_event(i))

    assert client.get_queue_depth() == 3
    metrics = client.get_metrics()
    assert metrics.queued_count == 5
    assert metrics.dropped_count == 2


@patch("httpx.Client.post")
def test_client_successful_transmission(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 202
    mock_response.is_success = True
    mock_post.return_value = mock_response

    client = TelemetryClient(
        endpoint="http://mock-ingest/api/v1/telemetry/ingest",
        api_key="test-key",
        batch_size=2,
        auto_start=False
    )
    client.enqueue(make_test_event(1))
    client.enqueue(make_test_event(2))

    # Trigger synchronous flush
    client.flush()

    assert client.get_queue_depth() == 0
    assert mock_post.called
    assert mock_post.call_count == 1

    # Verify headers sent
    call_kwargs = mock_post.call_args[1]
    assert call_kwargs["headers"]["X-GASHA-TELEMETRY-KEY"] == "test-key"
    assert "Bearer test-key" in call_kwargs["headers"]["Authorization"]

    metrics = client.get_metrics()
    assert metrics.transmitted_count == 2
    assert metrics.error_count == 0


@patch("httpx.Client.post")
def test_client_drops_on_client_error(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.is_success = False
    mock_post.return_value = mock_response

    client = TelemetryClient(
        endpoint="http://mock-ingest/api/v1/telemetry/ingest",
        api_key="test-key",
        batch_size=2,
        max_retries=3,
        auto_start=False
    )
    client.enqueue(make_test_event(1))
    client.flush()

    # Should NOT retry 400 client error
    assert mock_post.call_count == 1
    metrics = client.get_metrics()
    assert metrics.error_count == 1


@patch("httpx.Client.post")
def test_client_retries_on_server_error(mock_post):
    mock_response_fail = MagicMock()
    mock_response_fail.status_code = 503
    mock_response_fail.is_success = False

    mock_response_ok = MagicMock()
    mock_response_ok.status_code = 202
    mock_response_ok.is_success = True

    # Fail twice, succeed on 3rd attempt
    mock_post.side_effect = [mock_response_fail, mock_response_fail, mock_response_ok]

    client = TelemetryClient(
        endpoint="http://mock-ingest/api/v1/telemetry/ingest",
        api_key="test-key",
        max_retries=3,
        auto_start=False
    )
    client.enqueue(make_test_event(1))
    client.flush()

    assert mock_post.call_count == 3
    metrics = client.get_metrics()
    assert metrics.transmitted_count == 1
    assert metrics.retry_count == 2


def test_client_shutdown():
    client = TelemetryClient(
        endpoint="http://mock-ingest/api/v1/telemetry/ingest",
        api_key="test-key",
        auto_start=True
    )
    assert client.get_metrics().is_running is True
    client.shutdown(timeout_seconds=1.0)
    assert client.get_metrics().is_running is False
