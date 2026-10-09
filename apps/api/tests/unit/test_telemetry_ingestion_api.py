"""
Unit and integration tests for GASHA Telemetry Ingestion API Endpoint.
Validates authentication, batch constraints, deduplication,
pipeline metrics, and health reporting.
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.telemetry.ingester import get_telemetry_ingester


@pytest.fixture(autouse=True)
def reset_ingester():
    """Resets ingester buffer, dedup cache, and counters between tests."""
    ingester = get_telemetry_ingester()
    ingester.reset_state()


@pytest.fixture
def test_client():
    return TestClient(app)


def build_event_dict(event_id: str, event_type: str = "HTTP_REQUEST", source_ip: str = "192.0.2.1") -> dict:
    return {
        "id": event_id,
        "schemaVersion": "1.0.0",
        "eventType": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sourceService": "checkout-service",
        "environmentId": getattr(settings, "GASHA_TELEMETRY_ENVIRONMENT", "env-prod"),
        "payload": {
            "sourceIp": source_ip,
            "httpMethod": "POST",
            "httpPath": "/api/checkout",
            "httpStatusCode": 200,
            "metadata": {"order_id": "ord_1234"}
        }
    }


def test_ingest_requires_authentication(test_client):
    # No header provided
    resp = test_client.post("/api/v1/telemetry/ingest", json={"events": [build_event_dict("evt-1")]})
    assert resp.status_code == 401

    # Invalid API key
    resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": [build_event_dict("evt-1")]},
        headers={"X-GASHA-TELEMETRY-KEY": "wrong-invalid-key"}
    )
    assert resp.status_code == 401


def test_ingest_succeeds_with_valid_api_key(test_client):
    valid_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")
    events = [build_event_dict("evt-auth-1"), build_event_dict("evt-auth-2")]

    resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": events},
        headers={"X-GASHA-TELEMETRY-KEY": valid_key}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "ACCEPTED"
    assert data["acceptedCount"] == 2
    assert data["rejectedCount"] == 0
    assert data["duplicateCount"] == 0
    assert len(data["results"]) == 2
    assert data["results"][0]["status"] == "accepted"


def test_ingest_succeeds_with_bearer_token(test_client):
    valid_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")
    events = [build_event_dict("evt-bearer-1")]

    resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": events},
        headers={"Authorization": f"Bearer {valid_key}"}
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "ACCEPTED"


def test_ingest_rejects_empty_batch(test_client):
    valid_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")
    resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": []},
        headers={"X-GASHA-TELEMETRY-KEY": valid_key}
    )
    assert resp.status_code == 400
    assert "contains no telemetry events" in resp.json()["detail"]


def test_ingest_rejects_oversized_batch(test_client):
    valid_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")
    oversized = [build_event_dict(f"evt-over-{i}") for i in range(105)]

    resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": oversized},
        headers={"X-GASHA-TELEMETRY-KEY": valid_key}
    )
    assert resp.status_code == 400
    assert "exceeds maximum limit" in resp.json()["detail"]


def test_ingest_deduplication(test_client):
    valid_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")
    evt = build_event_dict("evt-dedup-unique-1")

    # First ingestion -> accepted
    resp1 = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": [evt]},
        headers={"X-GASHA-TELEMETRY-KEY": valid_key}
    )
    assert resp1.status_code == 202
    assert resp1.json()["acceptedCount"] == 1
    assert resp1.json()["duplicateCount"] == 0

    # Second ingestion of the same event ID -> duplicate
    resp2 = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": [evt]},
        headers={"X-GASHA-TELEMETRY-KEY": valid_key}
    )
    assert resp2.status_code == 202
    assert resp2.json()["acceptedCount"] == 0
    assert resp2.json()["duplicateCount"] == 1
    assert resp2.json()["results"][0]["status"] == "duplicate"


def test_ingest_partially_accepted_batch(test_client):
    valid_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")
    good_evt = build_event_dict("evt-good-1")
    bad_evt = build_event_dict("evt-bad-1", source_ip="not_an_ip")

    resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": [good_evt, bad_evt]},
        headers={"X-GASHA-TELEMETRY-KEY": valid_key}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "PARTIALLY_ACCEPTED"
    assert data["acceptedCount"] == 1
    assert data["rejectedCount"] == 1
    assert data["totalCount"] == 2


def test_telemetry_health_endpoint(test_client):
    resp = test_client.get("/api/v1/telemetry/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "queueDepth" in data
    assert "bufferCapacity" in data
    assert "droppedOverflow" in data


def test_telemetry_metrics_endpoint(test_client):
    valid_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")
    test_client.post(
        "/api/v1/telemetry/ingest",
        json={"events": [build_event_dict("evt-metric-1")]},
        headers={"X-GASHA-TELEMETRY-KEY": valid_key}
    )

    resp = test_client.get("/api/v1/telemetry/metrics")
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["events_received"] >= 1
    assert metrics["events_accepted"] >= 1
    assert metrics["batches_processed"] >= 1
    assert metrics["queue_depth"] >= 1
