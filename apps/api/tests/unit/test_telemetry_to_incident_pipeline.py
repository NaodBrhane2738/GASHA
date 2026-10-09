"""
Integration tests for End-to-End Pipeline:
Authenticated Ingestion -> Telemetry Buffer -> Processor -> Detection Engine -> Correlation -> Incident Store -> APIs.
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.core.security import create_jwt_token
from app.telemetry.ingester import get_telemetry_ingester
from app.workers.telemetry import flush_all_pending
from app.detection.engine import get_detection_engine
from app.detection.deduplicator import get_event_deduplicator
from app.correlation.engine import get_correlation_engine
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository


@pytest.fixture(autouse=True)
def reset_all_state():
    """Resets all in-memory pipelines, deduplicators, and repositories before each test."""
    get_telemetry_ingester().reset_state()
    get_detection_engine().reset_state()
    get_event_deduplicator().clear()
    get_correlation_engine().reset_state()
    get_incident_repository().clear()
    get_detection_repository().clear()


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    token = create_jwt_token({"sub": "analyst-1", "environmentId": "env-prod", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def make_ingest_payload(events: list) -> dict:
    return {"events": events}


def test_pipeline_auth_failure_brute_force_to_incident(test_client, auth_headers):
    valid_api_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")

    # Ingest 5 failed login attempts
    events = []
    for i in range(5):
        events.append({
            "id": f"evt-bf-{i}",
            "schemaVersion": "1.0.0",
            "eventType": "AUTH_FAILURE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "auth-service",
            "environmentId": "env-prod",
            "payload": {
                "sourceIp": "198.51.100.77",
                "userId": "target_user",
                "action": "LOGIN",
                "outcome": "FAILURE"
            }
        })

    ingest_resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json=make_ingest_payload(events),
        headers={"X-GASHA-TELEMETRY-KEY": valid_api_key}
    )
    assert ingest_resp.status_code == 202

    # Flush the background buffer into the detection/correlation pipeline
    import asyncio
    asyncio.run(flush_all_pending())

    # Query detections via API
    det_resp = test_client.get("/api/v1/detections", headers=auth_headers)
    assert det_resp.status_code == 200
    detections = det_resp.json()
    assert len(detections) >= 1
    bf_det = next(d for d in detections if d["rule"]["ruleId"] == "RULE-AUTH-001")
    assert bf_det["severity"] == "HIGH"
    assert len(bf_det["matchedEventIds"]) == 5

    # Query incidents via API
    inc_resp = test_client.get("/api/v1/incidents", headers=auth_headers)
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc["status"] == "ACTIVE"
    assert inc["severity"] == "HIGH"
    assert bf_det["id"] in inc["detectionEventIds"]


def test_pipeline_suspicious_probe_to_incident(test_client, auth_headers):
    valid_api_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")

    probe_event = [{
        "id": "evt-probe-99",
        "schemaVersion": "1.0.0",
        "eventType": "SUSPICIOUS_REQUEST",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sourceService": "web-gateway",
        "environmentId": "env-prod",
        "payload": {
            "sourceIp": "203.0.113.195",
            "httpMethod": "GET",
            "httpPath": "/search?q=' UNION SELECT 1,2--",
            "metadata": {"pattern_type": "SQL_INJECTION_PROBE"}
        }
    }]

    resp = test_client.post(
        "/api/v1/telemetry/ingest",
        json=make_ingest_payload(probe_event),
        headers={"X-GASHA-TELEMETRY-KEY": valid_api_key}
    )
    assert resp.status_code == 202

    import asyncio
    asyncio.run(flush_all_pending())

    # Check incident created
    inc_resp = test_client.get("/api/v1/incidents", headers=auth_headers)
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()
    assert len(incidents) == 1
    inc = incidents[0]
    assert "Suspicious Web Intrusion" in inc["title"]


def test_incident_status_update_via_api(test_client, auth_headers):
    # Pre-create an incident in repository
    from app.schemas.incident import IncidentResponse
    repo = get_incident_repository()
    repo.create_incident(IncidentResponse(
        id="inc-api-test",
        title="Test Incident",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId="asset-1",
        relatedAssetIds=[],
        detectionEventIds=["det-1"],
        createdAt="2026-10-09T12:00:00Z",
        updatedAt="2026-10-09T12:00:00Z",
        environmentId="env-prod"
    ))

    # Update status: ACTIVE -> INVESTIGATING
    patch_resp = test_client.patch(
        "/api/v1/incidents/inc-api-test/status",
        json={"status": "INVESTIGATING", "reason": "Triage started"},
        headers=auth_headers
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "INVESTIGATING"

    # Invalid transition: INVESTIGATING -> ACTIVE is allowed, but invalid string is rejected
    invalid_resp = test_client.patch(
        "/api/v1/incidents/inc-api-test/status",
        json={"status": "NONEXISTENT_STATUS"},
        headers=auth_headers
    )
    assert invalid_resp.status_code == 422


def test_cross_environment_incident_access_rejected(test_client):
    from app.schemas.incident import IncidentResponse
    repo = get_incident_repository()
    repo.create_incident(IncidentResponse(
        id="inc-isolated",
        title="Confidential Dev Incident",
        severity="LOW",
        status="ACTIVE",
        primaryAffectedAssetId="asset-1",
        relatedAssetIds=[],
        detectionEventIds=[],
        createdAt="2026-10-09T12:00:00Z",
        updatedAt="2026-10-09T12:00:00Z",
        environmentId="env-dev"
    ))

    # User authorized for env-prod only
    token_prod = create_jwt_token({"sub": "user-prod", "environmentId": "env-prod"})
    resp = test_client.get(
        "/api/v1/incidents/inc-isolated",
        headers={"Authorization": f"Bearer {token_prod}"}
    )
    assert resp.status_code == 404
