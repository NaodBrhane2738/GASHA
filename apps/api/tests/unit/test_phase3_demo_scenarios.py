"""
Demonstration Scenarios A through E exercising the Phase 3 backend pipeline.
Verifies end-to-end evidence linking, partitioning, deduplication, and outcome preservation.
"""
import asyncio
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
    get_telemetry_ingester().reset_state()
    get_detection_engine().reset_state()
    get_event_deduplicator().clear()
    get_correlation_engine().reset_state()
    get_incident_repository().clear()
    get_detection_repository().clear()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_header_prod():
    token = create_jwt_token({"sub": "analyst-prod", "environmentId": "env-prod"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_header_dev():
    token = create_jwt_token({"sub": "analyst-dev", "environmentId": "env-dev"})
    return {"Authorization": f"Bearer {token}"}


def test_scenario_a_brute_force_pattern(client, auth_header_prod):
    """
    Scenario A: Repeated authentication failures from one source within configured window.
    Verifies: Telemetry -> Detection finding -> Correlated incident -> Evidence-linked incident record.
    """
    api_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")

    # 1. Submit 5 failed login events
    events = [
        {
            "id": f"scen-a-evt-{i}",
            "schemaVersion": "1.0.0",
            "eventType": "AUTH_FAILURE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "idp-gateway",
            "environmentId": "env-prod",
            "payload": {
                "sourceIp": "198.51.100.50",
                "userId": "finance_admin",
                "action": "LOGIN",
                "outcome": "FAILURE"
            }
        }
        for i in range(5)
    ]

    resp = client.post(
        "/api/v1/telemetry/ingest",
        json={"events": events},
        headers={"X-GASHA-TELEMETRY-KEY": api_key}
    )
    assert resp.status_code == 202

    # 2. Flush background buffer
    asyncio.run(flush_all_pending())

    # 3. Verify detection finding exists
    det_resp = client.get("/api/v1/detections", headers=auth_header_prod)
    assert det_resp.status_code == 200
    detections = det_resp.json()
    assert len(detections) == 1
    det = detections[0]
    assert det["rule"]["ruleId"] == "RULE-AUTH-001"
    assert det["severity"] == "HIGH"
    assert len(det["matchedEventIds"]) == 5

    # 4. Verify correlated incident exists with evidence link
    inc_resp = client.get("/api/v1/incidents", headers=auth_header_prod)
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["status"] == "ACTIVE"
    assert det["id"] in inc["detectionEventIds"]
    assert "198.51.100.50" in inc["title"]


def test_scenario_b_suspicious_web_probe(client, auth_header_prod):
    """
    Scenario B: Supported SQL injection, XSS, or path-traversal probe through ingestion pipeline.
    Verifies matching rule and incident evidence.
    """
    api_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")

    # Ingest Path Traversal probe
    probe_event = [{
        "id": "scen-b-evt-1",
        "schemaVersion": "1.0.0",
        "eventType": "SUSPICIOUS_REQUEST",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sourceService": "web-api",
        "environmentId": "env-prod",
        "payload": {
            "sourceIp": "203.0.113.88",
            "httpMethod": "GET",
            "httpPath": "/api/download?file=../../../../etc/shadow",
            "metadata": {"pattern_type": "PATH_TRAVERSAL_PROBE"}
        }
    }]

    resp = client.post(
        "/api/v1/telemetry/ingest",
        json={"events": probe_event},
        headers={"X-GASHA-TELEMETRY-KEY": api_key}
    )
    assert resp.status_code == 202
    asyncio.run(flush_all_pending())

    # Verify detection finding
    det_resp = client.get("/api/v1/detections", headers=auth_header_prod)
    assert det_resp.status_code == 200
    detections = det_resp.json()
    assert len(detections) == 1
    assert detections[0]["rule"]["ruleId"] == "RULE-INJ-002"
    assert "PATH_TRAVERSAL_PROBE" in detections[0]["evidenceSummary"]

    # Verify incident
    inc_resp = client.get("/api/v1/incidents", headers=auth_header_prod)
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()
    assert len(incidents) == 1
    assert "203.0.113.88" in incidents[0]["title"]


def test_scenario_c_separate_sources_and_environments(client, auth_header_prod, auth_header_dev):
    """
    Scenario C: Similar suspicious activity from different sources and environments.
    Verifies findings and incidents remain partitioned rather than merging into a global incident.
    """
    api_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")

    prod_events = [
        # Source 1 in env-prod
        {
            "id": "scen-c-prod-1",
            "eventType": "SUSPICIOUS_REQUEST",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "prod-web",
            "environmentId": "env-prod",
            "payload": {
                "sourceIp": "198.51.100.1",
                "httpMethod": "GET",
                "httpPath": "/search?q=' OR 1=1--",
                "metadata": {"pattern_type": "SQL_INJECTION_PROBE"}
            }
        },
        # Source 2 in env-prod
        {
            "id": "scen-c-prod-2",
            "eventType": "SUSPICIOUS_REQUEST",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "prod-web",
            "environmentId": "env-prod",
            "payload": {
                "sourceIp": "198.51.100.2",
                "httpMethod": "GET",
                "httpPath": "/search?q=' OR 1=1--",
                "metadata": {"pattern_type": "SQL_INJECTION_PROBE"}
            }
        }
    ]

    dev_events = [
        # Source 1 in env-dev
        {
            "id": "scen-c-dev-1",
            "eventType": "SUSPICIOUS_REQUEST",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "dev-web",
            "environmentId": "env-dev",
            "payload": {
                "sourceIp": "198.51.100.1",
                "httpMethod": "GET",
                "httpPath": "/search?q=' OR 1=1--",
                "metadata": {"pattern_type": "SQL_INJECTION_PROBE"}
            }
        }
    ]

    resp_prod = client.post(
        "/api/v1/telemetry/ingest",
        json={"events": prod_events},
        headers={"X-GASHA-TELEMETRY-KEY": api_key, "X-GASHA-ENVIRONMENT": "env-prod"}
    )
    assert resp_prod.status_code == 202

    resp_dev = client.post(
        "/api/v1/telemetry/ingest",
        json={"events": dev_events},
        headers={"X-GASHA-TELEMETRY-KEY": api_key, "X-GASHA-ENVIRONMENT": "env-dev"}
    )
    assert resp_dev.status_code == 202

    asyncio.run(flush_all_pending())

    # Query env-prod incidents: should have 2 distinct incidents (one for IP 1, one for IP 2)
    inc_prod = client.get("/api/v1/incidents", headers=auth_header_prod).json()
    assert len(inc_prod) == 2
    sources_in_prod = {inc["title"] for inc in inc_prod}
    assert any("198.51.100.1" in title for title in sources_in_prod)
    assert any("198.51.100.2" in title for title in sources_in_prod)

    # Query env-dev incidents: should have 1 distinct incident
    inc_dev = client.get("/api/v1/incidents", headers=auth_header_dev).json()
    assert len(inc_dev) == 1
    assert inc_dev[0]["environmentId"] == "env-dev"


def test_scenario_d_duplicate_retry_delivery(client, auth_header_prod):
    """
    Scenario D: Replaying an identical event and a duplicated batch.
    Verifies duplicate delivery does not inflate thresholds or create duplicate incidents.
    """
    api_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")

    # Submit batch of 2 failed logins
    batch = [
        {
            "id": f"scen-d-evt-{i}",
            "eventType": "AUTH_FAILURE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "auth",
            "environmentId": "env-prod",
            "payload": {"sourceIp": "198.51.100.99", "action": "LOGIN", "outcome": "FAILURE"}
        }
        for i in range(2)
    ]

    # Ingest 1st time
    client.post("/api/v1/telemetry/ingest", json={"events": batch}, headers={"X-GASHA-TELEMETRY-KEY": api_key})
    asyncio.run(flush_all_pending())

    # Ingest exact same batch a 2nd time (simulating network retry)
    client.post("/api/v1/telemetry/ingest", json={"events": batch}, headers={"X-GASHA-TELEMETRY-KEY": api_key})
    asyncio.run(flush_all_pending())

    # Ingest exact same batch a 3rd time
    client.post("/api/v1/telemetry/ingest", json={"events": batch}, headers={"X-GASHA-TELEMETRY-KEY": api_key})
    asyncio.run(flush_all_pending())

    # Total unique attempts is 2 -> Threshold of 5 is NOT reached -> 0 detections, 0 incidents
    dets = client.get("/api/v1/detections", headers=auth_header_prod).json()
    assert len(dets) == 0, "Duplicate submissions must NOT inflate threshold counts"


def test_scenario_e_mixed_success_and_failure(client, auth_header_prod):
    """
    Scenario E: Submit mixture of successful authentication/resource access and denied actions.
    Verifies underlying outcomes are preserved and detector does not turn a denied action into compromise.
    """
    api_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026")

    events = [
        # 1. Normal successful login
        {
            "id": "scen-e-evt-1",
            "eventType": "AUTH_SUCCESS",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "idp",
            "environmentId": "env-prod",
            "payload": {"sourceIp": "198.51.100.12", "userId": "alice", "action": "LOGIN", "outcome": "SUCCESS"}
        },
        # 2. Normal successful resource access
        {
            "id": "scen-e-evt-2",
            "eventType": "RESOURCE_ACCESS",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "app",
            "environmentId": "env-prod",
            "payload": {"sourceIp": "198.51.100.12", "resourceAccessed": "/dashboard", "action": "READ", "outcome": "GRANTED"}
        },
        # 3. Denied privilege escalation attempt
        {
            "id": "scen-e-evt-3",
            "eventType": "PRIVILEGE_CHANGE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sourceService": "iam",
            "environmentId": "env-prod",
            "payload": {
                "sourceIp": "198.51.100.12",
                "userId": "alice",
                "action": "ROLE_MUTATION",
                "outcome": "DENIED",
                "metadata": {"old_role": "viewer", "new_role": "admin"}
            }
        }
    ]

    resp = client.post(
        "/api/v1/telemetry/ingest",
        json={"events": events},
        headers={"X-GASHA-TELEMETRY-KEY": api_key}
    )
    assert resp.status_code == 202
    asyncio.run(flush_all_pending())

    # Verify detection generated only for the denied privilege escalation
    dets = client.get("/api/v1/detections", headers=auth_header_prod).json()
    assert len(dets) == 1
    det = dets[0]
    assert det["rule"]["ruleId"] == "RULE-PRIV-004"
    assert "DENIED" in det["evidenceSummary"]
    assert "Unauthorized privilege escalation attempt" in det["evidenceSummary"]

    # Verify incident preserves outcome
    incs = client.get("/api/v1/incidents", headers=auth_header_prod).json()
    assert len(incs) == 1
    assert "alice" in incs[0]["summary"]
