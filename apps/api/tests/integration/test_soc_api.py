import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.security import create_jwt_token


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(settings, "SOC_RATE_LIMIT_REQUESTS", 5)
    monkeypatch.setattr(settings, "SOC_ESCALATION_COUNT", 2)
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def auth():
    return {"Authorization": f"Bearer {create_jwt_token({'sub': 'analyst', 'role': 'admin'})}"}


def test_rate_limit_returns_429_problem_json(client):
    for _ in range(5):
        r = client.get("/api/v1/assets")
        assert r.status_code != 429
        assert r.headers["ratelimit-limit"] == "5"
    r = client.get("/api/v1/assets")
    assert r.status_code == 429
    assert r.headers["content-type"] == "application/problem+json"
    assert int(r.headers["retry-after"]) > 0
    body = r.json()
    assert body["code"] == "RATE_LIMITED" and body["incidentId"].startswith("inc-")
    assert r.headers["x-content-type-options"] == "nosniff"


def test_injection_locks_source_with_423_and_dashboard_sees_it(client, auth):
    r = client.post("/api/v1/auth/login", json={"email": "a' OR '1'='1' --", "password": "x"})
    assert r.status_code == 423
    assert r.json()["code"] == "SOURCE_LOCKED"
    assert r.headers["ratelimit-remaining"] == "0"
    assert client.get("/api/v1/assets").status_code == 423  # lock persists

    incidents = client.get("/api/v1/soc/incidents", headers=auth).json()
    assert incidents[0]["stage"] == "MITIGATED" and incidents[0]["blockedRequests"] >= 2

    fid = incidents[0]["findingIds"][0]
    analysis = client.get(f"/api/v1/soc/findings/{fid}/analysis", headers=auth).json()
    assert analysis["finding"]["field"] == "email"
    assert any("prepared statements" in r["title"].lower() for r in analysis["recommendations"])

    metrics = client.get("/api/v1/soc/metrics?window=30", headers=auth).json()
    assert metrics["totals"]["locked"] >= 2 and metrics["activeMitigations"]

    source = metrics["activeMitigations"][0]["sourceKey"]
    assert client.delete(f"/api/v1/soc/mitigations/{source}", headers=auth).status_code == 200
    assert client.get("/api/v1/assets").status_code != 423


def test_malformed_json_is_flagged_but_allowed(client, auth):
    r = client.post("/api/v1/auth/login", content=b'{"email": ', headers={"content-type": "application/json"})
    assert r.status_code not in (423, 429)
    findings = client.get("/api/v1/soc/findings", headers=auth).json()
    assert findings[0]["category"] == "MALFORMED_PAYLOAD"


def test_oversized_body_rejected_413(client, monkeypatch):
    big = b"x" * (settings.SOC_MAX_BODY_BYTES + 1)
    r = client.post("/api/v1/auth/login", content=big, headers={"content-type": "text/plain"})
    assert r.status_code == 413


def test_soc_routes_require_auth_and_are_exempt_from_enforcement(client):
    assert client.get("/api/v1/soc/metrics").status_code == 401
    for _ in range(20):
        assert client.get("/api/v1/soc/metrics").status_code == 401  # never 429


def test_telemetry_brute_force_returns_enforcement(client):
    events = [{
        "id": f"e{i}", "eventType": "AUTH_FAILURE", "timestamp": "2026-10-25T00:00:00Z",
        "sourceService": "demo-target", "environmentId": "env-1",
        "payload": {"sourceIp": "203.0.113.7", "httpPath": "/login"},
    } for i in range(5)]
    r = client.post("/api/v1/telemetry/ingest", json={"events": events},
                    headers={"X-GASHA-TELEMETRY-KEY": settings.GASHA_TELEMETRY_API_KEY})
    assert r.status_code == 202
    enf = r.json()["enforcement"]
    assert enf == [{"action": "LOCK", "statusCode": 423, "ruleId": "RULE-AUTH-001",
                    "retryAfterSeconds": settings.SOC_LOCK_DURATION_SECONDS, "sourceKey": "203.0.113.7"}]


def test_telemetry_collector_is_not_locked_by_attack_evidence(client):
    probe = [{
        "id": "p1", "eventType": "SUSPICIOUS_REQUEST", "timestamp": "2026-10-25T00:00:00Z",
        "sourceService": "demo-target", "environmentId": "env-1",
        "payload": {"sourceIp": "198.51.100.23", "httpPath": "/search?q=1 UNION SELECT password FROM users"},
    }]
    key = {"X-GASHA-TELEMETRY-KEY": settings.GASHA_TELEMETRY_API_KEY}
    r = client.post("/api/v1/telemetry/ingest", json={"events": probe}, headers=key)
    assert r.status_code == 202
    assert r.json()["enforcement"][0]["sourceKey"] == "198.51.100.23"
    # The collector itself (testclient) keeps working.
    assert client.post("/api/v1/telemetry/ingest", json={"events": []}, headers=key).status_code == 202
