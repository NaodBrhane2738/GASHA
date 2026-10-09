"""
==============================================================================
FILE: apps/demo-target/tests/test_demo_target_defenses.py
OBJECTIVE: Unit and integration tests for Demo Target security defenses and endpoints.
           Verifies authentication, resource access, probe handling, blocklist,
           and session invalidation.
==============================================================================
"""

import pytest
from fastapi.testclient import TestClient

try:
    from apps.demo_target.main import create_demo_target_app
    from apps.demo_target.security.blocklist import block_ip, clear_blocklist, is_blocked
    from apps.demo_target.security.sessions import disable_session, clear_disabled_sessions, is_session_disabled
except ImportError:
    from main import create_demo_target_app
    from security.blocklist import block_ip, clear_blocklist, is_blocked
    from security.sessions import disable_session, clear_disabled_sessions, is_session_disabled



@pytest.fixture
def target_client():
    clear_blocklist()
    clear_disabled_sessions()
    app = create_demo_target_app()
    return TestClient(app)


def test_health_check(target_client):
    res = target_client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert res.json()["service"] == "gasha-demo-target"


def test_login_success_and_failure(target_client):
    # Success admin
    res_succ = target_client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SuperAdmin2026!"},
        headers={"X-Forwarded-For": "10.0.0.1"}
    )
    assert res_succ.status_code == 200
    assert res_succ.json()["status"] == "success"
    assert "sess-admin-" in res_succ.json()["token"]

    # Failure bad password
    res_fail = target_client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "WrongPassword!"},
        headers={"X-Forwarded-For": "10.0.0.1"}
    )
    assert res_fail.status_code == 401
    assert res_fail.json()["error"] == "INVALID_CREDENTIALS"


def test_normal_resource_access(target_client):
    res = target_client.get("/api/tickets", headers={"X-Forwarded-For": "10.0.0.2"})
    assert res.status_code == 200
    assert len(res.json()["tickets"]) > 0


def test_probe_patterns_handled_safely(target_client):
    # SQLi probe
    res_sqli = target_client.get(
        "/api/customers/lookup?query=' UNION SELECT 1,2,3--",
        headers={"X-Forwarded-For": "10.0.0.3"}
    )
    assert res_sqli.status_code == 200
    assert res_sqli.json()["status"] == "safe_handled"
    assert res_sqli.json()["detectedPattern"] == "SQL_INJECTION"

    # XSS probe
    res_xss = target_client.get(
        "/api/customers/lookup?query=<script>alert(1)</script>",
        headers={"X-Forwarded-For": "10.0.0.3"}
    )
    assert res_xss.status_code == 200
    assert res_xss.json()["status"] == "safe_handled"
    assert res_xss.json()["detectedPattern"] == "XSS_PROBE"

    # Path traversal probe
    res_trav = target_client.get(
        "/api/customers/lookup?query=../../etc/passwd",
        headers={"X-Forwarded-For": "10.0.0.3"}
    )
    assert res_trav.status_code == 200
    assert res_trav.json()["status"] == "safe_handled"
    assert res_trav.json()["detectedPattern"] == "PATH_TRAVERSAL"


def test_admin_access_controls(target_client):
    # Without admin token: 403
    res_denied = target_client.get("/api/admin/secrets", headers={"X-Forwarded-For": "10.0.0.4"})
    assert res_denied.status_code == 403
    assert res_denied.json()["error"] == "FORBIDDEN"

    # With admin token: 200
    login_res = target_client.post("/api/auth/login", json={"username": "admin", "password": "SuperAdmin2026!"})
    token = login_res.json()["token"]

    res_allowed = target_client.get(
        "/api/admin/secrets",
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "10.0.0.4"}
    )
    assert res_allowed.status_code == 200
    assert "crownJewel" in res_allowed.json()


def test_privilege_mutation_denied_for_non_admin(target_client):
    # Login as analyst
    login_res = target_client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass2026!"})
    token = login_res.json()["token"]

    res_priv = target_client.post(
        "/api/admin/privilege-change",
        json={"targetUser": "analyst", "newRole": "admin"},
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "10.0.0.5"}
    )
    assert res_priv.status_code == 403
    assert res_priv.json()["error"] == "UNAUTHORIZED_ROLE_MUTATION"


def test_source_ip_blocklist_enforcement(target_client):
    attacker_ip = "198.51.100.99"
    benign_ip = "10.0.0.10"

    # Initially allowed
    assert target_client.get("/health", headers={"X-Forwarded-For": attacker_ip}).status_code == 200

    # Add to blocklist
    block_ip(attacker_ip)
    assert is_blocked(attacker_ip) is True

    # Blocked requests return 403
    res_blocked = target_client.get("/health", headers={"X-Forwarded-For": attacker_ip})
    assert res_blocked.status_code == 403
    assert res_blocked.json()["error"] == "ACCESS_BLOCKED_BY_GASHA"

    # Benign requests unaffected
    res_benign = target_client.get("/health", headers={"X-Forwarded-For": benign_ip})
    assert res_benign.status_code == 200


def test_session_invalidation_enforcement(target_client):
    login_res = target_client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass2026!"})
    token = login_res.json()["token"]

    # Valid session accesses resource
    res_before = target_client.get("/api/tickets", headers={"Authorization": f"Bearer {token}"})
    assert res_before.status_code == 200

    # Invalidate session
    disable_session(token)
    assert is_session_disabled(token) is True

    # Subsequent requests rejected with 401
    res_after = target_client.get("/api/tickets", headers={"Authorization": f"Bearer {token}"})
    assert res_after.status_code == 401
    assert res_after.json()["error"] == "SESSION_REVOKED_BY_GASHA"
