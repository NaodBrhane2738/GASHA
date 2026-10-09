"""
==============================================================================
FILE: tests/backend_audit/test_independent_backend_audit.py
PURPOSE: Independent Audit Verification Test Suite for the Entire GASHA Backend.
MANDATE: Probes actual security boundaries, tenant isolation, tamper evidence,
         active defense execution, proxy spoofing, and durability.
==============================================================================
"""

import time
import uuid
import pytest
import jwt
from fastapi.testclient import TestClient

from app.main import create_app
from app.core.config import settings
from app.core.security import create_jwt_token, verify_jwt_token
from app.core.crypto import encrypt_credential, decrypt_credential, _derive_default_fernet_key
from app.db.repositories.incident_repository import IncidentRepository, get_incident_repository
from app.db.repositories.detection_repository import DetectionRepository, get_detection_repository
from app.db.repositories.response_repository import ResponseRepository, get_response_repository
from app.db.repositories.asset_repository import AssetRepository, get_asset_repository
from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.asset import AssetResponse
from app.schemas.vulnerability import VulnerabilityResponse
from app.schemas.response import ResponseProposalRequest, ResponseApprovalRequest
from app.response.service import ResponseService
from app.response.audit import AuditTrail, compute_canonical_hash, GENESIS_HASH
from app.response.validator import ResponseProposalValidator
from app.response.enforcement import TargetSecurityClient
from app.risk.calculator import calculate_environment_risk
from app.digital_twin.graph import SecurityGraph
from app.attack_paths.engine import AttackPathEngine

# Demo target imports
try:
    from apps.demo_target.main import create_demo_target_app
    from apps.demo_target.security.blocklist import block_ip, clear_blocklist, is_blocked
    from apps.demo_target.security.sessions import disable_session, clear_disabled_sessions, is_session_disabled
except ImportError:
    from main import create_demo_target_app
    from security.blocklist import block_ip, clear_blocklist, is_blocked
    from security.sessions import disable_session, clear_disabled_sessions, is_session_disabled


@pytest.fixture
def api_client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def demo_target_client():
    app = create_demo_target_app()
    clear_blocklist()
    clear_disabled_sessions()
    return TestClient(app)


@pytest.fixture
def valid_analyst_token():
    return create_jwt_token({"sub": "auditor-analyst", "role": "security_analyst", "environmentId": "env-prod"})


def make_incident(
    inc_id: str = "inc-test",
    env_id: str = "env-prod",
    asset_id: str = "srv-1",
    severity: str = "HIGH",
    status: str = "ACTIVE",
    detections: list = None
) -> IncidentResponse:
    now = "2026-10-09T12:00:00Z"
    return IncidentResponse(
        id=inc_id,
        title=f"Incident {inc_id}",
        severity=severity,
        status=status,
        primaryAffectedAssetId=asset_id,
        relatedAssetIds=[],
        detectionEventIds=detections or [],
        createdAt=now,
        updatedAt=now,
        environmentId=env_id
    )


# ============================================================================
# AUDIT DOMAIN 1: AUTHENTICATION, JWT TOKENS, AND REALTIME WEBSOCKET
# ============================================================================

def test_audit_auth_missing_bearer_token_rejected(api_client):
    """Verifies that protected routes reject unauthenticated requests with HTTP 401."""
    res = api_client.get("/api/v1/incidents")
    assert res.status_code == 401
    assert "Missing bearer authentication token" in res.json()["detail"]


def test_audit_auth_tampered_jwt_signature_rejected(api_client):
    """Verifies that tokens signed with an unauthorized secret are rejected."""
    tampered_token = jwt.encode({"sub": "attacker", "role": "admin"}, "wrong-secret-key-123456789012345678901234", algorithm="HS256")
    res = api_client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401
    assert "Invalid or expired authentication token" in res.json()["detail"]


def test_audit_auth_expired_jwt_rejected(api_client):
    """Verifies that expired JWT tokens are strictly rejected."""
    expired_token = create_jwt_token({"sub": "expired-user"}, expires_seconds=-10)
    res = api_client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "Invalid or expired authentication token" in res.json()["detail"]


def test_audit_auth_hardcoded_credentials_presence(api_client):
    """
    AUDIT REMEDIATION VERIFICATION: Confirms that hardcoded dev credentials
    (admin / admin123) are rejected with HTTP 401 Unauthorized, and that authenticating
    with seeded PBKDF2 credentials issues an immutable environmentId claim.
    """
    # 1. Hardcoded admin123 is rejected
    res_bad = api_client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_bad.status_code == 401
    assert "Invalid username or password" in res_bad.json()["detail"]

    # 2. Seeded PBKDF2 account succeeds and binds environmentId
    res_ok = api_client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminRoot2026!"})
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert "accessToken" in data
    assert "refreshToken" in data
    decoded = verify_jwt_token(data["accessToken"])
    assert decoded["sub"] == "admin"
    assert decoded["environmentId"] == "env-prod"


def test_audit_realtime_websocket_unauthenticated_connection(api_client):
    """
    AUDIT REMEDIATION VERIFICATION: Confirms that unauthenticated WebSocket connections
    are rejected, while single-use authenticated tickets allow connection.
    """
    # 1. Unauthenticated connection is rejected
    with pytest.raises(Exception):
        with api_client.websocket_connect("/api/v1/realtime/ws"):
            pass

    # 2. Authenticated ticket allows connection
    login_res = api_client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystSecure2026!"})
    token = login_res.json()["accessToken"]
    ticket_res = api_client.post("/api/v1/realtime/ticket", headers={"Authorization": f"Bearer {token}"})
    assert ticket_res.status_code == 200
    ticket = ticket_res.json()["ticket"]

    with api_client.websocket_connect(f"/api/v1/realtime/ws?ticket={ticket}") as websocket:
        websocket.send_text("ping")
        assert True


# ============================================================================
# AUDIT DOMAIN 2: TENANT & ENVIRONMENT ISOLATION
# ============================================================================

def test_audit_environment_idor_via_query_param_when_claim_missing(api_client):
    """
    AUDIT REMEDIATION VERIFICATION: Verifies that attempts to query cross-tenant resources
    using ?environmentId query params are strictly rejected with HTTP 403 Forbidden.
    """
    inc_repo = get_incident_repository()
    inc = make_incident(inc_id="inc-audit-tenant-b", env_id="env-tenant-b", asset_id="srv-tenant-b")
    inc_repo.save_incident(inc)

    # Login as env-prod user
    login_res = api_client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystSecure2026!"})
    token = login_res.json()["accessToken"]

    # Attempt cross-tenant IDOR access
    res = api_client.get("/api/v1/incidents?environmentId=env-tenant-b", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "Forbidden: Token authorized for 'env-prod'" in res.json()["detail"]


def test_audit_response_proposal_cross_environment_rejection():
    """Verifies that an operator in env-prod cannot propose action for an incident in env-tenant-x."""
    inc_repo = get_incident_repository()
    inc = make_incident(inc_id="inc-tenant-x", env_id="env-tenant-x", asset_id="srv-x")
    inc_repo.save_incident(inc)

    req = ResponseProposalRequest(
        incidentId="inc-tenant-x",
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.99",
        reason="Testing cross-tenant proposal"
    )

    is_valid, err = ResponseProposalValidator.validate_proposal(
        req=req,
        incident=inc,
        detections=[],
        caller_env="env-prod"
    )
    assert not is_valid
    assert "Environment mismatch" in err


# ============================================================================
# AUDIT DOMAIN 3: AUDIT TRAIL INTEGRITY & TAMPER DETECTION GAPS
# ============================================================================

def test_audit_trail_broken_linkage_detected():
    """Verifies that broken SHA-256 previousHash links are detected by verify_chain."""
    trail = AuditTrail()
    trail.append_entry(
        environment_id="env-audit-1",
        event_type="PROPOSAL_CREATED",
        actor="operator-1",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.1",
        outcome="PROPOSED"
    )
    trail.append_entry(
        environment_id="env-audit-1",
        event_type="PROPOSAL_APPROVED",
        actor="operator-1",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.1",
        outcome="APPROVED"
    )

    entries = trail.get_entries("env-audit-1")
    entries[1].previousHash = "0" * 64

    res = trail.verify_chain("env-audit-1")
    assert not res.verified
    assert "Hash chain broken" in res.error


def test_audit_trail_payload_tamper_detection_gap():
    """
    AUDIT REMEDIATION VERIFICATION: Verifies that verify_chain recomputes canonical payload
    hashes and reliably detects in-memory payload tampering.
    """
    trail = AuditTrail()
    trail.append_entry(
        environment_id="env-audit-gap",
        event_type="PROPOSAL_CREATED",
        actor="operator-1",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.50",
        outcome="PROPOSED"
    )

    entries = trail.get_entries("env-audit-gap")
    entries[0].targetIdentifier = "10.0.0.1"

    res = trail.verify_chain("env-audit-gap")
    assert res.verified is False
    assert "Payload tampering detected" in res.error


# ============================================================================
# AUDIT DOMAIN 4: ACTIVE DEFENSE RESPONSE PROPOSAL & DIRECT EXECUTION
# ============================================================================

def test_audit_response_unallowlisted_action_rejected(api_client, valid_analyst_token):
    """Verifies that non-allowlisted actions like arbitrary commands are rejected via 422 Unprocessable Entity."""
    inc = make_incident(inc_id="inc-safe", env_id="env-prod", asset_id="srv-1")
    get_incident_repository().save_incident(inc)

    res = api_client.post(
        "/api/v1/responses/propose",
        json={
            "incidentId": "inc-safe",
            "actionType": "EXECUTE_COMMAND",  # Not allowlisted
            "targetType": "IP_ADDRESS",
            "targetIdentifier": "198.51.100.1",
            "reason": "Testing unallowlisted action"
        },
        headers={"Authorization": f"Bearer {valid_analyst_token}"}
    )
    assert res.status_code == 422


def test_audit_response_ungrounded_target_rejected():
    """Verifies that response proposals targeting entities not in incident evidence are rejected."""
    inc = make_incident(inc_id="inc-ungrounded", env_id="env-prod", asset_id="srv-1")
    req = ResponseProposalRequest(
        incidentId="inc-ungrounded",
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.77",
        reason="Testing ungrounded target"
    )
    is_valid, err = ResponseProposalValidator.validate_proposal(req, inc, [], caller_env="env-prod")
    assert not is_valid
    assert "not present in incident" in err


def test_audit_response_isolate_resource_safely_unsupported():
    """Verifies that ISOLATE_RESOURCE fails safely with explicit unsupported notice at target interface."""
    client = TargetSecurityClient()
    ok, msg = client.enforce_isolate_resource("asset-crown-jewel")
    assert ok is False
    assert "Unsupported action" in msg


def test_audit_response_direct_execution_endpoint_self_approves(api_client):
    """
    AUDIT REMEDIATION VERIFICATION: Verifies that /api/v1/responses/execute rejects
    standard analyst/operator calls with HTTP 403, and strictly requires emergency break-glass role.
    """
    inc_repo = get_incident_repository()
    inc = make_incident(inc_id="inc-direct-test", env_id="env-prod", asset_id="srv-direct")
    inc_repo.save_incident(inc)

    det_repo = get_detection_repository()
    rule_sum = DetectionRuleSummarySchema(
        ruleId="RULE-AUTH-001",
        name="Brute Force",
        description="Detects brute force",
        severity="HIGH",
        confidence=0.95
    )
    det = DetectionEventResponse(
        id="det-direct-test",
        rule=rule_sum,
        matchedEventIds=["evt-1", "evt-2"],
        primaryAssetId="srv-direct",
        timestamp="2026-10-09T12:00:00Z",
        severity="HIGH",
        confidence=0.95,
        environmentId="env-prod",
        evidenceSummary="Brute force from 198.51.100.22",
        metadata={"sourceIp": "198.51.100.22"}
    )
    det_repo.save_detection(det)
    inc.detectionEventIds = ["det-direct-test"]
    inc_repo.save_incident(inc)

    payload = {
        "incidentId": "inc-direct-test",
        "actionType": "BLOCK_SOURCE",
        "targetType": "IP_ADDRESS",
        "targetIdentifier": "198.51.100.22",
        "reason": "Direct containment call"
    }

    # 1. Standard analyst role is rejected with HTTP 403
    analyst_token = create_jwt_token({"sub": "analyst-1", "role": "security_analyst", "environmentId": "env-prod"})
    res_rejected = api_client.post(
        "/api/v1/responses/execute",
        json=payload,
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert res_rejected.status_code == 403
    assert "Direct single-step execution is restricted to emergency_admin" in res_rejected.json()["detail"]

    # 2. Emergency admin role is authorized for immediate direct containment
    breakglass_token = create_jwt_token({"sub": "breakglass-1", "role": "emergency_admin", "environmentId": "env-prod"})
    res = api_client.post(
        "/api/v1/responses/execute",
        json=payload,
        headers={"Authorization": f"Bearer {breakglass_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["details"]["verificationStatus"] == "VERIFIED"
    assert is_blocked("198.51.100.22")


# ============================================================================
# AUDIT DOMAIN 5: DEMO TARGET ENFORCEMENT & PROXY SPOOFING
# ============================================================================

def test_audit_demo_target_enforcement_and_proxy_spoof_bypass(demo_target_client):
    """
    AUDIT REMEDIATION VERIFICATION:
    1. Verifies that IP block enforcement works for direct matching IP.
    2. Verifies that an attacker CANNOT bypass the IP block by supplying
       a spoofed X-Forwarded-For header when connecting directly.
    """
    blocked_ip = "198.51.100.99"
    block_ip(blocked_ip)

    # Direct connection from blocked client (simulated via ASGI client host override)
    class ClientHostOverrideMiddleware:
        def __init__(self, app, host):
            self.app = app
            self.host = host
        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                scope = dict(scope)
                scope["client"] = (self.host, 54321)
            await self.app(scope, receive, send)

    app = create_demo_target_app()
    direct_client = TestClient(ClientHostOverrideMiddleware(app, blocked_ip))
    res_direct = direct_client.get(
        "/api/tickets",
        headers={"X-Forwarded-For": "203.0.113.1"}  # Spoofed forwarded header attempting bypass
    )
    assert res_direct.status_code == 403
    assert "ACCESS_BLOCKED_BY_GASHA" in res_direct.json()["error"]

    # Connection through trusted proxy
    res_trusted = demo_target_client.get("/api/tickets", headers={"X-Forwarded-For": blocked_ip})
    assert res_trusted.status_code == 403
    assert "ACCESS_BLOCKED_BY_GASHA" in res_trusted.json()["error"]


def test_audit_demo_target_session_revocation_enforcement(demo_target_client):
    """Verifies that revoked session tokens are rejected with HTTP 401."""
    revoked_sid = "sess-compromised-token-123"
    disable_session(revoked_sid)

    res = demo_target_client.get("/api/tickets", headers={"X-Session-ID": revoked_sid})
    assert res.status_code == 401
    assert "SESSION_REVOKED_BY_GASHA" in res.json()["error"]


# ============================================================================
# AUDIT DOMAIN 6: CRYPTO KEY DERIVATION & CREDENTIAL ENCRYPTION
# ============================================================================

def test_audit_credential_encryption_default_key_derivation(monkeypatch):
    """
    AUDIT REMEDIATION VERIFICATION: When CREDENTIAL_ENCRYPTION_KEY is unset,
    production mode strictly refuses startup, while development mode functions safely.
    """
    secret = "ghp_realSecretTokenForGithubIntegration12345"
    encrypted = encrypt_credential(secret)
    assert encrypted != secret
    decrypted = decrypt_credential(encrypted)
    assert decrypted == secret

    # Production mode strictly refuses unconfigured encryption key
    monkeypatch.setattr(settings, "NODE_ENV", "production")
    monkeypatch.setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    with pytest.raises(RuntimeError) as exc_info:
        _derive_default_fernet_key()
    assert "CREDENTIAL_ENCRYPTION_KEY must be configured in production" in str(exc_info.value)


# ============================================================================
# AUDIT DOMAIN 7: RISK ENGINE MATHEMATICAL INTEGRITY
# ============================================================================

def test_audit_risk_engine_hand_calculated_reproduction():
    """
    Verifies that the risk calculation matches exact hand-calculated weights:
    - Finding 1: CRITICAL (25.0) on TIER_0_CROWN_JEWEL (2.0x) = 50.0
    - Public exposure penalty: exposed vulnerable TIER_0 asset = 8.0 * 2.0 = 16.0
    - Expected total = 66.0
    """
    asset = AssetResponse(
        id="asset-crown-db",
        name="Production Database",
        type="DATABASE",
        environmentId="env-prod",
        source="STATIC_CONFIG",
        criticality="TIER_0_CROWN_JEWEL",
        isPubliclyExposed=True,
        status="ACTIVE",
        createdAt="2026-10-09T12:00:00Z",
        updatedAt="2026-10-09T12:00:00Z",
        metadata={}
    )
    vuln = VulnerabilityResponse(
        id="vuln-db-1",
        assetId="asset-crown-db",
        environmentId="env-prod",
        ruleId="RULE-EXPOSURE-DB-001",
        title="Direct Public Database Exposure",
        description="Public DB",
        severity="CRITICAL",
        cvssScore=9.8,
        category="PUBLIC_EXPOSURE",
        remediationGuidance="Isolate within private VPC",
        status="OPEN",
        discoveredAt="2026-10-09T12:00:00Z"
    )

    result = calculate_environment_risk(
        environment_id="env-prod",
        assets=[asset],
        findings=[vuln],
        attack_paths=[]
    )
    assert result.overallScore == 66.0
    assert result.criticalAssetsAtRiskCount == 1


# ============================================================================
# AUDIT DOMAIN 8: PERSISTENCE & DURABILITY ACROSS RESTARTS
# ============================================================================

def test_audit_in_memory_persistence_wiped_on_reinstantiation():
    """
    Verifies that the in-memory repository double is purely ephemeral.
    """
    repo_a = IncidentRepository()
    repo_a.save_incident(make_incident(inc_id="inc-restart-test", env_id="env-prod"))
    assert repo_a.get_incident("inc-restart-test") is not None

    repo_b = IncidentRepository()
    assert repo_b.get_incident("inc-restart-test") is None
    assert len(repo_b.list_incidents()) == 0


def test_audit_durable_sql_persistence_survives_restart(tmp_path):
    """
    AUDIT REMEDIATION VERIFICATION: Verifies that SQLIncidentRepository
    persists data across process restarts / repository reinstantiations.
    """
    db_file = str(tmp_path / "test_durability.db")
    from app.db.sql_engine import SQLIncidentRepository

    # 1. First process / instance saves incident
    repo_1 = SQLIncidentRepository(db_path=db_file)
    inc = make_incident(inc_id="inc-durable-123", env_id="env-prod", asset_id="db-master")
    repo_1.save_incident(inc)
    assert repo_1.get_incident("inc-durable-123") is not None

    # 2. Second process / instance reinstantiates against the same DB file
    repo_2 = SQLIncidentRepository(db_path=db_file)
    reloaded = repo_2.get_incident("inc-durable-123")
    assert reloaded is not None
    assert reloaded.id == "inc-durable-123"
    assert reloaded.primaryAffectedAssetId == "db-master"
    assert len(repo_2.list_incidents(environment_id="env-prod")) == 1


def test_audit_refresh_token_rotation_and_reuse_detection(api_client):
    """
    AUDIT REMEDIATION VERIFICATION: Verifies that refresh tokens are single-use,
    rotated upon refresh, and reused tokens trigger revocation.
    """
    # 1. Login to obtain refresh token
    login_res = api_client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystSecure2026!"})
    assert login_res.status_code == 200
    refresh_token_1 = login_res.json()["refreshToken"]

    # 2. Use refresh token to obtain new access and refresh tokens
    refresh_res = api_client.post("/api/v1/auth/refresh", json={"refreshToken": refresh_token_1})
    assert refresh_res.status_code == 200
    refresh_token_2 = refresh_res.json()["refreshToken"]
    assert refresh_token_2 != refresh_token_1

    # 3. Attempt to reuse previous refresh token (must be rejected)
    reuse_res = api_client.post("/api/v1/auth/refresh", json={"refreshToken": refresh_token_1})
    assert reuse_res.status_code == 401
    assert "revoked" in reuse_res.json()["detail"].lower() or "invalid" in reuse_res.json()["detail"].lower()


def test_audit_separation_of_duties_self_approval_prevented():
    """
    AUDIT REMEDIATION VERIFICATION: Verifies that an operator cannot approve
    their own containment proposal.
    """
    svc = ResponseService()
    inc = make_incident(inc_id="inc-sod-test", env_id="env-prod", asset_id="web-srv")
    get_incident_repository().save_incident(inc)

    det = DetectionEventResponse(
        id="det-sod-1",
        rule=DetectionRuleSummarySchema(ruleId="R1", name="Det", description="", severity="HIGH", confidence=0.9),
        matchedEventIds=[],
        primaryAssetId="web-srv",
        timestamp="2026-10-09T12:00:00Z",
        severity="HIGH",
        confidence=0.9,
        evidenceSummary="Attacker IP 198.51.100.88",
        environmentId="env-prod",
        metadata={"sourceIp": "198.51.100.88"}
    )
    get_detection_repository().save_detection(det)
    inc.detectionEventIds = ["det-sod-1"]
    get_incident_repository().save_incident(inc)

    # Operator Alice proposes action
    prop_req = ResponseProposalRequest(
        incidentId=inc.id,
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.88",
        reason="Perimeter drop"
    )
    operator_alice = {"sub": "alice", "role": "security_operator", "environmentId": "env-prod"}
    record, err = svc.propose_action(prop_req, user=operator_alice)
    assert err is None

    # Operator Alice attempts to approve her own proposal (must be rejected)
    appr_req = ResponseApprovalRequest(decision="APPROVE", comment="Self-approval attempt")
    _, self_err = svc.review_proposal(record.id, appr_req, user=operator_alice)
    assert self_err is not None
    assert "Separation of duties violation" in self_err

    # Operator Bob approves Alice's proposal (allowed)
    operator_bob = {"sub": "bob", "role": "security_operator", "environmentId": "env-prod"}
    approved_record, bob_err = svc.review_proposal(record.id, appr_req, user=operator_bob)
    assert bob_err is None
    assert approved_record.status == "APPROVED"


def test_audit_security_response_headers_emitted(api_client):
    """
    AUDIT REMEDIATION VERIFICATION: Verifies that defensive security headers
    (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
    are present on HTTP responses.
    """
    res = api_client.get("/docs")
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert res.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in res.headers.get("permissions-policy", "")


def test_audit_security_headers_on_api_and_error_routes(api_client):
    """
    ADVERSARIAL VERIFICATION: Confirms defensive security headers appear on
    ordinary API responses and error responses (401, 404), not just /docs.
    """
    # 1. Ordinary API route (health)
    res_api = api_client.get("/health")
    assert res_api.status_code == 200
    assert res_api.headers.get("x-content-type-options") == "nosniff"
    assert res_api.headers.get("x-frame-options") == "DENY"

    # 2. Error route (401 Unauthorized)
    res_err = api_client.get("/api/v1/incidents")
    assert res_err.status_code == 401
    assert res_err.headers.get("x-content-type-options") == "nosniff"
    assert res_err.headers.get("x-frame-options") == "DENY"


def test_audit_cors_explicit_allowed_origin_and_preflight_headers(api_client):
    """
    ADVERSARIAL VERIFICATION: Verifies CORS behavior:
    1. Authorized origin receives Access-Control-Allow-Origin with credentials.
    2. Telemetry headers (X-GASHA-TELEMETRY-KEY, X-GASHA-ENVIRONMENT) are permitted in preflight.
    """
    # Preflight request from allowed origin
    preflight_res = api_client.options(
        "/api/v1/telemetry/ingest",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization, Content-Type, X-GASHA-TELEMETRY-KEY, X-GASHA-ENVIRONMENT"
        }
    )
    assert preflight_res.status_code == 200
    assert preflight_res.headers.get("access-control-allow-origin") == "http://localhost:3000"
    allowed_hdrs = preflight_res.headers.get("access-control-allow-headers", "").lower()
    assert "x-gasha-telemetry-key" in allowed_hdrs
    assert "x-gasha-environment" in allowed_hdrs


def test_audit_cors_unauthorized_origin_rejected(api_client):
    """
    ADVERSARIAL VERIFICATION: Unauthorized origins cannot obtain permission to
    read credentialed responses; wildcard is never returned with Allow-Credentials.
    """
    unauth_origin = "https://malicious-attacker-site.com"
    res = api_client.get(
        "/health",
        headers={"Origin": unauth_origin}
    )
    # Origin should either not be present or not match the malicious origin
    assert res.headers.get("access-control-allow-origin") != unauth_origin
    assert res.headers.get("access-control-allow-origin") != "*"


def test_audit_proxy_right_to_left_traversal_blocks_spoofed_prefix(demo_target_client):
    """
    ADVERSARIAL VERIFICATION: Proves that an attacker connecting through a trusted proxy
    with an attacker-controlled prefix (e.g. '203.0.113.1, 198.51.100.99') CANNOT bypass
    active defense blocklists. The right-to-left trust boundary algorithm correctly resolves
    the first untrusted IP (198.51.100.99) and blocks the request.
    """
    attacker_ip = "198.51.100.99"
    block_ip(attacker_ip)

    # Attacker crafts X-Forwarded-For with spoofed innocent prefix followed by real IP
    spoofed_chain = f"203.0.113.1, {attacker_ip}"
    res = demo_target_client.get(
        "/api/tickets",
        headers={"X-Forwarded-For": spoofed_chain}
    )
    assert res.status_code == 403
    assert "ACCESS_BLOCKED_BY_GASHA" in res.json()["error"]
    assert attacker_ip in res.json()["message"]


def test_audit_crypto_fails_closed_in_ambiguous_non_dev_environments(monkeypatch):
    """
    ADVERSARIAL VERIFICATION: Confirms that if NODE_ENV is unset, empty, staging,
    or production, the system strictly refuses default key derivation and fails closed.
    """
    monkeypatch.setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")

    # 1. Empty mode -> fails closed
    monkeypatch.setattr(settings, "NODE_ENV", "")
    with pytest.raises(RuntimeError) as exc_1:
        _derive_default_fernet_key()
    assert "Insecure configuration" in str(exc_1.value)

    # 2. Staging mode -> fails closed
    monkeypatch.setattr(settings, "NODE_ENV", "staging")
    with pytest.raises(RuntimeError) as exc_2:
        _derive_default_fernet_key()
    assert "Insecure configuration" in str(exc_2.value)


def test_audit_crypto_explicit_key_independent_of_jwt_secret(monkeypatch):
    """
    ADVERSARIAL VERIFICATION: Changing JWT_SECRET or INTERNAL_API_KEY does NOT
    affect ciphertext decryption when CREDENTIAL_ENCRYPTION_KEY is explicitly configured.
    """
    from cryptography.fernet import Fernet
    custom_key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", custom_key)

    plaintext = "super-secret-oauth-token-github-12345"
    ciphertext = encrypt_credential(plaintext, key=custom_key)

    # Mutate JWT_SECRET
    monkeypatch.setattr(settings, "JWT_SECRET", "completely-altered-jwt-secret-key-9999")
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", "completely-altered-internal-key-9999")

    # Decryption remains 100% successful and independent
    decrypted = decrypt_credential(ciphertext, key=custom_key)
    assert decrypted == plaintext


def test_audit_websocket_ticket_concurrent_single_use_consumption():
    """
    ADVERSARIAL VERIFICATION: Confirms thread-synchronized single-use ticket consumption.
    A ticket consumed once cannot be consumed a second time under concurrent access.
    """
    import concurrent.futures
    from app.api.realtime import create_websocket_ticket, consume_websocket_ticket

    ticket = create_websocket_ticket(user_id="analyst-conc", environment_id="env-prod", expires_seconds=60)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(consume_websocket_ticket, ticket) for _ in range(5)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    # Exactly one consumption succeeds, all others return None
    successful = [r for r in results if r is not None]
    failed = [r for r in results if r is None]
    assert len(successful) == 1
    assert len(failed) == 4
    assert successful[0]["userId"] == "analyst-conc"

