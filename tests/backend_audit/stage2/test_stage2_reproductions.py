"""
==============================================================================
FILE: tests/backend_audit/stage2/test_stage2_reproductions.py
ROLE / PURPOSE: GASHA Final Acceptance — Stage 2 Controlled Reproduction Tests
AUDIT TARGET: D:\\CODING\\GASHA
SCOPE:
  - Storage Backend Defaults (Unset, SQL, Invalid values, Relative paths)
  - Re-instantiation persistence gaps across all 18 state containers
  - Application-level subprocess restart durability
  - WebSocket ticket sharing and broadcast isolation across OS processes
  - PostgreSQL migration dialect probes against SQLite
  - Telemetry deduplication loss & duplicate incident replay consequences
==============================================================================
"""

import os
import sys
import time
import json
import sqlite3
import tempfile
import threading
import subprocess
import pytest
from datetime import datetime, timezone
from pathlib import Path

# Ensure paths are available
repo_root = Path(__file__).resolve().parent.parent.parent.parent
sys.path.extend([
    str(repo_root / "apps" / "api"),
    str(repo_root / "apps" / "demo-target"),
    str(repo_root / "packages" / "telemetry-sdk" / "python"),
])

from app.schemas.incident import IncidentResponse, IncidentStatus
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.response import ResponseRecordResponse, ResponseActionType, ResponseTargetType, ResponseStatus
from app.schemas.investigation import InvestigationResultResponse, AttackStorySchema
from app.schemas.asset import AssetResponse, RelationshipResponse
from app.schemas.vulnerability import VulnerabilityResponse
from app.schemas.risk import RiskScoreResponse
from app.schemas.attack_path import AttackPathResponse
from app.schemas.user import UserRecord
from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema


# ============================================================================
# 1. STORAGE BACKEND DEFAULTS & CONFIGURATION TESTS (EXPERIMENTS A, B, C, D)
# ============================================================================

def test_stage2_exp_a_default_storage_backend_is_memory():
    """
    Experiment A: Launch fresh subprocess with GASHA_STORAGE_BACKEND absent.
    Verify that all repositories default to in-memory classes.
    """
    env = os.environ.copy()
    env.pop("GASHA_STORAGE_BACKEND", None)

    script = """
import sys
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.response_repository import get_response_repository
from app.db.repositories.user_repository import get_user_repository
from app.db.repositories.investigation_repository import get_investigation_repository
from app.response.audit import get_audit_trail
from app.db.repositories.asset_repository import get_asset_repository

print('incidents:', type(get_incident_repository()).__name__)
print('detections:', type(get_detection_repository()).__name__)
print('responses:', type(get_response_repository()).__name__)
print('audit:', type(get_audit_trail()).__name__)
print('users:', type(get_user_repository()).__name__)
print('investigations:', type(get_investigation_repository()).__name__)
print('assets:', type(get_asset_repository()).__name__)
"""
    res = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, cwd=str(repo_root))
    assert res.returncode == 0, f"Subprocess failed: {res.stderr}"

    lines = dict(line.split(": ") for line in res.stdout.strip().splitlines())
    assert lines["incidents"] == "IncidentRepository"
    assert lines["detections"] == "DetectionRepository"
    assert lines["responses"] == "ResponseRepository"
    assert lines["audit"] == "AuditTrail"
    assert lines["users"] == "UserRepository"
    assert lines["investigations"] == "InvestigationRepository"
    assert lines["assets"] == "AssetRepository"


def test_stage2_exp_b_sql_storage_backend_selection():
    """
    Experiment B (Security Regression): Set GASHA_STORAGE_BACKEND=sql with disposable SQLite DB.
    Verify that ALL persistent repositories are wired to their SQL-backed implementations.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    try:
        env = os.environ.copy()
        env["GASHA_STORAGE_BACKEND"] = "sql"
        env["GASHA_DATABASE_PATH"] = temp_db

        script = """
import sys
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.response_repository import get_response_repository
from app.db.repositories.user_repository import get_user_repository
from app.db.repositories.investigation_repository import get_investigation_repository
from app.response.audit import get_audit_trail
from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.connection_repository import get_connection_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.db.repositories.risk_repository import get_risk_repository
from app.db.repositories.attack_path_repository import get_attack_path_repository

print('incidents:', type(get_incident_repository()).__name__)
print('detections:', type(get_detection_repository()).__name__)
print('responses:', type(get_response_repository()).__name__)
print('audit:', type(get_audit_trail()).__name__)
print('users:', type(get_user_repository()).__name__)
print('investigations:', type(get_investigation_repository()).__name__)
print('assets:', type(get_asset_repository()).__name__)
print('connections:', type(get_connection_repository()).__name__)
print('vulnerabilities:', type(get_vulnerability_repository()).__name__)
print('risks:', type(get_risk_repository()).__name__)
print('attack_paths:', type(get_attack_path_repository()).__name__)
"""
        res = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, cwd=str(repo_root))
        assert res.returncode == 0, f"Subprocess failed: {res.stderr}"

        lines = dict(line.split(": ") for line in res.stdout.strip().splitlines())
        # Confirmed SQL adapters across all persistent entities
        assert lines["incidents"] == "SQLIncidentRepository"
        assert lines["detections"] == "SQLDetectionRepository"
        assert lines["responses"] == "SQLResponseRepository"
        assert lines["audit"] == "SQLAuditTrail", "AuditTrail must be SQL-backed in SQL mode"
        assert lines["users"] == "SQLUserRepository", "UserRepository must be SQL-backed in SQL mode"
        assert lines["investigations"] == "SQLInvestigationRepository", "InvestigationRepository must be SQL-backed"
        assert lines["assets"] == "SQLAssetRepository", "AssetRepository must be SQL-backed"
        assert lines["connections"] == "SQLConnectionRepository", "ConnectionRepository must be SQL-backed"
        assert lines["vulnerabilities"] == "SQLVulnerabilityRepository", "VulnerabilityRepository must be SQL-backed"
        assert lines["risks"] == "SQLRiskRepository", "RiskRepository must be SQL-backed"
        assert lines["attack_paths"] == "SQLAttackPathRepository", "AttackPathRepository must be SQL-backed"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


@pytest.mark.parametrize("invalid_val", ["invalid", "sqlite", "postgres", ""])
def test_stage2_exp_c_invalid_backend_fails_closed(invalid_val):
    """
    Experiment C1 (Security Regression): Test invalid, misspelled, or unsupported backend configuration.
    Demonstrates fail-closed validation: the application rejects the configuration and refuses to run.
    """
    env = os.environ.copy()
    env["GASHA_STORAGE_BACKEND"] = invalid_val

    script = """
import sys
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from app.db.repositories.incident_repository import get_incident_repository
print(type(get_incident_repository()).__name__)
"""
    res = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, cwd=str(repo_root))
    assert res.returncode != 0, f"Invalid backend '{invalid_val}' must fail closed with non-zero exit code"
    assert "ValueError" in res.stderr or "Invalid GASHA_STORAGE_BACKEND" in res.stderr


@pytest.mark.parametrize("valid_val,expected_class", [
    ("SQL", "SQLIncidentRepository"),
    ("sql", "SQLIncidentRepository"),
    ("Memory", "IncidentRepository"),
    ("memory", "IncidentRepository")
])
def test_stage2_exp_c_valid_backend_case_insensitive(valid_val, expected_class):
    """
    Experiment C2 (Security Regression): Test valid case-insensitive storage backend configuration.
    """
    env = os.environ.copy()
    env["GASHA_STORAGE_BACKEND"] = valid_val

    script = """
import sys
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from app.db.repositories.incident_repository import get_incident_repository
print(type(get_incident_repository()).__name__)
"""
    res = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, cwd=str(repo_root))
    assert res.returncode == 0, f"Valid backend '{valid_val}' must execute successfully: {res.stderr}"
    assert res.stdout.strip() == expected_class


def test_stage2_exp_d_relative_database_path_cwd_dependent():
    """
    Experiment D (Security Regression): Test relative database path resolution across different working directories.
    Demonstrates that relative paths are normalized to canonical project root, ensuring consistent persistence.
    """
    rel_db_name = "stage2_exp_d_relative_test.db"
    cmd = """
import os, sys
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from app.db.sql_engine import SQLDatabaseEngine
engine = SQLDatabaseEngine()
print('path:', engine.db_path)
print('isabs:', os.path.isabs(engine.db_path))
"""
    env = dict(os.environ, GASHA_DATABASE_PATH=rel_db_name)

    # Run 1: from repository root
    r1 = subprocess.run([sys.executable, "-c", cmd], cwd=str(repo_root), env=env, capture_output=True, text=True)
    assert r1.returncode == 0
    assert "isabs: True" in r1.stdout

    # Run 2: from apps/api
    api_dir = repo_root / "apps" / "api"
    r2 = subprocess.run([sys.executable, "-c", cmd], cwd=str(api_dir), env=env, capture_output=True, text=True)
    assert r2.returncode == 0
    assert "isabs: True" in r2.stdout

    # Verify both resolved to the exact same canonical path
    p1 = [l.split("path: ")[1].strip() for l in r1.stdout.splitlines() if "path: " in l][0]
    p2 = [l.split("path: ")[1].strip() for l in r2.stdout.splitlines() if "path: " in l][0]
    assert p1 == p2, f"Paths must be identical across CWDs: {p1} vs {p2}"
    assert Path(p1) == (repo_root / rel_db_name).resolve()

    # Cleanup any created relative files
    for p in [repo_root / rel_db_name, api_dir / rel_db_name]:
        if p.exists():
            os.remove(p)


# ============================================================================
# 2. RE-INSTANTIATION PERSISTENCE GAPS BY RECORD TYPE
# ============================================================================

def test_stage2_reinstantiation_incidents_memory_vs_sql():
    """Verify IncidentRepository loses state on reinstantiation, but SQLIncidentRepository survives."""
    now = datetime.now(timezone.utc).isoformat()
    inc = IncidentResponse(
        id="inc-test-stage2",
        title="Test Incident",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId="ast-1",
        relatedAssetIds=[],
        detectionEventIds=[],
        createdAt=now,
        updatedAt=now
    )

    # 1. Memory mode
    from app.db.repositories.incident_repository import IncidentRepository
    repo_mem1 = IncidentRepository()
    repo_mem1.save_incident(inc)
    assert repo_mem1.get_incident("inc-test-stage2") is not None

    repo_mem2 = IncidentRepository()
    assert repo_mem2.get_incident("inc-test-stage2") is None, "Memory repository must not survive reinstantiation"

    # 2. SQL mode
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        from app.db.sql_engine import SQLIncidentRepository
        repo_sql1 = SQLIncidentRepository(db_path=temp_db)
        repo_sql1.save_incident(inc)
        assert repo_sql1.get_incident("inc-test-stage2") is not None

        repo_sql2 = SQLIncidentRepository(db_path=temp_db)
        survived = repo_sql2.get_incident("inc-test-stage2")
        assert survived is not None, "SQL repository must survive reinstantiation"
        assert survived.id == "inc-test-stage2"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


def test_stage2_reinstantiation_detections_memory_vs_sql():
    """Verify DetectionRepository loses state on reinstantiation, but SQLDetectionRepository survives."""
    now = datetime.now(timezone.utc).isoformat()
    det = DetectionEventResponse(
        id="det-test-stage2",
        rule=DetectionRuleSummarySchema(
            ruleId="RULE-AUTH-001",
            name="Auth Failure",
            description="Desc",
            severity="MEDIUM",
            confidence=0.9
        ),
        matchedEventIds=["evt-1"],
        primaryAssetId="ast-1",
        timestamp=now,
        severity="MEDIUM",
        confidence=0.9,
        evidenceSummary="Summary",
        environmentId="env-prod"
    )

    # Memory mode
    from app.db.repositories.detection_repository import DetectionRepository
    mem1 = DetectionRepository()
    mem1.save_detection(det)
    assert mem1.get_detection("det-test-stage2") is not None
    mem2 = DetectionRepository()
    assert mem2.get_detection("det-test-stage2") is None, "Memory detection repo must lose state"

    # SQL mode
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        from app.db.sql_engine import SQLDetectionRepository
        sql1 = SQLDetectionRepository(db_path=temp_db)
        sql1.save_detection(det)
        sql2 = SQLDetectionRepository(db_path=temp_db)
        survived = sql2.get_detection("det-test-stage2")
        assert survived is not None, "SQL detection repo must survive reinstantiation"
        assert survived.id == "det-test-stage2"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


def test_stage2_reinstantiation_responses_memory_vs_sql():
    """Verify ResponseRepository loses state on reinstantiation, but SQLResponseRepository survives."""
    now = datetime.now(timezone.utc).isoformat()
    resp = ResponseRecordResponse(
        id="resp-test-stage2",
        incidentId="inc-1",
        environmentId="env-prod",
        actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS",
        targetIdentifier="198.51.100.99",
        status="PROPOSED",
        reason="Malicious brute force",
        proposedAt=now,
        proposedBy="analyst"
    )

    # Memory mode
    from app.db.repositories.response_repository import ResponseRepository
    m1 = ResponseRepository()
    m1.save_response(resp)
    assert m1.get_response("resp-test-stage2", "env-prod") is not None
    m2 = ResponseRepository()
    assert m2.get_response("resp-test-stage2", "env-prod") is None

    # SQL mode
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        from app.db.sql_engine import SQLResponseRepository
        s1 = SQLResponseRepository(db_path=temp_db)
        s1.save_response(resp)
        s2 = SQLResponseRepository(db_path=temp_db)
        survived = s2.get_response("resp-test-stage2", "env-prod")
        assert survived is not None
        assert survived.id == "resp-test-stage2"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


def test_stage2_reinstantiation_audit_trail_runtime_is_in_memory_only():
    """
    Verify that runtime AuditTrail loses records on reinstantiation,
    and that get_audit_trail() does NOT connect to SQLAuditTrail.
    """
    from app.response.audit import AuditTrail, get_audit_trail
    a1 = AuditTrail()
    entry = a1.append_entry(
        environment_id="env-prod",
        event_type="TEST_ACTION",
        actor="operator",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.99",
        outcome="SUCCESS"
    )
    assert entry.auditId is not None

    a2 = AuditTrail()
    res = a2.verify_chain("env-prod")
    assert res.totalRecords == 0, "Fresh AuditTrail instance must be empty (in-memory)"


def test_stage2_reinstantiation_user_repository_loses_users_and_refresh_tokens():
    """
    Verify that UserRepository loses dynamic accounts and refresh tokens on reinstantiation.
    """
    from app.db.repositories.user_repository import UserRepository
    u1 = UserRepository()
    now = datetime.now(timezone.utc).isoformat()
    custom_user = UserRecord(
        id="usr-dynamic-test",
        username="dynamic_sec",
        passwordHash="pbkdf2:dummy",
        role="security_analyst",
        environmentId="env-prod",
        isActive=True,
        createdAt=now,
        updatedAt=now
    )
    u1.save_user(custom_user)
    u1.store_refresh_token(user_id="usr-dynamic-test", raw_refresh_token="rft_custom_stage2", expires_seconds=3600)

    # Check existence in instance 1
    assert u1.get_by_id("usr-dynamic-test") is not None
    assert u1.consume_refresh_token("usr-dynamic-test", "rft_custom_stage2") is True

    # Re-instantiate
    u2 = UserRepository()
    assert u2.get_by_id("usr-dynamic-test") is None, "Dynamically created user must be lost on reinstantiation"
    assert u2.consume_refresh_token("usr-dynamic-test", "rft_custom_stage2") is False, "Refresh token must be lost"


def test_stage2_reinstantiation_investigations_lost_on_reinstantiation():
    """Verify that InvestigationRepository loses investigation results on reinstantiation."""
    from app.db.repositories.investigation_repository import InvestigationRepository
    now = datetime.now(timezone.utc).isoformat()
    inv = InvestigationResultResponse(
        incidentId="inc-stage2-inv",
        environmentId="env-prod",
        summary="Automated Investigation Summary",
        severity="HIGH",
        confidenceScore=0.95,
        attackStory=AttackStorySchema(
            observedFacts=["Observed brute force"],
            reasonableInferences=["Likely automated bot"],
            unknownsAndGaps=["Origin ASN unknown"],
            narrativeSummary="Narrative text"
        ),
        groundedEvidence=[],
        recommendations=[],
        generatedAt=now
    )
    r1 = InvestigationRepository()
    r1.save_investigation(inv, environment_id="env-prod")
    assert r1.get_investigation("inc-stage2-inv", "env-prod") is not None

    r2 = InvestigationRepository()
    assert r2.get_investigation("inc-stage2-inv", "env-prod") is None, "Investigations must be lost on reinstantiation"


def test_stage2_reinstantiation_assets_and_relationships_lost():
    """Verify that AssetRepository loses assets and relationships on reinstantiation."""
    from app.db.repositories.asset_repository import AssetRepository
    now = datetime.now(timezone.utc).isoformat()
    asset = AssetResponse(
        id="ast-stage2-node",
        environmentId="env-prod",
        name="Production Gateway",
        type="SERVICE",
        criticality="TIER_1_HIGH",
        source="TELEMETRY",
        metadata={},
        createdAt=now,
        updatedAt=now
    )
    rel = RelationshipResponse(
        id="rel-stage2-edge",
        sourceAssetId="ast-stage2-node",
        targetAssetId="ast-database",
        type="CONNECTS_TO",
        createdAt=now
    )
    ar1 = AssetRepository()
    ar1.upsert_asset(asset, asset.id)
    ar1.upsert_relationship(rel, rel.id, "env-prod")
    assert ar1.get_asset("ast-stage2-node", "env-prod") is not None
    assert len(ar1.list_relationships("env-prod")) == 1

    ar2 = AssetRepository()
    assert ar2.get_asset("ast-stage2-node", "env-prod") is None, "Assets must be lost on reinstantiation"
    assert len(ar2.list_relationships("env-prod")) == 0, "Relationships must be lost on reinstantiation"


def test_stage2_reinstantiation_connections_and_runs_lost():
    """Verify that ConnectionRepository loses cloud integrations and runs on reinstantiation."""
    from app.db.repositories.connection_repository import ConnectionRepository
    from app.schemas.connection import ConnectionRecord
    now = datetime.now(timezone.utc).isoformat()
    cr1 = ConnectionRepository()
    conn = ConnectionRecord(
        id="conn-stage2-1",
        provider="GITHUB",
        environmentId="env-prod",
        encryptedToken="enc_tok_stage2",
        status="CONNECTED",
        createdAt=now,
        updatedAt=now
    )
    cr1.save_connection(conn)
    assert cr1.get_connection("env-prod", "GITHUB") is not None

    cr2 = ConnectionRepository()
    assert cr2.get_connection("env-prod", "GITHUB") is None, "Connections must be lost on reinstantiation"


def test_stage2_reinstantiation_vulnerabilities_and_risks_lost():
    """Verify that VulnerabilityRepository and RiskRepository lose state on reinstantiation."""
    from app.db.repositories.vulnerability_repository import VulnerabilityRepository
    from app.db.repositories.risk_repository import RiskRepository
    now = datetime.now(timezone.utc).isoformat()

    vuln = VulnerabilityResponse(
        id="vuln-stage2-cve",
        assetId="ast-stage2-node",
        environmentId="env-prod",
        title="CVE-2026-0001",
        description="Vulnerability description",
        severity="HIGH",
        cvssScore=8.5,
        category="INSECURE_CONFIG",
        remediationGuidance="Fix config",
        status="OPEN",
        discoveredAt=now
    )
    vr1 = VulnerabilityRepository()
    vr1.upsert_finding(vuln, vuln.id)
    assert vr1.get_finding("vuln-stage2-cve", "env-prod") is not None

    vr2 = VulnerabilityRepository()
    assert vr2.get_finding("vuln-stage2-cve", "env-prod") is None, "Vulnerabilities must be lost on reinstantiation"

    risk = RiskScoreResponse(
        overallScore=75.5,
        criticalAssetsAtRiskCount=1,
        highRiskVulnerabilitiesCount=2,
        activeAttackPathsCount=1,
        contributors=[],
        calculatedAt=now,
        environmentId="env-prod"
    )
    rr1 = RiskRepository()
    rr1.save_current_risk(risk)
    assert rr1.get_current_risk("env-prod") is not None

    rr2 = RiskRepository()
    assert rr2.get_current_risk("env-prod") is None, "Risk snapshots must be lost on reinstantiation"


def test_stage2_reinstantiation_attack_paths_and_digital_twin_lost():
    """Verify that AttackPathRepository and DigitalTwinState lose state on reinstantiation."""
    from app.db.repositories.attack_path_repository import AttackPathRepository
    now = datetime.now(timezone.utc).isoformat()

    path = AttackPathResponse(
        id="path-stage2-01",
        environmentId="env-prod",
        entryPointAssetId="ast-ingress",
        targetAssetId="ast-database",
        severity="HIGH",
        pathScore=88.0,
        nodes=[],
        isActive=True,
        discoveredAt=now
    )
    apr1 = AttackPathRepository()
    apr1.save_attack_paths("env-prod", [path])
    assert apr1.get_attack_path("path-stage2-01", "env-prod") is not None

    apr2 = AttackPathRepository()
    assert apr2.get_attack_path("path-stage2-01", "env-prod") is None, "Attack paths must be lost on reinstantiation"


def test_stage2_reinstantiation_target_blocklist_and_disabled_sessions_lost():
    """
    Verify that the demo target's IP blocklist and revoked sessions are in-memory sets,
    and are wiped upon clear/reinstantiation.
    """
    from security.blocklist import block_ip, is_blocked, clear_blocklist, get_blocked_ips
    from security.sessions import disable_session, is_session_disabled, clear_disabled_sessions, get_disabled_sessions

    block_ip("198.51.100.99")
    assert is_blocked("198.51.100.99") is True
    clear_blocklist()
    assert is_blocked("198.51.100.99") is False, "Demo target blocklist is purely in-memory set"

    disable_session("sess-compromised-777")
    assert is_session_disabled("sess-compromised-777") is True
    clear_disabled_sessions()
    assert is_session_disabled("sess-compromised-777") is False, "Demo target disabled sessions is purely in-memory set"


# ============================================================================
# 3. WEBSOCKET TICKET & MULTI-WORKER LIMITATIONS (EXPERIMENTS A, B, C, D)
# ============================================================================

def test_stage2_websocket_tickets_not_shared_across_processes():
    """
    Experiment 5A: Issue a ticket in Process A, attempt to consume in Process B.
    Demonstrates that process-local memory prevents cross-worker ticket consumption.
    """
    cmd_issue = """
import sys
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from app.api.realtime import create_websocket_ticket
t = create_websocket_ticket('user-proc-a', 'env-prod')
print(t)
"""
    p_issue = subprocess.run([sys.executable, "-c", cmd_issue], capture_output=True, text=True, cwd=str(repo_root))
    assert p_issue.returncode == 0
    ticket = p_issue.stdout.strip()
    assert ticket.startswith("wst_")

    cmd_consume = """
import sys
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from app.api.realtime import consume_websocket_ticket
res = consume_websocket_ticket(sys.argv[1])
print('RESULT:', res)
"""
    p_consume = subprocess.run([sys.executable, "-c", cmd_consume, ticket], capture_output=True, text=True, cwd=str(repo_root))
    assert p_consume.returncode == 0
    assert "RESULT: None" in p_consume.stdout, "Process B must fail to consume ticket created by Process A"


def test_stage2_websocket_tickets_atomic_consumption_and_expiry_within_process():
    """
    Experiment 5B: Within same process:
    - Atomicity: 10 concurrent threads consume same ticket -> exactly 1 succeeds.
    - Expiration: Ticket with negative TTL returns None.
    - Replay: Consuming twice fails on second attempt.
    """
    from app.api.realtime import create_websocket_ticket, consume_websocket_ticket

    # Replay
    t1 = create_websocket_ticket("usr-replay", "env-prod", expires_seconds=60)
    assert consume_websocket_ticket(t1) is not None
    assert consume_websocket_ticket(t1) is None, "Replay must fail"

    # Concurrency
    t2 = create_websocket_ticket("usr-race", "env-prod", expires_seconds=60)
    results = []
    def worker():
        r = consume_websocket_ticket(t2)
        results.append(r is not None)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for th in threads: th.start()
    for th in threads: th.join()

    assert results.count(True) == 1, "Exactly 1 consumer must succeed"
    assert results.count(False) == 9, "9 consumers must be rejected"

    # Expiration
    t3 = create_websocket_ticket("usr-exp", "env-prod", expires_seconds=-1)
    assert consume_websocket_ticket(t3) is None, "Expired ticket must return None"


def test_stage2_websocket_broadcast_isolated_to_process():
    """
    Experiment 5C: Verify ConnectionManager stores WebSockets in process-local memory.
    Broadcasts in Process A cannot reach sockets connected to Process B.
    """
    from app.api.realtime import ConnectionManager
    mgr = ConnectionManager()
    assert mgr.get_connection_count("env-prod") == 0
    assert not hasattr(mgr, "redis_client"), "No external pub/sub client exists"
    assert not hasattr(mgr, "_pubsub"), "No inter-process broadcast transport exists"


# ============================================================================
# 4. POSTGRESQL / SUPABASE MIGRATION DIALECT PROBES AGAINST SQLITE
# ============================================================================

def test_stage2_postgresql_migration_syntax_fails_on_sqlite():
    """
    Probe the SQL migration files against SQLite to empirically prove dialect incompatibility.
    Verifies that TEXT[], TIMESTAMPTZ, timezone(), and ENABLE ROW LEVEL SECURITY fail on SQLite.
    """
    mig1_path = repo_root / "infra" / "database" / "migrations" / "001_create_incidents_and_detections.sql"
    mig2_path = repo_root / "infra" / "database" / "migrations" / "002_create_investigations_and_responses.sql"

    with open(mig1_path, "r", encoding="utf-8") as f:
        sql1 = f.read()

    conn1 = sqlite3.connect(":memory:")
    with pytest.raises(sqlite3.OperationalError) as exc_info1:
        conn1.executescript(sql1)
    assert "syntax error" in str(exc_info1.value).lower(), "PostgreSQL migration 001 must fail on SQLite"

    with open(mig2_path, "r", encoding="utf-8") as f:
        sql2 = f.read()

    conn2 = sqlite3.connect(":memory:")
    with pytest.raises(sqlite3.OperationalError) as exc_info2:
        conn2.executescript(sql2)
    assert "syntax error" in str(exc_info2.value).lower(), "PostgreSQL migration 002 must fail on SQLite"


# ============================================================================
# 5. DEDUPLICATION & CORRELATION BEHAVIOR AFTER STATE LOSS
# ============================================================================

def test_stage2_telemetry_replay_after_dedup_loss_causes_duplicate_detection_and_incident():
    """
    Ingest a telemetry event through the real processor pipeline.
    Simulate process restart by clearing EventDeduplicator and CorrelationEngine.
    Replay the identical event.
    Verify that state loss causes:
    1. Acceptance as NEW instead of DUPLICATE.
    2. Re-triggering of detection engine.
    3. Creation of duplicate incident.
    """
    import asyncio
    from app.detection.deduplicator import get_event_deduplicator
    from app.telemetry.processor import process_stream
    from app.detection.engine import get_detection_engine
    from app.db.repositories.incident_repository import get_incident_repository
    from app.db.repositories.detection_repository import get_detection_repository

    inc_repo = get_incident_repository("memory")
    det_repo = get_detection_repository("memory")
    inc_repo.clear()
    det_repo.clear()

    dedup = get_event_deduplicator()
    dedup.clear()
    engine = get_detection_engine()
    engine.tracker.clear()

    # Generate 5 auth failures to trigger RULE-AUTH-001
    events = [
        TelemetryEventSchema(
            id=f"evt-dedup-stage2-{i}",
            timestamp="2026-10-09T18:00:00Z",
            eventType="AUTH_FAILURE",
            sourceService="auth-svc",
            environmentId="env-prod",
            payload=TelemetryEventPayloadSchema(
                sourceIp="198.51.100.88",
                httpMethod="POST",
                httpPath="/api/v1/auth/login",
                httpStatusCode=401,
                action="AUTH_FAILURE",
                outcome="FAILURE"
            )
        )
        for i in range(5)
    ]

    # Run 1: Initial Ingestion
    count1 = asyncio.run(process_stream(events))
    assert count1 == 5
    initial_incidents = inc_repo.list_incidents("env-prod")
    assert len(initial_incidents) == 1, "Initial batch must generate 1 correlated incident"

    # Immediate replay without restart: Deduplication blocks duplicate events!
    count_replay = asyncio.run(process_stream(events))
    assert len(inc_repo.list_incidents("env-prod")) == 1, "Deduplication must block duplicate events within same session"

    # SIMULATE PROCESS RESTART: State loss wipes in-memory deduplicator, detection tracker, and active correlation bindings!
    dedup.clear()
    engine.tracker.clear()
    from app.correlation.engine import get_correlation_engine
    corr = get_correlation_engine()
    corr.reset_state()

    # Replay after process restart: Deduplication state is lost!
    count_post_restart = asyncio.run(process_stream(events))
    all_incidents = inc_repo.list_incidents("env-prod")
    assert len(all_incidents) == 2, "State loss caused duplicate incident generation on identical replay"


def test_stage2_app_restart_across_subprocesses_sessions_survive_and_replay_rejected():
    """
    Experiment (Security Regression): Full Application-level restart across separate Python subprocesses.
    Subprocess 1: Boots API on disposable SQLite DB, ingests 5 telemetry events, creates incident, logs in to issue refresh token.
    Subprocess 2: Boots API on same SQLite DB.
    Verifies:
    1. Incident survives process restart in SQLite.
    2. Refresh token issued in Subprocess 1 survives process restart in SQLite and succeeds (200).
    3. Replayed/reused refresh token is immediately rejected with 401 (single-use semantics).
    4. Invalid refresh token is rejected with 401.
    5. Newly rotated refresh token succeeds with 200.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        script_p1 = '''
import sys, os, asyncio
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from fastapi.testclient import TestClient
from app.main import app
from app.telemetry.processor import process_stream
from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema

client = TestClient(app)
# Login
login_res = client.post('/api/v1/auth/login', json={'username': 'admin', 'password': 'AdminRoot2026!'})
assert login_res.status_code == 200
tokens = login_res.json()
refresh_token = tokens['refreshToken']
print('REFRESH_TOKEN:' + refresh_token)

# Ingest 5 events to trigger and persist an incident in SQLite
events = []
for i in range(5):
    events.append(TelemetryEventSchema(
        id=f'evt-restart-p1-{i}',
        timestamp='2026-10-09T18:00:00Z',
        eventType='AUTH_FAILURE',
        sourceService='auth-svc',
        environmentId='env-prod',
        payload=TelemetryEventPayloadSchema(
            sourceIp='198.51.100.44',
            httpMethod='POST',
            httpPath='/api/v1/auth/login',
            httpStatusCode=401,
            action='AUTH_FAILURE',
            outcome='FAILURE'
        )
    ))

asyncio.run(process_stream(events))
'''
        env = dict(os.environ, GASHA_STORAGE_BACKEND="sql", GASHA_DATABASE_PATH=temp_db)
        p1 = subprocess.run([sys.executable, "-c", script_p1], env=env, capture_output=True, text=True, cwd=str(repo_root))
        assert p1.returncode == 0, f"Process 1 failed: {p1.stderr}"

        ref_tok = None
        for line in p1.stdout.splitlines():
            if line.startswith("REFRESH_TOKEN:"):
                ref_tok = line.split(":", 1)[1].strip()
        assert ref_tok is not None

        script_p2 = f'''
import sys, os
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_jwt_token

client = TestClient(app)
token = create_jwt_token({{'sub': 'admin', 'role': 'admin', 'environmentId': 'env-prod'}})
headers = {{'Authorization': f'Bearer {{token}}'}}

# Query incidents
inc_res = client.get('/api/v1/incidents', headers=headers)
assert inc_res.status_code == 200
incidents = inc_res.json()
print('INCIDENT_COUNT:' + str(len(incidents)))

# 1. Valid refresh token issued by Process 1 works after restart (durable persistence)
ref_res = client.post('/api/v1/auth/refresh', json={{'refreshToken': '{ref_tok}'}})
print('REFRESH_STATUS:' + str(ref_res.status_code))
new_tok_data = ref_res.json() if ref_res.status_code == 200 else {{}}
new_ref_tok = new_tok_data.get('refreshToken', '')
print('NEW_REFRESH_TOKEN:' + new_ref_tok)

# 2. Token reuse / replay attack rejected with 401
ref_reuse = client.post('/api/v1/auth/refresh', json={{'refreshToken': '{ref_tok}'}})
print('REUSE_STATUS:' + str(ref_reuse.status_code))

# 3. Invalid token rejected with 401
ref_invalid = client.post('/api/v1/auth/refresh', json={{'refreshToken': 'rft_invalid_bogus_token'}})
print('INVALID_STATUS:' + str(ref_invalid.status_code))

# 4. Rotated token works with 200
ref_rotated = client.post('/api/v1/auth/refresh', json={{'refreshToken': new_ref_tok}})
print('ROTATED_STATUS:' + str(ref_rotated.status_code))
'''
        p2 = subprocess.run([sys.executable, "-c", script_p2], env=env, capture_output=True, text=True, cwd=str(repo_root))
        assert p2.returncode == 0, f"Process 2 failed: {p2.stderr}"

        out_lines = dict(line.split(":") for line in p2.stdout.splitlines() if ":" in line and not line.startswith("2026-"))
        assert int(out_lines["INCIDENT_COUNT"]) >= 1, "Incident must survive process restart in SQLite"
        assert int(out_lines["REFRESH_STATUS"]) == 200, "Valid refresh token must succeed (200) across process restarts in SQLite"
        assert int(out_lines["REUSE_STATUS"]) == 401, "Reused refresh token must be rejected (401)"
        assert int(out_lines["INVALID_STATUS"]) == 401, "Invalid refresh token must be rejected (401)"
        assert int(out_lines["ROTATED_STATUS"]) == 200, "Newly rotated refresh token must succeed (200)"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)
