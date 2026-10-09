"""
==============================================================================
FILE: tests/backend_audit/stage3/test_stage3_persistence.py
ROLE / OWNERSHIP: Lead Security & Quality Assurance Engineers
OBJECTIVE: Independent, deterministic persistence regression tests for Stage 3.
           Validates that all operational entities (investigations, assets,
           relationships, cloud connections, discovery runs, vulnerabilities,
           risk snapshots, attack paths, users, refresh tokens, audit trail,
           and deduplication cache) survive restart when backed by SQL,
           enforce tenant isolation, support digital twin graph reconstruction,
           and fail-closed under invalid configuration.
==============================================================================
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
import pytest

repo_root = Path(__file__).resolve().parents[3]
sys.path.extend([
    str(repo_root / "apps" / "api"),
    str(repo_root / "apps" / "demo-target"),
    str(repo_root / "packages" / "telemetry-sdk" / "python"),
])

from app.db.storage_mode import resolve_storage_backend, StorageMode
from app.db.sql_engine import (
    SQLDatabaseEngine,
    normalize_db_path,
    SQLInvestigationRepository,
    SQLAssetRepository,
    SQLConnectionRepository,
    SQLVulnerabilityRepository,
    SQLRiskRepository,
    SQLAttackPathRepository,
    SQLUserRepository,
    SQLAuditTrail,
    SQLIncidentRepository,
    SQLDetectionRepository,
    SQLResponseRepository,
)
from app.schemas.investigation import (
    InvestigationResultResponse,
    InvestigationTimelineResponse,
    AttackStorySchema,
    EvidenceSchema,
    RecommendationSchema,
    TimelineEventResponse,
)
from app.schemas.asset import AssetBase, RelationshipBase
from app.schemas.connection import ConnectionRecord, DiscoveryRunStatus
from app.schemas.vulnerability import VulnerabilityBase, VulnerabilityStatus
from app.schemas.risk import RiskScoreResponse, RiskContributorSchema, RiskHistoryEntryResponse
from app.schemas.attack_path import AttackPathResponse, AttackPathNodeSchema
from app.schemas.user import UserRecord
from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema
from app.digital_twin.builder import DigitalTwinBuilder
from app.attack_paths.service import AttackPathService
from app.risk.service import RiskService
from app.detection.deduplicator import EventDeduplicator, DeduplicationResult
import security.blocklist as target_blocklist
import security.sessions as target_sessions


@pytest.fixture
def temp_db_path():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


# ============================================================================
# 1. STORAGE MODE SAFETY & PATH NORMALIZATION TESTS
# ============================================================================

def test_storage_mode_default_and_explicit_resolution():
    # Unset in non-production defaults to memory
    old_mode = os.environ.pop("GASHA_STORAGE_BACKEND", None)
    old_env = os.environ.get("NODE_ENV", "development")
    os.environ["NODE_ENV"] = "development"
    try:
        assert resolve_storage_backend() == StorageMode.MEMORY

        # Explicit modes
        assert resolve_storage_backend("sql") == StorageMode.SQL
        assert resolve_storage_backend("SQL ") == StorageMode.SQL
        assert resolve_storage_backend("memory") == StorageMode.MEMORY

        # Invalid mode fails closed
        with pytest.raises(ValueError, match="Invalid GASHA_STORAGE_BACKEND"):
            resolve_storage_backend("invalid")

        with pytest.raises(ValueError, match="Invalid GASHA_STORAGE_BACKEND"):
            resolve_storage_backend("sqlite")

        # Production mode enforces SQL
        os.environ["NODE_ENV"] = "production"
        assert resolve_storage_backend() == StorageMode.SQL
        with pytest.raises(RuntimeError, match="Production environment requires durable 'sql'"):
            resolve_storage_backend("memory")
    finally:
        os.environ["NODE_ENV"] = old_env
        if old_mode is not None:
            os.environ["GASHA_STORAGE_BACKEND"] = old_mode
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)


def test_db_path_normalization_across_working_dirs():
    # Relative path normalization
    norm = normalize_db_path("data/test_db.db")
    assert os.path.isabs(norm)
    assert norm.endswith(os.path.normpath("data/test_db.db"))

    # In-memory remains untouched
    assert normalize_db_path(":memory:") == ":memory:"

    # sqlite:/// prefix stripped and resolved to absolute path
    norm_url = normalize_db_path("sqlite:///custom.db")
    assert os.path.isabs(norm_url)
    assert norm_url.endswith("custom.db")


# ============================================================================
# 2. INVESTIGATION REPOSITORY DURABILITY
# ============================================================================

def test_investigation_and_timeline_survives_restart(temp_db_path):
    engine1 = SQLDatabaseEngine(temp_db_path)
    repo1 = SQLInvestigationRepository(engine=engine1)

    result = InvestigationResultResponse(
        incidentId="inc-stage3-inv-001",
        summary="Deterministic root cause: credential leakage and unauthorized access.",
        severity="HIGH",
        confidenceScore=0.95,
        attackStory=AttackStorySchema(
            observedFacts=["Failed auth from IP 198.51.100.42", "Successful admin login shortly after"],
            reasonableInferences=["Attacker guessed or acquired valid credentials"],
            unknownsAndGaps=["Exact initial leak vector unconfirmed"],
            narrativeSummary="Attacker achieved unauthorized privilege elevation."
        ),
        groundedEvidence=[
            EvidenceSchema(
                id="ev-001",
                type="TELEMETRY_EVENT",
                source="auth-service",
                timestamp="2026-10-09T20:00:00Z",
                content={"status": 401, "ip": "198.51.100.42"},
                relevanceExplanation="Observed initial brute-force attempts",
                verified=True
            )
        ],
        recommendations=[
            RecommendationSchema(
                id="rec-001",
                actionType="BLOCK_SOURCE",
                targetIdentifier="198.51.100.42",
                targetType="IP_ADDRESS",
                rationale="Halt active attack origin",
                confidence=0.98,
                expectedImpact="Rejects traffic from malicious source"
            )
        ],
        generatedAt="2026-10-09T20:05:00Z"
    )

    repo1.save_investigation(result, environment_id="env-prod")

    timeline = InvestigationTimelineResponse(
        incidentId="inc-stage3-inv-001",
        environmentId="env-prod",
        events=[
            TimelineEventResponse(
                timestamp="2026-10-09T20:00:00Z",
                eventId="evt-001",
                eventType="AUTH_FAILURE",
                source="auth-svc",
                outcome="FAILURE",
                summary="Bad password",
                details={"ip": "198.51.100.42"}
            )
        ],
        totalEvents=1,
        hasContradictions=False,
        notes=["Evidence chronological linkage complete"]
    )
    repo1.save_timeline(timeline)

    # Reinstantiate repository on a fresh engine connection
    del repo1
    del engine1

    engine2 = SQLDatabaseEngine(temp_db_path)
    repo2 = SQLInvestigationRepository(engine=engine2)

    # Verify retrieval
    loaded_inv = repo2.get_investigation("inc-stage3-inv-001", environment_id="env-prod")
    assert loaded_inv is not None
    assert loaded_inv.incidentId == "inc-stage3-inv-001"
    assert loaded_inv.confidenceScore == 0.95
    assert len(loaded_inv.groundedEvidence) == 1
    assert loaded_inv.groundedEvidence[0].id == "ev-001"
    assert len(loaded_inv.recommendations) == 1
    assert loaded_inv.recommendations[0].targetIdentifier == "198.51.100.42"

    # Verify timeline retrieval
    loaded_tl = repo2.get_timeline("inc-stage3-inv-001", environment_id="env-prod")
    assert loaded_tl is not None
    assert loaded_tl.totalEvents == 1
    assert loaded_tl.events[0].eventId == "evt-001"

    # Tenant isolation check
    assert repo2.get_investigation("inc-stage3-inv-001", environment_id="env-tenant-b") is None
    assert repo2.get_timeline("inc-stage3-inv-001", environment_id="env-tenant-b") is None


# ============================================================================
# 3. ASSETS & RELATIONSHIPS DURABILITY & DIGITAL TWIN RECONSTRUCTION
# ============================================================================

def test_assets_relationships_survive_and_reconstruct_digital_twin(temp_db_path):
    engine1 = SQLDatabaseEngine(temp_db_path)
    asset_repo1 = SQLAssetRepository(engine=engine1)
    vuln_repo1 = SQLVulnerabilityRepository(engine=engine1)

    # Upsert nodes
    a1 = asset_repo1.upsert_asset(AssetBase(
        name="web-frontend",
        type="SERVICE",
        criticality="TIER_1_HIGH",
        environmentId="env-prod",
        source="GITHUB",
        metadata={"repo": "org/frontend"},
        isPubliclyExposed=True,
        status="ACTIVE"
    ), asset_id="asset-web-01")

    a2 = asset_repo1.upsert_asset(AssetBase(
        name="auth-service",
        type="SERVICE",
        criticality="TIER_0_CROWN_JEWEL",
        environmentId="env-prod",
        source="GITHUB",
        metadata={"repo": "org/auth"},
        isPubliclyExposed=False,
        status="ACTIVE"
    ), asset_id="asset-auth-02")

    # Upsert edge
    rel = asset_repo1.upsert_relationship(RelationshipBase(
        sourceAssetId=a1.id,
        targetAssetId=a2.id,
        type="DEPENDS_ON",
        metadata={"protocol": "HTTPS"}
    ), environment_id="env-prod")

    # Upsert open vulnerability
    v1 = vuln_repo1.upsert_finding(VulnerabilityBase(
        assetId=a1.id,
        environmentId="env-prod",
        ruleId="sec-rule-exposure",
        cveId="CVE-2026-0001",
        title="Unauthenticated Public Exposure",
        description="Endpoint is accessible without auth",
        severity="HIGH",
        cvssScore=7.5,
        category="PUBLIC_EXPOSURE",
        remediationGuidance="Add token check",
        status="OPEN",
        evidence={"port": 443}
    ))

    # Destroy instances simulating service shutdown
    del asset_repo1, vuln_repo1, engine1

    # Reinstantiate
    engine2 = SQLDatabaseEngine(temp_db_path)
    asset_repo2 = SQLAssetRepository(engine=engine2)
    vuln_repo2 = SQLVulnerabilityRepository(engine=engine2)

    # Verify durability
    assert asset_repo2.count_assets("env-prod") == 2
    assert asset_repo2.count_relationships("env-prod") == 1
    assert asset_repo2.get_asset("asset-web-01", "env-prod").name == "web-frontend"
    assert len(vuln_repo2.list_findings("env-prod")) == 1

    # Reconstruct Digital Twin from persistent data
    builder = DigitalTwinBuilder()
    builder.asset_repo = asset_repo2
    builder.vuln_repo = vuln_repo2

    graph = builder.build_graph_for_environment("env-prod")
    assert len(graph.list_nodes()) == 2
    assert graph.get_node("asset-web-01") is not None
    assert graph.get_node("asset-auth-02") is not None

    # Check node findings attached
    web_node = graph.get_node("asset-web-01")
    assert len(web_node["findings"]) == 1
    assert web_node["findings"][0].id == v1.id


# ============================================================================
# 4. CLOUD CONNECTIONS & DISCOVERY RUNS DURABILITY
# ============================================================================

def test_cloud_connections_and_discovery_runs_survive(temp_db_path):
    engine1 = SQLDatabaseEngine(temp_db_path)
    repo1 = SQLConnectionRepository(engine=engine1)

    conn = ConnectionRecord(
        id="conn-gh-001",
        provider="GITHUB",
        environmentId="env-prod",
        accountName="gasha-security-org",
        scope="repo,read:org",
        encryptedToken="gAAAAABm_encrypted_fernet_token_secret",
        status="CONNECTED",
        resourceCount=12,
        lastSyncAt="2026-10-09T20:10:00Z",
        createdAt="2026-10-09T20:00:00Z",
        updatedAt="2026-10-09T20:10:00Z"
    )
    repo1.save_connection(conn)

    run = DiscoveryRunStatus(
        id="run-gh-001",
        environmentId="env-prod",
        provider="GITHUB",
        status="COMPLETED",
        startedAt="2026-10-09T20:08:00Z",
        completedAt="2026-10-09T20:10:00Z",
        assetsDiscovered=12,
        relationshipsDiscovered=8,
        errors=[]
    )
    repo1.record_run(run)

    del repo1, engine1

    engine2 = SQLDatabaseEngine(temp_db_path)
    repo2 = SQLConnectionRepository(engine=engine2)

    loaded_conn = repo2.get_connection("env-prod", "GITHUB")
    assert loaded_conn is not None
    assert loaded_conn.accountName == "gasha-security-org"
    assert loaded_conn.encryptedToken == "gAAAAABm_encrypted_fernet_token_secret"
    assert loaded_conn.resourceCount == 12

    recent_runs = repo2.get_recent_runs("env-prod")
    assert len(recent_runs) == 1
    assert recent_runs[0].assetsDiscovered == 12

    # Tenant isolation
    assert repo2.get_connection("env-tenant-b", "GITHUB") is None


# ============================================================================
# 5. RISK SNAPSHOTS & ATTACK PATHS DURABILITY
# ============================================================================

def test_risk_snapshots_and_attack_paths_survive(temp_db_path):
    engine1 = SQLDatabaseEngine(temp_db_path)
    risk_repo1 = SQLRiskRepository(engine=engine1)
    path_repo1 = SQLAttackPathRepository(engine=engine1)

    risk = RiskScoreResponse(
        overallScore=68.5,
        criticalAssetsAtRiskCount=1,
        highRiskVulnerabilitiesCount=2,
        activeAttackPathsCount=1,
        contributors=[
            RiskContributorSchema(factor="Public Exposure", weight=30.0, description="Direct internet route"),
            RiskContributorSchema(factor="Tier-0 Asset Reachable", weight=38.5, description="Path leads to Auth DB")
        ],
        calculatedAt="2026-10-09T20:15:00Z",
        environmentId="env-prod",
        explanation={"formula": "base_weights_v1"}
    )
    risk_repo1.save_current_risk(risk)

    path = AttackPathResponse(
        id="path-001",
        environmentId="env-prod",
        entryPointAssetId="asset-web-01",
        targetAssetId="asset-auth-02",
        severity="HIGH",
        pathScore=72.0,
        nodes=[
            AttackPathNodeSchema(
                assetId="asset-web-01",
                assetName="web-frontend",
                assetType="SERVICE",
                stepOrder=1,
                description="Initial breach"
            ),
            AttackPathNodeSchema(
                assetId="asset-auth-02",
                assetName="auth-service",
                assetType="SERVICE",
                stepOrder=2,
                description="Privilege pivot"
            )
        ],
        isActive=True,
        reachability="REACHABLE",
        discoveredAt="2026-10-09T20:15:00Z"
    )
    path_repo1.save_attack_paths("env-prod", [path])

    del risk_repo1, path_repo1, engine1

    engine2 = SQLDatabaseEngine(temp_db_path)
    risk_repo2 = SQLRiskRepository(engine=engine2)
    path_repo2 = SQLAttackPathRepository(engine=engine2)

    loaded_risk = risk_repo2.get_current_risk("env-prod")
    assert loaded_risk is not None
    assert loaded_risk.overallScore == 68.5
    assert len(loaded_risk.contributors) == 2

    history = risk_repo2.get_history("env-prod")
    assert len(history) >= 1
    assert history[-1].score == 68.5

    loaded_paths = path_repo2.list_attack_paths("env-prod")
    assert len(loaded_paths) == 1
    assert loaded_paths[0].id == "path-001"
    assert loaded_paths[0].reachability == "REACHABLE"

    # Mitigation update durability
    path_repo2.update_path_reachability("path-001", "env-prod", is_active=False, reachability="BLOCKED")
    reloaded_path = path_repo2.get_attack_path("path-001", "env-prod")
    assert reloaded_path.reachability == "BLOCKED"
    assert reloaded_path.isActive is False


# ============================================================================
# 6. USERS, AUTHENTICATION & SINGLE-USE REFRESH TOKEN ROTATION
# ============================================================================

def test_users_and_refresh_tokens_durable_rotation(temp_db_path):
    engine1 = SQLDatabaseEngine(temp_db_path)
    repo1 = SQLUserRepository(engine=engine1)

    # Verify default accounts were seeded
    admin_u = repo1.authenticate("admin", "AdminRoot2026!")
    assert admin_u is not None
    assert admin_u.role == "admin"

    # Create dynamic user
    now_iso = "2026-10-09T20:20:00Z"
    new_user = UserRecord(
        id="usr-custom-audit-01",
        username="auditor",
        passwordHash=repo1.authenticate("admin", "AdminRoot2026!").passwordHash,
        role="security_analyst",
        environmentId="env-prod",
        isActive=True,
        createdAt=now_iso,
        updatedAt=now_iso
    )
    repo1.save_user(new_user)

    # Store refresh token
    raw_token = "rt_stage3_secret_token_12345"
    repo1.store_refresh_token(new_user.id, raw_token, expires_seconds=3600)

    # Restart
    del repo1, engine1

    engine2 = SQLDatabaseEngine(temp_db_path)
    repo2 = SQLUserRepository(engine=engine2)

    # Verify dynamic user survived
    loaded_user = repo2.get_by_id("usr-custom-audit-01")
    assert loaded_user is not None
    assert loaded_user.username == "auditor"

    # Verify refresh token survives and can be single-use consumed
    assert repo2.consume_refresh_token("usr-custom-audit-01", raw_token) is True

    # Replay must fail (single-use enforced)
    assert repo2.consume_refresh_token("usr-custom-audit-01", raw_token) is False


# ============================================================================
# 7. CRYPTOGRAPHIC AUDIT LOG OVER RESTARTS
# ============================================================================

def test_cryptographic_audit_trail_survives_and_verifies_over_restart(temp_db_path):
    engine1 = SQLDatabaseEngine(temp_db_path)
    audit1 = SQLAuditTrail(engine=engine1)

    e1 = audit1.append_entry(
        environment_id="env-prod",
        event_type="RESPONSE_PROPOSED",
        actor="usr-analyst-1",
        incident_id="inc-001",
        response_id="resp-001",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.42",
        outcome="SUCCESS",
        details={"reason": "Active brute-force containment"}
    )
    assert e1.sequenceNumber == 1

    e2 = audit1.append_entry(
        environment_id="env-prod",
        event_type="RESPONSE_EXECUTED",
        actor="usr-operator-1",
        incident_id="inc-001",
        response_id="resp-001",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.42",
        outcome="SUCCESS",
        details={"status": "Enforced at edge"}
    )
    assert e2.sequenceNumber == 2
    assert e2.previousHash == e1.recordHash

    # Restart
    del audit1, engine1

    engine2 = SQLDatabaseEngine(temp_db_path)
    audit2 = SQLAuditTrail(engine=engine2)

    entries = audit2.get_entries("env-prod")
    assert len(entries) == 2
    assert entries[0].recordHash == e1.recordHash
    assert entries[1].recordHash == e2.recordHash

    # Verify hash chain
    res = audit2.verify_chain("env-prod")
    assert res.verified is True
    assert res.totalRecords == 2
    assert res.error is None


# ============================================================================
# 8. PERSISTENT TELEMETRY DEDUPLICATION & REPLAY PREVENTION
# ============================================================================

def test_telemetry_deduplicator_prevents_replay_across_restart(temp_db_path):
    old_env = os.environ.get("GASHA_DATABASE_PATH")
    os.environ["GASHA_DATABASE_PATH"] = temp_db_path
    try:
        dedup1 = EventDeduplicator(storage_backend=StorageMode.SQL)

        evt = TelemetryEventSchema(
            id="evt-durable-dedup-001",
            eventType="AUTH_FAILURE",
            sourceService="auth-api",
            environmentId="env-prod",
            timestamp="2026-10-09T20:00:00Z",
            payload=TelemetryEventPayloadSchema(
                sourceIp="198.51.100.77",
                httpMethod="POST",
                httpPath="/api/v1/auth/login",
                httpStatusCode=401,
                action="USER_LOGIN",
                outcome="FAILURE"
            )
        )

        # First ingestion -> NEW
        res, _ = dedup1.check_and_record(evt)
        assert res == DeduplicationResult.IS_NEW

        # Duplicate in same process -> DUPLICATE
        res_dup, _ = dedup1.check_and_record(evt)
        assert res_dup == DeduplicationResult.IS_DUPLICATE

        # Simulate service shutdown and empty in-memory cache
        del dedup1

        # Fresh instance on restart
        dedup2 = EventDeduplicator(storage_backend=StorageMode.SQL)
        assert len(dedup2._cache) == 0  # In-memory cache completely empty

        # Replay identical event -> MUST BE DETECTED AS DUPLICATE FROM DB
        res_replay, _ = dedup2.check_and_record(evt)
        assert res_replay == DeduplicationResult.IS_DUPLICATE
    finally:
        if old_env is not None:
            os.environ["GASHA_DATABASE_PATH"] = old_env
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)


# ============================================================================
# 9. DEMO TARGET DEFENSE PERSISTENCE OVER RESTARTS
# ============================================================================

def test_demo_target_defenses_persist_across_restarts():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_bl:
        bl_path = f_bl.name
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_sess:
        sess_path = f_sess.name

    old_bl = os.environ.get("DEMO_TARGET_BLOCKLIST_FILE")
    old_sess = os.environ.get("DEMO_TARGET_SESSIONS_FILE")
    os.environ["DEMO_TARGET_BLOCKLIST_FILE"] = bl_path
    os.environ["DEMO_TARGET_SESSIONS_FILE"] = sess_path

    try:
        target_blocklist.clear_blocklist()
        target_sessions.clear_disabled_sessions()

        target_blocklist.block_ip("203.0.113.199")
        target_sessions.disable_session("sess-compromised-token-999")

        assert target_blocklist.is_blocked("203.0.113.199") is True
        assert target_sessions.is_session_disabled("sess-compromised-token-999") is True

        # Simulate process termination by wiping runtime in-memory sets
        target_blocklist._blocked_ips.clear()
        target_sessions._disabled_sessions.clear()

        # Re-check: file persistence must restore defenses
        assert target_blocklist.is_blocked("203.0.113.199") is True
        assert target_sessions.is_session_disabled("sess-compromised-token-999") is True
    finally:
        if old_bl:
            os.environ["DEMO_TARGET_BLOCKLIST_FILE"] = old_bl
        else:
            os.environ.pop("DEMO_TARGET_BLOCKLIST_FILE", None)
        if old_sess:
            os.environ["DEMO_TARGET_SESSIONS_FILE"] = old_sess
        else:
            os.environ.pop("DEMO_TARGET_SESSIONS_FILE", None)
        for p in (bl_path, sess_path):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
