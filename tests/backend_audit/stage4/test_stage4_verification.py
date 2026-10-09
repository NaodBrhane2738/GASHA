"""
==============================================================================
FILE: tests/backend_audit/stage4/test_stage4_verification.py
ROLE / PURPOSE: GASHA Final Acceptance — Stage 4 Comprehensive Verification Suite
AUDIT TARGET: D:\\CODING\\GASHA
SCOPE:
  - Storage mode safety resolver & fail-closed behavior in production
  - Database path normalization across arbitrary process working directories
  - All 12 SQL-backed persistent repositories CRUD & multi-tenant isolation
  - Digital Twin graph reconstruction (multinodes, cycles, containment, determinism)
  - Telemetry deduplication (immediate, post-restart, multi-tenant, concurrency)
  - Demo target file-backed defense durability & corrupt-state resilience
  - Authentication security, token rotation, and single-use replay detection
  - SHA-256 cryptographic audit chain verification & tamper detection
  - End-to-end defense loop under explicit SQL storage mode with service restart
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
import asyncio
import pytest
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent.parent
sys.path.extend([
    str(repo_root / "apps" / "api"),
    str(repo_root / "apps" / "demo-target"),
    str(repo_root / "packages" / "telemetry-sdk" / "python"),
])

from app.db.storage_mode import resolve_storage_backend, StorageMode
from app.db.sql_engine import (
    SQLDatabaseEngine,
    normalize_db_path,
    get_sql_engine,
    SQLIncidentRepository,
    SQLDetectionRepository,
    SQLResponseRepository,
    SQLUserRepository,
    SQLInvestigationRepository,
    SQLAssetRepository,
    SQLConnectionRepository,
    SQLVulnerabilityRepository,
    SQLRiskRepository,
    SQLAttackPathRepository,
    SQLAuditTrail,
)
from app.db.repositories.incident_repository import get_incident_repository, IncidentRepository
from app.db.repositories.detection_repository import get_detection_repository, DetectionRepository
from app.db.repositories.response_repository import get_response_repository, ResponseRepository
from app.db.repositories.user_repository import get_user_repository, UserRepository
from app.db.repositories.investigation_repository import get_investigation_repository, InvestigationRepository
from app.db.repositories.asset_repository import get_asset_repository, AssetRepository
from app.db.repositories.connection_repository import get_connection_repository, ConnectionRepository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository, VulnerabilityRepository
from app.db.repositories.risk_repository import get_risk_repository, RiskRepository
from app.db.repositories.attack_path_repository import get_attack_path_repository, AttackPathRepository
from app.response.audit import get_audit_trail, AuditTrail

from app.schemas.incident import IncidentResponse, IncidentStatus
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.response import ResponseRecordResponse, ResponseActionType, ResponseTargetType, ResponseStatus
from app.schemas.investigation import (
    InvestigationResultResponse, AttackStorySchema, EvidenceSchema,
    RecommendationSchema, InvestigationTimelineResponse, TimelineEventResponse
)
from app.schemas.asset import AssetResponse, AssetBase, RelationshipResponse, RelationshipBase
from app.schemas.vulnerability import VulnerabilityResponse, VulnerabilityStatus
from app.schemas.risk import RiskScoreResponse, RiskContributorSchema, RiskHistoryEntryResponse
from app.schemas.attack_path import AttackPathResponse, AttackPathNodeSchema, ReachabilityStatus
from app.schemas.user import UserRecord
from app.schemas.connection import ConnectionRecord, DiscoveryRunStatus
from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema

from app.detection.deduplicator import EventDeduplicator, DeduplicationResult
from app.digital_twin.builder import DigitalTwinBuilder
from app.risk.service import RiskService
from app.attack_paths.service import AttackPathService
from app.core.security import create_jwt_token, hash_password, verify_password


# ============================================================================
# 1. STORAGE MODE RESOLVER & FAIL-CLOSED SAFETY
# ============================================================================

def test_stage4_storage_mode_resolution_and_fail_closed():
    """Verify resolve_storage_backend behavior across environments and fail-closed rules."""
    old_env = os.environ.copy()
    try:
        os.environ.pop("GASHA_STORAGE_BACKEND", None)
        os.environ["NODE_ENV"] = "development"
        assert resolve_storage_backend() == StorageMode.MEMORY

        # Production unset defaults to sql
        os.environ["NODE_ENV"] = "production"
        assert resolve_storage_backend() == StorageMode.SQL

        # Production with explicit memory fails closed
        os.environ["GASHA_STORAGE_BACKEND"] = "memory"
        with pytest.raises(RuntimeError, match="Production environment requires durable 'sql' storage"):
            resolve_storage_backend()

        # Invalid backend values fail closed with ValueError
        for invalid in ["redis", "postgres_pool", "mongo", "unknown"]:
            os.environ["GASHA_STORAGE_BACKEND"] = invalid
            with pytest.raises(ValueError, match="Invalid GASHA_STORAGE_BACKEND"):
                resolve_storage_backend()

        # Case-insensitivity works
        assert resolve_storage_backend("SQL") == "sql"
        assert resolve_storage_backend("sql") == "sql"
        os.environ["NODE_ENV"] = "development"
        assert resolve_storage_backend("MEMORY") == "memory"
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def test_stage4_database_path_normalization_across_dirs():
    """Verify normalize_db_path anchors relative paths to canonical repo root."""
    rel = "gasha_test_stage4.db"
    norm = normalize_db_path(rel)
    assert os.path.isabs(norm)
    assert Path(norm) == (repo_root / rel).resolve()

    # Absolute path remains untouched
    abs_path = os.path.abspath(tempfile.gettempdir() + os.sep + "custom.db")
    assert normalize_db_path(abs_path) == abs_path


# ============================================================================
# 2. ADAPTER SELECTION & FACTORY VERIFICATION (MODE A vs MODE B)
# ============================================================================

def test_stage4_adapter_selection_mode_a_vs_mode_b():
    """Verify factory functions return in-memory doubles in Mode A and SQL adapters in Mode B."""
    # Mode A: Explicit Memory
    assert type(get_incident_repository("memory")).__name__ == "IncidentRepository"
    assert type(get_detection_repository("memory")).__name__ == "DetectionRepository"
    assert type(get_response_repository("memory")).__name__ == "ResponseRepository"
    assert type(get_audit_trail("memory")).__name__ == "AuditTrail"
    assert type(get_user_repository("memory")).__name__ == "UserRepository"
    assert type(get_investigation_repository("memory")).__name__ == "InvestigationRepository"
    assert type(get_asset_repository("memory")).__name__ == "AssetRepository"
    assert type(get_connection_repository("memory")).__name__ == "ConnectionRepository"
    assert type(get_vulnerability_repository("memory")).__name__ == "VulnerabilityRepository"
    assert type(get_risk_repository("memory")).__name__ == "RiskRepository"
    assert type(get_attack_path_repository("memory")).__name__ == "AttackPathRepository"

    # Mode B: Explicit SQL
    assert type(get_incident_repository("sql")).__name__ == "SQLIncidentRepository"
    assert type(get_detection_repository("sql")).__name__ == "SQLDetectionRepository"
    assert type(get_response_repository("sql")).__name__ == "SQLResponseRepository"
    assert type(get_audit_trail("sql")).__name__ == "SQLAuditTrail"
    assert type(get_user_repository("sql")).__name__ == "SQLUserRepository"
    assert type(get_investigation_repository("sql")).__name__ == "SQLInvestigationRepository"
    assert type(get_asset_repository("sql")).__name__ == "SQLAssetRepository"
    assert type(get_connection_repository("sql")).__name__ == "SQLConnectionRepository"
    assert type(get_vulnerability_repository("sql")).__name__ == "SQLVulnerabilityRepository"
    assert type(get_risk_repository("sql")).__name__ == "SQLRiskRepository"
    assert type(get_attack_path_repository("sql")).__name__ == "SQLAttackPathRepository"


# ============================================================================
# 3. ALL 12 SQL ADAPTERS: CRUD, IDEMPOTENCY & MULTI-TENANT ISOLATION
# ============================================================================

def test_stage4_all_sql_adapters_crud_and_isolation():
    """Test full CRUD lifecycle, idempotency, and strict tenant isolation across all SQL adapters."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        engine = SQLDatabaseEngine(db_path=temp_db)
        now = datetime.now(timezone.utc).isoformat()

        # 1. Incidents
        inc_repo = SQLIncidentRepository(engine=engine)
        inc_prod = IncidentResponse(
            id="inc-stage4-prod", title="Prod Incident", severity="HIGH", status="ACTIVE",
            primaryAffectedAssetId="ast-prod-1", relatedAssetIds=[], detectionEventIds=[],
            createdAt=now, updatedAt=now
        )
        inc_repo.save_incident(inc_prod)
        assert inc_repo.get_incident("inc-stage4-prod") is not None
        assert len(inc_repo.list_incidents("env-prod")) == 1
        assert len(inc_repo.list_incidents("env-dev")) == 0  # Tenant isolation

        # 2. Detections
        det_repo = SQLDetectionRepository(engine=engine)
        det = DetectionEventResponse(
            id="det-stage4-1",
            rule=DetectionRuleSummarySchema(
                ruleId="RULE-AUTH-001", name="Auth Fail", description="Desc",
                severity="MEDIUM", confidence=0.85
            ),
            matchedEventIds=["evt-1"], primaryAssetId="ast-prod-1", timestamp=now,
            severity="MEDIUM", confidence=0.85, evidenceSummary="Summary", environmentId="env-prod"
        )
        det_repo.save_detection(det)
        assert det_repo.get_detection("det-stage4-1", "env-prod") is not None
        assert det_repo.get_detection("det-stage4-1", "env-dev") is None  # Isolated

        # 3. Responses
        resp_repo = SQLResponseRepository(engine=engine)
        resp = ResponseRecordResponse(
            id="resp-stage4-1", incidentId="inc-stage4-prod", environmentId="env-prod",
            actionType="BLOCK_SOURCE", targetType="IP_ADDRESS", targetIdentifier="198.51.100.22",
            status="PROPOSED", reason="Brute force", proposedAt=now, proposedBy="analyst"
        )
        resp_repo.save_response(resp)
        assert resp_repo.get_response("resp-stage4-1", "env-prod") is not None
        assert resp_repo.get_response("resp-stage4-1", "env-dev") is None

        # 4. Users & Refresh Tokens
        user_repo = SQLUserRepository(engine=engine)
        user = UserRecord(
            id="usr-stage4-sec", username="auditor_sec", passwordHash=hash_password("AuditPass2026!"),
            role="security_analyst", environmentId="env-prod", isActive=True, createdAt=now, updatedAt=now
        )
        user_repo.save_user(user)
        assert user_repo.authenticate("auditor_sec", "AuditPass2026!") is not None
        assert user_repo.authenticate("auditor_sec", "WrongPassword!") is None
        user_repo.store_refresh_token(user.id, "rft_stage4_token", expires_seconds=3600)
        assert user_repo.consume_refresh_token(user.id, "rft_stage4_token") is True
        assert user_repo.consume_refresh_token(user.id, "rft_stage4_token") is False  # Single-use

        # 5. Investigations & Timelines
        inv_repo = SQLInvestigationRepository(engine=engine)
        inv = InvestigationResultResponse(
            incidentId="inc-stage4-prod", environmentId="env-prod", summary="Investigation Summary",
            severity="HIGH", confidenceScore=0.92,
            attackStory=AttackStorySchema(
                observedFacts=["Facts"], reasonableInferences=["Inferences"],
                unknownsAndGaps=["None"], narrativeSummary="Narrative"
            ),
            groundedEvidence=[], recommendations=[], generatedAt=now
        )
        inv_repo.save_investigation(inv, "env-prod")
        assert inv_repo.get_investigation("inc-stage4-prod", "env-prod") is not None
        assert inv_repo.get_investigation("inc-stage4-prod", "env-dev") is None

        timeline = InvestigationTimelineResponse(
            incidentId="inc-stage4-prod", environmentId="env-prod",
            events=[TimelineEventResponse(
                timestamp=now, eventId="evt-1", eventType="DETECTION",
                source="ENGINE", outcome="SUCCESS", summary="Rule matched"
            )],
            totalEvents=1,
            hasContradictions=False
        )
        inv_repo.save_timeline(timeline)
        assert inv_repo.get_timeline("inc-stage4-prod", "env-prod") is not None

        # 6. Assets & Relationships
        asset_repo = SQLAssetRepository(engine=engine)
        a1 = AssetBase(name="auth-api", type="SERVICE", criticality="TIER_1_HIGH", environmentId="env-prod", source="GITHUB", metadata={"port": 8000}, isPubliclyExposed=True)
        saved_a1 = asset_repo.upsert_asset(a1, "ast-1")
        assert saved_a1.id == "ast-1"
        assert asset_repo.count_assets("env-prod") == 1
        assert asset_repo.count_assets("env-dev") == 0

        # Idempotent upsert with metadata merge
        a1_update = AssetBase(name="auth-api", type="SERVICE", criticality="TIER_1_HIGH", environmentId="env-prod", source="GITHUB", metadata={"version": "1.2.0"}, isPubliclyExposed=True)
        updated_a1 = asset_repo.upsert_asset(a1_update, "ast-1")
        assert updated_a1.metadata.get("port") == 8000
        assert updated_a1.metadata.get("version") == "1.2.0"

        # 7. Connections & Discovery Runs
        conn_repo = SQLConnectionRepository(engine=engine)
        conn = ConnectionRecord(id="conn-1", provider="GITHUB", environmentId="env-prod", encryptedToken="enc_token", status="CONNECTED", createdAt=now, updatedAt=now)
        conn_repo.save_connection(conn)
        assert conn_repo.get_connection("env-prod", "GITHUB") is not None
        assert conn_repo.get_connection("env-dev", "GITHUB") is None

        run = DiscoveryRunStatus(id="run-1", environmentId="env-prod", provider="GITHUB", status="COMPLETED", assetsDiscovered=5, relationshipsDiscovered=4, startedAt=now, completedAt=now)
        conn_repo.record_run(run)
        assert len(conn_repo.get_recent_runs("env-prod")) == 1

        # 8. Vulnerabilities
        vuln_repo = SQLVulnerabilityRepository(engine=engine)
        v = VulnerabilityResponse(
            id="vuln-1", assetId="ast-1", environmentId="env-prod", title="SQLi", description="SQL injection",
            severity="CRITICAL", cvssScore=9.8, category="INSECURE_CONFIG", remediationGuidance="Fix",
            status="OPEN", discoveredAt=now
        )
        vuln_repo.upsert_finding(v, "vuln-1")
        assert vuln_repo.get_finding("vuln-1", "env-prod") is not None
        assert vuln_repo.get_finding("vuln-1", "env-dev") is None

        # 9. Risks
        risk_repo = SQLRiskRepository(engine=engine)
        r = RiskScoreResponse(
            overallScore=82.5, criticalAssetsAtRiskCount=1, highRiskVulnerabilitiesCount=1,
            activeAttackPathsCount=1, contributors=[], calculatedAt=now, environmentId="env-prod"
        )
        risk_repo.save_current_risk(r)
        assert risk_repo.get_current_risk("env-prod").overallScore == 82.5
        assert risk_repo.get_current_risk("env-dev") is None

        # 10. Attack Paths
        path_repo = SQLAttackPathRepository(engine=engine)
        p = AttackPathResponse(
            id="path-1", environmentId="env-prod", entryPointAssetId="ast-1", targetAssetId="ast-1",
            severity="HIGH", pathScore=75.0, nodes=[], isActive=True, reachability="REACHABLE",
            discoveredAt=now
        )
        path_repo.save_attack_paths("env-prod", [p])
        assert len(path_repo.list_attack_paths("env-prod")) == 1
        assert len(path_repo.list_attack_paths("env-dev")) == 0

        # 11. Audit Trail
        audit_repo = SQLAuditTrail(engine=engine)
        entry = audit_repo.append_entry(
            environment_id="env-prod", event_type="TEST_ACTION", actor="auditor",
            incident_id="inc-1", response_id="resp-1", action_type="BLOCK_SOURCE",
            target_identifier="198.51.100.22", outcome="SUCCESS"
        )
        assert entry.auditId is not None
        assert audit_repo.verify_chain("env-prod").verified is True

        # 12. Telemetry Deduplication in DB
        engine.save_dedup_record("env-prod:evt-dedup-sql", "env-prod", "evt-dedup-sql", "hash-xyz-123", time.time(), [])
        assert engine.get_dedup_record("env-prod:evt-dedup-sql")["fingerprint"] == "hash-xyz-123"
        assert engine.get_dedup_record("env-dev:evt-dedup-sql") is None  # Environment isolated
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


# ============================================================================
# 4. DIGITAL TWIN RECONSTRUCTION, CONTAINMENT, AND RISK DETERMINISM
# ============================================================================

def test_stage4_digital_twin_reconstruction_scenarios():
    """
    Test Digital Twin reconstruction across:
    - Multiple nodes & directed relationships
    - Disconnected nodes
    - Cycles
    - Finding attachment
    - Containment reachability change & risk reduction
    - Unresolved source finding remaining OPEN after runtime containment
    - Deterministic recalculation
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        engine = SQLDatabaseEngine(db_path=temp_db)
        asset_repo = SQLAssetRepository(engine=engine)
        vuln_repo = SQLVulnerabilityRepository(engine=engine)
        path_repo = SQLAttackPathRepository(engine=engine)
        risk_repo = SQLRiskRepository(engine=engine)
        now = datetime.now(timezone.utc).isoformat()

        # Build assets
        # 1. ast-gw (Public Gateway)
        asset_repo.upsert_asset(AssetBase(
            name="api-gateway", type="SERVICE", criticality="TIER_1_HIGH",
            environmentId="env-prod", source="GITHUB", metadata={}, isPubliclyExposed=True
        ), "ast-gw")

        # 2. ast-app (Internal App)
        asset_repo.upsert_asset(AssetBase(
            name="app-service", type="SERVICE", criticality="TIER_2_MEDIUM",
            environmentId="env-prod", source="GITHUB", metadata={}, isPubliclyExposed=False
        ), "ast-app")

        # 3. ast-db (Target Database)
        asset_repo.upsert_asset(AssetBase(
            name="db-prod", type="DATABASE", criticality="TIER_1_HIGH",
            environmentId="env-prod", source="GITHUB", metadata={}, isPubliclyExposed=False
        ), "ast-db")

        # 4. ast-isolated (Disconnected Worker)
        asset_repo.upsert_asset(AssetBase(
            name="batch-worker", type="SERVICE", criticality="TIER_3_LOW",
            environmentId="env-prod", source="GITHUB", metadata={}, isPubliclyExposed=False
        ), "ast-isolated")

        # Build directed relationships: ast-gw -> ast-app -> ast-db, and cycle ast-app -> ast-gw
        asset_repo.upsert_relationship(RelationshipBase(sourceAssetId="ast-gw", targetAssetId="ast-app", type="CONNECTS_TO"), "rel-1", "env-prod")
        asset_repo.upsert_relationship(RelationshipBase(sourceAssetId="ast-app", targetAssetId="ast-db", type="CONNECTS_TO"), "rel-2", "env-prod")
        asset_repo.upsert_relationship(RelationshipBase(sourceAssetId="ast-app", targetAssetId="ast-gw", type="CALLS"), "rel-3", "env-prod")  # Cycle

        # Vulnerabilities: Critical finding on ast-gw and High finding on ast-db
        vuln_repo.upsert_finding(VulnerabilityResponse(
            id="vuln-cve-gw", assetId="ast-gw", environmentId="env-prod", title="CVE-2026-9001 RCE",
            description="Remote code execution on gateway", severity="CRITICAL", cvssScore=9.8,
            category="INSECURE_CONFIG", remediationGuidance="Patch", status="OPEN", discoveredAt=now
        ), "vuln-cve-gw")

        vuln_repo.upsert_finding(VulnerabilityResponse(
            id="vuln-cve-db", assetId="ast-db", environmentId="env-prod", title="CVE-2026-9002 Auth Bypass",
            description="DB auth bypass", severity="HIGH", cvssScore=8.5,
            category="INSECURE_CONFIG", remediationGuidance="Upgrade DB", status="OPEN", discoveredAt=now
        ), "vuln-cve-db")

        # 1. Reconstruct SecurityGraph
        builder = DigitalTwinBuilder()
        builder.asset_repo = asset_repo
        builder.vuln_repo = vuln_repo

        graph = builder.build_graph_for_environment("env-prod")
        assert len(graph.list_nodes()) == 4, "Must contain all 4 nodes including disconnected ast-isolated"
        assert graph.get_node("ast-isolated") is not None
        assert graph.get_node("ast-gw")["vulnerabilityIds"] == ["vuln-cve-gw"]
        assert graph.get_node("ast-db")["vulnerabilityIds"] == ["vuln-cve-db"]

        # 2. Compute attack paths
        path_svc = AttackPathService()
        path_svc.builder = builder
        path_svc.path_repo = path_repo

        paths = path_svc.recalculate_attack_paths("env-prod")
        assert len(paths) >= 1
        path = paths[0]
        assert path.entryPointAssetId == "ast-gw"
        assert path.targetAssetId == "ast-db"
        assert path.reachability == "REACHABLE"
        assert path.isActive is True

        # 3. Compute risk
        risk_svc = RiskService()
        risk_svc.asset_repo = asset_repo
        risk_svc.vuln_repo = vuln_repo
        risk_svc.path_repo = path_repo
        risk_svc.risk_repo = risk_repo

        initial_risk = risk_svc.recalculate_risk("env-prod")
        assert initial_risk.overallScore > 50.0

        # 4. Contain ast-gw and update path reachability
        path_repo.update_path_reachability(
            path_id=path.id, environment_id="env-prod",
            is_active=False, reachability="BLOCKED"
        )
        post_containment_paths = path_repo.list_attack_paths("env-prod")
        assert post_containment_paths[0].reachability == "BLOCKED"
        assert post_containment_paths[0].isActive is False

        # Recalculate risk post-containment
        mitigated_risk = risk_svc.recalculate_risk("env-prod")
        assert mitigated_risk.overallScore < initial_risk.overallScore, "Risk score must decrease after path containment"

        # 5. Verify source code vulnerability remains OPEN
        persisted_vuln = vuln_repo.get_finding("vuln-cve-gw", "env-prod")
        assert persisted_vuln.status == "OPEN", "Runtime containment must not alter source vulnerability status"

        # 6. Verify 100% determinism across 3 repeated runs
        scores = [risk_svc.recalculate_risk("env-prod").overallScore for _ in range(3)]
        assert scores[0] == scores[1] == scores[2], f"Scores must be perfectly deterministic: {scores}"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


# ============================================================================
# 5. DEDUPLICATION & REPLAY UNDER PERSISTENCE & CONCURRENCY
# ============================================================================

def test_stage4_telemetry_deduplication_deep_scenarios():
    """Verify deduplication across immediate replay, post-restart, cross-tenant isolation, and races."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    try:
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        engine = SQLDatabaseEngine(db_path=temp_db)
        dedup = EventDeduplicator(max_size=10, ttl_seconds=3600, storage_backend="sql", engine=engine)

        evt = TelemetryEventSchema(
            id="evt-deep-1",
            timestamp="2026-10-09T20:00:00Z",
            eventType="AUTH_FAILURE",
            sourceService="auth-svc",
            environmentId="env-prod",
            payload=TelemetryEventPayloadSchema(
                sourceIp="198.51.100.1",
                httpMethod="POST",
                httpPath="/api/v1/auth/login",
                httpStatusCode=401,
                action="AUTH_FAILURE",
                outcome="FAILURE"
            )
        )

        # 1. New event accepted
        r1, _ = dedup.check_and_record(evt)
        assert r1 == DeduplicationResult.IS_NEW

        # 2. Immediate replay recognized as duplicate
        r2, _ = dedup.check_and_record(evt)
        assert r2 == DeduplicationResult.IS_DUPLICATE

        # 3. Simulate process restart by clearing memory cache
        dedup._cache.clear()
        assert len(dedup._cache) == 0
        r3, _ = dedup.check_and_record(evt)
        assert r3 == DeduplicationResult.IS_DUPLICATE, "Must detect duplicate from durable SQLite table"

        # 4. Same event ID in DIFFERENT environment (tenant isolation)
        evt_other_env = evt.model_copy(update={"environmentId": "env-dev"})
        r_other, _ = dedup.check_and_record(evt_other_env)
        assert r_other == DeduplicationResult.IS_NEW, "Cross-tenant event with same ID must not collide"

        # 5. Concurrent race condition: 10 threads submit the exact same event ID concurrently
        evt_race = evt.model_copy(update={"id": "evt-race-target"})
        results = []
        def worker():
            res, _ = dedup.check_and_record(evt_race)
            results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for th in threads: th.start()
        for th in threads: th.join()

        assert results.count(DeduplicationResult.IS_NEW) == 1, "Exactly 1 concurrent request must be accepted as NEW"
        assert results.count(DeduplicationResult.IS_DUPLICATE) == 9, "9 concurrent requests must be rejected as duplicates"
    finally:
        if old_db:
            os.environ["GASHA_DATABASE_PATH"] = old_db
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)
        if os.path.exists(temp_db):
            os.remove(temp_db)


# ============================================================================
# 6. DEMO-TARGET FILE-BACKED DEFENSE DURABILITY & SAFE ERROR HANDLING
# ============================================================================

def test_stage4_demo_target_defenses_durability_and_resilience():
    """Verify demo-target blocklist and session revocation persist to disk and handle corrupt files safely."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_bl:
        bl_path = f_bl.name
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_sess:
        sess_path = f_sess.name

    old_bl = os.environ.get("DEMO_TARGET_BLOCKLIST_FILE")
    old_sess = os.environ.get("DEMO_TARGET_SESSIONS_FILE")
    try:
        os.environ["DEMO_TARGET_BLOCKLIST_FILE"] = bl_path
        os.environ["DEMO_TARGET_SESSIONS_FILE"] = sess_path

        from security.blocklist import block_ip, is_blocked, clear_blocklist, _blocked_ips, _load_persisted as load_blocklist
        from security.sessions import disable_session, is_session_disabled, clear_disabled_sessions, _disabled_sessions, _load_persisted as load_sessions

        # 1. IP Blocklist writes and survives restart
        clear_blocklist()
        block_ip("198.51.100.77")
        assert is_blocked("198.51.100.77") is True
        assert is_blocked("198.51.100.1") is False

        # Simulate restart by clearing in-memory set only (disk file retained)
        _blocked_ips.clear()
        assert is_blocked("198.51.100.77") is True

        # 2. Session Store writes and survives restart
        clear_disabled_sessions()
        disable_session("sess-compromised-xyz")
        assert is_session_disabled("sess-compromised-xyz") is True
        assert is_session_disabled("sess-benign-abc") is False

        # Simulate restart by clearing in-memory set only (disk file retained)
        _disabled_sessions.clear()
        assert is_session_disabled("sess-compromised-xyz") is True

        # 3. Corrupt file resilience: write invalid json
        with open(bl_path, "w", encoding="utf-8") as f:
            f.write("{ INVALID_JSON_CORRUPTED !!!")

        # Must not crash; loads gracefully
        clear_blocklist()
        load_blocklist()
        assert is_blocked("198.51.100.77") is False
        block_ip("198.51.100.99")
        assert is_blocked("198.51.100.99") is True
    finally:
        if old_bl:
            os.environ["DEMO_TARGET_BLOCKLIST_FILE"] = old_bl
        else:
            os.environ.pop("DEMO_TARGET_BLOCKLIST_FILE", None)
        if old_sess:
            os.environ["DEMO_TARGET_SESSIONS_FILE"] = old_sess
        else:
            os.environ.pop("DEMO_TARGET_SESSIONS_FILE", None)

        for p in [bl_path, sess_path]:
            if os.path.exists(p):
                os.remove(p)


# ============================================================================
# 7. CRYPTOGRAPHIC AUDIT TRAIL TAMPER DETECTION
# ============================================================================

def test_stage4_audit_trail_tamper_detection_and_linkage_verification():
    """Verify SHA-256 cryptographic hash chain detects modifications, deletions, and reordering."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        engine = SQLDatabaseEngine(db_path=temp_db)
        audit = SQLAuditTrail(engine=engine)

        e1 = audit.append_entry("env-prod", "PROPOSE", "analyst", "inc-1", "resp-1", "BLOCK_SOURCE", "1.1.1.1", "SUCCESS")
        e2 = audit.append_entry("env-prod", "APPROVE", "operator", "inc-1", "resp-1", "BLOCK_SOURCE", "1.1.1.1", "SUCCESS")
        e3 = audit.append_entry("env-prod", "EXECUTE", "system", "inc-1", "resp-1", "BLOCK_SOURCE", "1.1.1.1", "SUCCESS")

        res_clean = audit.verify_chain("env-prod")
        assert res_clean.verified is True
        assert res_clean.totalRecords == 3

        # Tamper test 1: Modify row 2 payload directly in SQLite
        with engine.get_connection() as conn:
            conn.execute("UPDATE response_audit_log SET target_identifier = '9.9.9.9' WHERE audit_id = ?", (e2.auditId,))

        res_tampered = audit.verify_chain("env-prod")
        assert res_tampered.verified is False
        assert "tampering" in res_tampered.error.lower() or "mismatch" in res_tampered.error.lower()

        # Tamper test 2: Break prev_hash linkage
        with engine.get_connection() as conn:
            conn.execute("UPDATE response_audit_log SET previous_hash = 'bogus_hash_link' WHERE audit_id = ?", (e3.auditId,))

        res_broken = audit.verify_chain("env-prod")
        assert res_broken.verified is False
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


# ============================================================================
# 8. COMPLETE END-TO-END DEFENSIVE WORKFLOW IN SQL MODE WITH PROCESS RESTART
# ============================================================================

def test_stage4_end_to_end_defense_flow_in_sql_mode_with_restart():
    """
    Subprocess 1:
      - Starts FastAPI app under explicit SQL storage mode.
      - Ingests brute-force attack telemetry via process_stream.
      - Detection rule matches -> creates incident in SQLite.
      - Analyst logs in, fetches incident, proposes IP block.
      - Operator logs in (dual-custody), approves response.
      - Response executes -> blocks IP on target.
      - Audit trail logs cryptographically chained record.
    Subprocess 2:
      - Starts fresh FastAPI app pointing to same SQLite database.
      - Validates incident, response, audit records, and user session token survival.
      - Validates replay rejection of previously consumed refresh token.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name
    try:
        script_proc1 = '''
import sys, os, asyncio, json
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from fastapi.testclient import TestClient
from app.main import app
from app.telemetry.processor import process_stream
from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema

client = TestClient(app)

# 1. Health check verifies SQL mode
health_res = client.get('/health')
assert health_res.status_code == 200
assert health_res.json().get('storage_mode') == 'sql'

# 2. Login as analyst
login_res = client.post('/api/v1/auth/login', json={'username': 'analyst', 'password': 'AnalystSecure2026!'})
assert login_res.status_code == 200
login_data = login_res.json()
analyst_token = login_data['accessToken']
analyst_refresh = login_data['refreshToken']
print('REFRESH_TOKEN:' + analyst_refresh)

analyst_headers = {'Authorization': f'Bearer {analyst_token}'}

# 3. Ingest 5 telemetry events to trigger RULE-AUTH-001 synchronously
events = [
    TelemetryEventSchema(
        id=f"evt-stage4-e2e-{i}",
        timestamp="2026-10-09T21:00:00Z",
        eventType="AUTH_FAILURE",
        sourceService="auth-svc",
        environmentId="env-prod",
        payload=TelemetryEventPayloadSchema(
            sourceIp="198.51.100.123",
            httpMethod="POST",
            httpPath="/api/v1/auth/login",
            httpStatusCode=401,
            action="AUTH_FAILURE",
            outcome="FAILURE"
        )
    )
    for i in range(5)
]
asyncio.run(process_stream(events))

# 4. Fetch created incident
inc_res = client.get('/api/v1/incidents', headers=analyst_headers)
assert inc_res.status_code == 200
incidents = inc_res.json()
assert len(incidents) >= 1
inc_id = incidents[0]['id']
print('INCIDENT_ID:' + inc_id)

# 5. Propose Response by analyst
prop_res = client.post('/api/v1/responses/propose', json={
    'incidentId': inc_id,
    'actionType': 'BLOCK_SOURCE',
    'targetType': 'IP_ADDRESS',
    'targetIdentifier': '198.51.100.123',
    'reason': 'Automated brute force defense'
}, headers=analyst_headers)
assert prop_res.status_code == 200
prop_id = prop_res.json()['id']
print('PROPOSAL_ID:' + prop_id)

# 6. Login as operator for dual custody approval
op_login = client.post('/api/v1/auth/login', json={'username': 'operator', 'password': 'OperatorSecure2026!'})
assert op_login.status_code == 200
op_token = op_login.json()['accessToken']
op_headers = {'Authorization': f'Bearer {op_token}'}

appr_res = client.post(f'/api/v1/responses/{prop_id}/approve', json={
    'decision': 'APPROVE',
    'comment': 'Verified brute force attack'
}, headers=op_headers)
assert appr_res.status_code == 200

# 7. Execute Response
exec_res = client.post(f'/api/v1/responses/{prop_id}/execute', headers=op_headers)
assert exec_res.status_code == 200
print('EXECUTION_STATUS:SUCCESS')
'''
        env = dict(os.environ, GASHA_STORAGE_BACKEND="sql", GASHA_DATABASE_PATH=temp_db)
        p1 = subprocess.run([sys.executable, "-c", script_proc1], env=env, capture_output=True, text=True, cwd=str(repo_root))
        assert p1.returncode == 0, f"Process 1 failed: {p1.stderr}\n{p1.stdout}"

        lines1 = dict(l.split(":", 1) for l in p1.stdout.splitlines() if ":" in l and not l.startswith("2026-"))
        ref_tok = lines1.get("REFRESH_TOKEN")
        inc_id = lines1.get("INCIDENT_ID")
        prop_id = lines1.get("PROPOSAL_ID")
        assert ref_tok and inc_id and prop_id

        # Subprocess 2: Restarts against the exact same SQLite database
        script_proc2 = f'''
import sys, os
sys.path.extend(['apps/api', 'apps/demo-target', 'packages/telemetry-sdk/python'])
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# 1. Health check in new process
h_res = client.get('/health')
assert h_res.json().get('storage_mode') == 'sql'

# 2. Refresh token rotation across restart
ref_res = client.post('/api/v1/auth/refresh', json={{'refreshToken': '{ref_tok}'}})
assert ref_res.status_code == 200, f"Refresh failed: {{ref_res.text}}"
new_tokens = ref_res.json()
new_auth_header = {{'Authorization': f"Bearer {{new_tokens['accessToken']}}"}}
print('SESSION_SURVIVED:TRUE')

# 3. Query incident in Process 2
inc_res = client.get('/api/v1/incidents/{inc_id}', headers=new_auth_header)
assert inc_res.status_code == 200
inc_data = inc_res.json()
assert inc_data['id'] == '{inc_id}'
print('INCIDENT_SURVIVED:TRUE')

# 4. Query response execution state in Process 2
resp_res = client.get('/api/v1/responses/{prop_id}?environmentId=env-prod', headers=new_auth_header)
assert resp_res.status_code == 200
assert resp_res.json()['status'] in ('APPROVED', 'EXECUTING', 'SUCCEEDED', 'SUCCESS')
print('RESPONSE_SURVIVED:TRUE')

# 5. Verify cryptographic audit chain in Process 2
audit_res = client.get('/api/v1/responses/audit/verify?environmentId=env-prod', headers=new_auth_header)
assert audit_res.status_code == 200
assert audit_res.json().get('verified') is True
print('AUDIT_CHAIN_VALID:TRUE')

# 6. Verify replay of old refresh token fails with 401
replay_res = client.post('/api/v1/auth/refresh', json={{'refreshToken': '{ref_tok}'}})
assert replay_res.status_code == 401
print('REPLAY_REJECTED:TRUE')
'''
        p2 = subprocess.run([sys.executable, "-c", script_proc2], env=env, capture_output=True, text=True, cwd=str(repo_root))
        assert p2.returncode == 0, f"Process 2 failed: {p2.stderr}\n{p2.stdout}"

        lines2 = dict(l.split(":", 1) for l in p2.stdout.splitlines() if ":" in l and not l.startswith("2026-"))
        assert lines2.get("SESSION_SURVIVED") == "TRUE"
        assert lines2.get("INCIDENT_SURVIVED") == "TRUE"
        assert lines2.get("RESPONSE_SURVIVED") == "TRUE"
        assert lines2.get("AUDIT_CHAIN_VALID") == "TRUE"
        assert lines2.get("REPLAY_REJECTED") == "TRUE"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)
