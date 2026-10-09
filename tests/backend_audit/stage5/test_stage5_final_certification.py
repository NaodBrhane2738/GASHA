"""
==============================================================================
FILE: tests/backend_audit/stage5/test_stage5_final_certification.py
ROLE / OWNERSHIP: Final Acceptance & Security Certification
OBJECTIVE: Exhaustive Stage 5 acceptance verification covering:
           - SQLite live backup and restoration integrity (with SHA-256 audit chain validation)
           - Database corruption fail-closed behavior
           - Production crypto fail-closed configuration enforcement
           - Multi-tenant boundary isolation across SQL repositories
           - WebSocket single-worker ticket atomicity and process-local broadcast boundary
           - PostgreSQL / Supabase runtime configuration boundary verification
==============================================================================
"""

import os
import sys
import json
import time
import shutil
import sqlite3
import tempfile
import threading
from typing import Generator
import pytest

from app.db.sql_engine import (
    SQLDatabaseEngine,
    SQLIncidentRepository,
    SQLResponseRepository,
    SQLAuditTrail,
    SQLUserRepository,
    SQLAssetRepository,
    normalize_db_path
)
from app.api.realtime import (
    create_websocket_ticket,
    consume_websocket_ticket,
    ConnectionManager
)
from app.core.crypto import _derive_default_fernet_key
from app.core.config import settings


# ============================================================================
# 1. SQLITE LIVE BACKUP & RESTORATION INTEGRITY (AUDIT CHAIN VALIDATION)
# ============================================================================

def test_stage5_sqlite_backup_and_recovery_verification():
    """
    Verifies that a live SQLite database under WAL mode can be cleanly backed up,
    restored to a new location, and verified with all state intact, including
    the full cryptographic SHA-256 audit log chain.
    """
    f_orig = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f_orig.close()
    orig_path = f_orig.name

    f_bkp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f_bkp.close()
    bkp_path = f_bkp.name

    try:
        # Step 1: Initialize original database and insert state
        orig_engine = SQLDatabaseEngine(db_path=orig_path)
        audit_orig = SQLAuditTrail(engine=orig_engine)
        user_repo = SQLUserRepository(engine=orig_engine)
        inc_repo = SQLIncidentRepository(engine=orig_engine)
        resp_repo = SQLResponseRepository(engine=orig_engine)

        # Append audit events forming a 4-record cryptographic chain
        e1 = audit_orig.append_entry("env-prod", "PROPOSE", "analyst", "inc-101", "resp-101", "BLOCK_SOURCE", "198.51.100.42", "SUCCESS")
        e2 = audit_orig.append_entry("env-prod", "APPROVE", "operator", "inc-101", "resp-101", "BLOCK_SOURCE", "198.51.100.42", "SUCCESS")
        e3 = audit_orig.append_entry("env-prod", "EXECUTE", "system", "inc-101", "resp-101", "BLOCK_SOURCE", "198.51.100.42", "SUCCESS")
        e4 = audit_orig.append_entry("env-prod", "VERIFY", "probe-svc", "inc-101", "resp-101", "BLOCK_SOURCE", "198.51.100.42", "SUCCESS")

        verify_orig = audit_orig.verify_chain("env-prod")
        assert verify_orig.verified is True
        assert verify_orig.totalRecords == 4

        # Step 2: Execute live SQLite backup using sqlite3.Connection.backup API
        with orig_engine.get_connection() as src_conn:
            dst_conn = sqlite3.connect(bkp_path)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()

        # Step 3: Open restored database with a completely new engine instance
        restored_engine = SQLDatabaseEngine(db_path=bkp_path)
        audit_restored = SQLAuditTrail(engine=restored_engine)
        user_restored = SQLUserRepository(engine=restored_engine)

        # Verify seed users survived in restored DB
        users = user_restored.list_users()
        assert len(users) >= 4
        usernames = {u.username for u in users}
        assert "analyst" in usernames and "operator" in usernames

        # Verify cryptographic audit chain integrity in restored DB
        verify_restored = audit_restored.verify_chain("env-prod")
        assert verify_restored.verified is True
        assert verify_restored.totalRecords == 4
        assert verify_restored.latestHash == e4.recordHash

    finally:
        for p in [orig_path, bkp_path]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass


# ============================================================================
# 2. DATABASE CORRUPTION FAIL-CLOSED BEHAVIOR
# ============================================================================

def test_stage5_corrupted_database_fail_closed():
    """
    Verifies that corrupted SQLite database files fail closed with explicit
    database errors rather than silently ignoring corruption or falling back to memory.
    """
    f_corrupt = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f_corrupt.write(b"CORRUPTED_GARBAGE_DATA_NOT_A_VALID_SQLITE_FILE" * 50)
    f_corrupt.close()
    corrupt_path = f_corrupt.name

    try:
        # Connecting to a corrupt file must fail during DDL or query execution
        with pytest.raises((sqlite3.DatabaseError, sqlite3.OperationalError)):
            engine = SQLDatabaseEngine(db_path=corrupt_path)
    finally:
        if os.path.exists(corrupt_path):
            try:
                os.remove(corrupt_path)
            except Exception:
                pass


# ============================================================================
# 3. PRODUCTION CRYPTO CONFIGURATION FAIL-CLOSED ENFORCEMENT
# ============================================================================

def test_stage5_production_crypto_fail_closed_without_explicit_key():
    """
    Verifies that credential encryption fails closed with RuntimeError when
    CREDENTIAL_ENCRYPTION_KEY is unset in non-development/production environments.
    """
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = getattr(settings, "NODE_ENV", "")
    old_key = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", None)
    try:
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
        setattr(settings, "NODE_ENV", "production")
        os.environ["ENVIRONMENT"] = "production"

        with pytest.raises(RuntimeError, match="CREDENTIAL_ENCRYPTION_KEY must be configured"):
            _derive_default_fernet_key()

        # Staging must also fail closed
        setattr(settings, "NODE_ENV", "staging")
        os.environ["ENVIRONMENT"] = "staging"
        with pytest.raises(RuntimeError, match="CREDENTIAL_ENCRYPTION_KEY must be configured"):
            _derive_default_fernet_key()

    finally:
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_key)
        setattr(settings, "NODE_ENV", old_node_env)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)


# ============================================================================
# 4. MULTI-TENANT BOUNDARY ISOLATION ACROSS SQL REPOSITORIES
# ============================================================================

def test_stage5_cross_tenant_isolation_comprehensive_matrix():
    """
    Verifies that SQL repositories strictly partition data by environment_id:
    Operations performed for 'env-prod' are invisible to 'env-tenant-b'.
    """
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    temp_db = f.name

    try:
        engine = SQLDatabaseEngine(db_path=temp_db)
        audit = SQLAuditTrail(engine=engine)
        user_repo = SQLUserRepository(engine=engine)
        asset_repo = SQLAssetRepository(engine=engine)

        # Audit events in separate environments
        audit.append_entry("env-prod", "PROPOSE", "analyst_a", "inc-p1", "resp-p1", "BLOCK_SOURCE", "1.1.1.1", "SUCCESS")
        audit.append_entry("env-tenant-b", "PROPOSE", "analyst_b", "inc-b1", "resp-b1", "BLOCK_SOURCE", "2.2.2.2", "SUCCESS")

        res_prod = audit.verify_chain("env-prod")
        res_tenant_b = audit.verify_chain("env-tenant-b")
        assert res_prod.totalRecords == 1
        assert res_tenant_b.totalRecords == 1
        assert res_prod.latestHash != res_tenant_b.latestHash

        # User repositories
        all_users = user_repo.list_users()
        users_prod = [u for u in all_users if u.environmentId == "env-prod"]
        users_tenant_b = [u for u in all_users if u.environmentId == "env-tenant-b"]
        assert len(users_prod) >= 4
        assert len(users_tenant_b) >= 1
        prod_names = {u.username for u in users_prod}
        tenant_b_names = {u.username for u in users_tenant_b}
        assert "analyst" in prod_names
        assert "analyst_b" in tenant_b_names
        assert "analyst" not in tenant_b_names
        assert "analyst_b" not in prod_names

        # Asset isolation
        from app.schemas.asset import AssetBase
        a1 = asset_repo.upsert_asset(AssetBase(
            name="Prod-Service",
            type="SERVICE",
            criticality="TIER_1_HIGH",
            source="VERCEL",
            environmentId="env-prod"
        ))
        a2 = asset_repo.upsert_asset(AssetBase(
            name="TenantB-Service",
            type="SERVICE",
            criticality="TIER_2_MEDIUM",
            source="VERCEL",
            environmentId="env-tenant-b"
        ))

        prod_assets = asset_repo.list_assets("env-prod")
        tenant_b_assets = asset_repo.list_assets("env-tenant-b")
        assert any(a.name == "Prod-Service" for a in prod_assets)
        assert not any(a.name == "TenantB-Service" for a in prod_assets)
        assert any(a.name == "TenantB-Service" for a in tenant_b_assets)
        assert not any(a.name == "Prod-Service" for a in tenant_b_assets)

    finally:
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


# ============================================================================
# 5. WEBSOCKET SINGLE-WORKER BOUNDARY AND ATOMICITY
# ============================================================================

def test_stage5_websocket_single_worker_boundary_and_atomicity():
    """
    Verifies that WebSocket tickets are single-use, expire after TTL,
    and survive race conditions (exactly one thread consumes ticket).
    """
    # 1. Ticket expiration
    t_short = create_websocket_ticket("usr-1", "env-prod", expires_seconds=0)
    time.sleep(0.01)
    assert consume_websocket_ticket(t_short) is None

    # 2. Single-use consumption
    t_valid = create_websocket_ticket("usr-1", "env-prod", expires_seconds=30)
    first_res = consume_websocket_ticket(t_valid)
    assert first_res is not None
    assert first_res["userId"] == "usr-1"
    assert first_res["environmentId"] == "env-prod"
    # Second consumption must return None
    assert consume_websocket_ticket(t_valid) is None

    # 3. Concurrent ticket consumption race
    t_race = create_websocket_ticket("usr-race", "env-prod", expires_seconds=60)
    consumed_results = []
    lock = threading.Lock()

    def worker():
        res = consume_websocket_ticket(t_race)
        with lock:
            if res is not None:
                consumed_results.append(res)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one thread must have succeeded
    assert len(consumed_results) == 1
    assert consumed_results[0]["userId"] == "usr-race"


# ============================================================================
# 6. POSTGRESQL RUNTIME BOUNDARY VERIFICATION
# ============================================================================

def test_stage5_postgresql_static_runtime_boundary():
    """
    Verifies that the runtime SQLDatabaseEngine is strictly an SQLite engine,
    documenting the architectural boundary that PostgreSQL/Supabase requires
    a dedicated driver adapter not presently wired into sql_engine.py.
    """
    pg_url = "postgresql://gasha_admin:secret@localhost:5432/gasha_db"
    # normalize_db_path does not treat postgresql as sqlite protocol
    norm = normalize_db_path(pg_url)
    assert "postgresql:" in norm or "gasha_db" in norm

    # Connecting sqlite3 to a non-existent or remote postgresql path fails
    with pytest.raises((sqlite3.OperationalError, sqlite3.DatabaseError, OSError)):
        engine = SQLDatabaseEngine(db_path=norm)
