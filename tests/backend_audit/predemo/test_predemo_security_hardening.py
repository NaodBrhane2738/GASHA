"""
==============================================================================
FILE: tests/backend_audit/predemo/test_predemo_security_hardening.py
ROLE / OWNERSHIP: Cybersecurity Engineers
OBJECTIVE: Rigorous pre-demo regression verification covering:
           - Elimination of predictable default bootstrap credentials in production
           - Secure one-time administrator provisioning via GASHA_PROVISIONING_TOKEN
           - Prevention of provisioning token reuse and unauthorized privilege escalation
           - Role-based account creation boundaries (analysts/operators cannot create users)
           - Authenticated password changes with complexity enforcement and session revocation
           - Absence of password hashes and secrets in API responses
           - Production startup safeguards against missing/placeholder secrets and memory fallback
==============================================================================
"""

import os
import sys
import json
import base64
import secrets
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.core.config import settings
from app.core.security import hash_password
from app.schemas.user import UserRecord
from app.core.production_guard import (
    validate_password_complexity,
    validate_production_configuration,
    is_production_mode
)
from app.db.sql_engine import SQLDatabaseEngine, SQLUserRepository, reset_shared_engine
from app.db.storage_mode import resolve_storage_backend


# ============================================================================
# 1. PRODUCTION ELIMINATION OF HARDCODED CREDENTIALS
# ============================================================================

def test_production_mode_refuses_default_account_seeding():
    """
    Verifies that in production mode, SQLUserRepository strictly refuses to
    seed default accounts with known hardcoded passwords (e.g., AdminRoot2026!).
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_node_settings = getattr(settings, "NODE_ENV", "")
    try:
        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        setattr(settings, "NODE_ENV", "production")

        engine = SQLDatabaseEngine(db_path=temp_db)
        repo = SQLUserRepository(engine=engine)

        # In production, users table must be completely empty on initialization
        users = repo.list_users()
        assert len(users) == 0

        # Attempting to authenticate with known default credentials must fail
        assert repo.authenticate("admin", "AdminRoot2026!") is None
        assert repo.authenticate("analyst", "AnalystSecure2026!") is None
        assert repo.authenticate("breakglass", "EmergencyRoot2026!") is None

    finally:
        setattr(settings, "NODE_ENV", old_node_settings)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


# ============================================================================
# 2. SECURE ONE-TIME INITIAL ADMINISTRATOR PROVISIONING
# ============================================================================

def test_initial_administrator_provisioning_workflow_and_reuse_prevention():
    """
    Verifies the complete one-time administrative provisioning workflow in production:
    - Rejects invalid or missing provisioning tokens
    - Enforces password complexity rules
    - Provisions initial root administrator
    - Prevents reuse of provisioning token (returns 409 Conflict)
    - Verifies newly provisioned admin can authenticate and receive tokens
    - Confirms password hashes and provisioning tokens are never returned in responses
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    token_secret = "provision-token-super-secure-high-entropy-2026-xyz"
    old_prov_token = os.environ.get("GASHA_PROVISIONING_TOKEN")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")

    try:
        os.environ["GASHA_PROVISIONING_TOKEN"] = token_secret
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", "prod-jwt-secret-secure-high-entropy-minimum-32-chars-2026")
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"0" * 32).decode())
        setattr(settings, "INTERNAL_API_KEY", "prod-internal-key-for-test-2026-min-chars")
        reset_shared_engine()

        # In production mode, database initializes completely empty of users
        engine = SQLDatabaseEngine(db_path=temp_db)
        user_repo = SQLUserRepository(engine=engine)
        assert len(user_repo.list_users()) == 0

        app = create_app()
        client = TestClient(app)

        # Step 1: Attempt provisioning with invalid token -> 401 Unauthorized
        res_no_tok = client.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": "wrong-token-guess",
            "username": "rootadmin",
            "password": "ValidPassword2026!#"
        })
        assert res_no_tok.status_code == 401
        assert "Invalid provisioning token" in res_no_tok.json()["detail"]

        # Step 2: Attempt provisioning with weak password -> 400 Bad Request
        res_weak = client.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": token_secret,
            "username": "rootadmin",
            "password": "weak"
        })
        assert res_weak.status_code == 400
        assert "at least 12 characters" in res_weak.json()["detail"]

        # Step 3: Legitimate initial provisioning -> 200 OK
        res_ok = client.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": token_secret,
            "username": "rootadmin",
            "password": "SuperAdminSecure2026!#",
            "environmentId": "env-prod"
        })
        assert res_ok.status_code == 200
        admin_data = res_ok.json()
        assert admin_data["username"] == "rootadmin"
        assert admin_data["role"] == "admin"
        assert admin_data["environmentId"] == "env-prod"
        # Verify NO password hash or token in response
        assert "password" not in admin_data
        assert "passwordHash" not in admin_data
        assert "token" not in admin_data

        # Step 4: Attempt reusing the provisioning token -> 409 Conflict
        res_reuse = client.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": token_secret,
            "username": "anotheradmin",
            "password": "AnotherAdminSecure2026!#"
        })
        assert res_reuse.status_code == 409
        assert "already provisioned" in res_reuse.json()["detail"]

        # Step 5: Verify provisioned admin can log in and obtain bearer tokens
        login_res = client.post("/api/v1/auth/login", json={
            "username": "rootadmin",
            "password": "SuperAdminSecure2026!#"
        })
        assert login_res.status_code == 200
        tokens = login_res.json()
        assert "accessToken" in tokens
        assert tokens["role"] == "admin"

    finally:
        setattr(settings, "JWT_SECRET", old_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_enc)
        setattr(settings, "INTERNAL_API_KEY", old_int)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        setattr(settings, "NODE_ENV", old_node_env or "development")

        if old_prov_token:
            os.environ["GASHA_PROVISIONING_TOKEN"] = old_prov_token
        else:
            os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        if old_db:
            os.environ["GASHA_DATABASE_PATH"] = old_db
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)
        reset_shared_engine()
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


# ============================================================================
# 3. ROLE-BASED ACCOUNT PROVISIONING & PRIVILEGE ESCALATION PREVENTION
# ============================================================================

def test_account_creation_role_restrictions_and_privilege_escalation():
    """
    Verifies that:
    - Ordinary analysts and operators cannot create user accounts (HTTP 403)
    - Unauthenticated users cannot create accounts (HTTP 401)
    - Authenticated administrators can provision analysts and operators
    - Ordinary administrators cannot create emergency_admin accounts
    """
    app = create_app()
    client = TestClient(app)

    # Login as analyst
    analyst_login = client.post("/api/v1/auth/login", json={
        "username": "analyst",
        "password": "AnalystSecure2026!"
    })
    assert analyst_login.status_code == 200
    analyst_header = {"Authorization": f"Bearer {analyst_login.json()['accessToken']}"}

    # Login as admin
    admin_login = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "AdminRoot2026!"
    })
    assert admin_login.status_code == 200
    admin_header = {"Authorization": f"Bearer {admin_login.json()['accessToken']}"}

    # 1. Unauthenticated request to /api/v1/auth/users -> 401
    res_unauth = client.post("/api/v1/auth/users", json={
        "username": "rogue_user",
        "password": "RoguePassword2026!#",
        "role": "admin"
    })
    assert res_unauth.status_code == 401

    # 2. Analyst attempts to create user -> 403 Forbidden
    res_analyst = client.post("/api/v1/auth/users", json={
        "username": "escalated_user",
        "password": "EscalatedPassword2026!#",
        "role": "admin"
    }, headers=analyst_header)
    assert res_analyst.status_code == 403

    # 3. Admin attempts to create emergency_admin -> 403 Forbidden
    res_admin_emg = client.post("/api/v1/auth/users", json={
        "username": "new_breakglass",
        "password": "BreakglassPassword2026!#",
        "role": "emergency_admin"
    }, headers=admin_header)
    assert res_admin_emg.status_code == 403

    # 4. Admin creates legitimate operator account -> 200 OK
    res_created = client.post("/api/v1/auth/users", json={
        "username": "operator_junior",
        "password": "JuniorOperator2026!#",
        "role": "security_operator",
        "environmentId": "env-prod"
    }, headers=admin_header)
    assert res_created.status_code == 200
    created_user = res_created.json()
    assert created_user["username"] == "operator_junior"
    assert created_user["role"] == "security_operator"
    assert "password" not in created_user
    assert "passwordHash" not in created_user


# ============================================================================
# 4. AUTHENTICATED PASSWORD CHANGE & SESSION REVOCATION
# ============================================================================

def test_authenticated_password_change_and_session_revocation():
    """
    Verifies that:
    - User cannot change password with invalid old password (HTTP 401)
    - User cannot set weak password (HTTP 400)
    - Successful password change revokes existing refresh tokens
    - User can authenticate with the new password
    - User can no longer authenticate with the old password
    """
    app = create_app()
    client = TestClient(app)

    # 1. Login as admin to provision a dedicated test user for rotation testing
    admin_login = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "AdminRoot2026!"
    })
    assert admin_login.status_code == 200
    admin_header = {"Authorization": f"Bearer {admin_login.json()['accessToken']}"}

    create_res = client.post("/api/v1/auth/users", json={
        "username": "rotator_analyst",
        "password": "InitialRotatorPassword2026!#",
        "role": "security_analyst",
        "environmentId": "env-prod"
    }, headers=admin_header)
    assert create_res.status_code == 200

    # 2. Initial login as rotator_analyst
    login1 = client.post("/api/v1/auth/login", json={
        "username": "rotator_analyst",
        "password": "InitialRotatorPassword2026!#"
    })
    assert login1.status_code == 200
    token1 = login1.json()
    auth_header = {"Authorization": f"Bearer {token1['accessToken']}"}
    old_refresh = token1["refreshToken"]

    # 3. Invalid old password -> 401
    bad_old = client.post("/api/v1/auth/password/change", json={
        "oldPassword": "WrongCurrentPassword123!",
        "newPassword": "NewSecurePassword2026!#"
    }, headers=auth_header)
    assert bad_old.status_code == 401

    # 4. Weak new password -> 400
    weak_new = client.post("/api/v1/auth/password/change", json={
        "oldPassword": "InitialRotatorPassword2026!#",
        "newPassword": "short"
    }, headers=auth_header)
    assert weak_new.status_code == 400

    # 5. Legitimate password change -> 200
    change_ok = client.post("/api/v1/auth/password/change", json={
        "oldPassword": "InitialRotatorPassword2026!#",
        "newPassword": "RotatedSecurePassword2026!#"
    }, headers=auth_header)
    assert change_ok.status_code == 200

    # 6. Old refresh token must be invalidated (revoked) -> 401
    refresh_old = client.post("/api/v1/auth/refresh", json={"refreshToken": old_refresh})
    assert refresh_old.status_code == 401

    # 7. Old password cannot authenticate -> 401
    old_auth = client.post("/api/v1/auth/login", json={
        "username": "rotator_analyst",
        "password": "InitialRotatorPassword2026!#"
    })
    assert old_auth.status_code == 401

    # 8. New password authenticates successfully -> 200
    new_auth = client.post("/api/v1/auth/login", json={
        "username": "rotator_analyst",
        "password": "RotatedSecurePassword2026!#"
    })
    assert new_auth.status_code == 200


# ============================================================================
# 5. PRODUCTION CONFIGURATION SAFEGUARDS & FAIL-CLOSED CHECKS
# ============================================================================

def test_production_fails_closed_with_insecure_jwt_secret():
    """Verifies that production refuses to start with known placeholder or short JWT_SECRET."""
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    try:
        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        setattr(settings, "NODE_ENV", "production")

        # Test short secret (< 32 chars)
        setattr(settings, "JWT_SECRET", "too-short")
        with pytest.raises(RuntimeError, match="JWT_SECRET must be configured with at least 32 characters"):
            validate_production_configuration()

        # Test placeholder secret
        setattr(settings, "JWT_SECRET", "super-secret-jwt-key-change-in-production-min32chars")
        with pytest.raises(RuntimeError, match="known development placeholder"):
            validate_production_configuration()

    finally:
        setattr(settings, "NODE_ENV", old_node_env or "development")
        setattr(settings, "JWT_SECRET", old_jwt)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)


def test_production_fails_closed_with_missing_or_dependent_encryption_key():
    """Verifies that production requires an explicit Fernet key independent of JWT_SECRET."""
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    try:
        valid_jwt = "prod-jwt-secret-secure-high-entropy-minimum-32-chars-2026"
        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", valid_jwt)

        # 1. Missing encryption key -> RuntimeError
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
        with pytest.raises(RuntimeError, match="CREDENTIAL_ENCRYPTION_KEY must be configured"):
            validate_production_configuration()

        # 2. Key identical to JWT secret -> RuntimeError (must be independent)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", valid_jwt)
        with pytest.raises(RuntimeError, match="independent of JWT_SECRET"):
            validate_production_configuration()

        # 3. Malformed Fernet key (not 32 bytes base64) -> RuntimeError
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "not-a-valid-fernet-key")
        with pytest.raises(RuntimeError, match="not a valid 32-byte Fernet key"):
            validate_production_configuration()

    finally:
        setattr(settings, "NODE_ENV", old_node_env or "development")
        setattr(settings, "JWT_SECRET", old_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_enc)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)


def test_production_fails_closed_with_insecure_internal_api_key():
    """Verifies that production refuses to start with default internal API key placeholder."""
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    try:
        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", "prod-jwt-secret-secure-high-entropy-minimum-32-chars-2026")
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"0" * 32).decode())

        setattr(settings, "INTERNAL_API_KEY", "gasha-internal-service-key-change-me")
        with pytest.raises(RuntimeError, match="INTERNAL_API_KEY is using a known development placeholder"):
            validate_production_configuration()

    finally:
        setattr(settings, "NODE_ENV", old_node_env or "development")
        setattr(settings, "JWT_SECRET", old_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_enc)
        setattr(settings, "INTERNAL_API_KEY", old_int)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)


def test_production_fails_closed_with_memory_storage_backend():
    """Verifies that production refuses to run with memory storage backend."""
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    try:
        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "memory"
        setattr(settings, "NODE_ENV", "production")

        with pytest.raises(RuntimeError, match="requires durable 'sql' storage backend"):
            resolve_storage_backend()

    finally:
        setattr(settings, "NODE_ENV", old_node_env or "development")
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)


# ============================================================================
# 6. UNPROVISIONED PRODUCTION & RACE CONDITION CONCURRENCY SAFEGUARDS
# ============================================================================

def test_unprovisioned_production_fails_closed_without_provisioning_token():
    """
    Verifies that when production is unprovisioned, startup strictly requires
    a valid GASHA_PROVISIONING_TOKEN of at least 32 characters, and rejects
    missing, short, or placeholder tokens.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_prov = os.environ.get("GASHA_PROVISIONING_TOKEN")

    try:
        valid_jwt = "prod-jwt-secret-secure-high-entropy-minimum-32-chars-2026"
        valid_enc = base64.urlsafe_b64encode(b"1" * 32).decode()
        valid_int = "prod-internal-key-secure-high-entropy-min-32-chars-2026"

        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", valid_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", valid_enc)
        setattr(settings, "INTERNAL_API_KEY", valid_int)
        reset_shared_engine()

        # 1. Token missing -> fails closed
        os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        setattr(settings, "PROVISIONING_TOKEN", None)
        with pytest.raises(RuntimeError, match="GASHA_PROVISIONING_TOKEN must be configured with at least 32 characters"):
            validate_production_configuration()

        # 2. Token too short -> fails closed
        os.environ["GASHA_PROVISIONING_TOKEN"] = "short-token"
        with pytest.raises(RuntimeError, match="GASHA_PROVISIONING_TOKEN must be configured with at least 32 characters"):
            validate_production_configuration()

        # 3. Token is a placeholder -> fails closed
        os.environ["GASHA_PROVISIONING_TOKEN"] = "placeholder-provisioning-token-change-me-32chars"
        with pytest.raises(RuntimeError, match="known development placeholder"):
            validate_production_configuration()

        # 4. High-entropy token provided -> passes validation
        secure_token = secrets.token_hex(32)
        os.environ["GASHA_PROVISIONING_TOKEN"] = secure_token
        validate_production_configuration()

    finally:
        setattr(settings, "NODE_ENV", old_node_env or "development")
        setattr(settings, "JWT_SECRET", old_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_enc)
        setattr(settings, "INTERNAL_API_KEY", old_int)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)
        if old_db:
            os.environ["GASHA_DATABASE_PATH"] = old_db
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)
        if old_prov:
            os.environ["GASHA_PROVISIONING_TOKEN"] = old_prov
        else:
            os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        reset_shared_engine()
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


def test_already_provisioned_production_succeeds_without_provisioning_token():
    """
    Verifies that once a production database is provisioned, the initial provisioning
    token can safely be retired/unset, and production startup succeeds normally.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_prov = os.environ.get("GASHA_PROVISIONING_TOKEN")

    try:
        valid_jwt = "prod-jwt-secret-secure-high-entropy-minimum-32-chars-2026"
        valid_enc = base64.urlsafe_b64encode(b"2" * 32).decode()
        valid_int = "prod-internal-key-secure-high-entropy-min-32-chars-2026"

        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", valid_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", valid_enc)
        setattr(settings, "INTERNAL_API_KEY", valid_int)
        reset_shared_engine()

        # Seed an admin user and bootstrap record into temp_db
        engine = SQLDatabaseEngine(db_path=temp_db)
        repo = SQLUserRepository(engine=engine)
        admin_u = UserRecord(
            id="usr-existing-admin",
            username="existingadmin",
            passwordHash=hash_password("ExistingAdminPass2026!#"),
            role="admin",
            environmentId="env-prod",
            isActive=True,
            createdAt="2026-10-10T00:00:00Z",
            updatedAt="2026-10-10T00:00:00Z"
        )
        repo.provision_initial_admin("dummy-token-hash-already-used", admin_u)
        assert repo.is_system_provisioned() is True

        # Unset GASHA_PROVISIONING_TOKEN
        os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        setattr(settings, "PROVISIONING_TOKEN", None)

        # Startup validation MUST succeed without requiring the retired bootstrap token
        validate_production_configuration()

    finally:
        setattr(settings, "NODE_ENV", old_node_env or "development")
        setattr(settings, "JWT_SECRET", old_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_enc)
        setattr(settings, "INTERNAL_API_KEY", old_int)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)
        if old_db:
            os.environ["GASHA_DATABASE_PATH"] = old_db
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)
        if old_prov:
            os.environ["GASHA_PROVISIONING_TOKEN"] = old_prov
        else:
            os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        reset_shared_engine()
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


def test_provisioning_concurrency_race_condition_rejected():
    """
    Verifies that under concurrent racing provisioning requests, exactly one request
    succeeds (HTTP 200) and all other racing requests receive HTTP 409 Conflict.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_prov = os.environ.get("GASHA_PROVISIONING_TOKEN")

    try:
        valid_jwt = "prod-jwt-secret-secure-high-entropy-minimum-32-chars-2026"
        valid_enc = base64.urlsafe_b64encode(b"3" * 32).decode()
        valid_int = "prod-internal-key-secure-high-entropy-min-32-chars-2026"
        token_secret = secrets.token_hex(32)

        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        os.environ["GASHA_PROVISIONING_TOKEN"] = token_secret
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", valid_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", valid_enc)
        setattr(settings, "INTERNAL_API_KEY", valid_int)
        reset_shared_engine()

        app = create_app()
        client = TestClient(app)

        from concurrent.futures import ThreadPoolExecutor

        def attempt_provision(idx):
            return client.post("/api/v1/auth/provision-admin", json={
                "provisioningToken": token_secret,
                "username": f"admin_race_{idx}",
                "password": f"RaceAdminPass{idx}2026!#",
                "environmentId": "env-prod"
            })

        with ThreadPoolExecutor(max_workers=10) as executor:
            responses = list(executor.map(attempt_provision, range(10)))

        statuses = [r.status_code for r in responses]
        success_count = statuses.count(200)
        conflict_count = statuses.count(409)

        # Exactly ONE request must succeed; all others must be 409 Conflict
        assert success_count == 1, f"Expected exactly 1 success, got {success_count}. Statuses: {statuses}"
        assert conflict_count == 9, f"Expected 9 conflicts, got {conflict_count}. Statuses: {statuses}"

        # Verify database holds only 1 user and 1 bootstrap record
        engine = SQLDatabaseEngine(db_path=temp_db)
        repo = SQLUserRepository(engine=engine)
        users = repo.list_users()
        assert len(users) == 1
        assert users[0].role == "admin"

    finally:
        setattr(settings, "NODE_ENV", old_node_env or "development")
        setattr(settings, "JWT_SECRET", old_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_enc)
        setattr(settings, "INTERNAL_API_KEY", old_int)
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)
        if old_db:
            os.environ["GASHA_DATABASE_PATH"] = old_db
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)
        if old_prov:
            os.environ["GASHA_PROVISIONING_TOKEN"] = old_prov
        else:
            os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        reset_shared_engine()
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


def test_default_network_launch_binds_to_loopback_only():
    """
    Verifies that the default API_HOST setting binds to 127.0.0.1 (loopback),
    preventing unintended exposure on all network interfaces (0.0.0.0).
    """
    assert settings.API_HOST == "127.0.0.1"
    assert settings.API_HOST != "0.0.0.0"


def test_no_hardcoded_example_passwords_or_runbook_secrets_allowed():
    """
    Verifies that known documented example credentials and insecure defaults
    are strictly rejected by password complexity validation.
    """
    blacklisted_examples = [
        "DemoAdminSecure2026!#",
        "DemoAnalystSecure2026!#",
        "DemoOperatorSecure2026!#",
        "AdminRoot2026!",
        "AnalystSecure2026!",
        "OperatorSecure2026!",
        "EmergencyRoot2026!",
        "TenantBSecure2026!"
    ]
    for bad_pwd in blacklisted_examples:
        with pytest.raises(ValueError, match="known insecure default credential"):
            validate_password_complexity(bad_pwd)

    # Verify dynamically generated password with high entropy and required classes passes
    valid_random_pwd = "X9#mK$2vL!pQ7@wZ"
    validate_password_complexity(valid_random_pwd)


def test_trusted_reverse_proxy_header_enforcement():
    """
    Verifies that the proxy security layer only honors X-Forwarded-For headers
    from explicit trusted proxies, ignoring spoofed headers from direct untrusted clients.
    """
    from security.middleware import SecurityEnforcementMiddleware
    from starlette.requests import Request

    class DummyApp:
        async def __call__(self, scope, receive, send):
            pass

    middleware = SecurityEnforcementMiddleware(DummyApp(), trusted_proxies=["127.0.0.1", "::1"])

    # 1. Untrusted connecting peer attempting to spoof X-Forwarded-For
    scope_untrusted = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": [
            (b"x-forwarded-for", b"203.0.113.195"),
            (b"host", b"localhost")
        ],
        "client": ("198.51.100.5", 12345)
    }
    req_untrusted = Request(scope_untrusted)
    extracted_untrusted = middleware._resolve_client_ip(req_untrusted)
    assert extracted_untrusted == "198.51.100.5", "Must ignore X-Forwarded-For from untrusted peer"

    # 2. Trusted proxy connecting peer forwarding client IP
    scope_trusted = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": [
            (b"x-forwarded-for", b"203.0.113.195"),
            (b"host", b"localhost")
        ],
        "client": ("127.0.0.1", 12345)
    }
    req_trusted = Request(scope_trusted)
    extracted_trusted = middleware._resolve_client_ip(req_trusted)
    assert extracted_trusted == "203.0.113.195", "Must accept X-Forwarded-For from trusted proxy peer"

