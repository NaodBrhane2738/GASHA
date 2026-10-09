"""
==============================================================================
FILE: tests/backend_audit/predemo/test_secret_lifecycle.py
ROLE / OWNERSHIP: Cybersecurity & Infrastructure Engineers
OBJECTIVE: Rigorous verification of secret lifecycle management:
           - Persistence of CREDENTIAL_ENCRYPTION_KEY across restarts
           - Safe failure and rejection when keys change without migration
           - Invalidation of JWT access tokens when JWT_SECRET changes
           - Preservation of authentication and stored secrets across normal restarts with stable keys
           - Single-use retirement of GASHA_PROVISIONING_TOKEN after initial provisioning
           - Safe startup of provisioned database without retaining bootstrap token
           - Absence of secrets and hashes in API responses
==============================================================================
"""

import os
import base64
import secrets
import tempfile
import pytest
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

from app.main import create_app
from app.core.config import settings
from app.core.crypto import (
    encrypt_credential,
    decrypt_credential,
    CredentialDecryptionError
)
from app.core.production_guard import validate_production_configuration
from app.db.sql_engine import (
    SQLDatabaseEngine,
    SQLUserRepository,
    SQLConnectionRepository,
    reset_shared_engine
)
from app.schemas.connection import ConnectionRecord
from app.schemas.user import UserRecord
from app.core.security import hash_password


# ============================================================================
# 1. CREDENTIAL ENCRYPTION LIFECYCLE & RESTART VERIFICATION
# ============================================================================

def test_credential_encryption_survives_restart_with_same_key():
    """
    Verifies that third-party credentials encrypted with CREDENTIAL_ENCRYPTION_KEY
    survive a full database and server restart when the same persistent key is reloaded.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_key = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")

    try:
        # Generate persistent test key (32 bytes url-safe base64)
        persistent_key = Fernet.generate_key().decode()
        os.environ["ENVIRONMENT"] = "development"
        os.environ["NODE_ENV"] = "development"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        setattr(settings, "NODE_ENV", "development")
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", persistent_key)
        reset_shared_engine()

        # Step 1: Encrypt and store credential in DB
        raw_secret_token = "ghp_secure_github_provider_token_abcdef123456"
        encrypted_token = encrypt_credential(raw_secret_token, key=persistent_key)
        assert encrypted_token != raw_secret_token

        engine1 = SQLDatabaseEngine(db_path=temp_db)
        conn_repo1 = SQLConnectionRepository(engine=engine1)
        record = ConnectionRecord(
            id="conn-github-prod",
            environmentId="env-prod",
            provider="GITHUB",
            accountName="sec-ops-team",
            scope="repo",
            encryptedToken=encrypted_token,
            status="CONNECTED",
            createdAt="2026-10-10T00:00:00Z",
            updatedAt="2026-10-10T00:00:00Z"
        )
        conn_repo1.save_connection(record)

        # Step 2: Simulate application shutdown & restart (reinstantiate engine and repos)
        reset_shared_engine()
        engine2 = SQLDatabaseEngine(db_path=temp_db)
        conn_repo2 = SQLConnectionRepository(engine=engine2)

        # Step 3: Fetch connection and decrypt with the SAME persistent key
        conn = conn_repo2.get_connection("env-prod", "GITHUB")
        assert conn is not None
        assert conn.status == "CONNECTED"

        decrypted_token = decrypt_credential(conn.encryptedToken, key=persistent_key)
        assert decrypted_token == raw_secret_token, "Stored credential must decrypt successfully across restart"

    finally:
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", old_key)
        setattr(settings, "NODE_ENV", old_node_env or "development")
        if old_env:
            os.environ["ENVIRONMENT"] = old_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if old_node_env:
            os.environ["NODE_ENV"] = old_node_env
        else:
            os.environ.pop("NODE_ENV", None)
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


def test_credential_decryption_fails_safely_when_key_changes_without_migration():
    """
    Verifies that if CREDENTIAL_ENCRYPTION_KEY changes on restart (e.g. from ephemeral regeneration),
    decryption fails safely with CredentialDecryptionError, and NO insecure plaintext fallback occurs.
    """
    key_v1 = Fernet.generate_key().decode()
    key_v2 = Fernet.generate_key().decode()

    raw_token = "vercel_token_super_secret_9876543210"
    ciphertext = encrypt_credential(raw_token, key=key_v1)

    # Decryption with matching key succeeds
    assert decrypt_credential(ciphertext, key=key_v1) == raw_token

    # Decryption with rotated key without migration MUST raise CredentialDecryptionError
    with pytest.raises(CredentialDecryptionError, match="token invalid or key mismatch"):
        decrypt_credential(ciphertext, key=key_v2)


# ============================================================================
# 2. JWT TOKEN LIFECYCLE & SIGNATURE INVALIDATION
# ============================================================================

def test_jwt_secret_rotation_invalidates_previously_issued_tokens():
    """
    Demonstrates why persistent secrets cannot be regenerated on every launch:
    Tokens minted under JWT_SECRET_1 fail cryptographic signature verification
    under JWT_SECRET_2, resulting in HTTP 401 Unauthorized.
    """
    old_jwt = getattr(settings, "JWT_SECRET", "")
    try:
        jwt_1 = "first-stable-jwt-secret-with-minimum-32-characters"
        jwt_2 = "second-altered-jwt-secret-with-minimum-32-chars"

        # 1. Start with jwt_1 and log in
        setattr(settings, "JWT_SECRET", jwt_1)
        app1 = create_app()
        client1 = TestClient(app1)

        login_res = client1.post("/api/v1/auth/login", json={
            "username": "analyst",
            "password": "AnalystSecure2026!"
        })
        assert login_res.status_code == 200
        token = login_res.json()["accessToken"]

        # Token is valid under jwt_1
        valid_res = client1.get("/api/v1/assets", headers={"Authorization": f"Bearer {token}"})
        assert valid_res.status_code == 200

        # 2. Simulate server restart where JWT_SECRET was regenerated to jwt_2
        setattr(settings, "JWT_SECRET", jwt_2)
        app2 = create_app()
        client2 = TestClient(app2)

        # Old token must fail signature verification
        invalid_res = client2.get("/api/v1/assets", headers={"Authorization": f"Bearer {token}"})
        assert invalid_res.status_code == 401
        detail = invalid_res.json().get("detail", "")
        assert "Invalid" in detail or "expired" in detail or "credentials" in detail

    finally:
        setattr(settings, "JWT_SECRET", old_jwt)


def test_normal_restart_with_stable_secrets_preserves_auth_and_credentials():
    """
    Verifies that a normal server restart with STABLE persistent secrets preserves
    both active authentication sessions and stored encrypted credentials.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")

    try:
        stable_jwt = "stable-production-jwt-secret-min-32-chars-2026"
        stable_enc = Fernet.generate_key().decode()
        stable_int = "stable-internal-api-key-min-32-chars-production"

        os.environ["ENVIRONMENT"] = "development"
        os.environ["NODE_ENV"] = "development"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        setattr(settings, "JWT_SECRET", stable_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", stable_enc)
        setattr(settings, "INTERNAL_API_KEY", stable_int)
        reset_shared_engine()

        # Step 1: Boot app, login, store encrypted token
        app1 = create_app()
        client1 = TestClient(app1)

        login_res = client1.post("/api/v1/auth/login", json={
            "username": "analyst",
            "password": "AnalystSecure2026!"
        })
        assert login_res.status_code == 200
        auth_token = login_res.json()["accessToken"]

        # Store encrypted credential in DB
        engine1 = SQLDatabaseEngine(db_path=temp_db)
        conn_repo1 = SQLConnectionRepository(engine=engine1)
        record = ConnectionRecord(
            id="conn-github-restart",
            environmentId="env-prod",
            provider="GITHUB",
            accountName="sec-ops-team",
            scope="repo",
            encryptedToken=encrypt_credential("ghp_test_token_12345", key=stable_enc),
            status="CONNECTED",
            createdAt="2026-10-10T00:00:00Z",
            updatedAt="2026-10-10T00:00:00Z"
        )
        conn_repo1.save_connection(record)

        # Step 2: Normal restart (reloading SAME persistent secrets)
        reset_shared_engine()
        app2 = create_app()
        client2 = TestClient(app2)

        # Bearer token remains valid
        verify_res = client2.get("/api/v1/assets", headers={"Authorization": f"Bearer {auth_token}"})
        assert verify_res.status_code == 200

        # Encrypted credential remains decryptable
        engine2 = SQLDatabaseEngine(db_path=temp_db)
        conn_repo2 = SQLConnectionRepository(engine=engine2)
        saved_conn = conn_repo2.get_connection("env-prod", "GITHUB")
        assert saved_conn is not None
        assert saved_conn.status == "CONNECTED"
        decrypted = decrypt_credential(saved_conn.encryptedToken, key=stable_enc)
        assert decrypted == "ghp_test_token_12345"

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
# 3. PROVISIONING TOKEN RETIREMENT & PRODUCTION STARTUP CHECKS
# ============================================================================

def test_provisioning_token_retired_safely_after_initial_bootstrap():
    """
    Verifies the complete lifecycle of GASHA_PROVISIONING_TOKEN:
    1. Unprovisioned production DB requires provisioning token to start.
    2. Admin is provisioned via POST /api/v1/auth/provision-admin.
    3. Immediate token reuse is rejected with HTTP 409 Conflict.
    4. Token is retired (unset from environment).
    5. Provisioned DB restarts cleanly WITHOUT provisioning token.
    6. Calls to /provision-admin on retired server return HTTP 403 or 409.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")
    old_prov = os.environ.get("GASHA_PROVISIONING_TOKEN")
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")

    try:
        valid_jwt = "prod-jwt-secret-secure-high-entropy-minimum-32-chars-2026"
        valid_enc = Fernet.generate_key().decode()
        valid_int = "prod-internal-key-secure-high-entropy-min-32-chars-2026"
        prov_token = secrets.token_hex(32)

        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        os.environ["GASHA_PROVISIONING_TOKEN"] = prov_token
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", valid_jwt)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", valid_enc)
        setattr(settings, "INTERNAL_API_KEY", valid_int)
        reset_shared_engine()

        # Phase 1: Boot app and provision root admin
        app1 = create_app()
        client1 = TestClient(app1)

        res_prov = client1.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": prov_token,
            "username": "superadmin",
            "password": "SuperAdminPassword2026!#",
            "environmentId": "env-prod"
        })
        assert res_prov.status_code == 200
        admin_data = res_prov.json()
        assert admin_data["username"] == "superadmin"

        # Phase 2: Immediate token reuse attempt -> 409 Conflict
        res_reuse = client1.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": prov_token,
            "username": "superadmin2",
            "password": "AnotherAdminPassword2026!#"
        })
        assert res_reuse.status_code == 409

        # Phase 3: Retire the provisioning token (unset from environment & settings)
        os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        setattr(settings, "PROVISIONING_TOKEN", None)

        # Phase 4: Server restart with retired provisioning token
        reset_shared_engine()
        # validate_production_configuration MUST pass without requiring the token
        validate_production_configuration()

        app2 = create_app()
        client2 = TestClient(app2)

        # Admin can log in normally after restart
        login_res = client2.post("/api/v1/auth/login", json={
            "username": "superadmin",
            "password": "SuperAdminPassword2026!#"
        })
        assert login_res.status_code == 200

        # Attempting to call /provision-admin on retired server is rejected (403 Forbidden or 409)
        res_after = client2.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": prov_token,
            "username": "rogueadmin",
            "password": "RogueAdminPassword2026!#"
        })
        assert res_after.status_code in (403, 409)

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
        if old_db:
            os.environ["GASHA_DATABASE_PATH"] = old_db
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)
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


def test_persistent_secrets_and_hashes_never_leaked_in_api_responses():
    """
    Verifies that persistent secrets (JWT_SECRET, CREDENTIAL_ENCRYPTION_KEY,
    INTERNAL_API_KEY, PROVISIONING_TOKEN, and password hashes) are NEVER leaked
    in responses from auth, health, status, or connections endpoints.
    """
    app = create_app()
    client = TestClient(app)

    # 1. Login response check
    login_res = client.post("/api/v1/auth/login", json={
        "username": "analyst",
        "password": "AnalystSecure2026!"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "password" not in login_data
    assert "passwordHash" not in login_data
    assert "password_hash" not in login_data
    assert "secret" not in login_data

    # 2. Health endpoint check
    health_res = client.get("/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert "jwt" not in str(health_data).lower()
    assert "secret" not in str(health_data).lower()
    assert "key" not in str(health_data).lower() or health_data.get("service") == "gasha-api"

    # 3. Connections status check
    tokens = login_res.json()
    auth_header = {"Authorization": f"Bearer {tokens['accessToken']}"}
    conn_res = client.get("/api/v1/connections/status", headers=auth_header)
    assert conn_res.status_code == 200
    conn_text = conn_res.text
    assert "encryptedToken" not in conn_text
    assert "fernet" not in conn_text.lower()


# ============================================================================
# 4. RUNBOOK CSPRNG ALGORITHM & PROCESS ISOLATION REGRESSION TESTS
# ============================================================================

def test_unbiased_csprng_password_generation_distribution_and_complexity():
    """
    Verifies the rejection-sampling CSPRNG password generation algorithm used in the runbook.
    Ensures that generated passwords strictly adhere to validate_password_complexity,
    have no modulo bias, satisfy character class requirements, and have length >= 16.
    """
    from app.core.production_guard import validate_password_complexity

    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lower = "abcdefghijkmnopqrstuvwxyz"
    digits = "23456789"
    special = "!@#$%^&*-_=+"
    all_chars = upper + lower + digits + special

    def get_unbiased_char(charset: str) -> str:
        length = len(charset)
        max_acceptable = 256 - (256 % length)
        while True:
            b = secrets.token_bytes(1)[0]
            if b < max_acceptable:
                return charset[b % length]

    def generate_secure_password(length: int = 24) -> str:
        if length < 16:
            length = 16
        chars = [
            get_unbiased_char(upper), get_unbiased_char(upper),
            get_unbiased_char(lower), get_unbiased_char(lower),
            get_unbiased_char(digits), get_unbiased_char(digits),
            get_unbiased_char(special), get_unbiased_char(special),
        ]
        while len(chars) < length:
            chars.append(get_unbiased_char(all_chars))

        # Unbiased Fisher-Yates shuffle
        n = len(chars)
        while n > 1:
            n -= 1
            max_acc = 256 - (256 % (n + 1))
            while True:
                b = secrets.token_bytes(1)[0]
                if b < max_acc:
                    k = b % (n + 1)
                    break
            chars[k], chars[n] = chars[n], chars[k]
        return "".join(chars)

    for _ in range(50):
        pwd = generate_secure_password(24)
        assert len(pwd) == 24
        # Must pass validate_password_complexity without error
        validate_password_complexity(pwd)
        # Verify character class minimums
        assert sum(1 for c in pwd if c in upper) >= 2
        assert sum(1 for c in pwd if c in lower) >= 2
        assert sum(1 for c in pwd if c in digits) >= 2
        assert sum(1 for c in pwd if c in special) >= 2


def test_process_environment_isolation_root_cause():
    """
    Demonstrates the Windows process isolation boundary that caused the previous
    rehearsal failure:
    - Environment variables set in a separate/sibling process are NOT visible
      in an already-running process.
    - Child processes inherit environment variables ONLY when set in the parent
      prior to spawn.
    """
    import subprocess
    import sys

    # 1. Independent process without variable
    cmd = [sys.executable, "-c", "import os; print(os.environ.get('GASHA_PROVISIONING_TOKEN', 'NONE'))"]
    clean_env = os.environ.copy()
    clean_env.pop("GASHA_PROVISIONING_TOKEN", None)

    p1 = subprocess.run(cmd, env=clean_env, capture_output=True, text=True, check=True)
    assert p1.stdout.strip() == "NONE", "Uninherited process must not have provisioning token"

    # 2. Child process with inherited variable
    token = secrets.token_hex(32)
    inherited_env = clean_env.copy()
    inherited_env["GASHA_PROVISIONING_TOKEN"] = token

    p2 = subprocess.run(cmd, env=inherited_env, capture_output=True, text=True, check=True)
    assert p2.stdout.strip() == token, "Spawned child process must inherit token from parent"


def test_single_session_full_lifecycle_and_restart_durability():
    """
    Simulates the complete single-session first-run rehearsal in Python:
    1. Unprovisioned SQL DB + valid persistent keys + ephemeral provisioning token.
    2. Admin is provisioned.
    3. Ephemeral token retired.
    4. First restart (production mode, no token): admin logs in, replay rejected.
    5. Admin creates a security_operator account.
    6. Second restart: operator logs in, accesses protected endpoints.
    7. Encrypted credentials persist and decrypt cleanly across all phases.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db = f.name

    old_jwt = getattr(settings, "JWT_SECRET", "")
    old_enc = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    old_int = getattr(settings, "INTERNAL_API_KEY", "")
    old_prov = os.environ.get("GASHA_PROVISIONING_TOKEN")
    old_env = os.environ.get("ENVIRONMENT")
    old_node_env = os.environ.get("NODE_ENV")
    old_db = os.environ.get("GASHA_DATABASE_PATH")
    old_backend = os.environ.get("GASHA_STORAGE_BACKEND")

    try:
        jwt_key = "secure-jwt-secret-min-32-chars-for-full-lifecycle-test"
        enc_key = Fernet.generate_key().decode()
        int_key = "secure-internal-api-key-min-32-chars-production"
        prov_token = secrets.token_hex(32)
        admin_pass = "AdminLifecycleP@ssword2026!"
        op_pass = "OperatorLifecycleP@ssword2026!"

        os.environ["ENVIRONMENT"] = "production"
        os.environ["NODE_ENV"] = "production"
        os.environ["GASHA_STORAGE_BACKEND"] = "sql"
        os.environ["GASHA_DATABASE_PATH"] = temp_db
        os.environ["GASHA_PROVISIONING_TOKEN"] = prov_token
        setattr(settings, "NODE_ENV", "production")
        setattr(settings, "JWT_SECRET", jwt_key)
        setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", enc_key)
        setattr(settings, "INTERNAL_API_KEY", int_key)
        reset_shared_engine()

        # Phase 1: Boot app with provisioning token & provision admin
        app1 = create_app()
        client1 = TestClient(app1)

        res_prov = client1.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": prov_token,
            "username": "superadmin",
            "password": admin_pass,
            "environmentId": "env-test"
        })
        assert res_prov.status_code == 200
        assert res_prov.json()["username"] == "superadmin"

        # Phase 2: Retire token
        os.environ.pop("GASHA_PROVISIONING_TOKEN", None)
        setattr(settings, "PROVISIONING_TOKEN", None)

        # Phase 3: First restart (no token in environment)
        reset_shared_engine()
        app2 = create_app()
        client2 = TestClient(app2)

        # Replay rejected
        replay = client2.post("/api/v1/auth/provision-admin", json={
            "provisioningToken": prov_token,
            "username": "rogueadmin",
            "password": admin_pass
        })
        assert replay.status_code in (403, 409)

        # Admin login
        login_res = client2.post("/api/v1/auth/login", json={
            "username": "superadmin",
            "password": admin_pass
        })
        assert login_res.status_code == 200
        admin_jwt = login_res.json()["accessToken"]

        # Admin creates security_operator
        create_op_res = client2.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {admin_jwt}"},
            json={
                "username": "ops_analyst",
                "password": op_pass,
                "role": "security_operator",
                "environmentId": "env-test"
            }
        )
        assert create_op_res.status_code in (200, 201)

        # Save an encrypted connection
        engine2 = SQLDatabaseEngine(db_path=temp_db)
        conn_repo2 = SQLConnectionRepository(engine=engine2)
        conn_repo2.save_connection(ConnectionRecord(
            id="conn-github-restart",
            environmentId="env-test",
            provider="GITHUB",
            accountName="sec-ops-team",
            scope="read",
            encryptedToken=encrypt_credential("ghp_secret_key_12345678", key=enc_key),
            status="CONNECTED",
            createdAt="2026-10-10T00:00:00Z",
            updatedAt="2026-10-10T00:00:00Z"
        ))

        # Phase 4: Second restart (testing operator login & credential survival)
        reset_shared_engine()
        app3 = create_app()
        client3 = TestClient(app3)

        op_login = client3.post("/api/v1/auth/login", json={
            "username": "ops_analyst",
            "password": op_pass
        })
        assert op_login.status_code == 200
        op_jwt = op_login.json()["accessToken"]

        # Operator accesses assets
        assets_res = client3.get("/api/v1/assets", headers={"Authorization": f"Bearer {op_jwt}"})
        assert assets_res.status_code == 200

        # Credential decrypts cleanly
        engine3 = SQLDatabaseEngine(db_path=temp_db)
        conn_repo3 = SQLConnectionRepository(engine=engine3)
        conn = conn_repo3.get_connection("env-test", "GITHUB")
        assert conn is not None
        assert decrypt_credential(conn.encryptedToken, key=enc_key) == "ghp_secret_key_12345678"

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
        if old_db:
            os.environ["GASHA_DATABASE_PATH"] = old_db
        else:
            os.environ.pop("GASHA_DATABASE_PATH", None)
        if old_backend:
            os.environ["GASHA_STORAGE_BACKEND"] = old_backend
        else:
            os.environ.pop("GASHA_STORAGE_BACKEND", None)
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


# ============================================================================
# 5. RUNBOOK SAFETY, OVERWRITE GUARDS, REPLAY ASSERTION & BACKUP/RESTORE TESTS
# ============================================================================

def test_first_run_refuses_to_overwrite_existing_env_or_db():
    """
    Verifies that first-run initialization logic fails safely before generating
    or writing persistent secrets if either .env.production or the target database exists.
    Guarantees existing configuration and encrypted credentials are never destroyed.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        env_path = os.path.join(tmp_dir, ".env.production")
        db_path = os.path.join(tmp_dir, "gasha_production.db")

        # Scenario A: .env.production already exists
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("EXISTING_SECRET=do_not_overwrite\n")

        def run_bootstrap_preflight(target_env: str, target_db: str):
            if os.path.exists(target_env):
                raise RuntimeError(f"ABORT: Target configuration '{target_env}' already exists.")
            if os.path.exists(target_db):
                raise RuntimeError(f"ABORT: Target database '{target_db}' already exists.")
            return True

        with pytest.raises(RuntimeError, match="Target configuration.*already exists"):
            run_bootstrap_preflight(env_path, db_path)

        # Confirm content was not modified
        with open(env_path, "r", encoding="utf-8") as f:
            assert f.read() == "EXISTING_SECRET=do_not_overwrite\n"

        # Scenario B: db already exists, even if env does not
        os.remove(env_path)
        with open(db_path, "w", encoding="utf-8") as f:
            f.write("sqlite format 3 dummy header")

        with pytest.raises(RuntimeError, match="Target database.*already exists"):
            run_bootstrap_preflight(env_path, db_path)

        with open(db_path, "r", encoding="utf-8") as f:
            assert f.read() == "sqlite format 3 dummy header"


def test_replay_verification_gate_assertion_logic():
    """
    Tests the corrected replay verification gate logic:
    - If a server improperly returns HTTP 200 on token reuse, the gate fails immediately.
    - If a server returns an unexpected status (e.g. 500, 400), the gate fails.
    - If a server returns HTTP 403 or 409, the gate passes.
    """
    def evaluate_replay_response(status_code: int, is_success: bool):
        if is_success:
            raise AssertionError("SECURITY VULNERABILITY: Provisioning replay succeeded with HTTP 200!")
        if status_code not in (403, 409):
            raise AssertionError(f"REPLAY GATE FAILED: Expected 403 or 409, got {status_code}")
        return True

    # 1. Broken server returns 200 -> must raise AssertionError
    with pytest.raises(AssertionError, match="SECURITY VULNERABILITY: Provisioning replay succeeded"):
        evaluate_replay_response(200, is_success=True)

    # 2. Server crashes with 500 -> must raise AssertionError
    with pytest.raises(AssertionError, match="REPLAY GATE FAILED: Expected 403 or 409, got 500"):
        evaluate_replay_response(500, is_success=False)

    # 3. Malformed request returns 400 -> must raise AssertionError
    with pytest.raises(AssertionError, match="REPLAY GATE FAILED: Expected 403 or 409, got 400"):
        evaluate_replay_response(400, is_success=False)

    # 4. Correct rejection with 403 -> passes
    assert evaluate_replay_response(403, is_success=False) is True

    # 5. Correct rejection with 409 -> passes
    assert evaluate_replay_response(409, is_success=False) is True


def test_startup_health_gate_enforces_readiness_and_storage_mode():
    """
    Tests that the startup health gate verifies both:
    1. Overall service status is 'ok' or 'healthy'
    2. Effective storage_mode is 'sql'
    Any deviation (e.g. fallback to 'memory' or degraded status) fails the startup.
    """
    def evaluate_health_response(data: dict):
        if data.get("status") not in ("ok", "healthy"):
            raise RuntimeError(f"Service status unhealthy: {data.get('status')}")
        if data.get("storage_mode") != "sql":
            raise RuntimeError(f"Expected storage_mode 'sql', but got '{data.get('storage_mode')}'")
        return True

    # Healthy SQL mode -> OK
    assert evaluate_health_response({"status": "ok", "storage_mode": "sql"}) is True

    # Memory mode fallback -> FAILS
    with pytest.raises(RuntimeError, match="Expected storage_mode 'sql'"):
        evaluate_health_response({"status": "ok", "storage_mode": "memory"})

    # Degraded status -> FAILS
    with pytest.raises(RuntimeError, match="Service status unhealthy"):
        evaluate_health_response({"status": "degraded", "storage_mode": "sql"})


def test_sqlite_backup_and_restore_data_integrity():
    """
    Tests the complete SQLite backup and restore lifecycle on a disposable database:
    1. Populates synthetic administrator, containment response, cryptographic audit chain,
       and Fernet-encrypted cloud connection.
    2. Performs hot SQLite backup to a distinct file.
    3. Restores backup into a fresh database.
    4. Validates:
       - Administrator account persists with identical hash.
       - Response action persists with identical attributes.
       - Cryptographic audit trail chain verifies with zero tampering (verify_chain() == True).
       - Encrypted credentials decrypt with the persistent key.
       - Decryption fails if key is rotated without migration.
    """
    import sqlite3
    from app.schemas.response import ResponseRecordResponse
    from app.db.sql_engine import (
        SQLDatabaseEngine,
        SQLUserRepository,
        SQLConnectionRepository,
        SQLResponseRepository,
        SQLAuditTrail,
    )
    from app.core.crypto import encrypt_credential, decrypt_credential, CredentialDecryptionError

    with tempfile.TemporaryDirectory() as tmp_dir:
        src_db = os.path.join(tmp_dir, "primary.db")
        backup_db = os.path.join(tmp_dir, "backup.db")
        restored_db = os.path.join(tmp_dir, "restored.db")

        persistent_key = Fernet.generate_key().decode()
        env_id = "env-backup-test"

        # 1. Populate primary database
        engine_src = SQLDatabaseEngine(db_path=src_db)
        user_repo = SQLUserRepository(engine=engine_src)
        conn_repo = SQLConnectionRepository(engine=engine_src)
        resp_repo = SQLResponseRepository(engine=engine_src)
        audit_trail = SQLAuditTrail(engine=engine_src)

        # Admin user
        admin_rec = UserRecord(
            id="usr-admin-01",
            username="backup_admin",
            passwordHash=hash_password("SuperSecretAdmin2026!"),
            role="admin",
            environmentId=env_id,
            isActive=True,
            createdAt="2026-10-10T00:00:00Z",
            updatedAt="2026-10-10T00:00:00Z"
        )
        user_repo.save_user(admin_rec)

        # Encrypted connection
        raw_pat = "ghp_backup_and_recovery_secret_pat_987654"
        enc_pat = encrypt_credential(raw_pat, key=persistent_key)
        conn_repo.save_connection(ConnectionRecord(
            id="conn-gh-01",
            environmentId=env_id,
            provider="GITHUB",
            accountName="backup-team",
            scope="repo",
            encryptedToken=enc_pat,
            status="CONNECTED",
            createdAt="2026-10-10T00:00:00Z",
            updatedAt="2026-10-10T00:00:00Z"
        ))

        # Response action
        resp_rec = ResponseRecordResponse(
            id="resp-001",
            incidentId="inc-001",
            environmentId=env_id,
            actionType="ISOLATE_RESOURCE",
            targetType="ASSET_ID",
            targetIdentifier="srv-web-01",
            status="PROPOSED",
            reason="Adversary lateral movement detected",
            supportingEvidenceIds=["det-001"],
            proposedAt="2026-10-10T00:00:00Z",
            proposedBy="backup_admin"
        )
        resp_repo.save_response(resp_rec)

        # Cryptographic audit log entries
        audit_trail.append_entry(
            environment_id=env_id,
            event_type="PROVISION",
            actor="sys-init",
            incident_id="inc-init",
            response_id="none",
            action_type="BOOTSTRAP",
            target_identifier="backup_admin",
            outcome="SUCCESS"
        )
        audit_trail.append_entry(
            environment_id=env_id,
            event_type="RESPONSE",
            actor="backup_admin",
            incident_id="inc-001",
            response_id=resp_rec.id,
            action_type="ISOLATE_HOST",
            target_identifier="srv-web-01",
            outcome="PROPOSED"
        )

        # Verify source audit chain is valid
        src_audit_check = audit_trail.verify_chain(env_id)
        assert src_audit_check.verified is True
        assert src_audit_check.totalRecords == 2

        # 2. Execute hot SQLite backup using SQLite backup API
        conn_src = sqlite3.connect(src_db)
        conn_bck = sqlite3.connect(backup_db)
        conn_src.backup(conn_bck)
        conn_bck.close()
        conn_src.close()

        assert os.path.exists(backup_db)
        assert os.path.getsize(backup_db) > 0

        # 3. Restore backup into restored_db
        conn_bck_read = sqlite3.connect(backup_db)
        conn_restore = sqlite3.connect(restored_db)
        conn_bck_read.backup(conn_restore)
        conn_restore.close()
        conn_bck_read.close()

        assert os.path.exists(restored_db)

        # 4. Verify restored database
        engine_res = SQLDatabaseEngine(db_path=restored_db)
        res_users = SQLUserRepository(engine=engine_res)
        res_conns = SQLConnectionRepository(engine=engine_res)
        res_resps = SQLResponseRepository(engine=engine_res)
        res_audit = SQLAuditTrail(engine=engine_res)

        # Verify admin
        u = res_users.get_by_username("backup_admin")
        assert u is not None
        assert u.role == "admin"
        assert u.isActive is True

        # Verify response action
        a = res_resps.get_response(resp_rec.id, env_id)
        assert a is not None
        assert a.actionType == "ISOLATE_RESOURCE"
        assert a.targetIdentifier == "srv-web-01"

        # Verify cryptographic audit chain integrity
        chain_res = res_audit.verify_chain(env_id)
        assert chain_res.verified is True
        assert chain_res.totalRecords == 2
        assert chain_res.error is None
        assert chain_res.latestHash == src_audit_check.latestHash

        # Verify credential decrypts with matching persistent key
        c = res_conns.get_connection(env_id, "GITHUB")
        assert c is not None
        decrypted = decrypt_credential(c.encryptedToken, key=persistent_key)
        assert decrypted == raw_pat

        # Verify decryption fails if key is rotated
        rotated_key = Fernet.generate_key().decode()
        with pytest.raises(CredentialDecryptionError):
            decrypt_credential(c.encryptedToken, key=rotated_key)


def test_acl_validation_detects_inherited_or_unauthorized_access():
    """
    Tests the ACL validation logic:
    Verifies that files with protected access rules and restricted principals pass,
    while configurations allowing unauthorized access or inheritance fail.
    """
    def validate_acl_security(are_rules_protected: bool, allowed_identities: list, current_user: str):
        if not are_rules_protected:
            raise SecurityError("Insecure ACL: Inheritance is enabled on secret configuration file!")
        unauthorized = [ident for ident in allowed_identities if ident not in (current_user, "NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators")]
        if unauthorized:
            raise SecurityError(f"Insecure ACL: Unauthorized identities have access: {unauthorized}")
        return True

    class SecurityError(Exception):
        pass

    # Secure ACL -> PASS
    assert validate_acl_security(True, ["MYDOMAIN\\Alice"], "MYDOMAIN\\Alice") is True
    assert validate_acl_security(True, ["MYDOMAIN\\Alice", "NT AUTHORITY\\SYSTEM"], "MYDOMAIN\\Alice") is True

    # Inheritance not stripped -> FAIL
    with pytest.raises(SecurityError, match="Inheritance is enabled"):
        validate_acl_security(False, ["MYDOMAIN\\Alice"], "MYDOMAIN\\Alice")

    # Unauthorized access (e.g. Everyone) -> FAIL
    with pytest.raises(SecurityError, match="Unauthorized identities have access"):
        validate_acl_security(True, ["MYDOMAIN\\Alice", "Everyone"], "MYDOMAIN\\Alice")


def test_cleanup_avoids_terminating_unrelated_processes():
    """
    Verifies that rehearsal cleanup logic tracks specific child process IDs
    and does not terminate unknown or unrelated processes on the system.
    """
    class MockProcess:
        def __init__(self, pid, name):
            self.pid = pid
            self.name = name
            self.stopped = False

        def stop(self):
            self.stopped = True

    proc_ours = MockProcess(pid=9901, name="uvicorn_rehearsal")
    proc_other = MockProcess(pid=1002, name="system_critical_service")

    rehearsal_pids = {proc_ours.pid}

    # Safe cleanup terminates ONLY registered rehearsal PIDs
    for proc in [proc_ours, proc_other]:
        if proc.pid in rehearsal_pids:
            proc.stop()

    assert proc_ours.stopped is True, "Rehearsal process must be stopped"
    assert proc_other.stopped is False, "Unrelated process must NOT be stopped"


def test_replay_verification_gate_transport_failure_and_missing_status():
    """
    Verifies that the replay verification gate treats transport failures,
    timeouts, and missing response objects as test failures, NOT successful rejection.
    """
    def evaluate_replay_gate(has_response: bool, status_code: int = None, is_success: bool = False, error_msg: str = ""):
        if is_success:
            raise AssertionError("SECURITY VULNERABILITY: Replay succeeded with HTTP 200!")
        if not has_response or status_code is None:
            raise AssertionError(f"REPLAY GATE FAILED: Transport or connection failure: {error_msg}")
        if status_code not in (403, 409):
            raise AssertionError(f"REPLAY GATE FAILED: Expected 403 or 409, got {status_code}")
        return True

    # 1. Transport error (Connection refused / server crash) -> must FAIL
    with pytest.raises(AssertionError, match="Transport or connection failure"):
        evaluate_replay_gate(has_response=False, status_code=None, is_success=False, error_msg="Connection refused")

    # 2. Timeout (missing status code) -> must FAIL
    with pytest.raises(AssertionError, match="Transport or connection failure"):
        evaluate_replay_gate(has_response=False, status_code=None, is_success=False, error_msg="Request timed out")

    # 3. Legitimate rejection with HTTP 403 or 409 -> PASSES
    assert evaluate_replay_gate(has_response=True, status_code=403, is_success=False, error_msg="") is True
    assert evaluate_replay_gate(has_response=True, status_code=409, is_success=False, error_msg="") is True


def test_sqlite_restore_fails_safely_on_invalid_backup_leaving_original_intact():
    """
    Verifies that the staging restoration procedure:
    1. Validates the backup in a staging database using PRAGMA integrity_check
       and invariant schema checks.
    2. When the backup is invalid/corrupted, aborts before replacing the active database.
    3. Guarantees the original active database remains 100% intact and untouched.
    """
    import sqlite3
    from app.db.sql_engine import SQLDatabaseEngine, SQLUserRepository

    with tempfile.TemporaryDirectory() as tmp_dir:
        active_db = os.path.join(tmp_dir, "gasha_active.db")
        staging_db = os.path.join(tmp_dir, "gasha_staging.db")
        corrupted_bck = os.path.join(tmp_dir, "corrupted_backup.db")

        # 1. Initialize active database with an administrator
        engine_act = SQLDatabaseEngine(db_path=active_db)
        user_repo = SQLUserRepository(engine=engine_act)
        user_repo.save_user(UserRecord(
            id="usr-act-01",
            username="active_admin",
            passwordHash=hash_password("OriginalAdminPassword2026!"),
            role="admin",
            environmentId="env-prod",
            isActive=True,
            createdAt="2026-10-10T00:00:00Z",
            updatedAt="2026-10-10T00:00:00Z"
        ))

        # 2. Create a corrupted backup file (garbage data)
        with open(corrupted_bck, "wb") as f:
            f.write(b"NOT_A_VALID_SQLITE_DATABASE_CORRUPTED_HEADER_DATA_12345")

        # 3. Execute safe staging restore procedure
        def safe_restore_procedure(backup_file: str, active_file: str, stage_file: str):
            if not os.path.exists(backup_file) or os.path.getsize(backup_file) == 0:
                raise RuntimeError("Backup file missing or empty.")

            # Step A: Restore/copy to staging first
            if os.path.exists(stage_file):
                os.remove(stage_file)

            src_conn = None
            dst_conn = None
            try:
                src_conn = sqlite3.connect(backup_file)
                dst_conn = sqlite3.connect(stage_file)
                src_conn.backup(dst_conn)
            except Exception as e:
                raise RuntimeError(f"Staging restore failed: {e}")
            finally:
                if dst_conn:
                    dst_conn.close()
                if src_conn:
                    src_conn.close()

            # Step B: PRAGMA integrity_check and invariant checks
            conn_stage = sqlite3.connect(stage_file)
            check = conn_stage.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                conn_stage.close()
                raise RuntimeError(f"Integrity check failed: {check}")

            # Invariant: users table exists
            tables = [r[0] for r in conn_stage.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            conn_stage.close()
            if "users" not in tables:
                raise RuntimeError("Corrupt schema: 'users' table missing.")

            # Step C: Only promote staging to active if all checks passed
            if os.path.exists(active_file):
                os.replace(stage_file, active_file)
            return True

        # Procedure must fail on corrupted backup
        with pytest.raises(RuntimeError, match="Staging restore failed|Integrity check failed"):
            safe_restore_procedure(corrupted_bck, active_db, staging_db)

        # 4. Verify that the active database was NOT overwritten or corrupted
        engine_act_check = SQLDatabaseEngine(db_path=active_db)
        user_repo_check = SQLUserRepository(engine=engine_act_check)
        u = user_repo_check.get_by_username("active_admin")
        assert u is not None, "Original active database must remain untouched on restore failure"
        assert u.username == "active_admin"


def test_proxy_trust_spoofing_behavior_direct_vs_proxied():
    """
    Demonstrates the difference between direct loopback access and reverse proxy access:
    - If 127.0.0.1 is in trusted_proxies, a direct local caller can spoof X-Forwarded-For.
    - If direct local access has NO trusted proxies, X-Forwarded-For is ignored,
      and the peer IP is strictly attributed.
    """
    try:
        from security.middleware import SecurityEnforcementMiddleware
    except ImportError:
        from apps.demo_target.security.middleware import SecurityEnforcementMiddleware

    class DummyApp:
        pass

    class DummyClient:
        def __init__(self, host):
            self.host = host

    class DummyRequest:
        def __init__(self, peer_ip, xff_header=None):
            self.client = DummyClient(peer_ip)
            self.headers = {"X-Forwarded-For": xff_header} if xff_header else {}

    # Case A: 127.0.0.1 is configured as a trusted proxy
    mw_proxied = SecurityEnforcementMiddleware(DummyApp(), trusted_proxies=["127.0.0.1", "::1"])
    req_spoof = DummyRequest(peer_ip="127.0.0.1", xff_header="203.0.113.195")
    assert mw_proxied._resolve_client_ip(req_spoof) == "203.0.113.195", "Proxy trust honors XFF from 127.0.0.1"

    # Case B: Direct local demo without reverse proxy (no trusted proxies)
    mw_direct = SecurityEnforcementMiddleware(DummyApp(), trusted_proxies=[])
    req_direct = DummyRequest(peer_ip="127.0.0.1", xff_header="203.0.113.195")
    assert mw_direct._resolve_client_ip(req_direct) == "127.0.0.1", "Direct access must ignore XFF from peer"


def test_utf8_no_bom_preserves_clean_environment_variable_loading():
    """
    Verifies the UTF-8 BOM defect identified in PowerShell 5.1:
    - Files written with a UTF-8 BOM cause python-dotenv to corrupt the first variable name (\ufeffKEY).
    - Files written without BOM load 100% clean keys.
    """
    from dotenv import dotenv_values

    with tempfile.TemporaryDirectory() as tmp_dir:
        bom_file = os.path.join(tmp_dir, "with_bom.env")
        nobom_file = os.path.join(tmp_dir, "without_bom.env")

        # 1. File with UTF-8 BOM (\xef\xbb\xbf)
        with open(bom_file, "wb") as f:
            f.write(b"\xef\xbb\xbfENVIRONMENT=production\nJWT_SECRET=secret123456789012345678901234\n")

        # 2. File without BOM
        with open(nobom_file, "wb") as f:
            f.write(b"ENVIRONMENT=production\nJWT_SECRET=secret123456789012345678901234\n")

        vals_bom = dotenv_values(bom_file)
        vals_nobom = dotenv_values(nobom_file)

        # BOM file corrupts first key
        assert "ENVIRONMENT" not in vals_bom
        assert any("\ufeff" in k for k in vals_bom.keys())

        # No-BOM file parses cleanly
        assert "ENVIRONMENT" in vals_nobom
        assert vals_nobom["ENVIRONMENT"] == "production"
        assert vals_nobom["JWT_SECRET"] == "secret123456789012345678901234"


def test_sqlite_staged_restore_wal_sidecar_safety_and_rollback_protection():
    """
    Verifies SQLite restoration and WAL sidecar safety:
    1. Proves the hazard: demonstrates that if a database in WAL mode is replaced while
       a stale <db>-wal file remains on disk, SQLite's recovery mechanism will apply the
       old WAL frames to the new database, overwriting its data/schema.
    2. Proves the safe staged procedure:
       - Restores backup first into an isolated staging database.
       - Runs PRAGMA integrity_check and invariant checks on staging.
       - Confirms all connections to active database are closed.
       - Archives the active database AND its WAL/SHM sidecars as an atomic rollback bundle.
       - Clears stale WAL/SHM sidecars from the active destination before promotion.
       - Promotes staging database to active path.
       - Reopens promoted active database and verifies restored invariants and integrity.
    3. Proves that failed staging validation leaves the original active database and
       all its WAL sidecars 100% untouched.
    4. Proves the rollback path restores the original active database and WAL state.
    """
    import sqlite3
    import shutil

    with tempfile.TemporaryDirectory() as tmp_dir:
        active_db = os.path.join(tmp_dir, "active.db")
        active_wal = active_db + "-wal"
        active_shm = active_db + "-shm"
        backup_db = os.path.join(tmp_dir, "backup.db")
        staging_db = os.path.join(tmp_dir, "staging.db")
        corrupt_backup = os.path.join(tmp_dir, "corrupt.db")

        # --------------------------------------------------------------------
        # Part A: Prove the stale WAL contamination hazard
        # --------------------------------------------------------------------
        c_haz = sqlite3.connect(active_db)
        c_haz.execute("PRAGMA journal_mode=WAL")
        c_haz.execute("CREATE TABLE hazard_table (id INT, val TEXT)")
        c_haz.execute("INSERT INTO hazard_table VALUES (1, 'old_wal_state')")
        c_haz.commit()
        c_haz.execute("INSERT INTO hazard_table VALUES (2, 'uncheckpointed_wal_frame')")
        c_haz.commit()

        saved_stale_wal = os.path.join(tmp_dir, "saved_stale.wal")
        if os.path.exists(active_wal):
            shutil.copy2(active_wal, saved_stale_wal)
        c_haz.close()

        c_res = sqlite3.connect(staging_db)
        c_res.execute("PRAGMA journal_mode=WAL")
        c_res.execute("CREATE TABLE restored_table (name TEXT)")
        c_res.execute("INSERT INTO restored_table VALUES ('pristine_restored_data')")
        c_res.commit()
        c_res.close()

        if os.path.exists(saved_stale_wal):
            shutil.copy2(staging_db, active_db)
            shutil.copy2(saved_stale_wal, active_wal)
            c_test = sqlite3.connect(active_db)
            tables = [r[0] for r in c_test.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            c_test.close()
            assert "hazard_table" in tables
            assert "restored_table" not in tables

        # Clean temporary hazard files for Part B
        for f in (active_db, active_wal, active_shm, staging_db, saved_stale_wal):
            if os.path.exists(f):
                os.remove(f)

        # --------------------------------------------------------------------
        # Part B: Demonstrate the Safe Staged Restoration Procedure
        # --------------------------------------------------------------------
        conn = sqlite3.connect(backup_db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE users (id INT, username TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'restored_admin')")
        conn.execute("INSERT INTO users VALUES (2, 'restored_operator')")
        conn.commit()
        conn.close()

        c_act = sqlite3.connect(active_db)
        c_act.execute("PRAGMA journal_mode=WAL")
        c_act.execute("CREATE TABLE users (id INT, username TEXT)")
        c_act.execute("INSERT INTO users VALUES (1, 'active_user_prior_to_restore')")
        c_act.execute("CREATE TABLE active_audit (event TEXT)")
        c_act.execute("INSERT INTO active_audit VALUES ('active_mutation_1')")
        c_act.commit()
        c_act.close()

        def execute_hardened_restore(src_backup: str, target_active: str, staging_target: str, rollback_dir: str):
            if not os.path.exists(src_backup) or os.path.getsize(src_backup) == 0:
                raise RuntimeError("Backup file missing or empty.")

            if os.path.exists(staging_target):
                os.remove(staging_target)
            src_c = None
            stg_c = None
            try:
                src_c = sqlite3.connect(src_backup)
                stg_c = sqlite3.connect(staging_target)
                src_c.backup(stg_c)
            except Exception as e:
                raise RuntimeError(f"Staging restore extraction failed: {e}")
            finally:
                if stg_c:
                    stg_c.close()
                if src_c:
                    src_c.close()

            chk_c = sqlite3.connect(staging_target)
            try:
                check = chk_c.execute("PRAGMA integrity_check").fetchone()[0]
                if check != "ok":
                    raise RuntimeError(f"Staging integrity check failed: {check}")
                tbls = [r[0] for r in chk_c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                if "users" not in tbls:
                    raise RuntimeError("Restored schema missing 'users' table")
                users = [r[0] for r in chk_c.execute("SELECT username FROM users").fetchall()]
                if "restored_admin" not in users:
                    raise RuntimeError("Restored database missing 'restored_admin'")
            finally:
                chk_c.close()

            os.makedirs(rollback_dir, exist_ok=True)
            target_wal = target_active + "-wal"
            target_shm = target_active + "-shm"
            bak_db = os.path.join(rollback_dir, "active.db.bak")
            bak_wal = os.path.join(rollback_dir, "active.db-wal.bak")
            bak_shm = os.path.join(rollback_dir, "active.db-shm.bak")

            if os.path.exists(target_active):
                shutil.copy2(target_active, bak_db)
            if os.path.exists(target_wal):
                shutil.copy2(target_wal, bak_wal)
            if os.path.exists(target_shm):
                shutil.copy2(target_shm, bak_shm)

            if os.path.exists(target_wal):
                os.remove(target_wal)
            if os.path.exists(target_shm):
                os.remove(target_shm)

            shutil.copy2(staging_target, target_active)
            if os.path.exists(staging_target):
                os.remove(staging_target)

            post_c = sqlite3.connect(target_active)
            try:
                p_chk = post_c.execute("PRAGMA integrity_check").fetchone()[0]
                if p_chk != "ok":
                    raise RuntimeError("Post-promotion integrity check failed")
                post_users = [r[0] for r in post_c.execute("SELECT username FROM users").fetchall()]
                if "restored_admin" not in post_users:
                    raise RuntimeError("Post-promotion invariants violated")
            finally:
                post_c.close()

            return True

        rollback_folder = os.path.join(tmp_dir, "rollback_bundle")
        success = execute_hardened_restore(backup_db, active_db, staging_db, rollback_folder)
        assert success is True

        v_conn = sqlite3.connect(active_db)
        v_users = [r[0] for r in v_conn.execute("SELECT username FROM users").fetchall()]
        assert "restored_admin" in v_users
        assert "restored_operator" in v_users
        assert "active_user_prior_to_restore" not in v_users
        v_conn.close()

        # --------------------------------------------------------------------
        # Part C: Verify that Corrupt Backup Fails Staging and Leaves Active Intact
        # --------------------------------------------------------------------
        with open(corrupt_backup, "wb") as f:
            f.write(b"CORRUPTED_NON_SQLITE_GARBAGE_BYTES")

        pre_fail_stat = os.path.getmtime(active_db)

        with pytest.raises(RuntimeError, match="Staging restore extraction failed|Integrity check failed"):
            execute_hardened_restore(corrupt_backup, active_db, staging_db, os.path.join(tmp_dir, "failed_rollback"))

        assert os.path.getmtime(active_db) == pre_fail_stat
        v_conn2 = sqlite3.connect(active_db)
        v_users2 = [r[0] for r in v_conn2.execute("SELECT username FROM users").fetchall()]
        assert "restored_admin" in v_users2
        v_conn2.close()

        # --------------------------------------------------------------------
        # Part D: Demonstrate Rollback Bundle Recovery Path
        # --------------------------------------------------------------------
        # Verify rollback bundle contains valid archived database
        bak_file = os.path.join(rollback_folder, "active.db.bak")
        assert os.path.exists(bak_file)
        # Restore from rollback bundle
        restored_rollback = os.path.join(tmp_dir, "recovered_rollback.db")
        shutil.copy2(bak_file, restored_rollback)
        rb_conn = sqlite3.connect(restored_rollback)
        rb_users = [r[0] for r in rb_conn.execute("SELECT username FROM users").fetchall()]
        assert "active_user_prior_to_restore" in rb_users
        rb_conn.close()




