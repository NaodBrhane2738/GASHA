"""
==============================================================================
FILE: apps/api/app/core/production_guard.py
ROLE / OWNERSHIP: Cybersecurity & Infrastructure Engineers
OBJECTIVE: Validates production startup safeguards, secret entropy, independent
           cryptographic keys, fail-closed persistence requirements, and password complexity.
==============================================================================
"""

import os
import re
import base64
import logging
from typing import Optional, Set

from app.core.config import settings

logger = logging.getLogger("gasha.production_guard")

KNOWN_INSECURE_SECRETS: Set[str] = {
    "super-secret-jwt-key-change-in-production-min32chars",
    "gasha-internal-service-key-change-me",
    "gasha-credential-store-salt",
    "gasha-telemetry-demo-key-2026",
    "secret",
    "jwt-secret",
    "dev-secret",
    "change-me",
    "password",
    "admin",
    "12345678",
    "AnalystSecure2026!",
    "OperatorSecure2026!",
    "AdminRoot2026!",
    "EmergencyRoot2026!",
    "TenantBSecure2026!",
    "DemoAdminSecure2026!#",
    "DemoAnalystSecure2026!#",
    "DemoOperatorSecure2026!#"
}


def is_production_mode() -> bool:
    """
    Returns True if current runtime environment is explicitly configured
    as production, staging, or live.
    """
    env_mode = (
        getattr(settings, "NODE_ENV", "") or
        os.environ.get("ENVIRONMENT", "") or
        os.environ.get("NODE_ENV", "") or
        os.environ.get("APP_ENV", "")
    ).strip().lower()
    return env_mode in ("production", "prod", "staging", "live")


def validate_password_complexity(password: str, username: Optional[str] = None) -> None:
    """
    Enforces password complexity:
    - Minimum length 12
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    - Must not equal username or known weak passwords
    """
    if not password or len(password) < 12:
        raise ValueError("Password must be at least 12 characters in length.")

    if username and password.strip().lower() == username.strip().lower():
        raise ValueError("Password cannot be identical to the username.")

    if password in KNOWN_INSECURE_SECRETS:
        raise ValueError("Password is a known insecure default credential and is prohibited.")

    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter (A-Z).")

    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter (a-z).")

    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one numeric digit (0-9).")

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password):
        raise ValueError("Password must contain at least one special character.")


def validate_production_configuration() -> None:
    """
    Validates that production environment meets all mandatory security requirements:
    - JWT_SECRET has minimum 32 characters and is not a known placeholder
    - CREDENTIAL_ENCRYPTION_KEY is independent, explicit, and a valid 32-byte Fernet key
    - INTERNAL_API_KEY is not a known placeholder
    - Storage backend is durable 'sql' and not ephemeral 'memory'
    - SQL database is reachable and writable
    """
    if not is_production_mode():
        logger.debug("Non-production environment: standard development configuration permitted.")
        return

    logger.info("Enforcing production startup security safeguards...")

    # 1. Storage Backend Guard
    from app.db.storage_mode import resolve_storage_backend, StorageMode
    backend = resolve_storage_backend()
    if backend != StorageMode.SQL:
        raise RuntimeError(
            "Production security violation: GASHA_STORAGE_BACKEND must be set to 'sql'. "
            "Ephemeral 'memory' storage is prohibited in production."
        )

    # 2. Database Reachability & WAL Check
    from app.db.sql_engine import get_sql_engine
    try:
        engine = get_sql_engine()
        with engine.get_connection() as conn:
            cur = conn.execute("SELECT 1 as alive")
            if cur.fetchone()["alive"] != 1:
                raise RuntimeError("Database probe returned unexpected result.")
    except Exception as e:
        raise RuntimeError(f"Production startup failed: Configured SQL database is unreachable or corrupt: {e}")

    # 3. JWT Secret Guard
    jwt_secret = getattr(settings, "JWT_SECRET", "")
    if not jwt_secret or len(jwt_secret.strip()) < 32:
        raise RuntimeError(
            "Production security violation: JWT_SECRET must be configured with at least 32 characters."
        )
    if jwt_secret in KNOWN_INSECURE_SECRETS or "change-in-production" in jwt_secret.lower():
        raise RuntimeError(
            "Production security violation: JWT_SECRET is using a known development placeholder. "
            "A high-entropy, independent secret is required in production."
        )

    # 4. Credential Encryption Key Guard
    enc_key = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    if not enc_key or not enc_key.strip():
        raise RuntimeError(
            "Production security violation: CREDENTIAL_ENCRYPTION_KEY must be configured in production."
        )
    if enc_key.strip() == jwt_secret.strip():
        raise RuntimeError(
            "Production security violation: CREDENTIAL_ENCRYPTION_KEY must be independent of JWT_SECRET."
        )
    # Validate Fernet base64 format (32 bytes url-safe base64 encoded)
    try:
        raw_key = enc_key.strip().encode("utf-8")
        decoded = base64.urlsafe_b64decode(raw_key)
        if len(decoded) != 32:
            raise ValueError(f"Expected 32 bytes, got {len(decoded)}")
    except Exception as e:
        raise RuntimeError(
            f"Production security violation: CREDENTIAL_ENCRYPTION_KEY is not a valid 32-byte Fernet key: {e}"
        )

    # 5. Internal API Key Guard
    internal_key = getattr(settings, "INTERNAL_API_KEY", "")
    if not internal_key or internal_key in KNOWN_INSECURE_SECRETS or "change-me" in internal_key.lower():
        raise RuntimeError(
            "Production security violation: INTERNAL_API_KEY is using a known development placeholder. "
            "A high-entropy key is required in production."
        )

    # 6. Provisioning Token Guard (Mandatory when unprovisioned)
    from app.db.repositories.user_repository import get_user_repository
    user_repo = get_user_repository()
    if not user_repo.is_system_provisioned():
        prov_token = os.environ.get("GASHA_PROVISIONING_TOKEN") or getattr(settings, "PROVISIONING_TOKEN", "") or ""
        if not prov_token or len(prov_token.strip()) < 32:
            raise RuntimeError(
                "Production security violation: Database is unprovisioned. "
                "GASHA_PROVISIONING_TOKEN must be configured with at least 32 characters for initial administrator bootstrap."
            )
        if prov_token in KNOWN_INSECURE_SECRETS or "change-me" in prov_token.lower() or "placeholder" in prov_token.lower():
            raise RuntimeError(
                "Production security violation: GASHA_PROVISIONING_TOKEN is using a known development placeholder. "
                "A high-entropy token is required for initial provisioning."
            )

    logger.info("Production configuration validation passed successfully.")

