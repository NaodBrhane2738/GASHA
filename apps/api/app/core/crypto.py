"""
==============================================================================
FILE: apps/api/app/core/crypto.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Authenticated credential encryption at rest for third-party tokens (Fernet / AES).
==============================================================================
"""

import os
import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


class CredentialDecryptionError(Exception):
    """Raised when encrypted credential cannot be decrypted or verified."""
    pass


def _derive_default_fernet_key() -> bytes:
    """
    Derives a deterministic 32-byte URL-safe base64 key for Fernet from system secrets
    if no explicit CREDENTIAL_ENCRYPTION_KEY is provided.
    """
    explicit_key = getattr(settings, "CREDENTIAL_ENCRYPTION_KEY", None)
    if explicit_key and explicit_key.strip():
        raw_key = explicit_key.strip().encode("utf-8")
        # If it's already a valid 32-byte urlsafe base64 key:
        if len(raw_key) == 44:
            try:
                base64.urlsafe_b64decode(raw_key)
                return raw_key
            except Exception:
                pass
        # Derive via SHA-256
        digest = hashlib.sha256(raw_key).digest()
        return base64.urlsafe_b64encode(digest)

    # Refuse default key derivation in any production, staging, or ambiguous non-dev mode
    env_mode = (
        getattr(settings, "NODE_ENV", "") or
        os.environ.get("ENVIRONMENT", "") or
        os.environ.get("APP_ENV", "")
    ).strip().lower()

    # Strictly require explicit development/test mode to permit local fallback derivation
    is_development = env_mode in ("development", "dev", "test", "testing", "local")
    if not is_development or env_mode in ("production", "prod", "staging", "live"):
        raise RuntimeError(
            "Insecure configuration: CREDENTIAL_ENCRYPTION_KEY must be configured in production environments. "
            "Deriving encryption keys from repository defaults is strictly prohibited."
        )

    # In development/test mode: derive deterministically from JWT_SECRET + INTERNAL_API_KEY
    seed = f"{settings.JWT_SECRET}:{settings.INTERNAL_API_KEY}:gasha-credential-store-salt"
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet_instance(key: Optional[str] = None) -> Fernet:
    """Returns a configured Fernet cipher instance."""
    if key and key.strip():
        k = key.strip().encode("utf-8")
        if len(k) == 44:
            try:
                base64.urlsafe_b64decode(k)
                fernet_key = k
            except Exception:
                fernet_key = base64.urlsafe_b64encode(hashlib.sha256(k).digest())
        else:
            fernet_key = base64.urlsafe_b64encode(hashlib.sha256(k).digest())
    else:
        fernet_key = _derive_default_fernet_key()

    return Fernet(fernet_key)


def encrypt_credential(plaintext: str, key: Optional[str] = None) -> str:
    """
    Encrypts a plaintext secret (such as an API token or private key).
    Returns a URL-safe base64 string containing the authenticated ciphertext.
    """
    if not plaintext:
        return ""
    fernet = get_fernet_instance(key)
    encrypted_bytes = fernet.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_credential(ciphertext: str, key: Optional[str] = None) -> str:
    """
    Decrypts an authenticated ciphertext string.
    Raises CredentialDecryptionError if corrupted, tampered with, or invalid key.
    """
    if not ciphertext:
        return ""
    fernet = get_fernet_instance(key)
    try:
        decrypted_bytes = fernet.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken as exc:
        raise CredentialDecryptionError("Failed to decrypt credential: token invalid or key mismatch") from exc
    except Exception as exc:
        raise CredentialDecryptionError(f"Unexpected error decrypting credential: {str(exc)}") from exc


def mask_secret(secret: str, visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """
    Returns a safe, masked representation of a secret for audit logs or status displays.
    Never exposes full tokens.
    """
    if not secret:
        return ""
    if len(secret) <= (visible_prefix + visible_suffix + 2):
        return "********"
    return f"{secret[:visible_prefix]}...{secret[-visible_suffix:]}"
