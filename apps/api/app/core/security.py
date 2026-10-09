"""
==============================================================================
FILE: apps/api/app/core/security.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Cryptographic helpers, OWASP-compliant PBKDF2 password hashing,
           JWT encode/decode with mandatory environmentId, and token rotation helpers.
==============================================================================
"""

import hashlib
import os
import secrets
import time
import jwt
from typing import Optional, Dict, Any
from app.core.config import settings

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16


def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 600,000 iterations and a cryptographically
    random 16-byte salt (OWASP Recommended). Format: pbkdf2_sha256$iterations$salt_hex$hash_hex
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = os.urandom(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a PBKDF2-HMAC-SHA256 hashed password in constant time.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])
        derived = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(derived, expected_hash)
    except Exception:
        return False


def create_jwt_token(data: Dict[str, Any], expires_seconds: int = 86400) -> str:
    """
    Creates a signed JWT access token. Enforces presence of environmentId and issue timestamp.
    """
    payload = data.copy()
    now = int(time.time())
    payload.setdefault("iat", now)
    payload.setdefault("environmentId", "env-prod")
    payload.update({"exp": now + expires_seconds})
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates a JWT access token. Returns None on signature failure, expiration, or format error.
    """
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def create_refresh_token() -> str:
    """Generates a high-entropy cryptographically secure refresh token string."""
    return f"rft_{secrets.token_urlsafe(32)}"


def hash_refresh_token(refresh_token: str) -> str:
    """Computes SHA-256 hash of refresh token for safe storage."""
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
