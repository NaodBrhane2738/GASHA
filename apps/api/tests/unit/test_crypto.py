"""
==============================================================================
FILE: apps/api/tests/unit/test_crypto.py
OBJECTIVE: Unit test credential encryption at rest, decryption, and tampering resistance.
==============================================================================
"""

import pytest
from app.core.crypto import (
    encrypt_credential,
    decrypt_credential,
    mask_secret,
    CredentialDecryptionError,
    _derive_default_fernet_key
)


def test_derive_default_fernet_key():
    key = _derive_default_fernet_key()
    assert isinstance(key, bytes)
    assert len(key) == 44  # 32-byte base64 encoded has length 44


def test_encrypt_and_decrypt_roundtrip():
    secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    encrypted = encrypt_credential(secret)
    assert encrypted != secret
    assert len(encrypted) > len(secret)
    
    decrypted = decrypt_credential(encrypted)
    assert decrypted == secret


def test_empty_string_handling():
    assert encrypt_credential("") == ""
    assert decrypt_credential("") == ""


def test_tampered_ciphertext_fails():
    secret = "vercel_token_super_secret_xyz123"
    encrypted = encrypt_credential(secret)
    # Tamper with the ciphertext
    tampered = encrypted[:-4] + "AAAA"
    with pytest.raises(CredentialDecryptionError):
        decrypt_credential(tampered)


def test_wrong_key_fails():
    import base64, os
    secret = "secret-token-payload"
    encrypted = encrypt_credential(secret)
    
    wrong_key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    with pytest.raises(CredentialDecryptionError):
        decrypt_credential(encrypted, key=wrong_key)


def test_mask_secret():
    assert mask_secret("ghp_1234567890abcdef", 4, 4) == "ghp_...cdef"
    assert mask_secret("short", 4, 4) == "********"


def test_production_mode_refuses_default_derivation(monkeypatch):
    from app.core.config import settings
    from app.core.crypto import _derive_default_fernet_key
    monkeypatch.setattr(settings, "NODE_ENV", "production")
    monkeypatch.setattr(settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    with pytest.raises(RuntimeError) as exc_info:
        _derive_default_fernet_key()
    assert "CREDENTIAL_ENCRYPTION_KEY must be configured in production" in str(exc_info.value)
    assert mask_secret("") == ""
