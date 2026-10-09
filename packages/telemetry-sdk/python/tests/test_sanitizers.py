"""
Unit tests for GASHA Telemetry SDK Sanitization routines.
Validates redaction of secrets and preservation of correlation identifiers.
"""
import pytest
from sanitizers import (
    sanitize_metadata,
    sanitize_headers,
    mask_token,
    is_sensitive_key,
    REDACTED_VALUE,
)


def test_sensitive_keys_identification():
    # Sensitive keys that should match
    assert is_sensitive_key("password") is True
    assert is_sensitive_key("user_password") is True
    assert is_sensitive_key("client_secret") is True
    assert is_sensitive_key("apiKey") is True
    assert is_sensitive_key("api_key") is True
    assert is_sensitive_key("access_token") is True
    assert is_sensitive_key("authorization") is True
    assert is_sensitive_key("cookie") is True
    assert is_sensitive_key("credit_card") is True

    # Correlation keys that must NOT match (must be preserved)
    assert is_sensitive_key("session_id") is False
    assert is_sensitive_key("sessionId") is False
    assert is_sensitive_key("user_id") is False
    assert is_sensitive_key("userId") is False
    assert is_sensitive_key("source_ip") is False
    assert is_sensitive_key("sourceIp") is False
    assert is_sensitive_key("action") is False
    assert is_sensitive_key("outcome") is False
    assert is_sensitive_key("resource") is False
    assert is_sensitive_key("endpoint") is False
    assert is_sensitive_key("status_code") is False


def test_sanitize_metadata_redaction():
    raw = {
        "user_id": "usr_9981",
        "sessionId": "sess_abc123",
        "password": "SuperSecretPassword123!",
        "api_key": "live_key_99999",
        "nested": {
            "client_secret": "secret_abc",
            "safe_counter": 42,
            "tokens": ["bearer_xyz", "safe_item"]
        }
    }
    sanitized = sanitize_metadata(raw)

    assert sanitized["user_id"] == "usr_9981"
    assert sanitized["sessionId"] == "sess_abc123"
    assert sanitized["password"] == REDACTED_VALUE
    assert sanitized["api_key"] == REDACTED_VALUE
    assert sanitized["nested"]["client_secret"] == REDACTED_VALUE
    assert sanitized["nested"]["safe_counter"] == 42


def test_sanitize_bearer_and_jwt_strings():
    jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    raw = {
        "header_auth": "Bearer secret-token-value",
        "basic_auth": "Basic dXNlcjpwYXNz",
        "custom_jwt": jwt_sample,
        "normal_text": "Hello world"
    }
    sanitized = sanitize_metadata(raw)
    assert sanitized["header_auth"] == "Bearer [REDACTED]"
    assert sanitized["basic_auth"] == "Basic [REDACTED]"
    assert sanitized["custom_jwt"] == "[REDACTED_JWT]"
    assert sanitized["normal_text"] == "Hello world"


def test_sanitize_headers():
    headers = {
        "content-type": "application/json",
        "authorization": "Bearer token123",
        "cookie": "session_id=123; secret=xyz",
        "user-agent": "Mozilla/5.0",
        "x-api-key": "my-secret-key"
    }
    cleaned = sanitize_headers(headers)
    assert cleaned["content-type"] == "application/json"
    assert cleaned["authorization"] == REDACTED_VALUE
    assert cleaned["cookie"] == REDACTED_VALUE
    assert cleaned["user-agent"] == "Mozilla/5.0"
    assert cleaned["x-api-key"] == REDACTED_VALUE


def test_mask_token():
    assert mask_token("sk-1234567890abcdef", visible_chars=4) == "***************cdef"
    assert mask_token("short", visible_chars=4) == "*hort"
    assert mask_token("abc", visible_chars=4) == "***"
    assert mask_token("") == ""
    assert mask_token(None) == ""
