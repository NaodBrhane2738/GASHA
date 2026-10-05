"""
==============================================================================
FILE: apps/api/app/ai/tests/security/test_data_leakage.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Data leakage and credential minimization test suite.
           Verifies that API keys, passwords, bearer tokens, AWS credentials,
           and secrets are scrubbed and not leaked in prompts, logs, or outputs.
==============================================================================
"""

import pytest
from app.ai.context_normalizer import scrub_secrets, normalize_telemetry_event


def test_api_key_and_bearer_token_scrubbing():
    """TEST: API keys, AWS tokens, and Bearer headers are scrubbed from telemetry strings."""
    raw_payload = {
        "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload",
        "aws_key": "AKIAIOSFODNN7EXAMPLE",
        "db_password": "SuperSecretPassword123!",
        "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    }

    scrubbed = scrub_secrets(raw_payload)
    serialized = str(scrubbed)

    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "SuperSecretPassword123!" not in serialized
    assert "ghp_1234567890" not in serialized
    assert "[REDACTED_SECRET]" in serialized or "[REDACTED" in serialized


def test_telemetry_event_normalization_scrubbing():
    """TEST: normalize_telemetry_event scrubs raw payloads before context inclusion."""
    raw_dict = {
        "id": "TEL-LEAK-1",
        "timestamp": "2026-09-24T00:00:00Z",
        "eventType": "HTTP_REQUEST",
        "sourceService": "api-gateway",
        "metadata": {
            "uri": "/login",
            "password": "CleartextPassword999",
            "api_key": "sk-live-abcdef1234567890",
        },
    }

    normalized = normalize_telemetry_event(raw_dict)
    meta_str = str(normalized.metadata)

    assert "CleartextPassword999" not in meta_str
    assert "sk-live-abcdef1234567890" not in meta_str
    assert "[REDACTED_SECRET]" in meta_str or "[REDACTED" in meta_str


def test_private_key_scrubbing():
    """TEST: PEM format private keys are cleanly redacted."""
    raw_text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...EXAMPLE...\n-----END RSA PRIVATE KEY-----"
    scrubbed = scrub_secrets(raw_text)

    assert "-----BEGIN RSA PRIVATE KEY-----" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed or "[REDACTED" in scrubbed
