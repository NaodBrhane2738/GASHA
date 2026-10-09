"""
==============================================================================
FILE: apps/api/tests/unit/test_tamper_evident_audit.py
OBJECTIVE: Unit tests for Tamper-Evident Cryptographic Audit Logging.
           Verifies canonical JSON serialization, SHA-256 hash chaining,
           tamper detection, and secret redaction.
==============================================================================
"""

import pytest
from app.response.audit import AuditTrail, redact_sensitive_dict, compute_canonical_hash


@pytest.fixture
def audit_trail():
    trail = AuditTrail()
    trail.clear()
    return trail


def test_valid_chain_verifies(audit_trail):
    env_id = "env-prod"
    audit_trail.append_entry(
        environment_id=env_id,
        event_type="PROPOSAL_CREATED",
        actor="operator-1",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.10",
        outcome="PROPOSED"
    )
    audit_trail.append_entry(
        environment_id=env_id,
        event_type="PROPOSAL_APPROVED",
        actor="operator-2",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.10",
        outcome="APPROVED"
    )
    audit_trail.append_entry(
        environment_id=env_id,
        event_type="EXECUTION_SUCCEEDED",
        actor="operator-2",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.10",
        outcome="SUCCEEDED"
    )

    result = audit_trail.verify_chain(env_id)
    assert result.verified is True
    assert result.totalRecords == 3
    assert result.error is None
    assert result.latestHash is not None


def test_broken_hash_chain_linkage_detected(audit_trail):
    env_id = "env-prod"
    e1 = audit_trail.append_entry(
        environment_id=env_id,
        event_type="PROPOSAL_CREATED",
        actor="operator-1",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.10",
        outcome="PROPOSED"
    )
    e2 = audit_trail.append_entry(
        environment_id=env_id,
        event_type="PROPOSAL_APPROVED",
        actor="operator-2",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.10",
        outcome="APPROVED"
    )

    # Maliciously alter previousHash in second entry
    chain = audit_trail._chains[env_id]
    tampered_e2 = chain[1].model_copy(update={"previousHash": "deadbeef" * 8})
    chain[1] = tampered_e2

    result = audit_trail.verify_chain(env_id)
    assert result.verified is False
    assert "Hash chain broken" in result.error


def test_sequence_anomaly_detected(audit_trail):
    env_id = "env-prod"
    audit_trail.append_entry(
        environment_id=env_id,
        event_type="PROPOSAL_CREATED",
        actor="operator-1",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.10",
        outcome="PROPOSED"
    )

    # Maliciously alter sequence number
    chain = audit_trail._chains[env_id]
    chain[0] = chain[0].model_copy(update={"sequenceNumber": 5})

    result = audit_trail.verify_chain(env_id)
    assert result.verified is False
    assert "Sequence anomaly" in result.error


def test_sensitive_credentials_redacted():
    raw_details = {
        "user": "admin",
        "password": "super-secret-password",
        "api_token": "bearer-token-12345",
        "headers": {
            "Authorization": "Bearer secret-key",
            "host": "localhost"
        }
    }
    cleaned = redact_sensitive_dict(raw_details)
    assert cleaned["user"] == "admin"
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["api_token"] == "[REDACTED]"
    assert cleaned["headers"]["Authorization"] == "[REDACTED]"
    assert cleaned["headers"]["host"] == "localhost"


def test_payload_tamper_detected(audit_trail):
    """Verifies that tampering with in-memory payload fields triggers verification failure."""
    env_id = "env-prod"
    audit_trail.append_entry(
        environment_id=env_id,
        event_type="PROPOSAL_CREATED",
        actor="operator-1",
        incident_id="inc-1",
        response_id="resp-1",
        action_type="BLOCK_SOURCE",
        target_identifier="198.51.100.10",
        outcome="PROPOSED"
    )

    # Maliciously alter payload field (targetIdentifier)
    chain = audit_trail._chains[env_id]
    chain[0] = chain[0].model_copy(update={"targetIdentifier": "10.0.0.1"})

    result = audit_trail.verify_chain(env_id)
    assert result.verified is False
    assert "Payload tampering detected" in result.error
