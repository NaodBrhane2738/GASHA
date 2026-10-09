"""
==============================================================================
FILE: apps/api/app/response/audit.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Tamper-evident cryptographic audit log for containment responses.
           Adapted from GAS0C ArchiveService. Implements canonical serialization,
           SHA-256 hash chaining, and integrity verification.
==============================================================================
"""

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional

from app.schemas.response import AuditEntryResponse, AuditVerificationResult

GENESIS_HASH = "0" * 64
SENSITIVE_KEYS = {"password", "secret", "token", "key", "authorization", "bearer"}


def redact_sensitive_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redacts any secret keys from audit metadata."""
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    for k, v in data.items():
        if any(s in k.lower() for s in SENSITIVE_KEYS):
            cleaned[k] = "[REDACTED]"
        elif isinstance(v, dict):
            cleaned[k] = redact_sensitive_dict(v)
        else:
            cleaned[k] = v
    return cleaned


def compute_canonical_hash(payload: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash of a payload dictionary
    using canonical JSON formatting (sorted keys, compact separators).
    """
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class AuditTrail:
    """
    Thread-safe cryptographic audit log maintaining an append-only SHA-256 hash chain per environment.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # Key: environment_id -> List[AuditEntryResponse]
        self._chains: Dict[str, List[AuditEntryResponse]] = {}

    def append_entry(
        self,
        environment_id: str,
        event_type: str,
        actor: str,
        incident_id: str,
        response_id: str,
        action_type: str,
        target_identifier: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEntryResponse:
        with self._lock:
            if environment_id not in self._chains:
                self._chains[environment_id] = []

            chain = self._chains[environment_id]
            seq_num = len(chain) + 1
            prev_hash = chain[-1].recordHash if chain else GENESIS_HASH

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            audit_id = f"aud-{uuid.uuid4().hex[:12]}"

            clean_details = redact_sensitive_dict(details or {})

            # Fields that define the immutable record
            record_data = {
                "auditId": audit_id,
                "sequenceNumber": seq_num,
                "timestamp": now_iso,
                "eventType": event_type,
                "actor": actor,
                "environmentId": environment_id,
                "incidentId": incident_id,
                "responseId": response_id,
                "actionType": action_type,
                "targetIdentifier": target_identifier,
                "outcome": outcome,
                "details": clean_details,
                "previousHash": prev_hash
            }

            record_hash = compute_canonical_hash(record_data)

            entry = AuditEntryResponse(
                auditId=audit_id,
                sequenceNumber=seq_num,
                timestamp=now_iso,
                eventType=event_type,
                actor=actor,
                environmentId=environment_id,
                incidentId=incident_id,
                responseId=response_id,
                actionType=action_type,
                targetIdentifier=target_identifier,
                outcome=outcome,
                details=clean_details,
                previousHash=prev_hash,
                recordHash=record_hash
            )

            chain.append(entry)
            return entry

    def get_entries(self, environment_id: str) -> List[AuditEntryResponse]:
        with self._lock:
            return list(self._chains.get(environment_id, []))

    def verify_chain(self, environment_id: str) -> AuditVerificationResult:
        with self._lock:
            chain = self._chains.get(environment_id, [])
            if not chain:
                return AuditVerificationResult(
                    verified=True,
                    totalRecords=0,
                    environmentId=environment_id,
                    latestHash=GENESIS_HASH,
                    error=None
                )

            for idx, entry in enumerate(chain):
                expected_seq = idx + 1
                if entry.sequenceNumber != expected_seq:
                    return AuditVerificationResult(
                        verified=False,
                        totalRecords=len(chain),
                        environmentId=environment_id,
                        latestHash=None,
                        error=f"Sequence anomaly at index {idx}: expected {expected_seq}, found {entry.sequenceNumber}"
                    )

                expected_prev = chain[idx - 1].recordHash if idx > 0 else GENESIS_HASH
                if entry.previousHash != expected_prev:
                    return AuditVerificationResult(
                        verified=False,
                        totalRecords=len(chain),
                        environmentId=environment_id,
                        latestHash=None,
                        error=f"Hash chain broken at sequence {entry.sequenceNumber}: previousHash '{entry.previousHash}' != expected '{expected_prev}'"
                    )

                # Reconstruct record data payload to verify cryptographic SHA-256 hash
                record_data = {
                    "auditId": entry.auditId,
                    "sequenceNumber": entry.sequenceNumber,
                    "timestamp": entry.timestamp,
                    "eventType": entry.eventType,
                    "actor": entry.actor,
                    "environmentId": entry.environmentId,
                    "incidentId": entry.incidentId,
                    "responseId": entry.responseId,
                    "actionType": entry.actionType,
                    "targetIdentifier": entry.targetIdentifier,
                    "outcome": entry.outcome,
                    "details": redact_sensitive_dict(getattr(entry, "details", {}) or {}),
                    "previousHash": entry.previousHash
                }
                recomputed_hash = compute_canonical_hash(record_data)
                if recomputed_hash != entry.recordHash:
                    return AuditVerificationResult(
                        verified=False,
                        totalRecords=len(chain),
                        environmentId=environment_id,
                        latestHash=None,
                        error=f"Payload tampering detected at sequence {entry.sequenceNumber}: computed '{recomputed_hash}' != stored '{entry.recordHash}'"
                    )

                if not entry.recordHash or len(entry.recordHash) != 64:
                    return AuditVerificationResult(
                        verified=False,
                        totalRecords=len(chain),
                        environmentId=environment_id,
                        latestHash=None,
                        error=f"Invalid hash format at sequence {entry.sequenceNumber}"
                    )

            return AuditVerificationResult(
                verified=True,
                totalRecords=len(chain),
                environmentId=environment_id,
                latestHash=chain[-1].recordHash,
                error=None
            )

    def clear(self) -> None:
        with self._lock:
            self._chains.clear()


_default_audit_trail: Optional[AuditTrail] = None


def get_audit_trail() -> AuditTrail:
    global _default_audit_trail
    if _default_audit_trail is None:
        _default_audit_trail = AuditTrail()
    return _default_audit_trail
