"""
==============================================================================
FILE: apps/api/app/db/sql_engine.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Thread-safe, durable SQL persistence engine using SQLite.
           Provides reliable relational persistence across process restarts,
           satisfying migrations 001 and 002 for incidents, detections,
           investigations, responses, users, and audit logs.
==============================================================================
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from app.schemas.incident import IncidentResponse, IncidentStatus, VALID_STATUS_TRANSITIONS
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.response import (
    ResponseRecordResponse,
    AuditEntryResponse,
    AuditVerificationResult,
    ResponseActionType,
    ResponseTargetType,
    ResponseStatus
)
from app.response.audit import compute_canonical_hash, redact_sensitive_dict, GENESIS_HASH

SEVERITY_RANKS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

DEFAULT_SQLITE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "data",
    "gasha_storage.db"
)


class SQLDatabaseEngine:
    """
    Manages SQLite database connection lifecycle, foreign keys, WAL journaling,
    and schema creation based on migrations 001 and 002.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("GASHA_DATABASE_PATH", DEFAULT_SQLITE_PATH)
        self._lock = threading.RLock()
        self._ensure_directory()
        self.init_schema()

    def _ensure_directory(self) -> None:
        if self.db_path != ":memory:":
            parent = os.path.dirname(self.db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        with self._lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            if self.db_path != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL;")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def init_schema(self) -> None:
        """Executes DDL to create tables matching migrations 001, 002, and user auth."""
        with self.get_connection() as conn:
            conn.executescript("""
            -- Migration 001: Detections and Incidents
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                rule_description TEXT,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                primary_asset_id TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                incident_id TEXT,
                matched_event_ids TEXT NOT NULL DEFAULT '[]',
                evidence_summary TEXT NOT NULL,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_detections_env ON detections(environment_id);
            CREATE INDEX IF NOT EXISTS idx_detections_incident ON detections(incident_id);

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                primary_affected_asset_id TEXT NOT NULL,
                related_asset_ids TEXT NOT NULL DEFAULT '[]',
                detection_event_ids TEXT NOT NULL DEFAULT '[]',
                attack_path_id TEXT,
                summary TEXT,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                correlation_key TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_env ON incidents(environment_id);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_corr_key ON incidents(environment_id, correlation_key);

            -- Migration 002: Investigations and Response Actions
            CREATE TABLE IF NOT EXISTS investigations (
                incident_id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                summary TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                attack_story TEXT NOT NULL DEFAULT '{}',
                grounded_evidence TEXT NOT NULL DEFAULT '[]',
                recommendations TEXT NOT NULL DEFAULT '[]',
                generated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_investigations_env ON investigations(environment_id);

            CREATE TABLE IF NOT EXISTS response_actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                action_type TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_identifier TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
                reason TEXT NOT NULL,
                supporting_evidence_ids TEXT NOT NULL DEFAULT '[]',
                proposed_at TEXT NOT NULL,
                proposed_by TEXT NOT NULL,
                approved_at TEXT,
                approved_by TEXT,
                executed_at TEXT,
                execution_message TEXT,
                verification_status TEXT,
                verification_message TEXT,
                audit_id TEXT,
                metadata TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_response_actions_env ON response_actions(environment_id);
            CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id);
            CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);

            -- Cryptographic Tamper-Evident Audit Trail Table
            CREATE TABLE IF NOT EXISTS response_audit_log (
                audit_id TEXT PRIMARY KEY,
                sequence_number INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                incident_id TEXT NOT NULL,
                response_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target_identifier TEXT NOT NULL,
                outcome TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_log_env ON response_audit_log(environment_id);
            CREATE INDEX IF NOT EXISTS idx_audit_log_seq ON response_audit_log(environment_id, sequence_number);

            -- User Directory & Refresh Tokens
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                full_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """)


# Global shared engine singleton
_shared_engine: Optional[SQLDatabaseEngine] = None


def get_sql_engine(db_path: Optional[str] = None) -> SQLDatabaseEngine:
    global _shared_engine
    if db_path:
        return SQLDatabaseEngine(db_path)
    if _shared_engine is None:
        _shared_engine = SQLDatabaseEngine()
    return _shared_engine


class SQLIncidentRepository:
    """Durable SQLite-backed Incident Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_incident(self, row: sqlite3.Row) -> IncidentResponse:
        return IncidentResponse(
            id=row["id"],
            title=row["title"],
            severity=row["severity"],
            status=row["status"],
            primaryAffectedAssetId=row["primary_affected_asset_id"],
            relatedAssetIds=json.loads(row["related_asset_ids"]),
            detectionEventIds=json.loads(row["detection_event_ids"]),
            attackPathId=row["attack_path_id"],
            summary=row["summary"],
            environmentId=row["environment_id"],
            correlationKey=row["correlation_key"],
            createdAt=row["created_at"],
            updatedAt=row["updated_at"]
        )

    def create_incident(self, incident: IncidentResponse) -> IncidentResponse:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO incidents (
                    id, title, severity, status, primary_affected_asset_id,
                    related_asset_ids, detection_event_ids, attack_path_id,
                    summary, environment_id, correlation_key, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    severity=excluded.severity,
                    status=excluded.status,
                    primary_affected_asset_id=excluded.primary_affected_asset_id,
                    related_asset_ids=excluded.related_asset_ids,
                    detection_event_ids=excluded.detection_event_ids,
                    attack_path_id=excluded.attack_path_id,
                    summary=excluded.summary,
                    environment_id=excluded.environment_id,
                    correlation_key=excluded.correlation_key,
                    updated_at=excluded.updated_at
            """, (
                incident.id,
                incident.title,
                incident.severity,
                incident.status,
                incident.primaryAffectedAssetId,
                json.dumps(incident.relatedAssetIds),
                json.dumps(incident.detectionEventIds),
                incident.attackPathId,
                incident.summary,
                incident.environmentId,
                incident.correlationKey,
                incident.createdAt,
                incident.updatedAt
            ))
        return incident

    def save_incident(self, incident: IncidentResponse) -> IncidentResponse:
        return self.create_incident(incident)

    def get_incident(self, incident_id: str, environment_id: Optional[str] = None) -> Optional[IncidentResponse]:
        with self.engine.get_connection() as conn:
            if environment_id:
                cur = conn.execute(
                    "SELECT * FROM incidents WHERE id = ? AND environment_id = ?",
                    (incident_id, environment_id)
                )
            else:
                cur = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cur.fetchone()
            return self._row_to_incident(row) if row else None

    def list_incidents(
        self,
        environment_id: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[IncidentResponse]:
        with self.engine.get_connection() as conn:
            query = "SELECT * FROM incidents WHERE 1=1"
            params: List[Any] = []
            if environment_id:
                query += " AND environment_id = ?"
                params.append(environment_id)
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY created_at DESC"
            cur = conn.execute(query, params)
            return [self._row_to_incident(row) for row in cur.fetchall()]

    def update_incident(
        self,
        incident_id: str,
        update_data: Dict[str, Any],
        environment_id: Optional[str] = None
    ) -> Optional[IncidentResponse]:
        inc = self.get_incident(incident_id, environment_id=environment_id)
        if not inc:
            return None
        dump = inc.model_dump()
        dump.update(update_data)
        dump["updatedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        updated = IncidentResponse(**dump)
        return self.save_incident(updated)

    def update_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        environment_id: Optional[str] = None
    ) -> Optional[IncidentResponse]:
        inc = self.get_incident(incident_id, environment_id=environment_id)
        if not inc:
            return None
        allowed = VALID_STATUS_TRANSITIONS.get(inc.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Invalid incident status transition from '{inc.status}' to '{new_status}'. Allowed: {allowed}"
            )
        return self.update_incident(incident_id, {"status": new_status}, environment_id=environment_id)

    def attach_detection(
        self,
        incident_id: str,
        detection_id: str,
        related_asset_id: Optional[str] = None,
        new_severity: Optional[str] = None
    ) -> Optional[IncidentResponse]:
        inc = self.get_incident(incident_id)
        if not inc:
            return None
        det_ids = list(inc.detectionEventIds)
        if detection_id not in det_ids:
            det_ids.append(detection_id)
        updates: Dict[str, Any] = {"detectionEventIds": det_ids}
        if related_asset_id:
            asset_ids = list(inc.relatedAssetIds)
            if related_asset_id not in asset_ids and related_asset_id != inc.primaryAffectedAssetId:
                asset_ids.append(related_asset_id)
            updates["relatedAssetIds"] = asset_ids
        if new_severity and SEVERITY_RANKS.get(new_severity, 0) > SEVERITY_RANKS.get(inc.severity, 0):
            updates["severity"] = new_severity
        return self.update_incident(incident_id, updates)

    def clear(self) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("DELETE FROM incidents")


class SQLDetectionRepository:
    """Durable SQLite-backed Detection Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_detection(self, row: sqlite3.Row) -> DetectionEventResponse:
        return DetectionEventResponse(
            id=row["id"],
            rule=DetectionRuleSummarySchema(
                ruleId=row["rule_id"],
                name=row["rule_name"],
                description=row["rule_description"] or "",
                severity=row["severity"],
                confidence=row["confidence"]
            ),
            matchedEventIds=json.loads(row["matched_event_ids"]),
            primaryAssetId=row["primary_asset_id"],
            timestamp=row["created_at"],
            severity=row["severity"],
            confidence=row["confidence"],
            evidenceSummary=row["evidence_summary"],
            environmentId=row["environment_id"],
            incidentId=row["incident_id"],
            metadata=json.loads(row["metadata"])
        )

    def create_detection(self, detection: DetectionEventResponse) -> DetectionEventResponse:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO detections (
                    id, rule_id, rule_name, rule_description, severity,
                    confidence, primary_asset_id, environment_id, incident_id,
                    matched_event_ids, evidence_summary, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    rule_id=excluded.rule_id,
                    rule_name=excluded.rule_name,
                    rule_description=excluded.rule_description,
                    severity=excluded.severity,
                    confidence=excluded.confidence,
                    primary_asset_id=excluded.primary_asset_id,
                    environment_id=excluded.environment_id,
                    incident_id=excluded.incident_id,
                    matched_event_ids=excluded.matched_event_ids,
                    evidence_summary=excluded.evidence_summary,
                    metadata=excluded.metadata
            """, (
                detection.id,
                detection.rule.ruleId,
                detection.rule.name,
                detection.rule.description,
                detection.severity,
                detection.confidence,
                detection.primaryAssetId,
                detection.environmentId,
                detection.incidentId,
                json.dumps(detection.matchedEventIds),
                detection.evidenceSummary,
                json.dumps(detection.metadata),
                detection.timestamp
            ))
        return detection

    def save_detection(self, detection: DetectionEventResponse) -> DetectionEventResponse:
        return self.create_detection(detection)

    def get_detection(self, detection_id: str, environment_id: Optional[str] = None) -> Optional[DetectionEventResponse]:
        with self.engine.get_connection() as conn:
            if environment_id:
                cur = conn.execute(
                    "SELECT * FROM detections WHERE id = ? AND environment_id = ?",
                    (detection_id, environment_id)
                )
            else:
                cur = conn.execute("SELECT * FROM detections WHERE id = ?", (detection_id,))
            row = cur.fetchone()
            return self._row_to_detection(row) if row else None

    def list_detections(
        self,
        environment_id: Optional[str] = None,
        incident_id: Optional[str] = None
    ) -> List[DetectionEventResponse]:
        with self.engine.get_connection() as conn:
            query = "SELECT * FROM detections WHERE 1=1"
            params: List[Any] = []
            if environment_id:
                query += " AND environment_id = ?"
                params.append(environment_id)
            if incident_id:
                query += " AND incident_id = ?"
                params.append(incident_id)
            query += " ORDER BY created_at DESC"
            cur = conn.execute(query, params)
            return [self._row_to_detection(row) for row in cur.fetchall()]

    def link_to_incident(self, detection_id: str, incident_id: str) -> Optional[DetectionEventResponse]:
        with self.engine.get_connection() as conn:
            conn.execute("UPDATE detections SET incident_id = ? WHERE id = ?", (incident_id, detection_id))
        return self.get_detection(detection_id)

    def clear(self) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("DELETE FROM detections")


class SQLResponseRepository:
    """Durable SQLite-backed Response Action Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_response(self, row: sqlite3.Row) -> ResponseRecordResponse:
        return ResponseRecordResponse(
            id=row["id"],
            incidentId=row["incident_id"],
            environmentId=row["environment_id"],
            actionType=row["action_type"],
            targetType=row["target_type"],
            targetIdentifier=row["target_identifier"],
            status=row["status"],
            reason=row["reason"],
            supportingEvidenceIds=json.loads(row["supporting_evidence_ids"]),
            proposedAt=row["proposed_at"],
            proposedBy=row["proposed_by"],
            approvedAt=row["approved_at"],
            approvedBy=row["approved_by"],
            executedAt=row["executed_at"],
            executionMessage=row["execution_message"],
            verificationStatus=row["verification_status"],
            verificationMessage=row["verification_message"],
            auditId=row["audit_id"],
            metadata=json.loads(row["metadata"])
        )

    def save_response(self, record: ResponseRecordResponse) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO response_actions (
                    id, incident_id, environment_id, action_type, target_type,
                    target_identifier, status, reason, supporting_evidence_ids,
                    proposed_at, proposed_by, approved_at, approved_by,
                    executed_at, execution_message, verification_status,
                    verification_message, audit_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    approved_at=excluded.approved_at,
                    approved_by=excluded.approved_by,
                    executed_at=excluded.executed_at,
                    execution_message=excluded.execution_message,
                    verification_status=excluded.verification_status,
                    verification_message=excluded.verification_message,
                    audit_id=excluded.audit_id,
                    metadata=excluded.metadata
            """, (
                record.id,
                record.incidentId,
                record.environmentId,
                record.actionType,
                record.targetType,
                record.targetIdentifier,
                record.status,
                record.reason,
                json.dumps(record.supportingEvidenceIds),
                record.proposedAt,
                record.proposedBy,
                record.approvedAt,
                record.approvedBy,
                record.executedAt,
                record.executionMessage,
                record.verificationStatus,
                record.verificationMessage,
                record.auditId,
                json.dumps(record.metadata)
            ))

    def get_response(self, response_id: str, environment_id: str) -> Optional[ResponseRecordResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM response_actions WHERE id = ? AND environment_id = ?",
                (response_id, environment_id)
            )
            row = cur.fetchone()
            return self._row_to_response(row) if row else None

    def list_responses(self, environment_id: str, incident_id: Optional[str] = None) -> List[ResponseRecordResponse]:
        with self.engine.get_connection() as conn:
            query = "SELECT * FROM response_actions WHERE environment_id = ?"
            params: List[Any] = [environment_id]
            if incident_id:
                query += " AND incident_id = ?"
                params.append(incident_id)
            query += " ORDER BY proposed_at DESC"
            cur = conn.execute(query, params)
            return [self._row_to_response(row) for row in cur.fetchall()]

    def clear(self) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("DELETE FROM response_actions")


class SQLAuditTrail:
    """Durable SQLite-backed Tamper-Evident Audit Trail."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)
        self._lock = threading.RLock()

    def _row_to_entry(self, row: sqlite3.Row) -> AuditEntryResponse:
        return AuditEntryResponse(
            auditId=row["audit_id"],
            sequenceNumber=row["sequence_number"],
            timestamp=row["timestamp"],
            eventType=row["event_type"],
            actor=row["actor"],
            environmentId=row["environment_id"],
            incidentId=row["incident_id"],
            responseId=row["response_id"],
            actionType=row["action_type"],
            targetIdentifier=row["target_identifier"],
            outcome=row["outcome"],
            details=json.loads(row["details"]),
            previousHash=row["previous_hash"],
            recordHash=row["record_hash"]
        )

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
            with self.engine.get_connection() as conn:
                cur = conn.execute(
                    "SELECT record_hash, sequence_number FROM response_audit_log WHERE environment_id = ? ORDER BY sequence_number DESC LIMIT 1",
                    (environment_id,)
                )
                last_row = cur.fetchone()
                if last_row:
                    prev_hash = last_row["record_hash"]
                    seq_num = last_row["sequence_number"] + 1
                else:
                    prev_hash = GENESIS_HASH
                    seq_num = 1

                now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                import uuid
                audit_id = f"aud-{uuid.uuid4().hex[:12]}"
                clean_details = redact_sensitive_dict(details or {})

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

                conn.execute("""
                    INSERT INTO response_audit_log (
                        audit_id, sequence_number, timestamp, event_type, actor,
                        environment_id, incident_id, response_id, action_type,
                        target_identifier, outcome, details, previous_hash, record_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    audit_id, seq_num, now_iso, event_type, actor,
                    environment_id, incident_id, response_id, action_type,
                    target_identifier, outcome, json.dumps(clean_details),
                    prev_hash, record_hash
                ))

                return AuditEntryResponse(
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

    def get_entries(self, environment_id: str) -> List[AuditEntryResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM response_audit_log WHERE environment_id = ? ORDER BY sequence_number ASC",
                (environment_id,)
            )
            return [self._row_to_entry(row) for row in cur.fetchall()]

    def verify_chain(self, environment_id: str) -> AuditVerificationResult:
        entries = self.get_entries(environment_id)
        if not entries:
            return AuditVerificationResult(
                verified=True,
                totalRecords=0,
                environmentId=environment_id,
                latestHash=GENESIS_HASH,
                error=None
            )

        for idx, entry in enumerate(entries):
            expected_seq = idx + 1
            if entry.sequenceNumber != expected_seq:
                return AuditVerificationResult(
                    verified=False,
                    totalRecords=len(entries),
                    environmentId=environment_id,
                    latestHash=None,
                    error=f"Sequence anomaly at index {idx}: expected {expected_seq}, found {entry.sequenceNumber}"
                )

            expected_prev = entries[idx - 1].recordHash if idx > 0 else GENESIS_HASH
            if entry.previousHash != expected_prev:
                return AuditVerificationResult(
                    verified=False,
                    totalRecords=len(entries),
                    environmentId=environment_id,
                    latestHash=None,
                    error=f"Hash chain broken at sequence {entry.sequenceNumber}: previousHash '{entry.previousHash}' != expected '{expected_prev}'"
                )

            record_data = {
                "auditId": entry.auditId,
                "sequenceNumber": entry.sequenceNumber,
                "timestamp": entry.timestamp,
                "eventType": entry.eventType,
                "actor": entry.actor,
                "environmentId": environment_id,
                "incidentId": entry.incidentId,
                "responseId": entry.responseId,
                "actionType": entry.actionType,
                "targetIdentifier": entry.targetIdentifier,
                "outcome": entry.outcome,
                "details": redact_sensitive_dict(getattr(entry, "details", {}) or {}),
                "previousHash": entry.previousHash
            }
            recomputed = compute_canonical_hash(record_data)
            if recomputed != entry.recordHash:
                return AuditVerificationResult(
                    verified=False,
                    totalRecords=len(entries),
                    environmentId=environment_id,
                    latestHash=None,
                    error=f"Payload tampering detected at sequence {entry.sequenceNumber}: computed '{recomputed}' != stored '{entry.recordHash}'"
                )

        return AuditVerificationResult(
            verified=True,
            totalRecords=len(entries),
            environmentId=environment_id,
            latestHash=entries[-1].recordHash,
            error=None
        )

    def clear(self) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("DELETE FROM response_audit_log")
