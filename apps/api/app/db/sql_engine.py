"""
==============================================================================
FILE: apps/api/app/db/sql_engine.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Thread-safe, durable SQL persistence engine using SQLite.
           Provides reliable relational persistence across process restarts,
           satisfying migrations 001, 002, and 003 for:
           incidents, detections, investigations, responses, audit trail,
           users & refresh tokens, assets & relationships, cloud connections & runs,
           vulnerabilities & findings, risk snapshots & history, attack paths,
           and telemetry deduplication.
==============================================================================
"""

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from app.schemas.incident import IncidentResponse, IncidentStatus, VALID_STATUS_TRANSITIONS
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.response import (
    ResponseRecordResponse,
    AuditEntryResponse,
    AuditVerificationResult,
    ResponseActionType,
    ResponseTargetType,
    ResponseStatus,
)
from app.response.audit import compute_canonical_hash, redact_sensitive_dict, GENESIS_HASH
from app.schemas.user import UserRecord, UserRole
from app.core.security import hash_password, verify_password, hash_refresh_token
from app.schemas.investigation import (
    InvestigationResultResponse,
    InvestigationTimelineResponse,
    AttackStorySchema,
    EvidenceSchema,
    RecommendationSchema,
    TimelineEventResponse,
)
from app.schemas.asset import (
    AssetBase,
    AssetResponse,
    RelationshipBase,
    RelationshipResponse,
)
from app.schemas.connection import ConnectionRecord, DiscoveryRunStatus
from app.schemas.vulnerability import (
    VulnerabilityBase,
    VulnerabilityResponse,
    VulnerabilityStatus,
)
from app.schemas.risk import (
    RiskScoreResponse,
    RiskHistoryEntryResponse,
    RiskContributorSchema,
)
from app.schemas.attack_path import (
    AttackPathResponse,
    ReachabilityStatus,
    AttackPathNodeSchema,
)

SEVERITY_RANKS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
DEFAULT_SQLITE_PATH = os.path.join(PROJECT_ROOT, "data", "gasha_storage.db")


def normalize_db_path(path_or_url: Optional[str] = None) -> str:
    """
    Normalizes database URL or file path to an absolute path.
    Prevents relative path bifurcation across different process working directories.
    """
    if not path_or_url or path_or_url == ":memory:":
        return ":memory:"
    raw = path_or_url
    if raw.startswith("sqlite:///"):
        raw = raw[len("sqlite:///"):]
    elif raw.startswith("sqlite://"):
        raw = raw[len("sqlite://"):]

    if os.path.isabs(raw):
        return os.path.normpath(raw)

    return os.path.normpath(os.path.join(PROJECT_ROOT, raw))


class SQLDatabaseEngine:
    """
    Manages SQLite database connection lifecycle, foreign keys, WAL journaling,
    and schema creation based on migrations 001, 002, and 003.
    """

    def __init__(self, db_path: Optional[str] = None):
        raw_target = db_path or os.environ.get("GASHA_DATABASE_PATH") or os.environ.get("DATABASE_URL")
        self.db_path = normalize_db_path(raw_target) if raw_target else DEFAULT_SQLITE_PATH
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
        """Executes DDL to create tables matching migrations 001, 002, and 003."""
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

            CREATE TABLE IF NOT EXISTS investigation_timelines (
                incident_id TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                timeline_data TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, environment_id)
            );

            CREATE INDEX IF NOT EXISTS idx_inv_timelines_env ON investigation_timelines(environment_id);

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
                role TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS system_bootstrap (
                id TEXT PRIMARY KEY,
                provisioned_at TEXT NOT NULL,
                admin_user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL
            );

            -- Migration 003: Assets, Relationships, Findings, Connections, Risk, Paths, Deduplication
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                criticality TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                source TEXT NOT NULL,
                metadata TEXT NOT NULL DEFAULT '{}',
                is_publicly_exposed INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(environment_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_env_source_name ON assets(environment_id, source, name);

            CREATE TABLE IF NOT EXISTS asset_relationships (
                id TEXT PRIMARY KEY,
                source_asset_id TEXT NOT NULL,
                target_asset_id TEXT NOT NULL,
                type TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (source_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY (target_asset_id) REFERENCES assets(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_relationships_env ON asset_relationships(environment_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_relationships_endpoints ON asset_relationships(environment_id, source_asset_id, target_asset_id, type);

            CREATE TABLE IF NOT EXISTS cloud_connections (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                provider TEXT NOT NULL,
                account_name TEXT,
                scope TEXT,
                encrypted_token TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'CONNECTED',
                resource_count INTEGER NOT NULL DEFAULT 0,
                last_sync_at TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_connections_env_prov ON cloud_connections(environment_id, provider);

            CREATE TABLE IF NOT EXISTS discovery_runs (
                id TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                assets_discovered INTEGER NOT NULL DEFAULT 0,
                relationships_discovered INTEGER NOT NULL DEFAULT 0,
                errors TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_runs_env ON discovery_runs(environment_id, started_at DESC);

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                rule_id TEXT,
                cve_id TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL,
                category TEXT NOT NULL,
                remediation_guidance TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                evidence TEXT NOT NULL DEFAULT '{}',
                is_stale INTEGER NOT NULL DEFAULT 0,
                discovered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_env ON vulnerabilities(environment_id);
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset ON vulnerabilities(asset_id);
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_env_asset_rule ON vulnerabilities(environment_id, asset_id, rule_id);

            CREATE TABLE IF NOT EXISTS risk_snapshots (
                environment_id TEXT PRIMARY KEY,
                overall_score REAL NOT NULL,
                calculated_at TEXT NOT NULL,
                critical_assets_at_risk_count INTEGER NOT NULL DEFAULT 0,
                high_risk_vulnerabilities_count INTEGER NOT NULL DEFAULT 0,
                active_attack_paths_count INTEGER NOT NULL DEFAULT 0,
                contributors TEXT NOT NULL DEFAULT '[]',
                explanation TEXT
            );

            CREATE TABLE IF NOT EXISTS risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                environment_id TEXT NOT NULL,
                score REAL NOT NULL,
                timestamp TEXT NOT NULL,
                trigger_event TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_risk_history_env ON risk_history(environment_id, timestamp DESC);

            CREATE TABLE IF NOT EXISTS attack_paths (
                id TEXT NOT NULL,
                environment_id TEXT NOT NULL DEFAULT 'env-prod',
                entry_point_asset_id TEXT NOT NULL,
                target_asset_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                path_score REAL NOT NULL,
                nodes TEXT NOT NULL DEFAULT '[]',
                is_active INTEGER NOT NULL DEFAULT 1,
                reachability TEXT NOT NULL DEFAULT 'REACHABLE',
                discovered_at TEXT NOT NULL,
                mitigated_at TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (environment_id, id)
            );
            CREATE INDEX IF NOT EXISTS idx_attack_paths_env ON attack_paths(environment_id);

            CREATE TABLE IF NOT EXISTS telemetry_deduplication (
                dedup_key TEXT PRIMARY KEY,
                environment_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                timestamp REAL NOT NULL,
                detections TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_dedup_ts ON telemetry_deduplication(timestamp);
            """)

    # Telemetry deduplication helpers
    def get_dedup_record(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT fingerprint, timestamp, detections FROM telemetry_deduplication WHERE dedup_key = ?",
                (dedup_key,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "fingerprint": row["fingerprint"],
                "timestamp": row["timestamp"],
                "detections": json.loads(row["detections"])
            }

    def save_dedup_record(
        self,
        dedup_key: str,
        environment_id: str,
        event_id: str,
        fingerprint: str,
        timestamp: float,
        detections: List[str]
    ) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO telemetry_deduplication (dedup_key, environment_id, event_id, fingerprint, timestamp, detections)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(dedup_key) DO UPDATE SET
                    fingerprint = excluded.fingerprint,
                    timestamp = excluded.timestamp,
                    detections = excluded.detections
            """, (dedup_key, environment_id, event_id, fingerprint, timestamp, json.dumps(detections)))

    def update_dedup_detections(self, dedup_key: str, detections: List[str]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE telemetry_deduplication SET detections = ? WHERE dedup_key = ?",
                (json.dumps(detections), dedup_key)
            )

    def prune_dedup_records(self, before_timestamp: float) -> None:
        with self.get_connection() as conn:
            conn.execute("DELETE FROM telemetry_deduplication WHERE timestamp < ?", (before_timestamp,))

    def clear_dedup_records(self) -> None:
        with self.get_connection() as conn:
            conn.execute("DELETE FROM telemetry_deduplication")


# Global shared engine singleton
_shared_engine: Optional[SQLDatabaseEngine] = None


def get_sql_engine(db_path: Optional[str] = None) -> SQLDatabaseEngine:
    global _shared_engine
    if db_path:
        return SQLDatabaseEngine(db_path)
    current_target = os.environ.get("GASHA_DATABASE_PATH") or os.environ.get("DATABASE_URL")
    normalized_target = normalize_db_path(current_target) if current_target else DEFAULT_SQLITE_PATH
    if _shared_engine is None or _shared_engine.db_path != normalized_target:
        _shared_engine = SQLDatabaseEngine(normalized_target)
    else:
        _shared_engine.init_schema()
    return _shared_engine


def reset_shared_engine() -> None:
    global _shared_engine
    _shared_engine = None


# ==============================================================================
# REPOSITORIES
# ==============================================================================

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


class SQLUserRepository:
    """Durable SQLite-backed User & Refresh Token Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)
        self._lock = threading.RLock()
        self._seed_default_accounts()

    def _seed_default_accounts(self) -> None:
        with self._lock:
            with self.engine.get_connection() as conn:
                cur = conn.execute("SELECT COUNT(*) as cnt FROM users")
                if cur.fetchone()["cnt"] > 0:
                    return

                from app.core.production_guard import is_production_mode
                if is_production_mode():
                    return

                now = datetime.now(timezone.utc).isoformat()
                seeds = [
                    ("usr-analyst-1", "analyst", "AnalystSecure2026!", "security_analyst", "env-prod"),
                    ("usr-operator-1", "operator", "OperatorSecure2026!", "security_operator", "env-prod"),
                    ("usr-admin-1", "admin", "AdminRoot2026!", "admin", "env-prod"),
                    ("usr-emergency-1", "breakglass", "EmergencyRoot2026!", "emergency_admin", "env-prod"),
                    ("usr-analyst-b", "analyst_b", "TenantBSecure2026!", "security_analyst", "env-tenant-b"),
                ]
                for uid, uname, pwd, role, env_id in seeds:
                    conn.execute("""
                        INSERT OR IGNORE INTO users (id, username, password_hash, role, environment_id, is_active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                    """, (uid, uname, hash_password(pwd), role, env_id, now, now))

    def is_system_provisioned(self) -> bool:
        with self._lock:
            with self.engine.get_connection() as conn:
                cur_b = conn.execute("SELECT COUNT(*) as cnt FROM system_bootstrap")
                if cur_b.fetchone()["cnt"] > 0:
                    return True
                cur_u = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE role IN ('admin', 'emergency_admin')")
                return cur_u.fetchone()["cnt"] > 0

    def provision_initial_admin(self, token_hash: str, user: UserRecord) -> UserRecord:
        with self._lock:
            if self.is_system_provisioned():
                raise ValueError("System is already provisioned. Initial provisioning token cannot be reused.")
            with self.engine.get_connection() as conn:
                cur_b = conn.execute("SELECT COUNT(*) as cnt FROM system_bootstrap")
                if cur_b.fetchone()["cnt"] > 0:
                    raise ValueError("System is already provisioned. Initial provisioning token cannot be reused.")
                now_iso = datetime.now(timezone.utc).isoformat()
                try:
                    conn.execute("""
                        INSERT INTO users (id, username, password_hash, role, environment_id, is_active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                    """, (user.id, user.username, user.passwordHash, user.role, user.environmentId, user.createdAt, user.updatedAt))
                    conn.execute("""
                        INSERT INTO system_bootstrap (id, provisioned_at, admin_user_id, token_hash)
                        VALUES (?, ?, ?, ?)
                    """, ("bootstrap_singleton", now_iso, user.id, token_hash))
                except sqlite3.IntegrityError:
                    raise ValueError("System is already provisioned. Initial provisioning token cannot be reused.")
            return user

    def change_password(self, user_id: str, new_password_hash: str) -> bool:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self.engine.get_connection() as conn:
                conn.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                    (new_password_hash, now_iso, user_id)
                )
            self.revoke_all_refresh_tokens(user_id)
            return True

    def _row_to_user(self, row: sqlite3.Row) -> UserRecord:
        return UserRecord(
            id=row["id"],
            username=row["username"],
            passwordHash=row["password_hash"],
            role=row["role"],
            environmentId=row["environment_id"],
            isActive=bool(row["is_active"]),
            createdAt=row["created_at"],
            updatedAt=row["updated_at"]
        )

    def get_by_username(self, username: str) -> Optional[UserRecord]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT * FROM users WHERE lower(username) = ?", (username.strip().lower(),))
            row = cur.fetchone()
            return self._row_to_user(row) if row else None

    def get_by_id(self, user_id: str) -> Optional[UserRecord]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            return self._row_to_user(row) if row else None

    def save_user(self, user: UserRecord) -> UserRecord:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO users (id, username, password_hash, role, environment_id, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    username=excluded.username,
                    password_hash=excluded.password_hash,
                    role=excluded.role,
                    environment_id=excluded.environment_id,
                    is_active=excluded.is_active,
                    updated_at=excluded.updated_at
            """, (
                user.id,
                user.username,
                user.passwordHash,
                user.role,
                user.environmentId,
                1 if user.isActive else 0,
                user.createdAt,
                user.updatedAt
            ))
        return user

    def authenticate(self, username: str, plain_password: str) -> Optional[UserRecord]:
        user = self.get_by_username(username)
        if not user or not user.isActive:
            verify_password("dummy_password", "pbkdf2_sha256$600000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000")
            return None
        if not verify_password(plain_password, user.passwordHash):
            return None
        return user

    def store_refresh_token(self, user_id: str, raw_refresh_token: str, expires_seconds: int = 604800) -> None:
        token_hash = hash_refresh_token(raw_refresh_token)
        expires_at = time.time() + expires_seconds
        now_iso = datetime.now(timezone.utc).isoformat()
        u = self.get_by_id(user_id)
        env_id = u.environmentId if u else "env-prod"

        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO refresh_tokens (token_hash, user_id, environment_id, expires_at, revoked, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                ON CONFLICT(token_hash) DO UPDATE SET
                    expires_at=excluded.expires_at,
                    revoked=0
            """, (token_hash, user_id, env_id, expires_at, now_iso))

    def consume_refresh_token(self, user_id: str, raw_refresh_token: str) -> bool:
        token_hash = hash_refresh_token(raw_refresh_token)
        now = time.time()
        with self._lock:
            with self.engine.get_connection() as conn:
                cur = conn.execute(
                    "SELECT expires_at, revoked FROM refresh_tokens WHERE token_hash = ? AND user_id = ?",
                    (token_hash, user_id)
                )
                row = cur.fetchone()
                if not row:
                    return False
                if row["revoked"] != 0 or now > row["expires_at"]:
                    conn.execute("DELETE FROM refresh_tokens WHERE token_hash = ?", (token_hash,))
                    return False
                # Consume atomically (single use)
                conn.execute("DELETE FROM refresh_tokens WHERE token_hash = ?", (token_hash,))
                return True

    def revoke_all_refresh_tokens(self, user_id: str) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))

    def list_users(self) -> List[UserRecord]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT * FROM users")
            return [self._row_to_user(row) for row in cur.fetchall()]

    def clear(self) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("DELETE FROM refresh_tokens")
            conn.execute("DELETE FROM users")
        self._seed_default_accounts()


class SQLInvestigationRepository:
    """Durable SQLite-backed Investigation Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_investigation(self, row: sqlite3.Row) -> InvestigationResultResponse:
        return InvestigationResultResponse(
            incidentId=row["incident_id"],
            summary=row["summary"],
            severity=row["severity"],
            confidenceScore=row["confidence_score"],
            attackStory=AttackStorySchema(**json.loads(row["attack_story"])),
            groundedEvidence=[EvidenceSchema(**e) for e in json.loads(row["grounded_evidence"])],
            recommendations=[RecommendationSchema(**r) for r in json.loads(row["recommendations"])],
            generatedAt=row["generated_at"]
        )

    def save_investigation(self, result: InvestigationResultResponse, environment_id: str) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO investigations (
                    incident_id, environment_id, summary, severity,
                    confidence_score, attack_story, grounded_evidence,
                    recommendations, generated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    environment_id=excluded.environment_id,
                    summary=excluded.summary,
                    severity=excluded.severity,
                    confidence_score=excluded.confidence_score,
                    attack_story=excluded.attack_story,
                    grounded_evidence=excluded.grounded_evidence,
                    recommendations=excluded.recommendations,
                    generated_at=excluded.generated_at
            """, (
                result.incidentId,
                environment_id,
                result.summary,
                result.severity,
                result.confidenceScore,
                json.dumps(result.attackStory.model_dump()),
                json.dumps([e.model_dump() for e in result.groundedEvidence]),
                json.dumps([r.model_dump() for r in result.recommendations]),
                result.generatedAt
            ))

    def get_investigation(self, incident_id: str, environment_id: str) -> Optional[InvestigationResultResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM investigations WHERE incident_id = ? AND environment_id = ?",
                (incident_id, environment_id)
            )
            row = cur.fetchone()
            return self._row_to_investigation(row) if row else None

    def list_investigations(self, environment_id: str) -> List[InvestigationResultResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM investigations WHERE environment_id = ? ORDER BY generated_at DESC",
                (environment_id,)
            )
            return [self._row_to_investigation(row) for row in cur.fetchall()]

    def save_timeline(self, timeline: InvestigationTimelineResponse) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO investigation_timelines (incident_id, environment_id, timeline_data, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(incident_id, environment_id) DO UPDATE SET
                    timeline_data=excluded.timeline_data,
                    updated_at=excluded.updated_at
            """, (timeline.incidentId, timeline.environmentId, json.dumps(timeline.model_dump()), now_iso))

    def get_timeline(self, incident_id: str, environment_id: str) -> Optional[InvestigationTimelineResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT timeline_data FROM investigation_timelines WHERE incident_id = ? AND environment_id = ?",
                (incident_id, environment_id)
            )
            row = cur.fetchone()
            if not row:
                return None
            return InvestigationTimelineResponse(**json.loads(row["timeline_data"]))

    def clear(self) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("DELETE FROM investigations")
            conn.execute("DELETE FROM investigation_timelines")


class SQLAssetRepository:
    """Durable SQLite-backed Asset and Relationship Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_asset(self, row: sqlite3.Row) -> AssetResponse:
        return AssetResponse(
            id=row["id"],
            name=row["name"],
            type=row["type"],
            criticality=row["criticality"],
            environmentId=row["environment_id"],
            source=row["source"],
            metadata=json.loads(row["metadata"]),
            isPubliclyExposed=bool(row["is_publicly_exposed"]),
            status=row["status"],
            createdAt=row["created_at"],
            updatedAt=row["updated_at"]
        )

    def _row_to_relationship(self, row: sqlite3.Row) -> RelationshipResponse:
        return RelationshipResponse(
            id=row["id"],
            sourceAssetId=row["source_asset_id"],
            targetAssetId=row["target_asset_id"],
            type=row["type"],
            metadata=json.loads(row["metadata"]),
            createdAt=row["created_at"]
        )

    def upsert_asset(self, asset: AssetBase, asset_id: Optional[str] = None) -> AssetResponse:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.engine.get_connection() as conn:
            # Check existing by ID or (env, source, name)
            cur = None
            if asset_id:
                cur = conn.execute(
                    "SELECT * FROM assets WHERE id = ? AND environment_id = ?",
                    (asset_id, asset.environmentId)
                )
            if not cur or not (existing_row := cur.fetchone()):
                cur = conn.execute(
                    "SELECT * FROM assets WHERE environment_id = ? AND source = ? AND name = ?",
                    (asset.environmentId, asset.source, asset.name)
                )
                existing_row = cur.fetchone()

            if existing_row:
                existing = self._row_to_asset(existing_row)
                merged_meta = dict(existing.metadata)
                merged_meta.update(asset.metadata)
                conn.execute("""
                    UPDATE assets SET
                        name = ?, type = ?, criticality = ?, source = ?,
                        metadata = ?, is_publicly_exposed = ?, status = ?, updated_at = ?
                    WHERE id = ? AND environment_id = ?
                """, (
                    asset.name, asset.type, asset.criticality, asset.source,
                    json.dumps(merged_meta), 1 if asset.isPubliclyExposed else 0,
                    asset.status, now_iso, existing.id, asset.environmentId
                ))
                return AssetResponse(
                    id=existing.id,
                    name=asset.name,
                    type=asset.type,
                    criticality=asset.criticality,
                    environmentId=asset.environmentId,
                    source=asset.source,
                    metadata=merged_meta,
                    isPubliclyExposed=asset.isPubliclyExposed,
                    status=asset.status,
                    createdAt=existing.createdAt,
                    updatedAt=now_iso
                )

            # Insert new
            new_id = asset_id or f"asset-{uuid.uuid4().hex[:12]}"
            conn.execute("""
                INSERT INTO assets (
                    id, name, type, criticality, environment_id, source,
                    metadata, is_publicly_exposed, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_id, asset.name, asset.type, asset.criticality, asset.environmentId, asset.source,
                json.dumps(asset.metadata), 1 if asset.isPubliclyExposed else 0, asset.status,
                now_iso, now_iso
            ))
            return AssetResponse(
                id=new_id,
                name=asset.name,
                type=asset.type,
                criticality=asset.criticality,
                environmentId=asset.environmentId,
                source=asset.source,
                metadata=asset.metadata,
                isPubliclyExposed=asset.isPubliclyExposed,
                status=asset.status,
                createdAt=now_iso,
                updatedAt=now_iso
            )

    def upsert_relationship(
        self,
        rel: RelationshipBase,
        rel_id: Optional[str] = None,
        environment_id: str = "env-prod"
    ) -> RelationshipResponse:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.engine.get_connection() as conn:
            cur = conn.execute("""
                SELECT * FROM asset_relationships
                WHERE environment_id = ? AND source_asset_id = ? AND target_asset_id = ? AND type = ?
            """, (environment_id, rel.sourceAssetId, rel.targetAssetId, rel.type))
            existing_row = cur.fetchone()

            if existing_row:
                existing = self._row_to_relationship(existing_row)
                merged_meta = dict(existing.metadata)
                merged_meta.update(rel.metadata)
                conn.execute("""
                    UPDATE asset_relationships SET metadata = ? WHERE id = ?
                """, (json.dumps(merged_meta), existing.id))
                return RelationshipResponse(
                    id=existing.id,
                    sourceAssetId=rel.sourceAssetId,
                    targetAssetId=rel.targetAssetId,
                    type=rel.type,
                    metadata=merged_meta,
                    createdAt=existing.createdAt
                )

            new_id = rel_id or f"rel-{uuid.uuid4().hex[:12]}"
            conn.execute("""
                INSERT INTO asset_relationships (
                    id, source_asset_id, target_asset_id, type, environment_id, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                new_id, rel.sourceAssetId, rel.targetAssetId, rel.type,
                environment_id, json.dumps(rel.metadata), now_iso
            ))
            return RelationshipResponse(
                id=new_id,
                sourceAssetId=rel.sourceAssetId,
                targetAssetId=rel.targetAssetId,
                type=rel.type,
                metadata=rel.metadata,
                createdAt=now_iso
            )

    def get_asset(self, asset_id: str, environment_id: str) -> Optional[AssetResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT * FROM assets WHERE id = ? AND environment_id = ?", (asset_id, environment_id))
            row = cur.fetchone()
            return self._row_to_asset(row) if row else None

    def get_asset_by_name(self, name: str, environment_id: str) -> Optional[AssetResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT * FROM assets WHERE name = ? AND environment_id = ?", (name, environment_id))
            row = cur.fetchone()
            return self._row_to_asset(row) if row else None

    def list_assets(
        self,
        environment_id: str,
        asset_type: Optional[str] = None,
        source: Optional[str] = None
    ) -> List[AssetResponse]:
        with self.engine.get_connection() as conn:
            query = "SELECT * FROM assets WHERE environment_id = ?"
            params: List[Any] = [environment_id]
            if asset_type:
                query += " AND type = ?"
                params.append(asset_type)
            if source:
                query += " AND source = ?"
                params.append(source)
            query += " ORDER BY created_at ASC"
            cur = conn.execute(query, params)
            return [self._row_to_asset(row) for row in cur.fetchall()]

    def list_relationships(self, environment_id: str) -> List[RelationshipResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM asset_relationships WHERE environment_id = ? ORDER BY created_at ASC",
                (environment_id,)
            )
            return [self._row_to_relationship(row) for row in cur.fetchall()]

    def count_assets(self, environment_id: str) -> int:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) as cnt FROM assets WHERE environment_id = ?", (environment_id,))
            return cur.fetchone()["cnt"]

    def count_relationships(self, environment_id: str) -> int:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) as cnt FROM asset_relationships WHERE environment_id = ?", (environment_id,))
            return cur.fetchone()["cnt"]

    def clear(self, environment_id: Optional[str] = None) -> None:
        with self.engine.get_connection() as conn:
            if environment_id:
                conn.execute("DELETE FROM asset_relationships WHERE environment_id = ?", (environment_id,))
                conn.execute("DELETE FROM assets WHERE environment_id = ?", (environment_id,))
            else:
                conn.execute("DELETE FROM asset_relationships")
                conn.execute("DELETE FROM assets")


class SQLConnectionRepository:
    """Durable SQLite-backed Cloud Connection and Discovery Run Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_connection(self, row: sqlite3.Row) -> ConnectionRecord:
        return ConnectionRecord(
            id=row["id"],
            provider=row["provider"],
            environmentId=row["environment_id"],
            accountName=row["account_name"],
            scope=row["scope"],
            encryptedToken=row["encrypted_token"],
            status=row["status"],
            resourceCount=row["resource_count"],
            lastSyncAt=row["last_sync_at"],
            errorMessage=row["error_message"],
            createdAt=row["created_at"],
            updatedAt=row["updated_at"]
        )

    def _row_to_run(self, row: sqlite3.Row) -> DiscoveryRunStatus:
        return DiscoveryRunStatus(
            id=row["id"],
            environmentId=row["environment_id"],
            provider=row["provider"],
            status=row["status"],
            startedAt=row["started_at"],
            completedAt=row["completed_at"],
            assetsDiscovered=row["assets_discovered"],
            relationshipsDiscovered=row["relationships_discovered"],
            errors=json.loads(row["errors"])
        )

    def save_connection(self, record: ConnectionRecord) -> ConnectionRecord:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO cloud_connections (
                    id, environment_id, provider, account_name, scope,
                    encrypted_token, status, resource_count, last_sync_at,
                    error_message, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(environment_id, provider) DO UPDATE SET
                    id=excluded.id,
                    account_name=excluded.account_name,
                    scope=excluded.scope,
                    encrypted_token=excluded.encrypted_token,
                    status=excluded.status,
                    resource_count=excluded.resource_count,
                    last_sync_at=excluded.last_sync_at,
                    error_message=excluded.error_message,
                    updated_at=excluded.updated_at
            """, (
                record.id,
                record.environmentId,
                record.provider.upper(),
                record.accountName,
                record.scope,
                record.encryptedToken,
                record.status,
                record.resourceCount,
                record.lastSyncAt,
                record.errorMessage,
                record.createdAt,
                record.updatedAt
            ))
            return record

    def get_connection(self, environment_id: str, provider: str) -> Optional[ConnectionRecord]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM cloud_connections WHERE environment_id = ? AND provider = ?",
                (environment_id, provider.upper())
            )
            row = cur.fetchone()
            return self._row_to_connection(row) if row else None

    def list_connections(self, environment_id: str) -> List[ConnectionRecord]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT * FROM cloud_connections WHERE environment_id = ?", (environment_id,))
            return [self._row_to_connection(row) for row in cur.fetchall()]

    def delete_connection(self, environment_id: str, provider: str) -> bool:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM cloud_connections WHERE environment_id = ? AND provider = ?",
                (environment_id, provider.upper())
            )
            return cur.rowcount > 0

    def update_sync_status(
        self,
        environment_id: str,
        provider: str,
        resource_count: int,
        last_sync_at: str,
        status: str = "CONNECTED",
        error: Optional[str] = None
    ) -> Optional[ConnectionRecord]:
        conn_rec = self.get_connection(environment_id, provider)
        if not conn_rec:
            return None
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.engine.get_connection() as conn:
            conn.execute("""
                UPDATE cloud_connections SET
                    resource_count = ?, last_sync_at = ?, status = ?,
                    error_message = ?, updated_at = ?
                WHERE environment_id = ? AND provider = ?
            """, (resource_count, last_sync_at, status, error, now_iso, environment_id, provider.upper()))
        return self.get_connection(environment_id, provider)

    def record_run(self, run: DiscoveryRunStatus) -> DiscoveryRunStatus:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO discovery_runs (
                    id, environment_id, provider, status, started_at,
                    completed_at, assets_discovered, relationships_discovered, errors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    completed_at=excluded.completed_at,
                    assets_discovered=excluded.assets_discovered,
                    relationships_discovered=excluded.relationships_discovered,
                    errors=excluded.errors
            """, (
                run.id,
                run.environmentId,
                run.provider,
                run.status,
                run.startedAt,
                run.completedAt,
                run.assetsDiscovered,
                run.relationshipsDiscovered,
                json.dumps(run.errors)
            ))
            return run

    def get_recent_runs(self, environment_id: str, limit: int = 10) -> List[DiscoveryRunStatus]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM discovery_runs WHERE environment_id = ? ORDER BY started_at DESC LIMIT ?",
                (environment_id, limit)
            )
            return [self._row_to_run(row) for row in cur.fetchall()]

    def get_latest_run(self, environment_id: str) -> Optional[DiscoveryRunStatus]:
        runs = self.get_recent_runs(environment_id, limit=1)
        return runs[0] if runs else None

    def clear(self, environment_id: Optional[str] = None) -> None:
        with self.engine.get_connection() as conn:
            if environment_id:
                conn.execute("DELETE FROM cloud_connections WHERE environment_id = ?", (environment_id,))
                conn.execute("DELETE FROM discovery_runs WHERE environment_id = ?", (environment_id,))
            else:
                conn.execute("DELETE FROM cloud_connections")
                conn.execute("DELETE FROM discovery_runs")


class SQLVulnerabilityRepository:
    """Durable SQLite-backed Vulnerability and Security Findings Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_vuln(self, row: sqlite3.Row) -> VulnerabilityResponse:
        return VulnerabilityResponse(
            id=row["id"],
            assetId=row["asset_id"],
            environmentId=row["environment_id"],
            ruleId=row["rule_id"],
            cveId=row["cve_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            cvssScore=row["cvss_score"],
            category=row["category"],
            remediationGuidance=row["remediation_guidance"],
            status=row["status"],
            evidence=json.loads(row["evidence"]),
            isStale=bool(row["is_stale"]),
            discoveredAt=row["discovered_at"],
            updatedAt=row["updated_at"]
        )

    def upsert_finding(
        self,
        finding: VulnerabilityBase,
        finding_id: Optional[str] = None
    ) -> VulnerabilityResponse:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.engine.get_connection() as conn:
            cur = None
            if finding_id:
                cur = conn.execute(
                    "SELECT * FROM vulnerabilities WHERE id = ? AND environment_id = ?",
                    (finding_id, finding.environmentId)
                )
            if not cur or not (existing_row := cur.fetchone()):
                cur = conn.execute("""
                    SELECT * FROM vulnerabilities
                    WHERE environment_id = ? AND asset_id = ? AND (rule_id = ? OR title = ?)
                """, (finding.environmentId, finding.assetId, finding.ruleId, finding.title))
                existing_row = cur.fetchone()

            if existing_row:
                existing = self._row_to_vuln(existing_row)
                merged_evidence = dict(existing.evidence)
                merged_evidence.update(finding.evidence)
                cve = finding.cveId or existing.cveId
                cvss = finding.cvssScore if finding.cvssScore is not None else existing.cvssScore

                conn.execute("""
                    UPDATE vulnerabilities SET
                        cve_id = ?, title = ?, description = ?, severity = ?,
                        cvss_score = ?, category = ?, remediation_guidance = ?,
                        status = ?, evidence = ?, is_stale = ?, updated_at = ?
                    WHERE id = ? AND environment_id = ?
                """, (
                    cve, finding.title, finding.description, finding.severity,
                    cvss, finding.category, finding.remediationGuidance,
                    finding.status, json.dumps(merged_evidence), 1 if finding.isStale else 0,
                    now_iso, existing.id, finding.environmentId
                ))
                return VulnerabilityResponse(
                    id=existing.id,
                    assetId=finding.assetId,
                    environmentId=finding.environmentId,
                    ruleId=finding.ruleId,
                    cveId=cve,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    cvssScore=cvss,
                    category=finding.category,
                    remediationGuidance=finding.remediationGuidance,
                    status=finding.status,
                    evidence=merged_evidence,
                    isStale=finding.isStale,
                    discoveredAt=existing.discoveredAt,
                    updatedAt=now_iso
                )

            clean_rule = (finding.ruleId or "rule").lower().replace("_", "-")
            clean_asset = finding.assetId.lower().replace("_", "-")
            new_id = finding_id or f"vuln-{clean_asset}-{clean_rule}"

            conn.execute("""
                INSERT INTO vulnerabilities (
                    id, asset_id, environment_id, rule_id, cve_id, title,
                    description, severity, cvss_score, category,
                    remediation_guidance, status, evidence, is_stale,
                    discovered_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_id, finding.assetId, finding.environmentId, finding.ruleId, finding.cveId,
                finding.title, finding.description, finding.severity, finding.cvssScore,
                finding.category, finding.remediationGuidance, finding.status,
                json.dumps(finding.evidence), 1 if finding.isStale else 0, now_iso, now_iso
            ))

            return VulnerabilityResponse(
                id=new_id,
                assetId=finding.assetId,
                environmentId=finding.environmentId,
                ruleId=finding.ruleId,
                cveId=finding.cveId,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                cvssScore=finding.cvssScore,
                category=finding.category,
                remediationGuidance=finding.remediationGuidance,
                status=finding.status,
                evidence=finding.evidence,
                isStale=finding.isStale,
                discoveredAt=now_iso,
                updatedAt=now_iso
            )

    def get_finding(self, vuln_id: str, environment_id: str) -> Optional[VulnerabilityResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM vulnerabilities WHERE id = ? AND environment_id = ?",
                (vuln_id, environment_id)
            )
            row = cur.fetchone()
            return self._row_to_vuln(row) if row else None

    def list_findings(
        self,
        environment_id: str,
        asset_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[VulnerabilityResponse]:
        with self.engine.get_connection() as conn:
            query = "SELECT * FROM vulnerabilities WHERE environment_id = ?"
            params: List[Any] = [environment_id]
            if asset_id:
                query += " AND asset_id = ?"
                params.append(asset_id)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if status:
                query += " AND status = ?"
                params.append(status)
            if category:
                query += " AND category = ?"
                params.append(category)
            query += " ORDER BY discovered_at DESC"
            cur = conn.execute(query, params)
            return [self._row_to_vuln(row) for row in cur.fetchall()]

    def update_status(
        self,
        vuln_id: str,
        environment_id: str,
        status: VulnerabilityStatus
    ) -> Optional[VulnerabilityResponse]:
        existing = self.get_finding(vuln_id, environment_id)
        if not existing:
            return None
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.engine.get_connection() as conn:
            conn.execute(
                "UPDATE vulnerabilities SET status = ?, updated_at = ? WHERE id = ? AND environment_id = ?",
                (status, now_iso, vuln_id, environment_id)
            )
        return self.get_finding(vuln_id, environment_id)

    def clear(self, environment_id: Optional[str] = None) -> None:
        with self.engine.get_connection() as conn:
            if environment_id:
                conn.execute("DELETE FROM vulnerabilities WHERE environment_id = ?", (environment_id,))
            else:
                conn.execute("DELETE FROM vulnerabilities")


class SQLRiskRepository:
    """Durable SQLite-backed Risk Scoring and History Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def save_current_risk(self, risk: RiskScoreResponse) -> RiskScoreResponse:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO risk_snapshots (
                    environment_id, overall_score, calculated_at,
                    critical_assets_at_risk_count, high_risk_vulnerabilities_count,
                    active_attack_paths_count, contributors, explanation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(environment_id) DO UPDATE SET
                    overall_score=excluded.overall_score,
                    calculated_at=excluded.calculated_at,
                    critical_assets_at_risk_count=excluded.critical_assets_at_risk_count,
                    high_risk_vulnerabilities_count=excluded.high_risk_vulnerabilities_count,
                    active_attack_paths_count=excluded.active_attack_paths_count,
                    contributors=excluded.contributors,
                    explanation=excluded.explanation
            """, (
                risk.environmentId,
                risk.overallScore,
                risk.calculatedAt,
                risk.criticalAssetsAtRiskCount,
                risk.highRiskVulnerabilitiesCount,
                risk.activeAttackPathsCount,
                json.dumps([c.model_dump() for c in risk.contributors]),
                json.dumps(risk.explanation) if risk.explanation else None
            ))

            # Add to history
            conn.execute("""
                INSERT INTO risk_history (environment_id, score, timestamp, trigger_event)
                VALUES (?, ?, ?, ?)
            """, (risk.environmentId, risk.overallScore, risk.calculatedAt, "Risk Recalculation"))

        return risk

    def get_current_risk(self, environment_id: str) -> Optional[RiskScoreResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("SELECT * FROM risk_snapshots WHERE environment_id = ?", (environment_id,))
            row = cur.fetchone()
            if not row:
                return None
            return RiskScoreResponse(
                overallScore=row["overall_score"],
                criticalAssetsAtRiskCount=row["critical_assets_at_risk_count"],
                highRiskVulnerabilitiesCount=row["high_risk_vulnerabilities_count"],
                activeAttackPathsCount=row["active_attack_paths_count"],
                contributors=[RiskContributorSchema(**c) for c in json.loads(row["contributors"])],
                calculatedAt=row["calculated_at"],
                environmentId=row["environment_id"],
                explanation=json.loads(row["explanation"]) if row["explanation"] else None
            )

    def add_history_entry(self, entry: RiskHistoryEntryResponse) -> None:
        with self.engine.get_connection() as conn:
            conn.execute("""
                INSERT INTO risk_history (environment_id, score, timestamp, trigger_event)
                VALUES (?, ?, ?, ?)
            """, (entry.environmentId, entry.score, entry.timestamp, entry.triggerEvent))

    def get_history(self, environment_id: str, limit: int = 50) -> List[RiskHistoryEntryResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute("""
                SELECT * FROM (
                    SELECT * FROM risk_history WHERE environment_id = ? ORDER BY id DESC LIMIT ?
                ) ORDER BY id ASC
            """, (environment_id, limit))
            return [
                RiskHistoryEntryResponse(
                    timestamp=row["timestamp"],
                    score=row["score"],
                    triggerEvent=row["trigger_event"],
                    environmentId=row["environment_id"]
                ) for row in cur.fetchall()
            ]

    def clear(self, environment_id: Optional[str] = None) -> None:
        with self.engine.get_connection() as conn:
            if environment_id:
                conn.execute("DELETE FROM risk_snapshots WHERE environment_id = ?", (environment_id,))
                conn.execute("DELETE FROM risk_history WHERE environment_id = ?", (environment_id,))
            else:
                conn.execute("DELETE FROM risk_snapshots")
                conn.execute("DELETE FROM risk_history")


class SQLAttackPathRepository:
    """Durable SQLite-backed Attack Path Repository."""

    def __init__(self, engine: Optional[SQLDatabaseEngine] = None, db_path: Optional[str] = None):
        self.engine = engine or get_sql_engine(db_path)

    def _row_to_path(self, row: sqlite3.Row) -> AttackPathResponse:
        return AttackPathResponse(
            id=row["id"],
            environmentId=row["environment_id"],
            entryPointAssetId=row["entry_point_asset_id"],
            targetAssetId=row["target_asset_id"],
            severity=row["severity"],
            pathScore=row["path_score"],
            nodes=[AttackPathNodeSchema(**n) for n in json.loads(row["nodes"])],
            isActive=bool(row["is_active"]),
            reachability=row["reachability"],
            discoveredAt=row["discovered_at"],
            mitigatedAt=row["mitigated_at"],
            metadata=json.loads(row["metadata"])
        )

    def save_attack_paths(self, environment_id: str, paths: List[AttackPathResponse]) -> None:
        with self.engine.get_connection() as conn:
            # Clear previous paths for this environment
            conn.execute("DELETE FROM attack_paths WHERE environment_id = ?", (environment_id,))
            for p in paths:
                conn.execute("""
                    INSERT INTO attack_paths (
                        id, environment_id, entry_point_asset_id, target_asset_id,
                        severity, path_score, nodes, is_active, reachability,
                        discovered_at, mitigated_at, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    p.id,
                    environment_id,
                    p.entryPointAssetId,
                    p.targetAssetId,
                    p.severity,
                    p.pathScore,
                    json.dumps([n.model_dump() for n in p.nodes]),
                    1 if p.isActive else 0,
                    p.reachability,
                    p.discoveredAt,
                    p.mitigatedAt,
                    json.dumps(p.metadata)
                ))

    def list_attack_paths(
        self,
        environment_id: str,
        is_active: Optional[bool] = None,
        reachability: Optional[ReachabilityStatus] = None
    ) -> List[AttackPathResponse]:
        with self.engine.get_connection() as conn:
            query = "SELECT * FROM attack_paths WHERE environment_id = ?"
            params: List[Any] = [environment_id]
            if is_active is not None:
                query += " AND is_active = ?"
                params.append(1 if is_active else 0)
            if reachability is not None:
                query += " AND reachability = ?"
                params.append(reachability)
            query += " ORDER BY path_score DESC"
            cur = conn.execute(query, params)
            return [self._row_to_path(row) for row in cur.fetchall()]

    def get_attack_path(self, path_id: str, environment_id: str) -> Optional[AttackPathResponse]:
        with self.engine.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM attack_paths WHERE id = ? AND environment_id = ?",
                (path_id, environment_id)
            )
            row = cur.fetchone()
            return self._row_to_path(row) if row else None

    def update_path_reachability(
        self,
        path_id: str,
        environment_id: str,
        is_active: bool,
        reachability: ReachabilityStatus,
        mitigated_at: Optional[str] = None
    ) -> Optional[AttackPathResponse]:
        existing = self.get_attack_path(path_id, environment_id)
        if not existing:
            return None
        mitigated = mitigated_at or (datetime.now(timezone.utc).isoformat() if not is_active else None)
        score = 0.0 if not is_active else existing.pathScore

        with self.engine.get_connection() as conn:
            conn.execute("""
                UPDATE attack_paths SET
                    is_active = ?, reachability = ?, mitigated_at = ?, path_score = ?
                WHERE id = ? AND environment_id = ?
            """, (1 if is_active else 0, reachability, mitigated, score, path_id, environment_id))

        return self.get_attack_path(path_id, environment_id)

    def clear(self, environment_id: Optional[str] = None) -> None:
        with self.engine.get_connection() as conn:
            if environment_id:
                conn.execute("DELETE FROM attack_paths WHERE environment_id = ?", (environment_id,))
            else:
                conn.execute("DELETE FROM attack_paths")
