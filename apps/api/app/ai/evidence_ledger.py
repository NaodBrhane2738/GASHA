"""
==============================================================================
FILE: apps/api/app/ai/evidence_ledger.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Canonical, immutable internal representation of forensic evidence.
           Extracts, normalizes, sorts, and detects temporal & semantic anomalies
           from InvestigationContext. Serves as the single source of truth for
           deterministic validation and reconciliation.
==============================================================================
"""

import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from pydantic import BaseModel, Field

from app.ai.contracts import (
    InvestigationContext,
    EvidenceItem,
    DetectionContext,
    IncidentContext,
    AssetContext,
    ObservedFact,
    Unknown,
    Inference,
    AttackProgressionItem,
    CompromiseAssessmentType,
    AttributionAssessmentType,
)

logger = logging.getLogger("gasha.ai.evidence_ledger")

# Regex patterns for entities
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SESSION_PATTERN = re.compile(r"\b(?:sess|session)-[a-zA-Z0-9-]+\b", re.IGNORECASE)
ASSET_PATTERN = re.compile(r"\b[a-zA-Z0-9]+-[a-zA-Z0-9]+-\d+\b")


class TemporalAnomaly(BaseModel):
    """Represents an unusual, suspicious, or out-of-order temporal relationship in evidence."""
    anomaly_type: str = Field(..., description="Classification (e.g. RESOURCE_ACCESS_BEFORE_AUTH)")
    description: str = Field(..., description="Explanation of the temporal anomaly")
    earlier_event_id: str
    later_event_id: str
    earlier_timestamp: str
    later_timestamp: str


class EvidenceConflict(BaseModel):
    """Represents a direct contradiction between evidence items."""
    entity: str
    conflict_type: str = Field(..., description="SUCCESS_VS_DENIED, HEALTHY_VS_COMPROMISED, or AUTHORIZATION_REJECTED")
    sources: List[str]
    description: str


class LedgerEntry(BaseModel):
    """Immutable, normalized representation of a single evidence item."""
    evidence_id: str
    incident_id: str
    evidence_type: str
    timestamp_str: Optional[str] = None
    parsed_timestamp: Optional[datetime] = None
    source: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    session_id: Optional[str] = None
    asset_id: Optional[str] = None
    target: Optional[str] = None
    action_type: Optional[str] = None
    raw_result: Optional[str] = None
    is_success: bool = False
    is_attempt: bool = False
    summary: str = ""
    raw_content: Dict[str, Any] = Field(default_factory=dict)
    provenance_type: str = "TELEMETRY"  # TELEMETRY, AUDIT_LOG, CONFIG_DIFF, SECURITY_SCANNER, TICKET_SYSTEM
    is_authoritative_audit: bool = False
    is_rejected_authorization: bool = False


def _parse_iso_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        clean = ts_str.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


def _extract_from_dict_or_summary(
    content: Dict[str, Any],
    summary: str,
    key_candidates: List[str],
) -> Optional[str]:
    for k in key_candidates:
        if k in content and content[k] is not None:
            return str(content[k]).strip()
    return None


class EvidenceLedger:
    """
    Canonical, immutable internal ledger constructed from an InvestigationContext.
    Enforces strict facts, chronological ordering, and temporal anomaly detection.
    """

    def __init__(self, context: InvestigationContext):
        self.context = context
        self.incident_id = context.incident.id if context.incident else "UNKNOWN"
        self.entries: List[LedgerEntry] = []
        self.entry_map: Dict[str, LedgerEntry] = {}
        self.temporal_anomalies: List[TemporalAnomaly] = []
        self.conflicts: List[EvidenceConflict] = []
        self.known_ips: Set[str] = set()
        self.known_sessions: Set[str] = set()
        self.known_users: Set[str] = set()
        self.known_assets: Set[str] = set(context.get_all_asset_ids())

        self._build_ledger()
        self._detect_temporal_anomalies()
        self._detect_evidence_conflicts()

    def _build_ledger(self) -> None:
        """Parses all evidence items, detections, and telemetry into normalized LedgerEntry objects."""
        for ev in self.context.evidence:
            content_dict = ev.content if isinstance(ev.content, dict) else {}
            content_str = str(ev.content)
            combined_text = f"{ev.summary} {content_str}"

            # IP extraction
            source_ip = _extract_from_dict_or_summary(
                content_dict, ev.summary, ["ip", "source_ip", "sourceIp", "clientIp", "remoteIp"]
            )
            if not source_ip:
                ip_match = IP_PATTERN.search(combined_text)
                if ip_match:
                    source_ip = ip_match.group(0)
            if source_ip:
                self.known_ips.add(source_ip)

            # Session extraction
            session_id = _extract_from_dict_or_summary(
                content_dict, ev.summary, ["session", "sessionId", "session_id", "authSession", "token"]
            )
            if not session_id:
                sess_match = SESSION_PATTERN.search(combined_text)
                if sess_match:
                    session_id = sess_match.group(0)
            if session_id:
                self.known_sessions.add(session_id)

            # User extraction
            user = _extract_from_dict_or_summary(
                content_dict, ev.summary, ["user", "username", "userId", "user_id", "principal", "account"]
            )
            if user:
                self.known_users.add(user)

            # Target / Resource / Role extraction
            target = _extract_from_dict_or_summary(
                content_dict, ev.summary, ["target", "path", "uri", "resource", "role", "targetRole"]
            )

            # Result / Status extraction
            raw_result = _extract_from_dict_or_summary(
                content_dict, ev.summary, ["result", "status", "statusCode", "responseCode"]
            )

            # Outcome determination
            comb_lower = combined_text.lower()
            is_success = False
            is_attempt = False

            # Explicit success indicators
            if (
                raw_result in ["SUCCESS", "200", 200, "status': 200", "200 OK"]
                or "result': 'success" in comb_lower
                or "result\": \"success" in comb_lower
                or "status': 'success" in comb_lower
                or "status\": \"success" in comb_lower
                or "auth_success" in comb_lower
                or "login status': 'success" in comb_lower
                or "admin_role assigned with status': 200" in comb_lower
                or "status': 200" in comb_lower
                or "logged in successfully" in comb_lower
                or "success" in comb_lower
                or any(
                    k in comb_lower
                    for k in ["role_escalation", "super_admin", "admin_role", "data_export", "exfil", "compromise_confirmed"]
                )
            ):
                is_success = True

            # Explicit failure / attempt / denial indicators
            if (
                raw_result in ["DENIED", "FAILED", "401", "403", "400", "REJECTED", "FORBIDDEN", 401, 403, 400]
                or "denied" in comb_lower
                or "blocked" in comb_lower
                or "status': 403" in comb_lower
                or "status': 401" in comb_lower
                or "auth_failure" in comb_lower
                or "401" in comb_lower
                or "403" in comb_lower
                or "failed" in comb_lower
                or "rejected" in comb_lower
                or "suspicious_request" in comb_lower
                or "probe" in comb_lower
            ):
                is_attempt = True
                # Only override is_success if explicit failure indicators without success status
                if not (
                    "status': 200" in comb_lower
                    or "result': 'success" in comb_lower
                    or "status': 'success" in comb_lower
                    or "auth_success" in comb_lower
                ):
                    is_success = False

            # Provenance & Authority
            provenance = "TELEMETRY"
            is_audit = False
            is_rejected_auth = False

            if "audit" in ev.source.lower() or "audit" in ev.type.lower() or "audit" in ev.summary.lower():
                provenance = "AUDIT_LOG"
                is_audit = True
            elif ev.type == "CONFIG_DIFF" or "ticket" in ev.source.lower():
                provenance = "TICKET_METADATA"

            if (
                ("rejected" in comb_lower and "ticket" in comb_lower)
                or ("not authorized" in comb_lower and is_audit)
                or ("approved_by=none" in comb_lower.replace(" ", ""))
            ):
                is_rejected_auth = True
                is_audit = True

            parsed_ts = _parse_iso_timestamp(ev.timestamp)

            entry = LedgerEntry(
                evidence_id=ev.id,
                incident_id=self.incident_id,
                evidence_type=ev.type,
                timestamp_str=ev.timestamp,
                parsed_timestamp=parsed_ts,
                source=ev.source,
                source_ip=source_ip,
                user=user,
                session_id=session_id,
                asset_id=getattr(ev, "assetId", None),
                target=target,
                action_type=ev.type,
                raw_result=raw_result,
                is_success=is_success,
                is_attempt=is_attempt,
                summary=ev.summary,
                raw_content=content_dict,
                provenance_type=provenance,
                is_authoritative_audit=is_audit,
                is_rejected_authorization=is_rejected_auth,
            )

            self.entries.append(entry)
            self.entry_map[entry.evidence_id] = entry

        # Sort entries chronologically where timestamps exist
        self.entries.sort(
            key=lambda e: e.parsed_timestamp or datetime.min.replace(tzinfo=timezone.utc)
        )

    def _detect_temporal_anomalies(self) -> None:
        """
        Detects impossible or highly unusual temporal sequences, such as:
        - Resource access SUCCESS preceding recorded authentication SUCCESS.
        """
        timed_entries = [e for e in self.entries if e.parsed_timestamp is not None]
        if len(timed_entries) < 2:
            return

        auth_success_entries = [
            e for e in timed_entries
            if e.is_success and ("auth" in e.summary.lower() or "auth" in str(e.action_type).lower() or "login" in e.summary.lower())
        ]

        for auth_entry in auth_success_entries:
            auth_ts = auth_entry.parsed_timestamp
            for prior_entry in timed_entries:
                if prior_entry.parsed_timestamp and prior_entry.parsed_timestamp < auth_ts:
                    if prior_entry.is_success and prior_entry.evidence_id != auth_entry.evidence_id:
                        p_sum_lower = prior_entry.summary.lower()
                        if "resource_access" in p_sum_lower or "admin" in p_sum_lower or "/admin" in str(prior_entry.target):
                            anomaly = TemporalAnomaly(
                                anomaly_type="RESOURCE_ACCESS_BEFORE_AUTH",
                                description=(
                                    f"Temporal anomaly: Successful resource access '{prior_entry.target or prior_entry.summary}' "
                                    f"({prior_entry.evidence_id}) at {prior_entry.timestamp_str} preceded recorded authentication "
                                    f"success ({auth_entry.evidence_id}) at {auth_entry.timestamp_str}."
                                ),
                                earlier_event_id=prior_entry.evidence_id,
                                later_event_id=auth_entry.evidence_id,
                                earlier_timestamp=prior_entry.timestamp_str or "",
                                later_timestamp=auth_entry.timestamp_str or "",
                            )
                            self.temporal_anomalies.append(anomaly)
                            logger.warning(
                                f"RULE=TEMPORAL_INCONSISTENCY description='{anomaly.description}' incident={self.incident_id}"
                            )

    def _detect_evidence_conflicts(self) -> None:
        """Detects contradictions between evidence items."""
        has_apparent_approval = any(
            e.provenance_type == "TICKET_METADATA"
            or "apparent authorization" in e.summary.lower()
            or "approved" in str(e.raw_content).lower()
            for e in self.entries
        )
        rejected_audits = [
            e for e in self.entries if e.is_rejected_authorization or (e.is_authoritative_audit and e.is_attempt)
        ]

        if has_apparent_approval and rejected_audits:
            audit_ids = [e.evidence_id for e in rejected_audits]
            ticket_ids = [
                e.evidence_id for e in self.entries
                if e.provenance_type == "TICKET_METADATA" or "apparent" in e.summary.lower()
            ]
            conflict = EvidenceConflict(
                entity="CHG_TICKET_AUTHORIZATION",
                conflict_type="AUTHORIZATION_CONTRADICTED_BY_AUDIT",
                sources=ticket_ids + audit_ids,
                description=(
                    f"Contradictory authorization claims: Apparent change ticket approval ({', '.join(ticket_ids)}) "
                    f"is explicitly refuted by authoritative audit evidence ({', '.join(audit_ids)}) showing rejection/unauthorized assignment."
                ),
            )
            self.conflicts.append(conflict)
            logger.warning(
                f"RULE=CONFLICT_DETECTED field={conflict.entity} type={conflict.conflict_type} incident={self.incident_id}"
            )

        grouped: Dict[str, List[LedgerEntry]] = {}
        for e in self.entries:
            key = e.session_id or e.asset_id or e.target or "global"
            grouped.setdefault(key, []).append(e)

        for key, group in grouped.items():
            succ = [e for e in group if e.is_success]
            den = [e for e in group if e.is_attempt and not e.is_success]
            if succ and den and len(succ) > 0 and len(den) > 0:
                s_ids = [e.evidence_id for e in succ]
                d_ids = [e.evidence_id for e in den]
                conflict = EvidenceConflict(
                    entity=key,
                    conflict_type="SUCCESS_VS_DENIED",
                    sources=s_ids + d_ids,
                    description=f"Conflicting telemetry on {key}: Sources {s_ids} report success while {d_ids} report denial/failure.",
                )
                self.conflicts.append(conflict)

    def get_entry(self, evidence_id: str) -> Optional[LedgerEntry]:
        return self.entry_map.get(evidence_id)

    def get_all_material_ids(self) -> Set[str]:
        return set(self.entry_map.keys())

    def validate_fact_consistency(
        self, statement: str, evidence_ids: List[str]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validates that a statement does not claim failure for a SUCCESS evidence item,
        or success for a DENIED/ATTEMPT evidence item.
        """
        stmt_lower = statement.lower()
        for eid in evidence_ids:
            entry = self.get_entry(eid)
            if not entry:
                continue

            # If evidence is strictly SUCCESS
            if entry.is_success and not entry.is_attempt:
                if any(
                    kw in stmt_lower
                    for kw in [
                        "was denied",
                        "denied",
                        "failed",
                        "unsuccessful",
                        "403 forbidden",
                        "401 unauthorized",
                        "blocked by waf",
                        "was rejected",
                    ]
                ):
                    if eid.lower() in stmt_lower or (entry.target and entry.target.lower() in stmt_lower):
                        return (
                            False,
                            "FACT_EVIDENCE_OUTCOME_MISMATCH",
                            f"Statement claims denial/failure but evidence '{eid}' explicitly recorded SUCCESS: '{entry.summary}'",
                        )

            # If evidence is strictly DENIED/ATTEMPT
            if entry.is_attempt and not entry.is_success:
                if any(
                    kw in stmt_lower
                    for kw in [
                        "succeeded",
                        "was successful",
                        "granted super_admin",
                        "obtained admin",
                        "privilege escalation succeeded",
                        "access was granted",
                    ]
                ):
                    if eid.lower() in stmt_lower or (entry.target and entry.target.lower() in stmt_lower):
                        return (
                            False,
                            "FACT_EVIDENCE_OUTCOME_MISMATCH",
                            f"Statement claims success but evidence '{eid}' explicitly recorded DENIED/ATTEMPT: '{entry.summary}'",
                        )

        return (True, None, None)

    def check_missing_material_evidence(self, cited_ids: Set[str]) -> List[LedgerEntry]:
        """Returns material evidence entries that were omitted from cited evidence."""
        missing = []
        for eid, entry in self.entry_map.items():
            if eid not in cited_ids:
                missing.append(entry)
        return missing

    def determine_compromise_and_attribution(
        self,
    ) -> Tuple[CompromiseAssessmentType, AttributionAssessmentType]:
        """
        Deterministically evaluates compromise assessment and attribution using the EvidenceLedger.
        """
        has_rejected_auth = any(e.is_rejected_authorization for e in self.entries)
        has_success_access = any(e.is_success for e in self.entries)

        if has_rejected_auth and has_success_access:
            return "CONFIRMED", "UNCONFIRMED"

        has_privilege_or_exfil = False
        has_any_success = False
        has_only_attempts = True

        for e in self.entries:
            comb = f"{e.summary} {str(e.raw_content)}".lower()
            if any(
                k in comb
                for k in ["super_admin", "admin_role", "exfil", "data_export", "compromise_confirmed", "role_escalation"]
            ):
                has_privilege_or_exfil = True
            if e.is_success:
                has_any_success = True
                has_only_attempts = False

        if has_privilege_or_exfil:
            compromise = "CONFIRMED"
        elif has_any_success:
            compromise = "SUSPECTED"
        elif has_only_attempts and self.entries:
            compromise = "ATTEMPT_ONLY"
        else:
            compromise = "NOT_ESTABLISHED"

        attribution: AttributionAssessmentType = "UNCONFIRMED"
        for e in self.entries:
            comb = f"{e.summary} {str(e.raw_content)}".lower()
            if "apt-" in comb or "threat_actor" in comb:
                attribution = "ESTABLISHED"
                break
            elif "malicious_ip" in comb or "threat" in comb:
                attribution = "CONSISTENT_WITH_THREAT"

        return compromise, attribution
