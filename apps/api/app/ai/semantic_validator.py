"""
==============================================================================
FILE: apps/api/app/ai/semantic_validator.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Deterministic semantic validation, evidence reconciliation,
           identifier grounding, and conflict handling for GASHA AI investigations.
==============================================================================
"""

import re
import logging
from typing import List, Dict, Set, Tuple, Any, Optional
from pydantic import BaseModel, Field

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AIRecommendation,
    ObservedFact,
    Unknown,
    Inference,
    AttackProgressionItem,
)
from app.ai.evidence_ledger import (
    EvidenceLedger,
    LedgerEntry,
    TemporalAnomaly,
    EvidenceConflict,
)

logger = logging.getLogger("gasha.ai.semantic_validator")


class SemanticValidationEvent(BaseModel):
    rule: str
    field: str
    value: str
    reason: str
    incidentId: str


class ConflictEvent(BaseModel):
    entity: str
    conflict_type: str
    sources: List[str]
    description: str


GASHA_ALLOWED_ATTACK_PHASES = {
    "RECONNAISSANCE",
    "PROBING",
    "AUTHENTICATION",
    "INITIAL_ACCESS",
    "RESOURCE_ACCESS",
    "PRIVILEGE_ATTEMPT",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "PERSISTENCE",
    "EXFILTRATION",
    "IMPACT",
    "OBSERVED_ACTIVITY",
}


def normalize_attack_phase(phase: str) -> str:
    if not phase:
        return "OBSERVED_ACTIVITY"
    upper_phase = phase.upper().strip().replace("-", "_").replace(" ", "_")
    if upper_phase in GASHA_ALLOWED_ATTACK_PHASES:
        return upper_phase

    # Standard mapping for common non-standard phases
    mapping = {
        "LATERAL_MOBILIZATION": "LATERAL_MOVEMENT",
        "PRE_EXPLOITATION": "INITIAL_ACCESS",
        "COMMAND_AND_CONTROL": "PERSISTENCE",
        "C2": "PERSISTENCE",
        "EXECUTION": "RESOURCE_ACCESS",
        "CREDENTIAL_ACCESS": "AUTHENTICATION",
        "DEFENSE_EVASION": "OBSERVED_ACTIVITY",
        "DISCOVERY": "PROBING",
        "COLLECTION": "RESOURCE_ACCESS",
    }
    return mapping.get(upper_phase, "OBSERVED_ACTIVITY")


def extract_known_identifiers(context: InvestigationContext) -> Dict[str, Set[str]]:
    """Extracts all known valid identifiers from context."""
    ledger = EvidenceLedger(context)
    return {
        "ips": ledger.known_ips,
        "sessions": ledger.known_sessions,
        "users": ledger.known_users,
        "assets": ledger.known_assets,
        "detections": set(d.id for d in context.detections),
        "incident_id": context.incident.id if context.incident else "",
    }


def scan_text_for_identifiers(text: str) -> Dict[str, Set[str]]:
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    session_pattern = re.compile(r"\b(?:sess|session)-[a-zA-Z0-9-]+\b", re.IGNORECASE)

    ips = set(ip_pattern.findall(text))
    sessions = set(session_pattern.findall(text))

    return {"ips": ips, "sessions": sessions}


def validate_identifier_grounding(
    context: InvestigationContext,
    result: AIInvestigationResult,
    ledger: Optional[EvidenceLedger] = None,
) -> List[SemanticValidationEvent]:
    """
    Validates that free-text prose does not contain ungrounded/corrupted IP addresses,
    session IDs, or fabricated asset identifiers.
    """
    ledger = ledger or EvidenceLedger(context)
    known_ips = ledger.known_ips
    known_sessions = ledger.known_sessions
    known_assets = ledger.known_assets
    events: List[SemanticValidationEvent] = []

    text_fields = {
        "summary": result.summary,
    }
    for i, fact in enumerate(result.observedFacts):
        text_fields[f"observedFacts[{i}].statement"] = fact.statement
    for i, inf in enumerate(result.inferences):
        text_fields[f"inferences[{i}].statement"] = inf.statement
        text_fields[f"inferences[{i}].rationale"] = inf.rationale
    for i, stage in enumerate(result.attackProgression):
        text_fields[f"attackProgression[{i}].description"] = stage.description
    for i, rec in enumerate(result.recommendedActions):
        text_fields[f"recommendations[{i}].rationale"] = rec.rationale

    asset_pattern = re.compile(r"\b[a-zA-Z]+-[a-zA-Z]+-\d+\b")

    for field, text in text_fields.items():
        if not text:
            continue
        found = scan_text_for_identifiers(text)
        for ip in found["ips"]:
            if ip not in known_ips:
                events.append(
                    SemanticValidationEvent(
                        rule="INVALID_IDENTIFIER",
                        field=field,
                        value=ip,
                        reason="IP address not found in evidence context.",
                        incidentId=result.incidentId,
                    )
                )
        for sess in found["sessions"]:
            if sess not in known_sessions:
                events.append(
                    SemanticValidationEvent(
                        rule="INVALID_IDENTIFIER",
                        field=field,
                        value=sess,
                        reason="Session ID not found in evidence context.",
                        incidentId=result.incidentId,
                    )
                )
        for match in asset_pattern.findall(text):
            if match not in known_assets and match not in known_sessions:
                events.append(
                    SemanticValidationEvent(
                        rule="INVALID_IDENTIFIER",
                        field=field,
                        value=match,
                        reason="Invented asset or entity ID not in context.",
                        incidentId=result.incidentId,
                    )
                )

    for ev in events:
        logger.warning(
            f"RULE={ev.rule} field={ev.field} value={ev.value} reason={ev.reason} incident={ev.incidentId}"
        )

    return events


def validate_nl_identifiers(
    context: InvestigationContext, text_fields: Dict[str, str]
) -> List[SemanticValidationEvent]:
    ledger = EvidenceLedger(context)
    events: List[SemanticValidationEvent] = []
    asset_pattern = re.compile(r"\b[a-zA-Z]+-[a-zA-Z]+-\d+\b")
    incident_id = context.incident.id if context.incident else ""

    for field, text in text_fields.items():
        if not text:
            continue
        found = scan_text_for_identifiers(text)
        for ip in found["ips"]:
            if ip not in ledger.known_ips:
                events.append(
                    SemanticValidationEvent(
                        rule="INVALID_IDENTIFIER",
                        field=field,
                        value=ip,
                        reason="IP address not found in evidence context.",
                        incidentId=incident_id,
                    )
                )
        for sess in found["sessions"]:
            if sess not in ledger.known_sessions:
                events.append(
                    SemanticValidationEvent(
                        rule="INVALID_IDENTIFIER",
                        field=field,
                        value=sess,
                        reason="Session ID not found in evidence context.",
                        incidentId=incident_id,
                    )
                )
        for match in asset_pattern.findall(text):
            if match not in ledger.known_assets and match not in ledger.known_sessions:
                events.append(
                    SemanticValidationEvent(
                        rule="INVALID_IDENTIFIER",
                        field=field,
                        value=match,
                        reason="Invented asset or entity ID not in context.",
                        incidentId=incident_id,
                    )
                )

    return events


def validate_attack_phases(
    context: InvestigationContext,
    result: AIInvestigationResult,
    ledger: Optional[EvidenceLedger] = None,
) -> Tuple[List[str], AIInvestigationResult]:
    """
    Validates attack progression phases against controlled vocabulary and evidence grounding.
    """
    ledger = ledger or EvidenceLedger(context)
    warnings: List[str] = []

    has_success_privilege = any(
        e.is_success and ("role" in e.summary.lower() or "admin" in e.summary.lower() or "privilege" in e.summary.lower())
        for e in ledger.entries
    )
    has_exfil = any("exfil" in e.summary.lower() or "data_export" in e.summary.lower() for e in ledger.entries)
    movement_kws = ["ssh", "rdp", "smb", "psexec", "lateral"]
    has_multi_asset_movement = (
        any(
            kw in f"{e.summary} {str(e.raw_content)}".lower()
            for e in ledger.entries
            for kw in movement_kws
        )
        and len(ledger.known_assets) > 1
    )

    for i, step in enumerate(result.attackProgression):
        orig_phase = step.phase or "OBSERVED_ACTIVITY"
        normalized = normalize_attack_phase(orig_phase)

        if normalized != orig_phase:
            warnings.append(
                f"Normalized invented attack phase '{orig_phase}' to '{normalized}' at attackProgression[{i}]"
            )
            step.phase = normalized

        if step.phase == "PRIVILEGE_ESCALATION" and not has_success_privilege:
            warnings.append(
                f"Downgraded PRIVILEGE_ESCALATION to PRIVILEGE_ATTEMPT due to lack of successful privilege change evidence at attackProgression[{i}]"
            )
            step.phase = "PRIVILEGE_ATTEMPT"
            step.isAttemptOnly = True

        if step.phase == "LATERAL_MOVEMENT" and not has_multi_asset_movement:
            warnings.append(
                f"Rejected unsupported LATERAL_MOVEMENT without explicit movement evidence at attackProgression[{i}]"
            )
            step.phase = "RESOURCE_ACCESS"

        if step.phase == "EXFILTRATION" and not has_exfil:
            warnings.append(
                f"Rejected unsupported EXFILTRATION without data departure evidence at attackProgression[{i}]"
            )
            step.phase = "IMPACT"

    return warnings, result


def detect_evidence_conflicts(context: InvestigationContext) -> List[ConflictEvent]:
    """Detects conflicts using the canonical EvidenceLedger."""
    ledger = EvidenceLedger(context)
    return [
        ConflictEvent(
            entity=c.entity,
            conflict_type=c.conflict_type,
            sources=c.sources,
            description=c.description,
        )
        for c in ledger.conflicts
    ]


def validate_recommendation_appropriateness(
    context: InvestigationContext,
    result: AIInvestigationResult,
    recommendations: List[AIRecommendation],
    ledger: Optional[EvidenceLedger] = None,
) -> Tuple[List[str], List[str]]:
    """
    Validates recommendations for contextual appropriateness.
    """
    ledger = ledger or EvidenceLedger(context)
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Maintenance context
    maintenance_context_detected = False
    has_unauthorized_deviations = False

    for e in ledger.entries:
        comb = f"{e.summary} {str(e.raw_content)}".lower()
        if "approved" in comb or "maintenance" in comb or "chg" in comb or "ticket" in comb:
            maintenance_context_detected = True
        if "unauthorized" in comb or "unexpected" in comb or "suspicious deviation" in comb or "shadow" in comb or e.is_rejected_authorization:
            has_unauthorized_deviations = True

    # 2. Session abuse context
    session_abuse_context = len(ledger.known_sessions) > 0
    has_success_activity = any(e.is_success for e in ledger.entries)
    source_exclusively_malicious = not has_success_activity

    for rec in recommendations:
        if rec.actionType == "ISOLATE_RESOURCE":
            if (
                maintenance_context_detected
                and result.compromiseAssessment in ("NOT_ESTABLISHED", "ATTEMPT_ONLY")
                and not has_unauthorized_deviations
            ):
                err_msg = (
                    "Recommendation ISOLATE_RESOURCE rejected: Context indicates authorized maintenance without verified compromise."
                )
                logger.warning(
                    f"RULE=RECOMMENDATION_REJECTED field=actionType value=ISOLATE_RESOURCE reason='{err_msg}' incident={result.incidentId}"
                )
                errors.append(err_msg)

        if rec.actionType == "BLOCK_SOURCE":
            if session_abuse_context and not source_exclusively_malicious:
                warn_msg = (
                    "Recommendation BLOCK_SOURCE flagged: Context indicates session-based abuse. DISABLE_SESSION may be more targeted."
                )
                logger.warning(
                    f"RULE=RECOMMENDATION_WARNING field=actionType value=BLOCK_SOURCE reason='{warn_msg}' incident={result.incidentId}"
                )
                warnings.append(warn_msg)

    return errors, warnings


def reconcile_investigation_with_ledger(
    context: InvestigationContext,
    result: AIInvestigationResult,
    ledger: Optional[EvidenceLedger] = None,
) -> AIInvestigationResult:
    """
    Authoritative reconciliation:
    1. Checks fact/evidence consistency: Ensures LLM never turns SUCCESS into DENIED or DENIED into SUCCESS.
    2. Completeness check: Injects missing material evidence facts into observedFacts and citedEvidenceIds.
    3. Chronological Attack Progression: Sorts all attack progression steps by timestamp, fills missing stages.
    4. Temporal Anomaly Ingestion: Adds explicit Unknown and limitation items for detected temporal inconsistencies.
    5. Evidence Conflict Ingestion: Surfaces contradictions as unknowns.
    6. Deterministic Compromise & Attribution Assessment.
    """
    ledger = ledger or EvidenceLedger(context)

    # 1. Fact / Evidence Consistency
    for i, fact in enumerate(result.observedFacts):
        is_consistent, rule, reason = ledger.validate_fact_consistency(fact.statement, fact.evidenceIds)
        if not is_consistent:
            logger.warning(
                f"RULE={rule} field=observedFacts[{i}] reason='{reason}' incident={result.incidentId}"
            )
            # Reconcile fact statement to reflect true immutable evidence
            for eid in fact.evidenceIds:
                entry = ledger.get_entry(eid)
                if entry and entry.is_success:
                    fact.statement = f"{entry.summary} (Result: SUCCESS)"
                elif entry and entry.is_attempt:
                    fact.statement = f"{entry.summary} (Result: ATTEMPT/DENIED)"

    # 2. Material Evidence Completeness Check
    cited_ids = result.collect_all_cited_evidence_ids()
    missing_entries = ledger.check_missing_material_evidence(cited_ids)

    # Identify critical material entries (involved in anomalies, conflicts, auth milestones, or if facts were empty)
    anomaly_event_ids = {a.earlier_event_id for a in ledger.temporal_anomalies} | {a.later_event_id for a in ledger.temporal_anomalies}
    conflict_event_ids = {eid for c in ledger.conflicts for eid in c.sources}

    for m_entry in missing_entries:
        is_critical = (
            m_entry.evidence_id in anomaly_event_ids
            or m_entry.evidence_id in conflict_event_ids
            or m_entry.is_rejected_authorization
            or (m_entry.is_success and "auth" in m_entry.summary.lower())
            or not result.observedFacts
        )
        if is_critical:
            logger.info(
                f"RULE=MATERIAL_EVIDENCE_INJECTED id={m_entry.evidence_id} summary='{m_entry.summary}' incident={result.incidentId}"
            )
            outcome_str = "SUCCESS" if m_entry.is_success else "ATTEMPT/DENIED"
            result.observedFacts.append(
                ObservedFact(
                    statement=f"Observed forensic event '{m_entry.summary}' ({outcome_str})",
                    evidenceIds=[m_entry.evidence_id],
                )
            )
            if m_entry.evidence_id not in result.citedEvidenceIds:
                result.citedEvidenceIds.append(m_entry.evidence_id)

    # 3. Chronological Attack Progression Reconstruction
    if result.attackProgression:
        # Re-order existing steps strictly by timestamp from ledger
        def _get_step_ts(step: AttackProgressionItem):
            for eid in step.evidenceIds:
                entry = ledger.get_entry(eid)
                if entry and entry.parsed_timestamp:
                    return entry.parsed_timestamp
            return datetime.min.replace(tzinfo=timezone.utc)

        sorted_steps = sorted(result.attackProgression, key=_get_step_ts)
        reconstructed_progression: List[AttackProgressionItem] = []

        for idx, step in enumerate(sorted_steps, start=1):
            step.stepOrder = idx
            step.phase = normalize_attack_phase(step.phase)
            # Reconcile attempt flag with ledger
            for eid in step.evidenceIds:
                entry = ledger.get_entry(eid)
                if entry:
                    if entry.is_success and not entry.is_attempt:
                        step.isAttemptOnly = False
                        if "denied" in step.description.lower() and (entry.target or "").lower() in step.description.lower():
                            step.description = f"Resource access to {entry.target or entry.summary} succeeded."
                    elif entry.is_attempt and not entry.is_success:
                        step.isAttemptOnly = True
            reconstructed_progression.append(step)

        # If an anomaly event was missing from progression, add it
        existing_eids = {eid for s in reconstructed_progression for eid in s.evidenceIds}
        for a_eid in anomaly_event_ids:
            if a_eid not in existing_eids:
                entry = ledger.get_entry(a_eid)
                if entry:
                    phase = "AUTHENTICATION" if "auth" in entry.summary.lower() else "RESOURCE_ACCESS"
                    is_attempt = entry.is_attempt if not entry.is_success else False
                    reconstructed_progression.append(
                        AttackProgressionItem(
                            stepOrder=len(reconstructed_progression) + 1,
                            phase=phase,
                            timestamp=entry.timestamp_str,
                            sourceEntity=entry.source_ip or entry.user,
                            targetAssetId=entry.asset_id,
                            description=entry.summary,
                            isAttemptOnly=is_attempt,
                            evidenceIds=[entry.evidence_id],
                        )
                    )
        # Re-sort
        reconstructed_progression.sort(key=_get_step_ts)
        for idx, step in enumerate(reconstructed_progression, start=1):
            step.stepOrder = idx
        result.attackProgression = reconstructed_progression
    else:
        # Build progression from ledger
        progression: List[AttackProgressionItem] = []
        for idx, entry in enumerate(ledger.entries, start=1):
            phase = "AUTHENTICATION" if "auth" in entry.summary.lower() else "RESOURCE_ACCESS"
            if entry.action_type == "PRIVILEGE_CHANGE":
                phase = "PRIVILEGE_ATTEMPT" if entry.is_attempt else "PRIVILEGE_ESCALATION"
            is_attempt = entry.is_attempt if not entry.is_success else False
            progression.append(
                AttackProgressionItem(
                    stepOrder=idx,
                    phase=phase,
                    timestamp=entry.timestamp_str,
                    sourceEntity=entry.source_ip or entry.user,
                    targetAssetId=entry.asset_id,
                    description=entry.summary,
                    isAttemptOnly=is_attempt,
                    evidenceIds=[entry.evidence_id],
                )
            )
        result.attackProgression = progression

    # 4. Temporal Anomaly Ingestion
    for anomaly in ledger.temporal_anomalies:
        # Check if already present in unknowns
        if not any(anomaly.earlier_event_id in u.statement for u in result.unknowns):
            result.unknowns.append(
                Unknown(
                    statement=anomaly.description,
                    significance="Causality between events cannot be confirmed due to out-of-order execution or pre-existing session token.",
                    recommendedTelemetry="Correlate upstream reverse proxy and session cache logs.",
                )
            )
        lim_str = f"Temporal anomaly detected: {anomaly.anomaly_type}"
        if lim_str not in result.confidence.limitations:
            result.confidence.limitations.append(lim_str)

    # 5. Evidence Conflict Ingestion
    for conflict in ledger.conflicts:
        if not any(conflict.entity in u.statement for u in result.unknowns):
            result.unknowns.append(
                Unknown(
                    statement=f"Contradictory evidence detected for {conflict.entity}.",
                    significance=conflict.description,
                    recommendedTelemetry="Manual review of conflicting authoritative sources required.",
                )
            )
        lim_str = f"Contradictory evidence: {conflict.conflict_type}"
        if lim_str not in result.confidence.limitations:
            result.confidence.limitations.append(lim_str)

    # 6. Deterministic Compromise & Attribution Assessment
    compromise, attribution = ledger.determine_compromise_and_attribution()
    result.compromiseAssessment = compromise
    result.attributionAssessment = attribution

    return result
