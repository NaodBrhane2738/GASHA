"""
==============================================================================
FILE: apps/api/app/ai/validation.py
ROLE / OWNERSHIP: AI & Backend Engineers
OBJECTIVE: Grounding, allowlist, and safety validation for AI investigation outputs.
TOOLS & LIBRARIES: Pydantic v2, Python standard library
KEY FEATURES:
  - validate_investigation_result(): Enforces evidence grounding, allowlist actions,
    asset consistency, and epistemic boundaries.
  - check_evidence_citations(): Validates that all cited IDs exist in the input context.
  - validate_recommendations(): Enforces allowlisted response actions and detects malicious commands.
  - create_fallback_investigation_result(): Generates deterministic safe fallback results
    anchored to the canonical EvidenceLedger.
EXPECTED RESULTS / BEHAVIOR:
  - Rejects hallucinated evidence IDs, non-allowlisted actions, and command injections
    before AI outputs can touch the response pipeline.
==============================================================================
"""

import re
import logging
from typing import List, Set, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field

from app.ai.contracts import (
    InvestigationContext,
    AIInvestigationResult,
    AIRecommendation,
    ConfidenceAssessment,
    ObservedFact,
    Inference,
    Unknown,
    AttackProgressionItem,
    AIInvestigationStatus,
    ResponseActionType,
    ResponseTargetType,
    CompromiseAssessmentType,
    AttributionAssessmentType,
)
from app.ai.recommendations.validator import validate_recommendations_list
from app.ai.evidence_ledger import EvidenceLedger, LedgerEntry
from app.ai.semantic_validator import (
    validate_identifier_grounding,
    validate_attack_phases,
    detect_evidence_conflicts,
    validate_recommendation_appropriateness,
    reconcile_investigation_with_ledger,
)

logger = logging.getLogger("gasha.ai.validation")

# Canonical allowlisted action mappings: actionType -> allowed targetTypes
ALLOWED_ACTION_TARGET_MAP: Dict[ResponseActionType, Set[ResponseTargetType]] = {
    "BLOCK_SOURCE": {"IP_ADDRESS"},
    "DISABLE_SESSION": {"USER_SESSION", "SESSION_ID"},
    "ISOLATE_RESOURCE": {"ASSET_ID"},
}

# Dangerous characters or patterns that must never appear in targetIdentifier or action fields
COMMAND_INJECTION_PATTERNS = [
    r"[;&|`$><]",                  # Shell control characters
    r"\b(rm|cat|curl|wget|bash|sh|nc|ncat|python|powershell|cmd|sudo)\b",  # Executable commands
    r"\b(DROP|SELECT|INSERT|DELETE|UPDATE|UNION|EXEC|ALTER)\b",            # SQL commands
    r"(\.\./|\.\.\\)",             # Path traversal
    r"(<script|javascript:)",      # Script tags
]

_COMPILED_INJECTION_REGEX = re.compile("|".join(COMMAND_INJECTION_PATTERNS), re.IGNORECASE)


class ValidationOutcome(BaseModel):
    """Result of programmatic validation against an AIInvestigationResult."""
    isValid: bool = Field(..., description="True if result satisfies all grounding and safety rules")
    errors: List[str] = Field(default_factory=list, description="Hard validation errors that invalidate the result")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings or minor anomalies")
    validatedResult: Optional[AIInvestigationResult] = Field(
        default=None,
        description="The validated or sanitized AI investigation result",
    )


def check_evidence_citations(
    context: InvestigationContext,
    result: AIInvestigationResult,
) -> List[str]:
    """
    Ensures that EVERY evidence ID cited in the AI output exists in the supplied context.
    Returns a list of error messages for any hallucinated evidence IDs.
    """
    valid_evidence_ids = context.get_all_evidence_ids()
    cited_ids = result.collect_all_cited_evidence_ids()
    errors: List[str] = []

    unknown_ids = cited_ids - valid_evidence_ids
    if unknown_ids:
        errors.append(
            f"AI referenced ungrounded/hallucinated evidence IDs: {sorted(list(unknown_ids))}. "
            f"Available evidence IDs were: {sorted(list(valid_evidence_ids))}"
        )

    # Validate that each ObservedFact has at least one valid evidence ID
    for idx, fact in enumerate(result.observedFacts):
        if not fact.evidenceIds:
            errors.append(f"ObservedFact[{idx}] has no supporting evidenceIds: '{fact.statement}'")
        else:
            invalid_fact_ids = set(fact.evidenceIds) - valid_evidence_ids
            if invalid_fact_ids:
                errors.append(
                    f"ObservedFact[{idx}] cites non-existent evidence IDs {sorted(list(invalid_fact_ids))}"
                )

    return errors


def validate_asset_consistency(
    context: InvestigationContext,
    result: AIInvestigationResult,
) -> List[str]:
    """
    Checks that assets cited in affectedAssetIds actually exist in the context.
    """
    errors: List[str] = []
    known_assets = context.get_all_asset_ids()

    if result.affectedAssetIds:
        unknown_assets = set(result.affectedAssetIds) - known_assets
        if unknown_assets:
            errors.append(
                f"AI claimed affected assets that do not exist in context: {sorted(list(unknown_assets))}. "
                f"Known asset IDs: {sorted(list(known_assets))}"
            )

    return errors


def validate_recommendations(
    context: InvestigationContext,
    recommendations: List[AIRecommendation],
) -> Tuple[List[str], List[str]]:
    """
    Validates recommendations against allowlists, target types, existence, and safety.
    Returns (errors: List[str], warnings: List[str]).
    """
    valid_recs, errors = validate_recommendations_list(recommendations, context)
    app_errors, app_warnings = validate_recommendation_appropriateness(context, None, valid_recs)
    return errors + app_errors, app_warnings


def determine_compromise_assessment(
    context: InvestigationContext,
    result: Optional[AIInvestigationResult] = None,
) -> Tuple[CompromiseAssessmentType, AttributionAssessmentType]:
    """
    Deterministically assesses whether the incident contains evidence of confirmed
    compromise versus unfulfilled attack attempts / probes, and assesses attribution.
    """
    ledger = EvidenceLedger(context)
    return ledger.determine_compromise_and_attribution()


def normalize_investigation_result(
    context: InvestigationContext,
    result: AIInvestigationResult,
    ledger: Optional[EvidenceLedger] = None,
) -> AIInvestigationResult:
    """
    Applies authoritative reconciliation against the EvidenceLedger:
    1. Reconciles fact/evidence consistency.
    2. Enforces material evidence completeness.
    3. Reconstructs chronological attack progression.
    4. Ingests temporal anomalies and evidence conflicts.
    5. Deduplicates limitations.
    """
    ledger = ledger or EvidenceLedger(context)
    result = reconcile_investigation_with_ledger(context, result, ledger=ledger)

    # Deduplicate limitations
    seen_lims = set()
    deduped_lims = []
    for lim in result.confidence.limitations:
        norm = lim.strip().rstrip(".").lower()
        if norm and norm not in seen_lims:
            seen_lims.add(norm)
            deduped_lims.append(lim.strip())
    result.confidence.limitations = deduped_lims

    return result


def validate_investigation_result(
    context: InvestigationContext,
    result: AIInvestigationResult,
) -> ValidationOutcome:
    """
    Comprehensive validator for AIInvestigationResult.
    Applies all grounding, allowlist, asset consistency, and safety checks.
    """
    all_errors: List[str] = []
    all_warnings: List[str] = []
    ledger = EvidenceLedger(context)

    # If the AI itself returned an explicit non-success status, validate error details
    if result.status != "SUCCESS":
        all_warnings.append(f"AI returned non-success status: {result.status}")
        return ValidationOutcome(
            isValid=True,
            errors=[],
            warnings=all_warnings,
            validatedResult=result,
        )

    # Check for overconfidence warning before reconciliation
    if context.evidence and not result.observedFacts and result.confidence.score > 0.8:
        all_warnings.append(
            "AI reported high confidence (>0.8) despite listing zero grounded observed facts."
        )

    # 1. Evidence Citation Verification
    evidence_errors = check_evidence_citations(context, result)
    all_errors.extend(evidence_errors)

    # 2. Asset Consistency Verification
    asset_errors = validate_asset_consistency(context, result)
    all_errors.extend(asset_errors)

    # 3. Identifier Grounding in Prose
    id_events = validate_identifier_grounding(context, result, ledger=ledger)
    for ev in id_events:
        all_warnings.append(
            f"Identifier Grounding [{ev.rule}]: {ev.field} contains invalid entity '{ev.value}' ({ev.reason})"
        )

    # 4. Attack Phase Validation
    phase_warnings, result = validate_attack_phases(context, result, ledger=ledger)
    all_warnings.extend(phase_warnings)

    # 5. Response Recommendation Allowlist & Command Injection Verification
    # Check for adversarial command injection in recommendations
    for rec in result.recommendedActions:
        if _COMPILED_INJECTION_REGEX.search(rec.targetIdentifier):
            all_errors.append(
                f"Recommendation contains prohibited command/script syntax: '{rec.targetIdentifier}'"
            )

    # Discard invalid/generic recommendations (like target="Unknown") rather than failing the whole investigation
    valid_recs, rec_errors = validate_recommendations_list(result.recommendedActions, context)
    result.recommendedActions = valid_recs
    for r_err in rec_errors:
        all_warnings.append(f"Discarded invalid recommendation: {r_err}")
        logger.warning(f"RULE=RECOMMENDATION_DISCARDED reason='{r_err}' incident={result.incidentId}")

    # 6. Contextual Recommendation Appropriateness
    app_errors, app_warnings = validate_recommendation_appropriateness(
        context, result, result.recommendedActions, ledger=ledger
    )
    if app_errors:
        for app_err in app_errors:
            all_warnings.append(app_err)
        result.recommendedActions = [
            r for r in result.recommendedActions
            if not (r.actionType == "ISOLATE_RESOURCE" and any("ISOLATE_RESOURCE rejected" in e for e in app_errors))
        ]
    all_warnings.extend(app_warnings)

    # 7. Authoritative Ledger Reconciliation
    is_valid = len(all_errors) == 0
    validated_res = normalize_investigation_result(context, result, ledger=ledger) if is_valid else None

    return ValidationOutcome(
        isValid=is_valid,
        errors=all_errors,
        warnings=all_warnings,
        validatedResult=validated_res,
    )


def create_fallback_investigation_result(
    context: InvestigationContext,
    status: AIInvestigationStatus = "UNAVAILABLE",
    reason: str = "AI investigation engine is temporarily unavailable.",
) -> AIInvestigationResult:
    """
    Deterministic fallback generator when the LLM is unreachable, times out,
    or returns an ungrounded/invalid response.

    Guarantees that the UI and response pipeline always receive a valid,
    100% grounded result anchored to the canonical EvidenceLedger.
    """
    ledger = EvidenceLedger(context)
    fallback_facts: List[ObservedFact] = []

    # If detections exist, prioritize deterministic detections
    if context.detections:
        for det in context.detections:
            fallback_facts.append(
                ObservedFact(
                    statement=f"Deterministic detection '{det.ruleName}' triggered: {det.evidenceSummary}",
                    evidenceIds=[det.id] + det.matchedEventIds,
                )
            )
    else:
        # Build facts from evidence items in ledger
        for entry in ledger.entries:
            outcome_str = "SUCCESS" if entry.is_success else "ATTEMPT/DENIED"
            fallback_facts.append(
                ObservedFact(
                    statement=f"Forensic record '{entry.summary}' ({outcome_str})",
                    evidenceIds=[entry.evidence_id],
                )
            )

    # Build chronological attack progression from ledger
    fallback_progression: List[AttackProgressionItem] = []
    for idx, entry in enumerate(ledger.entries, start=1):
        phase = "AUTHENTICATION" if "auth" in entry.summary.lower() else "RESOURCE_ACCESS"
        if entry.action_type == "PRIVILEGE_CHANGE":
            phase = "PRIVILEGE_ATTEMPT" if entry.is_attempt else "PRIVILEGE_ESCALATION"
        is_attempt = entry.is_attempt if not entry.is_success else False
        fallback_progression.append(
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

    compromise, attribution = ledger.determine_compromise_and_attribution()

    # Unknowns
    unknowns: List[Unknown] = []
    for anomaly in ledger.temporal_anomalies:
        unknowns.append(
            Unknown(
                statement=anomaly.description,
                significance="Causality between events cannot be confirmed due to temporal anomaly.",
                recommendedTelemetry="Correlate upstream reverse proxy and session cache logs.",
            )
        )
    for conflict in ledger.conflicts:
        unknowns.append(
            Unknown(
                statement=f"Contradictory evidence detected for {conflict.entity}.",
                significance=conflict.description,
                recommendedTelemetry="Manual review of conflicting authoritative sources required.",
            )
        )

    if not unknowns:
        unknowns.append(
            Unknown(
                statement="Detailed attack narrative and root-cause analysis unavailable due to AI fallback.",
                significance="Manual analyst review required to reconstruct full attack progression.",
                recommendedTelemetry=None,
            )
        )

    if context.detections:
        cited_ids = [det.id for det in context.detections]
    else:
        cited_ids = list(ledger.get_all_material_ids())

    score = 0.0 if status in ("UNAVAILABLE", "TIMEOUT", "INSUFFICIENT_EVIDENCE") else 0.3

    return AIInvestigationResult(
        incidentId=context.incident.id,
        status=status,
        summary=(
            f"Deterministic investigation ({status}). "
            f"Synthesized from {len(ledger.entries)} forensic evidence record(s) and {len(context.detections)} detection(s)."
        ),
        severity=context.incident.severity,
        confidence=ConfidenceAssessment(
            score=score,
            rationale=f"Fallback result generated deterministically due to: {reason}",
            evidenceCompleteness="INSUFFICIENT",
            limitations=[reason, "Analysis was generated without LLM cognitive synthesis."],
        ),
        observedFacts=fallback_facts,
        inferences=[],
        unknowns=unknowns,
        attackProgression=fallback_progression,
        affectedAssetIds=[context.incident.primaryAffectedAssetId] + context.incident.relatedAssetIds,
        citedEvidenceIds=cited_ids,
        recommendedActions=[],
        errorMessage=reason,
        compromiseAssessment=compromise,
        attributionAssessment=attribution,
    )
