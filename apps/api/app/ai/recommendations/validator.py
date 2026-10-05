"""
==============================================================================
FILE: apps/api/app/ai/recommendations/validator.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Strict validator for defensive AI recommendations in GASHA.
           Enforces allowlist adherence, target-type compatibility, evidence
           grounding, and command injection prevention.
TOOLS & LIBRARIES: Python standard library, re
==============================================================================
"""

import re
from typing import List, Tuple, Set

from app.ai.contracts import (
    InvestigationContext,
    AIRecommendation,
    ALLOWED_RESPONSE_ACTIONS,
    ALLOWED_ACTION_TARGET_MAP,
)

# Forbidden execution patterns
FORBIDDEN_COMMAND_PATTERNS = [
    re.compile(r"\b(rm\s+-rf|sudo|chmod|chown|kill|pkill|reboot|shutdown)\b", re.IGNORECASE),
    re.compile(r"\b(bash|sh|zsh|cmd\.exe|powershell|pwsh|eval\(|exec\()\b", re.IGNORECASE),
    re.compile(r"\b(curl\s+|wget\s+|nc\s+|ncat\s+|socat\s+)", re.IGNORECASE),
    re.compile(r"\b(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+.*?SET)\b", re.IGNORECASE),
    re.compile(r"[;&|`$><]", re.IGNORECASE),
]


def validate_recommendation(
    rec: AIRecommendation,
    context: InvestigationContext,
) -> Tuple[bool, List[str]]:
    """
    Validates a single AIRecommendation against GASHA's security boundaries.

    Returns:
        (is_valid: bool, errors: List[str])
    """
    errors: List[str] = []

    # 1. Allowlist Action Verification
    if rec.actionType not in ALLOWED_RESPONSE_ACTIONS:
        errors.append(
            f"Action type '{rec.actionType}' is not in GASHA allowlist: {sorted(list(ALLOWED_RESPONSE_ACTIONS))}"
        )

    # 2. Target Type Compatibility Verification
    allowed_targets = ALLOWED_ACTION_TARGET_MAP.get(rec.actionType, set())
    if rec.targetType not in allowed_targets:
        errors.append(
            f"Target type '{rec.targetType}' is invalid for action '{rec.actionType}'. Allowed: {sorted(list(allowed_targets))}"
        )

    # 3. Target Identifier Validity
    if not rec.targetIdentifier or not rec.targetIdentifier.strip():
        errors.append("Target identifier cannot be empty.")
    elif rec.targetIdentifier.strip().lower() in ["unknown", "none", "null", "all", "*"]:
        errors.append(f"Target identifier '{rec.targetIdentifier}' is too generic or invalid.")

    # 4. Command Injection & Arbitrary Syntax Defense
    for pattern in FORBIDDEN_COMMAND_PATTERNS:
        if pattern.search(rec.targetIdentifier):
            errors.append(f"Target identifier contains prohibited command/script syntax: '{rec.targetIdentifier}'")
            break

    # 5. Target Existence in Context Verification
    known_ips = context.get_all_known_ips() if hasattr(context, "get_all_known_ips") else set()
    known_sessions = context.get_all_known_sessions() if hasattr(context, "get_all_known_sessions") else set()
    known_users = context.get_all_known_users() if hasattr(context, "get_all_known_users") else set()
    valid_assets = context.get_all_asset_ids()

    if rec.actionType == "BLOCK_SOURCE" and rec.targetType == "IP_ADDRESS":
        if known_ips and rec.targetIdentifier not in known_ips:
            found = any(
                rec.targetIdentifier in str(e.content) or rec.targetIdentifier in e.summary
                for e in context.evidence
            )
            if not found:
                errors.append(
                    f"BLOCK_SOURCE target IP '{rec.targetIdentifier}' does not exist in supplied context."
                )
    elif rec.actionType == "DISABLE_SESSION":
        if (known_sessions or known_users) and rec.targetIdentifier not in known_sessions and rec.targetIdentifier not in known_users:
            found = any(
                rec.targetIdentifier in str(e.content) or rec.targetIdentifier in e.summary
                for e in context.evidence
            )
            if not found:
                errors.append(
                    f"DISABLE_SESSION target '{rec.targetIdentifier}' does not exist in supplied context."
                )
    elif rec.actionType == "ISOLATE_RESOURCE" and rec.targetType == "ASSET_ID":
        if rec.targetIdentifier not in valid_assets:
            errors.append(
                f"ISOLATE_RESOURCE target asset '{rec.targetIdentifier}' is not among context assets: {sorted(list(valid_assets))}"
            )

    # 6. Evidence Grounding Verification
    valid_eids = context.get_all_evidence_ids()
    if not rec.supportingEvidenceIds:
        errors.append(f"Recommendation '{rec.id}' lacks supporting evidence citations.")
    else:
        for eid in rec.supportingEvidenceIds:
            if eid not in valid_eids:
                errors.append(f"Recommendation '{rec.id}' cites non-existent evidence ID '{eid}'.")

    # 7. Confidence Score Bounds
    if not (0.0 <= rec.confidence <= 1.0):
        errors.append(f"Confidence score {rec.confidence} is outside valid range [0.0, 1.0].")

    # 8. Non-empty rationale and expected impact
    if not rec.rationale or not rec.rationale.strip():
        errors.append("Rationale cannot be empty.")
    if not rec.expectedImpact or not rec.expectedImpact.strip():
        errors.append("Expected impact cannot be empty.")

    return (len(errors) == 0, errors)


def validate_recommendations_list(
    recommendations: List[AIRecommendation],
    context: InvestigationContext,
) -> Tuple[List[AIRecommendation], List[str]]:
    """
    Validates a list of recommendations, discarding invalid ones and collecting error details.

    Returns:
        (valid_recommendations: List[AIRecommendation], all_errors: List[str])
    """
    valid_recs: List[AIRecommendation] = []
    all_errors: List[str] = []

    for rec in recommendations:
        is_valid, errors = validate_recommendation(rec, context)
        if is_valid:
            valid_recs.append(rec)
        else:
            all_errors.extend([f"Recommendation '{rec.id}': {err}" for err in errors])

    return valid_recs, all_errors
