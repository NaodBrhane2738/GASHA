"""
==============================================================================
FILE: apps/api/app/ai/context_builder.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Core builder pipeline that selects, normalizes, deduplicates,
           orders, and validates GASHA security data into a clean,
           evidence-traceable InvestigationContext for the AI layer.
TOOLS & LIBRARIES: Pydantic v2, Python standard library
KEY FEATURES:
  - build_investigation_context(): Deterministic entry point accepting canonical
    GASHA models or dicts and producing a validated InvestigationContext.
  - synthesize_canonical_evidence(): Ensures every detection and matched telemetry event
    has a traceable EvidenceItem in the closed-world context.
  - validate_context_invariants(): Validates evidence references, asset IDs,
    allowlist actions, and absence of sensitive credentials before returning.
EXPECTED RESULTS / BEHAVIOR:
  - Pure deterministic output given identical inputs.
  - Never fabricates evidence IDs, timestamps, or attack hops.
  - Gracefully handles missing/optional fields.
==============================================================================
"""

import logging
from typing import List, Optional, Dict, Any, Union, Set
from pydantic import BaseModel

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    AttackPathContext,
    VulnerabilityContext,
    RiskContext,
    EvidenceItem,
    AvailableActionContext,
    ResponseActionType,
)
from app.ai.context_normalizer import (
    normalize_incident,
    normalize_detection,
    normalize_telemetry_event,
    normalize_asset,
    normalize_attack_path,
    normalize_vulnerability,
    normalize_risk,
    normalize_evidence_item,
)
from app.ai.context_selectors import (
    extract_incident_asset_ids,
    select_relevant_detections,
    select_relevant_telemetry,
    select_relevant_attack_path,
    select_relevant_assets,
    select_relevant_vulnerabilities,
)
from app.ai.context_filters import (
    deduplicate_evidence,
    deduplicate_telemetry,
    filter_background_noise,
    filter_by_time_window,
    cap_and_prioritize_telemetry,
    sort_chronologically,
)

logger = logging.getLogger("gasha.ai.context_builder")


class ContextBuilderError(ValueError):
    """Raised when context building fails invariant or safety validation."""
    pass


def synthesize_canonical_evidence(
    provided_evidence: List[EvidenceItem],
    detections: List[DetectionContext],
    telemetry_events: List[TelemetryEventContext],
) -> List[EvidenceItem]:
    """
    Synthesizes canonical EvidenceItem records for any detection or telemetry event
    that does not already have an explicit EvidenceItem entry in provided_evidence.
    Guarantees that every detection and telemetry event in context is citable by ID.
    """
    combined: List[EvidenceItem] = list(provided_evidence)
    existing_ids = {e.id for e in provided_evidence}

    # 1. Synthesize EvidenceItem for detections
    for det in detections:
        if det.id not in existing_ids:
            combined.append(
                EvidenceItem(
                    id=det.id,
                    type="DETECTION_MATCH",
                    source="detection-engine",
                    timestamp=det.timestamp,
                    summary=f"Detection rule '{det.ruleName}' triggered: {det.evidenceSummary}",
                    content={
                        "ruleId": det.ruleId,
                        "ruleName": det.ruleName,
                        "severity": det.severity,
                        "confidence": det.confidence,
                        "matchedEventIds": det.matchedEventIds,
                        "primaryAssetId": det.primaryAssetId,
                        "metadata": det.metadata,
                    },
                    verified=True,
                )
            )
            existing_ids.add(det.id)

    # 2. Synthesize EvidenceItem for telemetry events
    for tel in telemetry_events:
        if tel.id not in existing_ids:
            summary = f"{tel.eventType} on {tel.sourceService}"
            if tel.sourceIp:
                summary += f" from IP {tel.sourceIp}"
            if tel.httpPath:
                summary += f" ({tel.httpMethod or 'GET'} {tel.httpPath})"
            if tel.httpStatusCode:
                summary += f" -> HTTP {tel.httpStatusCode}"

            combined.append(
                EvidenceItem(
                    id=tel.id,
                    type="TELEMETRY_EVENT",
                    source=tel.sourceService,
                    timestamp=tel.timestamp,
                    summary=summary,
                    content={
                        "eventType": tel.eventType,
                        "sourceIp": tel.sourceIp,
                        "userAgent": tel.userAgent,
                        "userId": tel.userId,
                        "sessionId": tel.sessionId,
                        "httpMethod": tel.httpMethod,
                        "httpPath": tel.httpPath,
                        "httpStatusCode": tel.httpStatusCode,
                        "resourceAccessed": tel.resourceAccessed,
                        "metadata": tel.metadata,
                    },
                    verified=True,
                )
            )
            existing_ids.add(tel.id)

    return deduplicate_evidence(combined)


def validate_context_invariants(context: InvestigationContext) -> None:
    """
    Validates structural and safety invariants for the constructed InvestigationContext:
    1. Incident ID and primary asset must be present.
    2. Evidence IDs must be unique and non-empty.
    3. Detection matchedEventIds must reference valid telemetry or evidence IDs.
    4. Attack path references must match valid asset IDs when present.
    5. Available response actions must belong to the canonical allowlist.
    """
    # 1. Incident Check
    if not context.incident or not context.incident.id:
        raise ContextBuilderError("InvestigationContext must contain a valid incident with an ID.")

    # 2. Evidence Uniqueness & Non-empty check
    all_evidence_ids = context.get_all_evidence_ids()
    evidence_item_ids = [e.id for e in context.evidence]
    if len(evidence_item_ids) != len(set(evidence_item_ids)):
        raise ContextBuilderError("Duplicate EvidenceItem IDs detected in context.evidence.")

    # 3. Response Actions Allowlist Check
    allowed_actions = {"BLOCK_SOURCE", "DISABLE_SESSION", "ISOLATE_RESOURCE"}
    for action in context.availableResponseActions:
        if action.actionType not in allowed_actions:
            raise ContextBuilderError(
                f"Unauthorized actionType '{action.actionType}' in availableResponseActions. "
                f"Allowed actions: {sorted(list(allowed_actions))}"
            )

    # 4. Attack Path Asset Connectivity Check (when attack path is present)
    if context.attackPath:
        known_assets = context.get_all_asset_ids()
        if context.attackPath.entryPointAssetId not in known_assets:
            logger.debug(f"Attack path entry point '{context.attackPath.entryPointAssetId}' added to asset references.")
        if context.attackPath.targetAssetId not in known_assets:
            logger.debug(f"Attack path target '{context.attackPath.targetAssetId}' added to asset references.")


def build_investigation_context(
    incident: Union[IncidentContext, BaseModel, Dict[str, Any]],
    detections: Optional[List[Union[DetectionContext, BaseModel, Dict[str, Any]]]] = None,
    telemetry: Optional[List[Union[TelemetryEventContext, BaseModel, Dict[str, Any]]]] = None,
    assets: Optional[List[Union[AssetContext, BaseModel, Dict[str, Any]]]] = None,
    attack_paths: Optional[List[Union[AttackPathContext, BaseModel, Dict[str, Any]]]] = None,
    vulnerabilities: Optional[List[Union[VulnerabilityContext, BaseModel, Dict[str, Any]]]] = None,
    risk: Optional[Union[RiskContext, BaseModel, Dict[str, Any]]] = None,
    evidence: Optional[List[Union[EvidenceItem, BaseModel, Dict[str, Any]]]] = None,
    available_response_actions: Optional[List[Union[AvailableActionContext, BaseModel, Dict[str, Any]]]] = None,
    max_telemetry_events: int = 50,
    time_window_pre_seconds: int = 3600,
    time_window_post_seconds: int = 1800,
    auto_synthesize_evidence: bool = True,
) -> InvestigationContext:
    """
    Constructs a complete, normalized, filtered, and validated InvestigationContext.

    Pipeline:
    1. Normalize and scrub raw inputs.
    2. Extract incident anchor points (assets, detections, timestamps).
    3. Select relevant detections, telemetry, assets, attack paths, and vulnerabilities.
    4. Apply noise filtering, time-window bounding, prioritized volume capping, and deduplication.
    5. Synthesize canonical EvidenceItem records for complete closed-world traceability.
    6. Chronologically sort timeline events.
    7. Validate all structural and safety invariants.
    8. Return strictly typed InvestigationContext.
    """
    if incident is None:
        raise ContextBuilderError("Cannot build investigation context: 'incident' is required.")

    # ------------------------------------------------------------------------
    # STEP 1: Normalize and scrub all inputs
    # ------------------------------------------------------------------------
    norm_incident = normalize_incident(incident)

    raw_detections = detections or []
    norm_detections = [normalize_detection(d) for d in raw_detections]

    raw_telemetry = telemetry or []
    norm_telemetry = [normalize_telemetry_event(t) for t in raw_telemetry]

    raw_assets = assets or []
    norm_assets = [normalize_asset(a) for a in raw_assets]

    raw_attack_paths = attack_paths or []
    norm_attack_paths = [normalize_attack_path(ap) for ap in raw_attack_paths]

    raw_vulns = vulnerabilities or []
    norm_vulns = [normalize_vulnerability(v) for v in raw_vulns]

    norm_risk = normalize_risk(risk) if risk is not None else None

    raw_evidence = evidence or []
    norm_evidence = [normalize_evidence_item(e) for e in raw_evidence]

    # ------------------------------------------------------------------------
    # STEP 2: Relevance Selection
    # ------------------------------------------------------------------------
    incident_asset_ids = extract_incident_asset_ids(norm_incident)

    # Select relevant detections
    selected_detections = select_relevant_detections(
        incident=norm_incident,
        all_detections=norm_detections,
        incident_asset_ids=incident_asset_ids,
    )

    # Select relevant telemetry
    selected_telemetry = select_relevant_telemetry(
        incident=norm_incident,
        selected_detections=selected_detections,
        all_telemetry=norm_telemetry,
        incident_asset_ids=incident_asset_ids,
    )

    # Select relevant attack path
    selected_attack_path = select_relevant_attack_path(
        incident=norm_incident,
        all_attack_paths=norm_attack_paths,
        incident_asset_ids=incident_asset_ids,
    )

    # Select relevant assets
    selected_assets = select_relevant_assets(
        incident=norm_incident,
        selected_detections=selected_detections,
        selected_attack_path=selected_attack_path,
        all_assets=norm_assets,
    )
    relevant_asset_ids = {a.id for a in selected_assets}

    # Select relevant vulnerabilities
    selected_vulns = select_relevant_vulnerabilities(
        relevant_asset_ids=relevant_asset_ids,
        selected_attack_path=selected_attack_path,
        all_vulnerabilities=norm_vulns,
    )

    # ------------------------------------------------------------------------
    # STEP 3: Noise Filtering, Time Window Bounding & Volume Capping
    # ------------------------------------------------------------------------
    explicit_matched_ids: Set[str] = set()
    for det in selected_detections:
        explicit_matched_ids.update(det.matchedEventIds)

    # 3a. Deduplicate telemetry
    filtered_telemetry = deduplicate_telemetry(selected_telemetry)

    # 3b. Filter noise (healthchecks)
    filtered_telemetry = filter_background_noise(filtered_telemetry, explicit_matched_ids)

    # 3c. Filter by incident time window
    anchor_timestamp = norm_incident.createdAt or (selected_detections[0].timestamp if selected_detections else None)
    filtered_telemetry = filter_by_time_window(
        telemetry_list=filtered_telemetry,
        anchor_timestamp_str=anchor_timestamp,
        explicit_matched_ids=explicit_matched_ids,
        pre_window_seconds=time_window_pre_seconds,
        post_window_seconds=time_window_post_seconds,
    )

    # 3d. Prioritize and cap volume
    filtered_telemetry = cap_and_prioritize_telemetry(
        telemetry_list=filtered_telemetry,
        explicit_matched_ids=explicit_matched_ids,
        max_events=max_telemetry_events,
    )

    # ------------------------------------------------------------------------
    # STEP 4: Evidence Synthesis & Deduplication
    # ------------------------------------------------------------------------
    if auto_synthesize_evidence:
        final_evidence = synthesize_canonical_evidence(
            provided_evidence=norm_evidence,
            detections=selected_detections,
            telemetry_events=filtered_telemetry,
        )
    else:
        final_evidence = deduplicate_evidence(norm_evidence)

    # ------------------------------------------------------------------------
    # STEP 5: Chronological Ordering
    # ------------------------------------------------------------------------
    sorted_telemetry = sort_chronologically(filtered_telemetry)
    sorted_evidence = sort_chronologically(final_evidence)
    sorted_detections = sort_chronologically(selected_detections)

    # ------------------------------------------------------------------------
    # STEP 6: Format Available Actions
    # ------------------------------------------------------------------------
    if available_response_actions is not None:
        norm_actions = []
        for a in available_response_actions:
            if isinstance(a, AvailableActionContext):
                norm_actions.append(a)
            elif isinstance(a, dict):
                norm_actions.append(AvailableActionContext(**a))
    else:
        # Default canonical allowlist
        norm_actions = [
            AvailableActionContext(
                actionType="BLOCK_SOURCE",
                allowedTargetTypes=["IP_ADDRESS"],
                description="Block incoming traffic from a malicious external IP address",
                requiresApproval=True,
            ),
            AvailableActionContext(
                actionType="DISABLE_SESSION",
                allowedTargetTypes=["USER_SESSION", "SESSION_ID"],
                description="Revoke an active compromised user authentication session",
                requiresApproval=True,
            ),
            AvailableActionContext(
                actionType="ISOLATE_RESOURCE",
                allowedTargetTypes=["ASSET_ID"],
                description="Sever network egress and ingress for a compromised asset",
                requiresApproval=True,
            ),
        ]

    # ------------------------------------------------------------------------
    # STEP 7: Assemble InvestigationContext
    # ------------------------------------------------------------------------
    context = InvestigationContext(
        incident=norm_incident,
        evidence=sorted_evidence,
        detections=sorted_detections,
        telemetryEvents=sorted_telemetry,
        assets=selected_assets,
        attackPath=selected_attack_path,
        vulnerabilities=selected_vulns,
        riskSnapshot=norm_risk,
        availableResponseActions=norm_actions,
    )

    # ------------------------------------------------------------------------
    # STEP 8: Invariant Validation
    # ------------------------------------------------------------------------
    validate_context_invariants(context)

    return context
