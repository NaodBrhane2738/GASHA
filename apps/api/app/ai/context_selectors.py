"""
==============================================================================
FILE: apps/api/app/ai/context_selectors.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Deterministic relevance selection rules for extracting incident-related
           detections, telemetry, assets, attack paths, and vulnerabilities.
TOOLS & LIBRARIES: Python standard library
KEY FEATURES:
  - select_relevant_detections(): Filters detections linked to incident or affected assets.
  - select_relevant_telemetry(): Extracts telemetry events referenced by detections,
    involving affected assets, or sharing attacker IPs/sessions.
  - select_relevant_assets(): Filters assets involved directly in incident, detections, or attack paths.
  - select_relevant_attack_path(): Matches attack paths associated with incident or affected assets.
  - select_relevant_vulnerabilities(): Gathers findings on affected assets or attack path hops.
EXPECTED RESULTS / BEHAVIOR:
  - Deterministically removes unrelated environment noise while preserving complete
    forensic connectivity across all relevant security entities.
==============================================================================
"""

from typing import List, Set, Optional, Dict
from app.ai.contracts import (
    IncidentContext,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    AttackPathContext,
    VulnerabilityContext,
    EvidenceItem,
)


def extract_incident_asset_ids(incident: IncidentContext) -> Set[str]:
    """Returns the set of all asset IDs directly attached to the incident."""
    asset_ids = set()
    if incident.primaryAffectedAssetId and incident.primaryAffectedAssetId != "UNKNOWN_ASSET":
        asset_ids.add(incident.primaryAffectedAssetId)
    for aid in incident.relatedAssetIds:
        if aid:
            asset_ids.add(aid)
    return asset_ids


def select_relevant_detections(
    incident: IncidentContext,
    all_detections: List[DetectionContext],
    incident_asset_ids: Optional[Set[str]] = None,
) -> List[DetectionContext]:
    """
    Selects detections that are:
    1. Explicitly referenced by ID in incident.detectionEventIds
    2. Associated with one of the incident's affected asset IDs
    """
    if incident_asset_ids is None:
        incident_asset_ids = extract_incident_asset_ids(incident)

    explicit_detection_ids = set(incident.detectionEventIds)

    selected: List[DetectionContext] = []
    seen_ids: Set[str] = set()

    # Pass 1: Explicitly referenced detections (highest priority)
    for det in all_detections:
        if det.id in explicit_detection_ids and det.id not in seen_ids:
            selected.append(det)
            seen_ids.add(det.id)

    # Pass 2: Detections matching affected assets
    for det in all_detections:
        if det.id not in seen_ids:
            if det.primaryAssetId and det.primaryAssetId in incident_asset_ids:
                selected.append(det)
                seen_ids.add(det.id)

    return selected


def select_relevant_telemetry(
    incident: IncidentContext,
    selected_detections: List[DetectionContext],
    all_telemetry: List[TelemetryEventContext],
    incident_asset_ids: Optional[Set[str]] = None,
) -> List[TelemetryEventContext]:
    """
    Selects telemetry events that are:
    1. Directly cited in matchedEventIds of selected detections
    2. Associated with attacker IPs or sessions observed in selected detections
    3. Originating from or targeting affected assets
    """
    if incident_asset_ids is None:
        incident_asset_ids = extract_incident_asset_ids(incident)

    # Gather explicit matched event IDs from detections
    explicit_matched_ids: Set[str] = set()
    for det in selected_detections:
        explicit_matched_ids.update(det.matchedEventIds)

    # Gather involved attacker IPs and sessions from detection metadata or matched events
    involved_ips: Set[str] = set()
    involved_sessions: Set[str] = set()
    involved_users: Set[str] = set()

    for tel in all_telemetry:
        if tel.id in explicit_matched_ids:
            if tel.sourceIp:
                involved_ips.add(tel.sourceIp)
            if tel.sessionId:
                involved_sessions.add(tel.sessionId)
            if tel.userId:
                involved_users.add(tel.userId)

    selected: List[TelemetryEventContext] = []
    seen_ids: Set[str] = set()

    # Priority 1: Explicitly matched telemetry events
    for tel in all_telemetry:
        if tel.id in explicit_matched_ids and tel.id not in seen_ids:
            selected.append(tel)
            seen_ids.add(tel.id)

    # Priority 2: Telemetry sharing attacker source IP, session, or user
    for tel in all_telemetry:
        if tel.id not in seen_ids:
            has_matching_actor = (
                (tel.sourceIp and tel.sourceIp in involved_ips) or
                (tel.sessionId and tel.sessionId in involved_sessions) or
                (tel.userId and tel.userId in involved_users)
            )
            if has_matching_actor:
                selected.append(tel)
                seen_ids.add(tel.id)

    # Priority 3: Telemetry touching affected asset services
    for tel in all_telemetry:
        if tel.id not in seen_ids:
            if tel.sourceService in incident_asset_ids:
                selected.append(tel)
                seen_ids.add(tel.id)

    return selected


def select_relevant_attack_path(
    incident: IncidentContext,
    all_attack_paths: List[AttackPathContext],
    incident_asset_ids: Optional[Set[str]] = None,
) -> Optional[AttackPathContext]:
    """
    Selects the single most relevant active attack path:
    1. Matching incident.attackPathId if provided
    2. Reaching or originating from primaryAffectedAssetId
    3. Reaching any related affected asset
    """
    if not all_attack_paths:
        return None

    if incident_asset_ids is None:
        incident_asset_ids = extract_incident_asset_ids(incident)

    # Match by explicit ID
    if incident.attackPathId:
        for ap in all_attack_paths:
            if ap.id == incident.attackPathId:
                return ap

    # Match by target asset matching primaryAffectedAssetId
    for ap in all_attack_paths:
        if ap.targetAssetId == incident.primaryAffectedAssetId and ap.isActive:
            return ap

    # Match by target or entry asset in incident assets
    for ap in all_attack_paths:
        if ap.isActive and (ap.targetAssetId in incident_asset_ids or ap.entryPointAssetId in incident_asset_ids):
            return ap

    return None


def select_relevant_assets(
    incident: IncidentContext,
    selected_detections: List[DetectionContext],
    selected_attack_path: Optional[AttackPathContext],
    all_assets: List[AssetContext],
) -> List[AssetContext]:
    """
    Selects assets that are:
    1. Attached to the incident (primary or related)
    2. Primary asset of a selected detection
    3. Present as a node hop in the selected attack path
    """
    required_asset_ids = extract_incident_asset_ids(incident)

    for det in selected_detections:
        if det.primaryAssetId:
            required_asset_ids.add(det.primaryAssetId)

    if selected_attack_path:
        required_asset_ids.add(selected_attack_path.entryPointAssetId)
        required_asset_ids.add(selected_attack_path.targetAssetId)
        for node in selected_attack_path.nodes:
            required_asset_ids.add(node.assetId)

    # Filter all_assets to matching IDs
    selected_assets: List[AssetContext] = []
    seen_ids: Set[str] = set()

    for asset in all_assets:
        if asset.id in required_asset_ids and asset.id not in seen_ids:
            selected_assets.append(asset)
            seen_ids.add(asset.id)

    # If an asset was referenced by ID but missing from all_assets inventory,
    # create a minimal placeholder AssetContext to ensure closed-world traceability
    for aid in required_asset_ids:
        if aid not in seen_ids and aid != "UNKNOWN_ASSET":
            selected_assets.append(
                AssetContext(
                    id=aid,
                    name=aid,
                    type="SERVICE",
                    criticality="TIER_2_MEDIUM",
                    status="ACTIVE",
                    metadata={"note": "Referenced in incident/detections but not in asset inventory"}
                )
            )
            seen_ids.add(aid)

    return selected_assets


def select_relevant_vulnerabilities(
    relevant_asset_ids: Set[str],
    selected_attack_path: Optional[AttackPathContext],
    all_vulnerabilities: List[VulnerabilityContext],
) -> List[VulnerabilityContext]:
    """
    Selects vulnerabilities matching:
    1. Affected asset IDs
    2. Vulnerability IDs cited in attack path nodes
    """
    path_vuln_ids: Set[str] = set()
    if selected_attack_path:
        for node in selected_attack_path.nodes:
            if node.vulnerabilityIds:
                path_vuln_ids.update(node.vulnerabilityIds)

    selected: List[VulnerabilityContext] = []
    seen_ids: Set[str] = set()

    for vuln in all_vulnerabilities:
        if vuln.id not in seen_ids:
            if vuln.assetId in relevant_asset_ids or vuln.id in path_vuln_ids:
                selected.append(vuln)
                seen_ids.add(vuln.id)

    return selected
