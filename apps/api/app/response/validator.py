"""
==============================================================================
FILE: apps/api/app/response/validator.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Validates response action proposals against allowlisted actions,
           target syntax, incident evidence, and environment boundaries.
==============================================================================
"""

import ipaddress
from typing import Tuple, Optional, List, Set

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse
from app.schemas.response import ResponseProposalRequest, ResponseActionRequest


ALLOWLISTED_ACTIONS = {"BLOCK_SOURCE", "DISABLE_SESSION", "ISOLATE_RESOURCE"}
VALID_TARGET_TYPES = {"IP_ADDRESS", "SESSION_ID", "USER_SESSION", "ASSET_ID"}


class ResponseProposalValidator:
    """
    Validates containment proposals before they enter the human approval workflow.
    Ensures zero arbitrary execution targets, strict evidence linkage, and correct environment scoping.
    """

    @classmethod
    def validate_proposal(
        cls,
        req: ResponseProposalRequest,
        incident: IncidentResponse,
        detections: List[DetectionEventResponse],
        caller_env: str = "env-prod"
    ) -> Tuple[bool, Optional[str]]:
        # 1. Action allowlist check
        if req.actionType not in ALLOWLISTED_ACTIONS:
            return False, f"Action type '{req.actionType}' is not allowlisted. Allowed actions: {sorted(list(ALLOWLISTED_ACTIONS))}"

        # 2. Target type check
        if req.targetType not in VALID_TARGET_TYPES:
            return False, f"Target type '{req.targetType}' is invalid. Allowed types: {sorted(list(VALID_TARGET_TYPES))}"

        # Action and target type compatibility
        if req.actionType == "BLOCK_SOURCE" and req.targetType != "IP_ADDRESS":
            return False, f"Action 'BLOCK_SOURCE' requires targetType 'IP_ADDRESS', got '{req.targetType}'"

        if req.actionType == "DISABLE_SESSION" and req.targetType not in ("SESSION_ID", "USER_SESSION"):
            return False, f"Action 'DISABLE_SESSION' requires targetType 'SESSION_ID' or 'USER_SESSION', got '{req.targetType}'"

        if req.actionType == "ISOLATE_RESOURCE" and req.targetType != "ASSET_ID":
            return False, f"Action 'ISOLATE_RESOURCE' requires targetType 'ASSET_ID', got '{req.targetType}'"

        # 3. Environment isolation check
        if incident.environmentId != caller_env:
            return False, f"Environment mismatch: Incident belongs to '{incident.environmentId}', caller authorized for '{caller_env}'"

        # 4. Target identifier syntax and sanity check
        target_id = req.targetIdentifier.strip() if req.targetIdentifier else ""
        if not target_id or target_id.lower() in ("unknown", "n/a", "none", "", "null", "undefined"):
            return False, f"Invalid or placeholder target identifier: '{req.targetIdentifier}'. Placeholder targets rejected."

        if req.actionType == "BLOCK_SOURCE":
            try:
                ipaddress.ip_address(target_id)
            except ValueError:
                return False, f"Invalid IP address for containment: '{target_id}'. Command injection / non-IP rejected."

        # 5. Target presence in incident evidence context
        evidence_targets: Set[str] = set()
        evidence_event_ids: Set[str] = set()

        for det in detections:
            meta = det.metadata or {}
            if meta.get("sourceIp"):
                evidence_targets.add(meta.get("sourceIp"))
            if meta.get("userId"):
                evidence_targets.add(meta.get("userId"))
                evidence_targets.add(f"session-{meta.get('userId')}")
            if meta.get("sessionId"):
                evidence_targets.add(meta.get("sessionId"))
            evidence_targets.add(det.primaryAssetId)
            evidence_event_ids.update(det.matchedEventIds)
            evidence_event_ids.add(det.id)

        evidence_targets.add(incident.primaryAffectedAssetId)
        evidence_targets.update(incident.relatedAssetIds)

        if target_id not in evidence_targets:
            return False, (
                f"Target '{target_id}' is not present in incident '{incident.id}' evidence context. "
                "Containment actions must be grounded in verified incident evidence."
            )

        # 6. Supporting evidence IDs check (if explicitly provided)
        if req.supportingEvidenceIds:
            unmatched = [eid for eid in req.supportingEvidenceIds if eid not in evidence_event_ids]
            if unmatched:
                return False, f"Supporting evidence IDs not found in incident: {unmatched}"

        # 7. Action suitability for incident lifecycle
        if incident.status == "RESOLVED":
            return False, f"Cannot propose containment action on an already RESOLVED incident '{incident.id}'"

        # 8. Special check for ISOLATE_RESOURCE
        if req.actionType == "ISOLATE_RESOURCE":
            return False, "Unsupported action: Verifiable resource isolation is not implemented for this target."

        return True, None
