"""
==============================================================================
FILE: apps/api/app/correlation/engine.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Multi-event correlation engine. Aggregates related detection findings
           within sliding time windows along environment, source, and target dimensions
           into unified, evidence-linked Incidents.
==============================================================================
"""

import time
import uuid
import logging
from typing import Optional, Dict, Tuple, Any
from datetime import datetime, timezone

from app.schemas.detection import DetectionEventResponse
from app.schemas.incident import IncidentResponse, IncidentStatus
from app.db.repositories.incident_repository import IncidentRepository, get_incident_repository
from app.db.repositories.detection_repository import DetectionRepository, get_detection_repository

logger = logging.getLogger("gasha.correlation.engine")

TITLE_MAP = {
    "RULE-AUTH-001": "Brute Force Authentication Activity",
    "RULE-INJ-002": "Suspicious Web Intrusion & Injection Probes",
    "RULE-PROBE-003": "Sensitive Administrative Endpoint Scanning",
    "RULE-PRIV-004": "Unauthorized Privilege Mutation & Escalation Attempt",
}


class CorrelationEngine:
    """
    Correlates detection findings into cohesive incidents across tenant/environment,
    source, and asset boundaries within configurable sliding time windows.
    """
    def __init__(
        self,
        window_seconds: float = 60.0,
        incident_repo: Optional[IncidentRepository] = None,
        detection_repo: Optional[DetectionRepository] = None
    ):
        self.window_seconds = window_seconds
        self.incident_repo = incident_repo or get_incident_repository()
        self.detection_repo = detection_repo or get_detection_repository()

        # compound_key -> {"incident_id": str, "last_updated": float}
        self._active_bindings: Dict[str, Dict[str, Any]] = {}

    def _build_correlation_key(self, detection: DetectionEventResponse) -> str:
        """
        Builds a deterministic correlation key partitioning by:
        environment, attack family, source entity, and target asset.
        """
        env = detection.environmentId or "env-prod"
        meta = detection.metadata or {}
        source_id = meta.get("sourceIp") or meta.get("userId") or "unspecified_source"
        rule_family = detection.rule.ruleId.split("-")[1] if "-" in detection.rule.ruleId else "SEC"
        target_asset = detection.primaryAssetId or "global"

        return f"{env}:{rule_family}:{source_id}:{target_asset}"

    def correlate_detection(
        self,
        detection: DetectionEventResponse
    ) -> Tuple[IncidentResponse, bool]:
        """
        Correlates a detection finding.
        If an active incident exists within the correlation window for the same key,
        attaches the detection to it. Otherwise, creates a new incident.
        Returns:
            (incident, is_new: bool)
        """
        now = time.time()
        corr_key = self._build_correlation_key(detection)
        binding = self._active_bindings.get(corr_key)

        # 1. Check for existing active incident in window
        if binding:
            if (now - binding["last_updated"]) <= self.window_seconds:
                active_incident = self.incident_repo.get_incident(
                    binding["incident_id"],
                    environment_id=detection.environmentId
                )
                if active_incident and active_incident.status in ("ACTIVE", "INVESTIGATING"):
                    # Attach detection to existing incident
                    updated = self.incident_repo.attach_detection(
                        incident_id=active_incident.id,
                        detection_id=detection.id,
                        related_asset_id=detection.primaryAssetId,
                        new_severity=detection.severity
                    )
                    # Update binding timestamp
                    binding["last_updated"] = now
                    # Link detection in detection repo
                    self.detection_repo.link_to_incident(detection.id, active_incident.id)

                    logger.info(
                        f"Correlated detection '{detection.id}' ({detection.rule.ruleId}) into existing "
                        f"incident '{active_incident.id}'"
                    )
                    return updated or active_incident, False

        # 2. Create new Incident
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        new_inc_id = f"inc-{uuid.uuid4().hex[:8]}"

        meta = detection.metadata or {}
        source_id = meta.get("sourceIp") or meta.get("userId") or "Unknown Entity"
        rule_title = TITLE_MAP.get(detection.rule.ruleId, detection.rule.name)
        incident_title = f"{rule_title} [{source_id}]"

        summary = (
            f"Deterministic correlation engine detected suspicious activity: {detection.evidenceSummary} "
            f"Mapped to MITRE ATT&CK technique {meta.get('mitreTechniqueId', 'N/A')}."
        )

        new_incident = IncidentResponse(
            id=new_inc_id,
            title=incident_title,
            severity=detection.severity,
            status="ACTIVE",
            primaryAffectedAssetId=detection.primaryAssetId,
            relatedAssetIds=[],
            detectionEventIds=[detection.id],
            summary=summary,
            environmentId=detection.environmentId,
            correlationKey=corr_key,
            createdAt=now_iso,
            updatedAt=now_iso
        )

        created = self.incident_repo.create_incident(new_incident)

        # Record binding
        self._active_bindings[corr_key] = {
            "incident_id": new_inc_id,
            "last_updated": now
        }

        # Link detection
        self.detection_repo.link_to_incident(detection.id, new_inc_id)

        logger.info(
            f"Created new correlated incident '{new_inc_id}' for detection '{detection.id}' "
            f"in environment '{detection.environmentId}'"
        )
        return created, True

    def reset_state(self):
        """Resets active correlation window bindings for test isolation."""
        self._active_bindings.clear()


# Global singleton correlation engine
_default_correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    global _default_correlation_engine
    if _default_correlation_engine is None:
        _default_correlation_engine = CorrelationEngine()
    return _default_correlation_engine
