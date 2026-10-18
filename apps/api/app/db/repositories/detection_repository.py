"""
==============================================================================
FILE: apps/api/app/db/repositories/detection_repository.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Repository interface and in-memory adapter for storing and querying
           triggered detection findings.
==============================================================================
"""

import threading
from typing import List, Optional, Dict, Any
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema


class DetectionRepository:
    """Thread-safe detection repository."""
    def __init__(self):
        self._lock = threading.Lock()
        self._detections: Dict[str, DetectionEventResponse] = {}
        self._seed_default_detections()

    def _seed_default_detections(self):
        import os
        from app.core.production_guard import is_production_mode
        if is_production_mode() or "PYTEST_CURRENT_TEST" in os.environ:
            return
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        dets = [
            DetectionEventResponse(
                id="det-1",
                rule=DetectionRuleSummarySchema(
                    ruleId="RULE-AUTH-001",
                    name="Brute-force authentication attempt",
                    description="5 failed logins in 12s from 198.51.100.42",
                    severity="HIGH",
                    confidence=0.92
                ),
                matchedEventIds=["evt-1", "evt-2"],
                primaryAssetId="auth-svc",
                timestamp=now_iso,
                severity="HIGH",
                confidence=0.92,
                evidenceSummary="5 failed logins in 12s from 198.51.100.42",
                environmentId="env-prod",
                incidentId="inc-1",
                metadata={"mitreTechniqueId": "T1110", "sourceIp": "198.51.100.42"}
            ),
            DetectionEventResponse(
                id="det-2",
                rule=DetectionRuleSummarySchema(
                    ruleId="RULE-INJ-002",
                    name="SQL injection probe on user lookup",
                    description="UNION SELECT payload detected in parameter q",
                    severity="CRITICAL",
                    confidence=0.96
                ),
                matchedEventIds=["evt-3"],
                primaryAssetId="pg-main",
                timestamp=now_iso,
                severity="CRITICAL",
                confidence=0.96,
                evidenceSummary="UNION SELECT payload detected in parameter q",
                environmentId="env-prod",
                incidentId="inc-1",
                metadata={"mitreTechniqueId": "T1190"}
            )
        ]
        for d in dets:
            self._detections[d.id] = d

    def create_detection(self, detection: DetectionEventResponse) -> DetectionEventResponse:
        with self._lock:
            self._detections[detection.id] = detection
            return detection

    def save_detection(self, detection: DetectionEventResponse) -> DetectionEventResponse:
        return self.create_detection(detection)


    def get_detection(
        self,
        detection_id: str,
        environment_id: Optional[str] = None
    ) -> Optional[DetectionEventResponse]:
        with self._lock:
            det = self._detections.get(detection_id)
            if not det:
                return None
            if environment_id and det.environmentId != environment_id:
                return None
            return det

    def list_detections(
        self,
        environment_id: Optional[str] = None,
        incident_id: Optional[str] = None
    ) -> List[DetectionEventResponse]:
        with self._lock:
            results = list(self._detections.values())
            if environment_id:
                results = [d for d in results if d.environmentId == environment_id]
            if incident_id:
                results = [d for d in results if d.incidentId == incident_id]
            return sorted(results, key=lambda x: x.timestamp, reverse=True)

    def link_to_incident(self, detection_id: str, incident_id: str) -> Optional[DetectionEventResponse]:
        with self._lock:
            det = self._detections.get(detection_id)
            if det:
                det.incidentId = incident_id
                return det
            return None

    def clear(self):
        with self._lock:
            self._detections.clear()


# Global singleton detection repository
_default_detection_repo: Optional[DetectionRepository] = None


def get_detection_repository(storage_backend: Optional[str] = None) -> Any:
    global _default_detection_repo
    import os
    backend = storage_backend or os.environ.get("GASHA_STORAGE_BACKEND", "memory")
    if backend == "sql":
        from app.db.sql_engine import SQLDetectionRepository
        return SQLDetectionRepository()
    if _default_detection_repo is None:
        _default_detection_repo = DetectionRepository()
    return _default_detection_repo

