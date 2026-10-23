"""
==============================================================================
FILE: apps/api/app/db/repositories/incident_repository.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Thread-safe repository interface and in-memory adapter for
           correlated Incident records, lifecycle management, and evidence association.
==============================================================================
"""

import os
import threading
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from app.schemas.incident import IncidentResponse, IncidentStatus, VALID_STATUS_TRANSITIONS

SEVERITY_RANKS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class IncidentRepository:
    """Thread-safe Incident repository with lifecycle validation and environment isolation."""
    def __init__(self):
        self._lock = threading.Lock()
        self._incidents: Dict[str, IncidentResponse] = {}
        self._seed_default_incidents()

    def _seed_default_incidents(self):
        # Clean production-live state: zero mock incidents
        pass

    def create_incident(self, incident: IncidentResponse) -> IncidentResponse:
        with self._lock:
            self._incidents[incident.id] = incident
            return incident

    def save_incident(self, incident: IncidentResponse) -> IncidentResponse:
        return self.create_incident(incident)


    def get_incident(
        self,
        incident_id: str,
        environment_id: Optional[str] = None
    ) -> Optional[IncidentResponse]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None
            if environment_id and inc.environmentId != environment_id:
                return None
            return inc

    def list_incidents(
        self,
        environment_id: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[IncidentResponse]:
        with self._lock:
            results = list(self._incidents.values())
            if environment_id:
                results = [i for i in results if i.environmentId == environment_id]
            if status:
                results = [i for i in results if i.status == status]
            return sorted(results, key=lambda x: x.createdAt, reverse=True)

    def update_incident(
        self,
        incident_id: str,
        update_data: Dict[str, Any],
        environment_id: Optional[str] = None
    ) -> Optional[IncidentResponse]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None
            if environment_id and inc.environmentId != environment_id:
                return None

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            dump = inc.model_dump()
            dump.update(update_data)
            dump["updatedAt"] = now_iso
            updated = IncidentResponse(**dump)
            self._incidents[incident_id] = updated
            return updated

    def update_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        environment_id: Optional[str] = None
    ) -> Optional[IncidentResponse]:
        """Applies a valid lifecycle transition to an incident."""
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None
            if environment_id and inc.environmentId != environment_id:
                return None

            allowed = VALID_STATUS_TRANSITIONS.get(inc.status, [])
            if new_status not in allowed:
                raise ValueError(
                    f"Invalid incident status transition from '{inc.status}' to '{new_status}'. "
                    f"Allowed transitions: {allowed}"
                )

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            dump = inc.model_dump()
            dump["status"] = new_status
            dump["updatedAt"] = now_iso
            updated = IncidentResponse(**dump)
            self._incidents[incident_id] = updated
            return updated

    def attach_detection(
        self,
        incident_id: str,
        detection_id: str,
        related_asset_id: Optional[str] = None,
        new_severity: Optional[str] = None
    ) -> Optional[IncidentResponse]:
        """Appends a new detection finding to an incident and upgrades severity if applicable."""
        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return None

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            dump = inc.model_dump()

            det_ids = list(dump.get("detectionEventIds", []))
            if detection_id not in det_ids:
                det_ids.append(detection_id)
            dump["detectionEventIds"] = det_ids

            if related_asset_id:
                asset_ids = list(dump.get("relatedAssetIds", []))
                if related_asset_id not in asset_ids and related_asset_id != dump.get("primaryAffectedAssetId"):
                    asset_ids.append(related_asset_id)
                dump["relatedAssetIds"] = asset_ids

            if new_severity and SEVERITY_RANKS.get(new_severity, 0) > SEVERITY_RANKS.get(dump.get("severity"), 0):
                dump["severity"] = new_severity

            dump["updatedAt"] = now_iso
            updated = IncidentResponse(**dump)
            self._incidents[incident_id] = updated
            return updated

    def clear(self):
        with self._lock:
            self._incidents.clear()


# Global singleton incident repository
_default_incident_repo: Optional[IncidentRepository] = None


def get_incident_repository(storage_backend: Optional[str] = None) -> Any:
    global _default_incident_repo
    backend = storage_backend or os.environ.get("GASHA_STORAGE_BACKEND", "memory")
    if backend == "sql":
        from app.db.sql_engine import SQLIncidentRepository
        return SQLIncidentRepository()
    if _default_incident_repo is None:
        _default_incident_repo = IncidentRepository()
    return _default_incident_repo

