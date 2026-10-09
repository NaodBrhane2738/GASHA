"""
==============================================================================
FILE: apps/api/app/db/repositories/investigation_repository.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Thread-safe repository for persisting and querying Investigation results.
==============================================================================
"""

import threading
from typing import Dict, List, Optional, Any
from app.schemas.investigation import InvestigationResultResponse, InvestigationTimelineResponse


class InvestigationRepository:
    def __init__(self):
        self._lock = threading.RLock()
        # Key: (incident_id, environment_id) -> InvestigationResultResponse
        self._investigations: Dict[tuple, InvestigationResultResponse] = {}
        # Key: (incident_id, environment_id) -> InvestigationTimelineResponse
        self._timelines: Dict[tuple, InvestigationTimelineResponse] = {}

    def save_investigation(self, result: InvestigationResultResponse, environment_id: str) -> None:
        with self._lock:
            key = (result.incidentId, environment_id)
            self._investigations[key] = result

    def get_investigation(self, incident_id: str, environment_id: str) -> Optional[InvestigationResultResponse]:
        with self._lock:
            key = (incident_id, environment_id)
            return self._investigations.get(key)

    def list_investigations(self, environment_id: str) -> List[InvestigationResultResponse]:
        with self._lock:
            return [inv for (inc_id, env), inv in self._investigations.items() if env == environment_id]

    def save_timeline(self, timeline: InvestigationTimelineResponse) -> None:
        with self._lock:
            key = (timeline.incidentId, timeline.environmentId)
            self._timelines[key] = timeline

    def get_timeline(self, incident_id: str, environment_id: str) -> Optional[InvestigationTimelineResponse]:
        with self._lock:
            key = (incident_id, environment_id)
            return self._timelines.get(key)

    def clear(self) -> None:
        with self._lock:
            self._investigations.clear()
            self._timelines.clear()


_default_repo: Optional[InvestigationRepository] = None


def get_investigation_repository(storage_backend: Optional[str] = None) -> Any:
    global _default_repo
    from app.db.storage_mode import resolve_storage_backend, StorageMode
    backend = resolve_storage_backend(storage_backend)
    if backend == StorageMode.SQL:
        from app.db.sql_engine import SQLInvestigationRepository
        return SQLInvestigationRepository()
    if _default_repo is None:
        _default_repo = InvestigationRepository()
    return _default_repo
