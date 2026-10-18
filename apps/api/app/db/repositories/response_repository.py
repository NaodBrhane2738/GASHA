"""
==============================================================================
FILE: apps/api/app/db/repositories/response_repository.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Thread-safe repository for active response proposals and execution records.
==============================================================================
"""

import threading
from typing import Dict, List, Optional, Any
from app.schemas.response import ResponseRecordResponse, ResponseStatus


class ResponseRepository:
    def __init__(self):
        self._lock = threading.RLock()
        self._responses: Dict[tuple, ResponseRecordResponse] = {}
        self._seed_default_responses()

    def _seed_default_responses(self):
        import os
        from app.core.production_guard import is_production_mode
        if is_production_mode() or "PYTEST_CURRENT_TEST" in os.environ:
            return
        from datetime import datetime, timezone
        now_iso = datetime.now(timezone.utc).isoformat()
        r1 = ResponseRecordResponse(
            id="resp-1",
            incidentId="inc-1",
            environmentId="env-prod",
            actionType="BLOCK_SOURCE",
            targetType="IP_ADDRESS",
            targetIdentifier="198.51.100.42",
            status="PROPOSED",
            proposedBy="analyst",
            proposedAt=now_iso,
            reason="Repeated authentication attack on auth-service",
            supportingEvidenceIds=["det-1"]
        )
        self.save_response(r1)

    def save_response(self, record: ResponseRecordResponse) -> None:
        with self._lock:
            key = (record.id, record.environmentId)
            self._responses[key] = record

    def get_response(self, response_id: str, environment_id: str) -> Optional[ResponseRecordResponse]:
        with self._lock:
            key = (response_id, environment_id)
            return self._responses.get(key)

    def list_responses(
        self,
        environment_id: str,
        incident_id: Optional[str] = None
    ) -> List[ResponseRecordResponse]:
        with self._lock:
            results = [
                rec for (r_id, env), rec in self._responses.items()
                if env == environment_id
            ]
            if incident_id:
                results = [r for r in results if r.incidentId == incident_id]
            return results

    def clear(self) -> None:
        with self._lock:
            self._responses.clear()


_default_response_repo: Optional[ResponseRepository] = None


def get_response_repository(storage_backend: Optional[str] = None) -> Any:
    global _default_response_repo
    import os
    backend = storage_backend or os.environ.get("GASHA_STORAGE_BACKEND", "memory")
    if backend == "sql":
        from app.db.sql_engine import SQLResponseRepository
        return SQLResponseRepository()
    if _default_response_repo is None:
        _default_response_repo = ResponseRepository()
    return _default_response_repo

