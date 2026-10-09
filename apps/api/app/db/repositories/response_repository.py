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
        # Key: (response_id, environment_id) -> ResponseRecordResponse
        self._responses: Dict[tuple, ResponseRecordResponse] = {}

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
    from app.db.storage_mode import resolve_storage_backend, StorageMode
    backend = resolve_storage_backend(storage_backend)
    if backend == StorageMode.SQL:
        from app.db.sql_engine import SQLResponseRepository
        return SQLResponseRepository()
    if _default_response_repo is None:
        _default_response_repo = ResponseRepository()
    return _default_response_repo

