import os
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
        if not os.environ.get("PYTEST_CURRENT_TEST"):
            self._seed_default_responses()

    def _seed_default_responses(self):
        env_id = "env-prod"
        seeds = [
            ResponseRecordResponse(
                id="ra-1",
                incidentId="inc-1",
                environmentId=env_id,
                actionType="ISOLATE_RESOURCE",
                targetType="ASSET_ID",
                targetIdentifier="auth-svc",
                status="PENDING_APPROVAL",
                reason="Isolate compromised auth-svc to sever lateral movement and stop credential abuse",
                proposedAt="2026-10-25T08:00:00Z",
                proposedBy="system",
            ),
            ResponseRecordResponse(
                id="ra-2",
                incidentId="inc-1",
                environmentId=env_id,
                actionType="DISABLE_SESSION",
                targetType="SESSION_ID",
                targetIdentifier="sess-analyst-compromised",
                status="PENDING_APPROVAL",
                reason="Revoke compromised session token for svc-role-auth",
                proposedAt="2026-10-25T08:00:00Z",
                proposedBy="system",
            ),
            ResponseRecordResponse(
                id="ra-3",
                incidentId="inc-1",
                environmentId=env_id,
                actionType="BLOCK_SOURCE",
                targetType="IP_ADDRESS",
                targetIdentifier="203.0.113.50",
                status="SUCCEEDED",
                reason="Perimeter blocklist drop rule enforced for malicious scanner",
                proposedAt="2026-10-25T08:00:00Z",
                proposedBy="system",
                approvedAt="2026-10-25T08:01:00Z",
                approvedBy="operator",
                executedAt="2026-10-25T08:01:05Z",
                executionMessage="Enforced perimeter blocklist drop for source IP '203.0.113.50'.",
                verificationStatus="VERIFIED",
                verificationMessage="Verified: IP '203.0.113.50' is actively registered in demo target blocklist.",
            ),
            ResponseRecordResponse(
                id="ra-4",
                incidentId="inc-4f3e5cf1",
                environmentId=env_id,
                actionType="BLOCK_SOURCE",
                targetType="IP_ADDRESS",
                targetIdentifier="198.51.100.101",
                status="PENDING_APPROVAL",
                reason="Adversary perimeter firewall containment for source IP 198.51.100.101",
                proposedAt="2026-10-25T08:00:00Z",
                proposedBy="system",
            ),
        ]
        for s in seeds:
            self._responses[(s.id, s.environmentId)] = s

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

