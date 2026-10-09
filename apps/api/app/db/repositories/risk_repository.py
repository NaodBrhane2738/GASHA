"""
==============================================================================
FILE: apps/api/app/db/repositories/risk_repository.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Thread-safe repository for risk score snapshots and historical time-series entries.
STRICT ISOLATION: Scoped strictly by environmentId.
==============================================================================
"""

import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from app.schemas.risk import RiskScoreResponse, RiskHistoryEntryResponse


class RiskRepository:
    def __init__(self):
        self._lock = threading.RLock()
        # Key: environmentId -> RiskScoreResponse
        self._current_scores: Dict[str, RiskScoreResponse] = {}
        # Key: environmentId -> List[RiskHistoryEntryResponse]
        self._history: Dict[str, List[RiskHistoryEntryResponse]] = {}

    def save_current_risk(self, risk: RiskScoreResponse) -> RiskScoreResponse:
        with self._lock:
            self._current_scores[risk.environmentId] = risk
            # Also record history entry
            entry = RiskHistoryEntryResponse(
                timestamp=risk.calculatedAt,
                score=risk.overallScore,
                triggerEvent="Risk Recalculation",
                environmentId=risk.environmentId
            )
            if risk.environmentId not in self._history:
                self._history[risk.environmentId] = []
            self._history[risk.environmentId].append(entry)
            return risk

    def get_current_risk(self, environment_id: str) -> Optional[RiskScoreResponse]:
        with self._lock:
            return self._current_scores.get(environment_id)

    def add_history_entry(self, entry: RiskHistoryEntryResponse):
        with self._lock:
            if entry.environmentId not in self._history:
                self._history[entry.environmentId] = []
            self._history[entry.environmentId].append(entry)

    def get_history(self, environment_id: str, limit: int = 50) -> List[RiskHistoryEntryResponse]:
        with self._lock:
            entries = self._history.get(environment_id, [])
            return list(entries[-limit:])

    def clear(self, environment_id: Optional[str] = None):
        with self._lock:
            if environment_id:
                self._current_scores.pop(environment_id, None)
                self._history.pop(environment_id, None)
            else:
                self._current_scores.clear()
                self._history.clear()


_risk_repo_instance: Optional[RiskRepository] = None

def get_risk_repository(storage_backend: Optional[str] = None) -> Any:
    global _risk_repo_instance
    from app.db.storage_mode import resolve_storage_backend, StorageMode
    backend = resolve_storage_backend(storage_backend)
    if backend == StorageMode.SQL:
        from app.db.sql_engine import SQLRiskRepository
        return SQLRiskRepository()
    if _risk_repo_instance is None:
        _risk_repo_instance = RiskRepository()
    return _risk_repo_instance
