"""
==============================================================================
FILE: apps/api/app/db/repositories/risk_repository.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Thread-safe repository for risk score snapshots and historical time-series entries.
STRICT ISOLATION: Scoped strictly by environmentId.
==============================================================================
"""

import threading
from typing import Dict, List, Optional
from datetime import datetime, timezone

from app.schemas.risk import RiskScoreResponse, RiskHistoryEntryResponse


class RiskRepository:
    def __init__(self):
        self._lock = threading.RLock()
        # Key: environmentId -> RiskScoreResponse
        self._current_scores: Dict[str, RiskScoreResponse] = {}
        # Key: environmentId -> List[RiskHistoryEntryResponse]
        self._history: Dict[str, List[RiskHistoryEntryResponse]] = {}
        self._seed_default_risk()

    def _seed_default_risk(self):
        import os
        from app.core.production_guard import is_production_mode
        if is_production_mode() or "PYTEST_CURRENT_TEST" in os.environ:
            return
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        env_id = "env-prod"
        self._history[env_id] = [
            RiskHistoryEntryResponse(
                timestamp=(now - timedelta(hours=i * 4)).isoformat(),
                score=score,
                triggerEvent="Baseline Recalculation",
                environmentId=env_id,
                openPaths=2,
                openIncidents=1,
            )
            for i, score in enumerate([82, 78, 75, 70, 68, 64][::-1])
        ]

    def save_current_risk(self, risk: RiskScoreResponse) -> RiskScoreResponse:
        with self._lock:
            self._current_scores[risk.environmentId] = risk
            # Also record history entry
            entry = RiskHistoryEntryResponse(
                timestamp=risk.calculatedAt,
                score=risk.overallScore,
                triggerEvent="Risk Recalculation",
                environmentId=risk.environmentId,
                openPaths=getattr(risk, "activeAttackPathsCount", 0),
                openIncidents=getattr(risk, "activeIncidentsCount", 0),
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

def get_risk_repository() -> RiskRepository:
    global _risk_repo_instance
    if _risk_repo_instance is None:
        _risk_repo_instance = RiskRepository()
    return _risk_repo_instance
