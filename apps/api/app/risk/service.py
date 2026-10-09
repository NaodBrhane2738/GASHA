"""
==============================================================================
FILE: apps/api/app/risk/service.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Orchestration service for risk calculation, caching, and persistence.
==============================================================================
"""

import logging
from typing import List, Optional

from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.db.repositories.attack_path_repository import get_attack_path_repository
from app.db.repositories.risk_repository import get_risk_repository
from app.db.repositories.incident_repository import get_incident_repository
from app.schemas.risk import RiskScoreResponse, RiskHistoryEntryResponse
from app.risk.calculator import calculate_environment_risk

logger = logging.getLogger("gasha.risk.service")


class RiskService:
    def __init__(self):
        self.asset_repo = get_asset_repository()
        self.vuln_repo = get_vulnerability_repository()
        self.path_repo = get_attack_path_repository()
        self.risk_repo = get_risk_repository()
        self.incident_repo = get_incident_repository()

    def recalculate_risk(self, environment_id: str) -> RiskScoreResponse:
        """
        Executes deterministic risk calculation and updates persistent risk state.
        """
        logger.info(f"Recalculating risk for environment: {environment_id}")
        assets = self.asset_repo.list_assets(environment_id=environment_id)
        findings = self.vuln_repo.list_findings(environment_id=environment_id)
        paths = self.path_repo.list_attack_paths(environment_id=environment_id)

        # Active incidents count
        active_incidents = 0
        try:
            incidents = self.incident_repo.list_incidents(environment_id=environment_id)
            active_incidents = sum(1 for inc in incidents if inc.status in ("ACTIVE", "INVESTIGATING"))
        except Exception:
            pass

        score_response = calculate_environment_risk(
            environment_id=environment_id,
            assets=assets,
            findings=findings,
            attack_paths=paths,
            active_incidents_count=active_incidents
        )

        self.risk_repo.save_current_risk(score_response)
        return score_response

    def get_current_risk(self, environment_id: str) -> RiskScoreResponse:
        cached = self.risk_repo.get_current_risk(environment_id)
        if cached:
            return cached
        # Compute if not yet calculated
        return self.recalculate_risk(environment_id)

    def get_risk_history(self, environment_id: str, limit: int = 50) -> List[RiskHistoryEntryResponse]:
        return self.risk_repo.get_history(environment_id=environment_id, limit=limit)


_risk_service_instance: Optional[RiskService] = None

def get_risk_service() -> RiskService:
    global _risk_service_instance
    if _risk_service_instance is None:
        _risk_service_instance = RiskService()
    return _risk_service_instance
