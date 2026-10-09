"""
==============================================================================
FILE: apps/api/app/api/environment.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Endpoints to inspect global environment status and containment state.
==============================================================================
"""

from fastapi import APIRouter, Depends, Query
from typing import Dict, Any, Optional
from app.core.auth import get_current_user, enforce_environment_boundary
from app.risk.service import get_risk_service
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.asset_repository import get_asset_repository

router = APIRouter()


@router.get("/state", summary="Get Operational Environment State")
async def get_environment_state(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    auth_env = enforce_environment_boundary(user, environment_id)
    risk_svc = get_risk_service()
    current_risk = risk_svc.get_current_risk(auth_env)

    inc_repo = get_incident_repository()
    active_incidents = inc_repo.list_incidents(environment_id=auth_env, status="ACTIVE")

    asset_repo = get_asset_repository()
    assets = asset_repo.list_assets(auth_env)

    containment_mode = "ACTIVE_DEFENSE" if active_incidents else "NORMAL"

    return {
        "id": auth_env,
        "name": f"GASHA Protected Environment ({auth_env})",
        "syncedAt": current_risk.calculatedAt,
        "totalAssets": len(assets),
        "activeIncidentsCount": len(active_incidents),
        "currentRiskScore": current_risk.overallScore,
        "containmentMode": containment_mode
    }
