"""
==============================================================================
FILE: apps/api/app/api/risks.py
ROLE / OWNERSHIP: Backend Engineers & Security Analysts
OBJECTIVE: Endpoints for querying quantitative risk scores, breakdowns, and historical trends.
STRICT ISOLATION: Scoped strictly by environmentId.
==============================================================================
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query

from app.core.auth import get_current_user, enforce_environment_boundary
from app.schemas.risk import RiskScoreResponse, RiskHistoryEntryResponse
from app.risk.service import get_risk_service

logger = logging.getLogger("gasha.api.risks")
router = APIRouter()


@router.get("/current", response_model=RiskScoreResponse, summary="Get Current Environment Risk")
async def get_current_risk(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> RiskScoreResponse:
    """
    Returns current quantitative risk score (0-100) and explainable contributor breakdown.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    service = get_risk_service()
    return service.get_current_risk(auth_env)


@router.get("/history", response_model=List[RiskHistoryEntryResponse], summary="Get Risk History Timeline")
async def get_risk_history(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(get_current_user)
) -> List[RiskHistoryEntryResponse]:
    """
    Returns historical risk timeline progression entries for charting.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    service = get_risk_service()
    return service.get_risk_history(auth_env, limit=limit)


@router.post("/recalculate", response_model=RiskScoreResponse, summary="Recalculate Environment Risk")
async def recalculate_risk(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> RiskScoreResponse:
    """
    Triggers explicit recalculation of risk based on current digital twin and finding states.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    service = get_risk_service()
    return service.recalculate_risk(auth_env)
