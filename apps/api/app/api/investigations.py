"""
==============================================================================
FILE: apps/api/app/api/investigations.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Operational REST API for Deterministic Investigations and Evidence Timelines.
==============================================================================
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.schemas.investigation import (
    InvestigationResultResponse,
    InvestigationTimelineResponse
)
from app.investigation.engine import get_investigation_engine

router = APIRouter()


@router.post(
    "/{incident_id}/run",
    response_model=InvestigationResultResponse,
    summary="Run Deterministic Incident Investigation"
)
async def run_investigation(
    incident_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> InvestigationResultResponse:
    """
    Executes a deterministic, evidence-grounded investigation of an active incident.
    Constructs factual attack story, timeline, grounded evidence references, and recommendations.
    Strictly scoped to authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    engine = get_investigation_engine()

    result, err = engine.investigate_incident(incident_id, environment_id=auth_env)
    if err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=err
        )
    return result


@router.get(
    "/{incident_id}",
    response_model=InvestigationResultResponse,
    summary="Get Investigation Result"
)
async def get_investigation(
    incident_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> InvestigationResultResponse:
    """Retrieves an existing investigation result for the specified incident within authorized environment."""
    auth_env = enforce_environment_boundary(user, environment_id)
    engine = get_investigation_engine()

    result = engine.get_investigation(incident_id, environment_id=auth_env)
    if not result:
        result, err = engine.investigate_incident(incident_id, environment_id=auth_env)
        if err:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err
            )
    return result


@router.get(
    "/{incident_id}/timeline",
    response_model=InvestigationTimelineResponse,
    summary="Get Investigation Forensic Timeline"
)
async def get_investigation_timeline(
    incident_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> InvestigationTimelineResponse:
    """Retrieves the authoritative chronological timeline within authorized environment."""
    auth_env = enforce_environment_boundary(user, environment_id)
    engine = get_investigation_engine()

    timeline = engine.get_timeline(incident_id, environment_id=auth_env)
    if not timeline:
        result, err = engine.investigate_incident(incident_id, environment_id=auth_env)
        if err:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err
            )
        timeline = engine.get_timeline(incident_id, environment_id=auth_env)

    if not timeline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Timeline for incident '{incident_id}' could not be generated in environment '{auth_env}'."
        )
    return timeline
