"""
==============================================================================
FILE: apps/api/app/api/incidents.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Operational endpoints for Incident lifecycle management (triage, status changes).
TOOLS & LIBRARIES: FastAPI APIRouter, app.schemas.incident
==============================================================================
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.schemas.incident import IncidentResponse, IncidentStatusUpdate
from app.db.repositories.incident_repository import get_incident_repository
from app.api.realtime import broadcast_system_event

router = APIRouter()


@router.get("", response_model=List[IncidentResponse], summary="List Correlated Incidents")
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> List[IncidentResponse]:
    """Lists correlated security incidents within the authorized environment."""
    auth_env = enforce_environment_boundary(user, environment_id)
    repo = get_incident_repository()
    return repo.list_incidents(environment_id=auth_env, status=status_filter)


@router.get("/{incident_id}", response_model=IncidentResponse, summary="Get Incident Details")
async def get_incident(
    incident_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> IncidentResponse:
    """Retrieves full incident details strictly within the caller's authorized environment."""
    auth_env = enforce_environment_boundary(user, environment_id)
    repo = get_incident_repository()
    incident = repo.get_incident(incident_id, environment_id=auth_env)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found in environment '{auth_env}'"
        )
    return incident


@router.patch("/{incident_id}/status", response_model=IncidentResponse, summary="Update Incident Lifecycle Status")
async def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> IncidentResponse:
    """
    Applies a deterministic lifecycle transition (ACTIVE -> INVESTIGATING -> CONTAINED -> RESOLVED).
    Rejects invalid state transitions and cross-environment mutations.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    repo = get_incident_repository()
    try:
        updated = repo.update_status(
            incident_id=incident_id,
            new_status=payload.status,
            environment_id=auth_env
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found in environment '{auth_env}'"
        )

    # Broadcast status change to realtime stream scoped to this environment
    try:
        await broadcast_system_event("incident.updated", updated.model_dump(), environment_id=auth_env)
    except Exception:
        pass

    return updated
