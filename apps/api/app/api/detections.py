"""
==============================================================================
FILE: apps/api/app/api/detections.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Operational endpoints to list triggered detection events, query active
           detection rules, and inspect detection evidence.
TOOLS & LIBRARIES: FastAPI APIRouter, app.schemas.detection
==============================================================================
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.schemas.detection import DetectionEventResponse
from app.detection.rules.catalog import ALL_RULES, DetectionRuleDefinition
from app.db.repositories.detection_repository import get_detection_repository

router = APIRouter()


@router.get("", response_model=List[DetectionEventResponse], summary="List Detection Events")
async def list_detections(
    incident_id: Optional[str] = Query(None, alias="incidentId"),
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> List[DetectionEventResponse]:
    """Returns detected security events filtered by authorized environment and optional incident."""
    auth_env = enforce_environment_boundary(user, environment_id)
    repo = get_detection_repository()
    return repo.list_detections(environment_id=auth_env, incident_id=incident_id)


@router.get("/rules", response_model=List[DetectionRuleDefinition], summary="List Active Detection Rules")
async def list_detection_rules(
    user: dict = Depends(get_current_user)
) -> List[DetectionRuleDefinition]:
    """Returns the catalog of active deterministic detection rules loaded in the engine."""
    return ALL_RULES


@router.get("/{detection_id}", response_model=DetectionEventResponse, summary="Get Detection Event")
async def get_detection(
    detection_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> DetectionEventResponse:
    """Retrieves a single detection event by ID with evidence citations strictly within caller's environment."""
    auth_env = enforce_environment_boundary(user, environment_id)
    repo = get_detection_repository()
    detection = repo.get_detection(detection_id, environment_id=auth_env)
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection event '{detection_id}' not found in environment '{auth_env}'"
        )
    return detection
