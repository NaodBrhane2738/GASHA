"""
==============================================================================
FILE: apps/api/app/api/incidents.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Endpoints for Incident lifecycle management (triage, status changes).
TOOLS & LIBRARIES: FastAPI APIRouter, app.schemas.incident
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - GET /api/v1/incidents: List correlated security incidents with status filter.
  - GET /api/v1/incidents/{incident_id}: Return incident timeline and associated detections.
  - PATCH /api/v1/incidents/{incident_id}/status: Update incident triage status.
EXPECTED RESULTS / BEHAVIOR:
  - Powers the incident queue and triage workflow in the web frontend.
==============================================================================
"""

from fastapi import APIRouter, Depends
from typing import List, Optional
from app.core.auth import get_current_user
from app.schemas.incident import IncidentResponse

router = APIRouter()

@router.get("", response_model=List[IncidentResponse])
async def list_incidents(status: Optional[str] = None, user: dict = Depends(get_current_user)):
    return []

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, user: dict = Depends(get_current_user)):
    return {
        "id": incident_id,
        "title": "Suspicious Authentication & Lateral Access",
        "severity": "HIGH",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-auth-service",
        "relatedAssetIds": ["asset-db"],
        "detectionEventIds": ["det-001"],
        "createdAt": "2026-09-18T00:00:00Z",
        "updatedAt": "2026-09-18T00:00:00Z"
    }
