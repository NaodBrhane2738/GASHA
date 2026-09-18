"""
==============================================================================
FILE: apps/api/app/api/detections.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Endpoints to list triggered detection events and query active detection rules.
TOOLS & LIBRARIES: FastAPI APIRouter, app.schemas.detection
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - GET /api/v1/detections: Returns stream of matched detection events.
  - GET /api/v1/detections/rules: Lists active deterministic detection rules loaded in the engine.
EXPECTED RESULTS / BEHAVIOR:
  - Returns rule match evidence, matched event IDs, and confidence scores.
==============================================================================
"""

from fastapi import APIRouter, Depends
from typing import List
from app.core.auth import get_current_user
from app.schemas.detection import DetectionEventResponse

router = APIRouter()

@router.get("", response_model=List[DetectionEventResponse])
async def list_detections(incident_id: str = None, user: dict = Depends(get_current_user)):
    return []
