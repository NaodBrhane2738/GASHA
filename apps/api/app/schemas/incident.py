"""
=============================================================================
FILE: apps/api/app/schemas/incident.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Pydantic schemas for correlated Incidents.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - IncidentResponse, IncidentCreate, IncidentUpdate, IncidentStatusUpdate
  - Status transitions: ACTIVE -> INVESTIGATING -> CONTAINED -> RESOLVED
=============================================================================
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field

SeverityLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
IncidentStatus = Literal['ACTIVE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED']

VALID_STATUS_TRANSITIONS: Dict[IncidentStatus, List[IncidentStatus]] = {
    'ACTIVE': ['INVESTIGATING', 'CONTAINED', 'RESOLVED'],
    'INVESTIGATING': ['CONTAINED', 'RESOLVED', 'ACTIVE'],
    'CONTAINED': ['RESOLVED', 'INVESTIGATING'],
    'RESOLVED': ['ACTIVE', 'INVESTIGATING'],
}


class IncidentResponse(BaseModel):
    id: str
    title: str
    severity: SeverityLevel
    status: IncidentStatus
    primaryAffectedAssetId: str
    relatedAssetIds: List[str]
    detectionEventIds: List[str]
    attackPathId: Optional[str] = None
    createdAt: str
    updatedAt: str
    summary: Optional[str] = None
    environmentId: Optional[str] = "env-prod"
    correlationKey: Optional[str] = None
    # Parity fields for frontend (@gasha/contracts Incident)
    openedAt: Optional[str] = None
    detectionIds: Optional[List[str]] = None
    pathId: Optional[str] = None
    confidence: float = 0.90
    riskBefore: float = 75.0
    riskAfter: Optional[float] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.openedAt:
            self.openedAt = self.createdAt
        if self.detectionIds is None:
            self.detectionIds = self.detectionEventIds
        if not self.pathId:
            self.pathId = self.attackPathId


class IncidentCreate(BaseModel):
    title: str
    severity: SeverityLevel
    status: IncidentStatus = "ACTIVE"
    primaryAffectedAssetId: str
    relatedAssetIds: List[str] = []
    detectionEventIds: List[str] = []
    attackPathId: Optional[str] = None
    summary: Optional[str] = None
    environmentId: str = "env-prod"
    correlationKey: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    reason: Optional[str] = None
