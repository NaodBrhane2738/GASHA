"""
==============================================================================
FILE: apps/api/app/schemas/incident.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Pydantic schemas for correlated Incidents.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - IncidentResponse, IncidentCreate, IncidentUpdate
  - Status transitions: ACTIVE -> INVESTIGATING -> CONTAINED -> RESOLVED
EXPECTED RESULTS / BEHAVIOR:
  - Correlated incident data structures consumable by frontend incident triage drawer.
==============================================================================
"""

from typing import List, Optional, Literal
from pydantic import BaseModel

SeverityLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
IncidentStatus = Literal['ACTIVE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED']

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
