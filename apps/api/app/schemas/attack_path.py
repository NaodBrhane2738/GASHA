"""
==============================================================================
FILE: apps/api/app/schemas/attack_path.py
ROLE / OWNERSHIP: Backend Engineers & Threat Modelers
OBJECTIVE: Pydantic schemas for AttackPath calculations and nodes.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - AttackPathNodeSchema: Represents an individual hop along an attack path.
  - AttackPathResponse: Complete path model with severity, score, and active status.
EXPECTED RESULTS / BEHAVIOR:
  - Validates attack path graphs computed by the traversal engine.
==============================================================================
"""

from typing import List, Optional, Literal
from pydantic import BaseModel
from app.schemas.asset import AssetType

SeverityLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

class AttackPathNodeSchema(BaseModel):
    assetId: str
    assetName: str
    assetType: AssetType
    stepOrder: int
    vulnerabilityIds: Optional[List[str]] = None
    description: str

class AttackPathResponse(BaseModel):
    id: str
    entryPointAssetId: str
    targetAssetId: str
    severity: SeverityLevel
    pathScore: float
    nodes: List[AttackPathNodeSchema]
    isActive: bool
    discoveredAt: str
    mitigatedAt: Optional[str] = None
