"""
==============================================================================
FILE: apps/api/app/schemas/attack_path.py
ROLE / OWNERSHIP: Backend Engineers & Threat Modelers
OBJECTIVE: Pydantic schemas for AttackPath calculations and nodes.
TOOLS & LIBRARIES: Pydantic v2
CONTRACT COMPLIANCE: Conforms strictly to @gasha/contracts (AttackPath).
==============================================================================
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field
from app.schemas.asset import AssetType

SeverityLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
ReachabilityStatus = Literal['REACHABLE', 'BLOCKED', 'UNKNOWN']


class AttackPathNodeSchema(BaseModel):
    assetId: str
    assetName: str
    assetType: AssetType
    stepOrder: int
    vulnerabilityIds: Optional[List[str]] = None
    description: str


class AttackPathResponse(BaseModel):
    id: str
    environmentId: str = "env-prod"
    entryPointAssetId: str
    targetAssetId: str
    severity: SeverityLevel
    pathScore: float  # 0.0 - 100.0
    nodes: List[AttackPathNodeSchema]
    isActive: bool
    reachability: ReachabilityStatus = 'REACHABLE'
    discoveredAt: str
    mitigatedAt: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # Parity & cross-platform fields
    techniques: List[str] = Field(default_factory=list)
    entryNodeId: Optional[str] = None
    crownJewelNodeId: Optional[str] = None
    nodeIds: List[str] = Field(default_factory=list)
    edgeIds: List[str] = Field(default_factory=list)
    likelihood: float = 0.75
    impact: float = 0.90
    riskScore: float = 0.0
    status: Literal['open', 'mitigated', 'accepted'] = 'open'
