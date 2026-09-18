"""
==============================================================================
FILE: apps/api/app/schemas/asset.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Pydantic schemas for Assets and Graph Relationships matching @gasha/contracts.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - AssetBase, AssetCreate, AssetResponse: Serialization models for discovered infrastructure.
  - RelationshipBase, RelationshipResponse: Models for directed graph edges.
EXPECTED RESULTS / BEHAVIOR:
  - Strict type validation and JSON serialization matching TypeScript contracts.
==============================================================================
"""

from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

AssetType = Literal[
    'SERVICE',
    'DATABASE',
    'API_ENDPOINT',
    'LAMBDA_FUNCTION',
    'VERCEL_DEPLOYMENT',
    'GITHUB_REPOSITORY',
    'SECRET_STORE',
    'IDENTITY_ROLE',
    'STORAGE_BUCKET'
]

AssetCriticality = Literal['TIER_0_CROWN_JEWEL', 'TIER_1_HIGH', 'TIER_2_MEDIUM', 'TIER_3_LOW']
AssetStatus = Literal['ACTIVE', 'DEGRADED', 'ISOLATED', 'INACTIVE']

class AssetBase(BaseModel):
    name: str
    type: AssetType
    criticality: AssetCriticality = 'TIER_2_MEDIUM'
    environmentId: str
    source: Literal['VERCEL', 'GITHUB', 'TELEMETRY', 'STATIC_CONFIG']
    metadata: Dict[str, Any] = Field(default_factory=dict)
    isPubliclyExposed: bool = False
    status: AssetStatus = 'ACTIVE'

class AssetResponse(AssetBase):
    id: str
    createdAt: str
    updatedAt: str

class RelationshipResponse(BaseModel):
    id: str
    sourceAssetId: str
    targetAssetId: str
    type: Literal['CALLS', 'CONNECTS_TO', 'AUTHENTICATES_WITH', 'HOSTS', 'READS_FROM', 'WRITES_TO', 'DEPLOYS', 'DEPENDS_ON']
    metadata: Dict[str, Any] = Field(default_factory=dict)
    createdAt: str
