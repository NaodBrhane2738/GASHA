"""
==============================================================================
FILE: apps/api/app/discovery/normalizer.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Transforms raw Vercel/GitHub JSON payloads into standard Asset entities.
TOOLS & LIBRARIES: Pydantic v2, app.schemas.asset
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - normalize_vercel_deployment(raw_data: dict) -> AssetBase
  - normalize_github_repo(raw_data: dict) -> AssetBase
EXPECTED RESULTS / BEHAVIOR:
  - Produces clean, typed Asset models adhering to @gasha/contracts.
==============================================================================
"""

from typing import Dict, Any
from app.schemas.asset import AssetBase

def normalize_vercel_resource(raw: Dict[str, Any], environment_id: str) -> AssetBase:
    return AssetBase(
        name=raw.get("name", "vercel-app"),
        type="VERCEL_DEPLOYMENT",
        criticality="TIER_1_HIGH",
        environmentId=environment_id,
        source="VERCEL",
        metadata=raw,
        isPubliclyExposed=True,
        status="ACTIVE"
    )
