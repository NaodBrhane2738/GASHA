"""
==============================================================================
FILE: apps/api/app/discovery/deduplicator.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Merges overlapping assets discovered from multiple sources (e.g. repo & deployment).
TOOLS & LIBRARIES: Python set logic / graph node reconciliation
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - deduplicate_assets(assets: List[AssetBase]) -> List[AssetBase]
EXPECTED RESULTS / BEHAVIOR:
  - Prevents duplicate nodes in the Digital Twin for the same underlying microservice.
==============================================================================
"""

from typing import List
from app.schemas.asset import AssetBase

def deduplicate_assets(assets: List[AssetBase]) -> List[AssetBase]:
    seen = {}
    for asset in assets:
        key = f"{asset.environmentId}:{asset.name}:{asset.type}"
        if key not in seen:
            seen[key] = asset
        else:
            seen[key].metadata.update(asset.metadata)
    return list(seen.values())
