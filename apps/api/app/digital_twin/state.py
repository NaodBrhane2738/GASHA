"""
==============================================================================
FILE: apps/api/app/digital_twin/state.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Manages runtime state mutations of the digital twin (quarantines, degradations).
==============================================================================
"""

import logging
from typing import Optional
from app.db.repositories.asset_repository import get_asset_repository
from app.schemas.asset import AssetResponse

logger = logging.getLogger("gasha.digital_twin.state")


def set_asset_containment_state(
    environment_id: str,
    asset_id: str,
    status: str
) -> Optional[AssetResponse]:
    """
    Transitions an asset's operational status (e.g. ISOLATED, DEGRADED, ACTIVE)
    in the authoritative repository.
    """
    logger.info(f"Transitioning asset {asset_id} to containment status: {status} in {environment_id}")
    repo = get_asset_repository()
    asset = repo.get_asset(asset_id, environment_id)
    if not asset:
        return None

    asset.status = status
    return repo.upsert_asset(asset, asset_id=asset.id)
