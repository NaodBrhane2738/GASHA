"""
==============================================================================
FILE: apps/api/app/api/assets.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Endpoints to list, filter, and inspect discovered infrastructure assets.
==============================================================================
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from app.core.auth import get_current_user, enforce_environment_boundary
from app.db.repositories.asset_repository import get_asset_repository
from app.schemas.asset import AssetResponse

router = APIRouter()


@router.get("", response_model=List[AssetResponse], summary="List Discovered Assets")
async def list_assets(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    asset_type: Optional[str] = Query(None, alias="type"),
    source: Optional[str] = Query(None),
    user: dict = Depends(get_current_user)
) -> List[AssetResponse]:
    """
    Returns inventory of discovered infrastructure assets strictly scoped to authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    asset_repo = get_asset_repository()
    return asset_repo.list_assets(
        environment_id=auth_env,
        asset_type=asset_type,
        source=source.upper() if source else None
    )


@router.get("/{asset_id}", response_model=AssetResponse, summary="Get Asset Details")
async def get_asset(
    asset_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> AssetResponse:
    """
    Returns detailed metadata and status for a specific asset within caller's authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    asset_repo = get_asset_repository()
    asset = asset_repo.get_asset(asset_id, auth_env)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found in environment '{auth_env}'"
        )
    return asset
