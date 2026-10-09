"""
==============================================================================
FILE: apps/api/app/api/discovery.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Trigger and monitor environment discovery crawls across Vercel & GitHub.
DATA INTEGRITY: Scans connected cloud platforms, normalizes assets into Digital Twin,
and prevents duplicate nodes via idempotent asset upsert.
==============================================================================
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, BackgroundTasks, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.db.repositories.connection_repository import get_connection_repository
from app.db.repositories.asset_repository import get_asset_repository
from app.discovery.orchestrator import get_discovery_orchestrator
from app.schemas.connection import (
    DiscoveryTriggerRequest,
    DiscoveryStatusResponse,
    DiscoveryRunStatus
)
from app.schemas.asset import (
    DiscoveredAssetsResponse,
    AssetResponse,
    RelationshipResponse
)

logger = logging.getLogger("gasha.api.discovery")
router = APIRouter()


@router.post("/trigger", response_model=DiscoveryRunStatus, summary="Trigger Discovery Crawl")
async def trigger_discovery(
    req: Optional[DiscoveryTriggerRequest] = None,
    user: dict = Depends(get_current_user)
) -> DiscoveryRunStatus:
    """
    Initiates discovery scan across authorized cloud integrations (GitHub, Vercel).
    Normalizes resources to canonical Asset and Relationship models,
    and updates the environment digital twin.
    """
    req = req or DiscoveryTriggerRequest()
    auth_env = enforce_environment_boundary(user, req.environmentId)
    provider = (req.provider or "ALL").upper()

    orchestrator = get_discovery_orchestrator()
    run = await orchestrator.run_discovery(environment_id=auth_env, provider=provider)
    return run


@router.get("/status", response_model=DiscoveryStatusResponse, summary="Get Discovery Status")
async def get_discovery_status(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> DiscoveryStatusResponse:
    """
    Returns current crawl status, latest run summary, and total discovered assets count within authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    orchestrator = get_discovery_orchestrator()
    status_summary = orchestrator.get_status(auth_env)

    asset_repo = get_asset_repository()
    assets = asset_repo.list_assets(auth_env)

    return DiscoveryStatusResponse(
        environmentId=auth_env,
        status=status_summary.get("status", "IDLE"),
        lastRunAt=status_summary.get("completedAt") or status_summary.get("startedAt"),
        assetsDiscovered=len(assets),
        relationshipsDiscovered=status_summary.get("relationshipsDiscovered", 0),
        summary=status_summary
    )


@router.get("/assets", response_model=DiscoveredAssetsResponse, summary="List Discovered Environment Assets")
async def list_discovered_assets(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> DiscoveredAssetsResponse:
    """
    Returns the complete set of assets and topological relationships normalized during discovery.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    asset_repo = get_asset_repository()

    assets = asset_repo.list_assets(auth_env)
    relationships = asset_repo.list_relationships(auth_env)

    return DiscoveredAssetsResponse(
        environmentId=auth_env,
        totalAssets=len(assets),
        totalRelationships=len(relationships),
        assets=assets,
        relationships=relationships
    )
