"""
==============================================================================
FILE: apps/api/app/api/attack_paths.py
ROLE / OWNERSHIP: Backend & Threat Modelers
OBJECTIVE: Endpoints to list, inspect, and calculate high-probability attacker traversal paths.
STRICT ISOLATION: Scoped strictly by environmentId.
==============================================================================
"""

import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.schemas.attack_path import AttackPathResponse, ReachabilityStatus
from app.attack_paths.service import get_attack_path_service

logger = logging.getLogger("gasha.api.attack_paths")
router = APIRouter()


@router.get("", response_model=List[AttackPathResponse], summary="List Active Attack Paths")
async def list_attack_paths(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    is_active: Optional[bool] = Query(None, alias="isActive"),
    reachability: Optional[str] = Query(None),
    user: dict = Depends(get_current_user)
) -> List[AttackPathResponse]:
    """
    Returns ranked attack paths discovered by graph reachability algorithms within authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    service = get_attack_path_service()
    reach_status = reachability.upper() if reachability else None
    paths = service.list_attack_paths(
        environment_id=auth_env,
        is_active=is_active,
        reachability=reach_status
    )
    if not paths:
        import os
        from app.core.production_guard import is_production_mode
        if not is_production_mode() and "PYTEST_CURRENT_TEST" not in os.environ:
            paths = service.recalculate_attack_paths(auth_env)
    return paths


@router.post("/recalculate", summary="Recalculate Attack Paths")
async def recalculate_attack_paths(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Re-runs graph reachability and attack path discovery across authorized environment topology.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    service = get_attack_path_service()
    paths = service.recalculate_attack_paths(auth_env)
    return {
        "status": "RECALCULATED",
        "environmentId": auth_env,
        "activePaths": sum(1 for p in paths if p.isActive),
        "paths": paths
    }


@router.get("/{path_id}", response_model=AttackPathResponse, summary="Get Attack Path Detail")
async def get_attack_path(
    path_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> AttackPathResponse:
    """
    Returns sequence hops and findings for a specific attack path within authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    service = get_attack_path_service()
    path = service.get_attack_path(path_id, auth_env)
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack path '{path_id}' not found in environment '{auth_env}'"
        )
    return path
