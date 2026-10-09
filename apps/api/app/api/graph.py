"""
==============================================================================
FILE: apps/api/app/api/graph.py
ROLE / OWNERSHIP: Backend & Graph Engineers
OBJECTIVE: Graph topology queries and subgraph extractions for Digital Twin visualization.
STRICT ISOLATION: Scoped strictly by environmentId.
==============================================================================
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, HTTPException, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.digital_twin.builder import get_digital_twin_builder
from app.digital_twin.queries import query_neighborhood

logger = logging.getLogger("gasha.api.graph")
router = APIRouter()


@router.get("/graph", summary="Get Full Digital Twin Graph")
async def get_digital_twin_graph(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Returns full node-link graph payload formatted for frontend visualization within authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    builder = get_digital_twin_builder()
    graph = builder.build_graph_for_environment(auth_env)

    nodes = graph.list_nodes()
    edges = []
    for nid, node_data in graph._nodes.items():
        for target in graph.get_neighbors(nid, include_severed=True):
            is_severed = (nid, target) in graph._severed_edges
            edges.append({
                "source": nid,
                "target": target,
                "isSevered": is_severed
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "environmentId": auth_env,
        "entryPoints": graph.get_entry_points(),
        "crownJewels": graph.get_crown_jewels(),
        "syncedAt": datetime.now(timezone.utc).isoformat()
    }


@router.get("/subgraph/{asset_id}", summary="Get Neighborhood Subgraph")
async def get_subgraph(
    asset_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    k_hops: int = Query(2, ge=1, le=5),
    user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Returns ego-centric subgraph of nodes and relationships within k hops of the target asset.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    builder = get_digital_twin_builder()
    graph = builder.build_graph_for_environment(auth_env)

    if not graph.get_node(asset_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found in environment {auth_env}"
        )

    subgraph = query_neighborhood(graph, asset_id, k_hops=k_hops)
    nodes = subgraph.get("nodes", [])
    return {
        "centerAssetId": asset_id,
        "kHops": k_hops,
        "environmentId": auth_env,
        "nodes": nodes,
        "edges": subgraph.get("edges", []),
        "totalNodes": len(nodes)
    }
