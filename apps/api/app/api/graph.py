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


@router.get("", summary="Get Full Digital Twin Graph")
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

    raw_nodes = graph.list_nodes()
    nodes = []
    for n in raw_nodes:
        crit_raw = n.get("criticality")
        crit_num = (
            5 if crit_raw in (5, "TIER_0_CROWN_JEWEL")
            else (4 if crit_raw in (4, "TIER_1_HIGH")
            else (3 if crit_raw in (3, "TIER_2_MEDIUM")
            else 2))
        )
        type_str = str(n.get("type", "")).lower()
        if "data" in type_str or "sql" in type_str or "pg" in type_str:
            kind = "database"
        elif "s3" in type_str or "store" in type_str or "bucket" in type_str:
            kind = "storage"
        elif "iam" in type_str or "auth" in type_str or "secret" in type_str or "ident" in type_str:
            kind = "identity"
        elif "net" in type_str or "lb" in type_str or "cdn" in type_str or "route" in type_str:
            kind = "network"
        elif "laptop" in type_str or "host" in type_str or "endpoint" in type_str:
            kind = "endpoint"
        elif "external" in type_str or "third" in type_str:
            kind = "external"
        else:
            kind = "compute"

        provider_str = str(n.get("source", "vercel")).lower()
        if provider_str not in ("vercel", "aws", "azure", "gcp", "onprem"):
            provider_str = "vercel"

        is_crown = crit_num == 5 or crit_raw == "TIER_0_CROWN_JEWEL"
        exposure = "public" if n.get("isPubliclyExposed") else "internal"
        if "private" in type_str or "db" in type_str or "secret" in type_str:
            exposure = "private"

        nodes.append({
            **n,
            "id": n["id"],
            "label": n.get("label") or n.get("name") or n["id"],
            "kind": n.get("kind") or kind,
            "provider": n.get("provider") or provider_str,
            "criticality": crit_num,
            "exposure": n.get("exposure") or exposure,
            "riskScore": n.get("riskScore", 84 if is_crown else (71 if crit_num >= 4 else 42)),
            "isCrownJewel": is_crown,
        })

    edges = []
    edge_idx = 1
    for nid, node_data in graph._nodes.items():
        for target in graph.get_neighbors(nid, include_severed=True):
            is_severed = (nid, target) in graph._severed_edges
            edges.append({
                "id": f"e{edge_idx}",
                "source": nid,
                "target": target,
                "relation": "data" if "db" in target or "s3" in target else ("iam" if "secret" in target else "network"),
                "exploitable": not is_severed,
                "isSevered": is_severed
            })
            edge_idx += 1

    now_iso = datetime.now(timezone.utc).isoformat()
    return {
        "nodes": nodes,
        "edges": edges,
        "environmentId": auth_env,
        "entryPoints": graph.get_entry_points(),
        "crownJewels": graph.get_crown_jewels(),
        "syncedAt": now_iso,
        "updatedAt": now_iso
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
