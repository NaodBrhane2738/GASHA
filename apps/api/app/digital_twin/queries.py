"""
==============================================================================
FILE: apps/api/app/digital_twin/queries.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Graph traversal queries (k-hop neighborhoods, blast radius analysis, reachability).
SAFEGUARDS: Bounded BFS/DFS, cycle safety, multi-tenant isolation.
==============================================================================
"""

from collections import deque
from typing import List, Dict, Any, Set
from app.digital_twin.graph import SecurityGraph


def query_blast_radius(graph: SecurityGraph, asset_id: str, max_depth: int = 3) -> List[str]:
    """
    Computes reachable downstream nodes from a compromised asset using bounded BFS.
    """
    if not graph.get_node(asset_id):
        return []

    visited: Set[str] = {asset_id}
    queue = deque([(asset_id, 0)])

    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue

        for neighbor in graph.get_neighbors(current, include_severed=False):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))

    return list(visited)


def query_neighborhood(graph: SecurityGraph, asset_id: str, k_hops: int = 2) -> Dict[str, Any]:
    """
    Extracts a k-hop subgraph around a central asset for UI rendering.
    """
    center_node = graph.get_node(asset_id)
    if not center_node:
        return {"nodes": [], "edges": [], "centerAssetId": asset_id}

    reachable_nodes = query_blast_radius(graph, asset_id, max_depth=k_hops)
    nodes = [graph.get_node(nid) for nid in reachable_nodes if graph.get_node(nid)]
    
    edges = []
    for nid in reachable_nodes:
        for target in graph.get_neighbors(nid, include_severed=False):
            if target in reachable_nodes:
                edges.append({"source": nid, "target": target})

    return {
        "nodes": nodes,
        "edges": edges,
        "centerAssetId": asset_id
    }
