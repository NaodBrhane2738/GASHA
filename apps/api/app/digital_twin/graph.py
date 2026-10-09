"""
==============================================================================
FILE: apps/api/app/digital_twin/graph.py
ROLE / OWNERSHIP: Backend & Graph Engineers
OBJECTIVE: Core directed graph data structure for Digital Twin topology and security traversals.
SAFEGUARDS: Bounded search, cycle detection, multi-tenant environment isolation.
==============================================================================
"""

from typing import List, Dict, Any, Optional, Set
from app.schemas.asset import AssetResponse


class SecurityGraph:
    """
    Directed graph representing infrastructure assets and relationships for an environment.
    Supports node metadata, findings linkage, edge containment severing, and cycle-safe traversals.
    """
    def __init__(self, environment_id: str = "env-prod"):
        self.environment_id = environment_id
        # node_id -> node_data dict
        self._nodes: Dict[str, Dict[str, Any]] = {}
        # source_id -> set of target_ids
        self._adjacency: Dict[str, Set[str]] = {}
        # target_id -> set of source_ids
        self._predecessors: Dict[str, Set[str]] = {}
        # Set of severed (source_id, target_id) edges resulting from containment response
        self._severed_edges: Set[tuple] = set()
        # Set of isolated asset IDs
        self._isolated_nodes: Set[str] = set()

    def add_node(self, node_id: str, data: Dict[str, Any]):
        self._nodes[node_id] = data
        if node_id not in self._adjacency:
            self._adjacency[node_id] = set()
        if node_id not in self._predecessors:
            self._predecessors[node_id] = set()
        if data.get("status") == "ISOLATED":
            self._isolated_nodes.add(node_id)

    def add_edge(self, source_id: str, target_id: str, metadata: Optional[Dict[str, Any]] = None):
        if source_id not in self._nodes or target_id not in self._nodes:
            # Safe handling: do not add edges for nonexistent assets
            return
        self._adjacency[source_id].add(target_id)
        self._predecessors[target_id].add(source_id)

    def sever_edge(self, source_id: str, target_id: str):
        """Actively breaks connection between two assets in response to containment."""
        self._severed_edges.add((source_id, target_id))

    def restore_edge(self, source_id: str, target_id: str):
        self._severed_edges.discard((source_id, target_id))

    def set_node_containment(self, node_id: str, status: str):
        if node_id in self._nodes:
            self._nodes[node_id]["status"] = status
            if status == "ISOLATED":
                self._isolated_nodes.add(node_id)
            else:
                self._isolated_nodes.discard(node_id)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._nodes.get(node_id)

    def list_nodes(self) -> List[Dict[str, Any]]:
        return list(self._nodes.values())

    def get_entry_points(self) -> List[str]:
        """Returns node IDs for publicly exposed infrastructure."""
        return [
            node_id for node_id, data in self._nodes.items()
            if data.get("isPubliclyExposed") is True and node_id not in self._isolated_nodes
        ]

    def get_crown_jewels(self) -> List[str]:
        """Returns node IDs for Tier-0 critical assets."""
        return [
            node_id for node_id, data in self._nodes.items()
            if data.get("criticality") == "TIER_0_CROWN_JEWEL"
        ]

    def get_high_value_targets(self) -> List[str]:
        """Returns Tier-0 and Tier-1 critical assets."""
        return [
            node_id for node_id, data in self._nodes.items()
            if data.get("criticality") in ("TIER_0_CROWN_JEWEL", "TIER_1_HIGH")
        ]

    def get_neighbors(self, node_id: str, include_severed: bool = False) -> List[str]:
        if node_id not in self._adjacency:
            return []
        neighbors = []
        for target in self._adjacency[node_id]:
            if not include_severed and (node_id, target) in self._severed_edges:
                continue
            neighbors.append(target)
        return neighbors

    def is_traversable(self, source_id: str, target_id: str) -> bool:
        """Checks if traversal between two nodes is currently possible."""
        if (source_id, target_id) in self._severed_edges:
            return False
        if source_id in self._isolated_nodes or target_id in self._isolated_nodes:
            return False
        return target_id in self._adjacency.get(source_id, set())

    def find_paths(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5
    ) -> List[List[str]]:
        """
        Bounded, cycle-free DFS traversal from start_id to end_id.
        """
        if start_id not in self._nodes or end_id not in self._nodes:
            return []
        if start_id == end_id:
            return [[start_id]]

        result_paths: List[List[str]] = []

        def dfs(current: str, current_path: List[str], visited: Set[str]):
            if len(current_path) > max_depth:
                return
            if current == end_id:
                result_paths.append(list(current_path))
                return

            for neighbor in self.get_neighbors(current, include_severed=False):
                if neighbor not in visited and neighbor not in self._isolated_nodes:
                    visited.add(neighbor)
                    current_path.append(neighbor)
                    dfs(neighbor, current_path, visited)
                    current_path.pop()
                    visited.remove(neighbor)

        dfs(start_id, [start_id], {start_id})
        return result_paths
