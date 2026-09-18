"""
==============================================================================
FILE: apps/api/app/digital_twin/graph.py
ROLE / OWNERSHIP: Backend & Graph Engineers
OBJECTIVE: Core graph data structure and operations wrapper (NetworkX DiGraph).
TOOLS & LIBRARIES: NetworkX
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - SecurityDiGraph: Directed graph with node metadata (criticality, exposures) and edge weights.
  - get_entry_points() -> List[str]: Finds all publicly exposed nodes.
  - get_crown_jewels() -> List[str]: Finds all Tier-0 critical nodes.
EXPECTED RESULTS / BEHAVIOR:
  - Efficient path traversals and cycle-free graph operations.
==============================================================================
"""

from typing import List, Dict, Any

class SecurityGraph:
    def __init__(self):
        self._adjacency: Dict[str, List[str]] = {}
        self._node_data: Dict[str, Dict[str, Any]] = {}

    def add_node(self, node_id: str, data: Dict[str, Any]):
        self._node_data[node_id] = data
        if node_id not in self._adjacency:
            self._adjacency[node_id] = []

    def add_edge(self, source_id: str, target_id: str):
        if source_id in self._adjacency and target_id not in self._adjacency[source_id]:
            self._adjacency[source_id].append(target_id)
