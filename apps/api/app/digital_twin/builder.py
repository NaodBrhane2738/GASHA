"""
==============================================================================
FILE: apps/api/app/digital_twin/builder.py
ROLE / OWNERSHIP: Backend & Graph Engineers
OBJECTIVE: Constructs in-memory SecurityGraph from normalized assets, edges, and findings.
STRICT ISOLATION: Scoped strictly by environmentId.
==============================================================================
"""

import logging
from typing import List, Optional

from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.digital_twin.graph import SecurityGraph

logger = logging.getLogger("gasha.digital_twin.builder")


class DigitalTwinBuilder:
    def __init__(self):
        self.asset_repo = get_asset_repository()
        self.vuln_repo = get_vulnerability_repository()

    def build_graph_for_environment(self, environment_id: str) -> SecurityGraph:
        """
        Constructs a complete SecurityGraph from persistent repositories for the environment.
        """
        graph = SecurityGraph(environment_id=environment_id)
        assets = self.asset_repo.list_assets(environment_id=environment_id)
        relationships = self.asset_repo.list_relationships(environment_id=environment_id)
        findings = self.vuln_repo.list_findings(environment_id=environment_id, status="OPEN")

        # Map findings by assetId
        findings_by_asset = {}
        for f in findings:
            if f.assetId not in findings_by_asset:
                findings_by_asset[f.assetId] = []
            findings_by_asset[f.assetId].append(f)

        # Add Nodes
        for a in assets:
            node_findings = findings_by_asset.get(a.id, [])
            node_data = {
                "id": a.id,
                "name": a.name,
                "type": a.type,
                "criticality": a.criticality,
                "environmentId": a.environmentId,
                "source": a.source,
                "metadata": a.metadata,
                "isPubliclyExposed": a.isPubliclyExposed,
                "status": a.status,
                "createdAt": a.createdAt,
                "updatedAt": a.updatedAt,
                "findings": node_findings,
                "vulnerabilityIds": [f.id for f in node_findings]
            }
            graph.add_node(a.id, node_data)

        # Add Edges
        for r in relationships:
            graph.add_edge(r.sourceAssetId, r.targetAssetId, metadata=r.metadata)

        logger.info(
            f"Built Digital Twin for {environment_id}: {len(assets)} nodes, {len(relationships)} edges, {len(findings)} open findings"
        )
        return graph


_builder_instance: Optional[DigitalTwinBuilder] = None

def get_digital_twin_builder() -> DigitalTwinBuilder:
    global _builder_instance
    if _builder_instance is None:
        _builder_instance = DigitalTwinBuilder()
    return _builder_instance
