"""
==============================================================================
FILE: apps/api/app/attack_paths/engine.py
ROLE / OWNERSHIP: Threat Modelers & Graph Engineers
OBJECTIVE: Graph-based attack path discovery and ranking engine.
SAFEGUARDS: Bounded DFS, cycle prevention, tenant isolation, reachability verification.
==============================================================================
"""

import uuid
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone

from app.digital_twin.graph import SecurityGraph
from app.schemas.asset import AssetType
from app.schemas.attack_path import (
    AttackPathResponse,
    AttackPathNodeSchema,
    SeverityLevel,
    ReachabilityStatus
)

logger = logging.getLogger("gasha.attack_paths.engine")


class AttackPathEngine:
    """
    Identifies and ranks potential attack paths from public entry points
    to high-value target assets (Tier-0 Crown Jewels / Tier-1 High).
    """

    def __init__(self, max_depth: int = 5, max_paths: int = 20):
        self.max_depth = max_depth
        self.max_paths = max_paths

    def find_attack_paths(self, graph: SecurityGraph) -> List[AttackPathResponse]:
        """
        Discovers all valid, reachable attack paths in the security graph.
        """
        entry_points = graph.get_entry_points()
        targets = graph.get_high_value_targets()

        if not entry_points or not targets:
            return []

        discovered_paths: List[AttackPathResponse] = []
        seen_path_signatures: Set[str] = set()

        for entry_id in entry_points:
            entry_node = graph.get_node(entry_id)
            if not entry_node:
                continue

            for target_id in targets:
                if entry_id == target_id:
                    # Traversal paths require traversal across relationships to a distinct target
                    continue

                # Multi-hop path search
                raw_paths = graph.find_paths(entry_id, target_id, max_depth=self.max_depth)

                for node_sequence in raw_paths:
                    path_sig = "->".join(node_sequence)
                    if path_sig in seen_path_signatures:
                        continue
                    seen_path_signatures.add(path_sig)

                    path_model = self._build_path_model(
                        graph=graph,
                        node_ids=node_sequence,
                        entry_id=entry_id,
                        target_id=target_id
                    )
                    if path_model:
                        discovered_paths.append(path_model)

        # Sort in descending order of pathScore
        discovered_paths.sort(key=lambda p: p.pathScore, reverse=True)
        return discovered_paths[:self.max_paths]

    def _build_path_model(
        self,
        graph: SecurityGraph,
        node_ids: List[str],
        entry_id: str,
        target_id: str
    ) -> Optional[AttackPathResponse]:
        """
        Constructs and scores an AttackPathResponse for a sequence of nodes.
        Evaluates weakness conditions, reachability, and destination criticality.
        """
        nodes_schema: List[AttackPathNodeSchema] = []
        total_weakness_score = 0.0
        all_vuln_ids: List[str] = []
        is_blocked = False
        has_unknown = False

        for idx, nid in enumerate(node_ids):
            ndata = graph.get_node(nid)
            if not ndata:
                return None

            # Check containment / status
            if ndata.get("status") == "ISOLATED":
                is_blocked = True

            node_findings = ndata.get("findings", [])
            node_vuln_ids = [f.id for f in node_findings if getattr(f, "status", "") == "OPEN"]
            all_vuln_ids.extend(node_vuln_ids)

            for f in node_findings:
                if getattr(f, "status", "") == "OPEN":
                    sev = getattr(f, "severity", "LOW")
                    if sev == "CRITICAL":
                        total_weakness_score += 20.0
                    elif sev == "HIGH":
                        total_weakness_score += 12.0
                    elif sev == "MEDIUM":
                        total_weakness_score += 6.0
                    else:
                        total_weakness_score += 2.0

            nodes_schema.append(
                AttackPathNodeSchema(
                    assetId=nid,
                    assetName=ndata.get("name", nid),
                    assetType=ndata.get("type", "SERVICE"),
                    stepOrder=idx + 1,
                    vulnerabilityIds=node_vuln_ids if node_vuln_ids else None,
                    description=f"Step {idx + 1}: Traversal through {ndata.get('name')} ({ndata.get('type')})"
                )
            )

        # Check edge severing along path
        for i in range(len(node_ids) - 1):
            if not graph.is_traversable(node_ids[i], node_ids[i + 1]):
                is_blocked = True

        target_node = graph.get_node(target_id)
        target_crit = target_node.get("criticality") if target_node else "TIER_2_MEDIUM"

        # Weakness condition requirement:
        # A valid attack path must contain at least one weakness condition or directly expose a Tier-0/1 asset
        if total_weakness_score == 0.0 and target_crit not in ("TIER_0_CROWN_JEWEL", "TIER_1_HIGH"):
            return None

        # Reachability determination
        if is_blocked:
            reachability: ReachabilityStatus = "BLOCKED"
            is_active = False
            mult = 0.0
        elif has_unknown:
            reachability = "UNKNOWN"
            is_active = True
            mult = 0.5
        else:
            reachability = "REACHABLE"
            is_active = True
            mult = 1.0

        # Destination Criticality Base
        if target_crit == "TIER_0_CROWN_JEWEL":
            dest_score = 40.0
        elif target_crit == "TIER_1_HIGH":
            dest_score = 25.0
        else:
            dest_score = 10.0

        entry_exposure_score = 15.0  # entry point is verified public
        capped_weakness_score = min(total_weakness_score, 35.0)

        raw_path_score = (dest_score + entry_exposure_score + capped_weakness_score) * mult
        final_path_score = min(max(round(raw_path_score, 1), 0.0), 100.0)

        # Derived Severity
        if final_path_score >= 70.0:
            severity: SeverityLevel = "CRITICAL"
        elif final_path_score >= 50.0:
            severity = "HIGH"
        elif final_path_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        now_iso = datetime.now(timezone.utc).isoformat()
        clean_entry = entry_id.replace("asset-", "").replace(":", "-")[:8]
        clean_target = target_id.replace("asset-", "").replace(":", "-")[:8]
        path_id = f"path-{clean_entry}-to-{clean_target}"

        # Derive MITRE techniques from nodes and vulnerabilities
        techniques = []
        for n in nodes_schema:
            if n.vulnerabilityIds:
                techniques.append("T1190")  # Exploit Public-Facing Application
            if "auth" in n.assetName.lower() or "secrets" in n.assetName.lower():
                techniques.append("T1078")  # Valid Accounts
            if "database" in n.assetType.lower() or "pg" in n.assetName.lower() or "s3" in n.assetName.lower():
                techniques.append("T1552")  # Unsecured Credentials / Data Exposure
        if not techniques:
            techniques = ["T1190", "T1078"]
        techniques = list(dict.fromkeys(techniques))

        edge_ids = [f"e{i+1}" for i in range(len(node_ids) - 1)]
        status_val = "mitigated" if is_blocked else "open"
        likelihood_val = round(max(0.2, min(0.95, final_path_score / 100.0)), 2)
        impact_val = 0.95 if target_crit == "TIER_0_CROWN_JEWEL" else (0.85 if target_crit == "TIER_1_HIGH" else 0.6)

        return AttackPathResponse(
            id=path_id,
            environmentId=graph.environment_id,
            entryPointAssetId=entry_id,
            targetAssetId=target_id,
            severity=severity,
            pathScore=final_path_score,
            nodes=nodes_schema,
            isActive=is_active,
            reachability=reachability,
            discoveredAt=now_iso,
            mitigatedAt=now_iso if is_blocked else None,
            metadata={
                "hopCount": len(node_ids),
                "weaknessCount": len(all_vuln_ids),
                "targetCriticality": target_crit,
                "nodeSequence": node_ids
            },
            techniques=techniques,
            entryNodeId=entry_id,
            crownJewelNodeId=target_id,
            nodeIds=node_ids,
            edgeIds=edge_ids,
            likelihood=likelihood_val,
            impact=impact_val,
            riskScore=round(final_path_score),
            status=status_val
        )
