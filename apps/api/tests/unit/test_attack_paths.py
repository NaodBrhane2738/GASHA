"""
==============================================================================
FILE: apps/api/tests/unit/test_attack_paths.py
OBJECTIVE: Unit tests for graph-based attack path analysis, reachability semantics,
blocking controls, ranking, and bounded traversal.
==============================================================================
"""

import pytest
from app.digital_twin.graph import SecurityGraph
from app.schemas.vulnerability import VulnerabilityResponse
from app.attack_paths.engine import AttackPathEngine


def make_vuln(vuln_id: str, asset_id: str, severity: str = "HIGH") -> VulnerabilityResponse:
    return VulnerabilityResponse(
        id=vuln_id,
        assetId=asset_id,
        environmentId="env-test",
        title="Remote Code Execution",
        description="Critical exploit vulnerability",
        severity=severity,
        category="INJECTION_FLAW",
        remediationGuidance="Patch vulnerability",
        status="OPEN",
        discoveredAt="2026-10-09T00:00:00Z"
    )


def test_valid_evidence_supported_attack_path():
    graph = SecurityGraph("env-test")
    
    # Entry Point: Public web portal
    graph.add_node(
        "asset-portal",
        {
            "id": "asset-portal",
            "name": "portal-ui",
            "type": "VERCEL_DEPLOYMENT",
            "criticality": "TIER_2_MEDIUM",
            "isPubliclyExposed": True,
            "status": "ACTIVE",
            "findings": [make_vuln("v1", "asset-portal", "HIGH")]
        }
    )

    # Destination: Tier-0 Customer DB
    graph.add_node(
        "asset-db",
        {
            "id": "asset-db",
            "name": "customer-db",
            "type": "DATABASE",
            "criticality": "TIER_0_CROWN_JEWEL",
            "isPubliclyExposed": False,
            "status": "ACTIVE",
            "findings": []
        }
    )

    # Edge: Portal CALLS DB
    graph.add_edge("asset-portal", "asset-db")

    engine = AttackPathEngine()
    paths = engine.find_attack_paths(graph)

    assert len(paths) == 1
    p = paths[0]
    assert p.entryPointAssetId == "asset-portal"
    assert p.targetAssetId == "asset-db"
    assert p.isActive is True
    assert p.reachability == "REACHABLE"
    assert p.severity in ("HIGH", "CRITICAL")
    assert p.pathScore >= 50.0
    assert len(p.nodes) == 2


def test_path_without_weakness_condition_is_rejected():
    """
    Section 8.3 & 14.4:
    A graph path without the required weakness condition is not falsely presented as an attack path
    unless the destination is high-criticality.
    If target is Tier-2 and there are 0 vulnerabilities, it should not become an attack path.
    """
    graph = SecurityGraph("env-test")
    # Public entry point with NO weaknesses
    graph.add_node(
        "entry-1",
        {"id": "entry-1", "name": "docs-site", "type": "VERCEL_DEPLOYMENT", "criticality": "TIER_2_MEDIUM", "isPubliclyExposed": True, "status": "ACTIVE", "findings": []}
    )
    # Tier-2 internal asset with NO weaknesses
    graph.add_node(
        "internal-1",
        {"id": "internal-1", "name": "analytics-logger", "type": "SERVICE", "criticality": "TIER_2_MEDIUM", "isPubliclyExposed": False, "status": "ACTIVE", "findings": []}
    )
    graph.add_edge("entry-1", "internal-1")

    engine = AttackPathEngine()
    paths = engine.find_attack_paths(graph)
    # No crown jewel and no weaknesses -> 0 attack paths
    assert len(paths) == 0


def test_missing_relationships_are_not_invented():
    graph = SecurityGraph("env-test")
    graph.add_node(
        "app-a",
        {"id": "app-a", "name": "app-a", "type": "SERVICE", "criticality": "TIER_2_MEDIUM", "isPubliclyExposed": True, "status": "ACTIVE", "findings": [make_vuln("v1", "app-a")]}
    )
    graph.add_node(
        "db-b",
        {"id": "db-b", "name": "db-b", "type": "DATABASE", "criticality": "TIER_0_CROWN_JEWEL", "isPubliclyExposed": False, "status": "ACTIVE", "findings": []}
    )
    # NO edge added!

    engine = AttackPathEngine()
    paths = engine.find_attack_paths(graph)
    assert len(paths) == 0


def test_verified_block_changes_reachability_without_resolving_vulnerability():
    """
    Section 8.1, 9, 14.4:
    A verified active response (e.g. asset isolation or severed edge) marks the path BLOCKED,
    while the underlying vulnerability remains intact!
    """
    graph = SecurityGraph("env-test")
    v = make_vuln("v1", "web-1", "CRITICAL")
    graph.add_node(
        "web-1",
        {"id": "web-1", "name": "web-service", "type": "SERVICE", "criticality": "TIER_1_HIGH", "isPubliclyExposed": True, "status": "ACTIVE", "findings": [v]}
    )
    graph.add_node(
        "db-1",
        {"id": "db-1", "name": "vault-db", "type": "DATABASE", "criticality": "TIER_0_CROWN_JEWEL", "isPubliclyExposed": False, "status": "ACTIVE", "findings": []}
    )
    graph.add_edge("web-1", "db-1")

    engine = AttackPathEngine()
    paths_before = engine.find_attack_paths(graph)
    assert len(paths_before) == 1
    assert paths_before[0].reachability == "REACHABLE"
    assert paths_before[0].isActive is True

    # Active Defense Response: Isolate web-1
    graph.set_node_containment("web-1", "ISOLATED")

    paths_after = engine.find_attack_paths(graph)
    # The entry point is now isolated, so traversals are blocked
    assert len(paths_after) == 0

    # Test edge severing
    graph.set_node_containment("web-1", "ACTIVE")
    graph.sever_edge("web-1", "db-1")
    paths_severed = engine.find_attack_paths(graph)
    assert len(paths_severed) == 0

    # Ensure vulnerability object itself was untouched and remains OPEN
    assert v.status == "OPEN"


def test_ranking_hierarchy_destination_criticality():
    graph = SecurityGraph("env-test")
    graph.add_node(
        "entry-app",
        {"id": "entry-app", "name": "entry-app", "type": "SERVICE", "criticality": "TIER_2_MEDIUM", "isPubliclyExposed": True, "status": "ACTIVE", "findings": [make_vuln("v1", "entry-app", "HIGH")]}
    )
    # Target 1: Tier-0 Crown Jewel
    graph.add_node(
        "target-crown",
        {"id": "target-crown", "name": "target-crown", "type": "DATABASE", "criticality": "TIER_0_CROWN_JEWEL", "isPubliclyExposed": False, "status": "ACTIVE", "findings": []}
    )
    # Target 2: Tier-1 High
    graph.add_node(
        "target-high",
        {"id": "target-high", "name": "target-high", "type": "SERVICE", "criticality": "TIER_1_HIGH", "isPubliclyExposed": False, "status": "ACTIVE", "findings": []}
    )
    graph.add_edge("entry-app", "target-crown")
    graph.add_edge("entry-app", "target-high")

    engine = AttackPathEngine()
    paths = engine.find_attack_paths(graph)
    assert len(paths) == 2
    # Crown jewel path must rank FIRST
    assert paths[0].targetAssetId == "target-crown"
    assert paths[1].targetAssetId == "target-high"
    assert paths[0].pathScore > paths[1].pathScore
