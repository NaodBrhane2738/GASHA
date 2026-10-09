"""
==============================================================================
FILE: apps/api/tests/unit/test_digital_twin_graph.py
OBJECTIVE: Unit tests for Digital Twin Graph construction, stable identities,
bounded traversals, blast radius, and environment isolation.
==============================================================================
"""

import pytest
from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.schemas.asset import AssetBase, RelationshipBase
from app.digital_twin.graph import SecurityGraph
from app.digital_twin.builder import DigitalTwinBuilder
from app.digital_twin.queries import query_blast_radius, query_neighborhood


@pytest.fixture(autouse=True)
def clean_repos():
    get_asset_repository().clear()
    get_vulnerability_repository().clear()
    yield
    get_asset_repository().clear()
    get_vulnerability_repository().clear()


def test_stable_identities_and_environment_isolation():
    asset_repo = get_asset_repository()

    # Two assets in different environments with the same name
    asset_env1 = asset_repo.upsert_asset(
        AssetBase(
            name="core-api",
            type="SERVICE",
            criticality="TIER_1_HIGH",
            environmentId="env-prod",
            source="VERCEL"
        )
    )
    asset_env2 = asset_repo.upsert_asset(
        AssetBase(
            name="core-api",
            type="SERVICE",
            criticality="TIER_2_MEDIUM",
            environmentId="env-staging",
            source="VERCEL"
        )
    )

    assert asset_env1.id != asset_env2.id
    assert asset_repo.count_assets("env-prod") == 1
    assert asset_repo.count_assets("env-staging") == 1


def test_repeated_discovery_does_not_duplicate_assets():
    asset_repo = get_asset_repository()
    asset1 = asset_repo.upsert_asset(
        AssetBase(
            name="payment-gateway",
            type="SERVICE",
            criticality="TIER_0_CROWN_JEWEL",
            environmentId="env-prod",
            source="VERCEL",
            metadata={"version": "1.0.0"}
        )
    )

    # Re-upsert with updated metadata
    asset2 = asset_repo.upsert_asset(
        AssetBase(
            name="payment-gateway",
            type="SERVICE",
            criticality="TIER_0_CROWN_JEWEL",
            environmentId="env-prod",
            source="VERCEL",
            metadata={"version": "1.1.0", "newField": True}
        )
    )

    assert asset1.id == asset2.id
    assert asset_repo.count_assets("env-prod") == 1
    stored = asset_repo.get_asset(asset1.id, "env-prod")
    assert stored.metadata["version"] == "1.1.0"
    assert stored.metadata["newField"] is True


def test_missing_endpoints_handled_safely():
    graph = SecurityGraph("env-prod")
    graph.add_node("node-1", {"name": "app-1", "isPubliclyExposed": True})
    
    # Adding edge to nonexistent node must not crash or create invalid edges
    graph.add_edge("node-1", "nonexistent-node-2")
    assert graph.get_neighbors("node-1") == []


def test_similar_names_do_not_imply_relationship():
    builder = DigitalTwinBuilder()
    asset_repo = get_asset_repository()

    # Two similarly named assets without an explicit relationship
    a1 = asset_repo.upsert_asset(
        AssetBase(name="auth-service", type="SERVICE", environmentId="env-prod", source="VERCEL")
    )
    a2 = asset_repo.upsert_asset(
        AssetBase(name="auth-service-worker", type="SERVICE", environmentId="env-prod", source="VERCEL")
    )

    graph = builder.build_graph_for_environment("env-prod")
    assert graph.get_neighbors(a1.id) == []
    assert graph.get_neighbors(a2.id) == []


def test_bounded_graph_queries_and_blast_radius():
    graph = SecurityGraph("env-prod")
    # Linear topology: N0 -> N1 -> N2 -> N3 -> N4
    for i in range(5):
        graph.add_node(f"node-{i}", {"name": f"Node {i}"})
    for i in range(4):
        graph.add_edge(f"node-{i}", f"node-{i+1}")

    # Blast radius max depth = 2 from node-0 should reach node-0, node-1, node-2
    blast = query_blast_radius(graph, "node-0", max_depth=2)
    assert set(blast) == {"node-0", "node-1", "node-2"}
    assert "node-3" not in blast

    # Neighborhood query
    neighborhood = query_neighborhood(graph, "node-1", k_hops=1)
    neighbor_ids = {n["name"] for n in neighborhood["nodes"]}
    assert neighbor_ids == {"Node 1", "Node 2"}


def test_cycle_prevention_in_path_traversal():
    graph = SecurityGraph("env-prod")
    # Cycle: A -> B -> C -> A
    graph.add_node("A", {"name": "A"})
    graph.add_node("B", {"name": "B"})
    graph.add_node("C", {"name": "C"})

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "A")

    paths = graph.find_paths("A", "C", max_depth=5)
    assert len(paths) == 1
    assert paths[0] == ["A", "B", "C"]
