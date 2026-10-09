"""
==============================================================================
FILE: apps/api/tests/unit/test_phase8_api_integration.py
OBJECTIVE: Integration tests for Vulnerabilities, Risk, Attack Paths, and Graph APIs.
==============================================================================
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_jwt_token
from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.db.repositories.risk_repository import get_risk_repository
from app.db.repositories.attack_path_repository import get_attack_path_repository
from app.schemas.asset import AssetBase, RelationshipBase


@pytest.fixture(autouse=True)
def clean_repos():
    get_asset_repository().clear()
    get_vulnerability_repository().clear()
    get_risk_repository().clear()
    get_attack_path_repository().clear()
    yield
    get_asset_repository().clear()
    get_vulnerability_repository().clear()
    get_risk_repository().clear()
    get_attack_path_repository().clear()


@pytest.fixture
def auth_headers():
    token = create_jwt_token({"sub": "admin", "environmentId": "env-prod", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    return TestClient(app)


def test_unauthenticated_api_requests_fail(client):
    assert client.get("/api/v1/vulnerabilities").status_code == 401
    assert client.post("/api/v1/vulnerabilities/assess").status_code == 401
    assert client.get("/api/v1/risks/current").status_code == 401
    assert client.get("/api/v1/attack-paths").status_code == 401
    assert client.get("/api/v1/digital-twin/graph").status_code == 401


def test_vulnerabilities_api_flow(client, auth_headers):
    asset_repo = get_asset_repository()
    # Seed an asset
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="payment-api",
            type="SERVICE",
            criticality="TIER_1_HIGH",
            environmentId="env-prod",
            source="VERCEL",
            metadata={"domains": ["pay.acme.com"]},
            isPubliclyExposed=True
        )
    )

    # 1. Trigger assessment
    assess_resp = client.post("/api/v1/vulnerabilities/assess", headers=auth_headers)
    assert assess_resp.status_code == 200
    data = assess_resp.json()
    assert data["status"] == "COMPLETED"
    assert data["findingsCount"] >= 1

    # 2. Query vulnerabilities list
    list_resp = client.get("/api/v1/vulnerabilities", headers=auth_headers)
    assert list_resp.status_code == 200
    findings = list_resp.json()
    assert len(findings) >= 1
    vuln_id = findings[0]["id"]

    # 3. Query specific vulnerability detail
    detail_resp = client.get(f"/api/v1/vulnerabilities/{vuln_id}", headers=auth_headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == vuln_id


def test_risk_api_flow(client, auth_headers):
    # Seed asset and run recalculation
    asset_repo = get_asset_repository()
    asset_repo.upsert_asset(
        AssetBase(
            name="core-service",
            type="SERVICE",
            criticality="TIER_1_HIGH",
            environmentId="env-prod",
            source="VERCEL",
            isPubliclyExposed=True
        )
    )

    # 1. Query current risk
    resp = client.get("/api/v1/risks/current", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "overallScore" in data
    assert "contributors" in data
    assert data["environmentId"] == "env-prod"

    # 2. Query history
    hist_resp = client.get("/api/v1/risks/history", headers=auth_headers)
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()) >= 1

    # 3. Explicit recalculate
    recalc_resp = client.post("/api/v1/risks/recalculate", headers=auth_headers)
    assert recalc_resp.status_code == 200
    assert "overallScore" in recalc_resp.json()


def test_attack_paths_and_graph_api_flow(client, auth_headers):
    asset_repo = get_asset_repository()
    # Create chain: frontend -> backend db
    fe = asset_repo.upsert_asset(
        AssetBase(
            name="frontend",
            type="VERCEL_DEPLOYMENT",
            criticality="TIER_2_MEDIUM",
            environmentId="env-prod",
            source="VERCEL",
            metadata={"domains": ["app.com"]},
            isPubliclyExposed=True
        )
    )
    be = asset_repo.upsert_asset(
        AssetBase(
            name="backend-db",
            type="DATABASE",
            criticality="TIER_0_CROWN_JEWEL",
            environmentId="env-prod",
            source="STATIC_CONFIG",
            isPubliclyExposed=False
        )
    )
    asset_repo.upsert_relationship(
        RelationshipBase(sourceAssetId=fe.id, targetAssetId=be.id, type="CALLS"),
        environment_id="env-prod"
    )

    # 1. Recalculate attack paths
    recalc_resp = client.post("/api/v1/attack-paths/recalculate", headers=auth_headers)
    assert recalc_resp.status_code == 200
    assert recalc_resp.json()["activePaths"] == 1

    # 2. List attack paths
    list_resp = client.get("/api/v1/attack-paths", headers=auth_headers)
    assert list_resp.status_code == 200
    paths = list_resp.json()
    assert len(paths) == 1
    path_id = paths[0]["id"]

    # 3. Get attack path detail
    detail_resp = client.get(f"/api/v1/attack-paths/{path_id}", headers=auth_headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == path_id

    # 4. Get digital twin graph
    graph_resp = client.get("/api/v1/digital-twin/graph", headers=auth_headers)
    assert graph_resp.status_code == 200
    gdata = graph_resp.json()
    assert len(gdata["nodes"]) == 2
    assert len(gdata["edges"]) == 1

    # 5. Get subgraph around frontend
    subgraph_resp = client.get(f"/api/v1/digital-twin/subgraph/{fe.id}", headers=auth_headers)
    assert subgraph_resp.status_code == 200
    assert len(subgraph_resp.json()["nodes"]) == 2
