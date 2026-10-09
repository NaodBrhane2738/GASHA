"""
==============================================================================
FILE: apps/api/tests/unit/test_connections_discovery_api.py
OBJECTIVE: Integration tests for Connection management, Credential encryption,
Discovery trigger, Idempotent asset updates, Multi-tenant isolation, and Partial failures.
==============================================================================
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_jwt_token
from app.core.crypto import decrypt_credential
from app.db.repositories.connection_repository import get_connection_repository
from app.db.repositories.asset_repository import get_asset_repository


@pytest.fixture(autouse=True)
def reset_repositories():
    """Reset in-memory connection and asset repositories between tests."""
    get_connection_repository().clear()
    get_asset_repository().clear()
    yield
    get_connection_repository().clear()
    get_asset_repository().clear()


@pytest.fixture
def auth_headers():
    token = create_jwt_token({"sub": "sec-admin", "environmentId": "env-prod", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def tenant_b_headers():
    token = create_jwt_token({"sub": "user-b", "environmentId": "env-tenant-b", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    return TestClient(app)


def test_unauthenticated_requests_fail(client):
    assert client.post("/api/v1/connections/vercel", json={"apiToken": "tok"}).status_code == 401
    assert client.post("/api/v1/connections/github", json={"token": "tok"}).status_code == 401
    assert client.get("/api/v1/connections/status").status_code == 401
    assert client.post("/api/v1/discovery/trigger").status_code == 401
    assert client.get("/api/v1/discovery/status").status_code == 401


@patch("app.integrations.vercel.client.VercelAPIClient.validate_credentials")
def test_connect_vercel_success_and_encryption(mock_val, client, auth_headers):
    mock_val.return_value = {
        "valid": True,
        "username": "gasha-bot",
        "teamName": "Gasha Core Infra"
    }

    raw_token = "vercel_secret_token_abc123"
    payload = {
        "apiToken": raw_token,
        "teamId": "team_core_1",
        "environmentId": "env-prod"
    }
    resp = client.post("/api/v1/connections/vercel", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["provider"] == "VERCEL"
    assert data["isConnected"] is True
    assert data["status"] == "CONNECTED"
    assert data["accountName"] == "Gasha Core Infra"
    assert data["environmentId"] == "env-prod"
    # Strict secret protection: raw token NEVER in response
    assert "token" not in str(data)
    assert raw_token not in str(data)

    # Verify token is encrypted at rest in the repository
    repo = get_connection_repository()
    conn = repo.get_connection("env-prod", "VERCEL")
    assert conn is not None
    assert conn.encryptedToken != raw_token
    assert decrypt_credential(conn.encryptedToken) == raw_token


@patch("app.integrations.github.client.GitHubAPIClient.validate_credentials")
def test_connect_github_success_and_encryption(mock_val, client, auth_headers):
    mock_val.return_value = {
        "valid": True,
        "login": "gasha-platform",
        "accountType": "User"
    }

    raw_token = "ghp_secure_github_token_xyz"
    payload = {
        "token": raw_token,
        "repository": "gasha-platform/core-api",
        "environmentId": "env-prod"
    }
    resp = client.post("/api/v1/connections/github", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["provider"] == "GITHUB"
    assert data["isConnected"] is True
    assert data["accountName"] == "gasha-platform"
    assert raw_token not in str(data)

    # Verify encrypted in repo
    repo = get_connection_repository()
    conn = repo.get_connection("env-prod", "GITHUB")
    assert conn is not None
    assert conn.encryptedToken != raw_token
    assert decrypt_credential(conn.encryptedToken) == raw_token


def test_disconnect_provider(client, auth_headers):
    # Setup connection
    with patch("app.integrations.vercel.client.VercelAPIClient.validate_credentials") as mock_val:
        mock_val.return_value = {"valid": True, "username": "admin"}
        client.post("/api/v1/connections/vercel", json={"apiToken": "tok123"}, headers=auth_headers)

    # Disconnect
    resp = client.delete("/api/v1/connections/vercel", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "DISCONNECTED"

    # Status check confirms disconnected
    status_resp = client.get("/api/v1/connections/status", headers=auth_headers)
    assert status_resp.status_code == 200
    vc_status = next(s for s in status_resp.json() if s["provider"] == "VERCEL")
    assert vc_status["isConnected"] is False


def test_multi_tenant_environment_isolation(client, auth_headers, tenant_b_headers):
    # Connect Vercel in env-prod
    with patch("app.integrations.vercel.client.VercelAPIClient.validate_credentials") as mock_val:
        mock_val.return_value = {"valid": True, "username": "prod-admin"}
        client.post("/api/v1/connections/vercel", json={"apiToken": "prod-token"}, headers=auth_headers)

    # Tenant B should see no connections
    status_b = client.get("/api/v1/connections/status", headers=tenant_b_headers)
    assert status_b.status_code == 200
    for s in status_b.json():
        assert s["isConnected"] is False

    # Tenant B discovery trigger finds 0 assets
    disc_b = client.post("/api/v1/discovery/trigger", json={}, headers=tenant_b_headers)
    assert disc_b.status_code == 200
    assert disc_b.json()["assetsDiscovered"] == 0


@patch("app.integrations.vercel.client.VercelAPIClient.get_project_domains")
@patch("app.integrations.vercel.client.VercelAPIClient.get_project_deployments")
@patch("app.integrations.vercel.client.VercelAPIClient.list_projects")
@patch("app.integrations.github.client.GitHubAPIClient.discover_manifests")
@patch("app.integrations.github.client.GitHubAPIClient.list_repositories")
def test_discovery_trigger_and_idempotency(
    mock_gh_repos,
    mock_gh_manifests,
    mock_vc_projects,
    mock_vc_deployments,
    mock_vc_domains,
    client,
    auth_headers
):
    # Setup connections first
    with patch("app.integrations.vercel.client.VercelAPIClient.validate_credentials") as mv:
        mv.return_value = {"valid": True, "username": "user"}
        client.post("/api/v1/connections/vercel", json={"apiToken": "vc-tok"}, headers=auth_headers)
    with patch("app.integrations.github.client.GitHubAPIClient.validate_credentials") as mg:
        mg.return_value = {"valid": True, "login": "user"}
        client.post("/api/v1/connections/github", json={"token": "gh-tok"}, headers=auth_headers)

    # Configure mock API responses
    mock_gh_repos.return_value = [
        {
            "id": 1001,
            "name": "api-service",
            "full_name": "acme/api-service",
            "private": True,
            "owner": {"login": "acme"},
            "language": "Python"
        }
    ]
    mock_gh_manifests.return_value = {
        "requirements.txt": {"ecosystem": "pip", "totalDependencies": 8}
    }

    mock_vc_projects.return_value = [
        {
            "id": "prj_1",
            "name": "web-frontend",
            "framework": "nextjs",
            "link": {"type": "github", "org": "acme", "repo": "api-service"}
        }
    ]
    mock_vc_deployments.return_value = [
        {"uid": "dpl_1", "name": "web-frontend", "url": "web-frontend.vercel.app", "state": "READY"}
    ]
    mock_vc_domains.return_value = [
        {"name": "app.example.com", "apexName": "example.com", "verified": True}
    ]

    # First discovery run:
    # Discovered: 1 GitHub repo + 1 Vercel project + 1 Domain endpoint = 3 assets
    resp1 = client.post("/api/v1/discovery/trigger", json={}, headers=auth_headers)
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "COMPLETED"
    assert resp1.json()["assetsDiscovered"] == 3
    assert resp1.json()["relationshipsDiscovered"] == 2  # 1 HOSTS domain + 1 DEPLOYS from GitHub

    # Check status endpoint
    status_resp = client.get("/api/v1/discovery/status", headers=auth_headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["assetsDiscovered"] == 3
    assert status_resp.json()["relationshipsDiscovered"] == 2

    # Check assets inventory endpoint
    assets_resp = client.get("/api/v1/assets", headers=auth_headers)
    assert assets_resp.status_code == 200
    assert len(assets_resp.json()) == 3

    # SECOND RUN (IDEMPOTENCY TEST)
    # Re-running discovery MUST NOT duplicate assets!
    resp2 = client.post("/api/v1/discovery/trigger", json={}, headers=auth_headers)
    assert resp2.status_code == 200

    assets_resp2 = client.get("/api/v1/assets", headers=auth_headers)
    assert assets_resp2.status_code == 200
    assert len(assets_resp2.json()) == 3, "Assets must not duplicate on subsequent discovery runs"


@patch("app.integrations.github.client.GitHubAPIClient.discover_manifests")
@patch("app.integrations.github.client.GitHubAPIClient.list_repositories")
@patch("app.integrations.vercel.client.VercelAPIClient.list_projects")
def test_partial_failure_resilience(mock_vc_projects, mock_gh_repos, mock_gh_manifests, client, auth_headers):
    # Setup connections
    with patch("app.integrations.vercel.client.VercelAPIClient.validate_credentials") as mv:
        mv.return_value = {"valid": True, "username": "user"}
        client.post("/api/v1/connections/vercel", json={"apiToken": "vc-tok"}, headers=auth_headers)
    with patch("app.integrations.github.client.GitHubAPIClient.validate_credentials") as mg:
        mg.return_value = {"valid": True, "login": "user"}
        client.post("/api/v1/connections/github", json={"token": "gh-tok"}, headers=auth_headers)

    from app.integrations.vercel.client import VercelAPIError

    mock_gh_repos.return_value = [
        {"id": 2002, "name": "backend", "full_name": "acme/backend", "private": True, "owner": {"login": "acme"}}
    ]
    mock_gh_manifests.return_value = {}
    mock_vc_projects.side_effect = VercelAPIError("Upstream Vercel 500 error", status_code=500)

    # Run discovery
    resp = client.post("/api/v1/discovery/trigger", json={}, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "PARTIAL"
    assert data["assetsDiscovered"] == 1
    assert len(data["errors"]) > 0

    # GitHub asset is preserved
    assets_resp = client.get("/api/v1/assets", headers=auth_headers)
    assert len(assets_resp.json()) == 1
    assert assets_resp.json()[0]["name"] == "acme/backend"
