"""
==============================================================================
FILE: apps/api/tests/unit/test_vercel_integration.py
OBJECTIVE: Unit tests for Vercel API client, rate limiting, project/domain discovery,
strict zero env-var secret leakage, and canonical Asset normalization.
==============================================================================
"""

import pytest
import httpx

from app.integrations.vercel.client import (
    VercelAPIClient,
    VercelAuthError,
    VercelRateLimitError,
    VercelNotFoundError,
    VercelAPIError
)
from app.integrations.vercel.normalizer import normalize_vercel_project


@pytest.mark.asyncio
async def test_vercel_validate_credentials_user_success():
    def handler(request: httpx.Request):
        assert request.url.path == "/v2/user"
        assert request.headers["authorization"] == "Bearer vercel_test_token"
        return httpx.Response(
            200,
            json={"user": {"id": "usr_123", "username": "alice", "email": "alice@example.com"}}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vc = VercelAPIClient(token="vercel_test_token", http_client=client)
        val = await vc.validate_credentials()
        assert val["valid"] is True
        assert val["userId"] == "usr_123"
        assert val["username"] == "alice"


@pytest.mark.asyncio
async def test_vercel_validate_credentials_with_team():
    def handler(request: httpx.Request):
        if request.url.path == "/v2/user":
            return httpx.Response(200, json={"user": {"id": "usr_123", "username": "bob"}})
        elif request.url.path == "/v2/teams/team_456":
            return httpx.Response(200, json={"id": "team_456", "name": "Acme Security Team"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vc = VercelAPIClient(token="vercel_test_token", team_id="team_456", http_client=client)
        val = await vc.validate_credentials()
        assert val["valid"] is True
        assert val["teamName"] == "Acme Security Team"


@pytest.mark.asyncio
async def test_vercel_auth_error_on_invalid_token():
    def handler(request: httpx.Request):
        return httpx.Response(403, json={"error": {"code": "forbidden", "message": "Invalid token"}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vc = VercelAPIClient(token="invalid_token", http_client=client)
        with pytest.raises(VercelAuthError):
            await vc.validate_credentials()


@pytest.mark.asyncio
async def test_vercel_rate_limit_error():
    def handler(request: httpx.Request):
        return httpx.Response(
            429,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000", "retry-after": "60"},
            json={"error": {"code": "rate_limited", "message": "Too Many Requests"}}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vc = VercelAPIClient(token="valid_token", http_client=client)
        with pytest.raises(VercelRateLimitError) as exc_info:
            await vc.list_projects()
        assert exc_info.value.retry_after == 60


@pytest.mark.asyncio
async def test_vercel_list_projects():
    def handler(request: httpx.Request):
        assert request.url.path == "/v9/projects"
        return httpx.Response(
            200,
            json={
                "projects": [
                    {
                        "id": "prj_001",
                        "name": "portal-frontend",
                        "framework": "nextjs",
                        "link": {"type": "github", "org": "acme", "repo": "portal"}
                    }
                ]
            }
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vc = VercelAPIClient(token="valid_token", http_client=client)
        projects = await vc.list_projects()
        assert len(projects) == 1
        assert projects[0]["name"] == "portal-frontend"
        assert projects[0]["framework"] == "nextjs"


@pytest.mark.asyncio
async def test_vercel_strict_zero_env_var_secret_leakage():
    """
    CRITICAL REQUIREMENT:
    Ensure raw environment variable secret values are NEVER collected or stored.
    All 'value' fields must be strictly redacted.
    """
    def handler(request: httpx.Request):
        assert request.url.path == "/v10/projects/prj_001/env"
        return httpx.Response(
            200,
            json={
                "envs": [
                    {
                        "id": "env_1",
                        "key": "DATABASE_PASSWORD",
                        "value": "SUPER_SECRET_PLAINTEXT_PW_12345!",
                        "type": "encrypted",
                        "target": ["production"]
                    },
                    {
                        "id": "env_2",
                        "key": "STRIPE_SECRET_KEY",
                        "value": "sk_live_9876543210fedcba",
                        "type": "secret",
                        "target": ["production", "preview"]
                    }
                ]
            }
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        vc = VercelAPIClient(token="valid_token", http_client=client)
        env_metadata = await vc.get_project_env_vars_metadata("prj_001")

        assert len(env_metadata) == 2
        for item in env_metadata:
            # Verify keys are captured for architecture mapping
            assert item["key"] in ("DATABASE_PASSWORD", "STRIPE_SECRET_KEY")
            # Verify RAW VALUES ARE NEVER EXPOSED
            assert item["value"] == "[REDACTED]"
            assert "SUPER_SECRET" not in item["value"]
            assert "sk_live" not in item["value"]


def test_normalize_vercel_project_with_domains_and_git():
    project_data = {
        "id": "prj_999",
        "name": "dashboard-ui",
        "framework": "nextjs",
        "nodeVersion": "18.x",
        "link": {
            "type": "github",
            "org": "my-corp",
            "repo": "dashboard-ui",
            "productionBranch": "main"
        }
    }
    deployments = [
        {"uid": "dpl_1", "name": "dashboard-ui", "url": "dashboard-ui-abc.vercel.app", "state": "READY"}
    ]
    domains = [
        {"name": "dashboard.example.com", "apexName": "example.com", "verified": True}
    ]

    proj_asset, endpoint_assets, rels = normalize_vercel_project(
        project_data, deployments, domains, environment_id="env-prod"
    )

    # Project asset verification
    assert proj_asset.name == "dashboard-ui"
    assert proj_asset.type == "VERCEL_DEPLOYMENT"
    assert proj_asset.criticality == "TIER_1_HIGH"
    assert proj_asset.isPubliclyExposed is True
    assert proj_asset.source == "VERCEL"
    assert proj_asset.metadata["framework"] == "nextjs"

    # Domain endpoint asset verification
    assert len(endpoint_assets) == 1
    assert endpoint_assets[0].name == "dashboard.example.com"
    assert endpoint_assets[0].type == "API_ENDPOINT"
    assert endpoint_assets[0].isPubliclyExposed is True

    # Relationship verification
    assert len(rels) == 2
    # 1. Project HOSTS domain
    hosts_rel = next(r for r in rels if r.type == "HOSTS")
    assert hosts_rel.sourceAssetId == "dashboard-ui"
    assert hosts_rel.targetAssetId == "dashboard.example.com"

    # 2. GitHub Repo DEPLOYS Project
    deploys_rel = next(r for r in rels if r.type == "DEPLOYS")
    assert deploys_rel.sourceAssetId == "my-corp/dashboard-ui"
    assert deploys_rel.targetAssetId == "dashboard-ui"
