"""
==============================================================================
FILE: apps/api/tests/unit/test_github_integration.py
OBJECTIVE: Unit tests for GitHub API client, pagination, manifest discovery,
rate limiting, and canonical Asset normalization.
==============================================================================
"""

import base64
import json
import pytest
import httpx

from app.integrations.github.client import (
    GitHubAPIClient,
    GitHubAuthError,
    GitHubRateLimitError,
    GitHubNotFoundError,
    GitHubAPIError
)
from app.integrations.github.normalizer import normalize_github_repo


@pytest.mark.asyncio
async def test_github_validate_credentials_user_success():
    def handler(request: httpx.Request):
        assert request.url.path == "/user"
        assert request.headers["authorization"] == "Bearer test_pat_token"
        return httpx.Response(
            200,
            json={"login": "octocat", "type": "User", "id": 12345, "name": "The Octocat"}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gh = GitHubAPIClient(token="test_pat_token", http_client=client)
        val = await gh.validate_credentials()
        assert val["valid"] is True
        assert val["login"] == "octocat"
        assert val["accountType"] == "User"


@pytest.mark.asyncio
async def test_github_validate_credentials_app_token_fallback():
    def handler(request: httpx.Request):
        if request.url.path == "/user":
            return httpx.Response(404, json={"message": "Not Found"})
        elif request.url.path == "/rate_limit":
            return httpx.Response(200, json={"resources": {"core": {"limit": 5000}}})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gh = GitHubAPIClient(token="ghs_app_token", http_client=client)
        val = await gh.validate_credentials()
        assert val["valid"] is True
        assert val["accountType"] == "AppInstallation"


@pytest.mark.asyncio
async def test_github_auth_error_on_invalid_token():
    def handler(request: httpx.Request):
        return httpx.Response(401, json={"message": "Bad credentials"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gh = GitHubAPIClient(token="invalid_token", http_client=client)
        with pytest.raises(GitHubAuthError):
            await gh.validate_credentials()


@pytest.mark.asyncio
async def test_github_rate_limit_error():
    def handler(request: httpx.Request):
        return httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"},
            json={"message": "API rate limit exceeded"}
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gh = GitHubAPIClient(token="valid_token", http_client=client)
        with pytest.raises(GitHubRateLimitError) as exc_info:
            await gh.list_repositories()
        assert exc_info.value.reset_time == "1700000000"


@pytest.mark.asyncio
async def test_github_list_repositories_with_pagination():
    def handler(request: httpx.Request):
        page = request.url.params.get("page", "1")
        if page == "1":
            return httpx.Response(
                200,
                headers={"link": '<https://api.github.com/user/repos?page=2>; rel="next"'},
                json=[{"id": 101, "name": "repo-one", "full_name": "org/repo-one", "private": True}]
            )
        elif page == "2":
            return httpx.Response(
                200,
                headers={},
                json=[{"id": 102, "name": "repo-two", "full_name": "org/repo-two", "private": False}]
            )
        return httpx.Response(200, json=[])

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gh = GitHubAPIClient(token="valid_token", http_client=client)
        repos = await gh.list_repositories(per_page=1, max_pages=3)
        assert len(repos) == 2
        assert repos[0]["name"] == "repo-one"
        assert repos[1]["name"] == "repo-two"


@pytest.mark.asyncio
async def test_github_discover_manifests():
    pkg_json_content = json.dumps({
        "name": "my-app",
        "dependencies": {"express": "^4.18.2", "cors": "^2.8.5"},
        "devDependencies": {"typescript": "^5.0.0"}
    })
    req_txt_content = "# Comment\nfastapi>=0.100.0\nuvicorn==0.23.0\npytest\n"

    def handler(request: httpx.Request):
        if "package.json" in request.url.path:
            encoded = base64.b64encode(pkg_json_content.encode()).decode()
            return httpx.Response(200, json={"encoding": "base64", "content": encoded})
        elif "requirements.txt" in request.url.path:
            encoded = base64.b64encode(req_txt_content.encode()).decode()
            return httpx.Response(200, json={"encoding": "base64", "content": encoded})
        return httpx.Response(404, json={"message": "Not Found"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        gh = GitHubAPIClient(token="valid_token", http_client=client)
        manifests = await gh.discover_manifests("org", "my-app")
        
        assert "package.json" in manifests
        assert manifests["package.json"]["ecosystem"] == "npm"
        assert "express" in manifests["package.json"]["dependencies"]
        assert manifests["package.json"]["totalDependencies"] == 3

        assert "requirements.txt" in manifests
        assert manifests["requirements.txt"]["ecosystem"] == "pip"
        assert "fastapi" in manifests["requirements.txt"]["dependencies"]
        assert "uvicorn" in manifests["requirements.txt"]["dependencies"]
        assert manifests["requirements.txt"]["totalDependencies"] == 3


def test_normalize_github_repo_private():
    repo_data = {
        "id": 9991,
        "name": "backend-core",
        "full_name": "acme/backend-core",
        "private": True,
        "archived": False,
        "language": "Python",
        "default_branch": "main",
        "html_url": "https://github.com/acme/backend-core"
    }
    manifests = {
        "requirements.txt": {"totalDependencies": 12}
    }
    asset, rels = normalize_github_repo(repo_data, manifests, environment_id="env-prod")

    assert asset.name == "acme/backend-core"
    assert asset.type == "GITHUB_REPOSITORY"
    assert asset.criticality == "TIER_1_HIGH"
    assert asset.isPubliclyExposed is False
    assert asset.environmentId == "env-prod"
    assert asset.source == "GITHUB"
    assert asset.metadata["dependencyCount"] == 12
    assert asset.metadata["language"] == "Python"


def test_normalize_github_repo_public():
    repo_data = {
        "id": 9992,
        "name": "docs-site",
        "full_name": "acme/docs-site",
        "private": False,
        "archived": False,
        "language": "Markdown"
    }
    asset, _ = normalize_github_repo(repo_data, {}, environment_id="env-staging")

    assert asset.name == "acme/docs-site"
    assert asset.criticality == "TIER_2_MEDIUM"
    assert asset.isPubliclyExposed is True
    assert asset.environmentId == "env-staging"
