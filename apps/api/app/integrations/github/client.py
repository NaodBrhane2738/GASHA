"""
==============================================================================
FILE: apps/api/app/integrations/github/client.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Read-only GitHub REST API client with pagination, rate limiting, and manifest discovery.
LEAST PRIVILEGE: Strict read-only operations. No write actions, commits, or workflow modifications.
==============================================================================
"""

import base64
import json
import logging
import re
from typing import Dict, List, Optional, Any
import httpx

logger = logging.getLogger("gasha.integrations.github")


class GitHubIntegrationError(Exception):
    """Base exception for GitHub integration errors."""
    pass


class GitHubAuthError(GitHubIntegrationError):
    """Raised when authentication fails (401/403 bad credentials)."""
    pass


class GitHubRateLimitError(GitHubIntegrationError):
    """Raised when GitHub rate limit is exceeded."""
    def __init__(self, message: str, reset_time: Optional[str] = None, retry_after: Optional[int] = None):
        super().__init__(message)
        self.reset_time = reset_time
        self.retry_after = retry_after


class GitHubNotFoundError(GitHubIntegrationError):
    """Raised when a requested resource is not found (404)."""
    pass


class GitHubAPIError(GitHubIntegrationError):
    """Raised for unexpected upstream GitHub API errors."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


class GitHubAPIClient:
    """
    Robust, read-only asynchronous GitHub REST API client.
    Supports App installation tokens and Personal Access Tokens (PAT).
    """

    def __init__(
        self,
        token: str,
        base_url: str = "https://api.github.com",
        http_client: Optional[httpx.AsyncClient] = None
    ):
        self.token = token.strip() if token else ""
        self.base_url = base_url.rstrip("/")
        self._external_client = http_client

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "GASHA-Security-Platform/1.0"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 15.0
    ) -> httpx.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = self._get_headers()

        async def _do(client: httpx.AsyncClient) -> httpx.Response:
            return await client.request(method, url, headers=headers, params=params, timeout=timeout)

        try:
            if self._external_client:
                response = await _do(self._external_client)
            else:
                async with httpx.AsyncClient() as client:
                    response = await _do(client)
        except httpx.RequestError as exc:
            logger.error(f"Network error contacting GitHub API at {url}: {exc}")
            raise GitHubAPIError(f"Network error contacting GitHub API: {str(exc)}") from exc

        # Rate Limit Check
        remaining = response.headers.get("x-ratelimit-remaining")
        reset_time = response.headers.get("x-ratelimit-reset")
        retry_after = response.headers.get("retry-after")

        if response.status_code in (403, 429) and remaining == "0":
            logger.warning(f"GitHub API rate limit exceeded. Reset at: {reset_time}")
            raise GitHubRateLimitError(
                "GitHub API rate limit exceeded",
                reset_time=reset_time,
                retry_after=int(retry_after) if retry_after and retry_after.isdigit() else None
            )

        if response.status_code == 401 or (response.status_code == 403 and "Bad credentials" in response.text):
            raise GitHubAuthError("GitHub authentication failed: invalid or expired token")

        if response.status_code == 404:
            raise GitHubNotFoundError(f"GitHub resource not found at {path}")

        if response.status_code >= 400:
            raise GitHubAPIError(
                f"GitHub API returned error {response.status_code}: {response.text[:200]}",
                status_code=response.status_code
            )

        return response

    async def validate_credentials(self) -> Dict[str, Any]:
        """
        Validates the token against GitHub.
        Works for both Personal Access Tokens and GitHub App installation tokens.
        """
        try:
            # Try /user endpoint first
            resp = await self._request("GET", "/user")
            data = resp.json()
            return {
                "valid": True,
                "login": data.get("login", "unknown"),
                "accountType": data.get("type", "User"),
                "id": str(data.get("id")),
                "name": data.get("name")
            }
        except GitHubNotFoundError:
            # May be an App installation token where /user 404s
            resp = await self._request("GET", "/rate_limit")
            return {
                "valid": True,
                "login": "github-app-installation",
                "accountType": "AppInstallation",
                "id": "app-installation"
            }

    async def list_repositories(self, per_page: int = 30, max_pages: int = 3) -> List[Dict[str, Any]]:
        """
        Lists repositories accessible with the token, handling pagination.
        """
        repositories = []
        page = 1

        while page <= max_pages:
            try:
                resp = await self._request("GET", "/user/repos", params={
                    "per_page": per_page,
                    "page": page,
                    "sort": "updated",
                    "direction": "desc"
                })
            except GitHubNotFoundError:
                # If /user/repos fails for App token, try /installation/repositories
                resp = await self._request("GET", "/installation/repositories", params={
                    "per_page": per_page,
                    "page": page
                })
                data = resp.json()
                items = data.get("repositories", [])
                repositories.extend(items)
                break

            items = resp.json()
            if not isinstance(items, list) or len(items) == 0:
                break

            repositories.extend(items)

            # Check Link header for rel="next"
            link_header = resp.headers.get("link", "")
            if 'rel="next"' not in link_header:
                break

            page += 1

        return repositories

    async def get_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetches repository details."""
        resp = await self._request("GET", f"/repos/{owner}/{repo}")
        return resp.json()

    async def get_file_content(self, owner: str, repo: str, path: str, ref: Optional[str] = None) -> Optional[str]:
        """
        Fetches the raw text content of a file from a repository.
        Decodes base64 content safely.
        """
        params = {"ref": ref} if ref else None
        try:
            resp = await self._request("GET", f"/repos/{owner}/{repo}/contents/{path}", params=params)
            data = resp.json()
            if data.get("encoding") == "base64" and "content" in data:
                raw_bytes = base64.b64decode(data["content"])
                return raw_bytes.decode("utf-8", errors="replace")
            return None
        except GitHubNotFoundError:
            return None

    async def discover_manifests(self, owner: str, repo: str, ref: Optional[str] = None) -> Dict[str, Any]:
        """
        Discovers and parses dependency manifests in the repository root.
        Supports package.json, requirements.txt, go.mod, etc.
        STRICT SECURITY: Never parses or extracts secret files or environment variables.
        """
        manifests = {}

        # 1. Node.js package.json
        pkg_json_text = await self.get_file_content(owner, repo, "package.json", ref)
        if pkg_json_text:
            try:
                pkg_data = json.loads(pkg_json_text)
                deps = list(pkg_data.get("dependencies", {}).keys())
                dev_deps = list(pkg_data.get("devDependencies", {}).keys())
                manifests["package.json"] = {
                    "ecosystem": "npm",
                    "dependencies": deps,
                    "devDependencies": dev_deps,
                    "totalDependencies": len(deps) + len(dev_deps)
                }
            except Exception as e:
                manifests["package.json"] = {"ecosystem": "npm", "error": f"Failed to parse: {str(e)}"}

        # 2. Python requirements.txt
        req_text = await self.get_file_content(owner, repo, "requirements.txt", ref)
        if req_text:
            pkgs = []
            for line in req_text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Strip version specifiers
                    pkg_name = re.split(r"[><=~!;]", line)[0].strip()
                    if pkg_name:
                        pkgs.append(pkg_name)
            manifests["requirements.txt"] = {
                "ecosystem": "pip",
                "dependencies": pkgs,
                "totalDependencies": len(pkgs)
            }

        # 3. Go go.mod
        go_mod_text = await self.get_file_content(owner, repo, "go.mod", ref)
        if go_mod_text:
            manifests["go.mod"] = {
                "ecosystem": "go",
                "detected": True
            }

        return manifests
