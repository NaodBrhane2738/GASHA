"""
==============================================================================
FILE: apps/api/app/integrations/vercel/client.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Read-only Vercel REST API client for projects, deployments, and domains.
SECURITY REQUIREMENT: Strict zero env-var secret leakage. Environment variable values
are NEVER retrieved, stored, logged, or exposed.
==============================================================================
"""

import logging
from typing import Dict, List, Optional, Any
import httpx

logger = logging.getLogger("gasha.integrations.vercel")


class VercelIntegrationError(Exception):
    """Base exception for Vercel integration errors."""
    pass


class VercelAuthError(VercelIntegrationError):
    """Raised when Vercel authentication fails (401/403)."""
    pass


class VercelRateLimitError(VercelIntegrationError):
    """Raised when Vercel API rate limit is exceeded."""
    def __init__(self, message: str, reset_time: Optional[str] = None, retry_after: Optional[int] = None):
        super().__init__(message)
        self.reset_time = reset_time
        self.retry_after = retry_after


class VercelNotFoundError(VercelIntegrationError):
    """Raised when a requested Vercel resource is not found (404)."""
    pass


class VercelAPIError(VercelIntegrationError):
    """Raised for unexpected upstream Vercel API errors."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


class VercelAPIClient:
    """
    Robust, read-only asynchronous Vercel REST API client.
    Supports user and team-scoped tokens.
    """

    def __init__(
        self,
        token: str,
        team_id: Optional[str] = None,
        base_url: str = "https://api.vercel.com",
        http_client: Optional[httpx.AsyncClient] = None
    ):
        self.token = token.strip() if token else ""
        self.team_id = team_id.strip() if team_id else None
        self.base_url = base_url.rstrip("/")
        self._external_client = http_client

    def _get_headers(self) -> Dict[str, str]:
        headers = {
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
        
        req_params = dict(params or {})
        if self.team_id and "teamId" not in req_params:
            req_params["teamId"] = self.team_id

        async def _do(client: httpx.AsyncClient) -> httpx.Response:
            return await client.request(method, url, headers=headers, params=req_params, timeout=timeout)

        try:
            if self._external_client:
                response = await _do(self._external_client)
            else:
                async with httpx.AsyncClient() as client:
                    response = await _do(client)
        except httpx.RequestError as exc:
            logger.error(f"Network error contacting Vercel API at {url}: {exc}")
            raise VercelAPIError(f"Network error contacting Vercel API: {str(exc)}") from exc

        # Rate Limit Check
        remaining = response.headers.get("x-ratelimit-remaining")
        reset_time = response.headers.get("x-ratelimit-reset")
        retry_after = response.headers.get("retry-after")

        if response.status_code in (403, 429) and remaining == "0":
            logger.warning(f"Vercel API rate limit exceeded. Reset at: {reset_time}")
            raise VercelRateLimitError(
                "Vercel API rate limit exceeded",
                reset_time=reset_time,
                retry_after=int(retry_after) if retry_after and retry_after.isdigit() else None
            )

        if response.status_code in (401, 403):
            raise VercelAuthError("Vercel authentication failed: invalid or expired token")

        if response.status_code == 404:
            raise VercelNotFoundError(f"Vercel resource not found at {path}")

        if response.status_code >= 400:
            raise VercelAPIError(
                f"Vercel API returned error {response.status_code}: {response.text[:200]}",
                status_code=response.status_code
            )

        return response

    async def validate_credentials(self) -> Dict[str, Any]:
        """
        Validates the token against Vercel. Checks user and team access.
        """
        user_resp = await self._request("GET", "/v2/user")
        user_data = user_resp.json().get("user", {})
        
        account_info = {
            "valid": True,
            "userId": user_data.get("id"),
            "username": user_data.get("username"),
            "email": user_data.get("email"),
            "teamId": self.team_id,
            "teamName": None
        }

        if self.team_id:
            try:
                team_resp = await self._request("GET", f"/v2/teams/{self.team_id}")
                team_data = team_resp.json()
                account_info["teamName"] = team_data.get("name")
            except Exception as e:
                logger.warning(f"Could not fetch team details for {self.team_id}: {e}")

        return account_info

    async def list_projects(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists projects accessible within the user or team scope."""
        resp = await self._request("GET", "/v9/projects", params={"limit": limit})
        data = resp.json()
        return data.get("projects", [])

    async def get_project(self, project_id_or_name: str) -> Dict[str, Any]:
        """Fetches a single project by ID or name."""
        resp = await self._request("GET", f"/v9/projects/{project_id_or_name}")
        return resp.json()

    async def get_project_deployments(self, project_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Lists recent deployments for a project."""
        resp = await self._request("GET", "/v6/deployments", params={"projectId": project_id, "limit": limit})
        data = resp.json()
        return data.get("deployments", [])

    async def get_project_domains(self, project_id: str) -> List[Dict[str, Any]]:
        """Lists domains configured on a project."""
        resp = await self._request("GET", f"/v9/projects/{project_id}/domains")
        data = resp.json()
        return data.get("domains", [])

    async def get_project_env_vars_metadata(self, project_id: str) -> List[Dict[str, Any]]:
        """
        Fetches environment variable configurations for a project.
        CRITICAL SECURITY REQUIREMENT:
        - NEVER returns, stores, or logs secret values.
        - All 'value' fields are strictly stripped and replaced with '[REDACTED]'.
        """
        try:
            resp = await self._request("GET", f"/v10/projects/{project_id}/env")
            data = resp.json()
            envs = data.get("envs", [])
            sanitized = []
            for env in envs:
                sanitized.append({
                    "id": env.get("id"),
                    "key": env.get("key"),
                    "type": env.get("type"),
                    "target": env.get("target"),
                    "gitBranch": env.get("gitBranch"),
                    "updatedAt": env.get("updatedAt"),
                    "value": "[REDACTED]"  # Strict redaction
                })
            return sanitized
        except VercelNotFoundError:
            return []
