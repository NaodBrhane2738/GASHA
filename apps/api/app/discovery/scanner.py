"""
==============================================================================
FILE: apps/api/app/discovery/scanner.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Orchestrates discovery scans against Vercel REST API and GitHub API.
==============================================================================
"""

import logging
from typing import List, Dict, Any, Optional

from app.integrations.vercel.client import VercelAPIClient
from app.integrations.github.client import GitHubAPIClient
from app.discovery.orchestrator import get_discovery_orchestrator
from app.schemas.connection import DiscoveryRunStatus

logger = logging.getLogger("gasha.discovery.scanner")


async def scan_vercel_environment(api_token: str, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches Vercel projects using VercelAPIClient."""
    logger.info(f"Scanning Vercel environment (project: {project_id or 'all'})")
    client = VercelAPIClient(token=api_token)
    if project_id:
        proj = await client.get_project(project_id)
        return [proj]
    return await client.list_projects()


async def scan_github_repository(token: str, repo: str) -> Dict[str, Any]:
    """Fetches repository details and manifests using GitHubAPIClient."""
    logger.info(f"Scanning GitHub repo: {repo}")
    client = GitHubAPIClient(token=token)
    if "/" in repo:
        owner, name = repo.split("/", 1)
        repo_data = await client.get_repository(owner, name)
        manifests = await client.discover_manifests(owner, name)
        repo_data["discovered_manifests"] = manifests
        return repo_data
    return {}


async def run_full_discovery(environment_id: str, provider: str = "ALL") -> DiscoveryRunStatus:
    """Executes full discovery crawl via DiscoveryOrchestrator."""
    orchestrator = get_discovery_orchestrator()
    return await orchestrator.run_discovery(environment_id=environment_id, provider=provider)
