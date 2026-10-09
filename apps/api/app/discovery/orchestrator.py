"""
==============================================================================
FILE: apps/api/app/discovery/orchestrator.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Orchestrates discovery scans across connected platforms (GitHub, Vercel),
normalizes discovered resources into canonical Assets, and persists them idempotently.
==============================================================================
"""

import uuid
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from app.core.crypto import decrypt_credential, CredentialDecryptionError
from app.db.repositories.connection_repository import get_connection_repository
from app.db.repositories.asset_repository import get_asset_repository
from app.schemas.connection import DiscoveryRunStatus
from app.schemas.asset import RelationshipBase
from app.integrations.github.client import (
    GitHubAPIClient,
    GitHubIntegrationError
)
from app.integrations.github.normalizer import normalize_github_repo
from app.integrations.vercel.client import (
    VercelAPIClient,
    VercelIntegrationError
)
from app.integrations.vercel.normalizer import normalize_vercel_project

logger = logging.getLogger("gasha.discovery.orchestrator")


class DiscoveryOrchestrator:
    def __init__(self):
        self.connection_repo = get_connection_repository()
        self.asset_repo = get_asset_repository()

    def get_status(self, environment_id: str) -> Dict[str, Any]:
        latest_run = self.connection_repo.get_latest_run(environment_id)
        if not latest_run:
            return {"status": "IDLE", "startedAt": None, "completedAt": None}
        return {
            "status": latest_run.status,
            "startedAt": latest_run.startedAt,
            "completedAt": latest_run.completedAt,
            "assetsDiscovered": latest_run.assetsDiscovered,
            "relationshipsDiscovered": latest_run.relationshipsDiscovered,
            "errors": latest_run.errors
        }

    async def run_discovery(
        self,
        environment_id: str,
        provider: str = "ALL"
    ) -> DiscoveryRunStatus:
        """
        Executes discovery scan for the specified environment and provider.
        """
        run_id = f"disc-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        run = DiscoveryRunStatus(
            id=run_id,
            environmentId=environment_id,
            provider=provider,
            status="IN_PROGRESS",
            startedAt=now_iso,
            assetsDiscovered=0,
            relationshipsDiscovered=0,
            errors=[]
        )
        self.connection_repo.record_run(run)

        connections = self.connection_repo.list_connections(environment_id)
        if provider != "ALL":
            connections = [c for c in connections if c.provider == provider.upper()]

        if not connections:
            run.status = "COMPLETED"
            run.completedAt = datetime.now(timezone.utc).isoformat()
            self.connection_repo.record_run(run)
            return run

        total_assets = 0
        total_relationships = 0
        provider_successes = 0
        provider_failures = 0
        raw_relationships: List[RelationshipBase] = []

        for conn in connections:
            try:
                # Decrypt token
                token = decrypt_credential(conn.encryptedToken)
            except CredentialDecryptionError as e:
                err_msg = f"Failed to decrypt credentials for {conn.provider}: {str(e)}"
                logger.error(err_msg)
                run.errors.append(err_msg)
                self.connection_repo.update_sync_status(
                    environment_id=environment_id,
                    provider=conn.provider,
                    resource_count=conn.resourceCount,
                    last_sync_at=now_iso,
                    status="ERROR",
                    error=err_msg
                )
                provider_failures += 1
                continue

            if conn.provider == "GITHUB":
                try:
                    gh_assets, gh_rels = await self._discover_github(token, environment_id, conn.scope)
                    total_assets += len(gh_assets)
                    raw_relationships.extend(gh_rels)
                    provider_successes += 1
                    self.connection_repo.update_sync_status(
                        environment_id=environment_id,
                        provider="GITHUB",
                        resource_count=len(gh_assets),
                        last_sync_at=now_iso,
                        status="CONNECTED",
                        error=None
                    )
                except GitHubIntegrationError as e:
                    err_msg = f"GitHub discovery failed: {str(e)}"
                    logger.error(err_msg)
                    run.errors.append(err_msg)
                    provider_failures += 1
                    self.connection_repo.update_sync_status(
                        environment_id=environment_id,
                        provider="GITHUB",
                        resource_count=conn.resourceCount,
                        last_sync_at=now_iso,
                        status="ERROR",
                        error=err_msg
                    )
                except Exception as e:
                    err_msg = f"Unexpected GitHub discovery error: {str(e)}"
                    logger.exception(err_msg)
                    run.errors.append(err_msg)
                    provider_failures += 1

            elif conn.provider == "VERCEL":
                try:
                    vc_assets, vc_rels = await self._discover_vercel(token, conn.scope, environment_id)
                    total_assets += len(vc_assets)
                    raw_relationships.extend(vc_rels)
                    provider_successes += 1
                    self.connection_repo.update_sync_status(
                        environment_id=environment_id,
                        provider="VERCEL",
                        resource_count=len(vc_assets),
                        last_sync_at=now_iso,
                        status="CONNECTED",
                        error=None
                    )
                except VercelIntegrationError as e:
                    err_msg = f"Vercel discovery failed: {str(e)}"
                    logger.error(err_msg)
                    run.errors.append(err_msg)
                    provider_failures += 1
                    self.connection_repo.update_sync_status(
                        environment_id=environment_id,
                        provider="VERCEL",
                        resource_count=conn.resourceCount,
                        last_sync_at=now_iso,
                        status="ERROR",
                        error=err_msg
                    )
                except Exception as e:
                    err_msg = f"Unexpected Vercel discovery error: {str(e)}"
                    logger.exception(err_msg)
                    run.errors.append(err_msg)
                    provider_failures += 1

        # Resolve relationships to canonical asset IDs and save idempotently
        for rel in raw_relationships:
            source_asset = self.asset_repo.get_asset_by_name(rel.sourceAssetId, environment_id)
            target_asset = self.asset_repo.get_asset_by_name(rel.targetAssetId, environment_id)

            source_id = source_asset.id if source_asset else rel.sourceAssetId
            target_id = target_asset.id if target_asset else rel.targetAssetId

            resolved_rel = RelationshipBase(
                sourceAssetId=source_id,
                targetAssetId=target_id,
                type=rel.type,
                metadata=rel.metadata
            )
            self.asset_repo.upsert_relationship(resolved_rel, environment_id=environment_id)
            total_relationships += 1

        run.assetsDiscovered = total_assets
        run.relationshipsDiscovered = total_relationships
        run.completedAt = datetime.now(timezone.utc).isoformat()

        if provider_failures == 0:
            run.status = "COMPLETED"
        elif provider_successes > 0:
            run.status = "PARTIAL"
        else:
            run.status = "FAILED"

        self.connection_repo.record_run(run)

        # Trigger automatic recalculation for the environment
        if total_assets > 0 or provider_successes > 0:
            try:
                from app.workers.recalculation import recalculate_environment_security_state
                recalculate_environment_security_state(environment_id, trigger_event="DISCOVERY_COMPLETED")
            except Exception as e:
                logger.warning(f"Could not trigger automatic security recalculation: {e}")

        return run

    async def _discover_github(
        self,
        token: str,
        environment_id: str,
        repo_filter: Optional[str] = None
    ) -> tuple:
        client = GitHubAPIClient(token=token)
        discovered_assets = []
        discovered_relationships = []

        if repo_filter and "/" in repo_filter:
            owner, repo_name = repo_filter.split("/", 1)
            raw_repos = [await client.get_repository(owner, repo_name)]
        else:
            raw_repos = await client.list_repositories(per_page=30)

        for raw_repo in raw_repos:
            owner = raw_repo.get("owner", {}).get("login") if isinstance(raw_repo.get("owner"), dict) else ""
            repo_name = raw_repo.get("name", "")

            # Manifest discovery
            manifests = {}
            if owner and repo_name:
                try:
                    manifests = await client.discover_manifests(owner, repo_name)
                except Exception as e:
                    logger.warning(f"Could not scan manifests for {owner}/{repo_name}: {e}")

            asset, rels = normalize_github_repo(raw_repo, manifests, environment_id)
            saved_asset = self.asset_repo.upsert_asset(asset)
            discovered_assets.append(saved_asset)
            discovered_relationships.extend(rels)

        return discovered_assets, discovered_relationships

    async def _discover_vercel(
        self,
        token: str,
        team_id: Optional[str],
        environment_id: str
    ) -> tuple:
        client = VercelAPIClient(token=token, team_id=team_id)
        discovered_assets = []
        discovered_relationships = []

        projects = await client.list_projects(limit=50)

        for proj in projects:
            proj_id = proj.get("id")
            deployments = []
            domains = []

            if proj_id:
                try:
                    deployments = await client.get_project_deployments(proj_id, limit=5)
                except Exception as e:
                    logger.warning(f"Could not fetch deployments for project {proj_id}: {e}")

                try:
                    domains = await client.get_project_domains(proj_id)
                except Exception as e:
                    logger.warning(f"Could not fetch domains for project {proj_id}: {e}")

            proj_asset, endpoint_assets, rels = normalize_vercel_project(
                proj, deployments, domains, environment_id
            )
            saved_proj = self.asset_repo.upsert_asset(proj_asset)
            discovered_assets.append(saved_proj)

            for ep in endpoint_assets:
                saved_ep = self.asset_repo.upsert_asset(ep)
                discovered_assets.append(saved_ep)

            discovered_relationships.extend(rels)

        return discovered_assets, discovered_relationships


_orchestrator_instance: Optional[DiscoveryOrchestrator] = None

def get_discovery_orchestrator() -> DiscoveryOrchestrator:
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = DiscoveryOrchestrator()
    return _orchestrator_instance
