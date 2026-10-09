"""
==============================================================================
FILE: apps/api/app/integrations/vercel/normalizer.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Normalize raw Vercel project, deployment, and domain metadata into canonical GASHA Assets.
CONTRACT COMPLIANCE: Conforms strictly to @gasha/contracts (Asset, Relationship).
==============================================================================
"""

from typing import Dict, Any, Tuple, List, Optional
from app.schemas.asset import AssetBase, RelationshipBase


def normalize_vercel_project(
    project_data: Dict[str, Any],
    deployments: List[Dict[str, Any]],
    domains: List[Dict[str, Any]],
    environment_id: str
) -> Tuple[AssetBase, List[AssetBase], List[RelationshipBase]]:
    """
    Normalizes a Vercel project, its deployments, and domains into canonical GASHA Assets and Relationships.
    Returns:
        (project_asset, endpoint_assets, relationships)
    """
    domain_names = [d.get("name") for d in domains if d.get("name")]
    
    # Check if there is an active/ready production deployment
    has_active_deployments = any(
        d.get("state") in ("READY", "INITIALIZING") for d in deployments
    )
    is_public = len(domain_names) > 0 or any(d.get("url") for d in deployments)

    # Summarize deployments safely (no secrets)
    safe_deployments = [
        {
            "uid": d.get("uid"),
            "name": d.get("name"),
            "url": d.get("url"),
            "state": d.get("state"),
            "created": d.get("created"),
            "target": d.get("target")
        }
        for d in deployments[:5]
    ]

    project_name = project_data.get("name", "unknown-vercel-project")

    # Main Vercel Service Asset
    project_asset = AssetBase(
        name=project_name,
        type="VERCEL_DEPLOYMENT",
        criticality="TIER_1_HIGH" if is_public else "TIER_2_MEDIUM",
        environmentId=environment_id,
        source="VERCEL",
        metadata={
            "projectId": project_data.get("id"),
            "name": project_name,
            "framework": project_data.get("framework"),
            "nodeVersion": project_data.get("nodeVersion"),
            "gitLink": project_data.get("link"),
            "domains": domain_names,
            "latestDeployments": safe_deployments,
            "targets": project_data.get("targets", {})
        },
        isPubliclyExposed=is_public,
        status="ACTIVE" if has_active_deployments or not deployments else "DEGRADED"
    )

    endpoint_assets: List[AssetBase] = []
    relationships: List[RelationshipBase] = []

    # Create API_ENDPOINT assets for custom domains
    for d in domains:
        d_name = d.get("name")
        if not d_name:
            continue
        domain_asset = AssetBase(
            name=d_name,
            type="API_ENDPOINT",
            criticality="TIER_1_HIGH",
            environmentId=environment_id,
            source="VERCEL",
            metadata={
                "domain": d_name,
                "apexName": d.get("apexName"),
                "verified": d.get("verified", True),
                "projectId": project_data.get("id")
            },
            isPubliclyExposed=True,
            status="ACTIVE"
        )
        endpoint_assets.append(domain_asset)

        # Relationship: Project HOSTS Domain
        relationships.append(
            RelationshipBase(
                sourceAssetId=project_name,
                targetAssetId=d_name,
                type="HOSTS",
                metadata={"domain": d_name}
            )
        )

    # Git Link Relationship if project is bound to a GitHub repo
    git_link = project_data.get("link")
    if isinstance(git_link, dict) and git_link.get("type") == "github":
        org = git_link.get("org")
        repo = git_link.get("repo")
        full_repo_name = f"{org}/{repo}" if org and repo else repo
        if full_repo_name:
            relationships.append(
                RelationshipBase(
                    sourceAssetId=full_repo_name,
                    targetAssetId=project_name,
                    type="DEPLOYS",
                    metadata={
                        "framework": project_data.get("framework"),
                        "productionBranch": git_link.get("productionBranch", "main")
                    }
                )
            )

    return project_asset, endpoint_assets, relationships
