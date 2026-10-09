"""
==============================================================================
FILE: apps/api/app/integrations/github/normalizer.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Normalize raw GitHub repository metadata into canonical GASHA Asset and Relationship entities.
CONTRACT COMPLIANCE: Conforms strictly to @gasha/contracts (Asset, Relationship).
==============================================================================
"""

from typing import Dict, Any, Tuple, List
from app.schemas.asset import AssetBase, RelationshipBase


def normalize_github_repo(
    repo_data: Dict[str, Any],
    manifests: Dict[str, Any],
    environment_id: str
) -> Tuple[AssetBase, List[RelationshipBase]]:
    """
    Normalizes a GitHub repository and its discovered manifests into a canonical GASHA Asset.
    """
    is_private = repo_data.get("private", True)
    is_archived = repo_data.get("archived", False)
    
    # Criticality tier
    criticality = "TIER_1_HIGH" if is_private else "TIER_2_MEDIUM"
    
    # Status
    status = "INACTIVE" if is_archived else "ACTIVE"

    # Compute dependency count
    total_deps = 0
    for m in manifests.values():
        total_deps += m.get("totalDependencies", 0)

    asset = AssetBase(
        name=repo_data.get("full_name") or repo_data.get("name", "unknown-repo"),
        type="GITHUB_REPOSITORY",
        criticality=criticality,
        environmentId=environment_id,
        source="GITHUB",
        metadata={
            "repoId": repo_data.get("id"),
            "owner": repo_data.get("owner", {}).get("login") if isinstance(repo_data.get("owner"), dict) else None,
            "fullName": repo_data.get("full_name"),
            "defaultBranch": repo_data.get("default_branch", "main"),
            "visibility": "private" if is_private else "public",
            "language": repo_data.get("language"),
            "htmlUrl": repo_data.get("html_url"),
            "archived": is_archived,
            "manifests": manifests,
            "dependencyCount": total_deps
        },
        isPubliclyExposed=not is_private,
        status=status
    )

    relationships: List[RelationshipBase] = []
    return asset, relationships
