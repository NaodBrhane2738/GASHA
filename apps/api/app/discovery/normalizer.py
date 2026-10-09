"""
==============================================================================
FILE: apps/api/app/discovery/normalizer.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Transforms raw Vercel/GitHub JSON payloads into standard Asset entities.
==============================================================================
"""

from typing import Dict, Any, Tuple, List, Optional
from app.schemas.asset import AssetBase, RelationshipBase
from app.integrations.github.normalizer import normalize_github_repo
from app.integrations.vercel.normalizer import normalize_vercel_project


def normalize_vercel_resource(raw: Dict[str, Any], environment_id: str) -> AssetBase:
    asset, _, _ = normalize_vercel_project(
        project_data=raw,
        deployments=[],
        domains=[],
        environment_id=environment_id
    )
    return asset


def normalize_github_resource(raw: Dict[str, Any], environment_id: str) -> AssetBase:
    asset, _ = normalize_github_repo(
        repo_data=raw,
        manifests={},
        environment_id=environment_id
    )
    return asset
