"""
==============================================================================
FILE: apps/api/app/db/repositories/asset_repository.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Thread-safe repository for canonical Assets and Relationships.
IDEMPOTENCY: Safely merges updates without creating duplicate nodes or edges.
STRICT ISOLATION: All asset and relationship queries are scoped by environmentId.
==============================================================================
"""

import uuid
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from app.schemas.asset import (
    AssetBase,
    AssetResponse,
    RelationshipBase,
    RelationshipResponse
)


class AssetRepository:
    def __init__(self):
        self._lock = threading.RLock()
        # Key: (environmentId, assetId) -> AssetResponse
        self._assets: Dict[tuple, AssetResponse] = {}
        # Key: (environmentId, source, name) -> assetId (for idempotent lookups)
        self._asset_index: Dict[tuple, str] = {}
        # Key: (environmentId, relId) -> RelationshipResponse
        self._relationships: Dict[tuple, RelationshipResponse] = {}
        # Key: (sourceAssetId, targetAssetId, type) -> relId (for idempotent edge lookups)
        self._relationship_index: Dict[tuple, str] = {}

    def upsert_asset(self, asset: AssetBase, asset_id: Optional[str] = None) -> AssetResponse:
        with self._lock:
            now_iso = datetime.now(timezone.utc).isoformat()
            index_key = (asset.environmentId, asset.source, asset.name)

            existing_id = asset_id if (asset_id and (asset.environmentId, asset_id) in self._assets) else self._asset_index.get(index_key)

            if existing_id:
                existing = self._assets[(asset.environmentId, existing_id)]
                # Merge metadata safely
                merged_meta = dict(existing.metadata)
                merged_meta.update(asset.metadata)

                updated = AssetResponse(
                    id=existing.id,
                    name=asset.name,
                    type=asset.type,
                    criticality=asset.criticality,
                    environmentId=asset.environmentId,
                    source=asset.source,
                    metadata=merged_meta,
                    isPubliclyExposed=asset.isPubliclyExposed,
                    status=asset.status,
                    createdAt=existing.createdAt,
                    updatedAt=now_iso
                )
                self._assets[(asset.environmentId, existing.id)] = updated
                self._asset_index[index_key] = existing.id
                return updated

            # New Asset
            new_id = asset_id or f"asset-{uuid.uuid4().hex[:12]}"
            new_asset = AssetResponse(
                id=new_id,
                name=asset.name,
                type=asset.type,
                criticality=asset.criticality,
                environmentId=asset.environmentId,
                source=asset.source,
                metadata=asset.metadata,
                isPubliclyExposed=asset.isPubliclyExposed,
                status=asset.status,
                createdAt=now_iso,
                updatedAt=now_iso
            )
            self._assets[(asset.environmentId, new_id)] = new_asset
            self._asset_index[index_key] = new_id
            return new_asset

    def upsert_relationship(
        self,
        rel: RelationshipBase,
        rel_id: Optional[str] = None,
        environment_id: str = "env-prod"
    ) -> RelationshipResponse:
        with self._lock:
            now_iso = datetime.now(timezone.utc).isoformat()
            edge_key = (rel.sourceAssetId, rel.targetAssetId, rel.type)

            existing_id = self._relationship_index.get(edge_key)
            if existing_id:
                existing = self._relationships[(environment_id, existing_id)]
                merged_meta = dict(existing.metadata)
                merged_meta.update(rel.metadata)

                updated = RelationshipResponse(
                    id=existing.id,
                    sourceAssetId=rel.sourceAssetId,
                    targetAssetId=rel.targetAssetId,
                    type=rel.type,
                    metadata=merged_meta,
                    createdAt=existing.createdAt
                )
                self._relationships[(environment_id, existing.id)] = updated
                return updated

            new_id = rel_id or f"rel-{uuid.uuid4().hex[:12]}"
            new_rel = RelationshipResponse(
                id=new_id,
                sourceAssetId=rel.sourceAssetId,
                targetAssetId=rel.targetAssetId,
                type=rel.type,
                metadata=rel.metadata,
                createdAt=now_iso
            )
            self._relationships[(environment_id, new_id)] = new_rel
            self._relationship_index[edge_key] = new_id
            return new_rel

    def get_asset(self, asset_id: str, environment_id: str) -> Optional[AssetResponse]:
        with self._lock:
            return self._assets.get((environment_id, asset_id))

    def get_asset_by_name(self, name: str, environment_id: str) -> Optional[AssetResponse]:
        with self._lock:
            for (env, _), asset in self._assets.items():
                if env == environment_id and asset.name == name:
                    return asset
            return None

    def list_assets(
        self,
        environment_id: str,
        asset_type: Optional[str] = None,
        source: Optional[str] = None
    ) -> List[AssetResponse]:
        with self._lock:
            results = [
                asset for (env, _), asset in self._assets.items()
                if env == environment_id
            ]
            if asset_type:
                results = [a for a in results if a.type == asset_type]
            if source:
                results = [a for a in results if a.source == source]
            return results

    def list_relationships(self, environment_id: str) -> List[RelationshipResponse]:
        with self._lock:
            return [
                rel for (env, _), rel in self._relationships.items()
                if env == environment_id
            ]

    def count_assets(self, environment_id: str) -> int:
        with self._lock:
            return sum(1 for (env, _) in self._assets.keys() if env == environment_id)

    def count_relationships(self, environment_id: str) -> int:
        with self._lock:
            return sum(1 for (env, _) in self._relationships.keys() if env == environment_id)

    def clear(self, environment_id: Optional[str] = None):
        with self._lock:
            if environment_id:
                keys_to_del = [k for k in self._assets if k[0] == environment_id]
                for k in keys_to_del:
                    del self._assets[k]
                idx_to_del = [k for k in self._asset_index if k[0] == environment_id]
                for k in idx_to_del:
                    del self._asset_index[k]
                rel_keys_to_del = [k for k in self._relationships if k[0] == environment_id]
                for k in rel_keys_to_del:
                    del self._relationships[k]
            else:
                self._assets.clear()
                self._asset_index.clear()
                self._relationships.clear()
                self._relationship_index.clear()


_asset_repo_instance: Optional[AssetRepository] = None

def get_asset_repository(storage_backend: Optional[str] = None) -> Any:
    global _asset_repo_instance
    from app.db.storage_mode import resolve_storage_backend, StorageMode
    backend = resolve_storage_backend(storage_backend)
    if backend == StorageMode.SQL:
        from app.db.sql_engine import SQLAssetRepository
        return SQLAssetRepository()
    if _asset_repo_instance is None:
        _asset_repo_instance = AssetRepository()
    return _asset_repo_instance
