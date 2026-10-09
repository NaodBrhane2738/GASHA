"""
==============================================================================
FILE: apps/api/app/db/repositories/attack_path_repository.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Thread-safe repository for computed Attack Paths and reachability states.
STRICT ISOLATION: Partitioned strictly by environmentId.
==============================================================================
"""

import threading
from typing import Dict, List, Optional
from datetime import datetime, timezone

from app.schemas.attack_path import AttackPathResponse, ReachabilityStatus


class AttackPathRepository:
    def __init__(self):
        self._lock = threading.RLock()
        # Key: (environmentId, pathId) -> AttackPathResponse
        self._paths: Dict[tuple, AttackPathResponse] = {}

    def save_attack_paths(self, environment_id: str, paths: List[AttackPathResponse]):
        with self._lock:
            # Clear previous paths for this environment
            keys_to_del = [k for k in self._paths if k[0] == environment_id]
            for k in keys_to_del:
                del self._paths[k]

            for p in paths:
                self._paths[(environment_id, p.id)] = p

    def list_attack_paths(
        self,
        environment_id: str,
        is_active: Optional[bool] = None,
        reachability: Optional[ReachabilityStatus] = None
    ) -> List[AttackPathResponse]:
        with self._lock:
            results = [
                p for (env, _), p in self._paths.items()
                if env == environment_id
            ]
            if is_active is not None:
                results = [p for p in results if p.isActive == is_active]
            if reachability is not None:
                results = [p for p in results if p.reachability == reachability]
            # Return ordered by pathScore descending
            results.sort(key=lambda x: x.pathScore, reverse=True)
            return results

    def get_attack_path(self, path_id: str, environment_id: str) -> Optional[AttackPathResponse]:
        with self._lock:
            return self._paths.get((environment_id, path_id))

    def update_path_reachability(
        self,
        path_id: str,
        environment_id: str,
        is_active: bool,
        reachability: ReachabilityStatus,
        mitigated_at: Optional[str] = None
    ) -> Optional[AttackPathResponse]:
        with self._lock:
            key = (environment_id, path_id)
            existing = self._paths.get(key)
            if not existing:
                return None
            updated = AttackPathResponse(
                id=existing.id,
                environmentId=existing.environmentId,
                entryPointAssetId=existing.entryPointAssetId,
                targetAssetId=existing.targetAssetId,
                severity=existing.severity,
                pathScore=0.0 if not is_active else existing.pathScore,
                nodes=existing.nodes,
                isActive=is_active,
                reachability=reachability,
                discoveredAt=existing.discoveredAt,
                mitigatedAt=mitigated_at or (datetime.now(timezone.utc).isoformat() if not is_active else None),
                metadata=existing.metadata
            )
            self._paths[key] = updated
            return updated

    def clear(self, environment_id: Optional[str] = None):
        with self._lock:
            if environment_id:
                keys_to_del = [k for k in self._paths if k[0] == environment_id]
                for k in keys_to_del:
                    del self._paths[k]
            else:
                self._paths.clear()


_attack_path_repo_instance: Optional[AttackPathRepository] = None

def get_attack_path_repository() -> AttackPathRepository:
    global _attack_path_repo_instance
    if _attack_path_repo_instance is None:
        _attack_path_repo_instance = AttackPathRepository()
    return _attack_path_repo_instance
