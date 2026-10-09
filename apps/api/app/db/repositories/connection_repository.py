"""
==============================================================================
FILE: apps/api/app/db/repositories/connection_repository.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Thread-safe repository for external cloud connections and discovery runs.
STRICT ISOLATION: Connections and sync logs are strictly partitioned by environmentId.
==============================================================================
"""

import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from app.schemas.connection import ConnectionRecord, DiscoveryRunStatus


class ConnectionRepository:
    def __init__(self):
        self._lock = threading.RLock()
        # Key: (environmentId, provider) -> ConnectionRecord
        self._connections: Dict[tuple, ConnectionRecord] = {}
        # Key: environmentId -> List[DiscoveryRunStatus]
        self._runs: Dict[str, List[DiscoveryRunStatus]] = {}

    def save_connection(self, record: ConnectionRecord) -> ConnectionRecord:
        with self._lock:
            key = (record.environmentId, record.provider.upper())
            self._connections[key] = record
            return record

    def get_connection(self, environment_id: str, provider: str) -> Optional[ConnectionRecord]:
        with self._lock:
            key = (environment_id, provider.upper())
            return self._connections.get(key)

    def list_connections(self, environment_id: str) -> List[ConnectionRecord]:
        with self._lock:
            return [
                conn for (env, _), conn in self._connections.items()
                if env == environment_id
            ]

    def delete_connection(self, environment_id: str, provider: str) -> bool:
        with self._lock:
            key = (environment_id, provider.upper())
            if key in self._connections:
                del self._connections[key]
                return True
            return False

    def update_sync_status(
        self,
        environment_id: str,
        provider: str,
        resource_count: int,
        last_sync_at: str,
        status: str = "CONNECTED",
        error: Optional[str] = None
    ) -> Optional[ConnectionRecord]:
        with self._lock:
            conn = self.get_connection(environment_id, provider)
            if not conn:
                return None
            conn.resourceCount = resource_count
            conn.lastSyncAt = last_sync_at
            conn.status = status
            conn.errorMessage = error
            conn.updatedAt = datetime.now(timezone.utc).isoformat()
            return conn

    def record_run(self, run: DiscoveryRunStatus) -> DiscoveryRunStatus:
        with self._lock:
            if run.environmentId not in self._runs:
                self._runs[run.environmentId] = []
            # Check if updating an existing run
            existing_idx = next(
                (i for i, r in enumerate(self._runs[run.environmentId]) if r.id == run.id),
                None
            )
            if existing_idx is not None:
                self._runs[run.environmentId][existing_idx] = run
            else:
                self._runs[run.environmentId].insert(0, run)
            return run

    def get_recent_runs(self, environment_id: str, limit: int = 10) -> List[DiscoveryRunStatus]:
        with self._lock:
            runs = self._runs.get(environment_id, [])
            return list(runs[:limit])

    def get_latest_run(self, environment_id: str) -> Optional[DiscoveryRunStatus]:
        with self._lock:
            runs = self._runs.get(environment_id, [])
            return runs[0] if runs else None

    def clear(self, environment_id: Optional[str] = None):
        with self._lock:
            if environment_id:
                keys_to_del = [k for k in self._connections if k[0] == environment_id]
                for k in keys_to_del:
                    del self._connections[k]
                self._runs.pop(environment_id, None)
            else:
                self._connections.clear()
                self._runs.clear()


_connection_repo_instance: Optional[ConnectionRepository] = None

def get_connection_repository(storage_backend: Optional[str] = None) -> Any:
    global _connection_repo_instance
    from app.db.storage_mode import resolve_storage_backend, StorageMode
    backend = resolve_storage_backend(storage_backend)
    if backend == StorageMode.SQL:
        from app.db.sql_engine import SQLConnectionRepository
        return SQLConnectionRepository()
    if _connection_repo_instance is None:
        _connection_repo_instance = ConnectionRepository()
    return _connection_repo_instance
