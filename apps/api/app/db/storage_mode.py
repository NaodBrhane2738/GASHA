"""
==============================================================================
FILE: apps/api/app/db/storage_mode.py
ROLE / OWNERSHIP: Backend & Infrastructure Engineers
OBJECTIVE: Centralized, authoritative resolution and validation of storage backend mode.
           Eliminates accidental in-memory operation in production deployments.
==============================================================================
"""

import os
import logging
from typing import Optional

logger = logging.getLogger("gasha.storage_mode")


class StorageMode:
    SQL = "sql"
    MEMORY = "memory"


def resolve_storage_backend(explicit_mode: Optional[str] = None) -> str:
    """
    Authoritatively resolves the active storage backend ('sql' or 'memory').
    
    Rules:
    1. If explicit_mode or GASHA_STORAGE_BACKEND is provided:
       - Must match 'sql' or 'memory' (case-insensitive).
       - Any unrecognized or invalid value raises a ValueError immediately (fail-closed).
       - If NODE_ENV is 'production' and mode is 'memory', raises RuntimeError.
    2. If GASHA_STORAGE_BACKEND is unset:
       - In production (NODE_ENV == 'production'): defaults authoritatively to 'sql'.
       - In non-production (development, testing, demo): defaults to 'memory' to support
         isolated in-memory test doubles, with explicit informational logging.
    """
    raw_mode = explicit_mode if explicit_mode is not None else os.environ.get("GASHA_STORAGE_BACKEND")
    node_env = (
        os.environ.get("NODE_ENV", "") or
        os.environ.get("ENVIRONMENT", "") or
        os.environ.get("APP_ENV", "development")
    ).strip().lower()

    if raw_mode is not None:
        cleaned = raw_mode.strip().lower()
        if cleaned not in (StorageMode.SQL, StorageMode.MEMORY):
            raise ValueError(
                f"Invalid GASHA_STORAGE_BACKEND '{raw_mode}'. Supported storage modes: 'sql', 'memory'."
            )
        if node_env in ("production", "prod") and cleaned == StorageMode.MEMORY:
            raise RuntimeError(
                "Production environment requires durable 'sql' storage backend. In-memory mode is prohibited in production."
            )
        return cleaned

    # Unset behavior
    if node_env in ("production", "prod"):
        logger.info("GASHA_STORAGE_BACKEND unset; defaulting to 'sql' for production environment.")
        return StorageMode.SQL

    # Non-production fallback (test doubles, fast local unit execution)
    logger.debug("GASHA_STORAGE_BACKEND unset; running in 'memory' mode for non-production environment.")
    return StorageMode.MEMORY


def get_storage_backend() -> str:
    """Convenience accessor for current effective storage backend."""
    return resolve_storage_backend()
