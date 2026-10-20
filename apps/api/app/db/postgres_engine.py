"""
==============================================================================
FILE: apps/api/app/db/postgres_engine.py
OBJECTIVE: PostgreSQL / Supabase version of the SQLite persistence engine.

It exposes the SAME interface the repositories already use (get_connection(),
conn.execute("... ?", params), cur.fetchone()/fetchall() returning dict-like
rows), so SQLIncidentRepository, SQLDetectionRepository, SQLResponseRepository
and SQLAuditTrail work unchanged on top of it.

The Postgres tables (infra/database/migrations) use real arrays, JSONB,
NUMERIC and TIMESTAMPTZ columns, while the repositories were written for
SQLite, which stores everything as text. This module translates in both
directions at the boundary:
  - WRITE: "?" placeholders become "%s"; JSON-encoded lists are sent as real
           arrays for the TEXT[] columns.
  - READ : JSONB / arrays become JSON text again, timestamps become ISO-8601
           strings ending in "Z", NUMERIC becomes float.
The audit hash chain depends on timestamp text staying identical, so the "Z"
format is the same one SQLAuditTrail generates.

Schema is NOT created here. Apply it with:
    python infra/scripts/apply_migrations.py

Enable with:  GASHA_DB_DIALECT=postgres  and  DATABASE_URL=postgresql://...
==============================================================================
"""

import json
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Generator, Optional, Sequence
from urllib.parse import urlparse

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

# Columns that are TEXT[] in Postgres but arrive from the repositories as JSON text.
ARRAY_COLUMNS = {
    "matched_event_ids",
    "related_asset_ids",
    "detection_event_ids",
    "supporting_evidence_ids",
}

# Postgres type ids: json, jsonb, text[], varchar[]
_JSON_TEXT_OIDS = {114, 3802, 1009, 1015}

REQUIRED_TABLES = (
    "detections",
    "incidents",
    "investigations",
    "response_actions",
    "response_audit_log",
)

_INSERT_RE = re.compile(r"INSERT\s+INTO\s+\w+\s*\((.*?)\)\s*VALUES", re.IGNORECASE | re.DOTALL)


def describe_url(url: str) -> str:
    """host:port/database only. Never includes the password."""
    parsed = urlparse(url)
    return f"{parsed.hostname}:{parsed.port or 5432}/{(parsed.path or '/').lstrip('/')}"


def to_postgres_sql(sql: str) -> str:
    """SQLite style '?' placeholders -> psycopg '%s' (literal '%' must be doubled)."""
    return sql.replace("%", "%%").replace("?", "%s")


def convert_params(sql: str, params: Optional[Sequence[Any]]) -> Sequence[Any]:
    """For INSERTs, send JSON-encoded lists to TEXT[] columns as real lists."""
    if not params:
        return ()
    match = _INSERT_RE.search(sql)
    if not match:
        return params
    columns = [c.strip() for c in match.group(1).split(",")]
    if len(columns) != len(params):
        return params
    converted = list(params)
    for index, column in enumerate(columns):
        if column in ARRAY_COLUMNS and isinstance(converted[index], str):
            converted[index] = json.loads(converted[index])
    return tuple(converted)


def normalize_value(value: Any, type_oid: int) -> Any:
    if value is None:
        return None
    if type_oid in _JSON_TEXT_OIDS:
        return json.dumps(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Decimal):
        return float(value)
    return value


class _Cursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def _normalize(self, row):
        if row is None:
            return None
        return {col.name: normalize_value(row[col.name], col.type_code) for col in self._cursor.description}

    def fetchone(self):
        return self._normalize(self._cursor.fetchone())

    def fetchall(self):
        return [self._normalize(row) for row in self._cursor.fetchall()]

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount


class _Connection:
    def __init__(self, raw_connection):
        self._raw = raw_connection

    def execute(self, sql: str, params: Optional[Sequence[Any]] = None) -> _Cursor:
        cursor = self._raw.execute(to_postgres_sql(sql), convert_params(sql, params))
        return _Cursor(cursor)


class PostgresDatabaseEngine:
    """Connection-pooled engine for Postgres / Supabase."""

    def __init__(self, database_url: Optional[str] = None):
        url = database_url or os.environ.get("DATABASE_URL", "")
        if not url:
            # Fall back to the app settings, which also read a .env file in the working directory.
            from app.core.config import settings

            url = settings.DATABASE_URL
        if not url or "your-" in url:
            raise RuntimeError(
                "GASHA_DB_DIALECT=postgres needs DATABASE_URL (Supabase: Connect -> Session pooler)."
            )
        self.db_path = describe_url(url)  # keeps the name database.py logs; no password
        self._lock = threading.RLock()  # same single-writer behaviour as the SQLite engine
        self._pool = ConnectionPool(
            conninfo=url,
            min_size=1,
            max_size=int(os.environ.get("GASHA_DB_POOL_MAX", "5")),
            kwargs={
                "row_factory": dict_row,
                # Works with Supabase's transaction pooler too (no server-side prepared statements).
                "prepare_threshold": None,
            },
            open=False,
        )
        self._pool.open(wait=True, timeout=30)
        self.init_schema()

    def init_schema(self) -> None:
        """Does NOT create tables. Fails early, with the fix, if migrations were not applied."""
        with self.get_connection() as conn:
            missing = [
                table
                for table in REQUIRED_TABLES
                if conn.execute("SELECT to_regclass(?) AS found", (f"public.{table}",)).fetchone()["found"] is None
            ]
        if missing:
            raise RuntimeError(
                f"Database is missing tables {missing}. Run: python infra/scripts/apply_migrations.py"
            )

    @contextmanager
    def get_connection(self) -> Generator[_Connection, None, None]:
        with self._lock:
            # The pool commits when the block ends normally and rolls back on an exception.
            with self._pool.connection() as raw:
                yield _Connection(raw)

    def close(self) -> None:
        self._pool.close()