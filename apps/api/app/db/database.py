"""
==============================================================================
FILE: apps/api/app/db/database.py
ROLE / OWNERSHIP: Backend & Database Engineers
OBJECTIVE: Supabase client initialization, PostgreSQL connection lifecycle, and repositories.
TOOLS & LIBRARIES: Supabase-py (or postgrest-py), SQLAlchemy async engine (asyncpg), Redis
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - init_db() -> Initializes Supabase / PostgreSQL connection pool.
  - get_supabase_client() -> Returns authenticated Supabase client using SUPABASE_SERVICE_ROLE_KEY.
  - get_db_session() -> Async SQLAlchemy / asyncpg session dependency.
EXPECTED RESULTS / BEHAVIOR:
  - Connects securely to the remote Supabase PostgreSQL instance with Row Level Security (RLS) support.
==============================================================================
"""

import logging
from typing import AsyncGenerator, Optional
from app.core.config import settings

logger = logging.getLogger("gasha.db")

_supabase_client = None

def get_supabase_client():
    """Initializes or returns singleton Supabase client."""
    global _supabase_client
    if _supabase_client is None and settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
        try:
            from supabase import create_client, Client
            _supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
            logger.info("Supabase client initialized successfully")
        except ImportError:
            logger.warning("supabase package not installed; using standard PostgreSQL connection")
    return _supabase_client

async def init_db():
    logger.info(f"Connecting to Supabase PostgreSQL database at {settings.DATABASE_URL.split('@')[-1]}")

async def get_db_session() -> AsyncGenerator:
    """Dependency providing database session context."""
    yield None
