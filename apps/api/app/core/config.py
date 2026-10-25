"""
==============================================================================
FILE: apps/api/app/core/config.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Configuration management and environment variable parsing with Supabase support.
TOOLS & LIBRARIES: Pydantic Settings / BaseSettings, python-dotenv
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - class Settings(BaseSettings): Defines typed settings with sensible defaults.
  - Parses SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, DATABASE_URL.
EXPECTED RESULTS / BEHAVIOR:
  - Centralized, validated configuration object loaded at server startup.
==============================================================================
"""

import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    NODE_ENV: str = "development"
    API_PORT: int = 4000
    API_HOST: str = "127.0.0.1"
    API_BASE_URL: str = "http://localhost:4000/api/v1"
    WEB_URL: str = "http://localhost:3000"
    LOG_LEVEL: str = "debug"
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:3001"]

    # Supabase & Database Configuration
    SUPABASE_URL: str = "https://your-project-id.supabase.co"
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    DATABASE_URL: str = "postgresql://postgres:password@db.your-project-id.supabase.co:5432/postgres"
    DIRECT_URL: str = ""
    REDIS_URL: str = "redis://localhost:6379"

    JWT_SECRET: str = "super-secret-jwt-key-change-in-production-min32chars"
    JWT_EXPIRES_IN: str = "24h"
    INTERNAL_API_KEY: str = "gasha-internal-service-key-change-me"

    VERCEL_API_TOKEN: str = ""
    VERCEL_TEAM_ID: str = ""
    VERCEL_PROJECT_ID: str = ""

    GITHUB_APP_ID: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""

    # Integration Credential Security
    CREDENTIAL_ENCRYPTION_KEY: str = ""

    # Telemetry Pipeline Configuration
    GASHA_TELEMETRY_API_KEY: str = "gasha-telemetry-demo-key-2026"
    GASHA_TELEMETRY_ENVIRONMENT: str = "env-prod"
    GASHA_TELEMETRY_MAX_BATCH_SIZE: int = 100
    GASHA_TELEMETRY_MAX_PAYLOAD_BYTES: int = 1048576  # 1MB
    GASHA_TELEMETRY_TRUSTED_PROXIES: List[str] = ["127.0.0.1", "::1"]
    GASHA_TELEMETRY_BUFFER_CAPACITY: int = 5000

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
