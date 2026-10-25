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
    API_HOST: str = "0.0.0.0"
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

    AI_PROVIDER: str = "ollama"
    AI_MODEL_NAME: str = "qwen2.5-coder:7b"
    AI_TEMPERATURE: float = 0.1
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    GASHA_TELEMETRY_API_KEY: str = "gasha-telemetry-demo-key-2026"

    # SOC policy enforcement (see app/response/policy.py)
    SOC_ENFORCEMENT_ENABLED: bool = True
    SOC_RATE_LIMIT_REQUESTS: int = 60
    SOC_RATE_LIMIT_WINDOW_SECONDS: int = 60
    SOC_ESCALATION_COUNT: int = 3
    SOC_ESCALATION_WINDOW_SECONDS: int = 300
    SOC_LOCK_DURATION_SECONDS: int = 900
    SOC_LOCK_ON_SEVERITY: str = "HIGH"
    SOC_AUTH_FAILURE_LIMIT: int = 5
    SOC_AUTH_FAILURE_WINDOW_SECONDS: int = 60
    SOC_MAX_BODY_BYTES: int = 1_048_576
    SOC_INSPECT_BODY_BYTES: int = 65_536
    # Only enable behind a proxy you control; otherwise clients can spoof X-Forwarded-For.
    SOC_TRUST_PROXY_HEADERS: bool = False
    # Number of trusted proxies in front of the API (Render / Railway / Fly: 1).
    SOC_TRUSTED_PROXY_HOPS: int = 1
    # Telemetry ingest is exempt: it is API-key authenticated and its bodies carry attack evidence by
    # design, so inspecting them would lock out the collector. Its events are analysed by the pipeline.
    SOC_EXEMPT_PATHS: List[str] = ["/health", "/docs", "/redoc", "/openapi.json", "/api/v1/soc", "/api/v1/realtime",
                                   "/api/v1/telemetry/ingest"]

    # SOC alert notifications (see app/notifications/)
    ALERT_EMAIL_PROVIDER: str = "log"  # log | smtp | resend
    ALERT_EMAIL_FROM: str = "GASHA SOC <alerts@gasha.local>"
    ALERT_EMAIL_TO: List[str] = []
    ALERT_MIN_SEVERITY: str = "HIGH"
    ALERT_COOLDOWN_SECONDS: int = 300
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False
    RESEND_API_KEY: str = ""
    RESEND_API_URL: str = "https://api.resend.com/emails"

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
