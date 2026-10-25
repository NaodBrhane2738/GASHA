"""
==============================================================================
FILE: apps/api/app/main.py
ROLE / OWNERSHIP: Backend Engineers (Lead Backend Developer: Abenezer)
OBJECTIVE: Application entry point for the GASHA FastAPI backend service.
TOOLS & LIBRARIES: FastAPI, Uvicorn, CORSMiddleware, Asyncpg / SQLAlchemy
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - create_app() -> FastAPI: Configures lifespan events, CORS, exception handlers, and routers.
  - Registers sub-routers for auth, discovery, digital twin, telemetry, detection, incidents, AI investigation, and responses.
  - WebSocket / SSE endpoint for live telemetry & state broadcasting.
EXPECTED RESULTS / BEHAVIOR:
  - Serves REST API at /api/v1/* and manages application startup/shutdown lifecycles.
==============================================================================
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.adaptive.soc_runtime import SocRuntime
from app.core.config import settings
from app.core.logging import setup_logging
from app.response.middleware import PolicyEnforcementMiddleware, SecurityHeadersMiddleware
from app.api import (
    auth,
    connections,
    discovery,
    assets,
    graph,
    vulnerabilities,
    risks,
    attack_paths,
    telemetry,
    detections,
    incidents,
    investigations,
    responses,
    environment,
    realtime,
    soc,
)

setup_logging()
logger = logging.getLogger("gasha.main")

def create_app() -> FastAPI:
    soc_runtime = SocRuntime.from_settings(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await soc_runtime.start()
        yield
        await soc_runtime.stop()

    app = FastAPI(
        title="GASHA Core API",
        description="Graph-Adaptive Security & Hardening Architecture Backend API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    app.state.soc = soc_runtime

    # Middleware runs bottom-up: CORS (outermost) -> security headers -> policy enforcement,
    # so 429/423 responses still carry CORS and hardening headers the browser can read.
    if settings.SOC_ENFORCEMENT_ENABLED:
        app.add_middleware(
            PolicyEnforcementMiddleware,
            pipeline=soc_runtime.pipeline,
            exempt_prefixes=settings.SOC_EXEMPT_PATHS,
            trust_proxy_headers=settings.SOC_TRUST_PROXY_HEADERS,
            trusted_proxy_hops=settings.SOC_TRUSTED_PROXY_HOPS,
            max_body_bytes=settings.SOC_MAX_BODY_BYTES,
            inspect_body_bytes=settings.SOC_INSPECT_BODY_BYTES,
        )
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Retry-After", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset", "X-GASHA-Policy"],
    )

    # Register API v1 Routers
    api_v1_prefix = "/api/v1"
    app.include_router(auth.router, prefix=f"{api_v1_prefix}/auth", tags=["Authentication"])
    app.include_router(connections.router, prefix=f"{api_v1_prefix}/connections", tags=["Connections"])
    app.include_router(discovery.router, prefix=f"{api_v1_prefix}/discovery", tags=["Discovery"])
    app.include_router(assets.router, prefix=f"{api_v1_prefix}/assets", tags=["Assets"])
    app.include_router(graph.router, prefix=f"{api_v1_prefix}/digital-twin", tags=["Digital Twin"])
    app.include_router(vulnerabilities.router, prefix=f"{api_v1_prefix}/vulnerabilities", tags=["Vulnerabilities"])
    app.include_router(risks.router, prefix=f"{api_v1_prefix}/risks", tags=["Risk Engine"])
    app.include_router(attack_paths.router, prefix=f"{api_v1_prefix}/attack-paths", tags=["Attack Paths"])
    app.include_router(telemetry.router, prefix=f"{api_v1_prefix}/telemetry", tags=["Telemetry Pipeline"])
    app.include_router(detections.router, prefix=f"{api_v1_prefix}/detections", tags=["Detection Engine"])
    app.include_router(incidents.router, prefix=f"{api_v1_prefix}/incidents", tags=["Incidents"])
    app.include_router(investigations.router, prefix=f"{api_v1_prefix}/investigations", tags=["AI Investigations"])
    app.include_router(responses.router, prefix=f"{api_v1_prefix}/responses", tags=["Controlled Response"])
    app.include_router(environment.router, prefix=f"{api_v1_prefix}/environment", tags=["Environment State"])
    app.include_router(realtime.router, prefix=f"{api_v1_prefix}/realtime", tags=["Realtime Stream"])
    app.include_router(soc.router, prefix=f"{api_v1_prefix}/soc", tags=["SOC Monitoring"])

    @app.get("/health", tags=["Health"])
    async def health_check():
        return {"status": "ok", "service": "gasha-api", "version": "0.1.0"}

    return app

app = create_app()
