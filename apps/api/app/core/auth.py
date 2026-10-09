"""
==============================================================================
FILE: apps/api/app/core/auth.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: JWT authentication, API key verification, role-based authorization (RBAC),
           and strict environment boundary enforcement dependencies for FastAPI.
==============================================================================
"""

from typing import Optional, List, Callable
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from app.core.config import settings
from app.core.security import verify_jwt_token

bearer_scheme = HTTPBearer(auto_error=False)
telemetry_api_key_header = APIKeyHeader(name="X-GASHA-TELEMETRY-KEY", auto_error=False)
telemetry_env_header = APIKeyHeader(name="X-GASHA-ENVIRONMENT", auto_error=False)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    """
    Validates JWT Bearer token and returns authenticated user claims.
    Ensures presence of authoritative environmentId claim.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer authentication token"
        )
    payload = verify_jwt_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token"
        )
    if not payload.get("environmentId"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token invalid: missing authoritative environmentId claim"
        )
    return payload


def enforce_environment_boundary(user: dict, requested_env: Optional[str] = None) -> str:
    """
    Validates caller environment against authoritative token claim.
    Rejects cross-environment query overrides with HTTP 403.
    """
    auth_env = user.get("environmentId")
    if not auth_env:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Caller identity lacks valid environment binding"
        )
    if requested_env and requested_env.strip() and requested_env.strip() != auth_env:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Token authorized for '{auth_env}', access to '{requested_env}' denied"
        )
    return auth_env


def require_role(allowed_roles: List[str]) -> Callable:
    """Dependency factory enforcing server-side role-based access control (RBAC)."""
    async def _role_checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role")
        if not user_role or user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: required one of {allowed_roles}, caller has '{user_role}'"
            )
        return user
    return _role_checker


require_analyst = require_role(["security_analyst", "security_operator", "admin", "emergency_admin"])
require_operator = require_role(["security_operator", "admin", "emergency_admin"])
require_admin = require_role(["admin", "emergency_admin"])


async def verify_telemetry_api_key(
    api_key: Optional[str] = Security(telemetry_api_key_header),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    target_env: Optional[str] = Security(telemetry_env_header)
) -> dict:
    """
    Validates telemetry ingestion API key and binds to authorized environment.
    """
    configured_key = getattr(settings, "GASHA_TELEMETRY_API_KEY", None)
    if not configured_key or not configured_key.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Telemetry ingestion is disabled: server API key not configured"
        )
    token = (api_key or (credentials.credentials if credentials else None) or "").strip()
    if not token or token != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing telemetry ingestion API key"
        )
    env_id = target_env.strip() if target_env and target_env.strip() else getattr(settings, "GASHA_TELEMETRY_ENVIRONMENT", "env-prod")
    return {
        "authenticated": True,
        "environmentId": env_id,
        "source": "api_key" if api_key else "bearer"
    }
