"""
==============================================================================
FILE: apps/api/app/core/auth.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: JWT authentication and API key verification dependencies for FastAPI.
TOOLS & LIBRARIES: FastAPI Security (HTTPBearer, APIKeyHeader), PyJWT, passlib
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - get_current_user(token: str = Depends(oauth2_scheme)) -> dict: Decodes & verifies JWT.
  - verify_telemetry_key(key: str = Security(api_key_header)) -> bool: Verifies SDK ingestion key.
  - verify_internal_key(key: str = Security(internal_header)) -> bool: Protects internal services.
EXPECTED RESULTS / BEHAVIOR:
  - Injects authenticated user/service context into protected routes; raises HTTP 401 on failure.
==============================================================================
"""

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from app.core.config import settings
from app.core.security import verify_jwt_token

bearer_scheme = HTTPBearer(auto_error=False)
telemetry_api_key_header = APIKeyHeader(name="X-GASHA-TELEMETRY-KEY", auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
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
    return payload

async def verify_telemetry_api_key(
    api_key: str = Security(telemetry_api_key_header),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
):
    token = api_key or (credentials.credentials if credentials else None)
    if token != settings.GASHA_TELEMETRY_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid telemetry ingestion API key"
        )
    return True
