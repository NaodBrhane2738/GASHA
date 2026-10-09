"""
==============================================================================
FILE: apps/api/app/api/auth.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Secure authentication, PBKDF2 credential verification, authoritative
           environment-bound JWT tokens, single-use refresh token rotation, and session management.
==============================================================================
"""

from fastapi import APIRouter, Depends, HTTPException, status
from app.core.security import create_jwt_token, create_refresh_token
from app.core.auth import get_current_user
from app.schemas.user import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserProfileResponse
)
from app.db.repositories.user_repository import get_user_repository

router = APIRouter()


@router.post("/login", response_model=TokenResponse, summary="Authenticate and Issue Tokens")
async def login(req: LoginRequest):
    """
    Authenticates username and password against the PBKDF2 user repository.
    Binds the authenticated user identity, role, and authorized environment into signed tokens.
    """
    user_repo = get_user_repository()
    user = user_repo.authenticate(req.username, req.password)
    if not user:
        # Uniform, timing-safe error response
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Determine authorized environment: honor requested env only if matching user's assignment
    authorized_env = user.environmentId
    if req.environmentId and req.environmentId != user.environmentId:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User '{user.username}' is not authorized for environment '{req.environmentId}'"
        )

    # 1. Issue access token bound to identity, role, and environmentId
    access_token = create_jwt_token({
        "sub": user.username,
        "userId": user.id,
        "role": user.role,
        "environmentId": authorized_env
    }, expires_seconds=86400)

    # 2. Issue single-use refresh token
    refresh_tok = create_refresh_token()
    user_repo.store_refresh_token(user.id, refresh_tok, expires_seconds=604800)

    return TokenResponse(
        accessToken=access_token,
        refreshToken=refresh_tok,
        tokenType="bearer",
        expiresIn=86400,
        environmentId=authorized_env,
        role=user.role
    )


@router.post("/refresh", response_model=TokenResponse, summary="Rotate Single-Use Refresh Token")
async def refresh_token(req: RefreshTokenRequest):
    """
    Rotates a single-use refresh token. Consumes the old token and issues a new pair.
    Detects token reuse and revokes on reuse.
    """
    user_repo = get_user_repository()
    # Find matching user for the refresh token
    matched_user = None
    for u in user_repo.list_users():
        if user_repo.consume_refresh_token(u.id, req.refreshToken):
            matched_user = u
            break

    if not matched_user or not matched_user.isActive:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or previously consumed refresh token"
        )

    # Issue new access token
    new_access_token = create_jwt_token({
        "sub": matched_user.username,
        "userId": matched_user.id,
        "role": matched_user.role,
        "environmentId": matched_user.environmentId
    }, expires_seconds=86400)

    # Issue new rotated refresh token
    new_refresh_tok = create_refresh_token()
    user_repo.store_refresh_token(matched_user.id, new_refresh_tok, expires_seconds=604800)

    return TokenResponse(
        accessToken=new_access_token,
        refreshToken=new_refresh_tok,
        tokenType="bearer",
        expiresIn=86400,
        environmentId=matched_user.environmentId,
        role=matched_user.role
    )


@router.post("/logout", summary="Revoke Active Sessions and Refresh Tokens")
async def logout(user: dict = Depends(get_current_user)):
    """Revokes all active refresh tokens for the authenticated user session."""
    user_repo = get_user_repository()
    uid = user.get("userId")
    if not uid:
        u = user_repo.get_by_username(user.get("sub", ""))
        uid = u.id if u else None
    if uid:
        user_repo.revoke_all_refresh_tokens(uid)
    return {"status": "success", "message": "Logged out and refresh tokens revoked."}


@router.get("/me", response_model=UserProfileResponse, summary="Get Authenticated User Profile")
async def get_me(user: dict = Depends(get_current_user)):
    """Returns profile and authorized environment scope of current authenticated user."""
    user_repo = get_user_repository()
    u = user_repo.get_by_username(user.get("sub", ""))
    if not u:
        return UserProfileResponse(
            id=user.get("userId", f"usr-{user.get('sub')}"),
            username=user.get("sub", "unknown"),
            role=user.get("role", "security_analyst"),
            environmentId=user.get("environmentId", "env-prod"),
            isActive=True
        )
    return UserProfileResponse(
        id=u.id,
        username=u.username,
        role=u.role,
        environmentId=u.environmentId,
        isActive=u.isActive
    )
