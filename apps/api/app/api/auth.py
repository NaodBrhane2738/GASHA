"""
==============================================================================
FILE: apps/api/app/api/auth.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Secure authentication, PBKDF2 credential verification, authoritative
           environment-bound JWT tokens, single-use refresh token rotation, and session management.
==============================================================================
"""

import os
import secrets
import hashlib
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.security import create_jwt_token, create_refresh_token, hash_password, verify_password
from app.core.auth import get_current_user
from app.core.config import settings
from app.schemas.user import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserProfileResponse,
    ProvisionAdminRequest,
    CreateUserRequest,
    ChangePasswordRequest,
    UserRecord
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


@router.post("/provision-admin", response_model=UserProfileResponse, summary="One-Time Administrator Provisioning")
async def provision_admin(req: ProvisionAdminRequest):
    """
    Secure, one-time initial administrator bootstrap.
    Requires server-configured GASHA_PROVISIONING_TOKEN.
    Prevents reuse once an administrator has been provisioned.
    Never returns or logs secrets.
    """
    from app.core.production_guard import validate_password_complexity

    configured_token = os.environ.get("GASHA_PROVISIONING_TOKEN") or getattr(settings, "PROVISIONING_TOKEN", None)
    if not configured_token or not configured_token.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative bootstrap provisioning is not enabled on this server."
        )

    # Constant-time comparison
    if not secrets.compare_digest(req.provisioningToken.strip(), configured_token.strip()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid provisioning token."
        )

    user_repo = get_user_repository()
    if user_repo.is_system_provisioned():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is already provisioned. Initial provisioning token cannot be reused."
        )

    try:
        validate_password_complexity(req.password, username=req.username)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    now = datetime.now(timezone.utc).isoformat()
    uid = f"usr-{uuid4().hex[:12]}"
    pwd_hash = hash_password(req.password)
    user_record = UserRecord(
        id=uid,
        username=req.username.strip(),
        passwordHash=pwd_hash,
        role="admin",
        environmentId=req.environmentId or "env-prod",
        isActive=True,
        createdAt=now,
        updatedAt=now
    )
    token_hash = hashlib.sha256(req.provisioningToken.strip().encode("utf-8")).hexdigest()
    try:
        user_repo.provision_initial_admin(token_hash, user_record)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )

    from app.response.audit import get_audit_trail
    audit = get_audit_trail()
    audit.append_entry(
        req.environmentId or "env-prod",
        "PROVISION",
        "PROVISIONING_BOOTSTRAP",
        "sys-init",
        uid,
        "CREATE_ADMIN",
        req.username.strip(),
        "SUCCESS"
    )

    return UserProfileResponse(
        id=user_record.id,
        username=user_record.username,
        role=user_record.role,
        environmentId=user_record.environmentId,
        isActive=user_record.isActive
    )


@router.post("/users", response_model=UserProfileResponse, summary="Provision User Account (Admin Only)")
async def create_user(req: CreateUserRequest, caller: dict = Depends(get_current_user)):
    """
    Allows authenticated administrators to provision new accounts with role-based access.
    Ordinary analysts and operators cannot create users or escalate privileges.
    """
    from app.core.production_guard import validate_password_complexity

    caller_role = caller.get("role", "")
    if caller_role not in ("admin", "emergency_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators can provision user accounts."
        )

    if req.role == "emergency_admin" and caller_role != "emergency_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only emergency administrators can create emergency administrator accounts."
        )

    try:
        validate_password_complexity(req.password, username=req.username)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user_repo = get_user_repository()
    if user_repo.get_by_username(req.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with username '{req.username}' already exists."
        )

    now = datetime.now(timezone.utc).isoformat()
    uid = f"usr-{uuid4().hex[:12]}"
    pwd_hash = hash_password(req.password)
    user_record = UserRecord(
        id=uid,
        username=req.username.strip(),
        passwordHash=pwd_hash,
        role=req.role,
        environmentId=req.environmentId,
        isActive=True,
        createdAt=now,
        updatedAt=now
    )
    user_repo.save_user(user_record)

    from app.response.audit import get_audit_trail
    audit = get_audit_trail()
    audit.append_entry(
        req.environmentId,
        "PROVISION",
        caller.get("sub", "admin"),
        "user-mgmt",
        uid,
        f"CREATE_USER_{req.role.upper()}",
        req.username.strip(),
        "SUCCESS"
    )

    return UserProfileResponse(
        id=user_record.id,
        username=user_record.username,
        role=user_record.role,
        environmentId=user_record.environmentId,
        isActive=user_record.isActive
    )


@router.post("/password/change", summary="Change Authenticated User Password")
async def change_password(req: ChangePasswordRequest, caller: dict = Depends(get_current_user)):
    """
    Allows authenticated users to change their own password.
    Requires existing password verification, complexity check, and revokes all active refresh tokens.
    """
    from app.core.production_guard import validate_password_complexity

    user_repo = get_user_repository()
    username = caller.get("sub", "")
    user = user_repo.get_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if not verify_password(req.oldPassword, user.passwordHash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect current password."
        )

    try:
        validate_password_complexity(req.newPassword, username=username)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    new_hash = hash_password(req.newPassword)
    user_repo.change_password(user.id, new_hash)

    from app.response.audit import get_audit_trail
    audit = get_audit_trail()
    audit.append_entry(
        user.environmentId,
        "AUTH_MUTATION",
        username,
        "password-mgmt",
        user.id,
        "PASSWORD_CHANGED",
        user.username,
        "SUCCESS"
    )

    return {"status": "success", "message": "Password changed successfully. All active sessions revoked."}
