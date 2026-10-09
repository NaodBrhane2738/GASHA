"""
==============================================================================
FILE: apps/api/app/api/connections.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Secure Endpoints to manage and test Vercel & GitHub integrations.
SECURITY: Authenticated encryption at rest. Zero plaintext secrets in responses or logs.
STRICT ISOLATION: Integrations are strictly partitioned by environmentId.
==============================================================================
"""

import uuid
import logging
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.core.crypto import encrypt_credential
from app.db.repositories.connection_repository import get_connection_repository
from app.schemas.connection import (
    VercelConnectRequest,
    GitHubConnectRequest,
    ConnectionRecord,
    ConnectionStatusResponse,
    DisconnectResponse
)
from app.integrations.github.client import (
    GitHubAPIClient,
    GitHubAuthError,
    GitHubIntegrationError
)
from app.integrations.vercel.client import (
    VercelAPIClient,
    VercelAuthError,
    VercelIntegrationError
)

logger = logging.getLogger("gasha.api.connections")
router = APIRouter()


@router.post("/vercel", response_model=ConnectionStatusResponse, summary="Connect Vercel Team/Project")
async def connect_vercel(
    req: VercelConnectRequest,
    user: dict = Depends(get_current_user)
) -> ConnectionStatusResponse:
    """
    Connects a Vercel team/account using an API token.
    Validates credentials with Vercel API, encrypts the token at rest,
    and stores the connection scoped to the caller's authorized environment.
    """
    auth_env = enforce_environment_boundary(user, req.environmentId)

    if not req.apiToken or not req.apiToken.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required Vercel apiToken"
        )

    # Validate with upstream Vercel API
    client = VercelAPIClient(token=req.apiToken, team_id=req.teamId)
    try:
        val = await client.validate_credentials()
    except VercelAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Vercel authentication failed: {str(e)}"
        )
    except VercelIntegrationError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Vercel API error: {str(e)}"
        )

    account_name = val.get("teamName") or val.get("name") or val.get("username") or "vercel-account"
    encrypted_token = encrypt_credential(req.apiToken)
    now_iso = datetime.now(timezone.utc).isoformat()

    conn_repo = get_connection_repository()
    record = ConnectionRecord(
        id=f"conn-vercel-{auth_env}",
        provider="VERCEL",
        environmentId=auth_env,
        accountName=account_name,
        teamId=req.teamId,
        projectId=req.projectId,
        encryptedToken=encrypted_token,
        status="CONNECTED",
        resourceCount=0,
        lastSyncAt=None,
        createdAt=now_iso,
        updatedAt=now_iso
    )
    conn_repo.save_connection(record)

    return ConnectionStatusResponse(
        provider="VERCEL",
        isConnected=True,
        status="CONNECTED",
        accountName=account_name,
        environmentId=auth_env,
        lastSyncAt=None,
        resourceCount=0
    )


@router.post("/github", response_model=ConnectionStatusResponse, summary="Connect GitHub Repository/Account")
async def connect_github(
    req: GitHubConnectRequest,
    user: dict = Depends(get_current_user)
) -> ConnectionStatusResponse:
    """
    Connects a GitHub account or repository using a Personal Access Token or App Installation.
    Validates credentials with GitHub API, encrypts credentials at rest,
    and stores connection record scoped to caller's authorized environment.
    """
    auth_env = enforce_environment_boundary(user, req.environmentId)

    token = req.token or req.installationId
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing GitHub token or installationId"
        )

    client = GitHubAPIClient(token=token)
    try:
        val = await client.validate_credentials()
    except GitHubAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"GitHub authentication failed: {str(e)}"
        )
    except GitHubIntegrationError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub API error: {str(e)}"
        )

    account_name = val.get("login") or req.repository or "github-account"
    encrypted_token = encrypt_credential(token)
    now_iso = datetime.now(timezone.utc).isoformat()

    conn_repo = get_connection_repository()
    record = ConnectionRecord(
        id=f"conn-gh-{auth_env}",
        provider="GITHUB",
        environmentId=auth_env,
        accountName=account_name,
        scope=req.repository,
        encryptedToken=encrypted_token,
        status="CONNECTED",
        resourceCount=0,
        lastSyncAt=None,
        createdAt=now_iso,
        updatedAt=now_iso
    )
    conn_repo.save_connection(record)

    return ConnectionStatusResponse(
        provider="GITHUB",
        isConnected=True,
        status="CONNECTED",
        accountName=account_name,
        environmentId=auth_env,
        lastSyncAt=None,
        resourceCount=0
    )


@router.get("/status", response_model=List[ConnectionStatusResponse], summary="List Active Cloud Connections")
async def get_connection_status(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> List[ConnectionStatusResponse]:
    """
    Returns active connection status for the authorized environment.
    Guarantees zero plaintext tokens are leaked.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    conn_repo = get_connection_repository()
    records = conn_repo.list_connections(auth_env)

    results: List[ConnectionStatusResponse] = []
    found_providers = set()

    for r in records:
        found_providers.add(r.provider)
        results.append(
            ConnectionStatusResponse(
                provider=r.provider,
                isConnected=(r.status == "CONNECTED"),
                status=r.status,
                accountName=r.accountName,
                environmentId=r.environmentId,
                lastSyncAt=r.lastSyncAt,
                resourceCount=r.resourceCount,
                errorMessage=r.errorMessage
            )
        )

    for p in ("VERCEL", "GITHUB"):
        if p not in found_providers:
            results.append(
                ConnectionStatusResponse(
                    provider=p,
                    isConnected=False,
                    status="DISCONNECTED",
                    environmentId=auth_env,
                    resourceCount=0
                )
            )

    return results


@router.delete("/{provider}", response_model=DisconnectResponse, summary="Disconnect Cloud Provider")
async def disconnect_provider(
    provider: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> DisconnectResponse:
    """
    Disconnects a cloud integration provider and purges its stored credentials within authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    provider_upper = provider.upper()
    if provider_upper not in ("VERCEL", "GITHUB"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}. Must be VERCEL or GITHUB."
        )

    conn_repo = get_connection_repository()
    deleted = conn_repo.delete_connection(auth_env, provider_upper)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active connection found for provider {provider_upper} in environment {auth_env}"
        )

    return DisconnectResponse(
        status="DISCONNECTED",
        provider=provider_upper,
        message=f"{provider_upper} integration successfully disconnected"
    )
