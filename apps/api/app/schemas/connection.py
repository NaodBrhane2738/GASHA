"""
==============================================================================
FILE: apps/api/app/schemas/connection.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Pydantic schemas for external platform connection configurations (Vercel & GitHub).
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - VercelConnectRequest, GitHubConnectRequest
  - ConnectionStatusResponse: Status of connected cloud environments without secret leakage.
  - DiscoveryTriggerRequest, DiscoveryRunStatus, DiscoveryStatusResponse
==============================================================================
"""

from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field


class VercelConnectRequest(BaseModel):
    apiToken: str
    teamId: Optional[str] = None
    projectId: Optional[str] = None
    environmentId: Optional[str] = None


class GitHubConnectRequest(BaseModel):
    token: Optional[str] = None
    installationId: Optional[str] = None
    repository: Optional[str] = None
    repositories: Optional[List[str]] = None
    environmentId: Optional[str] = None


class ConnectionRecord(BaseModel):
    id: str
    provider: Literal['VERCEL', 'GITHUB']
    environmentId: str
    accountName: Optional[str] = None
    scope: Optional[str] = None
    encryptedToken: str
    status: Literal['CONNECTED', 'DISCONNECTED', 'ERROR'] = 'CONNECTED'
    resourceCount: int = 0
    lastSyncAt: Optional[str] = None
    errorMessage: Optional[str] = None
    createdAt: str
    updatedAt: str


class ConnectionStatusResponse(BaseModel):
    provider: Literal['VERCEL', 'GITHUB']
    isConnected: bool
    status: Literal['CONNECTED', 'DISCONNECTED', 'ERROR'] = 'CONNECTED'
    accountName: Optional[str] = None
    environmentId: str = "env-prod"
    lastSyncAt: Optional[str] = None
    resourceCount: int = 0
    errorMessage: Optional[str] = None


class DisconnectResponse(BaseModel):
    status: str
    provider: str
    message: str


class DiscoveryTriggerRequest(BaseModel):
    provider: Optional[Literal['VERCEL', 'GITHUB', 'ALL']] = 'ALL'
    environmentId: Optional[str] = None


class DiscoveryRunStatus(BaseModel):
    id: str
    environmentId: str
    provider: str
    status: Literal['PENDING', 'IN_PROGRESS', 'COMPLETED', 'PARTIAL', 'FAILED']
    startedAt: str
    completedAt: Optional[str] = None
    assetsDiscovered: int = 0
    relationshipsDiscovered: int = 0
    errors: List[str] = Field(default_factory=list)


class DiscoveryStatusResponse(BaseModel):
    status: str
    environmentId: str
    assetsDiscovered: int = 0
    relationshipsDiscovered: int = 0
    lastRunAt: Optional[str] = None
    recentRuns: List[DiscoveryRunStatus] = Field(default_factory=list)
