"""
==============================================================================
FILE: apps/api/app/schemas/connection.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Pydantic schemas for external platform connection configurations (Vercel & GitHub).
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - VercelConnectRequest, GitHubConnectRequest
  - ConnectionStatusResponse: Status of connected cloud environments.
EXPECTED RESULTS / BEHAVIOR:
  - Validates API tokens and credentials prior to discovery execution.
==============================================================================
"""

from typing import Optional, Literal
from pydantic import BaseModel

class VercelConnectRequest(BaseModel):
    apiToken: str
    teamId: Optional[str] = None
    projectId: Optional[str] = None

class GitHubConnectRequest(BaseModel):
    installationId: str
    repository: str

class ConnectionStatusResponse(BaseModel):
    provider: Literal['VERCEL', 'GITHUB']
    isConnected: bool
    lastSyncAt: Optional[str] = None
    resourceCount: int = 0
