"""
==============================================================================
FILE: apps/api/app/schemas/user.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Pydantic schemas for authenticated analysts, operators, and administrators.
==============================================================================
"""

from typing import Optional, Literal
from pydantic import BaseModel, Field

UserRole = Literal['security_analyst', 'security_operator', 'admin', 'emergency_admin']


class UserRecord(BaseModel):
    id: str
    username: str
    passwordHash: str
    role: UserRole
    environmentId: str = "env-prod"
    isActive: bool = True
    createdAt: str
    updatedAt: str


class UserProfileResponse(BaseModel):
    id: str
    username: str
    role: UserRole
    environmentId: str
    isActive: bool


class LoginRequest(BaseModel):
    username: str
    password: str
    environmentId: Optional[str] = None


class TokenResponse(BaseModel):
    accessToken: str
    refreshToken: Optional[str] = None
    tokenType: str = "bearer"
    expiresIn: int = 86400
    environmentId: str
    role: UserRole


class RefreshTokenRequest(BaseModel):
    refreshToken: str
