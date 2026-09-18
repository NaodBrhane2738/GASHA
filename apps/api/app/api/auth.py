"""
==============================================================================
FILE: apps/api/app/api/auth.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Analyst authentication and session management endpoints.
TOOLS & LIBRARIES: FastAPI APIRouter, OAuth2PasswordRequestForm, PyJWT
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - POST /api/v1/auth/login: Authenticates analyst credentials and returns JWT bearer token.
  - GET /api/v1/auth/me: Returns profile of current authenticated analyst.
EXPECTED RESULTS / BEHAVIOR:
  - Generates secure JWT token; returns 401 on invalid credentials.
==============================================================================
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from app.core.security import create_jwt_token
from app.core.auth import get_current_user

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    accessToken: str
    tokenType: str = "bearer"
    expiresIn: int = 86400

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    # Standard development authentication logic
    if req.username == "admin" and req.password == "admin123":
        token = create_jwt_token({"sub": req.username, "role": "security_analyst"})
        return TokenResponse(accessToken=token)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

@router.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    return {"user": user}
