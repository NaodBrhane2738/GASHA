"""
==============================================================================
FILE: apps/api/app/core/security.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Cryptographic helpers, password hashing, and JWT encode/decode utilities.
TOOLS & LIBRARIES: PyJWT, passlib (bcrypt), secrets
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - create_jwt_token(data: dict, expires_delta: Optional[timedelta]) -> str
  - verify_jwt_token(token: str) -> Optional[dict]
  - hash_password(password: str) -> str
  - verify_password(plain_password: str, hashed_password: str) -> bool
EXPECTED RESULTS / BEHAVIOR:
  - Secure token creation and credential verification without plain-text storage.
==============================================================================
"""

import time
import jwt
from typing import Optional, Dict, Any
from app.core.config import settings

def create_jwt_token(data: Dict[str, Any], expires_seconds: int = 86400) -> str:
    payload = data.copy()
    payload.update({"exp": int(time.time()) + expires_seconds})
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
