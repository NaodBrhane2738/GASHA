"""
==============================================================================
FILE: apps/api/app/db/repositories/user_repository.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Thread-safe repository managing user accounts, password hashes,
           environment memberships, and single-use refresh token rotation.
==============================================================================
"""

import threading
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from app.schemas.user import UserRecord, UserRole
from app.core.security import hash_password, verify_password, hash_refresh_token


class UserRepository:
    """
    Thread-safe repository managing user identities, hashed credentials, and refresh tokens.
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._users_by_id: Dict[str, UserRecord] = {}
        self._users_by_username: Dict[str, str] = {}  # username.lower() -> id
        # user_id -> Dict[token_hash, expires_at]
        self._refresh_tokens: Dict[str, Dict[str, float]] = {}
        self._seed_default_accounts()

    def _seed_default_accounts(self):
        """Seeds standard role accounts with strong hashed passwords for demonstration & testing."""
        now = datetime.now(timezone.utc).isoformat()
        seeds = [
            ("usr-analyst-1", "analyst", "AnalystSecure2026!", "security_analyst", "env-prod"),
            ("usr-operator-1", "operator", "OperatorSecure2026!", "security_operator", "env-prod"),
            ("usr-admin-1", "admin", "AdminRoot2026!", "admin", "env-prod"),
            ("usr-emergency-1", "breakglass", "EmergencyRoot2026!", "emergency_admin", "env-prod"),
            ("usr-analyst-b", "analyst_b", "TenantBSecure2026!", "security_analyst", "env-tenant-b"),
        ]
        for uid, uname, pwd, role, env_id in seeds:
            u = UserRecord(
                id=uid,
                username=uname,
                passwordHash=hash_password(pwd),
                role=role,
                environmentId=env_id,
                isActive=True,
                createdAt=now,
                updatedAt=now
            )
            self._users_by_id[uid] = u
            self._users_by_username[uname.lower()] = uid

    def get_by_username(self, username: str) -> Optional[UserRecord]:
        with self._lock:
            uid = self._users_by_username.get(username.strip().lower())
            if not uid:
                return None
            return self._users_by_id.get(uid)

    def get_by_id(self, user_id: str) -> Optional[UserRecord]:
        with self._lock:
            return self._users_by_id.get(user_id)

    def save_user(self, user: UserRecord) -> UserRecord:
        with self._lock:
            self._users_by_id[user.id] = user
            self._users_by_username[user.username.strip().lower()] = user.id
            return user

    def authenticate(self, username: str, plain_password: str) -> Optional[UserRecord]:
        """
        Authenticates username and password against PBKDF2 hash in constant time.
        Returns UserRecord if valid and active, else None.
        """
        user = self.get_by_username(username)
        if not user or not user.isActive:
            # Constant-time dummy verification to thwart timing attacks
            verify_password("dummy_password", "pbkdf2_sha256$600000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000")
            return None
        if not verify_password(plain_password, user.passwordHash):
            return None
        return user

    def store_refresh_token(self, user_id: str, raw_refresh_token: str, expires_seconds: int = 604800) -> None:
        """Stores a hashed refresh token with expiry timestamp (7 days default)."""
        token_hash = hash_refresh_token(raw_refresh_token)
        expires_at = time.time() + expires_seconds
        with self._lock:
            if user_id not in self._refresh_tokens:
                self._refresh_tokens[user_id] = {}
            self._refresh_tokens[user_id][token_hash] = expires_at

    def consume_refresh_token(self, user_id: str, raw_refresh_token: str) -> bool:
        """
        Validates and single-use consumes a refresh token.
        Returns True if valid and consumed; False if invalid, expired, or already reused.
        """
        token_hash = hash_refresh_token(raw_refresh_token)
        now = time.time()
        with self._lock:
            user_tokens = self._refresh_tokens.get(user_id, {})
            expires_at = user_tokens.pop(token_hash, None)
            if expires_at is None:
                return False
            if now > expires_at:
                return False
            return True

    def revoke_all_refresh_tokens(self, user_id: str) -> None:
        with self._lock:
            self._refresh_tokens.pop(user_id, None)

    def list_users(self) -> List[UserRecord]:
        with self._lock:
            return list(self._users_by_id.values())


_default_user_repo: Optional[UserRepository] = None


def get_user_repository() -> UserRepository:
    global _default_user_repo
    if _default_user_repo is None:
        _default_user_repo = UserRepository()
    return _default_user_repo
