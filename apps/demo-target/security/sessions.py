"""
==============================================================================
FILE: apps/demo-target/security/sessions.py
ROLE / OWNERSHIP: Full Team (Demo Target Defenses)
OBJECTIVE: Session revocation store responsive to GASHA DISABLE_SESSION actions.
           Supports optional durable file persistence via DEMO_TARGET_SESSIONS_FILE.
TOOLS & LIBRARIES: Python set
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - disable_session(session_id: str) -> None
  - is_session_disabled(session_id: str) -> bool
  - clear_disabled_sessions() -> None
EXPECTED RESULTS / BEHAVIOR:
  - Immediately terminates compromised sessions when an admin account is flagged.
==============================================================================
"""

import os
import json
import sys
from typing import Set

_disabled_sessions: Set[str] = set()

def _get_persist_file() -> str:
    return os.environ.get("DEMO_TARGET_SESSIONS_FILE", "")

def _load_persisted() -> None:
    path = _get_persist_file()
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                _disabled_sessions.update(data)
        except Exception:
            pass

def _sync_persist() -> None:
    path = _get_persist_file()
    if path:
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(list(_disabled_sessions), f)
        except Exception:
            pass

_load_persisted()

# Register aliases in sys.modules to prevent disjoint module instances
_this_module = sys.modules.get(__name__)
if _this_module:
    sys.modules["security.sessions"] = _this_module
    sys.modules["apps.demo_target.security.sessions"] = _this_module

def disable_session(session_id: str) -> None:
    _disabled_sessions.add(session_id)
    _sync_persist()

def is_session_disabled(session_id: str) -> bool:
    _load_persisted()
    return session_id in _disabled_sessions

def clear_disabled_sessions() -> None:
    _disabled_sessions.clear()
    _sync_persist()

def get_disabled_sessions() -> Set[str]:
    _load_persisted()
    return set(_disabled_sessions)
