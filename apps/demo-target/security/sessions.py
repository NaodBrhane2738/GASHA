"""
==============================================================================
FILE: apps/demo-target/security/sessions.py
ROLE / OWNERSHIP: Full Team (Demo Target Defenses)
OBJECTIVE: Session revocation store responsive to GASHA DISABLE_SESSION actions.
TOOLS & LIBRARIES: Python set
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - disable_session(session_id: str) -> None
  - is_session_disabled(session_id: str) -> bool
  - clear_disabled_sessions() -> None
EXPECTED RESULTS / BEHAVIOR:
  - Immediately terminates compromised sessions when an admin account is flagged.
==============================================================================
"""

import sys
from typing import Set

_disabled_sessions: Set[str] = set()

# Register aliases in sys.modules to prevent disjoint module instances
_this_module = sys.modules.get(__name__)
if _this_module:
    sys.modules["security.sessions"] = _this_module
    sys.modules["apps.demo_target.security.sessions"] = _this_module

def disable_session(session_id: str) -> None:
    _disabled_sessions.add(session_id)

def is_session_disabled(session_id: str) -> bool:
    return session_id in _disabled_sessions

def clear_disabled_sessions() -> None:
    _disabled_sessions.clear()

def get_disabled_sessions() -> Set[str]:
    return set(_disabled_sessions)

