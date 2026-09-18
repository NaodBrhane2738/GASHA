"""
==============================================================================
FILE: apps/api/app/adaptive/state_manager.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Manages global environment containment modes (NORMAL -> ACTIVE_DEFENSE -> LOCKDOWN).
TOOLS & LIBRARIES: Python state machine
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - set_containment_mode(mode: str)
  - get_containment_mode() -> str
EXPECTED RESULTS / BEHAVIOR:
  - Enforces platform-wide operational posture during ongoing attacks.
==============================================================================
"""

import logging

logger = logging.getLogger("gasha.adaptive.state_manager")

class EnvironmentStateManager:
    def __init__(self):
        self.mode = "NORMAL"

    def transition_mode(self, new_mode: str):
        logger.info(f"Transitioning containment mode: {self.mode} -> {new_mode}")
        self.mode = new_mode

state_manager = EnvironmentStateManager()
