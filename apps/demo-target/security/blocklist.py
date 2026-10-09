"""
==============================================================================
FILE: apps/demo-target/security/blocklist.py
ROLE / OWNERSHIP: Full Team (Demo Target Defenses)
OBJECTIVE: IP blocklist responsive to GASHA BLOCK_SOURCE containment actions.
           Supports optional durable file persistence via DEMO_TARGET_BLOCKLIST_FILE.
TOOLS & LIBRARIES: Python set, ipaddress
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - block_ip(ip_address: str) -> None
  - is_blocked(ip_address: str) -> bool
  - clear_blocklist() -> None
EXPECTED RESULTS / BEHAVIOR:
  - When GASHA executes BLOCK_SOURCE on an attacker IP, this module rejects subsequent requests with 403 Forbidden.
==============================================================================
"""

import os
import json
import sys
from typing import Set

_blocked_ips: Set[str] = set()

def _get_persist_file() -> str:
    return os.environ.get("DEMO_TARGET_BLOCKLIST_FILE", "")

def _load_persisted() -> None:
    path = _get_persist_file()
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                _blocked_ips.update(data)
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
                json.dump(list(_blocked_ips), f)
        except Exception:
            pass

_load_persisted()

# Register aliases in sys.modules to prevent disjoint module instances
_this_module = sys.modules.get(__name__)
if _this_module:
    sys.modules["security.blocklist"] = _this_module
    sys.modules["apps.demo_target.security.blocklist"] = _this_module

def block_ip(ip_address: str) -> None:
    _blocked_ips.add(ip_address)
    _sync_persist()

def is_blocked(ip_address: str) -> bool:
    _load_persisted()
    return ip_address in _blocked_ips

def clear_blocklist() -> None:
    _blocked_ips.clear()
    _sync_persist()

def get_blocked_ips() -> Set[str]:
    _load_persisted()
    return set(_blocked_ips)
