"""
==============================================================================
FILE: apps/demo-target/security/blocklist.py
ROLE / OWNERSHIP: Full Team (Demo Target Defenses)
OBJECTIVE: In-memory IP blocklist responsive to GASHA BLOCK_SOURCE containment actions.
TOOLS & LIBRARIES: Python set, ipaddress
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - block_ip(ip_address: str) -> None
  - is_blocked(ip_address: str) -> bool
  - clear_blocklist() -> None
EXPECTED RESULTS / BEHAVIOR:
  - When GASHA executes BLOCK_SOURCE on an attacker IP, this module rejects subsequent requests with 403 Forbidden.
==============================================================================
"""

from typing import Set

_blocked_ips: Set[str] = set()

def block_ip(ip_address: str) -> None:
    _blocked_ips.add(ip_address)

def is_blocked(ip_address: str) -> bool:
    return ip_address in _blocked_ips

def clear_blocklist() -> None:
    _blocked_ips.clear()
