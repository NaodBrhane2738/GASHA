"""
==============================================================================
FILE: apps/api/app/response/enforcement.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Controlled Target Security Client. Interfaces strictly with the
           controlled demo target security enforcement modules (blocklist, sessions).
           Zero shell execution, zero arbitrary command strings.
==============================================================================
"""

import ipaddress
import importlib.util
import pathlib
import sys
from typing import Tuple, Optional


def _ensure_demo_target_modules():
    """
    Safely locates and registers apps/demo-target/security modules in sys.modules.
    Allows clean imports without package-naming conflicts, syncing both
    'apps.demo_target.security.*' and 'security.*' aliases to share identical state.
    """
    mod_b = sys.modules.get("apps.demo_target.security.blocklist") or sys.modules.get("security.blocklist")
    mod_s = sys.modules.get("apps.demo_target.security.sessions") or sys.modules.get("security.sessions")
    if mod_b is not None and mod_s is not None:
        sys.modules["apps.demo_target.security.blocklist"] = mod_b
        sys.modules["security.blocklist"] = mod_b
        sys.modules["apps.demo_target.security.sessions"] = mod_s
        sys.modules["security.sessions"] = mod_s
        return mod_b, mod_s

    # Find root path
    current_file = pathlib.Path(__file__).resolve()
    # Traversal up to GASHA repository root: apps/api/app/response/enforcement.py -> root is 5 levels up
    root_dir = current_file.parent.parent.parent.parent.parent
    demo_sec = root_dir / "apps" / "demo-target" / "security"
    if not demo_sec.exists():
        demo_sec = pathlib.Path.cwd() / "apps" / "demo-target" / "security"

    blocklist_path = demo_sec / "blocklist.py"
    sessions_path = demo_sec / "sessions.py"

    if blocklist_path.exists():
        spec_b = importlib.util.spec_from_file_location("apps.demo_target.security.blocklist", str(blocklist_path))
        mod_b = importlib.util.module_from_spec(spec_b)
        sys.modules["apps.demo_target.security.blocklist"] = mod_b
        sys.modules["security.blocklist"] = mod_b
        spec_b.loader.exec_module(mod_b)

    if sessions_path.exists():
        spec_s = importlib.util.spec_from_file_location("apps.demo_target.security.sessions", str(sessions_path))
        mod_s = importlib.util.module_from_spec(spec_s)
        sys.modules["apps.demo_target.security.sessions"] = mod_s
        sys.modules["security.sessions"] = mod_s
        spec_s.loader.exec_module(mod_s)

    return mod_b, mod_s


class TargetSecurityClient:
    """
    Enforces and verifies allowlisted active response actions against the controlled demo target.
    """

    def __init__(self):
        _ensure_demo_target_modules()

    def enforce_block_ip(self, ip_address: str) -> Tuple[bool, str]:
        """
        Validates target IP address and registers it on the demo target blocklist.
        Rejects invalid IPs, shell metacharacters, and placeholders.
        """
        clean_ip = ip_address.strip() if isinstance(ip_address, str) else ""
        try:
            parsed = ipaddress.ip_address(clean_ip)
            canonical_ip = str(parsed)
        except ValueError:
            return False, f"Invalid IP address for containment: '{clean_ip}'. Command injection or malformed input rejected."

        mod_b, _ = _ensure_demo_target_modules()
        if mod_b is None:
            return False, "Target security enforcement module 'blocklist' unavailable."

        mod_b.block_ip(canonical_ip)
        return True, f"Enforced perimeter blocklist drop for source IP '{canonical_ip}'."

    def verify_block_ip(self, ip_address: str) -> Tuple[bool, str]:
        """
        Actively queries the controlled demo target blocklist to verify enforcement state.
        """
        clean_ip = ip_address.strip() if isinstance(ip_address, str) else ""
        try:
            canonical_ip = str(ipaddress.ip_address(clean_ip))
        except ValueError:
            return False, f"Verification probe aborted: invalid IP '{clean_ip}'."

        mod_b, _ = _ensure_demo_target_modules()
        if mod_b is None:
            return False, "Target security blocklist module unavailable."

        if mod_b.is_blocked(canonical_ip):
            return True, f"Verified: IP '{canonical_ip}' is actively registered in demo target blocklist."
        return False, f"Verification Check: IP '{canonical_ip}' not found in active blocklist."

    def enforce_disable_session(self, session_id: str) -> Tuple[bool, str]:
        """
        Revokes an active session token in the controlled target sessions store.
        """
        clean_sid = session_id.strip() if isinstance(session_id, str) else ""
        if not clean_sid or clean_sid.lower() in ("unknown", "n/a", "none"):
            return False, f"Invalid session identifier: '{clean_sid}'."

        _, mod_s = _ensure_demo_target_modules()
        if mod_s is None:
            return False, "Target security sessions module unavailable."

        mod_s.disable_session(clean_sid)
        return True, f"Revoked active session token '{clean_sid}' in target session store."

    def verify_disable_session(self, session_id: str) -> Tuple[bool, str]:
        """
        Actively queries the controlled target disabled sessions store to verify revocation.
        """
        clean_sid = session_id.strip() if isinstance(session_id, str) else ""
        _, mod_s = _ensure_demo_target_modules()
        if mod_s is None:
            return False, "Target security sessions module unavailable."

        if mod_s.is_session_disabled(clean_sid):
            return True, f"Verified: Session '{clean_sid}' is actively revoked."
        return False, f"Verification Check: Session '{clean_sid}' not found in revoked sessions list."

    def enforce_isolate_resource(self, resource_id: str) -> Tuple[bool, str]:
        """
        Resource isolation requires explicit reversible mechanisms.
        Fails safely with explicit unsupported status if no verifiable isolation is implemented.
        """
        return False, (
            f"Unsupported action: Verifiable resource isolation is not implemented for target '{resource_id}'. "
            "Action rejected per security boundary mandate."
        )

    def verify_isolate_resource(self, resource_id: str) -> Tuple[bool, str]:
        return False, f"Verification probe failed: Resource isolation state is unsupported for '{resource_id}'."

    def clear_all_enforcements(self) -> None:
        """Clears all blocklists and disabled sessions for test isolation."""
        mod_b, mod_s = _ensure_demo_target_modules()
        if mod_b and hasattr(mod_b, "clear_blocklist"):
            mod_b.clear_blocklist()
        if mod_s and hasattr(mod_s, "clear_disabled_sessions"):
            mod_s.clear_disabled_sessions()


_default_target_client: Optional[TargetSecurityClient] = None


def get_target_security_client() -> TargetSecurityClient:
    global _default_target_client
    if _default_target_client is None:
        _default_target_client = TargetSecurityClient()
    return _default_target_client
