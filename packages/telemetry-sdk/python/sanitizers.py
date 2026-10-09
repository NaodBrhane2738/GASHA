"""
GASHA Telemetry Data Sanitizer
Ensures passwords, session tokens, authorization headers, private keys, and secrets
are strictly redacted before serialization and queueing, while preserving essential
security correlation identifiers (session IDs, user IDs, resource names).
"""
import re
from typing import Any, Dict, List, Union, Optional

REDACTED_VALUE = "[REDACTED]"

# Matches keys containing credential/secret values, while avoiding non-secret correlation identifiers
# (e.g. session_id, sessionId, user_id, auth_method, auth_result, api_version).
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"^.*(pass(word)?|passwd).*$", re.IGNORECASE),
    re.compile(r"^.*(client_secret|client_key|private_key|privkey).*$", re.IGNORECASE),
    re.compile(r"^.*(secret).*$", re.IGNORECASE),
    re.compile(r"^.*(access_token|refresh_token|id_token|bearer_token|auth_token).*$", re.IGNORECASE),
    re.compile(r"^.*(cookie|set_cookie).*$", re.IGNORECASE),
    re.compile(r"^.*(api[_-]?key).*$", re.IGNORECASE),
    re.compile(r"^.*(credit[_-]?card|card[_-]?num(ber)?|cvv|cvc).*$", re.IGNORECASE),
]

EXACT_SENSITIVE_KEYS = {
    "token", "authorization", "auth", "session_secret", "session_token",
    "signature", "sig", "pin", "credential", "credentials", "proxy-authorization"
}

# Explicitly exempt correlation/telemetry identifiers from false-positive redaction
PRESERVED_KEYS = {
    "session_id", "sessionid", "user_id", "userid", "auth_method", "auth_result",
    "action", "outcome", "target", "resource", "endpoint", "path", "source_ip",
    "sourceip", "client_id", "agent_id", "environment_id", "correlation_id",
    "event_id", "status_code", "http_status", "http_method"
}

# Regex to detect JWT patterns: 3 base64url segments separated by dots
JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")

def is_sensitive_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    lower_key = key.strip().lower()
    if lower_key in PRESERVED_KEYS:
        return False
    if lower_key in EXACT_SENSITIVE_KEYS:
        return True
    return any(p.search(lower_key) for p in SENSITIVE_KEY_PATTERNS)

def sanitize_value(value: Any) -> Any:
    """Recursively walks nested structures and redacts sensitive data."""
    if isinstance(value, dict):
        sanitized_dict = {}
        for k, v in value.items():
            str_key = str(k)
            if is_sensitive_key(str_key):
                sanitized_dict[k] = REDACTED_VALUE
            else:
                sanitized_dict[k] = sanitize_value(v)
        return sanitized_dict
    elif isinstance(value, list):
        return [sanitize_value(item) for item in value]
    elif isinstance(value, tuple):
        return tuple(sanitize_value(item) for item in value)
    elif isinstance(value, str):
        val_lower = value.strip().lower()
        if val_lower.startswith("bearer ") and len(value) > 7:
            return "Bearer [REDACTED]"
        if val_lower.startswith("basic ") and len(value) > 6:
            return "Basic [REDACTED]"
        if JWT_PATTERN.match(value.strip()):
            return "[REDACTED_JWT]"
        return value
    return value

def sanitize_metadata(data: Union[Dict[str, Any], List[Any], Any]) -> Any:
    """Public helper to sanitize telemetry metadata dictionaries or payloads."""
    if data is None:
        return {}
    return sanitize_value(data)

def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Sanitizes HTTP headers, redacting Authorization, Cookie, etc."""
    if not headers:
        return {}
    sanitized = {}
    for k, v in headers.items():
        if is_sensitive_key(str(k)):
            sanitized[k] = REDACTED_VALUE
        else:
            sanitized[k] = sanitize_value(v)
    return sanitized

def mask_token(token: Optional[str], visible_chars: int = 4) -> str:
    """Masks a token showing only the last few characters (e.g. ****abcd)."""
    if not token:
        return ""
    if len(token) <= visible_chars:
        return "*" * len(token)
    return "*" * (len(token) - visible_chars) + token[-visible_chars:]

