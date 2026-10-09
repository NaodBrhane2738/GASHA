"""
GASHA Detection Rules Package.
"""

from .catalog import (
    DetectionRuleDefinition,
    BRUTE_FORCE_AUTH_RULE,
    SUSPICIOUS_PROBE_RULE,
    SENSITIVE_ENDPOINT_PROBE_RULE,
    PRIVILEGE_ESCALATION_RULE,
    ALL_RULES,
    RULES_BY_ID,
)

__all__ = [
    "DetectionRuleDefinition",
    "BRUTE_FORCE_AUTH_RULE",
    "SUSPICIOUS_PROBE_RULE",
    "SENSITIVE_ENDPOINT_PROBE_RULE",
    "PRIVILEGE_ESCALATION_RULE",
    "ALL_RULES",
    "RULES_BY_ID",
]
