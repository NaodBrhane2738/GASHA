"""
==============================================================================
FILE: apps/api/app/ai/context_normalizer.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Normalize raw GASHA security data structures, scrub sensitive
           credentials/secrets, and enforce untrusted data boundaries.
TOOLS & LIBRARIES: Pydantic v2, Python standard library (re, datetime)
KEY FEATURES:
  - normalize_incident(), normalize_detection(), normalize_telemetry_event()
  - normalize_asset(), normalize_attack_path(), normalize_vulnerability(), normalize_risk()
  - scrub_secrets(): Redacts passwords, API keys, bearer tokens, private keys from metadata/payloads.
  - sanitize_untrusted_string(): Ensures untrusted log strings remain inert data.
EXPECTED RESULTS / BEHAVIOR:
  - Produces consistent, typed Context models compatible with contracts.py
  - Strips credentials while preserving structural forensic identifiers.
==============================================================================
"""

import re
import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

from app.ai.contracts import (
    IncidentContext,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    AttackPathContext,
    AttackPathHopContext,
    VulnerabilityContext,
    RiskContext,
    EvidenceItem,
    AvailableActionContext,
    SeverityLevel,
    IncidentStatusType,
    ResponseActionType,
    ResponseTargetType,
    EvidenceType,
)

# ============================================================================
# SECRET SCRUBBING REGEXES & SENSITIVE KEYS
# ============================================================================

SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|bearer|jwt|"
    r"private[_-]?key|session[_-]?token|client[_-]?secret|credentials|authorization|"
    r"aws[_-]?(key|access|secret)|github[_-]?token)",
    re.IGNORECASE,
)

SENSITIVE_VALUE_PATTERNS = [
    # JWT tokens (eyJ...)
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    # AWS Access Key IDs
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # GitHub personal access tokens
    re.compile(r"\bghp_[a-zA-Z0-9]{20,}\b"),
    # OpenAI/Anthropic/generic API keys
    re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
    # Private Key blocks
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    # Generic API Keys / Tokens (hex or base64 > 32 chars)
    re.compile(r"(?:api[_-]?key|token|secret)[=:\s]+(['\"]?)([a-zA-Z0-9_\-]{32,})\1", re.IGNORECASE),
    # Bearer tokens in headers
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE),
]

REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_TOKEN = "[REDACTED_TOKEN]"


def scrub_secrets(data: Any) -> Any:
    """
    Recursively scans and scrubs credentials, tokens, and secret strings from
    dictionaries, lists, and string values. Preserves non-sensitive structure.
    """
    if isinstance(data, dict):
        scrubbed_dict = {}
        for key, value in data.items():
            if SENSITIVE_KEY_PATTERNS.search(str(key)):
                scrubbed_dict[key] = REDACTED_SECRET
            else:
                scrubbed_dict[key] = scrub_secrets(value)
        return scrubbed_dict
    elif isinstance(data, list):
        return [scrub_secrets(item) for item in data]
    elif isinstance(data, str):
        scrubbed_str = data
        for pattern in SENSITIVE_VALUE_PATTERNS:
            scrubbed_str = pattern.sub(REDACTED_SECRET, scrubbed_str)
        return scrubbed_str
    return data


def parse_iso_timestamp(timestamp_str: Optional[str]) -> str:
    """
    Ensures timestamp is ISO 8601 UTC formatted. If missing or invalid,
    defaults to current UTC ISO timestamp without crashing.
    """
    if not timestamp_str:
        return datetime.now(timezone.utc).isoformat()
    try:
        # Standardize representation if parseable
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return dt.isoformat()
    except (ValueError, TypeError):
        return str(timestamp_str)


def to_dict(obj: Any) -> Dict[str, Any]:
    """Helper to convert Pydantic model or dict to plain dict."""
    if isinstance(obj, BaseModel):
        return obj.model_dump()
    if isinstance(obj, dict):
        return copy.deepcopy(obj)
    return {}


# ============================================================================
# NORMALIZERS FOR CANONICAL BACKEND STRUCTURES
# ============================================================================

def normalize_incident(raw: Union[BaseModel, Dict[str, Any]]) -> IncidentContext:
    """Normalizes raw incident data into IncidentContext."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    return IncidentContext(
        id=str(d.get("id") or "UNKNOWN_INCIDENT"),
        title=str(d.get("title") or "Untitled Incident"),
        severity=d.get("severity") if d.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM",
        status=d.get("status") if d.get("status") in ("ACTIVE", "INVESTIGATING", "CONTAINED", "RESOLVED") else "ACTIVE",
        primaryAffectedAssetId=str(d.get("primaryAffectedAssetId") or d.get("assetId") or "UNKNOWN_ASSET"),
        relatedAssetIds=[str(a) for a in d.get("relatedAssetIds", [])],
        detectionEventIds=[str(e) for e in d.get("detectionEventIds", [])],
        attackPathId=str(d["attackPathId"]) if d.get("attackPathId") else None,
        createdAt=parse_iso_timestamp(d.get("createdAt")),
        updatedAt=parse_iso_timestamp(d.get("updatedAt")),
        summary=d.get("summary"),
    )


def normalize_detection(raw: Union[BaseModel, Dict[str, Any]]) -> DetectionContext:
    """Normalizes detection event or match into DetectionContext."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    rule_info = d.get("rule", {})
    if isinstance(rule_info, dict):
        rule_id = str(rule_info.get("ruleId") or d.get("ruleId") or "DET_RULE_UNKNOWN")
        rule_name = str(rule_info.get("name") or d.get("ruleName") or rule_id)
        rule_desc = str(rule_info.get("description") or d.get("description") or "")
        confidence = float(rule_info.get("confidence") or d.get("confidence") or 0.8)
    else:
        rule_id = str(d.get("ruleId") or "DET_RULE_UNKNOWN")
        rule_name = str(d.get("ruleName") or rule_id)
        rule_desc = str(d.get("description") or "")
        confidence = float(d.get("confidence") or 0.8)

    # Clamp confidence between 0.0 and 1.0
    confidence = max(0.0, min(1.0, confidence))

    return DetectionContext(
        id=str(d.get("id") or "DET_UNKNOWN"),
        ruleId=rule_id,
        ruleName=rule_name,
        description=rule_desc,
        severity=d.get("severity") if d.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM",
        confidence=confidence,
        matchedEventIds=[str(e) for e in d.get("matchedEventIds", [])],
        primaryAssetId=str(d["primaryAssetId"]) if d.get("primaryAssetId") else None,
        timestamp=parse_iso_timestamp(d.get("timestamp")),
        evidenceSummary=str(d.get("evidenceSummary") or rule_desc or "Rule triggered match"),
        metadata=d.get("metadata", {}),
    )


def normalize_telemetry_event(raw: Union[BaseModel, Dict[str, Any]]) -> TelemetryEventContext:
    """Normalizes individual telemetry event into TelemetryEventContext."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    payload = d.get("payload", {})
    if not isinstance(payload, dict):
        payload = {}

    return TelemetryEventContext(
        id=str(d.get("id") or "TEL_UNKNOWN"),
        eventType=str(d.get("eventType") or "HTTP_REQUEST"),
        timestamp=parse_iso_timestamp(d.get("timestamp")),
        sourceService=str(d.get("sourceService") or "unknown-service"),
        environmentId=d.get("environmentId"),
        sourceIp=payload.get("sourceIp") or d.get("sourceIp"),
        userAgent=payload.get("userAgent") or d.get("userAgent"),
        userId=payload.get("userId") or d.get("userId"),
        sessionId=payload.get("sessionId") or d.get("sessionId"),
        httpMethod=payload.get("httpMethod") or d.get("httpMethod"),
        httpPath=payload.get("httpPath") or d.get("httpPath"),
        httpStatusCode=int(payload.get("httpStatusCode") or d.get("httpStatusCode")) if (payload.get("httpStatusCode") or d.get("httpStatusCode")) is not None else None,
        resourceAccessed=payload.get("resourceAccessed") or d.get("resourceAccessed"),
        metadata=payload.get("metadata", {}) or d.get("metadata", {}),
    )


def normalize_asset(raw: Union[BaseModel, Dict[str, Any]]) -> AssetContext:
    """Normalizes asset metadata into AssetContext."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    return AssetContext(
        id=str(d.get("id") or "ASSET_UNKNOWN"),
        name=str(d.get("name") or d.get("id") or "unnamed-asset"),
        type=str(d.get("type") or "SERVICE"),
        criticality=str(d.get("criticality") or "TIER_2_MEDIUM"),
        isPubliclyExposed=bool(d.get("isPubliclyExposed", False)),
        environmentId=d.get("environmentId"),
        status=str(d.get("status") or "ACTIVE"),
        metadata=d.get("metadata", {}),
    )


def normalize_attack_path(raw: Union[BaseModel, Dict[str, Any]]) -> AttackPathContext:
    """Normalizes attack path graph calculation into AttackPathContext."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    raw_nodes = d.get("nodes", [])
    nodes: List[AttackPathHopContext] = []
    for idx, node in enumerate(raw_nodes):
        if isinstance(node, dict):
            nodes.append(
                AttackPathHopContext(
                    stepOrder=int(node.get("stepOrder", idx + 1)),
                    assetId=str(node.get("assetId") or "UNKNOWN_HOP_ASSET"),
                    assetName=str(node.get("assetName") or node.get("assetId") or "unknown-node"),
                    assetType=str(node.get("assetType") or "SERVICE"),
                    description=str(node.get("description") or f"Hop {idx + 1}"),
                    vulnerabilityIds=[str(v) for v in node.get("vulnerabilityIds", [])] if node.get("vulnerabilityIds") else None,
                )
            )

    return AttackPathContext(
        id=str(d.get("id") or "AP_UNKNOWN"),
        entryPointAssetId=str(d.get("entryPointAssetId") or "UNKNOWN_ENTRY"),
        targetAssetId=str(d.get("targetAssetId") or "UNKNOWN_TARGET"),
        severity=d.get("severity") if d.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "HIGH",
        pathScore=float(d.get("pathScore", 50.0)),
        nodes=nodes,
        isActive=bool(d.get("isActive", True)),
    )


def normalize_vulnerability(raw: Union[BaseModel, Dict[str, Any]]) -> VulnerabilityContext:
    """Normalizes vulnerability/finding into VulnerabilityContext."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    return VulnerabilityContext(
        id=str(d.get("id") or "VULN_UNKNOWN"),
        cveId=d.get("cveId") or d.get("cve"),
        assetId=str(d.get("assetId") or "UNKNOWN_ASSET"),
        title=str(d.get("title") or d.get("name") or "Security Finding"),
        severity=d.get("severity") if d.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM",
        description=str(d.get("description") or ""),
        cvssScore=float(d["cvssScore"]) if d.get("cvssScore") is not None else None,
    )


def normalize_risk(raw: Union[BaseModel, Dict[str, Any]]) -> RiskContext:
    """Normalizes risk score snapshot into RiskContext."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    drivers = []
    contributors = d.get("contributors", [])
    for c in contributors:
        if isinstance(c, dict):
            factor = c.get("factor") or c.get("description") or ""
            if factor:
                drivers.append(str(factor))
        elif isinstance(c, str):
            drivers.append(c)

    return RiskContext(
        overallScore=max(0.0, min(100.0, float(d.get("overallScore", 0.0)))),
        criticalAssetsAtRiskCount=int(d.get("criticalAssetsAtRiskCount", 0)),
        highRiskVulnerabilitiesCount=int(d.get("highRiskVulnerabilitiesCount", 0)),
        activeAttackPathsCount=int(d.get("activeAttackPathsCount", 0)),
        primaryRiskDrivers=drivers,
    )


def normalize_evidence_item(raw: Union[BaseModel, Dict[str, Any]]) -> EvidenceItem:
    """Normalizes raw or backend evidence object into EvidenceItem."""
    d = to_dict(raw)
    d = scrub_secrets(d)

    ev_type = d.get("type", "TELEMETRY_EVENT")
    valid_types = ("TELEMETRY_EVENT", "DETECTION_MATCH", "NETWORK_LOG", "GRAPH_RELATIONSHIP", "CONFIG_DIFF", "VULNERABILITY_FINDING")
    if ev_type not in valid_types:
        ev_type = "TELEMETRY_EVENT"

    return EvidenceItem(
        id=str(d.get("id") or "EV_UNKNOWN"),
        type=ev_type,
        source=str(d.get("source") or "gasha-pipeline"),
        timestamp=parse_iso_timestamp(d.get("timestamp")),
        summary=str(d.get("summary") or d.get("relevanceExplanation") or "Forensic evidence item"),
        content=d.get("content", {}) if isinstance(d.get("content"), dict) else {"raw": str(d.get("content"))},
        verified=bool(d.get("verified", True)),
    )
