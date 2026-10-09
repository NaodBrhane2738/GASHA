"""
==============================================================================
FILE: apps/api/app/detection/engine.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Deterministic rule evaluation engine for normalized telemetry streams.
           Evaluates Rule A (Brute Force), Rule B (Web Probes), Rule C (Endpoint Scan),
           and Rule D (Privilege Mutation) with sliding time-window tracking.
==============================================================================
"""

import time
import re
import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from app.schemas.telemetry import TelemetryEventSchema
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.detection.rules.catalog import (
    BRUTE_FORCE_AUTH_RULE,
    SUSPICIOUS_PROBE_RULE,
    SENSITIVE_ENDPOINT_PROBE_RULE,
    PRIVILEGE_ESCALATION_RULE,
    ALL_RULES,
    RULES_BY_ID,
)

logger = logging.getLogger("gasha.detection.engine")

SENSITIVE_ENDPOINT_PATTERN = re.compile(
    r"^/(admin|\.env|actuator|api/v1/auth/keys|\.git|config|backup|aws|secrets|v1/admin)",
    re.IGNORECASE
)

ELEVATED_ROLES = {"admin", "root", "superuser", "security_admin", "administrator"}


class SlidingEventTracker:
    """Tracks historical events per grouping key within configurable time windows."""
    def __init__(self):
        # key -> list of {"timestamp": float, "event_id": str, "data": dict}
        self._windows: Dict[str, List[Dict[str, Any]]] = {}
        # key -> float timestamp of last fired detection (to enforce cooldowns)
        self._last_fired: Dict[str, float] = {}

    def record_and_get_window(
        self,
        group_key: str,
        event_id: str,
        window_seconds: float,
        extra_data: Optional[Dict[str, Any]] = None,
        event_time: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        now = event_time if event_time is not None else time.time()
        entries = self._windows.get(group_key, [])
        # Prune older than window_seconds
        valid_entries = [e for e in entries if (now - e["timestamp"]) <= window_seconds]
        valid_entries.append({
            "timestamp": now,
            "event_id": event_id,
            "data": extra_data or {}
        })
        self._windows[group_key] = valid_entries
        return valid_entries

    def is_in_cooldown(self, group_key: str, cooldown_seconds: float) -> bool:
        last = self._last_fired.get(group_key)
        if last is None:
            return False
        return (time.time() - last) < cooldown_seconds

    def mark_fired(self, group_key: str):
        self._last_fired[group_key] = time.time()

    def clear(self):
        self._windows.clear()
        self._last_fired.clear()


class DetectionEngine:
    """
    Deterministic detection engine.
    Processes validated, normalized telemetry events and produces structured detection findings.
    Zero external AI or OSINT dependencies.
    """
    def __init__(self):
        self.tracker = SlidingEventTracker()

    def evaluate_event(self, event: TelemetryEventSchema) -> List[DetectionEventResponse]:
        """
        Evaluates all applicable deterministic rules against an incoming telemetry event.
        Returns a list of triggered DetectionEventResponse findings.
        """
        detections: List[DetectionEventResponse] = []

        # 1. Evaluate Rule A — Brute Force Authentication (RULE-AUTH-001)
        det_a = self._eval_brute_force(event)
        if det_a:
            detections.append(det_a)

        # 2. Evaluate Rule B — Suspicious Web Request / Injection (RULE-INJ-002)
        det_b = self._eval_suspicious_probe(event)
        if det_b:
            detections.append(det_b)

        # 3. Evaluate Rule C — Sensitive Endpoint Probing (RULE-PROBE-003)
        det_c = self._eval_sensitive_endpoint_probing(event)
        if det_c:
            detections.append(det_c)

        # 4. Evaluate Rule D — Privilege-Related Event (RULE-PRIV-004)
        det_d = self._eval_privilege_escalation(event)
        if det_d:
            detections.append(det_d)

        return detections

    def _eval_brute_force(self, event: TelemetryEventSchema) -> Optional[DetectionEventResponse]:
        if event.eventType != "AUTH_FAILURE":
            return None

        source_ip = event.payload.sourceIp or "unknown"
        user_id = event.payload.userId or "unspecified_user"
        env_id = event.environmentId

        # Grouping key strictly bound to environment and source
        group_key = f"auth_fail:{env_id}:{source_ip}"
        window_events = self.tracker.record_and_get_window(
            group_key=group_key,
            event_id=event.id,
            window_seconds=BRUTE_FORCE_AUTH_RULE.time_window_seconds
        )

        count = len(window_events)
        if count >= BRUTE_FORCE_AUTH_RULE.threshold_count:
            # Check cooldown to prevent duplicate alert storms within same active window
            if not self.tracker.is_in_cooldown(group_key, BRUTE_FORCE_AUTH_RULE.time_window_seconds / 2):
                self.tracker.mark_fired(group_key)
                matched_ids = [e["event_id"] for e in window_events]
                primary_asset = f"asset:auth-service:{env_id}"

                evidence = (
                    f"Observed {count} failed authentication attempts for target account '{user_id}' "
                    f"originating from source IP '{source_ip}' within {BRUTE_FORCE_AUTH_RULE.time_window_seconds}s window."
                )

                return DetectionEventResponse(
                    id=f"det-{uuid.uuid4().hex[:10]}",
                    environmentId=env_id,
                    rule=DetectionRuleSummarySchema(
                        ruleId=BRUTE_FORCE_AUTH_RULE.id,
                        name=BRUTE_FORCE_AUTH_RULE.name,
                        description=BRUTE_FORCE_AUTH_RULE.description,
                        severity=BRUTE_FORCE_AUTH_RULE.severity,
                        confidence=BRUTE_FORCE_AUTH_RULE.confidence
                    ),
                    matchedEventIds=matched_ids,
                    primaryAssetId=primary_asset,
                    timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    severity=BRUTE_FORCE_AUTH_RULE.severity,
                    confidence=BRUTE_FORCE_AUTH_RULE.confidence,
                    evidenceSummary=evidence,
                    metadata={
                        "environmentId": env_id,
                        "sourceIp": source_ip,
                        "userId": user_id,
                        "attemptCount": count,
                        "mitreTechniqueId": BRUTE_FORCE_AUTH_RULE.mitre_technique_id,
                    }
                )
        return None

    def _eval_suspicious_probe(self, event: TelemetryEventSchema) -> Optional[DetectionEventResponse]:
        # Triggers on explicit SUSPICIOUS_REQUEST or HTTP_REQUEST tagged with suspicious probe metadata
        is_suspicious_event = event.eventType == "SUSPICIOUS_REQUEST"
        meta = event.payload.metadata or {}
        has_probe_tag = bool(meta.get("pattern_type") or meta.get("suspicious_tags"))

        if not (is_suspicious_event or has_probe_tag):
            return None

        probe_type = meta.get("pattern_type") or (meta.get("suspicious_tags")[0] if meta.get("suspicious_tags") else "INJECTION_PROBE")
        source_ip = event.payload.sourceIp or "unknown"
        target_path = event.payload.httpPath or "/"
        env_id = event.environmentId
        primary_asset = f"asset:web-service:{env_id}"

        evidence = (
            f"Observed passive attack pattern indicator [{probe_type}] targeting path '{target_path}' "
            f"originating from source IP '{source_ip}'."
        )

        return DetectionEventResponse(
            id=f"det-{uuid.uuid4().hex[:10]}",
            environmentId=env_id,
            rule=DetectionRuleSummarySchema(
                ruleId=SUSPICIOUS_PROBE_RULE.id,
                name=SUSPICIOUS_PROBE_RULE.name,
                description=SUSPICIOUS_PROBE_RULE.description,
                severity=SUSPICIOUS_PROBE_RULE.severity,
                confidence=SUSPICIOUS_PROBE_RULE.confidence
            ),
            matchedEventIds=[event.id],
            primaryAssetId=primary_asset,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            severity=SUSPICIOUS_PROBE_RULE.severity,
            confidence=SUSPICIOUS_PROBE_RULE.confidence,
            evidenceSummary=evidence,
            metadata={
                "environmentId": env_id,
                "sourceIp": source_ip,
                "targetPath": target_path,
                "patternType": probe_type,
                "mitreTechniqueId": SUSPICIOUS_PROBE_RULE.mitre_technique_id,
            }
        )

    def _eval_sensitive_endpoint_probing(self, event: TelemetryEventSchema) -> Optional[DetectionEventResponse]:
        if event.eventType != "HTTP_REQUEST":
            return None

        path = event.payload.httpPath or ""
        status_code = event.payload.httpStatusCode or 200

        # Must target a sensitive endpoint and result in denied or not found status (401, 403, 404)
        if not (SENSITIVE_ENDPOINT_PATTERN.search(path) and status_code in (401, 403, 404)):
            return None

        source_ip = event.payload.sourceIp or "unknown"
        env_id = event.environmentId
        group_key = f"endpoint_probe:{env_id}:{source_ip}"

        window_events = self.tracker.record_and_get_window(
            group_key=group_key,
            event_id=event.id,
            window_seconds=SENSITIVE_ENDPOINT_PROBE_RULE.time_window_seconds
        )

        count = len(window_events)
        if count >= SENSITIVE_ENDPOINT_PROBE_RULE.threshold_count:
            if not self.tracker.is_in_cooldown(group_key, SENSITIVE_ENDPOINT_PROBE_RULE.time_window_seconds / 2):
                self.tracker.mark_fired(group_key)
                matched_ids = [e["event_id"] for e in window_events]
                primary_asset = f"asset:web-service:{env_id}"

                evidence = (
                    f"Observed repeated scanning / reconnaissance ({count} probing attempts) against sensitive "
                    f"protected endpoints from source IP '{source_ip}' within {SENSITIVE_ENDPOINT_PROBE_RULE.time_window_seconds}s."
                )

                return DetectionEventResponse(
                    id=f"det-{uuid.uuid4().hex[:10]}",
                    environmentId=env_id,
                    rule=DetectionRuleSummarySchema(
                        ruleId=SENSITIVE_ENDPOINT_PROBE_RULE.id,
                        name=SENSITIVE_ENDPOINT_PROBE_RULE.name,
                        description=SENSITIVE_ENDPOINT_PROBE_RULE.description,
                        severity=SENSITIVE_ENDPOINT_PROBE_RULE.severity,
                        confidence=SENSITIVE_ENDPOINT_PROBE_RULE.confidence
                    ),
                    matchedEventIds=matched_ids,
                    primaryAssetId=primary_asset,
                    timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    severity=SENSITIVE_ENDPOINT_PROBE_RULE.severity,
                    confidence=SENSITIVE_ENDPOINT_PROBE_RULE.confidence,
                    evidenceSummary=evidence,
                    metadata={
                        "environmentId": env_id,
                        "sourceIp": source_ip,
                        "scanCount": count,
                        "lastScannedPath": path,
                        "mitreTechniqueId": SENSITIVE_ENDPOINT_PROBE_RULE.mitre_technique_id,
                    }
                )
        return None

    def _eval_privilege_escalation(self, event: TelemetryEventSchema) -> Optional[DetectionEventResponse]:
        if event.eventType != "PRIVILEGE_CHANGE":
            return None

        meta = event.payload.metadata or {}
        new_role = (meta.get("new_role") or "").lower()
        old_role = (meta.get("old_role") or "viewer").lower()
        outcome = (event.payload.outcome or "UPDATED").upper()
        user_id = event.payload.userId or "unknown"
        source_ip = event.payload.sourceIp or "unknown"
        env_id = event.environmentId

        is_elevated = new_role in ELEVATED_ROLES
        is_denied_attempt = outcome in ("DENIED", "FAILED", "BLOCKED")

        if not (is_elevated or is_denied_attempt):
            return None

        primary_asset = f"asset:iam-service:{env_id}"
        if is_denied_attempt:
            evidence = (
                f"Unauthorized privilege escalation attempt detected: user '{user_id}' requested role '{new_role}', "
                f"action was DENIED from IP '{source_ip}'."
            )
        else:
            evidence = (
                f"High-privilege role mutation observed: user '{user_id}' elevated from '{old_role}' to '{new_role}' "
                f"from IP '{source_ip}'."
            )

        return DetectionEventResponse(
            id=f"det-{uuid.uuid4().hex[:10]}",
            environmentId=env_id,
            rule=DetectionRuleSummarySchema(
                ruleId=PRIVILEGE_ESCALATION_RULE.id,
                name=PRIVILEGE_ESCALATION_RULE.name,
                description=PRIVILEGE_ESCALATION_RULE.description,
                severity=PRIVILEGE_ESCALATION_RULE.severity,
                confidence=PRIVILEGE_ESCALATION_RULE.confidence
            ),
            matchedEventIds=[event.id],
            primaryAssetId=primary_asset,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            severity=PRIVILEGE_ESCALATION_RULE.severity,
            confidence=PRIVILEGE_ESCALATION_RULE.confidence,
            evidenceSummary=evidence,
            metadata={
                "environmentId": env_id,
                "sourceIp": source_ip,
                "userId": user_id,
                "oldRole": old_role,
                "newRole": new_role,
                "outcome": outcome,
                "mitreTechniqueId": PRIVILEGE_ESCALATION_RULE.mitre_technique_id,
            }
        )

    def reset_state(self):
        """Resets sliding window tracker for test isolation."""
        self.tracker.clear()


# Global singleton engine instance
_default_engine: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    global _default_engine
    if _default_engine is None:
        _default_engine = DetectionEngine()
    return _default_engine
