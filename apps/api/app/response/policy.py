"""
==============================================================================
FILE: apps/api/app/response/policy.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Deterministic policy enforcement. Turns request rate + detection findings into a
           defensive decision and owns the active mitigation table.
KEY FEATURES:
  - Per-source sliding-window rate limit       -> THROTTLE (HTTP 429 + Retry-After)
  - Repeated throttle episodes / brute force   -> LOCK     (HTTP 423 Locked)
  - Findings at or above the lock severity     -> LOCK
  - Lower-severity findings                    -> FLAG (request allowed, analyst notified)
EXPECTED RESULTS / BEHAVIOR:
  - No I/O and no event publishing: the pipeline orchestrates side effects. A monotonic clock
    is injected so windows are testable and immune to wall-clock jumps.
==============================================================================
"""

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from app.core.events import utc_iso
from app.detection.rate_window import SlidingWindowCounter
from app.schemas.soc import SEVERITY_RANK, Mitigation, PolicyDecision


@dataclass(frozen=True)
class PolicyConfig:
    rate_limit: int = 60
    rate_window_seconds: int = 60
    escalation_count: int = 3
    escalation_window_seconds: int = 300
    lock_duration_seconds: int = 900
    lock_on_severity: str = "HIGH"
    auth_failure_limit: int = 5
    auth_failure_window_seconds: int = 60


@dataclass
class _ActiveMitigation:
    model: Mitigation
    expires_mono: float


@dataclass
class Evaluation:
    decision: PolicyDecision
    new_mitigation: Optional[Mitigation] = None
    blocked_by: Optional[Mitigation] = None
    expired: List[Mitigation] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, config: PolicyConfig, clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time):
        self.config = config
        self._clock = clock
        self._wall = wall_clock
        self.requests = SlidingWindowCounter(config.rate_window_seconds, clock)
        self._violations = SlidingWindowCounter(config.escalation_window_seconds, clock)
        self._auth_failures = SlidingWindowCounter(config.auth_failure_window_seconds, clock)
        self._active: Dict[str, _ActiveMitigation] = {}

    # ------------------------------------------------------------------ mitigations
    def _mitigate(self, source: str, action: str, rule_id: str, reason: str,
                  severity: str, seconds: int) -> Mitigation:
        now_wall = self._wall()
        m = Mitigation(
            sourceKey=source, action=action, ruleId=rule_id, reason=reason, severity=severity,
            createdAt=utc_iso(now_wall), expiresAt=utc_iso(now_wall + seconds),
        )
        self._active[source] = _ActiveMitigation(m, self._clock() + seconds)
        return m

    def _extend(self, active: _ActiveMitigation, seconds: int) -> None:
        active.expires_mono = self._clock() + seconds
        active.model.expiresAt = utc_iso(self._wall() + seconds)

    def active_mitigations(self) -> List[Mitigation]:
        return [a.model for a in self._active.values()]

    def mitigation_for(self, source: str) -> Optional[Mitigation]:
        a = self._active.get(source)
        return a.model if a else None

    def release(self, source: str) -> Optional[Mitigation]:
        """Analyst override: lift a throttle or lock immediately."""
        a = self._active.pop(source, None)
        return a.model if a else None

    def sweep(self) -> List[Mitigation]:
        now = self._clock()
        expired = [s for s, a in self._active.items() if a.expires_mono <= now]
        out = [self._active.pop(s).model for s in expired]
        self.requests.prune()
        self._violations.prune()
        self._auth_failures.prune()
        return out

    def _remaining(self, a: _ActiveMitigation) -> int:
        return max(1, int(a.expires_mono - self._clock() + 0.999))

    # ------------------------------------------------------------------ decisions
    def _lock(self, source: str, rule_id: str, reason: str, severity: str,
              finding_ids: Sequence[str]) -> Evaluation:
        secs = self.config.lock_duration_seconds
        m = self._mitigate(source, "LOCK", rule_id, reason, severity, secs)
        return Evaluation(
            decision=PolicyDecision(action="LOCK", statusCode=423, ruleId=rule_id, reason=reason,
                                    severity=severity, retryAfterSeconds=secs, sourceKey=source,
                                    findingIds=list(finding_ids)),
            new_mitigation=m,
        )

    def evaluate_request(self, source: str, findings: Sequence[dict] = ()) -> Evaluation:
        """`findings` items carry at least id, severity, ruleId, category."""
        cfg = self.config
        finding_ids = [f["id"] for f in findings]
        active = self._active.get(source)

        if active and active.expires_mono <= self._clock():
            self._active.pop(source, None)
            active = None

        # 1. An existing lock rejects everything until it expires.
        if active and active.model.action == "LOCK":
            active.model.blockedRequests += 1
            return Evaluation(
                decision=PolicyDecision(action="LOCK", statusCode=423, ruleId=active.model.ruleId,
                                        reason=active.model.reason, severity=active.model.severity,
                                        retryAfterSeconds=self._remaining(active), sourceKey=source,
                                        findingIds=finding_ids),
                blocked_by=active.model,
            )

        count = self.requests.hit(source)

        # 2. High-severity content findings lock the source outright.
        worst = max(findings, key=lambda f: SEVERITY_RANK[f["severity"]], default=None)
        if worst and SEVERITY_RANK[worst["severity"]] >= SEVERITY_RANK[cfg.lock_on_severity]:
            return self._lock(source, worst["ruleId"],
                              f"{worst['category'].replace('_', ' ').lower()} detected in request ({worst['ruleId']})",
                              worst["severity"], finding_ids)

        # 3. Rate limit.
        if count > cfg.rate_limit:
            retry = max(1, self.requests.seconds_until_below(source, cfg.rate_limit))
            if active and active.model.action == "THROTTLE":
                active.model.blockedRequests += 1
                self._extend(active, retry)
                return Evaluation(
                    decision=PolicyDecision(action="THROTTLE", statusCode=429, ruleId=active.model.ruleId,
                                            reason=active.model.reason, severity=active.model.severity,
                                            retryAfterSeconds=retry, sourceKey=source, findingIds=finding_ids),
                    blocked_by=active.model,
                )
            episodes = self._violations.hit(source)
            if episodes >= cfg.escalation_count:
                return self._lock(
                    source, "RULE-RATE-002",
                    f"Rate limit violated {episodes}x within {cfg.escalation_window_seconds}s",
                    "HIGH", finding_ids)
            reason = f"{count} requests in {cfg.rate_window_seconds}s exceeds limit of {cfg.rate_limit}"
            m = self._mitigate(source, "THROTTLE", "RULE-RATE-001", reason, "MEDIUM", retry)
            return Evaluation(
                decision=PolicyDecision(action="THROTTLE", statusCode=429, ruleId="RULE-RATE-001",
                                        reason=reason, severity="MEDIUM", retryAfterSeconds=retry,
                                        sourceKey=source, findingIds=finding_ids),
                new_mitigation=m,
            )

        expired: List[Mitigation] = []
        if active and active.model.action == "THROTTLE":
            expired.append(self._active.pop(source).model)

        if findings:
            return Evaluation(
                decision=PolicyDecision(action="FLAG", statusCode=200, ruleId=worst["ruleId"],
                                        reason="Suspicious content flagged for review",
                                        severity=worst["severity"], sourceKey=source, findingIds=finding_ids),
                expired=expired,
            )
        return Evaluation(decision=PolicyDecision(action="ALLOW", sourceKey=source), expired=expired)

    def evaluate_auth_failure(self, source: str) -> Optional[Evaluation]:
        """Brute-force rule (RULE-AUTH-001) fed from AUTH_FAILURE telemetry."""
        if source in self._active and self._active[source].model.action == "LOCK":
            return None
        n = self._auth_failures.hit(source)
        if n < self.config.auth_failure_limit:
            return None
        return self._lock(source, "RULE-AUTH-001",
                          f"{n} failed logins in {self.config.auth_failure_window_seconds}s", "HIGH", [])

    def window_count(self, source: str) -> int:
        return self.requests.count(source)
