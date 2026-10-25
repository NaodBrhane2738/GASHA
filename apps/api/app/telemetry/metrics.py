"""
==============================================================================
FILE: apps/api/app/telemetry/metrics.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Per-second request/decision counters for the SOC telemetry charts.
EXPECTED RESULTS / BEHAVIOR:
  - Fixed-size ring of 1-second buckets (default 10 minutes); constant memory.
  - Seconds with no traffic are rendered as zero-filled buckets.
==============================================================================
"""

import time
from typing import Callable, Dict, List

from app.core.events import utc_iso
from app.schemas.soc import MetricsBucket

_ACTION_FIELD = {"ALLOW": "allowed", "FLAG": "flagged", "THROTTLE": "throttled", "LOCK": "locked", "REJECT": "rejected"}


class MetricsStore:
    def __init__(self, retention_seconds: int = 600, clock: Callable[[], float] = time.time):
        self.retention = retention_seconds
        self._clock = clock
        self._buckets: Dict[int, Dict[str, int]] = {}
        self.totals: Dict[str, int] = {"total": 0, "allowed": 0, "flagged": 0, "throttled": 0, "locked": 0, "rejected": 0}

    def _bucket(self, sec: int) -> Dict[str, int]:
        b = self._buckets.get(sec)
        if b is None:
            b = self._buckets[sec] = {k: 0 for k in self.totals} | {"peakSourceRate": 0}
            cutoff = sec - self.retention
            for old in [s for s in self._buckets if s <= cutoff]:
                del self._buckets[old]
        return b

    def record(self, action: str, source_rate: int = 0) -> None:
        b = self._bucket(int(self._clock()))
        field = _ACTION_FIELD[action]
        b["total"] += 1
        b[field] += 1
        b["peakSourceRate"] = max(b["peakSourceRate"], source_rate)
        self.totals["total"] += 1
        self.totals[field] += 1

    def series(self, window_seconds: int = 300) -> List[MetricsBucket]:
        now = int(self._clock())
        window = min(window_seconds, self.retention)
        out = []
        for sec in range(now - window + 1, now + 1):
            b = self._buckets.get(sec)
            out.append(MetricsBucket(ts=utc_iso(sec), **b) if b else MetricsBucket(ts=utc_iso(sec)))
        return out

    def current(self) -> MetricsBucket:
        return self.series(1)[0]
