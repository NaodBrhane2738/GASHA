"""
==============================================================================
FILE: apps/api/app/detection/rate_window.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Sliding-window event counter keyed by source (IP, session, user).
TOOLS & LIBRARIES: collections.deque
EXPECTED RESULTS / BEHAVIOR:
  - O(1) amortised hit(); exact counts over the trailing window, no fixed-bucket bursts.
  - Idle keys are evicted by prune() so memory stays bounded under IP rotation.
==============================================================================
"""

import time
from collections import deque
from typing import Callable, Deque, Dict, List, Tuple


class SlidingWindowCounter:
    def __init__(self, window_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.window = window_seconds
        self._clock = clock
        self._hits: Dict[str, Deque[float]] = {}

    def _trim(self, key: str, now: float) -> Deque[float]:
        q = self._hits.setdefault(key, deque())
        cutoff = now - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        return q

    def hit(self, key: str) -> int:
        now = self._clock()
        q = self._trim(key, now)
        q.append(now)
        return len(q)

    def count(self, key: str) -> int:
        return len(self._trim(key, self._clock()))

    def seconds_until_below(self, key: str, limit: int) -> int:
        """Seconds until the window holds fewer than `limit` hits (for Retry-After)."""
        now = self._clock()
        q = self._trim(key, now)
        if len(q) < limit:
            return 0
        # The hit that must expire is the (len - limit + 1)-th oldest.
        oldest_needed = q[len(q) - limit]
        return max(1, int(oldest_needed + self.window - now + 0.999))

    def top(self, n: int = 5) -> List[Tuple[str, int]]:
        now = self._clock()
        counts = [(k, len(self._trim(k, now))) for k in list(self._hits)]
        return sorted((c for c in counts if c[1]), key=lambda c: c[1], reverse=True)[:n]

    def prune(self) -> None:
        now = self._clock()
        for key in list(self._hits):
            if not self._trim(key, now):
                del self._hits[key]
