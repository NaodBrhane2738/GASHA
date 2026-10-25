"""
==============================================================================
FILE: apps/api/app/core/events.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: In-process publish/subscribe bus that keeps the event logger, enforcement
           middleware, incident tracker, notifier and SOC dashboard stream in sync.
TOOLS & LIBRARIES: asyncio
KEY FEATURES:
  - Synchronous handlers for cheap in-memory state updates (run inline, in order).
  - Bounded asyncio.Queue subscriptions for slow consumers (SSE clients); a full queue
    drops its oldest event instead of applying back-pressure to request handling.
EXPECTED RESULTS / BEHAVIOR:
  - A component failing never breaks publishing for the others.
  - Swappable for Redis pub/sub when the API runs with more than one worker.
==============================================================================
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set

from app.schemas.soc import SocEvent

logger = logging.getLogger("gasha.events")

Handler = Callable[[SocEvent], None]


def utc_iso(epoch: Optional[float] = None) -> str:
    t = time.time() if epoch is None else epoch
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}Z"


class EventBus:
    def __init__(self, queue_size: int = 256):
        self._handlers: Dict[str, List[Handler]] = {}
        self._queues: Set[asyncio.Queue] = set()
        self._queue_size = queue_size

    def on(self, event_type: str, handler: Handler) -> None:
        """Register a sync handler. Use "*" to receive every event."""
        self._handlers.setdefault(event_type, []).append(handler)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        self._queues.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._queues.discard(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._queues)

    def publish(self, event_type: str, data: Dict[str, Any]) -> SocEvent:
        event = SocEvent(id=f"evt-{uuid.uuid4().hex[:12]}", type=event_type, ts=utc_iso(), data=data)

        for handler in self._handlers.get(event_type, []) + self._handlers.get("*", []):
            try:
                handler(event)
            except Exception:
                logger.exception("Event handler failed for %s", event_type)

        for q in list(self._queues):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(event)
        return event
