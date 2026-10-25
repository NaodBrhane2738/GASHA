"""
==============================================================================
FILE: apps/api/app/notifications/dispatcher.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Turns high-severity policy enforcement events into analyst email alerts.
KEY FEATURES:
  - Subscribes to `policy.enforced` on the event bus; never blocks request handling.
  - Severity floor + per-(source, rule) cooldown so an attack produces one alert, not thousands.
  - Bounded queue, retry with exponential backoff, outcome published back to the bus.
  - All attacker-controlled values are HTML-escaped and stripped of CR/LF before rendering.
==============================================================================
"""

import asyncio
import html
import logging
import time
from typing import Callable, Dict, List, Optional, Tuple

from app.core.events import EventBus
from app.notifications.transports import EmailAlert, EmailTransport
from app.schemas.soc import SEVERITY_RANK, SocEvent

logger = logging.getLogger("gasha.notifications")


def _one_line(value: object, limit: int = 200) -> str:
    return " ".join(str(value).split())[:limit]


class AlertDispatcher:
    def __init__(self, bus: EventBus, transport: EmailTransport, sender: str, recipients: List[str],
                 min_severity: str = "HIGH", cooldown_seconds: int = 300, dashboard_url: str = "",
                 max_attempts: int = 3, queue_size: int = 100,
                 clock: Callable[[], float] = time.monotonic):
        self.bus = bus
        self.transport = transport
        self.sender = sender
        self.recipients = recipients
        self.min_rank = SEVERITY_RANK[min_severity]
        self.cooldown = cooldown_seconds
        self.dashboard_url = dashboard_url.rstrip("/")
        self.max_attempts = max_attempts
        self._clock = clock
        self._last_sent: Dict[Tuple[str, str], float] = {}
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._task: Optional[asyncio.Task] = None
        bus.on("policy.enforced", self._on_enforced)

    # -------------------------------------------------------------- filtering
    def should_alert(self, source: str, rule_id: str, severity: str) -> bool:
        if not self.recipients or SEVERITY_RANK.get(severity, 0) < self.min_rank:
            return False
        key = (source, rule_id)
        now = self._clock()
        last = self._last_sent.get(key)
        if last is not None and now - last < self.cooldown:
            return False
        self._last_sent[key] = now
        return True

    def _on_enforced(self, event: SocEvent) -> None:
        m = event.data.get("mitigation") or {}
        if not self.should_alert(m.get("sourceKey", ""), m.get("ruleId", ""), m.get("severity", "LOW")):
            return
        try:
            self._queue.put_nowait(self.render(event.data))
        except asyncio.QueueFull:
            logger.error("Alert queue full; dropping alert for %s", m.get("sourceKey"))

    # -------------------------------------------------------------- rendering
    def render(self, data: dict) -> EmailAlert:
        m = data.get("mitigation", {})
        inc = data.get("incident") or {}
        findings = data.get("findings") or []
        code = 423 if m.get("action") == "LOCK" else 429
        source = _one_line(m.get("sourceKey", "unknown"), 80)
        subject = f"[GASHA {m.get('severity', '')}] {m.get('action', '')} {source} — {_one_line(m.get('ruleId', ''), 40)}"

        rows = [
            ("Source", source),
            ("Action", f"{m.get('action')} (HTTP {code})"),
            ("Rule", m.get("ruleId", "")),
            ("Reason", m.get("reason", "")),
            ("Expires", m.get("expiresAt", "")),
            ("Incident", inc.get("id", "")),
        ]
        for f in findings[:5]:
            rows.append(("Finding", f"{f.get('category')} in {f.get('location')}"
                                    f"{' (' + f['field'] + ')' if f.get('field') else ''}: {f.get('evidence') or ''}"))

        link = f"{self.dashboard_url}/soc?incident={inc.get('id', '')}" if self.dashboard_url and inc.get("id") else ""
        text = "\n".join(f"{k}: {_one_line(v, 300)}" for k, v in rows) + (f"\n\nOpen in SOC: {link}" if link else "")
        table = "".join(
            f"<tr><td style='padding:4px 12px 4px 0;color:#666'>{html.escape(k)}</td>"
            f"<td style='padding:4px 0;font-family:monospace'>{html.escape(_one_line(v, 300))}</td></tr>"
            for k, v in rows
        )
        body = (f"<h2 style='font-family:sans-serif'>GASHA protective action triggered</h2>"
                f"<table style='font-family:sans-serif;font-size:13px'>{table}</table>")
        if link:
            body += f"<p><a href='{html.escape(link, quote=True)}'>Open incident in SOC dashboard</a></p>"
        return EmailAlert(subject=subject, text=text, html=body, recipients=self.recipients, sender=self.sender)

    # -------------------------------------------------------------- delivery
    async def _deliver(self, alert: EmailAlert) -> None:
        delay = 1.0
        for attempt in range(1, self.max_attempts + 1):
            try:
                msg_id = await self.transport.send(alert)
                self.bus.publish("alert.dispatched", {"subject": alert.subject, "provider": self.transport.name,
                                                      "recipients": len(alert.recipients), "messageId": msg_id})
                return
            except Exception as exc:
                logger.warning("Alert delivery attempt %d/%d failed: %s", attempt, self.max_attempts, exc)
                if attempt == self.max_attempts:
                    self.bus.publish("alert.failed", {"subject": alert.subject, "provider": self.transport.name,
                                                      "error": type(exc).__name__})
                    return
                await asyncio.sleep(delay)
                delay *= 2

    async def _run(self) -> None:
        while True:
            alert = await self._queue.get()
            try:
                await self._deliver(alert)
            finally:
                self._queue.task_done()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="gasha-alert-dispatcher")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def drain(self) -> None:
        await self._queue.join()
