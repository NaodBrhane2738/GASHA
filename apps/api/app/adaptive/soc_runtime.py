"""
==============================================================================
FILE: apps/api/app/adaptive/soc_runtime.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Composition root for the SOC monitoring components. Builds the event bus, policy
           engine, incident tracker, metrics store, pipeline and alert dispatcher from Settings
           and manages their background tasks.
==============================================================================
"""

from dataclasses import dataclass

from app.adaptive.incidents import IncidentTracker
from app.adaptive.soc_pipeline import SocPipeline
from app.core.config import Settings
from app.core.events import EventBus
from app.notifications.dispatcher import AlertDispatcher
from app.notifications.transports import EmailTransport, LogTransport, ResendTransport, SmtpTransport
from app.response.policy import PolicyConfig, PolicyEngine
from app.telemetry.metrics import MetricsStore


def build_transport(s: Settings) -> EmailTransport:
    provider = s.ALERT_EMAIL_PROVIDER.lower()
    if provider == "smtp":
        return SmtpTransport(s.SMTP_HOST, s.SMTP_PORT, s.SMTP_USERNAME, s.SMTP_PASSWORD,
                             use_tls=s.SMTP_USE_TLS, use_ssl=s.SMTP_USE_SSL)
    if provider == "resend":
        return ResendTransport(s.RESEND_API_KEY, s.RESEND_API_URL)
    return LogTransport()


@dataclass
class SocRuntime:
    bus: EventBus
    pipeline: SocPipeline
    alerts: AlertDispatcher

    @classmethod
    def from_settings(cls, s: Settings) -> "SocRuntime":
        bus = EventBus()
        policy = PolicyEngine(PolicyConfig(
            rate_limit=s.SOC_RATE_LIMIT_REQUESTS,
            rate_window_seconds=s.SOC_RATE_LIMIT_WINDOW_SECONDS,
            escalation_count=s.SOC_ESCALATION_COUNT,
            escalation_window_seconds=s.SOC_ESCALATION_WINDOW_SECONDS,
            lock_duration_seconds=s.SOC_LOCK_DURATION_SECONDS,
            lock_on_severity=s.SOC_LOCK_ON_SEVERITY,
            auth_failure_limit=s.SOC_AUTH_FAILURE_LIMIT,
            auth_failure_window_seconds=s.SOC_AUTH_FAILURE_WINDOW_SECONDS,
        ))
        pipeline = SocPipeline(bus, policy, IncidentTracker(), MetricsStore(), max_body_bytes=s.SOC_MAX_BODY_BYTES)
        alerts = AlertDispatcher(
            bus, build_transport(s), sender=s.ALERT_EMAIL_FROM, recipients=s.ALERT_EMAIL_TO,
            min_severity=s.ALERT_MIN_SEVERITY, cooldown_seconds=s.ALERT_COOLDOWN_SECONDS, dashboard_url=s.WEB_URL,
        )
        return cls(bus=bus, pipeline=pipeline, alerts=alerts)

    async def start(self) -> None:
        self.pipeline.start()
        self.alerts.start()

    async def stop(self) -> None:
        await self.alerts.stop()
        await self.pipeline.stop()
