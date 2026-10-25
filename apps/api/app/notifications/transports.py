"""
==============================================================================
FILE: apps/api/app/notifications/transports.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Pluggable email delivery for SOC alerts.
TOOLS & LIBRARIES: smtplib + email.message (stdlib), httpx (Resend HTTP API)
KEY FEATURES:
  - SmtpTransport: STARTTLS or implicit TLS, runs the blocking client in a worker thread.
  - ResendTransport: POST https://api.resend.com/emails with a bearer API key.
  - LogTransport: development default; writes the alert to the log instead of sending.
==============================================================================
"""

import asyncio
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import List, Optional, Protocol

logger = logging.getLogger("gasha.notifications")


@dataclass(frozen=True)
class EmailAlert:
    subject: str
    text: str
    html: str
    recipients: List[str]
    sender: str


class EmailTransport(Protocol):
    name: str

    async def send(self, alert: EmailAlert) -> Optional[str]:
        """Deliver the alert; return a provider message id if one is available."""


class LogTransport:
    name = "log"

    async def send(self, alert: EmailAlert) -> Optional[str]:
        logger.warning("[ALERT dry-run] to=%s subject=%s\n%s", ",".join(alert.recipients), alert.subject, alert.text)
        return None


class SmtpTransport:
    name = "smtp"

    def __init__(self, host: str, port: int, username: str = "", password: str = "",
                 use_tls: bool = True, use_ssl: bool = False, timeout: float = 10.0):
        self.host, self.port = host, port
        self.username, self.password = username, password
        self.use_tls, self.use_ssl = use_tls, use_ssl
        self.timeout = timeout

    def _send_blocking(self, alert: EmailAlert) -> None:
        msg = EmailMessage()
        msg["Subject"] = alert.subject
        msg["From"] = alert.sender
        msg["To"] = ", ".join(alert.recipients)
        msg.set_content(alert.text)
        msg.add_alternative(alert.html, subtype="html")

        ctx = ssl.create_default_context()
        if self.use_ssl:
            client = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            client = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        with client:
            if self.use_tls and not self.use_ssl:
                client.starttls(context=ctx)
            if self.username:
                client.login(self.username, self.password)
            client.send_message(msg)

    async def send(self, alert: EmailAlert) -> Optional[str]:
        await asyncio.to_thread(self._send_blocking, alert)
        return None


class ResendTransport:
    name = "resend"

    def __init__(self, api_key: str, api_url: str = "https://api.resend.com/emails", timeout: float = 10.0):
        if not api_key:
            raise ValueError("RESEND_API_KEY is required for the resend alert provider")
        self.api_key, self.api_url, self.timeout = api_key, api_url, timeout

    async def send(self, alert: EmailAlert) -> Optional[str]:
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            res = await client.post(
                self.api_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"from": alert.sender, "to": alert.recipients, "subject": alert.subject,
                      "text": alert.text, "html": alert.html},
            )
            res.raise_for_status()
            return res.json().get("id")
