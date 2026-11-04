"""Email (SMTP) and Microsoft Teams notifications."""
from __future__ import annotations

import asyncio
import html
import logging
import smtplib
import ssl
from email.message import EmailMessage

import httpx

from .config import AlertsCfg

log = logging.getLogger("netmon.notify")


class Notifier:
    def __init__(self, cfg: AlertsCfg, dashboard_url: str = ""):
        self.cfg = cfg
        self.dashboard_url = dashboard_url

    async def send(self, alarm: dict, ctx: dict, recovered: bool):
        title = ("✅ RECOVERED: " if recovered else "🔴 ALARM: ") + alarm["message"]
        jobs = []
        if self.cfg.email.enabled:
            jobs.append(asyncio.to_thread(self._send_email, title, ctx, recovered))
        if self.cfg.teams.enabled:
            jobs.append(self._send_teams(title, ctx, recovered))
        for r in await asyncio.gather(*jobs, return_exceptions=True):
            if isinstance(r, Exception):
                log.error("notification failed: %s", r)

    async def test(self) -> dict:
        ctx = {"Device": "TEST", "Message": "This is a test notification from NetMon"}
        result = {}
        if self.cfg.email.enabled:
            try:
                await asyncio.to_thread(self._send_email, "🧪 NetMon test notification", ctx, False)
                result["email"] = "sent"
            except Exception as e:
                result["email"] = f"failed: {e}"
        else:
            result["email"] = "disabled"
        if self.cfg.teams.enabled:
            try:
                await self._send_teams("🧪 NetMon test notification", ctx, False)
                result["teams"] = "sent"
            except Exception as e:
                result["teams"] = f"failed: {e}"
        else:
            result["teams"] = "disabled"
        return result

    # ------------------------------------------------------------------ email
    def _send_email(self, title: str, ctx: dict, recovered: bool):
        e = self.cfg.email
        msg = EmailMessage()
        msg["Subject"] = f"[NetMon] {title}"
        msg["From"] = e.sender or e.username
        msg["To"] = ", ".join(e.to)
        lines = [title, ""] + [f"{k:12}: {v}" for k, v in ctx.items()]
        if self.dashboard_url:
            lines += ["", f"Dashboard: {self.dashboard_url}"]
        msg.set_content("\n".join(lines))
        color = "#1a7f37" if recovered else "#cf222e"
        rows = "".join(
            f"<tr><td style='padding:4px 12px 4px 0;color:#555'><b>{html.escape(k)}</b></td>"
            f"<td style='padding:4px 0'>{html.escape(str(v))}</td></tr>" for k, v in ctx.items())
        link = (f"<p><a href='{html.escape(self.dashboard_url)}'>Open dashboard</a></p>"
                if self.dashboard_url else "")
        msg.add_alternative(
            f"<div style='font-family:Segoe UI,Arial,sans-serif'>"
            f"<h2 style='color:{color};margin:0 0 12px'>{html.escape(title)}</h2>"
            f"<table style='border-collapse:collapse;font-size:14px'>{rows}</table>{link}</div>",
            subtype="html")

        ctx_ssl = ssl.create_default_context()
        if e.use_ssl:
            server = smtplib.SMTP_SSL(e.smtp_host, e.smtp_port, timeout=15, context=ctx_ssl)
        else:
            server = smtplib.SMTP(e.smtp_host, e.smtp_port, timeout=15)
        with server:
            if e.starttls and not e.use_ssl:
                server.starttls(context=ctx_ssl)
            if e.username:
                server.login(e.username, e.password)
            server.send_message(msg)
        log.info("email sent: %s", title)

    # ------------------------------------------------------------------ teams
    async def _send_teams(self, title: str, ctx: dict, recovered: bool):
        """Posts an Adaptive Card. Works with a Teams 'Workflows' webhook
        ("Post to a channel when a webhook request is received") and with
        the older Incoming Webhook connector."""
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "msteams": {"width": "Full"},
            "body": [
                {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Large", "wrap": True,
                 "color": "Good" if recovered else "Attention"},
                {"type": "FactSet", "facts": [{"title": k, "value": str(v)} for k, v in ctx.items()]},
            ],
        }
        if self.dashboard_url:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open dashboard", "url": self.dashboard_url}]
        payload = {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(self.cfg.teams.webhook_url, json=payload)
            r.raise_for_status()
        log.info("teams message sent: %s", title)
