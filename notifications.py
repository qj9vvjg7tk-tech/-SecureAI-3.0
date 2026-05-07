"""
📣 قنوات الإشعارات: Email + Telegram + Discord + Slack
"""

import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional

import httpx

from db import get_notification_settings


async def send_telegram_message(message: str, settings: Optional[Dict] = None) -> Dict:
    settings = settings or get_notification_settings()
    token = (settings.get("telegram_bot_token") or "").strip()
    chat_id = (settings.get("telegram_chat_id") or "").strip()
    if not token or not chat_id:
        return {"success": False, "channel": "telegram", "error": "Telegram غير مهيأ"}

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, json={"chat_id": chat_id, "text": message})
    if resp.status_code >= 400:
        return {"success": False, "channel": "telegram", "error": resp.text}
    return {"success": True, "channel": "telegram"}


async def send_webhook_message(message: str, webhook_url: str, webhook_type: str) -> Dict:
    if not webhook_url:
        return {"success": False, "channel": webhook_type, "error": f"{webhook_type} webhook غير مهيأ"}

    payload = {"text": message}
    if webhook_type == "discord":
        payload = {"content": message}

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(webhook_url, json=payload)
    if resp.status_code >= 400:
        return {"success": False, "channel": webhook_type, "error": resp.text}
    return {"success": True, "channel": webhook_type}


async def send_email_message(
    to_email: str,
    subject: str,
    body: str,
    html_body: Optional[str] = None,
    settings: Optional[Dict] = None,
) -> Dict:
    settings = settings or get_notification_settings()
    smtp_host = (settings.get("smtp_host") or "").strip()
    smtp_user = (settings.get("smtp_user") or "").strip()
    smtp_password = settings.get("smtp_password") or ""
    smtp_sender = (settings.get("smtp_sender") or smtp_user).strip()
    smtp_port = int(settings.get("smtp_port") or 587)
    smtp_use_tls = bool(settings.get("smtp_use_tls", 1))

    if not smtp_host or not smtp_sender:
        return {"success": False, "channel": "email", "error": "إعدادات SMTP غير مكتملة"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_sender
    msg["To"] = to_email
    msg.attach(MIMEText(body, "plain", "utf-8"))
    if html_body:
        msg.attach(MIMEText(html_body, "html", "utf-8"))

    def _send():
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)
        try:
            server.ehlo()
            if smtp_use_tls:
                server.starttls()
                server.ehlo()
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_sender, [to_email], msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                pass

    try:
        await asyncio.to_thread(_send)
        return {"success": True, "channel": "email", "to": to_email}
    except Exception as exc:
        return {"success": False, "channel": "email", "error": str(exc)}


async def broadcast_alert(message: str, settings: Optional[Dict] = None) -> Dict:
    settings = settings or get_notification_settings()
    results = []

    if settings.get("telegram_bot_token") and settings.get("telegram_chat_id"):
        results.append(await send_telegram_message(message, settings))

    if settings.get("discord_webhook"):
        results.append(await send_webhook_message(message, settings.get("discord_webhook"), "discord"))

    if settings.get("slack_webhook"):
        results.append(await send_webhook_message(message, settings.get("slack_webhook"), "slack"))

    return {
        "success": any(r.get("success") for r in results) if results else False,
        "results": results,
    }
