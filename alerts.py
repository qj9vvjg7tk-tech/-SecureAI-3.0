"""
📡 نظام التنبيهات والمراقبة المستمرة المعتمد على SQLite
"""

import asyncio
import hashlib
from datetime import datetime
from typing import Optional

import httpx

from db import (
    delete_monitor,
    get_alerts as db_get_alerts,
    get_monitor_by_url,
    list_monitors,
    save_alert,
    update_monitor_state,
    upsert_monitor,
)
from notifications import broadcast_alert


MONITOR_POLL_SECONDS = 60


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


async def _push_alert(alert: dict):
    text = f"[{alert.get('level', 'info').upper()}] {alert.get('message', '')}"
    try:
        await broadcast_alert(text)
    except Exception:
        pass



def send_alert(message: str, level: str = "info", target: Optional[str] = None):
    """تسجيل تنبيه جديد مع محاولة إرساله للقنوات الخارجية"""
    alert = save_alert(message, level, target)
    print(f"🚨 [{level.upper()}] {message}")
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_push_alert(alert))
    except Exception:
        pass
    return alert



def get_alerts(limit: int = 50) -> list:
    return db_get_alerts(limit)


async def add_monitor(url: str, interval: int = 300, user_id: Optional[int] = None):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            r = await client.get(url)
            content_hash = hash_content(r.text)

        upsert_monitor(user_id, url, content_hash, interval_seconds=interval)
        send_alert(f"بدأت مراقبة الموقع: {url}", "info", url)
        return {"success": True, "url": url, "interval": interval}
    except Exception as e:
        return {"success": False, "error": str(e)}



def remove_monitor(url: str):
    if delete_monitor(url):
        send_alert(f"تم إيقاف مراقبة: {url}", "info", url)
        return {"success": True}
    return {"success": False, "error": "الموقع غير مُراقب"}



def get_monitors(user_id: Optional[int] = None) -> list:
    return list_monitors(user_id=user_id)


async def check_changes():
    monitors = list_monitors()
    if not monitors:
        return

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
        for monitor in monitors:
            url = monitor["url"]
            try:
                r = await client.get(url)
                new_hash = hash_content(r.text)
                changed = new_hash != (monitor.get("content_hash") or "")
                update_monitor_state(
                    url,
                    new_hash,
                    changed=changed,
                    details="content changed" if changed else "no change",
                )
                if changed:
                    send_alert(
                        f"⚠️ تم اكتشاف تغيير في محتوى الموقع: {url}",
                        "warning",
                        url,
                    )
            except Exception as e:
                send_alert(f"تعذر فحص {url}: {str(e)}", "warning", url)


async def monitor_loop():
    while True:
        try:
            await check_changes()
        except Exception as e:
            print(f"خطأ في حلقة المراقبة: {e}")
        await asyncio.sleep(MONITOR_POLL_SECONDS)
