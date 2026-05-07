"""
🗄️ طبقة قاعدة البيانات SQLite لمنصة SecureAI
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("SECUREAI_DB_PATH", str(BASE_DIR / "secureai.db"))


def _dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = _dict_factory
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now_iso() -> str:
    return datetime.utcnow().isoformat()


def init_db():
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                preferred_language TEXT DEFAULT 'ar',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                level TEXT NOT NULL,
                target TEXT,
                channel TEXT DEFAULT 'system',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS monitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT UNIQUE NOT NULL,
                content_hash TEXT,
                last_check TEXT,
                interval_seconds INTEGER DEFAULT 300,
                checks INTEGER DEFAULT 0,
                changes INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS monitor_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notification_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                telegram_bot_token TEXT,
                telegram_chat_id TEXT,
                discord_webhook TEXT,
                slack_webhook TEXT,
                smtp_host TEXT,
                smtp_port INTEGER DEFAULT 587,
                smtp_user TEXT,
                smtp_password TEXT,
                smtp_sender TEXT,
                smtp_use_tls INTEGER DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            """
        )

        exists = conn.execute("SELECT id FROM notification_settings WHERE id = 1").fetchone()
        if not exists:
            conn.execute(
                """
                INSERT INTO notification_settings (
                    id, telegram_bot_token, telegram_chat_id, discord_webhook, slack_webhook,
                    smtp_host, smtp_port, smtp_user, smtp_password, smtp_sender, smtp_use_tls, updated_at
                ) VALUES (1, '', '', '', '', '', 587, '', '', '', 1, ?)
                """,
                (now_iso(),),
            )


def create_user(username: str, email: str, password_hash: str, preferred_language: str = "ar") -> Dict[str, Any]:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, preferred_language, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email.lower(), password_hash, preferred_language, now_iso()),
        )
        return conn.execute("SELECT id, username, email, preferred_language, created_at FROM users WHERE email = ?", (email.lower(),)).fetchone()



def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()



def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()



def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute("SELECT id, username, email, preferred_language, created_at FROM users WHERE id = ?", (user_id,)).fetchone()



def update_user_language(user_id: int, preferred_language: str):
    with get_conn() as conn:
        conn.execute("UPDATE users SET preferred_language = ? WHERE id = ?", (preferred_language, user_id))



def save_scan(user_id: Optional[int], target: str, scan_type: str, result: Dict[str, Any]):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (user_id, target, scan_type, result_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, target, scan_type, json.dumps(result, ensure_ascii=False), now_iso()),
        )



def get_recent_scans(limit: int = 50, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM scans"
    params = []
    if user_id is not None:
        query += " WHERE user_id = ?"
        params.append(user_id)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    for row in rows:
        try:
            row["result"] = json.loads(row.pop("result_json"))
        except Exception:
            row["result"] = {}
    return rows



def get_stats_summary(user_id: Optional[int] = None) -> Dict[str, Any]:
    with get_conn() as conn:
        scans_query = "SELECT COUNT(*) AS c FROM scans"
        scans_params = []
        if user_id is not None:
            scans_query += " WHERE user_id = ?"
            scans_params.append(user_id)
        total_scans = conn.execute(scans_query, tuple(scans_params)).fetchone()["c"]

        recent = get_recent_scans(50, user_id=user_id)
        total_threats = 0
        ports_scanned = 0
        leaks_found = 0
        for item in recent:
            result = item.get("result", {})
            total_threats += len(result.get("threats", []))
            ports_scanned += result.get("open_count", 0)
            leaks_found += result.get("leaks_found", 0)

        monitors_query = "SELECT COUNT(*) AS c FROM monitors"
        monitors_params = []
        if user_id is not None:
            monitors_query += " WHERE user_id = ?"
            monitors_params.append(user_id)
        monitored_sites = conn.execute(monitors_query, tuple(monitors_params)).fetchone()["c"]

        alerts_count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]

    scan_history = [
        {
            "type": item.get("scan_type"),
            "target": item.get("target"),
            "timestamp": item.get("created_at"),
        }
        for item in recent[::-1]
    ]

    return {
        "total_scans": total_scans,
        "total_threats": total_threats,
        "ports_scanned": ports_scanned,
        "leaks_found": leaks_found,
        "monitored_sites": monitored_sites,
        "alerts_count": alerts_count,
        "scan_history": scan_history,
    }



def save_alert(message: str, level: str = "info", target: Optional[str] = None, channel: str = "system") -> Dict[str, Any]:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alerts (message, level, target, channel, created_at) VALUES (?, ?, ?, ?, ?)",
            (message, level, target, channel, now_iso()),
        )
        return conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1").fetchone()



def get_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()



def get_notification_settings() -> Dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM notification_settings WHERE id = 1").fetchone()
    return row or {}



def update_notification_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    current = get_notification_settings()
    merged = {**current, **payload, "updated_at": now_iso()}
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE notification_settings SET
                telegram_bot_token = ?,
                telegram_chat_id = ?,
                discord_webhook = ?,
                slack_webhook = ?,
                smtp_host = ?,
                smtp_port = ?,
                smtp_user = ?,
                smtp_password = ?,
                smtp_sender = ?,
                smtp_use_tls = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (
                merged.get("telegram_bot_token", ""),
                merged.get("telegram_chat_id", ""),
                merged.get("discord_webhook", ""),
                merged.get("slack_webhook", ""),
                merged.get("smtp_host", ""),
                int(merged.get("smtp_port", 587) or 587),
                merged.get("smtp_user", ""),
                merged.get("smtp_password", ""),
                merged.get("smtp_sender", ""),
                1 if bool(merged.get("smtp_use_tls", True)) else 0,
                merged.get("updated_at"),
            ),
        )
    return get_notification_settings()



def upsert_monitor(user_id: Optional[int], url: str, content_hash: str, interval_seconds: int = 300) -> Dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM monitors WHERE url = ?", (url,)).fetchone()
        if row:
            conn.execute(
                """
                UPDATE monitors
                SET user_id = COALESCE(?, user_id), content_hash = ?, last_check = ?, interval_seconds = ?, checks = COALESCE(checks, 0) + 1
                WHERE url = ?
                """,
                (user_id, content_hash, now_iso(), interval_seconds, url),
            )
        else:
            conn.execute(
                """
                INSERT INTO monitors (user_id, url, content_hash, last_check, interval_seconds, checks, changes, created_at)
                VALUES (?, ?, ?, ?, ?, 1, 0, ?)
                """,
                (user_id, url, content_hash, now_iso(), interval_seconds, now_iso()),
            )
        return conn.execute("SELECT * FROM monitors WHERE url = ?", (url,)).fetchone()



def list_monitors(user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        if user_id is None:
            return conn.execute("SELECT * FROM monitors ORDER BY id DESC").fetchall()
        return conn.execute("SELECT * FROM monitors WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()



def get_monitor_by_url(url: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM monitors WHERE url = ?", (url,)).fetchone()



def update_monitor_state(url: str, content_hash: str, changed: bool = False, details: str = ""):
    with get_conn() as conn:
        monitor = conn.execute("SELECT * FROM monitors WHERE url = ?", (url,)).fetchone()
        if not monitor:
            return None
        conn.execute(
            """
            UPDATE monitors
            SET content_hash = ?, last_check = ?, checks = checks + 1, changes = changes + ?
            WHERE url = ?
            """,
            (content_hash, now_iso(), 1 if changed else 0, url),
        )
        updated = conn.execute("SELECT * FROM monitors WHERE url = ?", (url,)).fetchone()
        if changed:
            conn.execute(
                "INSERT INTO monitor_history (monitor_id, event_type, details, created_at) VALUES (?, ?, ?, ?)",
                (updated["id"], "change", details, now_iso()),
            )
        return updated



def delete_monitor(url: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM monitors WHERE url = ?", (url,))
        return cur.rowcount > 0
