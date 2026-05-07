"""
🧠 SecureAI - منصة احترافية للأمن السيبراني
FastAPI + SQLite + JWT + PWA-ready frontend
"""

import asyncio
import csv
import io
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from ai_engine import generate_username_insight
from alerts import add_monitor, get_alerts, get_monitors, monitor_loop, remove_monitor, send_alert
from auth import authenticate_user, create_token, get_current_user, hash_password
from db import (
    create_user,
    get_notification_settings,
    get_recent_scans,
    get_stats_summary,
    get_user_by_email,
    get_user_by_username,
    init_db,
    save_scan,
    update_notification_settings,
    update_user_language,
)
from notifications import broadcast_alert, send_email_message
from scanner import scan_site
from tools import (
    analyze_dns,
    analyze_headers,
    check_ssl,
    detect_leaks,
    enumerate_subdomains,
    owasp_top10_scan,
    port_scan,
    username_lookup,
)

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(monitor_loop())
    send_alert("🚀 تم تشغيل خادم SecureAI بنجاح", "info")
    yield
    task.cancel()


app = FastAPI(
    title="SecureAI",
    description="منصة احترافية للأمن السيبراني والاختراق الأخلاقي",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TargetInput(BaseModel):
    target: str
    lang: str = "ar"


class MonitorInput(BaseModel):
    url: str
    interval: int = 300


class RegisterInput(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    preferred_language: str = "ar"


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class NotificationSettingsInput(BaseModel):
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    discord_webhook: str = ""
    slack_webhook: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_sender: str = ""
    smtp_use_tls: bool = True


class EmailReportInput(BaseModel):
    to_email: EmailStr
    subject: str
    content: str
    html_content: Optional[str] = None


@app.get("/")
async def home():
    return {
        "message": "🧠 SecureAI Running",
        "version": "3.0.0",
        "app_url": "/app/",
        "endpoints": [
            "/auth/register", "/auth/login", "/auth/me", "/scan", "/scan/full",
            "/tools/port-scan", "/tools/headers", "/tools/leaks", "/tools/dns",
            "/tools/ssl", "/tools/username", "/tools/subdomains", "/tools/owasp",
            "/monitor/add", "/monitor/list", "/alerts", "/stats", "/reports/export",
            "/reports/email", "/settings/notifications",
        ],
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/auth/register")
async def register(data: RegisterInput):
    if get_user_by_email(data.email):
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مستخدم بالفعل")
    if get_user_by_username(data.username):
        raise HTTPException(status_code=400, detail="اسم المستخدم مستخدم بالفعل")
    user = create_user(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        preferred_language=data.preferred_language,
    )
    token = create_token(user)
    return {"token": token, "user": user}


@app.post("/auth/login")
async def login(data: LoginInput):
    user = authenticate_user(data.email, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة")
    token = create_token(user)
    public_user = {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "preferred_language": user.get("preferred_language", "ar"),
        "created_at": user.get("created_at"),
    }
    return {"token": token, "user": public_user}


@app.get("/auth/me")
async def auth_me(user=Depends(get_current_user)):
    return user


@app.post("/auth/language")
async def set_language(lang: str = Query("ar"), user=Depends(get_current_user)):
    update_user_language(user["id"], lang)
    return {"success": True, "preferred_language": lang}


@app.get("/stats")
async def stats(user=Depends(get_current_user)):
    return get_stats_summary(user_id=user["id"])


@app.post("/scan")
async def scan(data: TargetInput, user=Depends(get_current_user)):
    result = await scan_site(data.target, lang=data.lang)
    save_scan(user["id"], data.target, "site_scan", result)
    if result.get("threats"):
        send_alert(f"تم اكتشاف {len(result['threats'])} تهديد في {data.target}", "warning", data.target)
    return result


@app.post("/tools/port-scan")
async def tool_port_scan(data: TargetInput, user=Depends(get_current_user)):
    result = await port_scan(data.target)
    save_scan(user["id"], data.target, "port_scan", result)
    return result


@app.post("/tools/headers")
async def tool_headers(data: TargetInput, user=Depends(get_current_user)):
    result = await analyze_headers(data.target)
    save_scan(user["id"], data.target, "headers_scan", result)
    return result


@app.post("/tools/leaks")
async def tool_leaks(data: TargetInput, user=Depends(get_current_user)):
    result = await detect_leaks(data.target)
    save_scan(user["id"], data.target, "leak_scan", result)
    if result.get("leaks_found", 0) > 0:
        send_alert(f"🚨 تم اكتشاف {result['leaks_found']} نوع تسريب في {data.target}", "critical", data.target)
    return result


@app.post("/tools/dns")
async def tool_dns(data: TargetInput, user=Depends(get_current_user)):
    result = await analyze_dns(data.target)
    save_scan(user["id"], data.target, "dns_scan", result)
    return result


@app.post("/tools/ssl")
async def tool_ssl(data: TargetInput, user=Depends(get_current_user)):
    result = await check_ssl(data.target)
    save_scan(user["id"], data.target, "ssl_scan", result)
    if result.get("expiring_soon"):
        send_alert(f"⚠️ شهادة SSL تنتهي قريباً: {result.get('host')}", "warning", result.get("host"))
    return result


@app.post("/tools/username")
async def tool_username(data: TargetInput, user=Depends(get_current_user)):
    result = await username_lookup(data.target)
    result["ai_insight"] = generate_username_insight(data.target, result["results"], lang=data.lang)
    save_scan(user["id"], data.target, "username_lookup", result)
    return result


@app.post("/tools/subdomains")
async def tool_subdomains(data: TargetInput, user=Depends(get_current_user)):
    result = await enumerate_subdomains(data.target)
    save_scan(user["id"], data.target, "subdomain_enum", result)
    if result.get("count", 0) > 0:
        send_alert(f"تم اكتشاف {result['count']} نطاق فرعي محتمل لـ {data.target}", "info", data.target)
    return result


@app.post("/tools/owasp")
async def tool_owasp(data: TargetInput, user=Depends(get_current_user)):
    result = await owasp_top10_scan(data.target)
    save_scan(user["id"], data.target, "owasp_top10", result)
    if result.get("findings_count", 0) > 0:
        send_alert(f"OWASP Top 10 كشف {result['findings_count']} ملاحظة على {data.target}", "warning", data.target)
    return result


@app.post("/monitor/add")
async def monitor_add(data: MonitorInput, user=Depends(get_current_user)):
    return await add_monitor(data.url, data.interval, user_id=user["id"])


@app.delete("/monitor/remove")
async def monitor_del(url: str, user=Depends(get_current_user)):
    return remove_monitor(url)


@app.get("/monitor/list")
async def monitor_list(user=Depends(get_current_user)):
    return get_monitors(user_id=user["id"])


@app.get("/alerts")
async def alerts(limit: int = 50, user=Depends(get_current_user)):
    return get_alerts(limit)


@app.post("/scan/full")
async def full_scan(data: TargetInput, user=Depends(get_current_user)):
    target = data.target
    results = await asyncio.gather(
        scan_site(target, lang=data.lang),
        port_scan(target),
        analyze_headers(target),
        detect_leaks(target),
        analyze_dns(target),
        check_ssl(target),
        enumerate_subdomains(target),
        owasp_top10_scan(target),
        return_exceptions=True,
    )
    keys = ["site", "ports", "headers", "leaks", "dns", "ssl", "subdomains", "owasp"]
    payload = {key: ({"error": str(value)} if isinstance(value, Exception) else value) for key, value in zip(keys, results)}
    response = {"target": target, "results": payload}
    save_scan(user["id"], data.target, "full_scan", response)
    return response


@app.get("/reports/export")
async def export_reports(
    format: str = Query("json", pattern="^(json|csv)$"),
    limit: int = Query(100, ge=1, le=1000),
    user=Depends(get_current_user),
):
    scans = get_recent_scans(limit=limit, user_id=user["id"])
    if format == "json":
        content = json.dumps(scans, ensure_ascii=False, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=secureai_reports.json"},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "scan_type", "target", "created_at", "summary"])
    for row in scans:
        result = row.get("result", {})
        summary = result.get("ai_report", {}).get("verdict") or result.get("error") or str(result)[:120]
        writer.writerow([row.get("id"), row.get("scan_type"), row.get("target"), row.get("created_at"), summary])
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=secureai_reports.csv"},
    )


@app.post("/reports/email")
async def email_report(data: EmailReportInput, user=Depends(get_current_user)):
    result = await send_email_message(
        to_email=data.to_email,
        subject=data.subject,
        body=data.content,
        html_body=data.html_content,
    )
    if result.get("success"):
        send_alert(f"تم إرسال تقرير عبر البريد إلى {data.to_email}", "info", data.to_email)
    return result


@app.get("/settings/notifications")
async def notification_settings(user=Depends(get_current_user)):
    settings = get_notification_settings()
    settings["smtp_password"] = "" if settings.get("smtp_password") else ""
    return settings


@app.post("/settings/notifications")
async def save_notification_settings(data: NotificationSettingsInput, user=Depends(get_current_user)):
    settings = update_notification_settings(data.model_dump())
    if settings.get("smtp_password"):
        settings["smtp_password"] = "********"
    send_alert("تم تحديث إعدادات الإشعارات الخارجية", "info")
    return settings


@app.post("/settings/test-alert")
async def test_alert(user=Depends(get_current_user)):
    result = await broadcast_alert("🔔 SecureAI test alert")
    send_alert("تم تنفيذ اختبار التنبيهات الخارجية", "info")
    return result


if FRONTEND_DIR.exists():
    app.mount("/app", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="app")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
