"""
🛡️ وحدة كشف التهديدات الأمنية
"""

import re


SECURITY_HEADERS = {
    "content-security-policy": "CSP - يحمي من XSS وحقن الأكواد",
    "x-frame-options": "يمنع هجمات Clickjacking",
    "x-content-type-options": "يمنع MIME-sniffing",
    "strict-transport-security": "HSTS - يفرض استخدام HTTPS",
    "referrer-policy": "يتحكم في معلومات Referrer",
    "permissions-policy": "يتحكم في صلاحيات المتصفح",
    "x-xss-protection": "حماية إضافية ضد XSS",
}



def detect_threats(headers: dict, html: str, url: str = "") -> list:
    issues = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    html_lower = html.lower() if html else ""

    for header, description in SECURITY_HEADERS.items():
        if header not in headers_lower:
            issues.append(f"⚠️ عنوان مفقود: {header} ({description})")

    if "<script" in html_lower:
        script_windows = html_lower.split("<script")[:5]
        if any("src=" not in chunk[:200] for chunk in script_windows[1:]):
            issues.append("🔴 تم اكتشاف برامج نصية مضمنة (Inline Scripts) - خطر XSS")

    if url.startswith("https://") and re.search(r'http://[^\s"\']+', html_lower):
        issues.append("🔴 محتوى مختلط (Mixed Content) - روابط HTTP داخل صفحة HTTPS")

    if re.search(r'(api[_-]?key|secret|token|password)\s*[:=]\s*["\'][^"\']+', html_lower):
        issues.append("🚨 احتمال تسريب مفاتيح API أو بيانات حساسة في الكود")

    if "eval(" in html_lower or "document.write" in html_lower:
        issues.append("⚠️ استخدام دوال خطرة (eval/document.write)")

    if "set-cookie" in headers_lower:
        cookie = headers_lower["set-cookie"].lower()
        if "httponly" not in cookie:
            issues.append("⚠️ الكوكيز بدون HttpOnly")
        if "secure" not in cookie:
            issues.append("⚠️ الكوكيز بدون Secure")
        if "samesite" not in cookie:
            issues.append("⚠️ الكوكيز بدون SameSite (خطر CSRF)")

    if any(token in html_lower for token in ["index of /", "directory listing for", "phpinfo()"]):
        issues.append("🔴 تم اكتشاف مؤشرات على Security Misconfiguration أو Directory Listing")

    if re.search(r"sql syntax|mysql_fetch|odbc sql|postgresql query failed", html_lower):
        issues.append("🚨 رسائل أخطاء قواعد بيانات ظاهرة للعموم - احتمال قابلية للاستغلال")

    if "server" in headers_lower:
        server_info = headers_lower["server"]
        if any(v in server_info.lower() for v in ["apache/2.2", "nginx/1.0", "iis/6", "php/5", "openssl/1.0"]):
            issues.append(f"🔴 إصدار خادم/مكوّن قديم ظاهر في الترويسة: {server_info}")

    if "x-powered-by" in headers_lower:
        issues.append(f"⚠️ تسريب معلومات التقنية: X-Powered-By = {headers_lower['x-powered-by']}")

    return issues



def calculate_risk_score(threats: list) -> dict:
    if not threats:
        return {"level": "آمن", "score": 0, "color": "#00ff88"}

    critical = sum(1 for t in threats if "🚨" in t or "🔴" in t)
    warnings = sum(1 for t in threats if "⚠️" in t)

    score = min((critical * 25) + (warnings * 10), 100)

    if score >= 70:
        return {"level": "خطر مرتفع", "score": score, "color": "#ff3366"}
    if score >= 40:
        return {"level": "خطر متوسط", "score": score, "color": "#ffaa00"}
    if score >= 15:
        return {"level": "خطر منخفض", "score": score, "color": "#ffdd00"}
    return {"level": "آمن نسبياً", "score": score, "color": "#00ff88"}
