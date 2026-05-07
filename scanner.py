"""
🔍 المحرك الأساسي للفحص الأمني
"""

import httpx

from ai_engine import ai_analyze
from threats import calculate_risk_score, detect_threats


async def scan_site(url: str, lang: str = "ar") -> dict:
    """فحص شامل لموقع ويب"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            r = await client.get(url)
            headers = dict(r.headers)
            html = r.text

        threats = detect_threats(headers, html, url=url)
        risk = calculate_risk_score(threats)
        ai_report = ai_analyze(url, threats, risk, lang=lang)

        return {
            "url": url,
            "status": r.status_code,
            "final_url": str(r.url),
            "threats": threats,
            "risk": risk,
            "ai_report": ai_report,
            "headers_count": len(headers),
            "page_size": len(html),
            "language": lang,
        }
    except httpx.TimeoutException:
        return {"url": url, "error": "انتهت مهلة الاتصال (Timeout)", "language": lang}
    except Exception as e:
        return {"url": url, "error": f"خطأ في الفحص: {str(e)}", "language": lang}
