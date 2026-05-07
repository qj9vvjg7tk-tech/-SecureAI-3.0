"""
🧠 محرك التحليل النصي المحلي مع دعم متعدد اللغات
"""

from datetime import datetime
from typing import Dict, List


LANG_TEXT = {
    "ar": {
        "safe_summary": "✅ تحليل أمني للموقع {url}",
        "safe_verdict": "لم يتم اكتشاف أي مشاكل أمنية حرجة. الوضع الأمني العام جيد.",
        "safe_recommendations": [
            "استمر في تحديث الخادم بشكل دوري",
            "راقب السجلات للكشف عن أي نشاط مشبوه",
            "نفّذ نسخاً احتياطية منتظمة للبيانات",
        ],
        "safe_insight": "🧠 الموقع يُظهر معايير أمان جيدة. ننصح بالحفاظ عليها.",
        "report_summary": "🔍 تقرير تحليل أمني شامل للموقع: {url}",
        "verdict": "تم اكتشاف {count} مشكلة أمنية تتطلب الانتباه.",
        "insight_critical_many": "🧠 الموقع يحتوي على ثغرات حرجة متعددة. ننصح بمعالجتها فوراً قبل أن يتم استغلالها.",
        "insight_critical": "🧠 توجد ثغرات حرجة. عالجها خلال 48 ساعة لتقليل المخاطر.",
        "insight_warning": "🧠 الموقع به إعدادات قابلة للتحسين. لا توجد ثغرات حرجة لكن يُفضل تطبيق التوصيات.",
        "username_none": "🧠 لم يتم العثور على حسابات بهذا الاسم ({username}) في المنصات المفحوصة.",
        "username_intro": "🧠 تم العثور على {count} حساب من أصل {total} منصة. المنصات الأكثر احتمالاً: {platforms}. ",
        "username_common": "هذا الاسم شائع الاستخدام. ننصح بفحص كل حساب يدوياً للتحقق من الهوية.",
        "username_limited": "بصمة رقمية محدودة، مما يعزز احتمال أن هذه الحسابات لنفس الشخص.",
    },
    "en": {
        "safe_summary": "✅ Security analysis for {url}",
        "safe_verdict": "No critical security issues were detected. Overall posture looks good.",
        "safe_recommendations": [
            "Keep the server regularly updated",
            "Monitor logs for suspicious activity",
            "Maintain routine data backups",
        ],
        "safe_insight": "🧠 The website shows a healthy security baseline. Keep it maintained.",
        "report_summary": "🔍 Comprehensive security analysis report for: {url}",
        "verdict": "{count} security issues were detected and require attention.",
        "insight_critical_many": "🧠 Multiple critical weaknesses were found. Remediate them immediately before exploitation.",
        "insight_critical": "🧠 Critical weaknesses exist. Fix them within 48 hours to reduce risk.",
        "insight_warning": "🧠 The site has room for improvement. No critical weakness was found, but hardening is recommended.",
        "username_none": "🧠 No public accounts were found for ({username}) on the checked platforms.",
        "username_intro": "🧠 {count} accounts were found out of {total} platforms. Most likely platforms: {platforms}. ",
        "username_common": "This username appears widely used. Manual verification is recommended.",
        "username_limited": "The digital footprint is limited, which may increase the chance that the found accounts belong to the same person.",
    },
    "fr": {
        "safe_summary": "✅ Analyse de sécurité pour {url}",
        "safe_verdict": "Aucun problème critique n'a été détecté. La posture globale semble correcte.",
        "safe_recommendations": [
            "Maintenez le serveur à jour régulièrement",
            "Surveillez les journaux pour toute activité suspecte",
            "Effectuez des sauvegardes régulières des données",
        ],
        "safe_insight": "🧠 Le site présente une bonne base de sécurité. Continuez ainsi.",
        "report_summary": "🔍 Rapport d'analyse de sécurité complet pour : {url}",
        "verdict": "{count} problèmes de sécurité ont été détectés et nécessitent une attention.",
        "insight_critical_many": "🧠 Plusieurs faiblesses critiques ont été trouvées. Corrigez-les immédiatement.",
        "insight_critical": "🧠 Des faiblesses critiques existent. Corrigez-les sous 48 heures pour réduire le risque.",
        "insight_warning": "🧠 Le site peut être renforcé davantage. Aucun problème critique, mais un durcissement est recommandé.",
        "username_none": "🧠 Aucun compte public n'a été trouvé pour ({username}) sur les plateformes vérifiées.",
        "username_intro": "🧠 {count} comptes trouvés sur {total} plateformes. Plateformes les plus probables : {platforms}. ",
        "username_common": "Ce nom d'utilisateur semble répandu. Une vérification manuelle est recommandée.",
        "username_limited": "L'empreinte numérique est limitée, ce qui peut indiquer que les comptes trouvés appartiennent à la même personne.",
    },
}


SECURITY_KNOWLEDGE = {
    "csp": {
        "ar": "أضف Content-Security-Policy لمنع هجمات XSS وحقن الأكواد الخبيثة",
        "en": "Add a strong Content-Security-Policy to reduce XSS and script injection risk",
        "fr": "Ajoutez une Content-Security-Policy stricte pour réduire le risque XSS",
    },
    "x-frame-options": {
        "ar": "أضف X-Frame-Options: DENY لمنع هجمات Clickjacking",
        "en": "Add X-Frame-Options: DENY to block clickjacking attacks",
        "fr": "Ajoutez X-Frame-Options: DENY pour bloquer le clickjacking",
    },
    "hsts": {
        "ar": "فعّل HSTS لإجبار المتصفحات على استخدام HTTPS فقط",
        "en": "Enable HSTS to force browsers to use HTTPS only",
        "fr": "Activez HSTS pour forcer l'utilisation de HTTPS",
    },
    "x-content-type-options": {
        "ar": "أضف X-Content-Type-Options: nosniff لمنع MIME sniffing",
        "en": "Add X-Content-Type-Options: nosniff to block MIME sniffing",
        "fr": "Ajoutez X-Content-Type-Options: nosniff pour bloquer le MIME sniffing",
    },
    "mixed_content": {
        "ar": "حوّل جميع روابط HTTP إلى HTTPS لتجنب اعتراض البيانات",
        "en": "Convert all HTTP links to HTTPS to avoid interception",
        "fr": "Convertissez tous les liens HTTP vers HTTPS pour éviter l'interception",
    },
    "inline_scripts": {
        "ar": "انقل البرامج النصية المضمنة إلى ملفات خارجية مع CSP صارم",
        "en": "Move inline scripts to external files and enforce a stricter CSP",
        "fr": "Déplacez les scripts inline vers des fichiers externes avec une CSP stricte",
    },
    "general": {
        "ar": "راجع إعدادات الخادم وأضف العناوين الأمنية المفقودة",
        "en": "Review the server configuration and add the missing security headers",
        "fr": "Révisez la configuration du serveur et ajoutez les en-têtes de sécurité manquants",
    },
}



def _lang_bundle(lang: str) -> Dict:
    return LANG_TEXT.get(lang or "ar", LANG_TEXT["ar"])



def ai_analyze(url: str, threats: List[str], risk: Dict = None, lang: str = "ar") -> Dict:
    bundle = _lang_bundle(lang)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    if not threats:
        return {
            "timestamp": timestamp,
            "summary": bundle["safe_summary"].format(url=url),
            "risk_level": "safe" if lang != "ar" else "آمن",
            "risk_score": 0,
            "verdict": bundle["safe_verdict"],
            "details": [],
            "recommendations": bundle["safe_recommendations"],
            "ai_insight": bundle["safe_insight"],
        }

    recommendations = []
    for threat in threats:
        threat_lower = threat.lower()
        if "csp" in threat_lower or "content-security-policy" in threat_lower:
            recommendations.append(SECURITY_KNOWLEDGE["csp"][lang])
        elif "x-frame" in threat_lower or "clickjacking" in threat_lower:
            recommendations.append(SECURITY_KNOWLEDGE["x-frame-options"][lang])
        elif "hsts" in threat_lower or "strict-transport" in threat_lower:
            recommendations.append(SECURITY_KNOWLEDGE["hsts"][lang])
        elif "mime" in threat_lower or "x-content-type" in threat_lower:
            recommendations.append(SECURITY_KNOWLEDGE["x-content-type-options"][lang])
        elif "mixed" in threat_lower or "مختلط" in threat_lower:
            recommendations.append(SECURITY_KNOWLEDGE["mixed_content"][lang])
        elif "inline" in threat_lower or "مضمن" in threat_lower:
            recommendations.append(SECURITY_KNOWLEDGE["inline_scripts"][lang])

    recommendations = list(dict.fromkeys(recommendations)) or [SECURITY_KNOWLEDGE["general"][lang]]

    critical_count = sum(1 for t in threats if "🚨" in t or "🔴" in t)
    if critical_count >= 3:
        insight = bundle["insight_critical_many"]
    elif critical_count >= 1:
        insight = bundle["insight_critical"]
    else:
        insight = bundle["insight_warning"]

    return {
        "timestamp": timestamp,
        "summary": bundle["report_summary"].format(url=url),
        "risk_level": risk["level"] if risk else None,
        "risk_score": risk["score"] if risk else len(threats) * 10,
        "verdict": bundle["verdict"].format(count=len(threats)),
        "details": threats,
        "recommendations": recommendations,
        "ai_insight": insight,
    }



def generate_username_insight(username: str, results: list, lang: str = "ar") -> str:
    bundle = _lang_bundle(lang)
    found = [r for r in results if r.get("found")]
    total = len(results)

    if not found:
        return bundle["username_none"].format(username=username)

    platforms = ", ".join([r["platform"] for r in found[:5]])
    text = bundle["username_intro"].format(count=len(found), total=total, platforms=platforms)
    text += bundle["username_common"] if len(found) > 7 else bundle["username_limited"]
    return text
