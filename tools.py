"""
🔧 مجموعة أدوات SecureAI
- فحص المنافذ
- تحليل العناوين
- كشف التسريبات
- تحليل DNS
- فحص SSL
- Username Lookup
- Subdomain Enumeration
- OWASP Top 10 Scanner
"""

import asyncio
import re
import socket
import ssl
from datetime import datetime
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import dns.resolver
import httpx


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "dev", "staging", "test", "api", "beta", "app", "admin",
    "portal", "vpn", "m", "cdn", "static", "blog", "shop", "docs", "dashboard",
]

SOCIAL_PLATFORMS = {
    "Facebook": "https://www.facebook.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter/X": "https://twitter.com/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "GitHub": "https://github.com/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Telegram": "https://t.me/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Medium": "https://medium.com/@{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "Vimeo": "https://vimeo.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "GitLab": "https://gitlab.com/{}",
}



def normalize_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target.strip()


async def scan_port(host: str, port: int, timeout: float = 1.5) -> dict:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "open", "open": True}
    except Exception:
        return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "closed", "open": False}


async def port_scan(target: str) -> dict:
    host = normalize_host(target)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"error": f"تعذر تحويل الاسم إلى IP: {str(e)}", "host": host}

    results = await asyncio.gather(*[scan_port(ip, port) for port in COMMON_PORTS.keys()])
    open_ports = [r for r in results if r["open"]]
    return {
        "host": host,
        "ip": ip,
        "total_scanned": len(COMMON_PORTS),
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "all_results": results,
        "timestamp": datetime.utcnow().isoformat(),
    }


async def analyze_headers(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            r = await client.get(url)
            headers = dict(r.headers)

        security_headers = {
            "Content-Security-Policy": "present" if any(k.lower() == "content-security-policy" for k in headers) else "missing",
            "X-Frame-Options": "present" if any(k.lower() == "x-frame-options" for k in headers) else "missing",
            "X-Content-Type-Options": "present" if any(k.lower() == "x-content-type-options" for k in headers) else "missing",
            "Strict-Transport-Security": "present" if any(k.lower() == "strict-transport-security" for k in headers) else "missing",
            "Referrer-Policy": "present" if any(k.lower() == "referrer-policy" for k in headers) else "missing",
            "Permissions-Policy": "present" if any(k.lower() == "permissions-policy" for k in headers) else "missing",
        }
        info_leaks = {
            k: v for k, v in headers.items()
            if k.lower() in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]
        }
        score = sum(1 for v in security_headers.values() if v == "present") * 100 // len(security_headers)
        return {
            "url": url,
            "status_code": r.status_code,
            "all_headers": headers,
            "security_headers": security_headers,
            "info_leaks": info_leaks,
            "security_score": score,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": f"تعذر تحليل العناوين: {str(e)}", "url": url}


LEAK_PATTERNS = {
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "API Key": r"(?i)(api[_-]?key|apikey)[\s:=\"']+([a-zA-Z0-9_\-]{20,})",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z\-_]{35}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "Phone": r"\+?[\d]{1,3}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}",
    "Credit Card": r"\b(?:\d[ -]*?){13,19}\b",
    "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


async def detect_leaks(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            r = await client.get(url)
            content = r.text

        findings = {}
        for leak_type, pattern in LEAK_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                if isinstance(matches[0], tuple):
                    matches = [m[-1] if isinstance(m, tuple) else m for m in matches]
                unique = list(dict.fromkeys(str(m)[:80] for m in matches))[:10]
                findings[leak_type] = {"count": len(matches), "samples": unique}

        return {
            "url": url,
            "leaks_found": len(findings),
            "findings": findings,
            "severity": "critical" if len(findings) >= 3 else ("medium" if findings else "safe"),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"error": f"تعذر فحص التسريبات: {str(e)}", "url": url}


async def analyze_dns(domain: str) -> dict:
    domain = normalize_host(domain)
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            records[rtype] = []

    security_analysis = {"SPF": any("v=spf1" in str(t).lower() for t in records.get("TXT", [])), "DMARC": False, "DKIM": False}
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        security_analysis["DMARC"] = any("v=dmarc1" in str(r).lower() for r in dmarc)
    except Exception:
        pass
    try:
        dkim = dns.resolver.resolve(f"default._domainkey.{domain}", "TXT", lifetime=5)
        security_analysis["DKIM"] = len(list(dkim)) > 0
    except Exception:
        pass

    return {"domain": domain, "records": records, "security_analysis": security_analysis, "timestamp": datetime.utcnow().isoformat()}


async def check_ssl(domain: str) -> dict:
    host = normalize_host(domain)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
        except Exception:
            days_left = -1
        return {
            "host": host,
            "valid": True,
            "issuer": issuer.get("organizationName", "Unknown"),
            "subject": subject.get("commonName", host),
            "valid_from": not_before,
            "valid_until": not_after,
            "days_remaining": days_left,
            "tls_version": version,
            "cipher": cipher[0] if cipher else "Unknown",
            "expiring_soon": days_left < 30 if days_left >= 0 else False,
            "san": [s[1] for s in cert.get("subjectAltName", [])][:15],
            "timestamp": datetime.utcnow().isoformat(),
        }
    except ssl.SSLError as e:
        return {"host": host, "valid": False, "error": f"SSL error: {str(e)}"}
    except Exception as e:
        return {"host": host, "valid": False, "error": f"تعذر الفحص: {str(e)}"}


async def check_platform(client: httpx.AsyncClient, platform: str, url: str, username: str) -> dict:
    full_url = url.format(username)
    try:
        r = await client.get(full_url, timeout=8.0, follow_redirects=False)
        if 200 <= r.status_code < 300:
            found = True
        elif r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("location", "").lower()
            found = "login" not in location and "signup" not in location
        else:
            found = False
        return {"platform": platform, "url": full_url, "status_code": r.status_code, "found": found}
    except Exception:
        return {"platform": platform, "url": full_url, "status_code": 0, "found": False, "error": "تعذر الوصول"}


async def username_lookup(username: str) -> dict:
    username = username.strip().lstrip("@")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36"
    }
    async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
        results = await asyncio.gather(*[check_platform(client, p, u, username) for p, u in SOCIAL_PLATFORMS.items()])
    found_count = sum(1 for r in results if r.get("found"))
    return {
        "username": username,
        "total_platforms": len(SOCIAL_PLATFORMS),
        "found_count": found_count,
        "results": results,
        "timestamp": datetime.utcnow().isoformat(),
    }


async def enumerate_subdomains(target: str) -> dict:
    domain = normalize_host(target)
    discovered = {}

    async def resolve_candidate(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
            discovered[fqdn] = {
                "host": fqdn,
                "ips": [str(a) for a in answers],
                "source": "dns-bruteforce",
            }
        except Exception:
            return

    await asyncio.gather(*[resolve_candidate(sub) for sub in COMMON_SUBDOMAINS])

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if r.status_code == 200 and r.text.strip():
                entries = r.json()
                for entry in entries[:200]:
                    for name in str(entry.get("name_value", "")).splitlines():
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain):
                            discovered.setdefault(name, {"host": name, "ips": [], "source": "crt.sh"})
    except Exception:
        pass

    return {
        "domain": domain,
        "count": len(discovered),
        "subdomains": sorted(discovered.values(), key=lambda x: x["host"]),
        "timestamp": datetime.utcnow().isoformat(),
    }


async def owasp_top10_scan(target: str) -> dict:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    parsed = urlparse(url)
    findings: List[Dict] = []
    checks = {"base_url": url, "timestamp": datetime.utcnow().isoformat()}

    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
        r = await client.get(url)
        html = r.text
        headers = {k.lower(): v for k, v in r.headers.items()}

        def add(category: str, title: str, severity: str, evidence: str, recommendation: str):
            findings.append({
                "category": category,
                "title": title,
                "severity": severity,
                "evidence": evidence,
                "recommendation": recommendation,
            })

        if parsed.scheme != "https" or "strict-transport-security" not in headers:
            add("A02:2021-Cryptographic Failures", "HTTPS/HSTS weak", "high", "HTTPS only or HSTS is missing", "Force HTTPS and add HSTS with includeSubDomains.")

        if "content-security-policy" not in headers:
            add("A03:2021-Injection", "Missing CSP", "medium", "No Content-Security-Policy header found", "Add a strict CSP to mitigate XSS/injection vectors.")

        if "server" in headers or "x-powered-by" in headers:
            add("A05:2021-Security Misconfiguration", "Technology disclosure", "medium", "Server/X-Powered-By headers disclose implementation details", "Hide or minimize server banners and framework headers.")

        if any(token in html.lower() for token in ["index of /", "directory listing for", "phpinfo()"]):
            add("A05:2021-Security Misconfiguration", "Directory listing or debug page exposed", "high", "Public page appears to expose directory listing or debug info", "Disable directory listing and debug endpoints in production.")

        if re.search(r"apache/[0-1]\.|nginx/1\.[0-9]|php/5\.|openssl/1\.0", " ".join(headers.values()).lower()):
            add("A06:2021-Vulnerable and Outdated Components", "Potentially outdated component banner", "medium", "Response headers expose old server/component versions", "Upgrade exposed components and remove version disclosure.")

        if "<form" in html.lower() and parsed.scheme != "https":
            add("A07:2021-Identification and Authentication Failures", "Login/forms over HTTP", "high", "HTML contains forms while site is not enforced over HTTPS", "Serve authentication and forms over HTTPS only.")

        if "set-cookie" in headers:
            cookie = headers["set-cookie"].lower()
            if "secure" not in cookie or "httponly" not in cookie or "samesite" not in cookie:
                add("A07:2021-Identification and Authentication Failures", "Session cookie flags missing", "medium", "Cookie flags Secure / HttpOnly / SameSite are not fully present", "Set Secure, HttpOnly and SameSite on all session cookies.")

        external_scripts = re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\']', html, re.I)
        if external_scripts and not re.search(r"integrity=", html, re.I):
            add("A08:2021-Software and Data Integrity Failures", "External scripts without SRI", "medium", f"Found {len(external_scripts)} external scripts without visible integrity attributes", "Use Subresource Integrity or self-host trusted assets.")

        if any(keyword in html.lower() for keyword in ["stack trace", "traceback", "exception in thread", "undefined index"]):
            add("A09:2021-Security Logging and Monitoring Failures", "Verbose error leakage", "low", "Verbose runtime errors are visible to end users", "Hide stack traces and centralize internal logging.")

        suspicious_params = re.findall(r'name=["\'](url|target|dest|redirect|callback|webhook)["\']', html, re.I)
        if suspicious_params:
            add("A10:2021-Server-Side Request Forgery", "Potential SSRF entry points", "low", "Forms expose parameters such as url/target/callback/webhook", "Validate and allow-list outbound destinations on the server side.")

        sensitive_paths = ["/admin", "/.git/HEAD", "/backup", "/phpinfo.php"]
        exposed = []
        for path in sensitive_paths:
            try:
                resp = await client.get(urljoin(str(r.url), path))
                if resp.status_code == 200:
                    exposed.append(path)
            except Exception:
                pass
        if exposed:
            add("A01:2021-Broken Access Control", "Sensitive paths exposed", "high", f"These paths responded with HTTP 200: {', '.join(exposed)}", "Restrict access to administration and sensitive resources.")

    score = min(100, sum({"high": 25, "medium": 15, "low": 8}.get(f["severity"], 0) for f in findings))
    return {
        "url": str(r.url),
        "owasp_findings": findings,
        "findings_count": len(findings),
        "risk_score": score,
        "status_code": r.status_code,
        "timestamp": datetime.utcnow().isoformat(),
    }
