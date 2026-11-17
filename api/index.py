from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx

app = FastAPI(title="CyberShield Scanner API", docs_url="/api/docs", openapi_url="/api/openapi.json")

# Allow CORS for development and frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this in production to your Vercel domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "FastAPI security backend is active!"}

import re
from urllib.parse import urlparse, urljoin

SEVERITY_PENALTY = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}


def _issue(id_, title, severity, description, solution):
    return {"id": id_, "title": title, "severity": severity, "description": description, "solution": solution}


def _directive(csp: str, name: str):
    for part in csp.split(";"):
        p = part.strip().lower()
        if p.split(" ")[0] == name:
            return p
    return None


def analyze_headers(headers, is_https: bool, set_cookies=None):
    """headers: httpx.Headers or dict. Returns issues + passed checks for the final response."""
    issues, passed = [], []
    h = {k.lower(): v for k, v in dict(headers).items()}
    set_cookies = set_cookies or []

    # 1. X-XSS-Protection (legacy)
    xss = h.get("x-xss-protection", "").strip()
    if xss.startswith("1"):
        issues.append(_issue("xss_protection", "Outdated X-XSS-Protection Header", "LOW",
            "X-XSS-Protection: 1 enables the removed browser XSS auditor, which itself introduced XS-Search leaks in older browsers.",
            "Set 'X-XSS-Protection: 0' and rely on a strong Content-Security-Policy instead."))
    else:
        passed.append("X-XSS-Protection not enabled (correct modern behaviour)")

    # 2. HSTS (only meaningful over HTTPS)
    hsts = h.get("strict-transport-security", "")
    if is_https:
        if not hsts:
            issues.append(_issue("hsts_missing", "Missing Strict-Transport-Security (HSTS)", "MEDIUM",
                "Without HSTS, a user's first visit (or a typed http:// link) can be downgraded and intercepted on hostile networks.",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:  # 180 days
                issues.append(_issue("hsts_short", "Weak HSTS max-age", "LOW",
                    f"HSTS max-age is only {age} seconds ({age // 86400} days). Short lifetimes leave gaps for downgrade attacks.",
                    "Use max-age of at least 31536000 (1 year)."))
            else:
                passed.append(f"HSTS enforced for {age // 86400} days" + (" incl. subdomains" if "includesubdomains" in hsts.lower() else ""))

    # 3. Server / framework fingerprint
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = h.get(hdr, "").strip()
        if not val:
            continue
        if re.search(r"\d+\.\d+", val):
            issues.append(_issue(f"{hdr}_version_leak", f"Version Disclosure in '{hdr}' Header", "MEDIUM",
                f"The '{hdr}' header discloses an exact software version: '{val}'. Attackers use this to look up known CVEs.",
                "Hide version numbers (e.g. nginx 'server_tokens off', Apache 'ServerTokens Prod', remove X-Powered-By)."))
        elif hdr != "server" or val.lower() in ["apache", "nginx", "iis", "microsoft-iis", "gunicorn", "uvicorn", "tomcat", "express", "php", "openresty", "lighttpd", "jetty", "werkzeug"]:
            issues.append(_issue(f"{hdr}_fingerprint", f"Technology Fingerprint in '{hdr}' Header", "LOW",
                f"The '{hdr}' header reveals the technology stack: '{val}'.",
                "Remove the header or replace it with a generic value."))
    if not any(i["id"].endswith(("_version_leak",)) for i in issues):
        passed.append("No software version numbers disclosed in headers")

    # 4. Content-Security-Policy
    csp = h.get("content-security-policy", "")
    csp_ro = h.get("content-security-policy-report-only", "")
    if not csp:
        issues.append(_issue("csp_missing", "Missing Content-Security-Policy (CSP)", "MEDIUM",
            "No enforced CSP was found" + (" (only a Report-Only policy, which blocks nothing)" if csp_ro else "") +
            ". CSP is the strongest browser-side defence against Cross-Site Scripting (XSS).",
            "Implement a CSP starting with \"default-src 'self'\" (or a nonce-based 'strict-dynamic' policy) and allow only required origins."))
    else:
        script = _directive(csp, "script-src") or _directive(csp, "default-src") or ""
        has_nonce_or_hash = bool(re.search(r"'(nonce-|sha256-|sha384-|sha512-)", script)) or "'strict-dynamic'" in script
        csp_problems = []
        if "'unsafe-inline'" in script and not has_nonce_or_hash:
            issues.append(_issue("csp_unsafe_inline", "CSP Allows Inline Scripts ('unsafe-inline')", "HIGH",
                "script-src allows 'unsafe-inline' without nonces/hashes, so injected inline scripts still execute — the CSP gives little XSS protection.",
                "Remove 'unsafe-inline' from script-src; use nonces or hashes for necessary inline scripts."))
            csp_problems.append(1)
        if "'unsafe-eval'" in script:
            issues.append(_issue("csp_unsafe_eval", "CSP Allows eval() ('unsafe-eval')", "MEDIUM",
                "script-src allows 'unsafe-eval', letting attacker-controlled strings be executed as code.",
                "Remove 'unsafe-eval' and refactor code that uses eval()/new Function()."))
            csp_problems.append(1)
        if re.search(r"(^|\s)(\*|https?:|data:)(\s|$)", script.replace("script-src", "").replace("default-src", "")):
            issues.append(_issue("csp_wildcard", "CSP Allows Scripts From Any Origin", "MEDIUM",
                "script-src contains a wildcard (*, https: or data:), allowing scripts from arbitrary hosts.",
                "List explicit trusted origins or use a nonce-based 'strict-dynamic' policy."))
            csp_problems.append(1)
        if not script:
            issues.append(_issue("csp_no_script", "CSP Does Not Restrict Scripts", "MEDIUM",
                "The CSP has neither script-src nor default-src, so script loading is unrestricted.",
                "Add a script-src or default-src directive."))
            csp_problems.append(1)
        if not csp_problems:
            passed.append("Content-Security-Policy restricts script execution")

    # 5. Clickjacking: X-Frame-Options OR CSP frame-ancestors
    xfo = h.get("x-frame-options", "").strip().upper()
    fa = _directive(csp, "frame-ancestors") if csp else None
    if fa or xfo in ("DENY", "SAMEORIGIN"):
        passed.append("Clickjacking protection active (" + ("CSP frame-ancestors" if fa else f"X-Frame-Options: {xfo}") + ")")
    else:
        issues.append(_issue("clickjacking", "No Clickjacking Protection", "MEDIUM" if set_cookies else "LOW",
            "Neither X-Frame-Options nor CSP frame-ancestors is set, so the site can be embedded in a hidden iframe on an attacker's page (clickjacking).",
            "Add \"Content-Security-Policy: frame-ancestors 'self'\" (or 'X-Frame-Options: DENY')."))

    # 6. X-Content-Type-Options
    if h.get("x-content-type-options", "").strip().lower() == "nosniff":
        passed.append("X-Content-Type-Options: nosniff (MIME sniffing blocked)")
    else:
        issues.append(_issue("nosniff_missing", "Missing X-Content-Type-Options", "LOW",
            "Browsers may MIME-sniff responses, which can turn uploaded files into executable scripts.",
            "Add 'X-Content-Type-Options: nosniff'."))

    # 7. Referrer-Policy
    rp = h.get("referrer-policy", "").strip().lower()
    if not rp:
        issues.append(_issue("referrer_missing", "Missing Referrer-Policy", "LOW",
            "Without a Referrer-Policy, full URLs (which may contain tokens or IDs) can leak to third-party sites in the Referer header on older browsers.",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin'."))
    elif "unsafe-url" in rp:
        issues.append(_issue("referrer_unsafe", "Unsafe Referrer-Policy", "MEDIUM",
            "'unsafe-url' sends the full URL, including paths and query strings, to every site — even over HTTP.",
            "Use 'strict-origin-when-cross-origin' or 'no-referrer'."))
    else:
        passed.append(f"Referrer-Policy set ({rp})")

    # 8. Permissions-Policy
    if h.get("permissions-policy") or h.get("feature-policy"):
        passed.append("Permissions-Policy restricts browser features")
    else:
        issues.append(_issue("permissions_missing", "Missing Permissions-Policy", "INFO",
            "No Permissions-Policy limits access to camera, microphone, geolocation etc. for embedded content.",
            "Add e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."))

    # 9. CORS
    acao = h.get("access-control-allow-origin", "").strip()
    acac = h.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*" and acac == "true":
        issues.append(_issue("cors_wildcard_creds", "Dangerous CORS Configuration", "HIGH",
            "Access-Control-Allow-Origin is '*' together with Allow-Credentials: true — a misconfiguration that signals cross-origin data exposure.",
            "Reflect only an allow-list of trusted origins and never combine credentials with '*'."))
    elif acao == "*":
        issues.append(_issue("cors_wildcard", "Wildcard CORS Policy", "LOW",
            "Any website can read this page's responses via JavaScript. Fine for public assets, risky for pages with user data.",
            "Restrict Access-Control-Allow-Origin to trusted origins if this page serves private data."))

    # 10. Cookies
    weak = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        missing = []
        if is_https and "; secure" not in attrs and not attrs.endswith(";secure") and ";secure;" not in attrs.replace(" ", ""):
            missing.append("Secure")
        is_session = bool(re.search(r"sess|auth|token|sid|jwt|login|remember|csrf|xsrf", name, re.I))
        if is_session and "httponly" not in attrs and not re.search(r"csrf|xsrf", name, re.I):
            missing.append("HttpOnly")  # only session/auth cookies need to be hidden from JavaScript
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            weak.append((name, missing, is_session))
    if weak:
        sev = "MEDIUM" if any(s and ("Secure" in m or "HttpOnly" in m) for _, m, s in weak) else "LOW"
        weak = [(n, m) for n, m, _ in weak]
        detail = "; ".join(f"{n} (missing {', '.join(m)})" for n, m in weak[:5])
        issues.append(_issue("cookie_flags", "Insecure Cookie Attributes", sev,
            f"Cookies are set without recommended protections: {detail}. Missing HttpOnly lets XSS steal them; missing Secure sends them over HTTP; missing SameSite enables CSRF.",
            "Set cookies with 'Secure; HttpOnly; SameSite=Lax' (or Strict)."))
    elif set_cookies:
        passed.append(f"All {len(set_cookies)} cookie(s) use Secure/HttpOnly/SameSite")

    return issues, passed


def compute_grade(issues):
    score = 100 - sum(SEVERITY_PENALTY.get(i["severity"], 0) for i in issues)
    score = max(score, 0)
    if any(i["severity"] == "CRITICAL" for i in issues):
        return "F", min(score, 39)
    for g, cutoff in (("A", 90), ("B", 75), ("C", 60), ("D", 40)):
        if score >= cutoff:
            return g, score
    return "F", score


SCAN_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}


async def _assert_public(host):
    if not host:
        raise HTTPException(status_code=400, detail="Please enter a valid website address, e.g. example.com")
    resolves, public = await _resolve_public(host)
    if not resolves:
        raise HTTPException(status_code=400, detail=f"The domain '{host}' does not exist or has no DNS records.")
    if not public:
        raise HTTPException(status_code=400, detail="Scanning private, local or internal network addresses is not allowed.")


async def _safe_get(url, verify=True, timeout=10.0, max_hops=6):
    """GET that follows redirects manually, re-validating every hop against SSRF."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=verify, headers=SCAN_UA) as client:
        chain = []
        for _ in range(max_hops):
            await _assert_public(urlparse(url).hostname)
            resp = await client.get(url)
            chain.append(url)
            if resp.is_redirect and resp.headers.get("location"):
                url = urljoin(url, resp.headers["location"])
                continue
            return resp, chain
        raise HTTPException(status_code=502, detail="Too many redirects.")


def _tls_error(e: Exception):
    s = str(e)
    if "CERTIFICATE_VERIFY_FAILED" in s or "certificate verify failed" in s:
        m = re.search(r"certificate verify failed: ([^(]+)", s)
        return (m.group(1).strip() if m else "certificate could not be verified")
    return None


@app.get("/api/scan/headers")
async def scan_headers(url: str):
    raw = url.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Please enter a website address.")
    scheme_given = bool(re.match(r"^https?://", raw, re.I))
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) and not scheme_given:
        raise HTTPException(status_code=400, detail="Only http:// and https:// websites can be scanned.")
    target = raw if scheme_given else "https://" + raw
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    await _assert_public(host)

    issues, passed = [], []
    tls_problem = None
    try:
        try:
            response, chain = await _safe_get(target)
        except httpx.TransportError as e:
            tls_problem = _tls_error(e)
            if tls_problem:
                response, chain = await _safe_get(target, verify=False)
            elif not scheme_given:
                # bare domain without working HTTPS -> try plain HTTP
                target = "http://" + raw
                response, chain = await _safe_get(target)
            else:
                raise
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="The website took too long to respond (timed out). It may be offline or blocking scanners.")
    except (httpx.ConnectError, httpx.RemoteProtocolError):
        raise HTTPException(status_code=502, detail="Could not connect to the website. It may be offline or refusing connections.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Scan failed: {type(e).__name__}: {str(e)[:150]}")

    final_url = str(response.url)
    final = urlparse(final_url)
    is_https = final.scheme == "https"
    base_url = f"{final.scheme}://{final.netloc}"

    # --- Transport security ---
    if tls_problem:
        issues.append(_issue("tls_invalid", "Invalid TLS/SSL Certificate", "CRITICAL",
            f"The certificate failed validation ({tls_problem}). Browsers show a full-page security warning, and the connection can be intercepted.",
            "Install a valid certificate from a trusted CA (e.g. free Let's Encrypt) that matches the domain and renew it before expiry."))
    elif is_https:
        passed.append("Valid TLS certificate (trusted CA, hostname matches)")
    if not is_https:
        https_ok = False
        try:
            await _safe_get(f"https://{final.netloc}", timeout=6.0)
            https_ok = True
        except Exception:
            pass
        if https_ok:
            issues.append(_issue("no_https_redirect", "Site Served Over Plain HTTP", "HIGH",
                "The page was delivered over unencrypted HTTP even though HTTPS is available. Everything users send can be read or modified in transit.",
                "Redirect all HTTP traffic to HTTPS (301) and enable HSTS."))
        else:
            issues.append(_issue("no_https", "HTTPS Not Supported", "CRITICAL",
                "The site does not offer HTTPS at all. All traffic, including passwords and cookies, travels in plain text.",
                "Enable HTTPS with a free Let's Encrypt certificate and redirect HTTP to HTTPS."))
    elif not tls_problem:
        # does http:// upgrade to https://?
        try:
            http_resp, _ = await _safe_get(f"http://{final.hostname}", timeout=6.0)
            if str(http_resp.url).startswith("https://"):
                passed.append("HTTP automatically redirects to HTTPS")
            else:
                issues.append(_issue("http_no_redirect", "HTTP Does Not Redirect to HTTPS", "MEDIUM",
                    "Visiting the http:// address serves content without upgrading to HTTPS.",
                    "Add a permanent (301) redirect from HTTP to HTTPS."))
        except Exception:
            passed.append("Plain HTTP port closed (HTTPS only)")

    # --- Headers & cookies ---
    h_issues, h_passed = analyze_headers(response.headers, is_https, response.headers.get_list("set-cookie"))
    issues += h_issues
    passed += h_passed

    # --- Sensitive file exposure probes (run concurrently on the validated host) ---
    probes = [
        ("/.env", lambda t: re.search(r"^[A-Z0-9_]+\s*=", t, re.M) and re.search(r"(DB_|PASSWORD|SECRET|API_KEY|TOKEN|DATABASE)", t, re.I),
         _issue("env_exposed", "Exposed .env File", "CRITICAL", "The environment file is publicly downloadable and usually contains database passwords, API keys and secrets.", "Block access to dotfiles in the web server and rotate every secret in the file immediately.")),
        ("/.git/config", lambda t: "[core]" in t,
         _issue("git_exposed", "Exposed Git Repository", "CRITICAL", "The .git directory is public; attackers can reconstruct the full source code and commit history (often including secrets).", "Deny access to /.git in the web server config and remove it from the web root.")),
        ("/.git/HEAD", lambda t: t.strip().startswith("ref: refs/"),
         _issue("git_head_exposed", "Exposed Git Metadata", "CRITICAL", "/.git/HEAD is publicly readable, confirming an exposed repository.", "Deny access to /.git in the web server config.")),
        ("/.DS_Store", lambda t: "Bud1" in t[:16],
         _issue("ds_store", "Exposed .DS_Store File", "LOW", "macOS .DS_Store files list directory contents, revealing hidden file names.", "Delete .DS_Store files from the server and block them.")),
        ("/server-status", lambda t: "apache server status" in t.lower(),
         _issue("server_status", "Apache server-status Exposed", "MEDIUM", "The server-status page reveals live requests, client IPs and internal URLs.", "Restrict /server-status to localhost.")),
        ("/phpinfo.php", lambda t: "phpinfo()" in t and "php version" in t.lower(),
         _issue("phpinfo", "phpinfo() Page Exposed", "MEDIUM", "phpinfo reveals PHP version, modules, paths and environment variables.", "Delete phpinfo.php from production.")),
        ("/wp-config.php.bak", lambda t: "DB_PASSWORD" in t,
         _issue("wp_config_bak", "WordPress Config Backup Exposed", "CRITICAL", "A backup of wp-config.php is downloadable, exposing database credentials.", "Delete the backup and rotate database credentials.")),
        ("/.well-known/security.txt", lambda t: "contact:" in t.lower(), None),
    ]

    async def run_probe(path, check, issue):
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, verify=False, headers=SCAN_UA) as c:
                r = await c.get(base_url + path)
            if r.status_code != 200:
                return None
            text = r.text[:20000]
            if "<html" in text.lower()[:2000] and issue is not None:
                return None  # soft-404 page, not the real file
            return (path, issue) if check(text) else None
        except Exception:
            return None

    results = await asyncio.gather(*(run_probe(*p) for p in probes))
    found_files = False
    for res in results:
        if not res:
            continue
        path, issue = res
        if issue is None:
            passed.append("security.txt vulnerability-disclosure policy published")
        else:
            issues.append(issue)
            found_files = True
    if not found_files:
        passed.append("No exposed .env, .git, backup or debug files found")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    issues.sort(key=lambda i: order.get(i["severity"], 5))
    grade, score = compute_grade(issues)
    return {
        "url": final_url,
        "requestedUrl": target,
        "redirectChain": chain,
        "status_code": response.status_code,
        "grade": grade,
        "score": score,
        "https": is_https,
        "passedChecks": passed or ["Connection established"],
        "issues": issues,
    }


import random

@app.get("/api/threats/live")
async def get_live_threats():
    """
    Fetches a live OSINT feed of compromised IPs and geolocates a random subset 
    to power the 3D Threat Globe with real-world data safely.
    """
    feed_url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(feed_url)
            if response.status_code != 200:
                raise Exception("Failed to fetch threat feed")
            
            # Parse lines, ignore comments, get valid IPs
            lines = response.text.splitlines()
            ips = [line.strip() for line in lines if line and not line.startswith("#")]
            
            # Pick a random subset of up to 5 IPs to prevent rate limiting on geoip
            sample_size = min(5, len(ips))
            if sample_size == 0:
                return {"threats": []}
                
            selected_ips = random.sample(ips, sample_size)
            
            # Geolocate IPs using ip-api.com (free, keyless, rate limit 45/min)
            threats = []
            for ip in selected_ips:
                geo_resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,query")
                if geo_resp.status_code == 200:
                    geo_data = geo_resp.json()
                    if geo_data.get("status") == "success":
                        threats.append({
                            "ip": geo_data["query"],
                            "city": geo_data.get("city", "Unknown City"),
                            "country": geo_data.get("country", "Unknown"),
                            "lat": geo_data["lat"],
                            "lon": geo_data["lon"]
                        })
                        
            return {"threats": threats}
    except Exception as e:
        print(f"Error fetching live threats: {e}")
        # Return fallback mock data if feed fails
        return {"threats": [
            {"ip": "203.0.113.45", "city": "Moscow", "country": "Russia", "lat": 55.7558, "lon": 37.6173},
            {"ip": "198.51.100.22", "city": "Beijing", "country": "China", "lat": 39.9042, "lon": 116.4074}
        ]}

from pydantic import BaseModel
from bs4 import BeautifulSoup
import joblib
import os

# Load ML Models if they exist
ml_vectorizer = None
ml_model = None
try:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, 'models')
    vec_path = os.path.join(models_dir, 'vectorizer.pkl') if os.path.exists(os.path.join(models_dir, 'vectorizer.pkl')) else 'models/vectorizer.pkl'
    mod_path = os.path.join(models_dir, 'cyber_model.pkl') if os.path.exists(os.path.join(models_dir, 'cyber_model.pkl')) else 'models/cyber_model.pkl'
    ml_vectorizer = joblib.load(vec_path)
    ml_model = joblib.load(mod_path)
    print("AI Models successfully loaded!")
except Exception as e:
    print("Warning: ML models not found or failed to load.", e)

import asyncio
import hashlib
import ipaddress
import json
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

try:
    import phonenumbers
except ImportError:  # pragma: no cover
    phonenumbers = None

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
AUDITOR_UA = "CyberShield-Security-Auditor/2.0"

# =========================================================================
# SCAM / PHISHING DETECTOR
# =========================================================================

# Public suffixes that take two labels (so registered domain = 3 labels)
MULTI_PART_SUFFIXES = {
    "co.in", "net.in", "org.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in", "bank.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.jp", "ne.jp",
    "com.br", "com.cn", "com.sg", "co.za", "com.mx", "co.nz", "com.tr", "com.pk", "com.bd", "co.id", "com.my", "com.ng",
    "com.ar", "com.co", "com.ph", "com.vn", "co.kr", "com.hk", "com.tw", "com.ua", "com.eg", "com.sa",
}

# Brand keyword -> official registered domains
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in", "sbicard.com", "yonobusiness.sbi", "sbilife.co.in", "sbimf.com"],
    "yono": ["sbi.co.in", "onlinesbi.sbi", "yonobusiness.sbi"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcbank.bank.in", "hdfcergo.com", "hdfcfund.com", "hdfcsec.com"],
    "icici": ["icicibank.com", "icicidirect.com", "icicilombard.com", "iciciprulife.com", "icici.bank.in"],
    "axisbank": ["axisbank.com", "axis.bank.in"],
    "kotak": ["kotak.com", "kotaksecurities.com", "kotak.bank.in"],
    "paytm": ["paytm.com", "paytm.in", "paytmbank.com", "paytmmoney.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["google.com"],
    "google": ["google.com", "google.co.in", "google.co.uk", "google.com.au", "google.ca", "google.de", "google.fr", "google.co.jp", "google.com.br","youtube.com", "gmail.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "withgoogle.com"],
    "gmail": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.jobs", "amazonpay.in"],
    "flipkart": ["flipkart.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "azure.com", "windows.net"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com"],
    "office365": ["office.com", "microsoft.com", "microsoftonline.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "telegram": ["telegram.org", "t.me"],
    "linkedin": ["linkedin.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "indiapost": ["indiapost.gov.in"],
    "airtel": ["airtel.in", "airtel.com"],
    "jio": ["jio.com", "ril.com"],
    "bsnl": ["bsnl.co.in"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "steamcommunity": ["steamcommunity.com", "steampowered.com"],
    "myntra": ["myntra.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
}

POPULAR_TRUSTED = {
    "wikipedia.org", "github.com", "x.com", "twitter.com", "reddit.com", "stackoverflow.com", "yahoo.com", "bing.com",
    "duckduckgo.com", "mozilla.org", "cloudflare.com", "openai.com", "anthropic.com", "claude.ai", "npmjs.com", "python.org",
    "nytimes.com", "bbc.com", "bbc.co.uk", "thehindu.com", "ndtv.com", "timesofindia.com", "indiatimes.com", "rbi.org.in", "npci.org.in",
}
TRUSTED_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".mil", ".edu", ".ac.in", ".edu.in", ".gov.uk", ".bank.in")
# Hosts on trusted domains where anyone can publish content (common phishing hosting)
USER_CONTENT_HOSTS = {"sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com", "s3.amazonaws.com"}
FREE_HOSTING_DOMAINS = {
    "github.io", "web.app", "firebaseapp.com", "pages.dev", "vercel.app", "netlify.app", "blogspot.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "glitch.me", "repl.co", "replit.app", "ngrok.io", "ngrok-free.app", "herokuapp.com",
    "webflow.io", "framer.app", "godaddysites.com", "square.site", "carrd.co", "workers.dev", "r2.dev", "surge.sh", "onrender.com",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly", "t.ly", "tiny.cc", "s.id", "v.gd", "shorturl.gg", "bitly.ws"}
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "cc", "work", "click", "link", "buzz", "sbs", "cfd", "icu", "rest", "monster",
    "cyou", "quest", "bond", "lol", "mom", "fit", "loan", "win", "bid", "zip", "mov", "country", "kim", "gdn", "men", "date",
    "review", "stream", "download", "racing", "accountant", "science", "party", "trade", "webcam", "support", "help", "live",
}
MEDIUM_RISK_TLDS = {"info", "online", "site", "shop", "store", "club", "vip", "app", "ru", "su", "pw", "ws", "biz", "today", "space", "website", "tech"}
PHISH_HOST_WORDS = ["login", "signin", "verify", "verification", "secure", "account", "update", "kyc", "reward", "bonus", "wallet",
                    "support", "refund", "unlock", "suspend", "confirm", "billing", "auth", "recovery", "claim", "gift", "prize", "offer", "helpdesk"]

all_brand_domains = {d for ds in BRANDS.values() for d in ds}


def registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_trusted(host: str, reg: str) -> bool:
    if host in USER_CONTENT_HOSTS:
        return False
    return reg in all_brand_domains or reg in POPULAR_TRUSTED or ("." + host).endswith(TRUSTED_SUFFIXES)


LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "!": "i"})


def deleet(s: str) -> str:
    return s.translate(LEET_MAP).replace("rn", "m").replace("vv", "w")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_hits(text: str):
    """Return brands mentioned in a host/path string (with lookalike normalisation)."""
    raw_tokens = [t for t in re.split(r"[^a-z0-9$@!]+", text.lower()) if t]
    hits = {}
    for raw in raw_tokens:
        norm = deleet(raw)
        for brand in BRANDS:
            if len(brand) <= 4:
                matched = norm == brand or norm.startswith(brand) or norm.endswith(brand)
            else:
                matched = brand in norm
            if matched:
                hits[brand] = ("lookalike" if brand not in raw else "exact", raw)
            elif len(brand) >= 6 and len(norm) >= 5:
                # typosquatting: amazom, flipkrt, paypall...
                for piece in {norm, *re.findall(r"[a-z]+", norm)}:
                    if abs(len(piece) - len(brand)) <= 2 and 0 < levenshtein(piece, brand) <= (1 if len(brand) < 8 else 2):
                        hits.setdefault(brand, ("typo", raw))
    return hits


# ---- Threat-intel feed cache (OpenPhish community feed + Phishing Army blocklist) ----
_feed_cache = {"openphish": (0.0, set(), set()), "army": (0.0, set())}
_army_task = None
FEED_TTL = 3600


async def _load_openphish(client):
    ts, urls, hosts = _feed_cache["openphish"]
    if time.time() - ts < FEED_TTL and urls:
        return urls, hosts
    try:
        r = await client.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", timeout=6.0)
        if r.status_code == 200:
            urls = {u.strip().rstrip("/").lower() for u in r.text.splitlines() if u.strip()}
            hosts = {urlparse(u).hostname for u in urls if urlparse(u).hostname}
            _feed_cache["openphish"] = (time.time(), urls, hosts)
    except Exception as e:
        print("OpenPhish feed error:", e)
    return _feed_cache["openphish"][1], _feed_cache["openphish"][2]


async def _refresh_army():
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as c:
            r = await c.get("https://phishing.army/download/phishing_army_blocklist.txt")
            if r.status_code == 200:
                doms = {l.strip().lower() for l in r.text.splitlines() if l.strip() and not l.startswith("#")}
                _feed_cache["army"] = (time.time(), doms)
    except Exception as e:
        print("Phishing Army feed error:", e)


async def _army_domains():
    """Large (~3MB) list: load in background, wait at most a few seconds on first use."""
    global _army_task
    ts, doms = _feed_cache["army"]
    if (time.time() - ts > FEED_TTL or not doms) and (_army_task is None or _army_task.done()):
        _army_task = asyncio.create_task(_refresh_army())
    if not doms and _army_task:
        try:
            await asyncio.wait_for(asyncio.shield(_army_task), timeout=6.0)
        except Exception:
            pass
    return _feed_cache["army"][1]


async def _safe_browsing(client, url):
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return None
    try:
        body = {
            "client": {"clientId": "cybershield", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
            },
        }
        r = await client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=6.0)
        if r.status_code == 200:
            return [m.get("threatType") for m in r.json().get("matches", [])]
    except Exception as e:
        print("Safe Browsing error:", e)
    return None


async def _domain_age_days(client, reg):
    try:
        r = await client.get(f"https://rdap.org/domain/{reg}", timeout=6.0, follow_redirects=True)
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - d).days
    except Exception as e:
        print("RDAP error:", e)
    return None


NAT64_NET = ipaddress.ip_network("64:ff9b::/96")


async def _resolve_public(host):
    """Resolve host; returns (resolves, is_public). Blocks SSRF to internal addresses."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except Exception:
        return False, False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6:
            if ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            elif ip in NAT64_NET:  # DNS64/NAT64 synthesised address -> check the embedded IPv4
                ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True, False
    return True, True


async def _fetch_page(url):
    """Fetch page with TLS verification; fall back to unverified to still inspect content."""
    headers = {"User-Agent": BROWSER_UA, "Accept-Language": "en-US,en;q=0.9"}
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, max_redirects=6) as c:
            r = await c.get(url, headers=headers)
            return r, None
    except httpx.ConnectError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e) or "SSL" in str(e):
            try:
                async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, max_redirects=6, verify=False) as c:
                    r = await c.get(url, headers=headers)
                    return r, "tls_invalid"
            except Exception:
                return None, "tls_invalid"
        return None, "unreachable"
    except Exception:
        return None, "unreachable"


URL_IN_TEXT_RE = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+|\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,24})/[^\s<>\"']*|\b(?:[a-z0-9-]+\.)+(?:com|in|net|org|xyz|top|tk|ml|ga|cf|gq|cc|info|online|site|shop|link|click|live|ly|me|co|io|app|sbs|icu)\b)", re.I)
SINGLE_URL_RE = re.compile(r"^(https?://)?(\[?[a-z0-9.:-]+\]?)(:\d+)?([/?#]\S*)?$", re.I)


def looks_like_url(s: str) -> bool:
    if " " in s or "." not in s:
        return False
    m = SINGLE_URL_RE.match(s)
    if not m:
        return False
    host = m.group(2).strip("[]")
    return is_ip(host) or bool(re.match(r"^([a-z0-9-]+\.)+[a-z][a-z0-9-]{1,23}$", host, re.I))


async def analyze_url(raw_url: str, deep: bool = True):
    score = 5
    flags, tactics, passed = [], [], []

    def flag(points, msg, tactic=None):
        nonlocal score
        score += points
        flags.append(msg)
        if tactic and tactic not in tactics:
            tactics.append(tactic)

    url = raw_url.strip()
    scheme_given = bool(re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I))
    if not scheme_given:
        url = "https://" + url  # users usually paste bare domains; browsers default to https
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return {"score": 50, "flags": ["Could not parse a valid hostname from this URL"], "tactics": ["Malformed URL"], "passed": [], "trusted": False, "feedHit": False, "host": ""}

    try:
        ascii_host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except Exception:
        ascii_host = host
    reg = registered_domain(ascii_host)
    tld = reg.rsplit(".", 1)[-1]
    trusted = is_trusted(ascii_host, reg)
    feed_hit = False

    # --- Static URL structure checks ---
    if parsed.scheme == "http":
        flag(15, "Uses unencrypted http:// — anything typed on this page can be intercepted", "Protocol Downgrade")
    if is_ip(host):
        flag(35, f"Link points to a raw IP address ({host}) instead of a domain name", "IP-Based Hosting")
    if "@" in (parsed.netloc or ""):
        flag(40, "URL contains '@' — text before it is ignored by the browser, a classic trick to disguise the real destination", "URL Obfuscation")
    if not host.isascii() or "xn--" in ascii_host:
        flag(35, f"Internationalised/punycode domain ({ascii_host}) — can display lookalike letters (homograph attack)", "Homograph Attack")
    if not is_ip(host):
        if tld in HIGH_RISK_TLDS:
            flag(20, f"Uses high-abuse top-level domain '.{tld}' (heavily used in phishing campaigns)", "High-Risk TLD")
        elif tld in MEDIUM_RISK_TLDS and not trusted:
            flag(8, f"Uses lower-reputation top-level domain '.{tld}'")
        sub_labels = ascii_host[: -len(reg)].strip(".").split(".") if ascii_host != reg else []
        if len([s for s in sub_labels if s and s != "www"]) >= 3:
            flag(15, f"Excessive subdomain nesting ({ascii_host}) — often used to bury a fake brand name", "Subdomain Abuse")
        if reg.split(".")[0].count("-") >= 2:
            flag(10, f"Domain name '{reg}' contains multiple hyphens (common in throwaway scam domains)")
        if len(ascii_host) > 45:
            flag(8, "Unusually long hostname")
    if reg in URL_SHORTENERS:
        flag(12, f"Link shortener ({reg}) hides the real destination", "Link Masking")
    if reg in FREE_HOSTING_DOMAINS or ascii_host in USER_CONTENT_HOSTS:
        flag(12, f"Hosted on free/user-content platform ({reg}) — anyone can publish here, frequently abused for phishing", "Free Hosting Abuse")

    # Brand impersonation (domain label, subdomains & path)
    if not trusted:
        host_hits = brand_hits(ascii_host)
        path_hits = brand_hits(parsed.path + " " + (parsed.query or ""))
        for brand, (kind, token) in host_hits.items():
            official = ", ".join(BRANDS[brand][:2])
            if kind == "typo":
                flag(45, f"Typosquatting: '{token}' is a misspelling of '{brand}' (official site: {official})", "Lookalike Typosquatting")
            elif kind == "lookalike":
                flag(50, f"Lookalike characters: '{token}' imitates '{brand}' using swapped letters/digits (official site: {official})", "Lookalike Typosquatting")
            else:
                flag(40, f"Uses brand name '{brand}' but is NOT an official {brand} domain (official: {official})", "Brand Impersonation")
            if "Brand Impersonation" not in tactics:
                tactics.append("Brand Impersonation")
            break  # one brand hit is enough to score
        if path_hits and not host_hits:
            brand = next(iter(path_hits))
            flag(15, f"Mentions '{brand}' in the link path while hosted on unrelated domain '{reg}'", "Brand Impersonation")
        words = [w for w in PHISH_HOST_WORDS if w in ascii_host]
        if words:
            flag(min(10 * len(words), 25), f"Hostname contains phishing bait words: {', '.join(words[:4])}", "Credential Bait Keywords")
    else:
        passed.append(f"'{reg}' is a recognised official / high-reputation domain")

    if not deep:
        return {"score": score, "flags": flags, "tactics": tactics, "passed": passed, "trusted": trusted, "feedHit": feed_hit, "host": ascii_host, "reg": reg}

    # --- Live intelligence (run concurrently) ---
    async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": AUDITOR_UA}) as client:
        openphish_t = asyncio.create_task(_load_openphish(client))
        army_t = asyncio.create_task(_army_domains())
        gsb_t = asyncio.create_task(_safe_browsing(client, url))
        age_t = asyncio.create_task(_domain_age_days(client, reg)) if not is_ip(host) else None
        resolve_t = asyncio.create_task(_resolve_public(ascii_host))

        resolves, public = await resolve_t
        page, fetch_err = (None, None)
        if not resolves:
            flag(15, f"Domain '{ascii_host}' does not resolve — fake, unregistered or already taken down", "Dead / Disposable Domain")
        elif not public:
            fetch_err = "private"
            flag(20, "Host resolves to a private/internal network address — not a legitimate public website")
        else:
            page, fetch_err = await _fetch_page(url)
            if fetch_err == "unreachable" and not scheme_given:
                http_page, http_err = await _fetch_page("http://" + url.split("://", 1)[1])
                if http_page is not None:
                    page, fetch_err = http_page, None
                    flag(10, "Site does not support HTTPS at all", "Protocol Downgrade")

        (op_urls, op_hosts), army = await openphish_t, await army_t
        gsb = await gsb_t
        age = await age_t if age_t else None

    # Threat feeds
    norm_url = url.rstrip("/").lower()
    final_url = str(page.url) if page is not None else url
    final_host = (urlparse(final_url).hostname or ascii_host).lower()
    candidates_hosts = {ascii_host, final_host}
    if any(u in op_urls for u in {norm_url, final_url.rstrip("/").lower()}) or any(h in op_hosts and not is_trusted(h, registered_domain(h)) for h in candidates_hosts):
        feed_hit = True
        flag(90, "LISTED in the OpenPhish live phishing feed — confirmed active phishing site", "Known Phishing (Threat Feed)")
    if any((h in army or registered_domain(h) in army) and not is_trusted(h, registered_domain(h)) for h in candidates_hosts):
        feed_hit = True
        flag(90, "LISTED in the Phishing Army blocklist — reported phishing domain", "Known Phishing (Threat Feed)")
    if gsb:
        feed_hit = True
        flag(90, f"Flagged by Google Safe Browsing ({', '.join(sorted(set(gsb)))})", "Known Malicious (Safe Browsing)")
    elif gsb == []:
        passed.append("Not flagged by Google Safe Browsing")
    if not feed_hit:
        passed.append(f"Not present in live phishing feeds (OpenPhish{', Phishing Army' if army else ''})")

    # Domain age
    if age is not None:
        if age < 30:
            flag(35, f"Domain was registered only {age} day(s) ago — most phishing domains are under a month old", "Newly Registered Domain")
        elif age < 180:
            flag(18, f"Domain is young ({age} days old)", "Newly Registered Domain")
        elif age > 730:
            score -= 10
            passed.append(f"Domain has existed for {age // 365} years")

    # TLS + redirects
    if fetch_err == "tls_invalid":
        flag(40, "TLS/SSL certificate is invalid, expired or does not match the domain — your browser would show a security warning", "Invalid Certificate")
    elif page is not None and final_url.startswith("https://"):
        passed.append("Valid TLS certificate")
    if fetch_err == "unreachable" and resolves:
        flags.append("Site did not respond — content could not be inspected")
    final_reg = registered_domain(final_host)
    if page is not None and final_reg != reg:
        if is_trusted(final_host, final_reg) and not trusted and reg not in URL_SHORTENERS:
            flags.append(f"Redirects to {final_host}")
        elif not is_trusted(final_host, final_reg):
            flag(15, f"Redirects to a different domain: {final_host}", "Redirect Chain")
            for brand, (kind, token) in brand_hits(final_host).items():
                flag(35, f"Final destination '{final_host}' impersonates '{brand}'", "Brand Impersonation")
                break

    # --- Page content inspection (skip for trusted official domains) ---
    final_trusted = is_trusted(final_host, final_reg)
    if page is not None and not final_trusted and "html" in page.headers.get("content-type", "html"):
        try:
            soup = BeautifulSoup(page.text[:2_000_000], "html.parser")
            title = (soup.title.get_text(" ", strip=True) if soup.title else "")[:200]
            text = soup.get_text(" ", strip=True).lower()[:200_000]
            pw_fields = soup.find_all("input", attrs={"type": re.compile("password", re.I)})
            sensitive_inputs = soup.find_all("input", attrs={"name": re.compile(r"otp|pin|cvv|card|aadhaar|pan|upi|mpin|ssn|account", re.I)})

            title_brands = brand_hits(title)
            if title_brands and (pw_fields or sensitive_inputs):
                b = next(iter(title_brands))
                flag(40, f"Page titled '{title[:60]}' presents a {b} login/payment form but is hosted on {final_reg}", "Credential Harvesting")
            elif pw_fields and (flags or (age is not None and age < 365)):
                flag(15, "Page asks for a password on an unverified domain", "Credential Harvesting")
            if sensitive_inputs:
                names = sorted({(i.get("name") or "").lower() for i in sensitive_inputs})[:4]
                flag(20, f"Page collects sensitive financial/identity fields ({', '.join(names)})", "Credential Harvesting")
            if final_url.startswith("http://") and pw_fields:
                flag(30, "Password field served over unencrypted HTTP", "Credential Harvesting (Unencrypted)")

            for form in soup.find_all("form"):
                action = (form.get("action") or "").strip()
                if action.startswith(("http://", "https://")):
                    ah = (urlparse(action).hostname or "").lower()
                    if ah and registered_domain(ah) != final_reg and not is_trusted(ah, registered_domain(ah)):
                        flag(25, f"Form submits data to a different domain ({ah})", "Data Exfiltration Form")
                        break
                if action.lower().startswith("mailto:") or "api.telegram.org" in action.lower():
                    flag(35, "Form sends entered data to email/Telegram — typical of phishing kits", "Data Exfiltration Form")
                    break
            if "api.telegram.org/bot" in page.text:
                flag(35, "Page script posts data to a Telegram bot — typical of phishing kits", "Data Exfiltration Form")

            if re.search(r"\b(claim|collect)\b.{0,40}\b(prize|reward|bonus|cashback|gift)\b|\b(you have won|congratulations[, ]+you|lucky winner)\b", text):
                flag(15, "Page uses prize/reward lures", "Financial Bait (Scraped)")
            if re.search(r"\b(account (has been |will be )?(suspended|blocked|locked)|verify (your )?kyc|kyc (update|pending|expired)|within 24 hours|immediate action)\b", text):
                flag(15, "Page uses urgency/suspension panic triggers", "Urgency Trigger (Scraped)")
            if re.search(r"\b(guaranteed|double your|risk[- ]free)\b.{0,40}\b(returns?|profit|investment|crypto|bitcoin)\b", text):
                flag(20, "Promises guaranteed / risk-free investment returns", "Investment Fraud")
            for img in soup.find_all("img"):
                src = (img.get("src") or "").lower()
                if ("norton" in src or "mcafee" in src) and not img.find_parent("a"):
                    flag(10, "Unlinked 'Norton/McAfee secured' badge image (fake trust seal)", "Fake Trust Indicators")
                    break
        except Exception as e:
            print("Content inspection error:", e)

    if trusted and not feed_hit:
        score = min(score, 10)
    return {"score": max(score, 0), "flags": flags, "tactics": tactics, "passed": passed, "trusted": trusted,
            "feedHit": feed_hit, "host": ascii_host, "reg": reg, "ageDays": age, "finalUrl": final_url}


def analyze_text_heuristics(text: str):
    t = text.lower()
    score, flags, tactics = 8, [], ["Linguistic Heuristics"]

    def rule(pattern, points, msg, tactic):
        nonlocal score
        if re.search(pattern, t):
            score += points
            flags.append(msg)
            if tactic not in tactics:
                tactics.append(tactic)

    if not re.search(r"\b(do not|don't|dont|never)\s+(share|disclose|tell)\b", t):  # genuine OTP SMS say "do not share"
        rule(r"\b(otp|one[- ]time password|verification code|m?pin|cvv)\b.{0,60}\b(share|send|tell|provide|give|enter)\b|\b(share|send|tell|provide|give)\b.{0,60}\b(otp|verification code|m?pin|cvv)\b",
             25, "Asks you to share OTP / PIN / CVV — no bank or company ever asks for these", "Credential Harvesting")
    rule(r"\b(suspend(ed)?|block(ed)?|deactivat\w*|disconnect\w*|terminat\w*|power cut|frozen|freeze)\b", 20, "Threatens account/service suspension or disconnection", "Urgency Trigger")
    rule(r"\b(urgent|immediately|within \d+ ?(hours?|hrs|minutes?|mins)|today only|last (chance|warning)|tonight)\b", 12, "Creates artificial time pressure", "Urgency Trigger")
    rule(r"\b(kyc|pan ?card|aadhaar|pension|subsidy|income tax|it department|customs|police|cbi|narcotics|court|rbi)\b", 15, "Invokes government/bank authority (KYC, Aadhaar, Police, Customs...)", "Authority Impersonation")
    rule(r"\b(lottery|jackpot|you (have )?won|winner|cash ?back|reward|bonus|refund|prize|free gift|lucky draw)\b", 22, "Offers unexpected money, prizes or refunds", "Financial Bait")
    rule(r"\b(processing|registration|delivery|customs|clearance) (fee|charge)s?\b|\bpay (rs\.?|inr|₹)\s?\d+", 20, "Demands a small upfront fee to release money/parcel", "Advance-Fee Fraud")
    rule(r"\b(work from home|part[- ]time job|earn (rs\.?|₹|\$)?\s?\d+.{0,20}(daily|per day|a day)|lik(e|ing) (youtube )?videos?|task[- ]based|prepaid task)\b", 30, "Too-good-to-be-true job / task offer", "Job Scam")
    rule(r"\b(contact|message|ping|join|reply)\b.{0,25}\b(on |via )?(telegram|whatsapp)\b|\bt\.me/|wa\.me/", 12, "Moves the conversation to Telegram/WhatsApp", "Off-Platform Contact")
    rule(r"\b(bitcoin|crypto|usdt|forex|trading)\b.{0,60}\b(profit|returns?|double|guaranteed)\b", 25, "Promises crypto/trading returns", "Investment Fraud")
    rule(r"\b(anydesk|teamviewer|quicksupport|rustdesk|screen ?share)\b", 30, "Asks you to install remote-access software", "Remote Access Scam")
    rule(r"\bdigital arrest\b|\b(arrest|warrant|fir)\b.{0,40}\b(your|you)\b", 30, "Threatens arrest / legal action", "Intimidation")
    rule(r"\b(click|tap|open|visit)\b.{0,30}\b(link|here|below)\b", 10, "Pushes you to click a link", "Call to Action")
    rule(r"\*\d{2,3}\*|\b(dial|call) \*?\d{3,}#?", 15, "Asks you to dial a USSD/forwarding code (call-forwarding hijack)", "Call-Forwarding Hijack")
    rule(r"\b(dear (customer|user|sir/madam)|valued customer)\b", 5, "Generic greeting instead of your name", "Generic Greeting")
    strong = [f for f in flags if not f.startswith("Generic")]
    if len(strong) >= 2:
        score += min(10 * (len(strong) - 1), 30)  # independent scam signals reinforce each other
    return score, flags, tactics


# =========================================================================
class ScamAnalysisRequest(BaseModel):
    text: str


@app.post("/api/analyze/scam")
async def analyze_scam(req: ScamAnalysisRequest):
    input_text = req.text.strip()[:5000]
    if not input_text:
        raise HTTPException(status_code=400, detail="Input cannot be empty")
    is_url = looks_like_url(input_text)

    tactics, red_flags, passed = [], [], []
    ml_confidence = 0
    if is_url:
        res = await analyze_url(input_text, deep=True)
        scam_prob = res["score"]
        red_flags, tactics, passed = res["flags"], ["Domain & DOM Inspection"] + res["tactics"], res["passed"]
        age_txt = f" Domain age: {res['ageDays']} days." if res.get("ageDays") is not None else ""
        explanation = (f"URL audit for '{res['host']}' (registered domain: {res.get('reg', '')}). Checked live phishing feeds, "
                       f"brand impersonation & typosquatting, domain age (RDAP), TLS certificate, redirects and the live page's forms/content.{age_txt}")
        feed_hit = res["feedHit"]
    else:
        scam_prob, red_flags, tactics = analyze_text_heuristics(input_text)
        feed_hit = False
        explanation = "Message analysed with scam-language heuristics and the ML text classifier."
        # Analyse any links inside the message
        text_score = scam_prob
        links = list(dict.fromkeys(m.group(0).rstrip(".,);!'\"") for m in URL_IN_TEXT_RE.finditer(input_text)))[:3]
        link_scores = []
        for i, link in enumerate(links):
            res = await analyze_url(link, deep=(i == 0))
            feed_hit = feed_hit or res["feedHit"]
            link_scores.append(res["score"])
            red_flags += [f"Link {res['host']}: {f}" for f in res["flags"]]
            tactics += [t for t in res["tactics"] if t not in tactics]
            if res["trusted"]:
                passed.append(f"Link {res['host']} points to an official domain")
        if links:
            explanation += f" Also inspected {len(links)} embedded link(s)."
            worst = max(link_scores)
            scam_prob = max(text_score, worst)
            if text_score >= 30 and worst >= 30:
                scam_prob += 15  # scary message + shady link is the classic smishing combo
            elif text_score >= 30 and all(s <= 10 for s in link_scores):
                scam_prob -= 10  # message only links to official domains

        # Tier 2: ML classifier (trained on SMS-style text, so only used for messages)
        if ml_vectorizer is not None and ml_model is not None:
            try:
                prob = ml_model.predict_proba(ml_vectorizer.transform([input_text]))[0][1]
                ml_confidence = int(prob * 100)
                if ml_confidence > 60:
                    red_flags.append(f"AI text classifier detected scam phrasing ({ml_confidence}% confidence)")
                    tactics.append("AI Pattern Match")
                    scam_prob += int((ml_confidence - 50) * 0.5)
            except Exception as e:
                print("ML Inference Error:", e)
            explanation += f" ML contextual confidence: {ml_confidence}%."

    if feed_hit:
        scam_prob = max(scam_prob, 95)
    scam_prob = max(1, min(int(scam_prob), 99))

    if scam_prob >= 70:
        verdict, urgency = "SCAM", "CRITICAL"
        recommendation = ("DO NOT OPEN OR ENTER ANY DETAILS. This site shows strong phishing/scam indicators. If you already entered a password or card/UPI details, change them and call your bank immediately (India cyber-fraud helpline: 1930, cybercrime.gov.in)."
                          if is_url else "DO NOT CLICK ANY LINKS, REPLY OR CALL BACK. Block and report the sender (India: report on Sanchar Saathi 'Chakshu' or call 1930).")
    elif scam_prob >= 35:
        verdict, urgency = "SUSPICIOUS", "HIGH"
        recommendation = ("Proceed with caution. Do not log in or pay through this link — type the official website address yourself instead."
                          if is_url else "Do not share OTPs or click links. Verify by contacting the organisation through its official number/app.")
    else:
        verdict, urgency = "SAFE", "LOW"
        recommendation = ("No significant risk indicators found. Still verify the address bar before entering passwords."
                          if is_url else "No strong scam indicators found. Stay cautious with any request for money, OTPs or personal data.")
        if not red_flags:
            red_flags = passed or ["No scam indicators detected"]

    return {
        "scamProbability": scam_prob,
        "verdict": verdict,
        "manipulationTactics": list(dict.fromkeys(tactics)),
        "redFlags": red_flags,
        "passedChecks": passed,
        "recommendation": recommendation,
        "explanation": explanation,
        "urgencyLevel": urgency,
    }


# =========================================================================
# CREDENTIAL LEAK AUDITOR (XposedOrNot + LeakCheck public index + HIBP Pwned Passwords)
# =========================================================================

def _norm_breach_name(name: str) -> str:
    n = (name or "").lower()
    n = re.sub(r"\.(com|net|org|ru|in|io|co|br|de|fr|uk|cn|jp|me|tv|info|biz|es|it|pl|nl|kr|vn|id|us|ca|au)\b", "", n)
    return re.sub(r"[^a-z0-9]", "", n)


_CATALOG = None


def _breach_catalog():
    """Index of the bundled XposedOrNot breach catalog (data classes, dates, record counts)."""
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = {}
        try:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "breach_catalog.json")
            with open(path, encoding="utf-8") as f:
                for b in json.load(f).get("exposedBreaches", []):
                    _CATALOG.setdefault(_norm_breach_name(b.get("breachID", "")), b)
                    if b.get("domain"):
                        _CATALOG.setdefault(_norm_breach_name(b["domain"]), b)
        except Exception as e:
            print("Breach catalog load error:", e)
    return _CATALOG


async def _xon_details(client, names):
    """Fetch details for breaches missing from the bundled catalog."""
    out = {}
    async def one(n):
        try:
            r = await client.get("https://api.xposedornot.com/v1/breaches", params={"breach_id": n}, timeout=6.0)
            if r.status_code == 200:
                lst = r.json().get("exposedBreaches") or []
                if lst:
                    out[_norm_breach_name(n)] = lst[0]
        except Exception:
            pass
    await asyncio.gather(*(one(n) for n in names[:15]))
    return out


SENSITIVE_CLASSES = ["password", "credit card", "bank", "passport", "social security", "ssn", "government issued", "aadhaar",
                     "security questions", "pan", "financial", "partial credit", "auth tokens", "private messages", "health", "biometric"]
PERSONAL_CLASSES = ["phone", "address", "date of birth", "dob", "geographic", "ip address", "physical", "gender", "names", "employer"]


def _rate(classes):
    low = " ".join(c.lower() for c in classes)
    if any(k in low for k in SENSITIVE_CLASSES):
        return "CRITICAL"
    if any(k in low for k in PERSONAL_CLASSES):
        return "HIGH"
    return "MEDIUM"


def _recommend(classes, name):
    low = " ".join(c.lower() for c in classes)
    tips = []
    if "password" in low:
        tips.append(f"Change your {name} password and every site where you reused it; turn on 2FA")
    if "phone" in low:
        tips.append("expect targeted SMS/WhatsApp scams and never share OTPs")
    if any(k in low for k in ["credit card", "bank", "financial", "upi"]):
        tips.append("watch bank statements and consider re-issuing the card")
    if any(k in low for k in ["aadhaar", "passport", "government", "pan"]):
        tips.append("lock Aadhaar biometrics via mAadhaar and monitor for identity misuse")
    if "address" in low or "date of birth" in low:
        tips.append("be wary of callers who 'verify' your address/DOB")
    if not tips:
        tips.append(f"Change your password on {name} if you still use it and watch for phishing emails referencing it")
    s = "; ".join(tips)
    return s[0].upper() + s[1:] + "."


async def _query_xon(client, email):
    try:
        r = await client.get(f"https://api.xposedornot.com/v1/check-email/{email}", timeout=8.0)
        if r.status_code == 404:
            return {"ok": True, "names": []}
        if r.status_code == 200:
            d = r.json()
            if d.get("Error") == "Not found":
                return {"ok": True, "names": []}
            names = []
            for item in d.get("breaches", []):
                names.extend(item if isinstance(item, list) else [item])
            return {"ok": True, "names": [n for n in names if isinstance(n, str)]}
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e) or type(e).__name__}


async def _query_leakcheck(client, query):
    try:
        r = await client.get("https://leakcheck.io/api/public", params={"check": query}, timeout=8.0)
        d = r.json() if r.headers.get("content-type", "").startswith("application/json") or r.text.startswith("{") else {}
        if d.get("success"):
            return {"ok": True, "found": d.get("found", 0), "fields": d.get("fields", []), "sources": d.get("sources", [])}
        if str(d.get("error", "")).lower() == "not found":
            return {"ok": True, "found": 0, "fields": [], "sources": []}
        return {"ok": False, "error": d.get("error") or f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e) or type(e).__name__}


async def _query_hudsonrock(client, email):
    """Hudson Rock Cavalier (free): is this email in info-stealer malware logs?"""
    try:
        r = await client.get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
                             params={"email": email}, timeout=8.0)
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        return {"ok": True, "stealers": r.json().get("stealers") or []}
    except Exception as e:
        return {"ok": False, "error": str(e) or type(e).__name__}


async def _query_comb(client, email):
    """ProxyNova COMB search (free). Its search is fuzzy, so only EXACT login matches are counted.
    The returned lines contain plaintext passwords: they are counted and immediately discarded, never returned or logged."""
    try:
        r = await client.get("https://api.proxynova.com/comb", params={"query": email, "start": 0, "limit": 100}, timeout=10.0)
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        lines = r.json().get("lines") or []
        exact = sum(1 for ln in lines if ln.split(":", 1)[0].strip().lower() == email)
        del lines
        return {"ok": True, "exact": exact}
    except Exception as e:
        return {"ok": False, "error": str(e) or type(e).__name__}


def _stealer_matches(stealers):
    """One combined card for all infections (computer names / IPs are deliberately not exposed)."""
    if not stealers:
        return []
    dates = sorted(d for d in ((s.get("date_compromised") or "")[:10] for s in stealers) if d)
    latest = dates[-1] if dates else None
    services = sum((s.get("total_user_services") or 0) + (s.get("total_corporate_services") or 0) for s in stealers)
    n = len(stealers)
    return [{
        "source": f"Info-stealer malware: {n} infected computer{'s' if n != 1 else ''}" + (f" (latest {latest})" if latest else ""),
        "breachName": "Hudson Rock info-stealer logs",
        "date": latest[:7] if latest else None,
        "domain": None, "records": None, "description": None,
        "leakType": f"Saved browser passwords, cookies & autofill stolen from infected device(s) ({services} logins captured)",
        "exposedData": ["Passwords", "Browser cookies", "Autofill data", "Device information"],
        "riskRating": "CRITICAL",
        "recommendations": "A computer where you logged in with this email was infected by password-stealing malware. Run a full antivirus scan "
                           "(or reinstall Windows), then change ALL saved passwords from a clean device, log out of all sessions, and enable 2FA everywhere.",
        "foundIn": ["Hudson Rock"],
    }]


def _comb_match(exact):
    return {
        "source": "COMB (Compilation of Many Breaches) credential list",
        "breachName": "COMB", "date": "2021-02", "domain": None, "records": 3_200_000_000, "description": None,
        "leakType": f"Email + plaintext password pairs ({exact}{'+' if exact >= 100 else ''} entries)",
        "exposedData": ["Email addresses", "Passwords"],
        "riskRating": "CRITICAL",
        "recommendations": "Your email appears with plaintext passwords in a public combo list used for credential-stuffing. "
                           "Change any password you have used with this email (especially old ones), and never reuse passwords.",
        "foundIn": ["ProxyNova COMB"],
    }


def _build_matches(xon_names, lc_sources, details):
    catalog = _breach_catalog()
    merged = {}
    for n in xon_names:
        merged.setdefault(_norm_breach_name(n), {"name": n, "date": None, "via": {"XposedOrNot"}})
    for s in lc_sources:
        key = _norm_breach_name(s.get("name", ""))
        if not key:
            continue
        entry = merged.setdefault(key, {"name": s.get("name"), "date": s.get("date") or None, "via": set()})
        entry["via"].add("LeakCheck")
        entry["date"] = entry["date"] or s.get("date") or None

    matches = []
    for key, e in merged.items():
        info = catalog.get(key) or details.get(key)
        classes = (info or {}).get("exposedData") or []
        date = e["date"] or ((info or {}).get("breachedDate") or "")[:7] or None
        rating = _rate(classes) if classes else "HIGH"
        if info and info.get("passwordRisk") in ("plaintext", "easytocrack"):
            rating = "CRITICAL"
        matches.append({
            "source": f"{e['name']}" + (f" ({date})" if date and date[:4] not in e["name"] else ""),
            "breachName": e["name"],
            "date": date,
            "domain": (info or {}).get("domain") or None,
            "records": (info or {}).get("exposedRecords"),
            "description": (info or {}).get("exposureDescription"),
            "leakType": ", ".join(classes) if classes else "Data classes not disclosed by the public index (assume email/phone + password)",
            "exposedData": classes,
            "passwordRisk": (info or {}).get("passwordRisk"),
            "riskRating": rating,
            "recommendations": _recommend(classes or ["password"], (info or {}).get("domain") or e["name"]),
            "foundIn": sorted(e["via"]),
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    matches.sort(key=lambda m: (order.get(m["riskRating"], 3), -(int((m["date"] or "0")[:4]) if (m["date"] or "")[:4].isdigit() else 0)))
    return matches


def _result(target, typ, matches, sources_checked, extra_fields=None, extra=None):
    any_ok = any(s["ok"] for s in sources_checked)
    if not any_ok:
        return {
            "status": "error", "target": target, "type": typ, "breached": None, "verified": False, "count": 0,
            "riskScore": None, "matches": [], "sourcesChecked": sources_checked,
            "summary": "Could not reach the breach databases right now — this result is UNVERIFIED. Please retry in a minute.",
        }
    exposed = sorted({c for m in matches for c in m["exposedData"]} | set(extra_fields or []))
    failed = [s["name"] for s in sources_checked if not s["ok"]]
    note = f" (Note: {', '.join(failed)} unavailable — results may be incomplete.)" if failed else ""
    checked = ", ".join(s["name"] for s in sources_checked if s["ok"])
    confirmed = [m for m in matches if not m.get("possibleMatch")]
    possible = [m for m in matches if m.get("possibleMatch")]
    if matches:
        crit = sum(m["riskRating"] == "CRITICAL" for m in confirmed)
        pw = any("password" in c.lower() for m in confirmed for c in m["exposedData"])
        score = min(98, 45 + 4 * len(confirmed) + 2 * len(possible) + 3 * crit + (15 if pw else 0)) if confirmed else min(70, 35 + 2 * len(possible))
        parts = []
        if confirmed:
            parts.append(f"Found in {len(confirmed)} data breach{'es' if len(confirmed) != 1 else ''} ({crit} critical)")
        if possible:
            parts.append(f"{len(possible)} possible match{'es' if len(possible) != 1 else ''} where the number was stored without a country code (could belong to a same-digit number in another country)")
        summary = " + ".join(parts) + f". Checked: {checked}." + note
    else:
        score = 8
        summary = (f"Not found in the databases we checked ({checked}). This does NOT guarantee your data was never leaked: "
                   "many leaks are never made public or indexed." + note)
    res = {
        "status": "success", "target": target, "type": typ, "breached": bool(matches), "verified": True,
        "count": len(matches), "riskScore": score, "matches": matches, "exposedDataTypes": exposed,
        "sourcesChecked": sources_checked, "summary": summary,
    }
    res.update(extra or {})
    return res


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class CredentialCheckRequest(BaseModel):
    target: str
    mode: Optional[str] = "auto"


@app.api_route("/api/check/credential", methods=["GET", "POST"])
async def check_credential(req: Optional[CredentialCheckRequest] = None, target: Optional[str] = None, mode: Optional[str] = "auto"):
    search_target = (req.target if req else target) or ""
    det_mode = ((req.mode if req else mode) or "auto").lower()
    clean = search_target.strip()
    if not clean:
        return {"status": "error", "message": "Search target cannot be empty", "breached": None, "matches": [], "summary": "Search target cannot be empty."}

    if det_mode == "auto":
        digits = re.sub(r"\D", "", clean)
        if "@" in clean and " " not in clean:
            det_mode = "email"
        elif re.fullmatch(r"\+?[\d\s\-().]{7,22}", clean) and 7 <= len(digits) <= 15:
            det_mode = "phone"
        else:
            det_mode = "password"

    async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": AUDITOR_UA}) as client:
        # 1. EMAIL
        if det_mode == "email":
            email = clean.lower()
            if not EMAIL_RE.match(email):
                return {"status": "error", "type": "email", "target": clean, "breached": None, "matches": [], "summary": "That does not look like a valid email address."}
            xon, lc, hr, comb = await asyncio.gather(_query_xon(client, email), _query_leakcheck(client, email),
                                                     _query_hudsonrock(client, email), _query_comb(client, email))
            xon_names = xon.get("names", []) if xon["ok"] else []
            lc_sources = lc.get("sources", []) if lc["ok"] else []
            catalog = _breach_catalog()
            missing = [n for n in xon_names if _norm_breach_name(n) not in catalog]
            details = await _xon_details(client, missing) if missing else {}
            stealer = _stealer_matches(hr.get("stealers", [])) if hr["ok"] else []
            comb_hit = [_comb_match(comb["exact"])] if comb["ok"] and comb["exact"] else []
            matches = stealer + comb_hit + _build_matches(xon_names, lc_sources, details)
            sources = [
                {"name": "XposedOrNot", "ok": xon["ok"], "found": len(xon_names), **({"error": xon["error"]} if not xon["ok"] else {})},
                {"name": "LeakCheck", "ok": lc["ok"], "found": lc.get("found", 0), **({"error": lc["error"]} if not lc["ok"] else {})},
                {"name": "Hudson Rock (info-stealers)", "ok": hr["ok"], "found": len(hr.get("stealers", [])), **({"error": hr["error"]} if not hr["ok"] else {})},
                {"name": "COMB combo list", "ok": comb["ok"], "found": comb.get("exact", 0), **({"error": comb["error"]} if not comb["ok"] else {})},
            ]
            extra_fields = [f.replace("_", " ").title() for f in lc.get("fields", [])] if lc["ok"] else []
            return _result(clean, "email", matches, sources, extra_fields,
                           {"totalRecordsIndexed": lc.get("found", 0) if lc["ok"] else None})

        # 2. PHONE
        if det_mode == "phone":
            e164 = None
            region_info = {}
            if phonenumbers:
                try:
                    num = phonenumbers.parse(clean, None if clean.startswith("+") else "IN")
                    if not phonenumbers.is_possible_number(num):
                        return {"status": "error", "type": "phone", "target": clean, "breached": None, "matches": [],
                                "summary": "That phone number is not a possible number. Include the country code, e.g. +91 98765 43210."}
                    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
                    from phonenumbers import geocoder, carrier
                    region_info = {"region": geocoder.description_for_number(num, "en") or None,
                                   "carrier": carrier.name_for_number(num, "en") or None,
                                   "validNumber": phonenumbers.is_valid_number(num)}
                except Exception:
                    return {"status": "error", "type": "phone", "target": clean, "breached": None, "matches": [],
                            "summary": "Could not parse that phone number. Include the country code, e.g. +91 98765 43210."}
            else:
                digits = re.sub(r"\D", "", clean)
                e164 = "+" + (digits if clean.startswith("+") or len(digits) > 10 else "91" + digits)
            full_digits = e164.lstrip("+")
            national = str(num.national_number) if phonenumbers else full_digits[-10:]
            # Many leaks (especially Indian ones) store numbers without the country code, so search both forms.
            search_national = national != full_digits and len(national) >= 8
            lc, lc_nat = await asyncio.gather(
                _query_leakcheck(client, full_digits),
                _query_leakcheck(client, national) if search_national else asyncio.sleep(0, result=None),
            )

            def fields_of(res):
                return [f.replace("_", " ").title() for f in res.get("fields", [])] if res and res["ok"] else []

            def fill(ms, fields, note=""):
                for m in ms:
                    if not m["exposedData"] and fields:
                        m["exposedData"] = fields
                        m["leakType"] = ", ".join(fields) + f" (combined fields across leaks{note})"
                        m["riskRating"] = _rate(fields)
                        m["recommendations"] = _recommend(fields, m["breachName"])
                return ms

            matches = fill(_build_matches([], lc.get("sources", []) if lc["ok"] else [], {}), fields_of(lc))
            seen = {_norm_breach_name(m["breachName"]) for m in matches}
            sources = [{"name": f"LeakCheck (+{full_digits})", "ok": lc["ok"], "found": lc.get("found", 0), **({"error": lc["error"]} if not lc["ok"] else {})}]
            if lc_nat is not None:
                nat_sources = [s for s in (lc_nat.get("sources", []) if lc_nat["ok"] else []) if _norm_breach_name(s.get("name", "")) not in seen]
                possible = fill(_build_matches([], nat_sources, {}), fields_of(lc_nat), "; number stored without country code")
                for m in possible:
                    m["possibleMatch"] = True
                    m["source"] += " (possible match)"
                    m["foundIn"] = [f"LeakCheck ({national}, no country code)"]
                    if m["riskRating"] == "CRITICAL":
                        m["riskRating"] = "HIGH"  # not certain it's this person's number
                matches += possible
                sources.append({"name": f"LeakCheck ({national})", "ok": lc_nat["ok"], "found": lc_nat.get("found", 0), **({"error": lc_nat["error"]} if not lc_nat["ok"] else {})})
            return _result(e164, "phone", matches, sources, fields_of(lc), {"normalized": e164, **region_info,
                           "totalRecordsIndexed": lc.get("found", 0) if lc["ok"] else None})

        # 3. PASSWORD (k-anonymity: only the first 5 SHA-1 chars leave the server)
        sha1 = hashlib.sha1(clean.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"}, timeout=8.0)
            if resp.status_code != 200:
                raise Exception(f"HTTP {resp.status_code}")
            count = 0
            for line in resp.text.splitlines():
                h, _, c = line.partition(":")
                if h.strip() == suffix:
                    count = int(c)
                    break
        except Exception as e:
            return {"status": "error", "type": "password", "target": "••••••••", "breached": None, "matches": [],
                    "summary": f"Could not reach Pwned Passwords ({e}) — result UNVERIFIED.", "sourcesChecked": [{"name": "HIBP Pwned Passwords", "ok": False}]}
        if count:
            return {
                "status": "success", "target": "••••••••", "type": "password", "breached": True, "verified": True, "count": count,
                "riskScore": 95,
                "matches": [{"source": f"Pwned Passwords corpus ({count:,} sightings)", "leakType": "Plaintext password seen in breach dumps",
                             "riskRating": "CRITICAL", "exposedData": ["Passwords"],
                             "recommendations": "Never use this password anywhere. Attackers use it in credential-stuffing and dictionary attacks."}],
                "sourcesChecked": [{"name": "HIBP Pwned Passwords", "ok": True, "found": count}],
                "summary": f"This password has appeared {count:,} times in public data breaches!",
            }
        return {"status": "success", "target": "••••••••", "type": "password", "breached": False, "verified": True, "count": 0,
                "riskScore": 10, "matches": [], "sourcesChecked": [{"name": "HIBP Pwned Passwords", "ok": True, "found": 0}],
                "summary": "This password does not appear in the HIBP Pwned Passwords corpus (~1 billion leaked passwords)."}
