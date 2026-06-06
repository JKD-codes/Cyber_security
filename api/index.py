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

def analyze_headers(headers: dict):
    issues = []
    passed = []
    
    # Lowercase keys for case-insensitive lookup
    headers = {k.lower(): v for k, v in headers.items()}
    
    # 1. X-XSS-Protection
    xss = headers.get("x-xss-protection", "")
    if xss == "0":
        passed.append("Modern X-XSS-Protection disabled (Safe from XS-Search attacks)")
    elif xss.startswith("1"):
        issues.append({
            "id": "xss_protection",
            "title": "Outdated X-XSS-Protection Header",
            "severity": "MEDIUM",
            "description": "Setting X-XSS-Protection to 1 is considered dangerous on modern browsers as it enables XS-Search attacks.",
            "solution": "Set 'X-XSS-Protection: 0' and rely on a strong Content-Security-Policy instead."
        })
    else:
        passed.append("No active X-XSS-Protection header (Standard modern behavior)")

    # 2. Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        passed.append("Strict-Transport-Security (HSTS) is active")
    else:
        issues.append({
            "id": "hsts_missing",
            "title": "Missing Strict-Transport-Security (HSTS)",
            "severity": "LOW",
            "description": "The response is missing the HSTS header. Note: If this domain is on the browser's HSTS Preload list (like google.com), this is safe as the browser enforces HTTPS natively.",
            "solution": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your server configuration."
        })

    # 3. Server Fingerprint
    server = headers.get("server", "")
    x_powered_by = headers.get("x-powered-by", "")
    fingerprint = server or x_powered_by
    if fingerprint:
        if re.search(r'\d+\.\d+', fingerprint):
            issues.append({
                "id": "server_version_leak",
                "title": "Server Version Leakage",
                "severity": "HIGH",
                "description": f"The server is leaking its exact version number: '{fingerprint}'. This allows attackers to easily look up known CVEs.",
                "solution": "Configure your web server to hide version numbers in the 'Server' and 'X-Powered-By' headers."
            })
        else:
            issues.append({
                "id": "server_fingerprint",
                "title": "Exposed Server Fingerprint",
                "severity": "LOW",
                "description": f"The server is revealing its technology stack: '{fingerprint}'. While no exact version is leaked, it still gives attackers intelligence.",
                "solution": "Change the Server header to a generic value or remove it entirely."
            })

    # 4. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy", "")
    if not csp:
        issues.append({
            "id": "csp_missing",
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "MEDIUM",
            "description": "No CSP was found. While hard to implement on legacy sites without breaking features, it is the best defense against Cross-Site Scripting (XSS).",
            "solution": "Implement a CSP starting with \"default-src 'self'\" and gradually allow required domains."
        })
    elif "unsafe-inline" in csp:
        issues.append({
            "id": "csp_unsafe",
            "title": "Weak Content-Security-Policy",
            "severity": "HIGH",
            "description": "The CSP allows 'unsafe-inline' scripts. This completely defeats the primary purpose of a CSP, as attackers can still inject malicious inline scripts.",
            "solution": "Remove 'unsafe-inline' from the script-src directive. Move inline scripts to external JS files or use nonces/hashes."
        })
    else:
        passed.append("Strong Content-Security-Policy is enforced")

    # 5. X-Frame-Options
    x_frame = headers.get("x-frame-options", "")
    if x_frame:
        passed.append("X-Frame-Options is protecting against Clickjacking")
    else:
        issues.append({
            "id": "x_frame_missing",
            "title": "Missing X-Frame-Options",
            "severity": "LOW",
            "description": "Without X-Frame-Options, attackers might be able to embed this site in an iframe to perform Clickjacking.",
            "solution": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        })

    # Calculate Grade
    if any(i['severity'] == 'HIGH' for i in issues):
        grade = 'D'
    elif any(i['severity'] == 'MEDIUM' for i in issues):
        grade = 'C'
    elif issues:
        grade = 'B'
    else:
        grade = 'A'

    return {
        "grade": grade,
        "passedChecks": passed if passed else ["Standard connection established"],
        "issues": issues
    }

@app.get("/api/scan/headers")
async def scan_headers(url: str):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # User-Agent spoofing to bypass basic bot blocks
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            # 1. Primary Header Scan
            response = await client.get(url, headers=headers)
            
            raw_headers = dict(response.headers)
            analysis = analyze_headers(raw_headers)
            
            # 2. Active Sensitive File Probing
            # We are firing off quick checks for critical file exposures
            probe_issues = []
            probe_passed = []
            
            probes = [
                {"path": "/.env", "name": "Exposed .env File", "severity": "CRITICAL", "description": "An environment file was found exposed to the public internet. This often contains live database passwords, API keys, and secret tokens.", "solution": "Block access to hidden files (starting with a dot) in your web server configuration."},
                {"path": "/.git/config", "name": "Exposed Git Repository", "severity": "CRITICAL", "description": "The .git folder is publicly accessible. Attackers can download your entire source code history and proprietary algorithms.", "solution": "Block access to the .git directory immediately."},
                {"path": "/.well-known/security.txt", "name": "Security.txt Discovered", "severity": "INFO", "description": "This site has a standard security.txt file, indicating they have a mature security vulnerability disclosure process.", "solution": "No action needed."}
            ]

            # Parse base URL to strip off paths for probing
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for probe in probes:
                probe_url = base_url + probe["path"]
                try:
                    # Very short timeout so we don't hold up the UI
                    probe_resp = await client.get(probe_url, headers=headers, timeout=4.0, follow_redirects=False)
                    if probe_resp.status_code == 200:
                        text = probe_resp.text.lower()
                        # Verify content to prevent false positives from generic 200 OK error pages
                        if probe["path"] == "/.env" and ("=" in text and ("db" in text or "key" in text or "secret" in text)):
                            probe_issues.append({"id": "env_exposed", "title": probe["name"], "severity": probe["severity"], "description": probe["description"], "solution": probe["solution"]})
                        elif probe["path"] == "/.git/config" and ("[core]" in text):
                            probe_issues.append({"id": "git_exposed", "title": probe["name"], "severity": probe["severity"], "description": probe["description"], "solution": probe["solution"]})
                        elif probe["path"] == "/.well-known/security.txt" and ("contact:" in text):
                            probe_passed.append("Official Security.txt policy found")
                except Exception:
                    pass # Ignore timeouts on probes
            
            # Merge probe results into main analysis
            all_issues = analysis["issues"] + probe_issues
            all_passed = analysis["passedChecks"] + probe_passed

            # Recalculate Grade if CRITICAL issues were found
            grade = analysis["grade"]
            if probe_issues:
                grade = "F" # Instant fail if .env or .git is exposed!

            return {
                "url": url,
                "status_code": response.status_code,
                "grade": grade,
                "passedChecks": all_passed,
                "issues": all_issues
            }
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Scan timed out. Target might be offline or blocking requests.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan target: {str(e)}")
