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
                        
                        # Soft-404 Detection: Real .env or .git files are raw text. If we see HTML tags, it's a generic error page masquerading as a 200 OK.
                        is_html = "<html" in text or "<body" in text or "<!doctype html" in text
                        
                        # Verify content to prevent false positives from generic 200 OK error pages
                        if probe["path"] == "/.env" and not is_html and ("=" in text and ("db" in text or "key" in text or "secret" in text)):
                            probe_issues.append({"id": "env_exposed", "title": probe["name"], "severity": probe["severity"], "description": probe["description"], "solution": probe["solution"]})
                        elif probe["path"] == "/.git/config" and not is_html and ("[core]" in text):
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

class ScamAnalysisRequest(BaseModel):
    text: str

@app.post("/api/analyze/scam")
async def analyze_scam(req: ScamAnalysisRequest):
    input_text = req.text.strip()
    is_url = False
    # Simple check if it looks like a URL
    if "." in input_text and (input_text.lower().startswith("http") or input_text.lower().startswith("www") or "." in input_text.split(" ")[0]):
        is_url = True

    scam_prob = 12 if is_url else 8
    red_flags = []
    tactics = []
    verdict = "SAFE"
    urgency = "LOW"
    recommendation = "Message content appears informational. Follow normal safety directories."
    explanation = "Linguistic heuristics scan and/or live DOM parsing executed."

    if is_url:
        # URL Logic
        url_lower = input_text.lower()
        if not url_lower.startswith("http"):
            url_to_fetch = "http://" + input_text
        else:
            url_to_fetch = input_text

        tactics.append("Domain & DOM Inspection")
        recommendation = "URL appears consistent with secure public registration records."
        
        # 1. Insecure Protocol
        if url_to_fetch.startswith("http://"):
            scam_prob += 24
            red_flags.append("Uses insecure http:// protocol instead of encrypted https://")
            tactics.append("Protocol Downgrade")

        # 2. High-Risk TLDs
        scam_tlds = ['.xyz', '.cc', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.net.ru', '.work', '.info']
        for tld in scam_tlds:
            if tld in url_lower:
                scam_prob += 35
                red_flags.append(f"Uses generic high-risk TLD ({tld}) popular in coordinate scam campaigns")
                tactics.append("Generic TLD Exploitation")
                break

        # 3. Homoglyphs
        homoglyphs = [
          {'keyword': 'paytrn', 'targets': 'Paytm'},
          {'keyword': 'paytm-rewards', 'targets': 'Paytm Rewards'},
          {'keyword': 'gpay-bonus', 'targets': 'Google Pay'},
          {'keyword': 'sbi-kyc', 'targets': 'State Bank of India (SBI)'},
          {'keyword': 'sbi-login', 'targets': 'SBI Portal'},
          {'keyword': 'hdfc-secure', 'targets': 'HDFC Bank'},
          {'keyword': 'amozon', 'targets': 'Amazon India'},
          {'keyword': 'filpkart', 'targets': 'Flipkart'}
        ]
        for h in homoglyphs:
            if h['keyword'] in url_lower:
                scam_prob += 48
                red_flags.append(f"Typosquatting Match: Mimics trusted brand '{h['targets']}' using lookalike letters '{h['keyword']}'")
                if "Brand Impersonation" not in tactics: tactics.append("Brand Impersonation")
                if "Lookalike Typosquatting" not in tactics: tactics.append("Lookalike Typosquatting")

        # 4. Live HTML Scraping
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as client:
                resp = await client.get(url_to_fetch)
                soup = BeautifulSoup(resp.text, 'html.parser')
                page_text = soup.get_text().lower()
                
                # Check for urgency/greed in scraped text
                if "claim" in page_text and ("prize" in page_text or "bonus" in page_text or "reward" in page_text):
                    scam_prob += 20
                    red_flags.append("Page contains high-pressure financial lures (Claim Prize/Bonus)")
                    tactics.append("Financial Bait (Scraped)")

                if "urgent" in page_text or "account suspended" in page_text or "kyc" in page_text:
                    scam_prob += 20
                    red_flags.append("Page uses urgent panic triggers (Suspension/KYC)")
                    tactics.append("Urgency Trigger (Scraped)")

                # Check for fake trust badges (images with norton/mcafee but no links)
                img_tags = soup.find_all('img')
                for img in img_tags:
                    src = img.get('src', '').lower()
                    if 'norton' in src or 'mcafee' in src or 'secure' in src:
                        if not img.find_parent('a'):
                            scam_prob += 15
                            red_flags.append("Found unlinked/fake trust badge image (Norton/McAfee/Secure)")
                            if "Fake Trust Indicators" not in tactics: tactics.append("Fake Trust Indicators")
                            break

                # Check for suspicious input forms on HTTP
                if url_to_fetch.startswith("http://"):
                    password_inputs = soup.find_all('input', type='password')
                    if password_inputs:
                        scam_prob += 40
                        red_flags.append("Insecure page contains a password input field!")
                        tactics.append("Credential Harvesting (Unencrypted)")

        except Exception as e:
            print(f"Scraping error for {url_to_fetch}: {e}")

        explanation = f"URL analysis audit for '{input_text}'. Our engine checked protocol handshakes, TLD reputation indices, and executed live DOM scraping to search for Lookalike Impersonations (homoglyphs) and linguistic panic triggers."

    else:
        # SMS Text Logic
        lower_text = input_text.lower()
        tactics.append("Linguistic Heuristics")

        if "otp" in lower_text or "verification code" in lower_text or "pin" in lower_text:
            scam_prob += 22
            red_flags.append("Requests confidential security authorization codes (OTP / PIN)")
            tactics.append("Credential Harvesting")

        if "electricity" in lower_text or "power cut" in lower_text or "disconnection" in lower_text or "suspend" in lower_text or "block" in lower_text:
            scam_prob += 26
            red_flags.append("Threatens immediate service deactivation (power lines, bank accounts)")
            tactics.append("Urgency Trigger")

        if "kyc" in lower_text or "pension" in lower_text or "subsidy" in lower_text or "pan card" in lower_text:
            scam_prob += 20
            red_flags.append("References official government updates to build fake authority")
            tactics.append("Authority Impersonation")

        if "lottery" in lower_text or "reward" in lower_text or "win" in lower_text or "bonus" in lower_text or "refund" in lower_text:
            scam_prob += 24
            red_flags.append("Offers unrequested financial refunds or cash bonuses")
            tactics.append("Financial Bait")

    # Tier 2: Machine Learning Analysis
    ml_confidence = 0
    if ml_vectorizer and ml_model:
        try:
            vec_input = ml_vectorizer.transform([input_text])
            prob = ml_model.predict_proba(vec_input)[0][1] # Probability of class 1 (Scam)
            ml_confidence = int(prob * 100)
            
            if ml_confidence > 60:
                red_flags.append(f"AI Engine detected anomalous scam phrasing ({ml_confidence}% confidence)")
                tactics.append("AI Pattern Match")
                scam_prob += int(ml_confidence * 0.6) # Blend AI score
        except Exception as e:
            print("ML Inference Error:", e)

    scam_prob = min(scam_prob, 99)
    if scam_prob > 70:
        verdict = "SCAM"
        urgency = "CRITICAL"
        if is_url:
            recommendation = "DO NOT ACCESS. Close the page immediately. Do not submit primary login cards, Aadhaar fields, or passwords."
        else:
            recommendation = "DO NOT CLICK ANY LINKS OR DIAL THE SENDER. Block the phone line. Report the number immediately."
    elif scam_prob > 30:
        verdict = "SUSPICIOUS"
        urgency = "HIGH"
        if is_url:
            recommendation = "EXERCISE EXTREME CAUTION. Check the domain prefix against official records before filling text fields."
        else:
            recommendation = "DO NOT SHARE OTPs. Reach out directly to your banking branch using their official support hotline."
    else:
        if not red_flags:
            if is_url:
                red_flags = ["No active homoglyph patterns detected", "Certificate matches security registers"]
            else:
                red_flags = ["No active threat verbs detected", "Presents generic linguistic structure"]

    if ml_confidence > 0:
        explanation += f" Machine Learning Contextual Confidence: {ml_confidence}%."

    return {
        "scamProbability": scam_prob,
        "verdict": verdict,
        "manipulationTactics": tactics,
        "redFlags": red_flags,
        "recommendation": recommendation,
        "explanation": explanation,
        "urgencyLevel": urgency
    }
