# 🛡️ CyberShield Platform

<div align="center">

![CyberShield Banner](https://img.shields.io/badge/SECURITY%20OPERATIONS%20CENTER-CYBERSHIELD%20v2.0-00e5a0?style=for-the-badge&logo=shield&logoColor=black)

**An Executive Cyber Defense Intelligence Suite, 3D Geographic Threat Operations Center & Advanced Heuristic Vulnerability Scanner**

[![Live Deployment](https://img.shields.io/badge/LIVE%20DEMO-cyber--shield--platform.vercel.app-00f2fe?style=for-the-badge&logo=vercel&logoColor=white)](https://cyber-shield-platform.vercel.app)
[![React 19](https://img.shields.io/badge/Frontend-React%2019%20%7C%20Vite%208-61dafb?style=flat-square&logo=react)](https://react.dev)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.11-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/AI%20Engine-Scikit--Learn%20Random%20Forest-F7931E?style=flat-square&logo=scikit-learn)](https://scikit-learn.org)
[![k-Anonymity](https://img.shields.io/badge/Privacy-k--Anonymity%20SHA--1-9d6eff?style=flat-square)](https://haveibeenpwned.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

[Explore Live Platform](https://cyber-shield-platform.vercel.app) • [View Architecture](#-system-architecture) • [Module Directory](#-core-security-modules) • [COCOMO Valuation](#-engineering--cocomo-metrics) • [Quickstart](#-quickstart--local-setup)

</div>

---

## 🌟 Executive Overview

**CyberShield** is an enterprise-grade cybersecurity operations platform designed to bridge the gap between technical penetration testing and actionable executive decision-making. Built with a high-contrast Cyberpunk Glassmorphism aesthetic, it unites perimeter vulnerability reconnaissance, live dark-web credential leak intelligence, machine-learning-assisted phishing detection, interactive educational attack laboratories, and demographic family safety advisories into a single high-performance dashboard.

Whether auditing web perimeters, investigating suspicious communications, or educating non-technical stakeholders, CyberShield delivers high-fidelity security intelligence in seconds.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    User([Security Operator / End User]) --> UI[CyberShield React 19 Client\nVite 8 + Glassmorphism UI]
    
    subgraph Frontend["Frontend Client Engines (Browser Native)"]
        UI --> ThreatGlobe[Native 3D Canvas Threat Globe\nSpherical Trigonometry + Drag Projection]
        UI --> WebCrypto[Web Crypto API\nSHA-1 In-Browser k-Anonymity Fallback]
        UI --> PDFGen[jsPDF Audit Engine\nSigned Vector PDF Memorandums]
        UI --> CodexaLink[Codexa AI Bridge\nAST Code Review Integration]
    end

    subgraph Backend["FastAPI Intelligence Gateway (api/index.py)"]
        UI -->|REST API Requests| API[FastAPI Async Server]
        
        API --> HeaderEngine[Perimeter Header Auditor\nCSP, HSTS, X-Frame, X-XSS, Server Versions]
        API --> FileProbes[Active Sensitive File Probes\nSoft-404 Detection on /.env, /.git/config]
        API --> ScamEngine[Dual-Tier Scam Detector\nLinguistic Heuristics + BeautifulSoup Scraper]
        API --> CredEngine[Credential Leak Auditor\nk-Anonymity Hash Slicing Engine]
    end

    subgraph Intelligence["External Intelligence & ML Corpuses"]
        ScamEngine --> MLModel[Random Forest Classifier\nTF-IDF N-Gram Vectorizer (models/)]
        CredEngine --> HIBP[HaveIBeenPwned API\nRange Suffix Protocol]
        CredEngine --> Xposed[XposedOrNot Live API\nDark Web Breach Indices]
        CredEngine --> Catalog[(Local 796-Breach Catalog\nIndian & Global Exposure Incidents)]
        HeaderEngine --> TargetSite[(Target Perimeter Host)]
    end
```

---

## 🛡️ Core Security Modules

### 1. 🌐 Global Threat Center & 3D Threat Globe
* **Zero-Dependency 3D Canvas:** Built completely on HTML5 2D Canvas using pure spherical trigonometry (`radius * cos(phi) * sin(theta)`), eliminating heavy Three.js runtime overhead.
* **Geographic Accuracy:** Mathematically projects over **1,500 density-clustered landmass coordinates** with atmospheric rayleigh gradient scattering.
* **Ballistic Bézier Attack Arcs:** Visualizes simulated kinetic cyber-strikes originating from major global relays (Tokyo, London, NYC, Frankfurt, Singapore) impacting the primary **Mumbai Operations Center**, complete with expanding perimeter shockwaves.
* **Synchronized Telemetry Stream:** Real-time rolling feed categorized with RFC protocol badges (`TLS 1.3`, `HTTP/3`, `TCP/443`, `BGP`, `DoH`) and severity indicators (`[BLOCKED]`, `[INTERCEPT]`, `[AUDIT]`, `[MITIGATED]`).

### 2. 🔍 Site Security Scanner (Perimeter Reconnaissance)
* **5 Critical Defensive Headers:**
  * **Strict-Transport-Security (HSTS):** Prevents SSL-stripping and downgrade attacks.
  * **Content-Security-Policy (CSP):** Flags dangerous `'unsafe-inline'` script allowances (gateway to XSS) and missing object guards.
  * **X-Frame-Options:** Audits frame-ancestor protections against Clickjacking attacks.
  * **Modern X-XSS-Protection:** Specifically flags legacy `1` settings as dangerous (which enable XS-Search side-channel leaks) and recommends modern CSP replacement.
  * **Server Fingerprint Suppression:** Detects exact software version leaks (`Apache/2.4.49`) that map directly to known CVEs in the NIST database.
* **Active Sensitive File Probing:** Sends non-intrusive asynchronous probes to `/.env`, `/.git/config`, and `/.well-known/security.txt`.
* **Soft-404 Anti-False-Positive Filter:** Analyzes response bodies to discard HTML-based 200 OK error pages, verifying raw syntax before triggering alarms.
* **Executive Letter Grading:** Automatically calculates holistic grades from **A (Hardened)** to **F (Instant Fail)**.

### 3. 📧 Compromised Identity & Credential Breach Auditor
* **Multi-Modal Target Input:** Audits emails, phone numbers (international/domestic MSISDN), and passwords.
* **Mathematical k-Anonymity (SHA-1):** 
  * Passwords are hashed locally using SHA-1.
  * Only the **first 5 hex characters** (`prefix`) are sent to the HaveIBeenPwned Range API.
  * Suffixes are matched client-side / server-side from returned candidate buckets.
  * **Zero Trust:** Plaintext passwords and full hashes are **never transmitted across the network**.
* **Curated Breach Catalog:** Maps raw breach IDs against a curated directory of Indian and global leaks (Air India, BigBasket, LinkedIn, Domino's, Canva, MobiKwik) with targeted remediation advice (e.g., mAadhaar biometric locks, UPI credential renewal).
* **Dual-Tier High Availability:** If the Python backend is unreachable, the frontend seamlessly triggers the browser's native **Web Crypto API** (`crypto.subtle.digest`) to execute the audit directly.

### 4. 🧠 Dual-Tier Link & Scam Auditor
* **Tier 1 (Linguistic & DOM Heuristics):**
  * Evaluates protocol security and flags high-risk TLDs (`.xyz`, `.top`, `.tk`, `.cc`).
  * **Homoglyph & Typosquatting Matching:** Detects lookalike Unicode and character swaps mimicking legitimate banking handles (`paytrn` vs `Paytm`, `sbi-kyc`, `filpkart`, `amozon`).
  * **Live DOM Web Scraping:** Employs BeautifulSoup to crawl live target HTML, hunting for unlinked trust badge images, unencrypted password inputs on plain HTTP, and panic verbs.
* **Tier 2 (Scikit-Learn Machine Learning):**
  * Evaluates text using a **Random Forest Classifier** trained on TF-IDF N-gram feature vectors (`api/train_model.py`).
  * Computes statistical scam probabilities (0% to 99%) and assigns clear verdicts (`SAFE`, `SUSPICIOUS`, `SCAM`).

### 5. 🧪 Attack Simulator Laboratories
Interactive, step-by-step exploit sandbox walking users through chronological attack kill-chains:
1. **Homoglyph Phishing Link Redirection:** Domain typosquatting &rarr; SMS lure &rarr; Cloned UI &rarr; Dynamic bank OTP socket harvesting.
2. **SS7 SIM Swapping:** OSINT profiling &rarr; Telecom social engineering &rarr; Cellular roaming node redirection &rarr; SMS 2FA intercept.
3. **WhatsApp Call-Forwarding Takeover:** Delivery impersonation &rarr; Carrier shortcode dial directive (`*401*`) &rarr; Unconditional call rerouting &rarr; Voice OTP registration.
4. **UPI Cashback QR Code Injection:** Fake bonus bait &rarr; Malicious QR delivery &rarr; Hidden debit request &rarr; PIN typing deception.

### 6. 🛡️ Family Shield Center
Empathetic, demographic cyber-advisory interface designed for non-technical users:
* **Elder / Parent:** Demystifies utility disconnection threats, pension KYC panic, and phone scams. Direct connection to **Senior Citizen Safety Line (14567)**.
* **Working Adult:** Highlights advance OLX/rental deposits and QR code payment scams. Direct link to **National Cyber Crime Helpline (1930)**.
* **Student / Teen:** Breaks down Telegram task Ponzi schemes and video-liking jobs from international recruiter codes (`+62`, `+84`).

### 7. 🤖 Codexa AI Code Review Integration
Seamless one-click neural bridge transition from the executive console sidebar to our companion autonomous code review platform, [Codexa](https://codexa-ye85.onrender.com), which performs automated AST-grade static security audits across GitHub repositories.

### 8. 📄 Official Signed PDF Audit Memorandum Generator
Built-in client-side vector reporting engine using `jsPDF`. Generates executive-ready security memorandums featuring audit tracking references, status banners, categorized findings with remediation code snippets, and formal cryptographic assurance badges.

---

## 💻 Tech Stack & Dependencies

| Layer | Technologies |
| :--- | :--- |
| **Frontend Framework** | **React 19** (`react`, `react-dom`), **Vite 8** |
| **Icons & Visuals** | **Lucide React** (high-contrast icon registry), Custom HTML5 Canvas Engine |
| **Document Generation** | **jsPDF** (Vector PDF compilation) |
| **Backend Framework** | **FastAPI 0.111.0**, **Uvicorn** (ASGI runner), **Starlette** |
| **HTTP & Networking** | **HTTPX 0.27.0** (Async client with TLS control), **Pydantic** |
| **Parsing & Scraping** | **BeautifulSoup4**, Python **urllib.parse** |
| **AI & Machine Learning** | **Scikit-Learn** (`RandomForestClassifier`, `TfidfVectorizer`), **Pandas**, **Joblib** |
| **Security Standards** | **OWASP Top 10**, RFC 6797 (HSTS), W3C CSP Level 3, k-Anonymity SHA-1 |

---

## 📈 Engineering & COCOMO Metrics

```
=== CODEBASE INVENTORY ===
.json   :   4 files |    20,919 lines (including 17.8k threat catalog)
.jsx    :   2 files |     7,194 lines
.js     :   3 files |       977 lines
.py     :   2 files |       838 lines
.css    :   2 files |       728 lines
.html   :   1 files |        22 lines
---------------------------------------------
TOTAL   :  14 files |    30,678 lines
PURE SOURCE CODE (SLOC): ~9,830 lines (9.83 KLOC)
```

### COCOMO Cost Estimation (Semi-Detached Mode)
Applying Barry Boehm’s standard algorithmic software cost model:
* **Size ($KLOC$):** $9.83$
* **Effort Equation:** $E = 3.0 \times (9.83)^{1.12} \approx \mathbf{38.80\text{ Person-Months}}$
* **Development Schedule:** $T_{dev} = 2.5 \times (38.80)^{0.35} \approx \mathbf{9.00\text{ Months}}$
* **Nominal Team Size:** $P = E / T_{dev} \approx \mathbf{4.31\text{ (4 to 5 Engineers)}}$
* **Development Valuation:**
  * **Indian Market Rate (₹1.0L/mo):** **₹38.80 Lakhs**
  * **Global Market Rate ($8.5k/mo):** **$329,800 USD**

---

## 🚀 Quickstart & Local Setup

### Prerequisites
* **Node.js** (v18.0 or higher)
* **Python** (v3.9 or higher)
* **npm** or **pnpm**

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JKD-codes/Cyber_security.git
   cd Cyber_security
   ```

2. **Install frontend dependencies:**
   ```bash
   npm install
   ```

3. **Install backend dependencies:**
   ```bash
   cd api
   pip install -r requirements.txt
   cd ..
   ```

4. **Run both servers concurrently:**
   ```bash
   npm run dev
   ```
   * Frontend will launch at: `http://localhost:5173`
   * FastAPI backend will run at: `http://localhost:8000`
   * Interactive OpenAPI Docs at: `http://localhost:8000/docs`

---

## 📡 API Reference Overview

| Endpoint | Method | Description | Parameters / Payload |
| :--- | :---: | :--- | :--- |
| `/api/health` | `GET` | Health check and telemetry state | None |
| `/api/scan/headers` | `GET` | Performs perimeter header audit & file probing | `?url=target.com` |
| `/api/analyze/scam` | `POST` | Dual-tier heuristic + ML scam analysis | `{"text": "SMS or URL"}` |
| `/api/check/credential` | `POST` | k-Anonymity identity breach lookup | `{"target": "email/pass/phone", "mode": "auto"}` |
| `/api/threats/live` | `GET` | Live OSINT threat coordinates feed | None |

---

## ⚖️ Legal & Ethical Usage Directive

CyberShield is engineered strictly for **authorized educational research, bug bounty hunting, security auditing, and defensive operations**.

* Active file probing features (`/.env`, `/.git`) must only be executed against systems you own or have explicit, documented authorization to test (e.g., within an official Vulnerability Disclosure Policy scope).
* The authors and maintainers assume no liability for misuse, unauthorized testing, or damage caused by deploying this software.

---

<div align="center">

**Developed with precision for modern security teams and the global cybersecurity community.**

*Protect your perimeter. Safeguard your family. Defend the network.*

</div>
