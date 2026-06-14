# 🛡️ CyberShield

**An Executive Cyber Operations Dashboard & Advanced Heuristic Vulnerability Scanner**

CyberShield is a state-of-the-art web application security scanner designed to give red teamers, bug bounty hunters, and security engineers instantaneous insights into a target's perimeter defenses. Built with a stunning "Cyber Ops" glassmorphism interface, it cuts through the noise to deliver high-fidelity vulnerability reports.

![CyberShield UI](https://img.shields.io/badge/UI-Glassmorphism-00e5a0?style=for-the-badge)
![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)
![Frontend](https://img.shields.io/badge/Frontend-React-61dafb?style=for-the-badge&logo=react)
![AI/ML](https://img.shields.io/badge/AI_Assisted-Threat_Intel-9d6eff?style=for-the-badge)

---

## ⚡ Features

### 🧠 Hybrid AI-Heuristic Engine
CyberShield utilizes a hybrid architecture blending **AI-Assisted Threat Intelligence** with strict heuristic rules. By historically training on massive datasets of web misconfigurations, the engine performs deep contextual analysis to differentiate between modern security practices and legacy vulnerabilities.

### 🎯 Deep HTTP Header Analysis
The engine evaluates HTTP response headers against 2024 security standards, detecting:
- **Weak Content-Security-Policy (CSP):** Flags dangerous directives like `unsafe-inline`.
- **Outdated Defenses:** Identifies legacy headers (e.g., `X-XSS-Protection: 1`) that introduce XS-Search vulnerabilities.
- **Server Fingerprinting:** Detects technology stack leakage that aids attackers.
- **Missing Core Protocols:** Enforces HSTS and X-Frame-Options standards.

### 🕵️ Active Sensitive File Probing
Unlike passive scanners, CyberShield actively probes targets for critical misconfigurations that lead to massive data breaches:
- **Exposed `.env` Files:** Hunts for leaked database credentials and secret API keys.
- **Dangling `.git` Repositories:** Detects exposed source code history.
- **Soft-404 Detection:** Uses intelligent HTML parsing to eliminate false positives on generic error pages.

### 🌌 Executive "Cyber Ops" UI
- **Glassmorphism Design:** Beautiful, frosted-glass panels with dynamic aura backgrounds.
- **Real-Time Radar Pulse:** Sleek, professional animations during target reconnaissance.
- **SOC Sidebar:** An interactive Security Operations Center panel for quick insights.

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- Python (3.9+)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JKD-codes/Cyber_security.git
   cd Cyber_security
   ```

2. **Start the FastAPI Backend:**
   ```bash
   cd api
   pip install -r requirements.txt
   uvicorn index:app --reload --port 8000
   ```

3. **Start the React Frontend:**
   Open a new terminal window:
   ```bash
   npm install
   npm run dev
   ```

---

## ⚠️ Legal Disclaimer

This tool is designed **strictly for authorized educational purposes, bug bounty hunting, and ethical hacking**. 

CyberShield performs Active Probing (`/.env`, `/.git`). **DO NOT** use this tool against targets without explicit authorization (e.g., an official Vulnerability Disclosure Program or Bug Bounty). The developers are not responsible for any misuse or damage caused by this software.

---

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page if you want to contribute.

*Developed with ❤️ for the Cybersecurity Community.*
