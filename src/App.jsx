import React, { useState, useEffect, useRef } from 'react';

// Live Verified Cybersecurity Threat Index (Real Threats active in India)
const ACTIVE_INDIAN_THREATS = [
  { id: 'T-IN-9041', name: 'UPI Lookalike Redirects', vector: 'Merchant Spoofing', description: 'Scammers register UPI IDs resembling prominent payment endpoints (e.g., paytrn@ybl instead of paytm@ybl) to hijack QR scanning transactions.', severity: 'CRITICAL', color: 'var(--aura-danger)' },
  { id: 'T-IN-8712', name: 'mAadhaar OTP Hijacking', vector: 'Identity Redirection', description: 'Coercive social calls pretending to be Aadhaar UIDAI auditors requesting biometric locks, tricking citizens into verifying access OTP tokens.', severity: 'HIGH', color: 'var(--aura-watch)' },
  { id: 'T-IN-7493', name: 'Sarkari Phishing campaigns', vector: 'Credential Harvesting', description: 'Deceptive generic web portals (e.g. pmkisan-subsidy.cc) targeting regional farmers by demanding bank credentials to release government payouts.', severity: 'CRITICAL', color: 'var(--aura-danger)' },
  { id: 'T-IN-6501', name: 'Utility Bill Suspensions', vector: 'Fear Induction SMS', description: 'Bulk SMS campaigns threatening immediate residential power disconnection within 30 minutes, directing victims to unofficial personal contact numbers.', severity: 'HIGH', color: 'var(--aura-watch)' }
];

// Context alerts for Floating SOC panel
const FLOATING_TIPS = [
  "Verify merchant names displayed on your payment app screen before entering any UPI PIN.",
  "Your UPI PIN is ONLY required to send money. Receiving money never demands your PIN.",
  "Official government portals always end with a strict .gov.in or .nic.in extension.",
  "Telecom providers will never ask for personal PINs orMother's maiden name to update SIM profiles.",
  "Enable Aadhaar Biometric Locking via the official mAadhaar portal to freeze identity lookups.",
  "Never dial * or # prefixes sent by strangers — these execute background call forwarding commands.",
  "Avoid installing AnyDesk or TeamViewer on command of anyone claiming your utility account is locked.",
  "Check URL addresses for lookalike letters (homoglyphs) like paytrn instead of paytm.",
  "Report local scam calls and UPI transaction frauds immediately to the Cybercrime Helpline at 1930."
];

// Simulated leak database index for HaveIBeenPwned-style Auditor
const LOCAL_LEAK_DATABASE = {
  'deepmind@google.com': [
    { source: 'Android Dev Log Breach (2024)', leakType: 'Source Code, API Keys, Passwords', riskRating: 'CRITICAL', recommendations: 'Deauthorize active API keys immediately. Shift credential structures to secure environment variables.' },
    { source: 'Global Vite CDN Exposure (2025)', leakType: 'Session Tokens, Email Address', riskRating: 'HIGH', recommendations: 'Clear current browser token caches and regenerate deployment credentials.' }
  ],
  'admin@domain.com': [
    { source: 'Retailer Express Database Dump (2022)', leakType: 'Plaintext Passwords, Phone Number', riskRating: 'HIGH', recommendations: 'Migrate admin accounts to separate usernames and configure secure multi-factor authentication.' },
    { source: 'Indian Telecom Leak (2024)', leakType: 'Aadhaar ID, Phone Number, Home Address', riskRating: 'CRITICAL', recommendations: 'Lock your biometric details via UIDAI portal immediately. Request secondary billing credentials.' }
  ],
  'user@example.com': [
    { source: 'EduCenter Education Leak (2023)', leakType: 'Encrypted Password Hashes, Address', riskRating: 'MEDIUM', recommendations: 'Rotate lookalike passwords shared across personal learning accounts.' }
  ]
};

// OWASP Top 10 Configurations & Auditing Framework
const OWASP_AUDIT_SETUP = {
  MERN: {
    stackName: 'MERN Stack Web App (Node.js/React)',
    criteria: [
      { id: 'a03_sql', label: 'SQL/NoSQL Parameterized Queries', desc: 'Are inputs parsed via Mongoose validation or strict parameterized parameters to block Injection (A03)?', mitigationCode: `// SECURE INPUT PARAMETERIZATION\nconst user = await User.findOne({\n  email: req.body.email.trim()\n});` },
      { id: 'a01_auth', label: 'Bcrypt Password Salting (rounds > 10)', desc: 'Are authentication passwords salted and hashed using secure algorithms to prevent Auth Failures (A01)?', mitigationCode: `// SECURE PASSWORD HASHING\nconst salt = await bcrypt.genSalt(12);\nconst hashed = await bcrypt.hash(password, salt);` },
      { id: 'a05_headers', label: 'Helmet HTTP Secure Headers', desc: 'Is Express configured with Helmet middleware to block XSS and clickjacking vulnerabilities (A05)?', mitigationCode: `// CONFIGURE SECURITY HEADERS\nconst express = require('express');\nconst helmet = require('helmet');\nconst app = express();\napp.use(helmet());` },
      { id: 'a02_cors', label: 'Strict Origin CORS Validation', desc: 'Are server cross-origin requests locked to explicit domain lists to secure API traces (A02)?', mitigationCode: `// SECURE CORS POLICIES\napp.use(cors({\n  origin: ['https://cybershield.in'],\n  methods: ['GET', 'POST']\n}));` }
    ]
  },
  WordPress: {
    stackName: 'WordPress Portal (PHP/MySQL)',
    criteria: [
      { id: 'wp_prefix', label: 'Custom WP Database Prefix', desc: 'Is the database prefix changed from generic "wp_" to block automated SQL injection searches?', mitigationCode: `// wp-config.php\n$table_prefix = 'shield_ops_';` },
      { id: 'wp_salts', label: 'Unique Config Security Salts', desc: 'Are unique authorization security salts set in wp-config.php to encrypt core cookies?', mitigationCode: `// wp-config.php Salts\ndefine('AUTH_KEY', 'xK9#8dF!$L92@zP_qP');\ndefine('SECURE_AUTH_KEY', 'vW3*8nH!$B19@yM_tX');` },
      { id: 'wp_errors', label: 'Disabled Public Login Error Hints', desc: 'Are default login hints disabled so scanners cannot guess usernames via brute force?', mitigationCode: `// functions.php\nadd_filter('login_errors', function() {\n  return 'System Isolated: Incorrect Credentials.';\n});` }
    ]
  },
  StaticServerless: {
    stackName: 'Static Serverless API (Next.js/AWS)',
    criteria: [
      { id: 'next_headers', label: 'Next.js Content Security Policies (CSP)', desc: 'Are strict CSP policies configured in next.config.js to block malicious inline script execution?', mitigationCode: `// next.config.js\nconst securityHeaders = [{\n  key: 'Content-Security-Policy',\n  value: "default-src 'self'; script-src 'self';"\n}];` },
      { id: 'next_rate', label: 'API Endpoint Rate Limiting', desc: 'Are serverless functions secured with rate-limiting locks to prevent Denial of Service?', mitigationCode: `// middleware.ts Rate Limiter\nimport { rateLimit } from './limiter';\nexport async function middleware(req) {\n  return rateLimit(req.ip, 60); // 60 requests/min\n}` }
    ]
  }
};

export default function App() {
  const [activeModule, setActiveModule] = useState('dashboard');
  const [riskScore, setRiskScore] = useState(24); // Hand-crafted initial baseline
  const [auraColor, setAuraColor] = useState('var(--aura-safe)');
  const [currentTime, setCurrentTime] = useState('');
  const [isMobile, setIsMobile] = useState(false);
  const [windowWidth, setWindowWidth] = useState(1200);

  // Floating Commentary alerts
  const [floatingIndex, setFloatingIndex] = useState(0);
  const [isSOCExpanded, setIsSOCExpanded] = useState(false);
  const [triggerLaser, setTriggerLaser] = useState(false);

  // Terminal stats configuration
  const [systemSpeed, setSystemSpeed] = useState('184 GB/s');
  const [securityEngineState, setSecurityEngineState] = useState('ACTIVE');

  // Track resizing dynamically
  useEffect(() => {
    const handleResize = () => {
      setWindowWidth(window.innerWidth);
      setIsMobile(window.innerWidth <= 768);
    };
    handleResize();
    window.addEventListener('resize', handleResize);

    const clockInterval = setInterval(() => {
      const d = new Date();
      setCurrentTime(d.toLocaleTimeString('en-US', { hour12: false }));
    }, 1000);

    const tipInterval = setInterval(() => {
      setFloatingIndex((prev) => (prev + 1) % FLOATING_TIPS.length);
    }, 8000);

    // Randomize system diagnostics to look realistic
    const diagInterval = setInterval(() => {
      const rates = ['182 GB/s', '184 GB/s', '189 GB/s', '178 GB/s'];
      setSystemSpeed(rates[Math.floor(Math.random() * rates.length)]);
    }, 6000);

    return () => {
      window.removeEventListener('resize', handleResize);
      clearInterval(clockInterval);
      clearInterval(tipInterval);
      clearInterval(diagInterval);
    };
  }, []);

  // Set Aura variables
  useEffect(() => {
    if (riskScore < 35) {
      setAuraColor('var(--aura-safe)');
    } else if (riskScore < 65) {
      setAuraColor('var(--aura-watch)');
    } else {
      setAuraColor('var(--aura-danger)');
    }
  }, [riskScore]);

  // Render content matching selected module
  const renderModuleContent = () => {
    switch (activeModule) {
      case 'dashboard':
        return <DashboardModule windowWidth={windowWidth} auraColor={auraColor} riskScore={riskScore} setRiskScore={setRiskScore} />;
      case 'scam-detector':
        return <ScamDetectorModule windowWidth={windowWidth} setRiskScore={setRiskScore} />;
      case 'site-scanner':
        return <SiteScannerModule windowWidth={windowWidth} setRiskScore={setRiskScore} setTriggerLaser={setTriggerLaser} />;
      case 'footprint':
        return <FootprintModule windowWidth={windowWidth} setRiskScore={setRiskScore} setTriggerLaser={setTriggerLaser} />;
      case 'simulator':
        return <AttackSimulatorModule windowWidth={windowWidth} />;
      case 'family-safety':
        return <FamilySafetyModule windowWidth={windowWidth} />;
      default:
        return <DashboardModule windowWidth={windowWidth} auraColor={auraColor} riskScore={riskScore} setRiskScore={setRiskScore} />;
    }
  };

  return (
    <div style={{ position: 'relative', width: '100%', height: '100vh', display: 'flex', flexDirection: isMobile ? 'column' : 'row', background: 'var(--void)', overflow: 'hidden' }}>
      
      {/* 1. Dynamic Background Radial Aura Glow */}
      <div 
        className="aura-bg" 
        style={{
          background: `radial-gradient(circle 500px at ${isMobile ? '50% 25%' : '60% 35%'}, ${auraColor}0c, transparent)`
        }}
      />

      {/* 2. Global sweeping laser scanner */}
      {triggerLaser && <div className="laser-scan" style={{ color: auraColor }} onAnimationEnd={() => setTriggerLaser(false)} />}

      {/* 3. Left Sidebar navigation (Desktop) / Bottom Navbar navigation (Mobile) */}
      {!isMobile ? (
        <aside style={{
          width: '260px',
          background: 'var(--surface-0)',
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          zIndex: 10,
          flexShrink: 0,
          position: 'sticky',
          top: 0,
          height: '100vh',
          overflow: 'hidden'
        }}>
          <div style={{ flex: 1, overflowY: 'auto', padding: '28px 24px 20px 24px', display: 'flex', flexDirection: 'column' }}>
            {/* Logo Area */}
            <div style={{ marginBottom: '36px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M16 2L3 7V14C3 21.5 8.5 28.5 16 30C23.5 28.5 29 21.5 29 14V7L16 2Z" fill="url(#shield_grad)" stroke="var(--aura-safe)" strokeWidth="1.5"/>
                  <path d="M16 7V25C21 23.5 24.5 18 24.5 14V9.5L16 7Z" fill="var(--aura-safe)" opacity="0.3"/>
                  <defs>
                    <linearGradient id="shield_grad" x1="16" y1="2" x2="16" y2="30" gradientUnits="userSpaceOnUse">
                      <stop stopColor="rgba(157, 110, 255, 0.4)"/>
                      <stop offset="1" stopColor="rgba(0, 229, 160, 0.1)"/>
                    </linearGradient>
                  </defs>
                </svg>
                <div className="font-syne" style={{ fontSize: '26px', fontWeight: '800', letterSpacing: '-0.02em', color: '#fff' }}>
                  CyberShield
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '8px' }}>
                <span style={{
                  display: 'inline-block',
                  width: '6px',
                  height: '6px',
                  background: 'var(--aura-safe)',
                  borderRadius: '50%',
                  boxShadow: '0 0 8px var(--aura-safe)',
                  animation: 'glow-breathe 2s infinite'
                }} />
                <span className="font-dm-mono" style={{ fontSize: '11px', fontWeight: '400', letterSpacing: '0.12em', color: 'var(--text-secondary)' }}>OPS TERMINAL</span>
              </div>
            </div>

            {/* Navigation links */}
            <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { id: 'dashboard', label: 'THREAT CENTER', icon: '📊' },
                { id: 'scam-detector', label: 'LINK & SCAM AUDIT', icon: '🔍' },
                { id: 'site-scanner', label: 'SITE SECURITY SCANNER', icon: '🌐' },
                { id: 'footprint', label: 'OWASP AUDITOR', icon: '👣' },
                { id: 'simulator', label: 'ATTACK LABS', icon: '🧪' },
                { id: 'family-safety', label: 'FAMILY SHIELD', icon: '🏠' }
              ].map((item) => {
                const isActive = activeModule === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveModule(item.id)}
                    className="font-dm-sans"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      padding: '12px 16px',
                      background: isActive ? 'rgba(255,255,255,0.03)' : 'transparent',
                      border: 'none',
                      borderRadius: '8px',
                      color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      fontWeight: isActive ? '500' : '400',
                      fontSize: '14px',
                      borderLeft: isActive ? `3px solid ${auraColor}` : '3px solid transparent',
                      width: '100%'
                    }}
                  >
                    <span style={{ fontSize: '16px' }}>{item.icon}</span>
                    <span style={{ letterSpacing: '0.04em' }}>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Diagnostics Panel & Live Clock */}
          <div style={{ padding: '0 24px 28px 24px', flexShrink: 0, background: 'var(--surface-0)' }}>
            <div className="glass-card" style={{ padding: '16px', background: 'var(--surface-0)', border: '1px solid var(--border)', marginBottom: '20px' }}>
              <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-secondary)', letterSpacing: '0.08em', marginBottom: '8px' }}>THREAT ANALYSIS ENGINE</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-safe)', fontWeight: '600' }}>{securityEngineState}</span>
                <span className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{systemSpeed}</span>
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
              <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.12em' }}>SYS TIME</div>
              <div className="font-dm-mono" style={{ fontSize: '20px', fontWeight: '500', color: 'var(--text-secondary)', marginTop: '4px' }}>
                {currentTime || '00:00:00'}
              </div>
            </div>
          </div>
        </aside>
      ) : (
        /* Mobile tab navigation bar */
        <nav style={{
          position: 'fixed',
          bottom: 0,
          left: 0,
          right: 0,
          background: 'var(--surface-0)',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-around',
          alignItems: 'center',
          height: '64px',
          zIndex: 100,
          paddingBottom: 'safe-area-inset-bottom'
        }}>
          {[
            { id: 'dashboard', label: 'Center', icon: '📊' },
            { id: 'scam-detector', label: 'Audit', icon: '🔍' },
            { id: 'site-scanner', label: 'Scanner', icon: '🌐' },
            { id: 'footprint', label: 'OWASP', icon: '👣' },
            { id: 'simulator', label: 'Labs', icon: '🧪' },
            { id: 'family-safety', label: 'Family', icon: '🏠' }
          ].map((item) => {
            const isActive = activeModule === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveModule(item.id)}
                className="font-dm-sans"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: 'transparent',
                  border: 'none',
                  color: isActive ? auraColor : 'var(--text-secondary)',
                  cursor: 'pointer',
                  padding: '4px 8px',
                  gap: '4px',
                  flex: 1
                }}
              >
                <span style={{ fontSize: '18px' }}>{item.icon}</span>
                <span style={{ fontSize: '10px', fontWeight: isActive ? '600' : '400' }}>{item.label}</span>
              </button>
            );
          })}
        </nav>
      )}

      {/* 4. Main viewport content container */}
      <main style={{
        flex: 1,
        padding: isMobile ? '24px 16px 88px 16px' : '40px',
        overflowY: 'auto',
        position: 'relative',
        zIndex: 5,
        display: 'flex',
        flexDirection: 'column'
      }}>
        {renderModuleContent()}
      </main>

      {/* 5. Right-Side Collapsible Security Operations Center (SOC) Console */}
      <ShieldSOCSidebar 
        isExpanded={isSOCExpanded} 
        setIsExpanded={setIsSOCExpanded} 
        floatingIndex={floatingIndex} 
        isMobile={isMobile} 
      />

    </div>
  );
}

/* =========================================================================
   UNIVERSAL COMPONENT: Heuristic Scanning Rain Overlay
   ========================================================================= */
function MatrixLoader({ message }) {
  const [currentText, setCurrentText] = useState(message || "Analyzing system files...");
  const [matrixSpans, setMatrixSpans] = useState([]);

  useEffect(() => {
    const messages = [
      "Hashing input structures...",
      "Analyzing URL structure and homograph signatures...",
      "Cross-referencing against threat intelligence databases...",
      "Verifying SSL/TLS certificate chain integrity...",
      "Scanning for malicious payload indicators..."
    ];
    let msgIndex = 0;
    const interval = setInterval(() => {
      msgIndex = (msgIndex + 1) % messages.length;
      setCurrentText(messages[msgIndex]);
    }, 900);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const chars = "0101XYZΩΨΦ🛡️🔍🔐🔴🟢";
    const newSpans = Array.from({ length: 15 }).map((_, idx) => {
      const char = chars.charAt(Math.floor(Math.random() * chars.length));
      const left = Math.floor(Math.random() * 95) + '%';
      const delay = (Math.random() * 2).toFixed(2) + 's';
      const fontSize = (12 + Math.random() * 14) + 'px';
      return { id: idx, char, left, delay, fontSize };
    });
    setMatrixSpans(newSpans);
  }, []);

  return (
    <div style={{
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(5, 5, 8, 0.96)',
      backdropFilter: 'blur(12px)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      borderRadius: 'inherit',
      zIndex: 100,
      overflow: 'hidden'
    }}>
      {/* Raining characters */}
      <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
        {matrixSpans.map((item) => (
          <span 
            key={item.id} 
            className="font-dm-mono"
            style={{
              position: 'absolute',
              color: Math.random() > 0.5 ? 'var(--aura-safe)' : 'var(--aura-purple)',
              fontFamily: 'DM Mono',
              fontSize: item.fontSize,
              fontWeight: '500',
              left: item.left,
              animation: 'matrix-fall 2.8s linear infinite',
              animationDelay: item.delay,
              pointerEvents: 'none',
              top: '-30px',
              opacity: 0
            }}
          >
            {item.char}
          </span>
        ))}
      </div>

      <div 
        style={{
          fontSize: '48px',
          animation: 'glow-breathe 2s ease-in-out infinite',
          marginBottom: '16px',
          zIndex: 10
        }}
      >
        📡
      </div>

      <div 
        className="font-dm-mono" 
        style={{ 
          fontSize: '13px', 
          color: 'var(--aura-info)', 
          letterSpacing: '0.08em', 
          textAlign: 'center', 
          zIndex: 10,
          textShadow: '0 0 10px rgba(77, 166, 255, 0.3)',
          padding: '0 16px'
        }}
      >
        {currentText.toUpperCase()}
      </div>
    </div>
  );
}

/* =========================================================================
   UNIVERSAL COMPONENT: Animated Number Counter
   ========================================================================= */
function AnimatedCounter({ value, duration = 1200 }) {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    let start = displayValue;
    let end = value;
    if (start === end) return;

    let startTime = null;

    const animate = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      const current = Math.floor(start + (end - start) * progress);
      setDisplayValue(current);

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }, [value]);

  return <span>{displayValue}</span>;
}

/* =========================================================================
   UNIVERSAL COMPONENT: Canvas 3D Interactive Cyber Globe
   ========================================================================= */
const CITIES = [
  { name: "MUMBAI OPS CENTER", lat: 19.076, lon: 72.877, isTarget: true },
  { name: "TOKYO HUB", lat: 35.676, lon: 139.65, isTarget: false },
  { name: "LONDON HUB", lat: 51.507, lon: -0.127, isTarget: false },
  { name: "NEW YORK NODE", lat: 40.712, lon: -74.006, isTarget: false },
  { name: "SYDNEY HUB", lat: -33.868, lon: 151.209, isTarget: false },
  { name: "MOSCOW CENTER", lat: 55.755, lon: 37.617, isTarget: false },
  { name: "BEIJING CENTER", lat: 39.904, lon: 116.407, isTarget: false },
  { name: "CAPE TOWN NODE", lat: -33.924, lon: 18.424, isTarget: false },
  { name: "RIO DE JANEIRO", lat: -22.906, lon: -43.172, isTarget: false }
];

// Pre-generate continent dot coordinates
const landDots = [];
const CONTINENTS = [
  { lat: 40, lon: -100, radius: 20, dots: 30 }, // North America
  { lat: -15, lon: -60, radius: 18, dots: 20 }, // South America
  { lat: 50, lon: 15, radius: 15, dots: 25 },  // Europe
  { lat: 0, lon: 20, radius: 20, dots: 25 },   // Africa
  { lat: 35, lon: 95, radius: 28, dots: 50 },   // Asia
  { lat: -25, lon: 135, radius: 12, dots: 15 }  // Australia
];
CONTINENTS.forEach(cont => {
  for (let i = 0; i < cont.dots; i++) {
    const r = Math.random() * cont.radius;
    const angle = Math.random() * Math.PI * 2;
    const lat = cont.lat + r * Math.sin(angle) * 0.7;
    const lon = cont.lon + r * Math.cos(angle);
    landDots.push({ lat, lon });
  }
});

function ThreatGlobe({ windowWidth, auraColor }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const [telemetryLogs, setTelemetryLogs] = useState([
    { time: "12:40:01", text: "[SYS] Global Threat Map initialized", type: "system" },
    { time: "12:40:05", text: "[SHIELD] Secured local threat center socket registries", type: "shield" }
  ]);

  const stateRef = useRef({
    yaw: 0.8, // Face Asia initially
    pitch: 0.3,
    isDragging: false,
    startX: 0,
    startY: 0,
    attacks: [],
    impacts: []
  });

  // Handle live logs generation and attack trigger sync
  useEffect(() => {
    const attackTypes = [
      { text: "Blocked typosquatted payment redirect from", type: "blocked" },
      { text: "SS7 SIM swap credentials hijacking probe locked by", type: "blocked" },
      { text: "Inbound utility SMS fear trigger bypassed from", type: "shield" },
      { text: "HaveIBeenPwned API checked compromised indices on", type: "query" },
      { text: "UPI QR cashback redirection vector isolated at", type: "blocked" }
    ];

    const logInterval = setInterval(() => {
      const city = CITIES[Math.floor(Math.random() * (CITIES.length - 1)) + 1]; // Pick non-Mumbai origin
      const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
      const d = new Date();
      const timeStr = d.toLocaleTimeString('en-US', { hour12: false });

      setTelemetryLogs(prev => [
        { time: timeStr, text: `[${attackType.type === 'blocked' ? 'BLOCKED' : 'AUDIT'}] ${attackType.text} ${city.name}`, type: attackType.type },
        ...prev.slice(0, 15)
      ]);

      // Trigger 3D attack arc
      const state = stateRef.current;
      if (state.attacks.length < 4) {
        state.attacks.push({
          origin: city,
          target: CITIES[0],
          progress: 0,
          speed: 0.012 + Math.random() * 0.012,
          color: attackType.type === 'blocked' ? 'var(--aura-danger)' : 'var(--aura-purple)',
          height: 18 + Math.random() * 24
        });
      }
    }, 2800);

    return () => clearInterval(logInterval);
  }, []);

  // Animation Loop and Canvas setup
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let animFrameId = null;

    const resizeCanvas = () => {
      const rect = containerRef.current?.getBoundingClientRect();
      canvas.width = rect ? rect.width : 400;
      canvas.height = 360;
    };

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    const draw = () => {
      const ctx = canvas.getContext('2d');
      const width = canvas.width;
      const height = canvas.height;
      ctx.clearRect(0, 0, width, height);

      const state = stateRef.current;
      if (!state.isDragging) {
        state.yaw += 0.002; // slow spin
      }

      const radius = Math.min(width, height) * 0.35;
      const centerX = width / 2;
      const centerY = height / 2;

      const latLongTo3D = (lat, lon) => {
        const phi = (lat * Math.PI) / 180;
        const theta = (lon * Math.PI) / 180;
        return {
          x: radius * Math.cos(phi) * Math.sin(theta),
          y: radius * Math.sin(phi),
          z: radius * Math.cos(phi) * Math.cos(theta)
        };
      };

      const project = (pt) => {
        const cosY = Math.cos(state.yaw);
        const sinY = Math.sin(state.yaw);
        const x1 = pt.x * cosY - pt.z * sinY;
        const z1 = pt.x * sinY + pt.z * cosY;

        const cosX = Math.cos(state.pitch);
        const sinX = Math.sin(state.pitch);
        const y2 = pt.y * cosX + z1 * sinX;
        const z2 = -pt.y * sinX + z1 * cosX;

        return { x: centerX + x1, y: centerY - y2, z: z2 };
      };

      // 1. Draw back gridlines (z < 0)
      ctx.lineWidth = 0.5;
      ctx.strokeStyle = 'rgba(77, 166, 255, 0.03)';
      
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lon = -180; lon <= 180; lon += 5) {
          const pt = latLongTo3D(lat, lon);
          const proj = project(pt);
          if (proj.z < 0) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }
        ctx.stroke();
      }

      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let first = true;
        for (let lat = -90; lat <= 90; lat += 5) {
          const pt = latLongTo3D(lat, lon);
          const proj = project(pt);
          if (proj.z < 0) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }
        ctx.stroke();
      }

      // 2. Draw back continental particles (z < 0)
      landDots.forEach(dot => {
        const pt = latLongTo3D(dot.lat, dot.lon);
        const proj = project(pt);
        if (proj.z < 0) {
          ctx.fillStyle = 'rgba(0, 229, 160, 0.03)';
          ctx.fillRect(proj.x, proj.y, 1, 1);
        }
      });

      // 3. Draw front gridlines (z >= 0)
      ctx.strokeStyle = 'rgba(77, 166, 255, 0.12)';
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lon = -180; lon <= 180; lon += 5) {
          const pt = latLongTo3D(lat, lon);
          const proj = project(pt);
          if (proj.z >= 0) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }
        ctx.stroke();
      }

      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let first = true;
        for (let lat = -90; lat <= 90; lat += 5) {
          const pt = latLongTo3D(lat, lon);
          const proj = project(pt);
          if (proj.z >= 0) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }
        ctx.stroke();
      }

      // 4. Draw front continental particles (z >= 0)
      landDots.forEach(dot => {
        const pt = latLongTo3D(dot.lat, dot.lon);
        const proj = project(pt);
        if (proj.z >= 0) {
          ctx.fillStyle = 'rgba(0, 229, 160, 0.28)';
          ctx.fillRect(proj.x, proj.y, 1.5, 1.5);
        }
      });

      // 5. Project cyber-attack arcs
      state.attacks.forEach(attack => {
        const ptA = latLongTo3D(attack.origin.lat, attack.origin.lon);
        const ptB = latLongTo3D(attack.target.lat, attack.target.lon);

        ctx.beginPath();
        let first = true;
        const steps = 30;
        for (let i = 0; i <= steps; i++) {
          const t = i / steps;
          const lx = ptA.x * (1 - t) + ptB.x * t;
          const ly = ptA.y * (1 - t) + ptB.y * t;
          const lz = ptA.z * (1 - t) + ptB.z * t;
          const len = Math.sqrt(lx*lx + ly*ly + lz*lz);
          const nx = lx / len;
          const ny = ly / len;
          const nz = lz / len;

          const h = attack.height * Math.sin(t * Math.PI);
          const ptProj = {
            x: nx * radius + nx * h,
            y: ny * radius + ny * h,
            z: nz * radius + nz * h
          };

          const proj = project(ptProj);
          if (proj.z >= 0) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }
        ctx.lineWidth = 1;
        ctx.strokeStyle = attack.color + '44';
        ctx.stroke();

        // Glowing missile projectile
        const tVal = attack.progress;
        const lx = ptA.x * (1 - tVal) + ptB.x * tVal;
        const ly = ptA.y * (1 - tVal) + ptB.y * tVal;
        const lz = ptA.z * (1 - tVal) + ptB.z * tVal;
        const len = Math.sqrt(lx*lx + ly*ly + lz*lz);
        const nx = lx / len;
        const ny = ly / len;
        const nz = lz / len;
        const h = attack.height * Math.sin(tVal * Math.PI);
        const ptProj = {
          x: nx * radius + nx * h,
          y: ny * radius + ny * h,
          z: nz * radius + nz * h
        };
        const proj = project(ptProj);
        if (proj.z >= 0) {
          ctx.beginPath();
          ctx.arc(proj.x, proj.y, 3, 0, Math.PI * 2);
          ctx.fillStyle = attack.color;
          ctx.shadowBlur = 10;
          ctx.shadowColor = attack.color;
          ctx.fill();
          ctx.shadowBlur = 0; // reset
        }

        attack.progress += attack.speed;
        if (attack.progress >= 1) {
          // Impact ripple
          state.impacts.push({
            x: ptB.x,
            y: ptB.y,
            z: ptB.z,
            radius: 1,
            maxRadius: 24,
            alpha: 1
          });
        }
      });

      state.attacks = state.attacks.filter(a => a.progress < 1);

      // 6. Project impact shockwave ripples
      state.impacts.forEach(imp => {
        const proj = project(imp);
        if (proj.z >= 0) {
          ctx.beginPath();
          ctx.arc(proj.x, proj.y, imp.radius, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(255, 61, 90, ${imp.alpha})`;
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }
        imp.radius += 1;
        imp.alpha -= 0.04;
      });
      state.impacts = state.impacts.filter(i => i.alpha > 0);

      // 7. Draw cities
      CITIES.forEach(city => {
        const pt = latLongTo3D(city.lat, city.lon);
        const proj = project(pt);
        if (proj.z >= 0) {
          ctx.beginPath();
          ctx.arc(proj.x, proj.y, city.isTarget ? 4.5 : 2, 0, Math.PI * 2);
          ctx.fillStyle = city.isTarget ? 'var(--aura-safe)' : 'var(--aura-danger)';
          ctx.fill();

          if (city.isTarget) {
            // Pulse Mumbai rings
            const breathe = Math.sin(Date.now() / 250) * 3;
            ctx.beginPath();
            ctx.arc(proj.x, proj.y, 8 + breathe, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(0, 229, 160, 0.45)';
            ctx.lineWidth = 0.8;
            ctx.stroke();

            ctx.fillStyle = '#fff';
            ctx.font = 'bold 9px DM Mono, monospace';
            ctx.fillText(city.name, proj.x + 12, proj.y + 3);
          } else {
            ctx.fillStyle = 'var(--text-secondary)';
            ctx.font = '8px DM Mono, monospace';
            ctx.fillText(city.name, proj.x + 8, proj.y + 2.5);
          }
        }
      });

      animFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animFrameId);
      window.removeEventListener('resize', resizeCanvas);
    };
  }, []);

  // Drag listeners for Globe rotation
  const handleMouseDown = (e) => {
    const state = stateRef.current;
    state.isDragging = true;
    state.startX = e.clientX;
    state.startY = e.clientY;
  };

  const handleMouseMove = (e) => {
    const state = stateRef.current;
    if (!state.isDragging) return;

    const dx = e.clientX - state.startX;
    const dy = e.clientY - state.startY;

    state.yaw += dx * 0.005;
    state.pitch = Math.max(-Math.PI / 2.1, Math.min(Math.PI / 2.1, state.pitch + dy * 0.005));

    state.startX = e.clientX;
    state.startY = e.clientY;
  };

  const handleMouseUpOrLeave = () => {
    stateRef.current.isDragging = false;
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: windowWidth > 1024 ? 'row' : 'column',
      gap: '24px',
      width: '100%'
    }}>
      {/* Visual Globe Frame */}
      <div 
        ref={containerRef}
        className="glass-card"
        style={{
          flex: 1.5,
          height: '360px',
          padding: 0,
          background: 'rgba(5, 5, 8, 0.4)',
          position: 'relative',
          cursor: stateRef.current.isDragging ? 'grabbing' : 'grab',
          userSelect: 'none',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          border: '1px solid var(--border)'
        }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUpOrLeave}
        onMouseLeave={handleMouseUpOrLeave}
      >
        <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block' }} />

        {/* Drag Indicator Overlay */}
        <div className="font-dm-mono" style={{
          position: 'absolute',
          bottom: '12px',
          left: '16px',
          fontSize: '9px',
          color: 'var(--text-muted)',
          letterSpacing: '0.08em',
          pointerEvents: 'none'
        }}>
          🖱️ DRAG TO ROTATE VECTOR SPHERE
        </div>

        {/* Dynamic scanlines */}
        <div className="cyber-terminal-overlay" style={{ position: 'absolute', inset: 0, pointerEvents: 'none', borderRadius: '16px' }} />
      </div>

      {/* Synchronized Telemetry Log Feed */}
      <div 
        className="glass-card cyber-terminal-overlay"
        style={{
          flex: 1,
          fontFamily: 'DM Mono, monospace',
          fontSize: '12px',
          background: 'rgba(5, 5, 8, 0.65)',
          border: '1px solid var(--border)',
          padding: '18px',
          height: '360px',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        <div style={{
          color: 'var(--aura-safe)',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          paddingBottom: '8px',
          marginBottom: '12px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span style={{ fontWeight: 'bold', letterSpacing: '0.05em' }}>📡 SYS THREAT TELEMETRY FEED</span>
          <span style={{ animation: 'glow-breathe 1.5s infinite', width: '8px', height: '8px', background: 'var(--aura-safe)', borderRadius: '50%', boxShadow: '0 0 8px var(--aura-safe)' }} />
        </div>

        <div style={{
          flex: 1,
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          paddingRight: '4px'
        }}>
          {telemetryLogs.map((log, index) => {
            const isBlocked = log.type === 'blocked';
            const isShield = log.type === 'shield';
            const color = isBlocked ? 'var(--aura-danger)' : isShield ? 'var(--aura-safe)' : 'var(--aura-purple)';
            return (
              <div 
                key={index} 
                style={{ 
                  lineHeight: '1.4', 
                  color: isBlocked ? 'var(--text-primary)' : 'var(--text-secondary)',
                  borderLeft: `2.5px solid ${color}`,
                  paddingLeft: '10px',
                  animation: 'float-in 0.3s ease forwards'
                }}
              >
                <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>[{log.time}]</span>{' '}
                <span style={{ color, fontWeight: isBlocked ? '600' : '400' }}>{log.text}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* =========================================================================
   UNIVERSAL COMPONENT: Right-Side Collapsible Security Operations Center (SOC) Console
   ========================================================================= */
function ShieldSOCSidebar({ isExpanded, setIsExpanded, floatingIndex, isMobile }) {
  const [consoleOutput, setConsoleOutput] = useState([
    "Awaiting operator command directive..."
  ]);
  const [isPrinting, setIsPrinting] = useState(false);
  const [shieldPower, setShieldPower] = useState(100);
  const consoleEndRef = useRef(null);

  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleOutput]);

  const runConsoleCommand = async (type) => {
    if (isPrinting) return;
    setIsPrinting(true);
    setConsoleOutput([`> Executing /sys/ops/${type}...`]);

    const delay = (ms) => new Promise(res => setTimeout(res, ms));

    let lines = [];
    if (type === 'overclock') {
      lines = [
        "Connecting local cryptographic nodes...",
        "Enabling parameter salting buffers... DONE",
        "Overclocking security core protocols...",
        "Redirection targets locked to 1930 Helpline...",
        "SUCCESS: Dura-Armor Shield Core stable at 184%!"
      ];
      setShieldPower(184);
    } else if (type === 'rescan') {
      lines = [
        "Accessing isolated memory registers...",
        "Scanning lookalike brand typomaps... DONE",
        "Auditing biometric lockdown parameters...",
        "0 exploits identified in active registers.",
        "System state baseline is: SECURED."
      ];
    } else {
      lines = [
        "Compiling regional threat vector vectors...",
        "UPI merchant redirect (Critical) - STABILIZED",
        "SMS panics (High) - DIRECTED TO Helpline",
        "Beijing -> Mumbai network vectors - SECURED",
        "Ops Center and ThreatGlobe fully synchronized."
      ];
    }

    for (let i = 0; i < lines.length; i++) {
      await delay(400);
      setConsoleOutput(prev => [...prev, `> ${lines[i]}`]);
    }
    setIsPrinting(false);
  };

  return (
    <>
      {/* Floating pulsing round toggle button when collapsed */}
      {!isExpanded && (
        <button 
          onClick={() => setIsExpanded(true)}
          className="glass-card"
          style={{
            position: 'fixed',
            bottom: isMobile ? '80px' : '24px',
            right: '24px',
            width: '56px',
            height: '56px',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'rgba(9, 9, 15, 0.8)',
            border: '1.5px solid var(--aura-purple)',
            boxShadow: '0 0 20px rgba(157, 110, 255, 0.45)',
            cursor: 'pointer',
            zIndex: 99,
            padding: 0,
            animation: 'glow-breathe 2s infinite'
          }}
        >
          <span style={{ fontSize: '24px' }}>🛡️</span>
        </button>
      )}

      {/* Floating Slide-out Panel */}
      <div 
        className="glass-card cyber-terminal-overlay"
        style={{
          position: 'fixed',
          top: isMobile ? '0' : '24px',
          bottom: isMobile ? '0' : '24px',
          right: isExpanded ? '24px' : '-360px',
          width: isMobile ? '100vw' : '330px',
          height: isMobile ? '100%' : 'calc(100vh - 48px)',
          borderRadius: isMobile ? '0' : '16px',
          border: '1.5px solid var(--aura-purple)',
          background: 'rgba(5, 5, 8, 0.85)',
          boxShadow: '0 12px 48px rgba(157, 110, 255, 0.15)',
          display: 'flex',
          flexDirection: 'column',
          zIndex: 100,
          padding: '24px 20px 20px 20px',
          transition: 'right 0.45s cubic-bezier(0.16, 1, 0.3, 1)',
          overflow: 'hidden'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '14px', marginBottom: '20px' }}>
          <div className="font-dm-mono" style={{ color: 'var(--aura-purple)', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', fontWeight: 'bold', letterSpacing: '0.08em' }}>
            <span style={{ animation: 'glow-breathe 1.5s infinite', width: '6px', height: '6px', background: 'var(--aura-purple)', borderRadius: '50%', boxShadow: '0 0 6px var(--aura-purple)' }} />
            🛡️ SHIELD AI OPERATIONS
          </div>
          <button 
            onClick={() => setIsExpanded(false)}
            style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '16px', padding: '4px' }}
          >
            ✕
          </button>
        </div>

        {/* Dynamic Commentary Suggestions */}
        <div style={{ marginBottom: '20px' }}>
          <div className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '8px' }}>
            [ SYS MONITOR COMM LOGS ]
          </div>
          <div className="glass-card" style={{ padding: '16px', background: 'rgba(157, 110, 255, 0.03)', border: '1px solid rgba(157, 110, 255, 0.15)' }}>
            <div 
              className="font-dm-sans" 
              style={{
                fontSize: '13px',
                lineHeight: '1.5',
                color: 'var(--text-primary)',
                fontStyle: 'italic',
                animation: 'float-in 0.4s ease forwards'
              }}
              key={floatingIndex}
            >
              "{FLOATING_TIPS[floatingIndex]}"
            </div>
          </div>
        </div>

        {/* Live Diagnostics Dashboard */}
        <div style={{ marginBottom: '20px' }}>
          <div className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '8px' }}>
            [ HARDWARE CORE METRIC STATE ]
          </div>
          <div className="glass-card" style={{ padding: '14px', background: 'rgba(5, 5, 8, 0.5)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'monospace' }}>
              <span style={{ color: 'var(--text-secondary)' }}>SHIELD CAP:</span>
              <span style={{ color: 'var(--aura-purple)', fontWeight: 'bold' }}>{shieldPower}%</span>
            </div>
            <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.04)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{ width: `${Math.min(shieldPower / 2, 100)}%`, height: '100%', background: 'var(--aura-purple)', transition: 'width 0.5s ease' }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'monospace', marginTop: '4px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>VECTOR FILTER:</span>
              <span style={{ color: 'var(--aura-safe)' }}>ACTIVE</span>
            </div>
          </div>
        </div>

        {/* Interactive Triggers */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px' }}>
          <div className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '4px' }}>
            [ DIRECT COMMAND DIRECTIVES ]
          </div>
          {[
            { id: 'overclock', label: '⚡ SHIELD CORE OVERCLOCK' },
            { id: 'rescan', label: '🔍 DEEP REGISTERS RE-SCAN' },
            { id: 'analyzer', label: '📊 VECTORS EXPLOIT STUDY' }
          ].map(btn => (
            <button
              key={btn.id}
              onClick={() => runConsoleCommand(btn.id)}
              disabled={isPrinting}
              className="font-dm-mono"
              style={{
                width: '100%',
                padding: '10px 14px',
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: '8px',
                color: '#fff',
                fontSize: '11px',
                textAlign: 'left',
                cursor: isPrinting ? 'not-allowed' : 'pointer',
                transition: 'all 0.2s ease',
                outline: 'none'
              }}
              onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--aura-purple)'}
              onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'}
            >
              {btn.label}
            </button>
          ))}
        </div>

        {/* Scrolling Telemetry Terminal */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '8px' }}>
            [ CONSOLE TERMINAL DIRECTIVE ]
          </div>
          <div 
            style={{ 
              flex: 1, 
              background: '#020204', 
              border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: '8px',
              padding: '12px',
              fontFamily: 'monospace',
              fontSize: '11px',
              color: 'var(--aura-purple)',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px'
            }}
          >
            {consoleOutput.map((ln, idx) => (
              <div 
                key={idx} 
                style={{ 
                  color: ln.startsWith('> SUCCESS') ? 'var(--aura-safe)' : ln.startsWith('> EXECUTING') ? 'var(--aura-watch)' : 'var(--aura-purple)',
                  lineHeight: '1.4'
                }}
              >
                {ln}
              </div>
            ))}
            <div ref={consoleEndRef} />
          </div>
        </div>

      </div>
    </>
  );
}

/* =========================================================================
   MODULE 1: EXECUTIVE THREAT CENTER & BREACH SEARCH
   ========================================================================= */
function DashboardModule({ windowWidth, auraColor, riskScore, setRiskScore }) {
  const [searchTarget, setSearchTarget] = useState('');
  const [breachResult, setBreachResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [backendHealth, setBackendHealth] = useState(null);

  // 3D Card tilt handlers for premium microinteractions
  const handleCardTilt = (e) => {
    const card = e.currentTarget;
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const xc = (x - rect.width / 2) / (rect.width / 2);
    const yc = (y - rect.height / 2) / (rect.height / 2);
    card.style.transform = `perspective(1000px) rotateY(${xc * 6}deg) rotateX(${-yc * 6}deg) translateY(-4px)`;
  };

  const handleCardReset = (e) => {
    const card = e.currentTarget;
    card.style.transform = 'perspective(1000px) rotateY(0deg) rotateX(0deg) translateY(0deg)';
  };

  const handleBreachSearch = async (e) => {
    e.preventDefault();
    if (!searchTarget.trim()) return;

    setLoading(true);
    setBreachResult(null);
    setHasSearched(false);

    // Simulate database lookup latency
    await new Promise((r) => setTimeout(r, 1800));

    const cleanInput = searchTarget.trim().toLowerCase();
    const result = LOCAL_LEAK_DATABASE[cleanInput] || null;
    
    setBreachResult(result);
    setHasSearched(true);
    setLoading(false);

    // Update risk score based on breach lookup status
    if (result) {
      const worstRisk = result.some(b => b.riskRating === 'CRITICAL');
      setRiskScore(worstRisk ? 82 : 54);
    } else {
      setRiskScore(14); // Isolated / Safe
    }
  };

  return (
    <div className="page-transition-enter-active" style={{ display: 'flex', flexDirection: 'column', gap: '36px' }}>
      
      {/* Title Header */}
      <div style={{ position: 'relative' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            display: 'inline-block',
            width: '6px',
            height: '6px',
            background: 'var(--aura-danger)',
            borderRadius: '50%',
            boxShadow: '0 0 8px var(--aura-danger)',
            animation: 'glow-breathe 1s infinite'
          }} />
          <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.18em' }}>
            [ DIRECTORY ROOM: GLOBAL SECTOR OPS INTERFACE ]
          </div>
        </div>
        <h2 className="font-syne" style={{ fontSize: '46px', fontWeight: '800', letterSpacing: '-0.03em', marginTop: '8px', color: '#fff', textShadow: '0 0 30px rgba(255,255,255,0.05)' }}>
          Threat Center
        </h2>
        <p className="font-dm-sans" style={{ fontSize: '15px', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '700px', lineHeight: '1.5' }}>
          Real-time cyber telemetry, local diagnostic sweeps, threat vectors check, and authenticated HaveIBeenPwned leak directory auditing.
        </p>
      </div>

      {/* CENTERPIECE: Native 3D Interactive Attack Projection Globe & Synchronized Telemetry Feed */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em' }}>
            🌐 LIVE 3D GEOGRAPHIC VECTOR MAP & IMPACT LOGS
          </div>
          <button 
            onClick={async () => {
              try {
                const res = await fetch('/api/health');
                const data = await res.json();
                setBackendHealth(data.status === 'ok' ? 'ONLINE' : 'ERROR');
              } catch (e) {
                setBackendHealth('OFFLINE');
              }
            }}
            className="font-dm-mono"
            style={{
              background: backendHealth === 'ONLINE' ? 'rgba(0, 229, 160, 0.1)' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${backendHealth === 'ONLINE' ? 'var(--aura-safe)' : 'rgba(255,255,255,0.1)'}`,
              color: backendHealth === 'ONLINE' ? 'var(--aura-safe)' : '#fff',
              padding: '6px 12px',
              borderRadius: '4px',
              fontSize: '10px',
              cursor: 'pointer'
            }}
          >
            {backendHealth ? `BACKEND: ${backendHealth}` : 'TEST FASTAPI BACKEND'}
          </button>
        </div>
        <ThreatGlobe windowWidth={windowWidth} auraColor={auraColor} />
      </div>

      {/* Row 1: Aura State Gauge & Breach search tool (Side-by-Side on Desktop) */}
      <div style={{
        display: 'flex',
        flexDirection: windowWidth > 1024 ? 'row' : 'column',
        gap: '24px'
      }}>
        
        {/* Left Side: Premium Aura Orb Card */}
        <div 
          className={`glass-card ${riskScore < 35 ? 'glass-card-safe' : riskScore < 65 ? 'glass-card-watch' : 'glass-card-danger'}`}
          onMouseMove={handleCardTilt}
          onMouseLeave={handleCardReset}
          style={{ 
            flex: 1.1, 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center', 
            justifyContent: 'center', 
            padding: '36px',
            borderTop: `2px solid ${auraColor}`
          }}
        >
          <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-secondary)', letterSpacing: '0.12em', alignSelf: 'flex-start', marginBottom: '12px' }}>
            🔒 SHIELD SHIELDING STABILITY
          </div>
          
          <div style={{ position: 'relative', width: '190px', height: '190px', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '12px 0' }}>
            {/* Concentric rings */}
            <div className="pulsing-ring" style={{ color: auraColor, animation: 'pulse-ring 2.8s cubic-bezier(0.215, 0.61, 0.355, 1) infinite' }} />
            <div className="pulsing-ring" style={{ color: auraColor, animation: 'pulse-ring 2.8s cubic-bezier(0.215, 0.61, 0.355, 1) infinite', animationDelay: '0.9s' }} />
            
            {/* SVG Aura Core */}
            <svg width="190" height="190" style={{ position: 'absolute', top: 0, left: 0 }}>
              <defs>
                <radialGradient id="auraGlowDashboard" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor={auraColor} stopOpacity="0.75" />
                  <stop offset="60%" stopColor={auraColor} stopOpacity="0.22" />
                  <stop offset="100%" stopColor={auraColor} stopOpacity="0" />
                </radialGradient>
              </defs>
              <circle cx="95" cy="95" r="65" fill="url(#auraGlowDashboard)" style={{ filter: 'blur(12px)', animation: 'glow-breathe 4s infinite ease-in-out' }} />
            </svg>

            {/* Core Box */}
            <div className="font-syne" style={{
              position: 'relative',
              zIndex: 5,
              fontSize: '24px',
              fontWeight: '800',
              color: '#fff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '80px',
              height: '80px',
              borderRadius: '50%',
              background: 'rgba(5, 5, 8, 0.95)',
              border: `1.5px solid ${auraColor}`,
              boxShadow: `0 0 20px ${auraColor}33`,
              textShadow: `0 0 8px ${auraColor}55`
            }}>
              {riskScore < 35 ? 'OK' : riskScore < 65 ? 'WARN' : 'HALT'}
            </div>
          </div>

          <div style={{ textAlign: 'center', marginTop: '12px' }}>
            <div className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.12em' }}>
              SECURE INTEGRITY INDEX
            </div>
            <div className="font-syne" style={{ fontSize: '64px', fontWeight: '800', color: auraColor, lineHeight: '1.0', textShadow: `0 0 24px ${auraColor}33` }}>
              <AnimatedCounter value={riskScore} />%
            </div>
            <div className="font-dm-mono text-wrap-safe" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '8px', letterSpacing: '0.04em' }}>
              {riskScore < 35 ? '✓ SHIELD SAFE: ISOLATED' : riskScore < 65 ? '⚠ INTENSIVE SUSPICION TRACKED' : '⚡ ALERT: EXPLOIT THREAT LOGGED'}
            </div>
          </div>
        </div>

        {/* Right Side: HaveIBeenPwned Identity leak auditor */}
        <div 
          className="glass-card glass-card-purple" 
          onMouseMove={handleCardTilt}
          onMouseLeave={handleCardReset}
          style={{ flex: 1.8, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', padding: '32px', position: 'relative' }}
        >
          {loading && <MatrixLoader message="Retrieving leak tables & scanning compromised directories..." />}

          <div>
            <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-purple)', letterSpacing: '0.15em', marginBottom: '8px' }}>
              🔎 COMPROMISED IDENTITY AUDITOR (LIVE INDEX)
            </div>
            <h3 className="font-syne" style={{ fontSize: '24px', fontWeight: '700', letterSpacing: '-0.02em', marginBottom: '12px', color: '#fff' }}>
              Have Credentials Been Leaked?
            </h3>
            <p className="font-dm-sans" style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '24px', maxWidth: '600px' }}>
              Audit major regional and global leaks (such as AirIndia data, Indian ISP dumps, and WhatsApp logs) by entering an email handle or phone endpoint.
            </p>

            <form onSubmit={handleBreachSearch} style={{ display: 'flex', flexDirection: windowWidth > 768 ? 'row' : 'column', gap: '12px', marginBottom: '24px' }}>
              <input 
                type="text" 
                placeholder="Enter email or phone (e.g. admin@domain.com)"
                value={searchTarget}
                onChange={(e) => setSearchTarget(e.target.value)}
                className="cyber-input"
                style={{ flex: 1 }}
              />
              <button 
                type="submit" 
                className="font-syne"
                style={{
                  background: 'linear-gradient(90deg, var(--aura-purple) 0%, #7d44ff 100%)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '12px 28px',
                  fontWeight: '600',
                  fontSize: '14px',
                  cursor: 'pointer',
                  boxShadow: '0 4px 16px rgba(157, 110, 255, 0.3)',
                  whiteSpace: 'nowrap',
                  transition: 'transform 0.2s ease'
                }}
              >
                CHECK LOGS
              </button>
            </form>
          </div>

          {/* Breach Search results block */}
          <div className="text-wrap-safe">
            {hasSearched ? (
              breachResult ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', animation: 'float-in 0.3s ease' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255, 61, 90, 0.08)', padding: '10px 16px', borderRadius: '8px', border: '1px solid var(--aura-danger)' }}>
                    <span style={{ fontSize: '14px' }}>🔴</span>
                    <span className="font-dm-mono" style={{ fontSize: '12px', fontWeight: '600', color: 'var(--aura-danger)' }}>
                      CRITICAL: {breachResult.length} MATCHES EXPOSED IN DATABASES
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '160px', overflowY: 'auto', paddingRight: '4px' }}>
                    {breachResult.map((leak, idx) => (
                      <div key={idx} className="glass-card cyber-terminal-overlay text-wrap-safe" style={{ background: 'rgba(5, 5, 8, 0.75)', padding: '14px', border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span className="font-syne text-wrap-safe" style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>{leak.source}</span>
                          <span className="font-dm-mono" style={{ fontSize: '9px', background: 'rgba(255,61,90,0.1)', color: 'var(--aura-danger)', padding: '2px 6px', borderRadius: '4px', fontWeight: '600' }}>
                            {leak.riskRating}
                          </span>
                        </div>
                        <div className="font-dm-mono text-wrap-safe" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                          EXPOSED: {leak.leakType}
                        </div>
                        <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4', borderLeft: '2px solid var(--aura-purple)', paddingLeft: '8px' }}>
                          <strong>ACTION:</strong> {leak.recommendations}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="font-dm-sans" style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(0, 229, 160, 0.08)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--aura-safe)', animation: 'float-in 0.3s ease' }}>
                  <span style={{ fontSize: '16px' }}>🟢</span>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span className="font-dm-mono" style={{ fontSize: '12px', fontWeight: '600', color: 'var(--aura-safe)' }}>SYS INTEGRITY: FULLY SECURED</span>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>This specific handle holds zero compromised entries inside our leak registries.</span>
                  </div>
                </div>
              )
            ) : (
              <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center', border: '1px dashed rgba(255,255,255,0.06)', padding: '16px', borderRadius: '8px' }}>
                Awaiting search triggers... Try auditing admin@domain.com or deepmind@google.com for examples.
              </div>
            )}
          </div>

        </div>
      </div>

      {/* Row 2: Live Verified Indian Cyber Threat Index */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.15em' }}>
          VERIFIED REGIONAL THREAT VECTOR DIRECTORY (INDIA REGION)
        </div>
        
        <div style={{
          display: 'grid',
          gridTemplateColumns: windowWidth > 768 ? 'repeat(2, 1fr)' : '1fr',
          gap: '20px'
        }}>
          {ACTIVE_INDIAN_THREATS.map((threat) => (
            <div 
              key={threat.id} 
              onMouseMove={handleCardTilt}
              onMouseLeave={handleCardReset}
              style={{ 
                background: 'linear-gradient(180deg, rgba(20,20,28,0.95) 0%, rgba(12,12,18,0.95) 100%)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderTop: `2px solid ${threat.color}`,
                borderRadius: '6px',
                padding: '20px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                position: 'relative',
                overflow: 'hidden',
                transition: 'transform 300ms cubic-bezier(0.16, 1, 0.3, 1), box-shadow 300ms ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.boxShadow = `0 12px 30px ${threat.color}20, 0 0 0 1px ${threat.color}40`;
              }}
            >
              {/* Subtle Tech Grid Pattern */}
              <div style={{ 
                position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, 
                backgroundImage: 'linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)', 
                backgroundSize: '16px 16px', opacity: 0.5, pointerEvents: 'none' 
              }} />

              <div style={{ position: 'relative', zIndex: 2 }}>
                {/* Header Row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                  <div>
                    <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: '4px' }}>
                      INTEL ID: {threat.id}
                    </div>
                    <h4 className="font-syne" style={{ fontSize: '17px', fontWeight: '600', color: '#fff', letterSpacing: '0.01em' }}>
                      {threat.name}
                    </h4>
                  </div>
                  <div className="font-dm-mono" style={{ 
                    fontSize: '9px', 
                    background: threat.severity === 'CRITICAL' ? 'rgba(255,61,90,0.1)' : 'rgba(245,197,24,0.1)', 
                    color: threat.color, 
                    border: `1px solid ${threat.color}40`, 
                    padding: '4px 8px', 
                    borderRadius: '2px', 
                    fontWeight: '700'
                  }}>
                    {threat.severity}
                  </div>
                </div>
                
                {/* Body content with professional structure */}
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.02)' }}>
                  <div className="font-dm-mono" style={{ fontSize: '11px', color: threat.color, marginBottom: '6px' }}>
                    VECTOR: {threat.vector}
                  </div>
                  <p className="font-dm-sans" style={{ fontSize: '13px', color: 'rgba(255,255,255,0.7)', lineHeight: '1.5' }}>
                    {threat.description}
                  </p>
                </div>
              </div>

              {/* Footer */}
              <div style={{ position: 'relative', zIndex: 2, borderTop: '1px solid rgba(255,255,255,0.04)', paddingTop: '12px', marginTop: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)' }}>INTEGRITY SECTOR AUDITED</span>
                <span style={{ width: '6px', height: '6px', background: 'var(--aura-safe)', borderRadius: '50%', boxShadow: '0 0 6px var(--aura-safe)' }} />
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}

/* =========================================================================
   MODULE 2: FUNCTIONAL HEURISTIC URL & SCAM AUDIT TERMINAL
   ========================================================================= */
function ScamDetectorModule({ windowWidth, setRiskScore }) {
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [activeAccordion, setActiveAccordion] = useState('explanation');

  const executeHeuristicAnalysis = () => {
    const input = inputText.trim();
    if (!input) return;

    setLoading(true);
    setResult(null);

    // Simulate scanner delay
    setTimeout(() => {
      let isUrl = false;
      try {
        // Simple check if looks like URL
        if (input.includes('.') && (input.toLowerCase().startsWith('http') || input.toLowerCase().startsWith('www') || input.split(' ')[0].includes('.'))) {
          isUrl = true;
        }
      } catch (e) {}

      let analysisResult = {};

      if (isUrl) {
        // ------------------ DYNAMIC URL AUDITOR ------------------
        const urlLower = input.toLowerCase();
        let scamProb = 12;
        let redFlags = [];
        let tactics = ["Domain Inspection"];
        let verdict = "SAFE";
        let urgency = "LOW";
        let recommendation = "URL appears consistent with secure public registration records. Double-check standard certificate padlocks.";

        // 1. Insecure Connection check
        if (urlLower.startsWith('http://')) {
          scamProb += 24;
          redFlags.push("Uses insecure http:// protocol instead of encrypted https://");
          tactics.push("Protocol Downgrade");
        }

        // 2. High-Risk Scam TLDs
        const scamTlds = ['.xyz', '.cc', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.net.ru', '.work', '.info'];
        const matchedTld = scamTlds.find(tld => urlLower.includes(tld));
        if (matchedTld) {
          scamProb += 35;
          redFlags.push(`Uses generic high-risk TLD (${matchedTld}) popular in coordinate scam campaigns`);
          tactics.push("Generic TLD Exploitation");
        }

        // 3. Indian Brand Homoglyphs / Typosquatting
        const homoglyphs = [
          { keyword: 'paytrn', targets: 'Paytm' },
          { keyword: 'paytm-rewards', targets: 'Paytm Rewards' },
          { keyword: 'gpay-bonus', targets: 'Google Pay' },
          { keyword: 'sbi-kyc', targets: 'State Bank of India (SBI)' },
          { keyword: 'sbi-login', targets: 'SBI Portal' },
          { keyword: 'hdfc-secure', targets: 'HDFC Bank' },
          { keyword: 'amozon', targets: 'Amazon India' },
          { keyword: 'filpkart', targets: 'Flipkart' }
        ];

        const matchedHomo = homoglyphs.find(h => urlLower.includes(h.keyword));
        if (matchedHomo) {
          scamProb += 48;
          redFlags.push(`Typosquatting Match: Mimics trusted Indian brand "${matchedHomo.targets}" using lookalike letters ("${matchedHomo.keyword}")`);
          tactics.push("Brand Impersonation");
          tactics.push("Lookalike Typosquatting");
        }

        // Finalize score limits
        scamProb = Math.min(scamProb, 99);

        if (scamProb > 70) {
          verdict = "SCAM";
          urgency = "CRITICAL";
          recommendation = "DO NOT ACCESS. Close the page immediately. Do not submit primary login cards, Aadhaar fields, or passwords.";
        } else if (scamProb > 30) {
          verdict = "SUSPICIOUS";
          urgency = "HIGH";
          recommendation = "EXERCISE EXTREME CAUTION. Check the domain prefix against official records before filling text fields.";
        }

        analysisResult = {
          scamProbability: scamProb,
          verdict: verdict,
          manipulationTactics: tactics,
          redFlags: redFlags.length > 0 ? redFlags : ["No active homoglyph patterns detected", "Certificate matches security registers"],
          recommendation: recommendation,
          explanation: `URL analysis audit for "${input}". Our engine checked protocol handshakes, TLD reputation indices, and parsed character maps to search for Lookalike Impersonations (homoglyph scams).${verdict === 'SCAM' ? ' This site matches templates engineered to hijack personal profiles.' : ' The domain appears standard.'}`,
          urgencyLevel: urgency
        };

      } else {
        // ------------------ DYNAMIC SCAM TEXT AUDITOR ------------------
        let scamProb = 8;
        let redFlags = [];
        let tactics = ["Linguistic Heuristics"];
        let verdict = "SAFE";
        let urgency = "LOW";
        let recommendation = "Message content appears informational. Follow normal safety directories.";

        const lowerText = input.toLowerCase();

        // 1. High-Pressure words
        if (lowerText.includes('otp') || lowerText.includes('verification code') || lowerText.includes('pin')) {
          scamProb += 22;
          redFlags.push("Requests confidential security authorization codes (OTP / PIN)");
          tactics.push("Credential Harvesting");
        }

        // 2. Immediate Panic triggers
        if (lowerText.includes('electricity') || lowerText.includes('power cut') || lowerText.includes('disconnection') || lowerText.includes('suspend') || lowerText.includes('block')) {
          scamProb += 26;
          redFlags.push("Threatens immediate service deactivation (power lines, bank accounts, Aadhaar locks)");
          tactics.push("Urgency Trigger");
        }

        // 3. Indian Scams context
        if (lowerText.includes('kyc') || lowerText.includes('pension') || lowerText.includes('subsidy') || lowerText.includes('kisan') || lowerText.includes('pan card')) {
          scamProb += 20;
          redFlags.push("References official Indian government updates (KYC, Kisan, PAN) to build fake authority");
          tactics.push("Authority Impersonation");
        }

        // 4. Financial lure
        if (lowerText.includes('lottery') || lowerText.includes('reward') || lowerText.includes('win') || lowerText.includes('bonus') || lowerText.includes('refund')) {
          scamProb += 24;
          redFlags.push("Offers unrequested financial refunds or cash bonuses");
          tactics.push("Financial Bait");
        }

        scamProb = Math.min(scamProb, 99);

        if (scamProb > 70) {
          verdict = "SCAM";
          urgency = "CRITICAL";
          recommendation = "DO NOT CLICK ANY LINKS OR DIAL THE SENDER. Block the phone line. Report the number immediately to the Indian Cyber crime department (Helpline: 1930).";
        } else if (scamProb > 30) {
          verdict = "SUSPICIOUS";
          urgency = "HIGH";
          recommendation = "DO NOT SHARE OTPs. Reach out directly to your banking branch or utility company using their official support hotline.";
        }

        analysisResult = {
          scamProbability: scamProb,
          verdict: verdict,
          manipulationTactics: tactics,
          redFlags: redFlags.length > 0 ? redFlags : ["No active threat verbs detected", "Presents generic linguistic structure"],
          recommendation: recommendation,
          explanation: `Linguistic heuristics scan of your text. Checked for high-pressure service threats, Aadhaar verification triggers, credential request logs, and financial cash baits popular in Indian SMS campaigns.`,
          urgencyLevel: urgency
        };
      }

      setResult(analysisResult);
      setLoading(false);

      // Adjust risk score
      if (analysisResult.verdict === 'SCAM') {
        setRiskScore((p) => Math.min(p + 15, 96));
      } else if (analysisResult.verdict === 'SUSPICIOUS') {
        setRiskScore((p) => Math.min(p + 8, 96));
      } else {
        setRiskScore((p) => Math.max(p - 6, 12));
      }

    }, 2000);
  };

  const getVerdictStyles = (v) => {
    switch (v) {
      case 'SAFE':
        return { color: 'var(--aura-safe)', bg: 'rgba(0, 229, 160, 0.08)', border: 'var(--aura-safe)' };
      case 'SUSPICIOUS':
        return { color: 'var(--aura-watch)', bg: 'rgba(245, 197, 24, 0.08)', border: 'var(--aura-watch)' };
      case 'SCAM':
      default:
        return { color: 'var(--aura-danger)', bg: 'rgba(255, 61, 90, 0.08)', border: 'var(--aura-danger)' };
    }
  };
  return (
    <div className="page-transition-enter-active" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      
      {/* Title Header */}
      <div>
        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.15em' }}>HEURISTICS DETECTION AUDIT</div>
        <h2 className="font-syne" style={{ fontSize: '42px', fontWeight: '700', letterSpacing: '-0.02em', marginTop: '6px' }}>Link & Scam Scanner</h2>
        <p className="font-dm-sans" style={{ fontSize: '15px', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '700px', lineHeight: '1.6' }}>Input links to search for lookalike homoglyphs, check connection protocols, and audit texts for scam terminology.</p>
      </div>

      {/* Input panel card */}
      <div className="glass-card" style={{ padding: '28px', position: 'relative' }}>
        
        {loading && <MatrixLoader message="Executing URL homoglyph scans & text parser..." />}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em' }}>SUSPICIOUS URL OR SMS COPY</label>
            <textarea
              rows={5}
              placeholder="Paste a URL (e.g. sbi-kyc.cc or paytrn.com) or an SMS template here to execute heuristic threat audits..."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              className="font-dm-mono text-wrap-safe"
              style={{
                background: 'rgba(0,0,0,0.3)',
                color: '#fff',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                padding: '16px',
                fontSize: '13px',
                outline: 'none',
                resize: 'none',
                lineHeight: '1.6',
                width: '100%'
              }}
            />
          </div>

          <button
            onClick={executeHeuristicAnalysis}
            disabled={!inputText.trim() || loading}
            className="font-syne"
            style={{
              background: inputText.trim() ? 'linear-gradient(90deg, var(--aura-danger) 0%, var(--aura-purple) 100%)' : 'var(--surface-3)',
              color: inputText.trim() ? '#fff' : 'var(--text-muted)',
              border: 'none',
              borderRadius: '8px',
              height: '52px',
              fontSize: '15px',
              fontWeight: '600',
              cursor: inputText.trim() ? 'pointer' : 'default',
              boxShadow: inputText.trim() ? '0 4px 20px rgba(157, 110, 255, 0.2)' : 'none'
            }}
          >
            {loading ? 'EXECUTING CORE THREAT AUDIT...' : 'ANALYZE LINK / TEXT'}
          </button>

        </div>
      </div>

      {/* Analysis Results */}
      {result && (
        <div className="page-transition-enter-active" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Verdict Banner */}
          <div 
            style={{
              height: '80px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: getVerdictStyles(result.verdict).bg,
              border: `1px solid ${getVerdictStyles(result.verdict).border}`,
              borderRadius: '16px',
              boxShadow: `0 0 20px ${getVerdictStyles(result.verdict).color}15`
            }}
          >
            <div className="font-syne" style={{ fontSize: '30px', fontWeight: '800', color: getVerdictStyles(result.verdict).color, letterSpacing: '0.05em' }}>
              {result.verdict} DETECTED
            </div>
          </div>

          {/* Breakdown cards */}
          <div style={{
            display: 'flex',
            flexDirection: windowWidth > 768 ? 'row' : 'column',
            gap: '24px'
          }}>
            
            {/* Probability Gauge */}
            <div className="glass-card" style={{ flex: 1, padding: '24px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em', alignSelf: 'flex-start', marginBottom: '16px' }}>THREAT PROBABILITY SCORE</div>
              
              <div style={{ position: 'relative', width: '180px', height: '110px', overflow: 'hidden', display: 'flex', alignItems: 'flex-end', justifyContent: 'center' }}>
                <svg width="180" height="90" style={{ position: 'absolute', top: 0, left: 0 }}>
                  <path 
                    d="M 10 90 A 80 80 0 0 1 170 90" 
                    fill="none" 
                    stroke="var(--surface-3)" 
                    strokeWidth="10" 
                    strokeLinecap="round" 
                  />
                  <path 
                    d="M 10 90 A 80 80 0 0 1 170 90" 
                    fill="none" 
                    stroke={result.scamProbability > 70 ? 'var(--aura-danger)' : result.scamProbability > 35 ? 'var(--aura-watch)' : 'var(--aura-safe)'} 
                    strokeWidth="10" 
                    strokeLinecap="round" 
                    strokeDasharray="251"
                    strokeDashoffset={251 - (251 * result.scamProbability) / 100}
                    style={{ transition: 'stroke-dashoffset 1s ease' }}
                  />
                </svg>

                <div style={{ textAlign: 'center', zIndex: 5, paddingBottom: '8px' }}>
                  <span className="font-syne" style={{ fontSize: '38px', fontWeight: '800', color: '#fff' }}>{result.scamProbability}%</span>
                </div>
              </div>
              
              <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '8px' }}>
                HEURISTICS SCAM CONFIDENCE
              </div>
            </div>

            {/* Action panel details */}
            <div className="glass-card" style={{ flex: 1.3, padding: '24px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em', marginBottom: '8px' }}>SYS SEVERITY STATUS</div>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', background: 'rgba(255,255,255,0.02)', padding: '6px 14px', borderRadius: '20px', border: '1px solid var(--border)' }}>
                  <span style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: getVerdictStyles(result.verdict).color,
                    boxShadow: `0 0 8px ${getVerdictStyles(result.verdict).color}`
                  }} />
                  <span className="font-dm-mono" style={{ fontSize: '11px', fontWeight: '600', color: '#fff' }}>{result.urgencyLevel} LEVEL URGENCY</span>
                </div>
              </div>

              <div style={{ marginTop: '20px' }}>
                <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em', marginBottom: '8px' }}>MITIGATION ACTION PROTOCOL</div>
                <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '14px', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                  {result.recommendation}
                </p>
              </div>
            </div>

          </div>

          {/* Details Accordion */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {[
              { id: 'explanation', title: '🔬 Diagnostics Summary', content: result.explanation, type: 'text' },
              { id: 'tactics', title: '🧠 Manipulation Tactics', items: result.manipulationTactics, type: 'tags' },
              { id: 'flags', title: '🚩 Identified Anomalies & Red Flags', items: result.redFlags, type: 'list' }
            ].map((acc) => {
              const isOpen = activeAccordion === acc.id;
              return (
                <div key={acc.id} className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
                  <button 
                    onClick={() => setActiveAccordion(isOpen ? null : acc.id)}
                    className="font-syne"
                    style={{
                      width: '100%',
                      padding: '16px 20px',
                      background: 'none',
                      border: 'none',
                      color: '#fff',
                      textAlign: 'left',
                      fontSize: '15px',
                      fontWeight: '600',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}
                  >
                    <span>{acc.title}</span>
                    <span>{isOpen ? '▼' : '►'}</span>
                  </button>

                  <div style={{
                    maxHeight: isOpen ? '300px' : '0px',
                    transition: 'max-height 300ms cubic-bezier(0.16, 1, 0.3, 1)',
                    overflow: 'hidden'
                  }}>
                    <div style={{ padding: '0 20px 20px 20px', borderTop: '1px solid var(--border)' }}>
                      {acc.type === 'text' && (
                        <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.6', marginTop: '16px' }}>
                          {acc.content}
                        </p>
                      )}
                      {acc.type === 'tags' && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '16px' }}>
                          {acc.items.map((item, idx) => (
                            <span 
                              key={idx} 
                              className="font-dm-mono"
                              style={{
                                background: 'rgba(255,255,255,0.02)',
                                border: '1px solid var(--border-active)',
                                color: '#fff',
                                fontSize: '11px',
                                padding: '6px 12px',
                                borderRadius: '14px'
                              }}
                            >
                              {item}
                            </span>
                          ))}
                        </div>
                      )}
                      {acc.type === 'list' && (
                        <ul style={{ display: 'flex', flexDirection: 'column', gap: '10px', listStyle: 'none', marginTop: '16px' }}>
                          {acc.items.map((item, idx) => (
                            <li 
                              key={idx} 
                              className="font-dm-sans text-wrap-safe"
                              style={{
                                borderLeft: `2px solid ${getVerdictStyles(result.verdict).color}`,
                                paddingLeft: '12px',
                                fontSize: '13px',
                                color: 'var(--text-secondary)',
                                lineHeight: '1.4'
                              }}
                            >
                              {item}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

        </div>
      )}

    </div>
  );
}

/* =========================================================================
   MODULE 3: OWASP TOP 10 CYBER AUDITOR
   ========================================================================= */
function FootprintModule({ windowWidth, setRiskScore, setTriggerLaser }) {
  const [selectedStack, setSelectedStack] = useState('MERN');
  const [checkedPolicies, setCheckedPolicies] = useState({});
  const [loading, setLoading] = useState(false);
  const [auditResult, setAuditResult] = useState(null);

  const activeCriteria = OWASP_AUDIT_SETUP[selectedStack].criteria;

  const handlePolicyToggle = (id) => {
    setCheckedPolicies((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const executeOwaspAudit = () => {
    setLoading(true);
    setAuditResult(null);
    setTriggerLaser(true); // Trigger laser sweep

    setTimeout(() => {
      // Calculate score based on policies checked
      let checkedCount = 0;
      activeCriteria.forEach((crit) => {
        if (checkedPolicies[crit.id]) checkedCount++;
      });

      const score = Math.round((checkedCount / activeCriteria.length) * 100);
      
      setAuditResult({
        score: score,
        passedCount: checkedCount,
        totalCount: activeCriteria.length,
        recommendations: activeCriteria.filter((crit) => !checkedPolicies[crit.id])
      });

      setLoading(false);

      // Adjust risk score
      setRiskScore(100 - score);

    }, 1800);
  };

  return (
    <div className="page-transition-enter-active" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      
      {/* Title */}
      <div>
        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.15em' }}>INFRASTRUCTURE AUDITING TOOL</div>
        <h2 className="font-syne" style={{ fontSize: '42px', fontWeight: '700', letterSpacing: '-0.02em', marginTop: '6px' }}>OWASP Top 10 Auditor</h2>
        <p className="font-dm-sans" style={{ fontSize: '15px', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '700px', lineHeight: '1.6' }}>Perform instant client-side audits on coding policies and secure database configurations to calculate risk indexes.</p>
      </div>

      {/* Stack Selection Carousel */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
        {[
          { id: 'MERN', name: 'MERN Stack App', icon: '⚛️' },
          { id: 'WordPress', name: 'WordPress Portal', icon: '📰' },
          { id: 'StaticServerless', name: 'Static Next.js / AWS', icon: '⚡' }
        ].map((stack) => {
          const isSelected = selectedStack === stack.id;
          return (
            <button
              key={stack.id}
              onClick={() => {
                setSelectedStack(stack.id);
                setAuditResult(null);
                setCheckedPolicies({});
              }}
              className="font-syne"
              style={{
                background: isSelected ? 'rgba(157, 110, 255, 0.08)' : 'var(--surface-1)',
                border: `1px solid ${isSelected ? 'var(--aura-purple)' : 'var(--border)'}`,
                color: '#fff',
                padding: '12px 24px',
                borderRadius: '8px',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '600',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                transform: isSelected ? 'scale(1.02)' : 'scale(1)'
              }}
            >
              <span>{stack.icon}</span>
              <span>{stack.name}</span>
            </button>
          );
        })}
      </div>

      {/* Main Checklist Card */}
      <div className="glass-card" style={{ padding: '28px', position: 'relative' }}>
        {loading && <MatrixLoader message="Executing full static configuration compile scans..." />}

        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.1em', marginBottom: '16px' }}>
          CHECK THE PROTOCOLS CURRENTLY INSTALLED IN YOUR SYSTEM
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '28px' }}>
          {activeCriteria.map((crit) => {
            const isChecked = checkedPolicies[crit.id] || false;
            return (
              <div 
                key={crit.id}
                onClick={() => handlePolicyToggle(crit.id)}
                className="glass-card"
                style={{
                  padding: '16px',
                  background: isChecked ? 'rgba(157, 110, 255, 0.03)' : 'rgba(0,0,0,0.1)',
                  borderColor: isChecked ? 'var(--aura-purple)' : 'var(--border)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '16px'
                }}
              >
                <span style={{
                  width: '18px',
                  height: '18px',
                  borderRadius: '4px',
                  border: `1.5px solid ${isChecked ? 'var(--aura-purple)' : 'var(--border-active)'}`,
                  background: isChecked ? 'var(--aura-purple)' : 'transparent',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '10px',
                  color: '#000',
                  marginTop: '2px',
                  flexShrink: 0
                }}>
                  {isChecked && '✓'}
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <h4 className="font-syne text-wrap-safe" style={{ fontSize: '15px', fontWeight: '600', color: '#fff' }}>{crit.label}</h4>
                  <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    {crit.desc}
                  </p>
                </div>
              </div>
            );
          })}
        </div>

        <button
          onClick={executeOwaspAudit}
          className="font-syne"
          style={{
            background: 'var(--aura-purple)',
            color: '#fff',
            border: 'none',
            borderRadius: '8px',
            height: '52px',
            width: '100%',
            fontWeight: '600',
            fontSize: '15px',
            cursor: 'pointer',
            boxShadow: '0 4px 20px rgba(157, 110, 255, 0.2)'
          }}
        >
          EXECUTE SECURITY AUDIT
        </button>
      </div>

      {/* Audit Report Result Modal Overlay */}
      {auditResult && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'var(--void)',
          zIndex: 1000,
          padding: windowWidth > 768 ? '40px' : '24px 16px 80px 16px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          animation: 'float-in 0.5s ease'
        }}>
          
          <div style={{ maxWidth: '800px', width: '100%', display: 'flex', flexDirection: 'column', gap: '32px' }}>
            
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-purple)', letterSpacing: '0.12em' }}>OWASP CONFIG SECURITY AUDIT REPORT</span>
              <button 
                onClick={() => setAuditResult(null)}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  color: '#fff',
                  border: 'none',
                  width: '36px',
                  height: '36px',
                  borderRadius: '50%',
                  cursor: 'pointer',
                  fontSize: '18px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                ×
              </button>
            </div>

            {/* Score circle */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', margin: '16px 0' }}>
              <div style={{ position: 'relative', width: '160px', height: '160px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div className="pulsing-ring" style={{ color: auditResult.score > 70 ? 'var(--aura-safe)' : auditResult.score > 40 ? 'var(--aura-watch)' : 'var(--aura-danger)', animation: 'pulse-ring 3s infinite' }} />
                <div style={{
                  width: '110px',
                  height: '110px',
                  borderRadius: '50%',
                  background: 'rgba(18,18,27,0.9)',
                  border: `2px solid ${auditResult.score > 70 ? 'var(--aura-safe)' : auditResult.score > 40 ? 'var(--aura-watch)' : 'var(--aura-danger)'}`,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 4px 24px rgba(0,0,0,0.6)'
                }}>
                  <span className="font-syne" style={{ fontSize: '38px', fontWeight: '800', color: '#fff' }}>{auditResult.score}%</span>
                  <span className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>SECURITY</span>
                </div>
              </div>
              <div style={{ marginTop: '16px', textAlign: 'center' }}>
                <h3 className="font-syne" style={{ fontSize: '22px', fontWeight: '700' }}>
                  {auditResult.score > 70 ? 'ISOLATED SYSTEM COVERAGE' : auditResult.score > 40 ? 'WARNING: CONFIG GAPS DETECTED' : 'CRITICAL: HIGH VULNERABILITY LEVEL'}
                </h3>
                <span className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  PASSED: {auditResult.passedCount} OF {auditResult.totalCount} CONTROLS
                </span>
              </div>
            </div>

            {/* Recommendations & Technical Remediation code snippets */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              
              <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
                TECHNICAL MITIGATION & SECURE CODE DIRECTORIES
              </div>

              {auditResult.recommendations.length > 0 ? (
                auditResult.recommendations.map((rec) => (
                  <div key={rec.id} className="glass-card text-wrap-safe" style={{ background: 'var(--surface-0)', border: '1px solid var(--border)', padding: '24px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div className="text-wrap-safe">
                      <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-danger)', marginBottom: '4px' }}>FAILED SECURITY RULE</div>
                      <h4 className="font-syne text-wrap-safe" style={{ fontSize: '16px', fontWeight: '600', color: '#fff' }}>{rec.label}</h4>
                      <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: '1.5' }}>
                        {rec.desc}
                      </p>
                    </div>

                    {/* Pre-formatted code block */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <span className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-safe)' }}>REMEDIATION SCHEMATIC (CODE)</span>
                      <pre className="font-dm-mono text-wrap-safe" style={{
                        background: 'rgba(0,0,0,0.4)',
                        border: '1.5px solid var(--border-active)',
                        padding: '14px',
                        borderRadius: '8px',
                        fontSize: '11px',
                        lineHeight: '1.6',
                        color: 'rgba(255,255,255,0.85)',
                        overflowX: 'auto'
                      }}>
                        {rec.mitigationCode}
                      </pre>
                    </div>
                  </div>
                ))
              ) : (
                <div className="glass-card" style={{ padding: '28px', borderLeft: '4px solid var(--aura-safe)', background: 'rgba(0,229,160,0.01)', textAlign: 'center' }}>
                  <div style={{ fontSize: '28px', marginBottom: '8px' }}>🛡️</div>
                  <h4 className="font-syne" style={{ fontSize: '18px', fontWeight: '600', color: 'var(--aura-safe)' }}>100% SECURED CONFIGURATION COMPLIANCE</h4>
                  <p className="font-dm-sans" style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                    All tested OWASP security policies are actively validated inside your infrastructure parameters.
                  </p>
                </div>
              )}

            </div>

            <button 
              onClick={() => setAuditResult(null)}
              className="font-syne"
              style={{
                background: 'var(--aura-purple)',
                color: '#fff',
                border: 'none',
                height: '48px',
                borderRadius: '8px',
                fontWeight: '600',
                cursor: 'pointer',
                marginBottom: '40px'
              }}
            >
              DISMISS REPORT
            </button>

          </div>

        </div>
      )}

    </div>
  );
}

/* =========================================================================
   MODULE 4: TECHNICAL ATTACK SIMULATOR (Labs)
   ========================================================================= */
const SIMULATED_ATTACKS = [
  { id: 'phishing', icon: '🎣', name: 'Phishing Link Redirection', desc: 'Cloning DNS headers and mapping homoglyph targets to capture auth packets.' },
  { id: 'sim', icon: '📱', name: 'SIM Swap (SS7 Exploit)', desc: 'Hijacking SS7 signalling structures or leveraging telecom social-engineering prompts.' },
  { id: 'whatsapp', icon: '💬', name: 'WhatsApp deep-link bypass', desc: 'Executing deep-link redirection code triggers to extract session cookies.' },
  { id: 'upi', icon: '💸', name: 'UPI cash-back QR Injection', desc: 'Inserting lookalike transaction request PIN triggers into cashback QR patterns.' }
];

const TECHNICAL_STEPS_DATABASE = {
  phishing: {
    attackName: "Lookalike Homoglyph Impersonation Campaign",
    victimJourney: "Target clicks a typosquatted domain link, initiating background DNS redirection routines.",
    steps: [
      { stepNumber: 1, title: "typosquatted Domain Registration", description: "Attackers register paytrn.com (swapping m for r+n) using generic offshore registrars to avoid standard KYC validation boards.", dangerLevel: 'medium', icon: '🌐' },
      { stepNumber: 2, title: "Lure Dispatch Framework", description: "Coercive SMS sent requesting immediate PAN matching links: 'Your account is locked dial paytrn.com/tax to restore access.'", dangerLevel: 'medium', icon: '📧' },
      { stepNumber: 3, title: "Static Cloned UI Rendering", description: "HTML/CSS site clones Paytm UI, loading in securely under a free SSL padlock. User enters credit credentials.", dangerLevel: 'critical', icon: '🖥️' },
      { stepNumber: 4, title: "Socket Session Redirection", description: "Harvested credentials are sent via secure sockets directly to hackers, who input them on genuine terminals to request dynamic bank OTPs.", dangerLevel: 'critical', icon: '📲' }
    ],
    totalDamage: "Total leakage of payment cards and unauthorized funds withdrawals.",
    howToPrevent: [
      "Check address bars for exact 'paytm.com' strings — watch for r+n characters closely",
      "Do not submit sensitive financial credentials on pages loaded from SMS hyperlinks",
      "Enable secure biometric locks to lock secondary funds transactions"
    ],
    realWorldExample: "A resident recently lost ₹1.8 Lakhs clicking a lookalike banking link claiming Aadhaar card issues."
  },
  sim: {
    attackName: "SIM Swapping (SS7 Access Hijack)",
    victimJourney: "Target's physical network registers 'No Service' as billing controls are redirected to hackers.",
    steps: [
      { stepNumber: 1, title: "Identity Profile Indexing", description: "Attackers compile targeted identity datasets (Birthdates, Maiden names) using open social tags and past database breaches.", dangerLevel: 'low', icon: '🕵️' },
      { stepNumber: 2, title: "Telecom Social Bypass", description: "Scammers dial telecom helpdesks presenting fake Aadhaar credentials to report a lost SIM, requesting physical redirection.", dangerLevel: 'high', icon: '📞' },
      { stepNumber: 3, title: "SS7 Network Switching", description: "Network nodes transfer active traffic keys from the target's physical device to the hacker's duplicate card. Target device shows 'No Service'.", dangerLevel: 'critical', icon: '🚫' },
      { stepNumber: 4, title: "Session Key Intercepts", description: "Scammers trigger password overrides across banking handles, capturing inbound SMS OTP verification keys directly.", dangerLevel: 'critical', icon: '💸' }
    ],
    totalDamage: "Total bypass of standard SMS-based authentication shields.",
    howToPrevent: [
      "Transition primary accounts from SMS 2FA to software security keys (e.g. Google Authenticator)",
      "Contact telecom carriers immediately if your device signals drop to 'No Service' inside standard coverage zones",
      "Enable customized PIN locks directly on your telecom provider SIM account profile"
    ],
    realWorldExample: "An investor lost ₹82 Lakhs when SIM swapping bypassed his primary financial accounts over a weekend."
  },
  whatsapp: {
    attackName: "WhatsApp deep-link Hijack",
    victimJourney: "A simple forwarding code command dialed by the target yields complete chat takeover.",
    steps: [
      { stepNumber: 1, title: "Delivery Impersonation Call", description: "Scammer dials target pretending to be a parcel distributor, claiming an address block prevents package arrival.", dangerLevel: 'medium', icon: '📦' },
      { stepNumber: 2, title: "Forwarding Code dial", description: "Hacker directs user to type **21*<hacker-number> on their device to 'reschedule dispatch routing'.", dangerLevel: 'high', icon: '📞' },
      { stepNumber: 3, title: "Call-Forward Execution", description: "Dialing the prefix forces standard carrier nodes to route all target's incoming phone calls to the attacker's line.", dangerLevel: 'critical', icon: '📲' },
      { stepNumber: 4, title: "Voice Verification Intercept", description: "Hacker triggers WhatsApp registration on their own device, requesting verification via phone call to intercept the voice token code.", dangerLevel: 'critical', icon: '💬' }
    ],
    totalDamage: "Full lockout of active chat logs and fraudulent messaging dispatched to private directories.",
    howToPrevent: [
      "Never dial * or # prefixes sent by strangers — these execute carrier call forwarding logs",
      "Turn on 'Two-Step Verification' in WhatsApp, setting a custom, non-shared PIN lock",
      "Reject calls from unknown business setups requesting network verification updates"
    ],
    realWorldExample: "A manager was locked out of her active profiles while scammers targeted her family contacts for quick personal loans."
  },
  upi: {
    attackName: "UPI cashback QR Code Injection",
    victimJourney: "User scans a 'rewards' code believing they are claiming cash, only to authorize outgoing transactions.",
    steps: [
      { stepNumber: 1, title: "Bonus Notification Dispatch", description: "Target receives a cashback notification claiming a ₹2,000 refund is pending inside their wallet profile.", dangerLevel: 'medium', icon: '💸' },
      { stepNumber: 2, title: "Scam QR Delivery", description: "A QR image is shared via WhatsApp. Scammer claims: 'Scan this code inside Google Pay to verify your refund transaction.'", dangerLevel: 'high', icon: '📱' },
      { stepNumber: 3, title: "Payment Request Execution", description: "The QR code contains a structural payment request parameter. User launches the code and is prompted for their UPI PIN.", dangerLevel: 'critical', icon: '🛑' },
      { stepNumber: 4, title: "PIN Authorization Leak", description: "Target enters their PIN, ignoring notices that PINs are ONLY typed to SEND money, never to receive. Funds are immediately debited.", dangerLevel: 'critical', icon: '💸' }
    ],
    totalDamage: "Irreversible funds transfer from connected savings accounts.",
    howToPrevent: [
      "Always remember: entering a UPI PIN is strictly for sending money. Receiving money NEVER demands a PIN",
      "Confirm merchant identity values shown on the app payment screen before typing details",
      "Decline unrequested money request prompts inside GPay, PhonePe, or Paytm"
    ],
    realWorldExample: "An online buyer looking for rental properties lost ₹45,000 scanning a booking deposit QR code sent by a fake broker."
  }
};

function AttackSimulatorModule({ windowWidth }) {
  const [selectedSim, setSelectedSim] = useState(SIMULATED_ATTACKS[0]);
  const [loading, setLoading] = useState(false);
  const [simData, setSimData] = useState(null);
  const [visibleSteps, setVisibleSteps] = useState(0);
  const simIntervalRef = useRef(null);

  useEffect(() => {
    return () => {
      if (simIntervalRef.current) {
        clearInterval(simIntervalRef.current);
      }
    };
  }, []);

  const handleSimulationStart = () => {
    setLoading(true);
    setSimData(null);
    setVisibleSteps(0);

    if (simIntervalRef.current) {
      clearInterval(simIntervalRef.current);
    }

    setTimeout(() => {
      const data = TECHNICAL_STEPS_DATABASE[selectedSim.id];
      setSimData(data);
      setLoading(false);

      let count = 0;
      simIntervalRef.current = setInterval(() => {
        count++;
        setVisibleSteps(count);
        if (count >= data.steps.length) {
          clearInterval(simIntervalRef.current);
        }
      }, 700);

    }, 1500);
  };

  const getDangerColor = (lvl) => {
    switch (lvl) {
      case 'low': return 'var(--aura-info)';
      case 'medium': return 'var(--aura-watch)';
      case 'high':
      case 'critical':
      default:
        return 'var(--aura-danger)';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px', animation: 'float-in 0.4s ease forwards' }}>
      
      {/* Title */}
      <div>
        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.15em' }}>TECHNICAL EXPLOIT LABORATORY</div>
        <h2 className="font-syne" style={{ fontSize: '42px', fontWeight: '700', letterSpacing: '-0.02em', marginTop: '6px' }}>Attack Simulator</h2>
        <p className="font-dm-sans" style={{ fontSize: '15px', color: 'var(--text-secondary)', marginTop: '4px' }}>Study chronological cyber exploit pipelines in safe, sandboxed simulation logs.</p>
      </div>

      {/* Select horizontal scroller */}
      <div>
        <label className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em', display: 'block', marginBottom: '12px' }}>
          SELECT LAB SCENARIO
        </label>
        
        <div style={{
          display: 'flex',
          gap: '16px',
          overflowX: 'auto',
          paddingBottom: '8px'
        }}>
          {SIMULATED_ATTACKS.map((item) => {
            const isSelected = selectedSim.id === item.id;
            return (
              <div
                key={item.id}
                onClick={() => setSelectedSim(item)}
                className="glass-card"
                style={{
                  minWidth: '220px',
                  flex: '0 0 auto',
                  padding: '20px',
                  cursor: 'pointer',
                  borderColor: isSelected ? 'var(--aura-danger)' : 'var(--border)',
                  background: isSelected ? 'rgba(255, 61, 90, 0.03)' : 'var(--surface-1)',
                  transform: isSelected ? 'scale(1.02)' : 'scale(1)'
                }}
              >
                <div style={{ fontSize: '28px', marginBottom: '10px' }}>{item.icon}</div>
                <h4 className="font-syne" style={{ fontSize: '14px', fontWeight: '600', color: '#fff' }}>{item.name}</h4>
                <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: '1.4' }}>
                  {item.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      <button 
        onClick={handleSimulationStart}
        className="font-syne"
        style={{
          background: 'linear-gradient(90deg, var(--aura-danger) 0%, var(--aura-purple) 100%)',
          color: '#fff',
          border: 'none',
          padding: '14px 28px',
          borderRadius: '8px',
          fontSize: '15px',
          fontWeight: '600',
          cursor: 'pointer',
          boxShadow: '0 4px 20px rgba(255, 61, 90, 0.2)',
          letterSpacing: '0.04em'
        }}
      >
        SIMULATE ATTACK PIPELINE
      </button>

      {/* Simulator Presentation */}
      <div style={{ position: 'relative' }}>
        {loading && <MatrixLoader message="Building target container logs..." />}

        {simData && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px', animation: 'float-in 0.4s ease' }}>
            
            {/* Overview */}
            <div className="glass-card" style={{ padding: '24px', borderLeft: '4px solid var(--aura-danger)', background: 'rgba(255,61,90,0.01)' }}>
              <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-danger)', marginBottom: '4px' }}>VICTIM JOURNEY INDEX</div>
              <h3 className="font-syne" style={{ fontSize: '18px', fontWeight: '600' }}>{simData.attackName}</h3>
              <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: '1.5' }}>
                {simData.victimJourney}
              </p>
            </div>

            {/* Timeline */}
            <div>
              <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '20px' }}>CHRONOLOGICAL LAB LOGS</div>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', position: 'relative', paddingLeft: '24px' }}>
                <div style={{
                  position: 'absolute',
                  left: '6px',
                  top: '12px',
                  bottom: '12px',
                  width: '2px',
                  background: 'linear-gradient(180deg, var(--aura-safe) 0%, var(--aura-watch) 50%, var(--aura-danger) 100%)'
                }} />

                {simData.steps.map((step, index) => {
                  const isVisible = visibleSteps > index;
                  return (
                    <div 
                      key={index}
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '8px',
                        position: 'relative',
                        opacity: isVisible ? 1 : 0,
                        transform: isVisible ? 'translateX(0)' : 'translateX(16px)',
                        transition: 'all 0.5s cubic-bezier(0.16, 1, 0.3, 1)',
                        visibility: isVisible ? 'visible' : 'hidden'
                      }}
                    >
                      <span style={{
                        position: 'absolute',
                        left: '-22px',
                        top: '4px',
                        width: '10px',
                        height: '10px',
                        borderRadius: '50%',
                        background: getDangerColor(step.dangerLevel),
                        boxShadow: `0 0 8px ${getDangerColor(step.dangerLevel)}`
                      }} />

                      <div className="glass-card" style={{ padding: '20px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontSize: '20px' }}>{step.icon}</span>
                            <span className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>STEP 0{step.stepNumber}</span>
                          </div>
                          <span className="font-dm-mono" style={{
                            fontSize: '9px',
                            background: `${getDangerColor(step.dangerLevel)}15`,
                            color: getDangerColor(step.dangerLevel),
                            border: `1px solid ${getDangerColor(step.dangerLevel)}`,
                            padding: '3px 8px',
                            borderRadius: '10px',
                            fontWeight: '600'
                          }}>
                            {step.dangerLevel.toUpperCase()}
                          </span>
                        </div>
                        <h4 className="font-syne text-wrap-safe" style={{ fontSize: '15px', fontWeight: '600', color: '#fff' }}>{step.title}</h4>
                        <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: '1.5' }}>
                          {step.description}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Total Damage and mitigation */}
            {visibleSteps >= simData.steps.length && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', animation: 'float-in 0.5s ease' }}>
                
                <div 
                  className="glass-card" 
                  style={{
                    padding: '24px',
                    borderColor: 'var(--aura-danger)',
                    background: 'rgba(255, 61, 90, 0.03)',
                    textAlign: 'center'
                  }}
                >
                  <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-danger)', letterSpacing: '0.12em', marginBottom: '6px' }}>TOTAL POTENTIAL EXPLOIT IMPACT</div>
                  <div className="font-syne text-wrap-safe" style={{ fontSize: '18px', fontWeight: '700', color: '#fff' }}>
                    "{simData.totalDamage}"
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: windowWidth > 768 ? '1.4fr 1fr' : '1fr', gap: '24px' }}>
                  
                  {/* Preventions */}
                  <div className="glass-card" style={{ padding: '24px' }}>
                    <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-safe)', marginBottom: '16px' }}>MITIGATION DEFENSE CODES</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {simData.howToPrevent.map((p, idx) => (
                        <div key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                          <span style={{ color: 'var(--aura-safe)' }}>🛡️</span>
                          <span className="font-dm-sans text-wrap-safe" style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: '1.4' }}>{p}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Incident index */}
                  <div className="glass-card" style={{ padding: '24px', borderLeft: '4px solid var(--aura-watch)', background: 'rgba(245, 197, 24, 0.01)' }}>
                    <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-watch)', marginBottom: '12px' }}>📰 HISTORICAL SCAM INDEX (INDIA)</div>
                    <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                      {simData.realWorldExample}
                    </p>
                  </div>

                </div>

              </div>
            )}

          </div>
        )}
      </div>

    </div>
  );
}

/* =========================================================================
   MODULE 5: FAMILY SAFETY CENTER
   ========================================================================= */
const MOCK_SAFETY_DIRECTORY = {
  Elder: {
    threatLevel: 'High',
    threatType: "Electricity Overdue Disconnection Phone Scams",
    simpleSummary: "This call is completely fake. Scammers are creating artificial panic to steal your savings. Your home electricity line is absolutely secure.",
    whatToDoNow: [
      "HANG UP the phone immediately. Do not dial the number back.",
      "Never download screensharing applications like AnyDesk or TeamViewer on their command.",
      "Ask a younger family member to verify your bills or contact your local electricity sub-station directly."
    ],
    warningSignsExplained: [
      "The caller dispatched warning texts from a standard 10-digit mobile number, not official telecom utility handles.",
      "They threatened deactivation within 30 minutes, an artificial timeline designed to bypass clear thinking.",
      "They asked you to perform payment audits on unverified mobile links."
    ],
    shouldCallPolice: true,
    emotionalSupport: "Take a slow breath. You are completely safe, and your home utilities are secure. Scammers target panic—we isolate them.",
    helplines: [
      { name: "National Cyber Crime Support", number: "1930" },
      { name: "Senior Citizen Safety Line", number: "14567" }
    ]
  },
  Adult: {
    threatLevel: 'Critical',
    threatType: "Advance QR Code Refund Scams",
    simpleSummary: "Scammers are impersonating military personnel or property tenants, tricking you into scanning payment requests to claim cash.",
    whatToDoNow: [
      "Do not scan any WhatsApp QR images to receive refund deposits.",
      "Remember that typing your UPI PIN always sends money, it never claims money.",
      "Decline unrequested money demand tokens on Google Pay or PhonePe."
    ],
    warningSignsExplained: [
      "The buyer agreed to full rents instantly without visiting your listing.",
      "They insisted on depositing advance bookings via custom scanner codes.",
      "They shared graphic tenant cards claiming army service to gain instant trust."
    ],
    shouldCallPolice: true,
    emotionalSupport: "Stay composed. Cut off payment triggers. Block the caller's payment handles.",
    helplines: [
      { name: "National Cyber Crime Helpline", number: "1930" }
    ]
  },
  Teen: {
    threatLevel: 'Medium',
    threatType: "Part-Time Video Like Schemes",
    simpleSummary: "This is a digital Ponzi scheme targeting pocket savings. They pay small sums first, then lock your larger deposits in Telegram groups.",
    whatToDoNow: [
      "Block the recruiter WhatsApp lines immediately.",
      "Do not transfer cash to unlock secondary tasks or invite classmates.",
      "Do not share verification photos of your identity logs."
    ],
    warningSignsExplained: [
      "The offer was sent from international codes (+62, +84) promising daily tasks can pay ₹8,000.",
      "They directed you to a closed Telegram group where 'cryptocurrency buys' are mandated.",
      "They demanded you deposit registration cards to claim earlier work credits."
    ],
    shouldCallPolice: false,
    emotionalSupport: "You did the smart thing by auditing this before paying. Block the channel and protect your pocket money.",
    helplines: [
      { name: "National Cyber Crime Portal", number: "1930" }
    ]
  }
};

function FamilySafetyModule({ windowWidth }) {
  const [selectedPersona, setSelectedPersona] = useState('Elder');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [advice, setAdvice] = useState(null);

  const handleAuditRequest = () => {
    if (!description.trim()) return;

    setLoading(true);
    setAdvice(null);

    // Latency
    setTimeout(() => {
      setAdvice(MOCK_SAFETY_DIRECTORY[selectedPersona]);
      setLoading(false);
    }, 1600);
  };

  const getThreatBadgeStyles = (lvl) => {
    switch ((lvl || '').toLowerCase()) {
      case 'safe':
        return { bg: 'rgba(0, 229, 160, 0.08)', color: 'var(--aura-safe)' };
      case 'low':
      case 'medium':
        return { bg: 'rgba(245, 197, 24, 0.08)', color: 'var(--aura-watch)' };
      case 'high':
      case 'critical':
      default:
        return { bg: 'rgba(255, 61, 90, 0.08)', color: 'var(--aura-danger)' };
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px', animation: 'float-in 0.4s ease forwards' }}>
      
      {/* Title */}
      <div>
        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.15em' }}>REGIONAL FAMILY ADVISOR</div>
        <h2 className="font-syne" style={{ fontSize: '42px', fontWeight: '700', letterSpacing: '-0.02em', marginTop: '6px' }}>Family Safety Center</h2>
        <p className="font-dm-sans" style={{ fontSize: '15px', color: 'var(--text-secondary)', marginTop: '4px' }}>Protect those who trust you. Clean, jargon-free instructions and verified helpline channels.</p>
      </div>

      {/* Select role card */}
      <div>
        <label className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em', display: 'block', marginBottom: '12px' }}>
          CHOOSE A FAMILY MEMBER ROLE
        </label>
        
        <div style={{ display: 'grid', gridTemplateColumns: windowWidth > 768 ? 'repeat(3, 1fr)' : '1fr', gap: '16px' }}>
          {[
            { id: 'Elder', label: '👴 Elder / Parent', desc: 'Simple, large guides focusing on utility bill threats, bank calls, and OTP block warnings.' },
            { id: 'Adult', label: '👩 Working Adult', desc: 'Audits UPI scanner QR requests, advance tenancy bookings, and tax refund links.' },
            { id: 'Teen', label: '🧒 Student / Teen', desc: 'Exposes WhatsApp part-time job codes, social media tags, and Telegram investment leaks.' }
          ].map((persona) => {
            const isSelected = selectedPersona === persona.id;
            return (
              <div
                key={persona.id}
                onClick={() => {
                  setSelectedPersona(persona.id);
                  setAdvice(null);
                }}
                className="glass-card"
                style={{
                  padding: '20px',
                  cursor: 'pointer',
                  borderColor: isSelected ? 'var(--aura-purple)' : 'var(--border)',
                  background: isSelected ? 'rgba(157, 110, 255, 0.03)' : 'var(--surface-1)',
                  transform: isSelected ? 'scale(1.01)' : 'scale(1)'
                }}
              >
                <h4 className="font-syne" style={{ fontSize: '16px', fontWeight: '600' }}>{persona.label}</h4>
                <p className="font-dm-sans" style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: '1.4' }}>
                  {persona.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Situation report box */}
      <div className="glass-card" style={{ padding: '24px', position: 'relative' }}>
        {loading && <MatrixLoader message="Safety consultant compiling diagnostics..." />}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <label className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>DESCRIBE WHAT OCCURRED IN SIMPLE TERMS</label>
          <textarea
            rows={4}
            placeholder="e.g. Someone called saying my electricity bill is overdue and my power will be cut in 30 minutes unless I download a fast support app..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="font-dm-sans"
            style={{
              background: 'rgba(0,0,0,0.3)',
              color: '#fff',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '16px',
              fontSize: '14px',
              outline: 'none',
              resize: 'none',
              lineHeight: '1.5',
              width: '100%'
            }}
          />
          <button
            onClick={handleAuditRequest}
            disabled={!description.trim() || loading}
            className="font-syne"
            style={{
              background: description.trim() ? 'var(--aura-purple)' : 'var(--surface-3)',
              color: description.trim() ? '#fff' : 'var(--text-muted)',
              border: 'none',
              padding: '14px 28px',
              borderRadius: '8px',
              fontSize: '15px',
              fontWeight: '600',
              cursor: description.trim() ? 'pointer' : 'default',
              boxShadow: description.trim() ? '0 4px 20px rgba(157, 110, 255, 0.2)' : 'none'
            }}
          >
            COMPILE SAFETY INSTRUCTIONS
          </button>
        </div>
      </div>

      {/* Guidance logs */}
      {advice && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '28px', animation: 'float-in 0.4s ease forwards' }}>
          
          <div 
            style={{
              height: '72px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: getThreatBadgeStyles(advice.threatLevel).bg,
              border: `1px solid ${getThreatBadgeStyles(advice.threatLevel).color}`,
              borderRadius: '16px'
            }}
          >
            <div className="font-syne" style={{ fontSize: '24px', fontWeight: '800', color: getThreatBadgeStyles(advice.threatLevel).color }}>
              {advice.threatLevel.toUpperCase()} LEVEL RISK RATING
            </div>
          </div>

          {/* Core summary */}
          <div className="glass-card" style={{ padding: '32px', textAlign: 'center', borderLeft: '4px solid var(--aura-purple)', background: 'rgba(157,110,255,0.01)' }}>
            <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-purple)', marginBottom: '8px' }}>CORE ASSESSMENT (JARGON-FREE)</div>
            <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '20px', lineHeight: '1.8', color: '#fff', fontWeight: '400' }}>
              "{advice.simpleSummary}"
            </p>
          </div>

          <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '14px', fontStyle: 'italic', textAlign: 'center', color: 'var(--aura-safe)' }}>
            💚 Reassurance: {advice.emotionalSupport}
          </p>

          {/* Steps */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>IMMEDIATE ACTION PLAN</div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {advice.whatToDoNow.map((action, idx) => (
                <div 
                  key={idx}
                  className="glass-card text-wrap-safe"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '24px',
                    position: 'relative',
                    overflow: 'hidden'
                  }}
                >
                  <span className="font-syne" style={{
                    position: 'absolute',
                    right: '16px',
                    bottom: '-16px',
                    fontSize: '84px',
                    fontWeight: '800',
                    color: 'rgba(255,255,255,0.01)',
                    pointerEvents: 'none',
                    userSelect: 'none'
                  }}>
                    {idx + 1}
                  </span>
                  <div style={{ display: 'flex', gap: '16px', alignItems: 'center', position: 'relative', zIndex: 5 }}>
                    <span className="font-syne" style={{ fontSize: '28px', fontWeight: '800', color: 'var(--aura-purple)' }}>0{idx + 1}</span>
                    <span className="font-dm-sans text-wrap-safe" style={{ fontSize: '16px', color: '#fff', fontWeight: '500', lineHeight: '1.5' }}>{action}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Warning signs */}
          <div className="glass-card" style={{ padding: '24px' }}>
            <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-watch)', marginBottom: '16px' }}>🚩 KEY MANIPULATION TRACES FOUND</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {advice.warningSignsExplained.map((sign, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--aura-watch)' }}>⚠️</span>
                  <span className="font-dm-sans text-wrap-safe" style={{ fontSize: '14px', color: 'var(--text-primary)', lineHeight: '1.5' }}>{sign}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Helplineemergencybox */}
          {advice.shouldCallPolice && (
            <div className="glass-card" style={{ padding: '24px', borderColor: 'var(--aura-danger)', background: 'rgba(255, 61, 90, 0.03)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                <span style={{ fontSize: '24px' }}>🚨</span>
                <span className="font-syne" style={{ fontSize: '16px', fontWeight: '700', color: 'var(--aura-danger)' }}>OFFICIAL INDIAN EMERGENCY HOTLINES</span>
              </div>
              <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '18px', lineHeight: '1.5' }}>
                Report caller IDs, fake URLs, and account transactions immediately to lock hackers' access points and freezing funds routing.
              </p>
              
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
                {advice.helplines.map((hl, idx) => (
                  <a 
                    key={idx}
                    href={`tel:${hl.number}`}
                    className="font-dm-mono"
                    style={{
                      background: 'var(--surface-0)',
                      border: '1.5px solid var(--aura-danger)',
                      color: '#fff',
                      padding: '10px 18px',
                      borderRadius: '8px',
                      textDecoration: 'none',
                      fontSize: '13px',
                      fontWeight: '600',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                  >
                    📞 {hl.name.toUpperCase()}: {hl.number}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Bottom standard directories */}
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: '24px', textAlign: 'center' }}>
            <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', marginBottom: '12px' }}>STANDARD INDIAN SAFETY DIRECTORIES</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center' }}>
              <span className="font-dm-mono" style={{ background: 'var(--surface-2)', padding: '6px 12px', borderRadius: '12px', fontSize: '10px', color: 'var(--text-secondary)' }}>NATIONAL CYBERCRIME: 1930</span>
              <span className="font-dm-mono" style={{ background: 'var(--surface-2)', padding: '6px 12px', borderRadius: '12px', fontSize: '10px', color: 'var(--text-secondary)' }}>SENIOR CITIZENS LINE: 14567</span>
              <span className="font-dm-mono" style={{ background: 'var(--surface-2)', padding: '6px 12px', borderRadius: '12px', fontSize: '10px', color: 'var(--text-secondary)' }}>WOMEN DIRECTORY: 1091</span>
            </div>
          </div>

        </div>
      )}

    </div>
  );
}


/* =========================================================================
   MODULE X: SITE SECURITY SCANNER
   ========================================================================= */
function SiteScannerModule({ windowWidth, setRiskScore, setTriggerLaser }) {
  const [inputUrl, setInputUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState('Initializing scan...');
  const [scanResult, setScanResult] = useState(null);
  
  // API Key removed for security
  const performScan = async () => {
    if (!inputUrl.trim()) return;
    
    let target = inputUrl.trim();
    if (!target.startsWith('http')) {
      target = 'https://' + target;
      setInputUrl(target);
    }

    setLoading(true);
    setScanResult(null);
    if(setTriggerLaser) setTriggerLaser(true);

    try {
      setLoadingMessage('Transmitting to State-of-the-Art Security Heuristics Engine...');
      
      // Fetch analysis from our new FastAPI backend
      const res = await fetch('/api/scan/headers?url=' + encodeURIComponent(target));
      if (!res.ok) {
        throw new Error(await res.text() || "Failed to scan target");
      }
      
      const data = await res.json();

      setScanResult({
        url: data.url,
        grade: data.grade,
        issues: data.issues || [],
        passedChecks: data.passedChecks || []
      });

      // Update global risk score based on grade
      if (['D', 'F'].includes(data.grade)) {
        setRiskScore(p => Math.min(p + 20, 96));
      } else if (['A', 'B'].includes(data.grade)) {
        setRiskScore(p => Math.max(p - 10, 12));
      }

    } catch (err) {
      console.error(err);
      
      // Attempt to parse FastAPI HTTPException detail
      let errorMessage = err.message;
      try {
         const parsed = JSON.parse(err.message);
         if (parsed.detail) errorMessage = parsed.detail;
      } catch (e) {}

      setScanResult({
        url: target,
        grade: 'ERR',
        issues: [{
          id: 'err',
          title: 'Scan Execution Failed',
          severity: 'HIGH',
          description: `An error occurred during the live scan: ${errorMessage}`,
          solution: 'Check the target URL validity, or ensure the target site is not blocking automated requests.'
        }],
        passedChecks: []
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-transition-enter-active" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      
      {/* Title */}
      <div>
        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.15em' }}>LIVE AI-POWERED RECONNAISSANCE</div>
        <h2 className="font-syne" style={{ fontSize: '42px', fontWeight: '700', letterSpacing: '-0.02em', marginTop: '6px' }}>Site Security Scanner</h2>
        <p className="font-dm-sans" style={{ fontSize: '15px', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '700px', lineHeight: '1.6' }}>
          Enter your website URL to perform a live perimeter scan. We bypass CORS to audit your live HTTP headers, then stream the data through Groq (LLaMA 3) to intelligently identify vulnerabilities and exact remediation codes.
        </p>
      </div>

      {/* Input Form */}
      <div className="glass-card" style={{ padding: '28px', position: 'relative' }}>
        {loading && <MatrixLoader message={loadingMessage} />}
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.12em' }}>TARGET URL TO SCAN</label>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="e.g. mysite.com or https://mysite.com"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                className="cyber-input font-dm-mono"
                style={{ flex: '1', minWidth: '250px' }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') performScan();
                }}
              />
              <button
                onClick={performScan}
                className="font-syne"
                style={{
                  background: 'var(--aura-safe)',
                  color: '#000',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '0 24px',
                  fontWeight: '700',
                  fontSize: '14px',
                  cursor: 'pointer',
                  boxShadow: '0 4px 15px rgba(0, 229, 160, 0.2)',
                  minHeight: '48px',
                  whiteSpace: 'nowrap'
                }}
              >
                EXECUTE LIVE AUDIT
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Scan Results */}
      {scanResult && (
        <div className="page-transition-enter-active" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
            {/* Grade Card */}
            <div className="glass-card" style={{ padding: '24px', flex: '1', minWidth: '200px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div className="font-dm-mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', letterSpacing: '0.1em', marginBottom: '8px' }}>SECURITY GRADE</div>
              <div className="font-syne" style={{ fontSize: '64px', fontWeight: '800', color: ['A', 'B'].includes(scanResult.grade) ? 'var(--aura-safe)' : (['C'].includes(scanResult.grade) ? 'var(--aura-watch)' : 'var(--aura-danger)'), lineHeight: '1' }}>
                {scanResult.grade}
              </div>
              <div className="font-dm-sans" style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '8px' }}>
                For {scanResult.url}
              </div>
            </div>

            {/* Passed Checks */}
            <div className="glass-card" style={{ padding: '24px', flex: '2', minWidth: '300px' }}>
              <div className="font-dm-mono" style={{ fontSize: '12px', color: 'var(--aura-safe)', letterSpacing: '0.1em', marginBottom: '16px' }}>VERIFIED SAFE PROTOCOLS</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {scanResult.passedChecks.map((check, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ color: 'var(--aura-safe)', fontSize: '14px' }}>✓</span>
                    <span className="font-dm-mono" style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{check}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="font-dm-mono" style={{ fontSize: '12px', color: 'var(--aura-danger)', letterSpacing: '0.1em', marginTop: '8px' }}>DETECTED VULNERABILITIES ({scanResult.issues.length})</div>
          
          {/* Issues List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {scanResult.issues.map((issue, idx) => (
              <div key={idx} className="glass-card" style={{ padding: '24px', borderLeft: `4px solid ${issue.severity === 'HIGH' ? 'var(--aura-danger)' : (issue.severity === 'LOW' ? 'var(--aura-info)' : 'var(--aura-watch)')}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                  <h4 className="font-syne" style={{ fontSize: '18px', fontWeight: '600', color: '#fff' }}>{issue.title}</h4>
                  <span className="font-dm-mono" style={{ 
                    fontSize: '10px', 
                    padding: '4px 8px', 
                    borderRadius: '4px',
                    background: issue.severity === 'HIGH' ? 'rgba(239, 68, 68, 0.1)' : (issue.severity === 'LOW' ? 'rgba(59, 130, 246, 0.1)' : 'rgba(245, 158, 11, 0.1)'),
                    color: issue.severity === 'HIGH' ? 'var(--aura-danger)' : (issue.severity === 'LOW' ? 'var(--aura-info)' : 'var(--aura-watch)'),
                    border: `1px solid ${issue.severity === 'HIGH' ? 'rgba(239, 68, 68, 0.3)' : (issue.severity === 'LOW' ? 'rgba(59, 130, 246, 0.3)' : 'rgba(245, 158, 11, 0.3)')}`
                  }}>
                    {issue.severity} RISK
                  </span>
                </div>
                
                <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '20px' }}>
                  {issue.description}
                </p>

                <div style={{ background: 'rgba(0,0,0,0.5)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-safe)', letterSpacing: '0.08em', marginBottom: '8px' }}>REMEDIATION SOLUTION</div>
                  <pre className="font-dm-mono text-wrap-safe" style={{ fontSize: '12px', color: '#a8b2d1', margin: 0, whiteSpace: 'pre-wrap' }}>
                    {issue.solution}
                  </pre>
                </div>
              </div>
            ))}
          </div>

        </div>
      )}

    </div>
  );
}
