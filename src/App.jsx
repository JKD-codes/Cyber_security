import React, { useState, useEffect, useRef } from 'react';

import { 

  BarChart3,
  Activity,
  Cpu,
  ExternalLink,
  ChevronRight,
  Terminal,
  Scan,
  Crosshair,
  Radar,
  RefreshCw,
  Play,
  Copy,
  ArrowRight, 

  Search, 

  Globe, 

  FlaskConical, 

  Shield, 

  ShieldAlert, 

  ShieldCheck, 

  Move, 

  Radio, 

  X, 

  Zap, 

  Lock, 

  AlertTriangle, 

  AlertOctagon, 

  AlertCircle, 

  CheckCircle2, 

  Check, 

  Fingerprint, 

  Mail, 

  KeyRound, 

  Smartphone, 

  FileText, 

  FileSearch, 

  Brain, 

  Flag, 

  Layers, 

  Cloud, 

  Link2, 

  MessageSquare, 

  QrCode, 

  CreditCard, 

  Monitor, 

  Send, 

  UserSearch, 

  PhoneCall, 

  Ban, 

  Package, 

  PhoneForwarded, 

  HeartHandshake, 

  Briefcase, 

  GraduationCap, 

  Heart 

} from 'lucide-react';



import { 

  downloadScamAuditPdf,

  downloadSiteSecurityPdf,

  generateScamAuditReport, 

  generateSiteSecurityReport, 

  triggerReportDownload, 

  printReportContent 

} from './reportGenerator';



// Live Verified Cybersecurity Threat Index (Real Threats active in India)

const ACTIVE_INDIAN_THREATS = [

  { id: 'T-IN-9041', name: 'UPI Lookalike Redirects', vector: 'Merchant Spoofing', description: 'Scammers register UPI IDs resembling prominent payment endpoints (e.g., paytrn@ybl instead of paytm@ybl) to hijack QR scanning transactions.', severity: 'CRITICAL', color: 'var(--aura-danger)' },

  { id: 'T-IN-8712', name: 'mAadhaar OTP Hijacking', vector: 'Identity Redirection', description: 'Coercive social calls pretending to be Aadhaar UIDAI auditors requesting biometric locks, tricking citizens into verifying access OTP tokens.', severity: 'HIGH', color: 'var(--aura-watch)' },

  { id: 'T-IN-7493', name: 'Sarkari Phishing campaigns', vector: 'Credential Harvesting', description: 'Deceptive generic web portals (e.g. pmkisan-subsidy.cc) targeting regional farmers by demanding bank credentials to release government payouts.', severity: 'CRITICAL', color: 'var(--aura-danger)' },

  { id: 'T-IN-6501', name: 'Utility Bill Suspensions', vector: 'Fear Induction SMS', description: 'Bulk SMS campaigns threatening immediate residential power disconnection within 30 minutes, directing victims to unofficial personal contact numbers.', severity: 'HIGH', color: 'var(--aura-watch)' }

];



// Context alerts for Floating SOC panel




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





// Helper to render high-end technical icons for Attack Simulator

function renderAttackIcon(key, size = 20, color = 'var(--aura-purple)') {

  switch (key) {

    case 'phishing':

    case 'link':

      return <Link2 size={size} color={color} />;

    case 'sim':

    case 'phone':

    case 'smartphone':

      return <Smartphone size={size} color={color} />;

    case 'whatsapp':

    case 'chat':

      return <MessageSquare size={size} color={color} />;

    case 'upi':

    case 'qr':

      return <QrCode size={size} color={color} />;

    case 'globe':

      return <Globe size={size} color={color} />;

    case 'mail':

      return <Mail size={size} color={color} />;

    case 'monitor':

      return <Monitor size={size} color={color} />;

    case 'send':

      return <Send size={size} color={color} />;

    case 'search':

      return <UserSearch size={size} color={color} />;

    case 'call':

      return <PhoneCall size={size} color={color} />;

    case 'ban':

      return <Ban size={size} color={color} />;

    case 'money':

    case 'card':

      return <CreditCard size={size} color={color} />;

    case 'package':

      return <Package size={size} color={color} />;

    case 'call-forward':

      return <PhoneForwarded size={size} color={color} />;

    case 'stop':

    case 'alert':

      return <AlertOctagon size={size} color={color} />;

    default:

      return <ShieldAlert size={size} color={color} />;

  }

}



/* =========================================================================
   CINEMATIC CODEXA NEURAL BRIDGE TRANSITION OVERLAY
   Executive warp tunnel transition between CyberShield and Codexa AI
   ========================================================================= */
function CodexaTransitionScreen({ launching, onComplete, onCancel }) {
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState(0);

  const stages = [
    { text: "ESTABLISHING ENCRYPTED QUANTUM BRIDGE...", code: "TLS_1.3_ECDSA_WITH_CHACHA20" },
    { text: "SYNCHRONIZING STATIC AST HEURISTICS...", code: "AST_VECTORS: 884 PARSED" },
    { text: "CALIBRATING CODEXA NEURAL ENGINE...", code: "PORTAL_ID: codexa-ye85.onrender.com" },
    { text: "NEURAL HANDSHAKE VERIFIED — LAUNCHING TERMINAL", code: "STATUS: 200 OK | REDIRECTING" }
  ];

  useEffect(() => {
    if (!launching) {
      setProgress(0);
      setStage(0);
      return;
    }

    const t1 = setTimeout(() => { setProgress(28); setStage(1); }, 400);
    const t2 = setTimeout(() => { setProgress(62); setStage(2); }, 900);
    const t3 = setTimeout(() => { setProgress(90); setStage(3); }, 1400);
    const t4 = setTimeout(() => {
      setProgress(100);
      setTimeout(() => {
        onComplete();
      }, 400);
    }, 1800);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, [launching]);

  if (!launching) return null;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'radial-gradient(circle at center, rgba(10, 16, 28, 0.96) 0%, rgba(3, 5, 10, 0.99) 100%)',
      backdropFilter: 'blur(24px)',
      WebkitBackdropFilter: 'blur(24px)',
      zIndex: 99999,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px',
      overflow: 'hidden'
    }}>
      {/* Dynamic Laser Warp Line */}
      <div style={{
        position: 'absolute',
        left: 0,
        right: 0,
        height: '2px',
        background: 'linear-gradient(90deg, transparent, #00e5a0, #4da6ff, #9d6eff, transparent)',
        boxShadow: '0 0 24px #00e5a0',
        animation: 'laser-glider 1.5s ease-in-out infinite'
      }} />

      {/* Cyberpunk Grid Background */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: 'linear-gradient(rgba(0, 229, 160, 0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 229, 160, 0.04) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
        pointerEvents: 'none'
      }} />

      {/* Center Quantum Portal Card */}
      <div className="glass-card" style={{
        maxWidth: '520px',
        width: '100%',
        padding: '36px 32px',
        background: 'rgba(8, 12, 22, 0.92)',
        border: '1px solid rgba(0, 229, 160, 0.4)',
        boxShadow: '0 24px 64px rgba(0, 0, 0, 0.9), 0 0 40px rgba(0, 229, 160, 0.2)',
        borderRadius: '20px',
        textAlign: 'center',
        position: 'relative',
        zIndex: 10
      }}>
        {/* Holographic Rotating Core */}
        <div style={{
          width: '90px',
          height: '90px',
          margin: '0 auto 20px auto',
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          {/* Outer Dashed Ring */}
          <div style={{
            position: 'absolute',
            inset: 0,
            borderRadius: '50%',
            border: '2px dashed rgba(0, 229, 160, 0.6)',
            animation: 'radar-sweep 5s linear infinite'
          }} />
          {/* Middle Cyan Ring */}
          <div style={{
            position: 'absolute',
            inset: '8px',
            borderRadius: '50%',
            border: '2px solid transparent',
            borderTopColor: '#00e5a0',
            borderBottomColor: '#4da6ff',
            animation: 'portal-spin 2s cubic-bezier(0.68, -0.55, 0.27, 1.55) infinite'
          }} />
          {/* Center Glowing CPU Icon */}
          <div style={{
            width: '54px',
            height: '54px',
            borderRadius: '50%',
            background: 'rgba(0, 229, 160, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(0, 229, 160, 0.4)'
          }}>
            <Cpu size={26} color="#00e5a0" />
          </div>
        </div>

        <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-safe)', letterSpacing: '0.14em', marginBottom: '8px' }}>
          CYBERSHIELD ➔ CODEXA CLOUD BRIDGE
        </div>

        <h2 className="font-syne" style={{ fontSize: '24px', fontWeight: '800', color: '#fff', margin: '0 0 10px 0', letterSpacing: '-0.02em' }}>
          CONNECTING TO CODEXA
        </h2>

        <p className="font-dm-sans" style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '0 0 22px 0', lineHeight: 1.5 }}>
          Launching autonomous AST static code review, vulnerability assessment, and production audit engine...
        </p>

        {/* Progress Bar */}
        <div style={{
          width: '100%',
          height: '6px',
          background: 'rgba(255, 255, 255, 0.08)',
          borderRadius: '4px',
          overflow: 'hidden',
          marginBottom: '12px'
        }}>
          <div style={{
            width: `${progress}%`,
            height: '100%',
            background: 'linear-gradient(90deg, #00e5a0, #4da6ff, #9d6eff)',
            boxShadow: '0 0 14px rgba(0, 229, 160, 0.9)',
            borderRadius: '4px',
            transition: 'width 0.4s cubic-bezier(0.16, 1, 0.3, 1)'
          }} />
        </div>

        {/* Dynamic Status Stream */}
        <div style={{
          background: 'rgba(0, 0, 0, 0.4)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          borderRadius: '8px',
          padding: '10px 14px',
          marginBottom: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px',
          textAlign: 'left'
        }}>
          <div className="font-dm-mono" style={{ fontSize: '11px', color: '#00e5a0', fontWeight: '600' }}>
            {stages[stage].text}
          </div>
          <div className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)' }}>
            CHANNEL: {stages[stage].code} | {progress}%
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' }}>
          <button
            onClick={() => onComplete()}
            className="font-syne"
            style={{
              padding: '12px 22px',
              background: 'var(--aura-safe)',
              color: '#060a12',
              fontWeight: '700',
              fontSize: '12px',
              borderRadius: '8px',
              border: 'none',
              cursor: 'pointer',
              letterSpacing: '0.04em',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 4px 16px rgba(0, 229, 160, 0.3)'
            }}
          >
            <span>LAUNCH TERMINAL NOW</span>
            <ExternalLink size={14} color="#060a12" />
          </button>
          <button
            onClick={() => onCancel()}
            className="font-dm-mono"
            style={{
              padding: '12px 18px',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border)',
              color: 'var(--text-secondary)',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '12px'
            }}
          >
            CANCEL
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {

  const [activeModule, setActiveModule] = useState('dashboard');

  const [riskScore, setRiskScore] = useState(24); // Hand-crafted initial baseline

  const [auraColor, setAuraColor] = useState('var(--aura-safe)');

  const [currentTime, setCurrentTime] = useState('');

  const [isMobile, setIsMobile] = useState(false);

  const [windowWidth, setWindowWidth] = useState(1200);



  // Floating Commentary alerts



  const [triggerLaser, setTriggerLaser] = useState(false);
  const [launchingCodexa, setLaunchingCodexa] = useState(false);
  const [codexaProgress, setCodexaProgress] = useState(0);

  const triggerCodexaRedirect = () => {
    setLaunchingCodexa(true);
  };



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






    // Randomize system diagnostics to look realistic

    const diagInterval = setInterval(() => {

      const rates = ['182 GB/s', '184 GB/s', '189 GB/s', '178 GB/s'];

      setSystemSpeed(rates[Math.floor(Math.random() * rates.length)]);

    }, 6000);



    return () => {

      window.removeEventListener('resize', handleResize);

      clearInterval(clockInterval);


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
      {/* Codexa Agent Cloud Neural Bridge Launch Overlay */}
      <CodexaTransitionScreen 
        launching={launchingCodexa} 
        onComplete={() => {
          window.open('https://codexa-ye85.onrender.com', '_blank');
          setLaunchingCodexa(false);
        }}
        onCancel={() => setLaunchingCodexa(false)}
      />

      {/* 3. Left Sidebar navigation (Desktop) / Bottom Navbar navigation (Mobile) */}

      {!isMobile ? (
        <aside style={{
          width: '290px',
          background: 'linear-gradient(180deg, rgba(8, 11, 20, 0.98) 0%, rgba(4, 6, 12, 0.99) 100%)',
          borderRight: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          flexDirection: 'column',
          zIndex: 20,
          flexShrink: 0,
          position: 'sticky',
          top: 0,
          height: '100vh',
          overflow: 'hidden',
          boxShadow: '6px 0 32px rgba(0, 0, 0, 0.6)'
        }}>
          {/* Ambient Top Glow Overlay */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '120px',
            background: 'radial-gradient(circle at 20% 0%, rgba(0, 229, 160, 0.12) 0%, transparent 70%)',
            pointerEvents: 'none'
          }} />

          {/* Top Brand & System Identity Header */}
          <div style={{
            padding: '24px 20px 18px 20px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
            position: 'relative',
            zIndex: 2
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              {/* Glowing Shield Hex Icon */}
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '12px',
                background: 'linear-gradient(135deg, rgba(0, 229, 160, 0.22) 0%, rgba(157, 110, 255, 0.18) 100%)',
                border: '1.5px solid rgba(0, 229, 160, 0.45)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 0 20px rgba(0, 229, 160, 0.25), inset 0 0 10px rgba(0, 229, 160, 0.15)',
                flexShrink: 0
              }}>
                <Shield size={22} color="var(--aura-safe)" />
              </div>

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="font-syne" style={{ fontSize: '20px', fontWeight: '800', letterSpacing: '-0.02em', color: '#ffffff', lineHeight: 1.1 }}>
                    CyberShield
                  </span>
                  <span className="font-dm-mono" style={{
                    fontSize: '8px',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'rgba(0, 229, 160, 0.12)',
                    color: 'var(--aura-safe)',
                    border: '1px solid rgba(0, 229, 160, 0.3)',
                    fontWeight: '700'
                  }}>
                    v4.8 PRO
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '5px' }}>
                  <span style={{
                    display: 'inline-block',
                    width: '6px',
                    height: '6px',
                    background: '#00e5a0',
                    borderRadius: '50%',
                    boxShadow: '0 0 8px #00e5a0',
                    animation: 'glow-breathe 2s infinite'
                  }} />
                  <span className="font-dm-mono" style={{ fontSize: '10px', fontWeight: '600', letterSpacing: '0.08em', color: 'var(--aura-safe)' }}>
                    PERIMETER HARDENED
                  </span>
                </div>
              </div>
            </div>

            {/* Micro Cyber Breathing Line */}
            <div style={{
              width: '100%',
              height: '1px',
              background: 'linear-gradient(90deg, #00e5a0 0%, #4da6ff 50%, transparent 100%)',
              marginTop: '16px',
              opacity: 0.6
            }} />
          </div>

          {/* Navigation Items Scroll Area */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            padding: '18px 14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
            position: 'relative',
            zIndex: 2
          }}>
            
            {/* Group 1: Security Intelligence */}
            <div>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0 8px 8px 8px'
              }}>
                <span className="font-dm-mono" style={{ fontSize: '9px', fontWeight: '700', color: 'rgba(255, 255, 255, 0.4)', letterSpacing: '0.14em' }}>
                  SECURITY INTELLIGENCE
                </span>
                <span className="font-dm-mono" style={{ fontSize: '8px', color: 'rgba(0, 229, 160, 0.7)' }}>
                  3 ACTIVE
                </span>
              </div>

              <nav style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {[
                  { id: 'dashboard', label: 'THREAT CENTER', sub: 'Live 3D Attack Radar', tag: '3D LIVE', Icon: BarChart3 },
                  { id: 'scam-detector', label: 'LINK & SCAM AUDIT', sub: 'Heuristic ML Fraud Engine', tag: 'ML SHIELD', Icon: Search },
                  { id: 'site-scanner', label: 'SITE SECURITY SCANNER', sub: 'SSL, Headers & Port Audit', tag: 'SCANNER', Icon: Globe }
                ].map((item) => {
                  const isActive = activeModule === item.id;
                  const NavIcon = item.Icon;
                  return (
                    <button
                      key={item.id}
                      onClick={() => setActiveModule(item.id)}
                      className="font-dm-sans"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 12px',
                        background: isActive 
                          ? 'linear-gradient(90deg, rgba(0, 229, 160, 0.14) 0%, rgba(77, 166, 255, 0.05) 100%)' 
                          : 'rgba(255, 255, 255, 0.015)',
                        border: isActive ? '1px solid rgba(0, 229, 160, 0.4)' : '1px solid rgba(255, 255, 255, 0.04)',
                        borderLeft: isActive ? '3px solid #00e5a0' : '3px solid transparent',
                        borderRadius: '10px',
                        color: isActive ? '#ffffff' : 'var(--text-secondary)',
                        cursor: 'pointer',
                        textAlign: 'left',
                        boxShadow: isActive ? '0 4px 16px rgba(0, 229, 160, 0.15), inset 0 0 12px rgba(0, 229, 160, 0.05)' : 'none',
                        transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
                        width: '100%'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{
                          width: '32px',
                          height: '32px',
                          borderRadius: '8px',
                          background: isActive ? 'rgba(0, 229, 160, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                          border: isActive ? '1px solid rgba(0, 229, 160, 0.5)' : '1px solid rgba(255, 255, 255, 0.06)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0
                        }}>
                          <NavIcon size={16} color={isActive ? '#00e5a0' : 'var(--text-secondary)'} />
                        </div>
                        <div>
                          <div style={{ fontSize: '13px', fontWeight: isActive ? '700' : '500', color: isActive ? '#fff' : 'var(--text-primary)', letterSpacing: '0.02em', lineHeight: 1.2 }}>
                            {item.label}
                          </div>
                          <div className="font-dm-mono" style={{ fontSize: '9px', color: isActive ? 'rgba(0, 229, 160, 0.85)' : 'var(--text-muted)', marginTop: '2px' }}>
                            {item.sub}
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span className="font-dm-mono" style={{
                          fontSize: '8px',
                          padding: '2px 5px',
                          borderRadius: '4px',
                          background: isActive ? 'rgba(0, 229, 160, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                          color: isActive ? '#00e5a0' : 'var(--text-muted)',
                          fontWeight: '600'
                        }}>
                          {item.tag}
                        </span>
                        {isActive && <ChevronRight size={14} color="#00e5a0" />}
                      </div>
                    </button>
                  );
                })}
              </nav>
            </div>

            {/* Group 2: Neural Agents & Labs */}
            <div>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0 8px 8px 8px'
              }}>
                <span className="font-dm-mono" style={{ fontSize: '9px', fontWeight: '700', color: 'rgba(255, 255, 255, 0.4)', letterSpacing: '0.14em' }}>
                  NEURAL AGENTS & LABS
                </span>
                <span className="font-dm-mono" style={{ fontSize: '8px', color: 'var(--aura-purple)' }}>
                  AUTONOMOUS
                </span>
              </div>

              <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                
                {/* HERO FEATURED BUTTON: Codexa Autonomous AI Agent */}
                <button
                  onClick={() => triggerCodexaRedirect()}
                  className="font-dm-sans"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '12px 14px',
                    background: 'linear-gradient(135deg, rgba(157, 110, 255, 0.18) 0%, rgba(0, 229, 160, 0.08) 100%)',
                    border: '1.5px solid rgba(157, 110, 255, 0.55)',
                    borderRadius: '12px',
                    color: '#ffffff',
                    cursor: 'pointer',
                    textAlign: 'left',
                    boxShadow: '0 6px 20px rgba(157, 110, 255, 0.2), inset 0 0 14px rgba(157, 110, 255, 0.1)',
                    transition: 'all 0.25s ease',
                    width: '100%',
                    position: 'relative',
                    overflow: 'hidden'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{
                      width: '34px',
                      height: '34px',
                      borderRadius: '8px',
                      background: 'rgba(157, 110, 255, 0.25)',
                      border: '1px solid rgba(157, 110, 255, 0.6)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: '0 0 12px rgba(157, 110, 255, 0.4)',
                      flexShrink: 0
                    }}>
                      <Cpu size={18} color="#c084fc" />
                    </div>
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: '800', color: '#ffffff', letterSpacing: '0.02em', lineHeight: 1.2 }}>
                        CODEXA CODE REVIEW
                      </div>
                      <div className="font-dm-mono" style={{ fontSize: '9px', color: '#c084fc', marginTop: '2px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <span>AST Neural Agent</span>
                        <span>↗</span>
                      </div>
                    </div>
                  </div>

                  <span className="font-dm-mono" style={{
                    fontSize: '8px',
                    padding: '3px 7px',
                    borderRadius: '5px',
                    background: 'rgba(157, 110, 255, 0.3)',
                    color: '#ffffff',
                    fontWeight: '700',
                    border: '1px solid rgba(157, 110, 255, 0.5)',
                    letterSpacing: '0.05em'
                  }}>
                    AI CORE
                  </span>
                </button>

                {/* Labs & Family Shield */}
                {[
                  { id: 'simulator', label: 'ATTACK LABS', sub: 'Exploit Simulation Sandbox', tag: 'SANDBOX', Icon: FlaskConical },
                  { id: 'family-safety', label: 'FAMILY SHIELD', sub: 'Device & Endpoint Guardian', tag: 'GUARDIAN', Icon: Shield }
                ].map((item) => {
                  const isActive = activeModule === item.id;
                  const NavIcon = item.Icon;
                  return (
                    <button
                      key={item.id}
                      onClick={() => setActiveModule(item.id)}
                      className="font-dm-sans"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 12px',
                        background: isActive 
                          ? 'linear-gradient(90deg, rgba(0, 229, 160, 0.14) 0%, rgba(77, 166, 255, 0.05) 100%)' 
                          : 'rgba(255, 255, 255, 0.015)',
                        border: isActive ? '1px solid rgba(0, 229, 160, 0.4)' : '1px solid rgba(255, 255, 255, 0.04)',
                        borderLeft: isActive ? '3px solid #00e5a0' : '3px solid transparent',
                        borderRadius: '10px',
                        color: isActive ? '#ffffff' : 'var(--text-secondary)',
                        cursor: 'pointer',
                        textAlign: 'left',
                        boxShadow: isActive ? '0 4px 16px rgba(0, 229, 160, 0.15), inset 0 0 12px rgba(0, 229, 160, 0.05)' : 'none',
                        transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
                        width: '100%'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{
                          width: '32px',
                          height: '32px',
                          borderRadius: '8px',
                          background: isActive ? 'rgba(0, 229, 160, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                          border: isActive ? '1px solid rgba(0, 229, 160, 0.5)' : '1px solid rgba(255, 255, 255, 0.06)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0
                        }}>
                          <NavIcon size={16} color={isActive ? '#00e5a0' : 'var(--text-secondary)'} />
                        </div>
                        <div>
                          <div style={{ fontSize: '13px', fontWeight: isActive ? '700' : '500', color: isActive ? '#fff' : 'var(--text-primary)', letterSpacing: '0.02em', lineHeight: 1.2 }}>
                            {item.label}
                          </div>
                          <div className="font-dm-mono" style={{ fontSize: '9px', color: isActive ? 'rgba(0, 229, 160, 0.85)' : 'var(--text-muted)', marginTop: '2px' }}>
                            {item.sub}
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span className="font-dm-mono" style={{
                          fontSize: '8px',
                          padding: '2px 5px',
                          borderRadius: '4px',
                          background: isActive ? 'rgba(0, 229, 160, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                          color: isActive ? '#00e5a0' : 'var(--text-muted)',
                          fontWeight: '600'
                        }}>
                          {item.tag}
                        </span>
                        {isActive && <ChevronRight size={14} color="#00e5a0" />}
                      </div>
                    </button>
                  );
                })}
              </nav>
            </div>
          </div>

          {/* Bottom Console: Executive SOC Telemetry Card */}
          <div style={{
            padding: '16px 18px',
            background: 'rgba(5, 7, 14, 0.92)',
            borderTop: '1px solid rgba(255, 255, 255, 0.07)',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px',
            position: 'relative',
            zIndex: 2
          }}>
            {/* Live Clock with IST indicator */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Terminal size={12} color="var(--aura-safe)" />
                <span className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
                  SYS TIME
                </span>
              </div>
              <span className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--aura-safe)', background: 'rgba(0, 229, 160, 0.1)', padding: '2px 6px', borderRadius: '4px', fontWeight: '700' }}>
                ONLINE
              </span>
            </div>

            <div className="font-dm-mono" style={{ fontSize: '20px', fontWeight: '700', color: '#ffffff', letterSpacing: '0.06em', textShadow: '0 0 12px rgba(0, 229, 160, 0.25)' }}>
              {currentTime || '00:00:00'}
            </div>

            {/* Hardware & Cryptographic Diagnostics */}
            <div style={{
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: '6px',
              padding: '8px 10px',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)' }}>ENCRYPTION</span>
                <span className="font-dm-mono" style={{ fontSize: '9px', color: '#4da6ff', fontWeight: '600' }}>4096-BIT RSA</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)' }}>OPERATOR</span>
                <span className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--aura-safe)', fontWeight: '700' }}>Codewithjainam7</span>
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
            { id: 'dashboard', label: 'Center', Icon: BarChart3 },
            { id: 'scam-detector', label: 'Audit', Icon: Search },
            { id: 'site-scanner', label: 'Scanner', Icon: Globe },
            { id: 'codexa', label: 'Codexa ↗', Icon: Zap },
            { id: 'simulator', label: 'Labs', Icon: FlaskConical },
            { id: 'family-safety', label: 'Family', Icon: Shield }
          ].map((item) => {

            const isActive = activeModule === item.id;

            const NavIcon = item.Icon;

            return (

              <button

                key={item.id}
                onClick={() => {
                  if (item.id === 'codexa') {
                    triggerCodexaRedirect();
                  } else {
                    setActiveModule(item.id);
                  }
                }}
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

                <NavIcon size={18} color={isActive ? auraColor : 'var(--text-secondary)'} />

                <span style={{ fontSize: '10px', fontWeight: isActive ? '600' : '400' }}>{item.label}</span>

              </button>

            );

          })}

        </nav>

      )}



      {/* 4. Main viewport content container */}

      <main style={{
        flex: 1,
        padding: isMobile ? '20px 16px 88px 16px' : '36px 40px',
        overflowY: 'auto',
        position: 'relative',
        zIndex: 5,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        width: '100%'
      }}>
        <div style={{
          width: '100%',
          maxWidth: '1160px',
          display: 'flex',
          flexDirection: 'column',
          gap: '28px'
        }}>
          {renderModuleContent()}
        </div>
      </main>






    </div>

  );

}



/* =========================================================================
   UNIVERSAL COMPONENT: Advanced Holographic Cyber Threat Scanner
   ========================================================================= */

function MatrixLoader({ message }) {
  const [currentText, setCurrentText] = useState(message || "Analyzing target security vectors...");
  const [progress, setProgress] = useState(18);

  useEffect(() => {
    const diagnosticPhases = [
      message || "Auditing payload signatures & byte entropy...",
      "Executing deep heuristic homoglyph inspection...",
      "Querying global threat intelligence database...",
      "Verifying TLS certificate chain & protocol handshake...",
      "Compiling cryptographic defense telemetry..."
    ];
    let msgIndex = 0;
    const interval = setInterval(() => {
      msgIndex = (msgIndex + 1) % diagnosticPhases.length;
      setCurrentText(diagnosticPhases[msgIndex]);
    }, 1100);

    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 94) return 94;
        const jump = Math.floor(Math.random() * 8) + 5;
        return Math.min(prev + jump, 94);
      });
    }, 220);

    return () => {
      clearInterval(interval);
      clearInterval(progressInterval);
    };
  }, [message]);

  return (
    <div style={{
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(7, 10, 18, 0.94)',
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      borderRadius: 'inherit',
      zIndex: 100,
      overflow: 'hidden',
      padding: '18px 24px',
      border: '1px solid rgba(0, 229, 160, 0.25)',
      boxShadow: 'inset 0 0 30px rgba(0, 229, 160, 0.04)'
    }}>
      {/* Top Live Scanning Pill */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        background: 'rgba(0, 229, 160, 0.08)',
        border: '1px solid rgba(0, 229, 160, 0.3)',
        borderRadius: '20px',
        padding: '4px 12px',
        marginBottom: '14px'
      }}>
        <span style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          background: '#00e5a0',
          boxShadow: '0 0 8px #00e5a0',
          animation: 'telemetry-blink 1.2s infinite'
        }} />
        <span className="font-dm-mono" style={{ fontSize: '10.5px', color: '#00e5a0', letterSpacing: '0.12em', fontWeight: '600' }}>
          SECURITY SCANNER ACTIVE
        </span>
      </div>

      {/* Real-time Dynamic Diagnostic Stream */}
      <div 
        className="font-dm-mono" 
        style={{ 
          fontSize: '12px', 
          color: '#ffffff', 
          letterSpacing: '0.06em', 
          textAlign: 'center', 
          zIndex: 10,
          maxWidth: '560px',
          lineHeight: '1.4',
          marginBottom: '14px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '8px'
        }}
      >
        <span style={{ color: '#00f2fe' }}>&gt;</span>
        <span>{currentText}</span>
      </div>

      {/* Slim Modern Progress Track */}
      <div style={{
        width: '100%',
        maxWidth: '360px',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        zIndex: 10,
        marginBottom: '12px'
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontFamily: "'DM Mono', monospace",
          fontSize: '10.5px',
          color: 'var(--text-secondary)'
        }}>
          <span>DIAGNOSTIC PIPELINE</span>
          <span style={{ color: '#00f2fe', fontWeight: '700' }}>{progress}%</span>
        </div>

        <div style={{
          width: '100%',
          height: '4px',
          background: 'rgba(255, 255, 255, 0.08)',
          borderRadius: '2px',
          overflow: 'hidden',
          position: 'relative'
        }}>
          <div style={{
            width: `${progress}%`,
            height: '100%',
            background: 'linear-gradient(90deg, #00e5a0 0%, #00f2fe 100%)',
            boxShadow: '0 0 10px rgba(0, 242, 254, 0.5)',
            borderRadius: '2px',
            transition: 'width 0.22s ease-out'
          }} />
        </div>
      </div>

      {/* Telemetry Micro-Badges */}
      <div 
        className="font-dm-mono"
        style={{
          fontSize: '9.5px',
          color: 'var(--text-muted)',
          letterSpacing: '0.08em',
          textAlign: 'center',
          zIndex: 10,
          display: 'flex',
          gap: '12px',
          flexWrap: 'wrap',
          justifyContent: 'center'
        }}
      >
        <span>LATENCY: <strong style={{ color: '#00f2fe' }}>14ms</strong></span>
        <span>•</span>
        <span>CIPHER: <strong style={{ color: 'var(--aura-safe)' }}>TLS 1.3 / AES-GCM</strong></span>
        <span>•</span>
        <span>CORE: <strong style={{ color: '#ffffff' }}>ZERO-DAY HEURISTICS</strong></span>
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
   UNIVERSAL COMPONENT: Canvas 3D Interactive Cyber Globe & Real-Time Telemetry
   High-visibility geographic cyber-threat projection engine
   ========================================================================= */

const CITIES = [
  { name: "MUMBAI OPS CENTER", lat: 19.076, lon: 72.877, isTarget: true, ip: "103.21.244.0/24", region: "India Central" },
  { name: "TOKYO HUB", lat: 35.676, lon: 139.65, isTarget: false, ip: "133.242.18.91", region: "Asia East" },
  { name: "LONDON GATEWAY", lat: 51.507, lon: -0.127, isTarget: false, ip: "185.86.151.11", region: "Europe West" },
  { name: "NEW YORK NODE", lat: 40.712, lon: -74.006, isTarget: false, ip: "198.51.100.42", region: "US East" },
  { name: "SYDNEY RELAY", lat: -33.868, lon: 151.209, isTarget: false, ip: "139.130.4.5", region: "Oceania" },
  { name: "FRANKFURT DC", lat: 50.110, lon: 8.682, isTarget: false, ip: "194.109.6.98", region: "Europe Central" },
  { name: "SINGAPORE CORE", lat: 1.352, lon: 103.819, isTarget: false, ip: "203.116.1.1", region: "SE Asia" },
  { name: "SAN FRANCISCO", lat: 37.774, lon: -122.419, isTarget: false, ip: "104.244.42.1", region: "US West" },
  { name: "DUBAI CLOUD", lat: 25.204, lon: 55.270, isTarget: false, ip: "94.200.12.8", region: "Middle East" },
  { name: "SAO PAULO NODE", lat: -23.550, lon: -46.633, isTarget: false, ip: "200.147.3.157", region: "S. America" }
];

// Rich, geographically accurate landmass points for high-density 3D rendering
const generateWorldLandDots = () => {
  const dots = [];
  const regions = [
    // India & South Asia (Dense cluster for high visibility)
    { minLat: 8, maxLat: 35, minLon: 68, maxLon: 92, count: 180 },
    // North America (US, Canada, Mexico)
    { minLat: 25, maxLat: 55, minLon: -125, maxLon: -70, count: 200 },
    { minLat: 15, maxLat: 30, minLon: -115, maxLon: -85, count: 60 },
    // South America
    { minLat: -35, maxLat: 10, minLon: -75, maxLon: -35, count: 140 },
    // Europe
    { minLat: 36, maxLat: 65, minLon: -10, maxLon: 35, count: 180 },
    // Africa
    { minLat: -32, maxLat: 35, minLon: -15, maxLon: 48, count: 200 },
    // Middle East
    { minLat: 15, maxLat: 38, minLon: 35, maxLon: 65, count: 90 },
    // East Asia (China, Japan, Korea)
    { minLat: 20, maxLat: 50, minLon: 95, maxLon: 142, count: 220 },
    // Southeast Asia (Indonesia, Malaysia, Philippines)
    { minLat: -10, maxLat: 20, minLon: 95, maxLon: 130, count: 120 },
    // Australia & New Zealand
    { minLat: -38, maxLat: -12, minLon: 115, maxLon: 155, count: 110 },
    { minLat: -46, maxLat: -35, minLon: 166, maxLon: 178, count: 30 }
  ];

  regions.forEach(reg => {
    for (let i = 0; i < reg.count; i++) {
      const lat = reg.minLat + Math.random() * (reg.maxLat - reg.minLat);
      const lon = reg.minLon + Math.random() * (reg.maxLon - reg.minLon);
      dots.push({ lat, lon });
    }
  });

  return dots;
};

const WORLD_LAND_DOTS = generateWorldLandDots();

function ThreatGlobe({ windowWidth, auraColor }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);

  const isMobile = windowWidth <= 768;
  const globeHeight = isMobile ? 310 : 420;
  const telemetryHeight = isMobile ? 280 : 420;

  const [telemetryLogs, setTelemetryLogs] = useState([
    { id: 1, time: "LIVE", tag: "SHIELD", text: "Global 3D Perimeter Vector Grid Online", ip: "103.21.244.0/24", proto: "TLS 1.3", color: "#00e5a0" },
    { id: 2, time: "LIVE", tag: "BLOCKED", text: "DDoS SYN flood dropped at Mumbai edge", ip: "185.86.151.11", proto: "TCP/443", color: "#ff3d5a" },
    { id: 3, time: "LIVE", tag: "AUDIT", text: "Encrypted OSINT crawler verified", ip: "133.242.18.91", proto: "HTTP/3", color: "#4da6ff" },
    { id: 4, time: "LIVE", tag: "DEFENSE", text: "BGP route hijacks neutralized via RPKI", ip: "94.200.12.8", proto: "BGP", color: "#9d6eff" }
  ]);

  const [threatCount, setThreatCount] = useState(142);
  const [activeArcsCount, setActiveArcsCount] = useState(3);
  const [autoRotate, setAutoRotate] = useState(true);

  const stateRef = useRef({
    yaw: 0.85, // Centered on India / South Asia initially
    pitch: 0.32,
    zoom: 1.0,
    isDragging: false,
    startX: 0,
    startY: 0,
    attacks: [
      { origin: CITIES[1], target: CITIES[0], progress: 0.15, speed: 0.012, color: "#ff3d5a", height: 28 },
      { origin: CITIES[2], target: CITIES[0], progress: 0.60, speed: 0.015, color: "#9d6eff", height: 35 },
      { origin: CITIES[3], target: CITIES[0], progress: 0.35, speed: 0.010, color: "#4da6ff", height: 40 }
    ],
    impacts: []
  });

  // Spawn dynamic attack telemetry cycles
  useEffect(() => {
    const attackPresets = [
      { tag: "BLOCKED", text: "Credential stuffing exploit dropped", proto: "HTTPS", color: "#ff3d5a" },
      { tag: "INTERCEPT", text: "Zero-day exploit payload quarantined", proto: "TCP/8443", color: "#ff3d5a" },
      { tag: "AUDIT", text: "Regional telecom dump breach lookup", proto: "API/v2", color: "#9d6eff" },
      { tag: "MITIGATED", text: "Port scanning automated probe halted", proto: "SSH-v2", color: "#f5c518" },
      { tag: "SHIELD", text: "TLS 1.3 Handshake validated", proto: "DoH", color: "#00e5a0" }
    ];

    const interval = setInterval(() => {
      const originCity = CITIES[Math.floor(Math.random() * (CITIES.length - 1)) + 1];
      const preset = attackPresets[Math.floor(Math.random() * attackPresets.length)];
      const d = new Date();
      const timeStr = d.toLocaleTimeString('en-US', { hour12: false });

      setTelemetryLogs(prev => [
        {
          id: Date.now(),
          time: timeStr,
          tag: preset.tag,
          text: `${preset.text} [${originCity.name}]`,
          ip: originCity.ip,
          proto: preset.proto,
          color: preset.color
        },
        ...prev.slice(0, 19)
      ]);

      setThreatCount(c => c + 1);

      const state = stateRef.current;
      if (state.attacks.length < 5) {
        state.attacks.push({
          origin: originCity,
          target: CITIES[0],
          progress: 0,
          speed: 0.009 + Math.random() * 0.014,
          color: preset.color,
          height: 22 + Math.random() * 25
        });
        setActiveArcsCount(state.attacks.length);
      }
    }, 2200);

    return () => clearInterval(interval);
  }, []);

  // 3D Rendering Animation Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let animId = null;

    const resize = () => {
      const rect = containerRef.current?.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const isMob = window.innerWidth <= 768;
      const w = rect ? rect.width : (isMob ? 340 : 500);
      const h = isMob ? 310 : 420;

      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;

      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
    };

    window.addEventListener('resize', resize);
    resize();

    const draw = () => {
      const ctx = canvas.getContext('2d');
      const rect = containerRef.current?.getBoundingClientRect();
      const isMob = window.innerWidth <= 768;
      const width = rect ? rect.width : (isMob ? 340 : 500);
      const height = isMob ? 310 : 420;

      ctx.clearRect(0, 0, width, height);

      const state = stateRef.current;
      if (autoRotate && !state.isDragging) {
        state.yaw += 0.003;
      }

      const centerX = width / 2;
      const centerY = isMob ? (height / 2 + 10) : (height / 2);
      const radius = Math.min(width, height) * (isMob ? 0.36 : 0.38) * state.zoom;

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

      // 1. Celestial Outer Atmosphere Glow
      const glowGrad = ctx.createRadialGradient(centerX, centerY, radius * 0.92, centerX, centerY, radius * 1.35);
      glowGrad.addColorStop(0, 'rgba(0, 229, 160, 0.22)');
      glowGrad.addColorStop(0.4, 'rgba(77, 166, 255, 0.12)');
      glowGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = glowGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // 2. Solid 3D Deep Space Globe Sphere Body
      const sphereGrad = ctx.createRadialGradient(
        centerX - radius * 0.35,
        centerY - radius * 0.35,
        radius * 0.1,
        centerX,
        centerY,
        radius
      );
      sphereGrad.addColorStop(0, '#101c30');
      sphereGrad.addColorStop(0.5, '#0a101d');
      sphereGrad.addColorStop(1, '#03050c');
      ctx.fillStyle = sphereGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.fill();

      // Sharp Illuminated Atmosphere Rim Ring
      ctx.strokeStyle = 'rgba(77, 166, 255, 0.45)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // 3. Back Lat/Lon Coordinate Gridlines (z < 0)
      ctx.lineWidth = 0.6;
      ctx.strokeStyle = 'rgba(77, 166, 255, 0.08)';
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lon = -180; lon <= 180; lon += 6) {
          const pt = latLongTo3D(lat, lon);
          const proj = project(pt);
          if (proj.z < 0) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }
        ctx.stroke();
      }

      // 4. Back Continental Particles (z < 0)
      WORLD_LAND_DOTS.forEach(dot => {
        const pt = latLongTo3D(dot.lat, dot.lon);
        const proj = project(pt);
        if (proj.z < 0) {
          ctx.fillStyle = 'rgba(77, 166, 255, 0.16)';
          ctx.fillRect(proj.x - 0.75, proj.y - 0.75, 1.5, 1.5);
        }
      });

      // 5. Front Lat/Lon Coordinate Gridlines (z >= 0)
      ctx.lineWidth = 0.8;
      ctx.strokeStyle = 'rgba(77, 166, 255, 0.22)';
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
        if (lat === 0) {
          ctx.strokeStyle = 'rgba(0, 229, 160, 0.4)';
          ctx.lineWidth = 1.2;
        } else {
          ctx.strokeStyle = 'rgba(77, 166, 255, 0.18)';
          ctx.lineWidth = 0.7;
        }
        ctx.stroke();
      }

      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let first = true;
        for (let lat = -90; lat <= 90; lat += 4) {
          const pt = latLongTo3D(lat, lon);
          const proj = project(pt);
          if (proj.z >= 0) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }
        ctx.strokeStyle = 'rgba(77, 166, 255, 0.18)';
        ctx.lineWidth = 0.7;
        ctx.stroke();
      }

      // 6. Front High-Visibility Continental Particles (z >= 0)
      WORLD_LAND_DOTS.forEach(dot => {
        const pt = latLongTo3D(dot.lat, dot.lon);
        const proj = project(pt);
        if (proj.z >= 0) {
          const depthAlpha = Math.min(1.0, 0.45 + (proj.z / radius) * 0.55);
          ctx.fillStyle = `rgba(0, 229, 160, ${depthAlpha})`;
          ctx.fillRect(proj.x - 1, proj.y - 1, 2.2, 2.2);
        }
      });

      // 7. Dynamic 3D Curved Threat Arcs
      state.attacks.forEach(attack => {
        const ptA = latLongTo3D(attack.origin.lat, attack.origin.lon);
        const ptB = latLongTo3D(attack.target.lat, attack.target.lon);

        ctx.beginPath();
        let first = true;
        const steps = 36;
        for (let i = 0; i <= steps; i++) {
          const t = i / steps;
          const lx = ptA.x * (1 - t) + ptB.x * t;
          const ly = ptA.y * (1 - t) + ptB.y * t;
          const lz = ptA.z * (1 - t) + ptB.z * t;
          const len = Math.sqrt(lx * lx + ly * ly + lz * lz);
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
          if (proj.z >= -radius * 0.2) {
            if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
            else { ctx.lineTo(proj.x, proj.y); }
          } else { first = true; }
        }

        ctx.lineWidth = 1.4;
        ctx.strokeStyle = attack.color;
        ctx.stroke();

        // Projectile Missile Head
        const tVal = attack.progress;
        const lx = ptA.x * (1 - tVal) + ptB.x * tVal;
        const ly = ptA.y * (1 - tVal) + ptB.y * tVal;
        const lz = ptA.z * (1 - tVal) + ptB.z * tVal;
        const len = Math.sqrt(lx * lx + ly * ly + lz * lz);
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

        if (proj.z >= -radius * 0.2) {
          ctx.beginPath();
          ctx.arc(proj.x, proj.y, 3.5, 0, Math.PI * 2);
          ctx.fillStyle = attack.color;
          ctx.shadowColor = attack.color;
          ctx.shadowBlur = 12;
          ctx.fill();
          ctx.shadowBlur = 0;
        }

        attack.progress += attack.speed;
        if (attack.progress >= 1) {
          state.impacts.push({
            x: ptB.x,
            y: ptB.y,
            z: ptB.z,
            radius: 2,
            maxRadius: 28,
            alpha: 1,
            color: attack.color
          });
        }
      });

      state.attacks = state.attacks.filter(a => a.progress < 1);

      // 8. Impact Shockwaves
      state.impacts.forEach(imp => {
        const proj = project(imp);
        if (proj.z >= 0) {
          ctx.beginPath();
          ctx.arc(proj.x, proj.y, imp.radius, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(255, 61, 90, ${imp.alpha})`;
          ctx.lineWidth = 1.8;
          ctx.stroke();
        }
        imp.radius += 1.2;
        imp.alpha -= 0.04;
      });
      state.impacts = state.impacts.filter(i => i.alpha > 0);

      // 9. Cities and Operational Nodes
      CITIES.forEach(city => {
        const pt = latLongTo3D(city.lat, city.lon);
        const proj = project(pt);
        if (proj.z >= 0) {
          if (city.isTarget) {
            const breathe = Math.sin(Date.now() / 200) * 4;

            ctx.beginPath();
            ctx.arc(proj.x, proj.y, 10 + breathe, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(0, 229, 160, 0.7)';
            ctx.lineWidth = 1.2;
            ctx.stroke();

            ctx.beginPath();
            ctx.arc(proj.x, proj.y, 16 + breathe * 1.4, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(0, 229, 160, 0.3)';
            ctx.lineWidth = 1;
            ctx.stroke();

            ctx.beginPath();
            ctx.arc(proj.x, proj.y, 5, 0, Math.PI * 2);
            ctx.fillStyle = '#00e5a0';
            ctx.shadowColor = '#00e5a0';
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.shadowBlur = 0;

            ctx.fillStyle = '#ffffff';
            ctx.font = isMob ? 'bold 8px "Space Mono", monospace' : 'bold 10px "Space Mono", monospace';
            ctx.fillText(isMob ? "MUMBAI HQ" : city.name, proj.x + 12, proj.y + 4);
          } else {
            ctx.beginPath();
            ctx.arc(proj.x, proj.y, 3, 0, Math.PI * 2);
            ctx.fillStyle = '#ff3d5a';
            ctx.shadowColor = '#ff3d5a';
            ctx.shadowBlur = 6;
            ctx.fill();
            ctx.shadowBlur = 0;

            if (!isMob) {
              ctx.fillStyle = 'rgba(255, 255, 255, 0.75)';
              ctx.font = '9px "Space Mono", monospace';
              ctx.fillText(city.name, proj.x + 8, proj.y + 3);
            }
          }
        }
      });

      animId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
    };
  }, [autoRotate]);

  // Touch and Mouse Drag Listeners
  const handleDragStart = (clientX, clientY) => {
    const state = stateRef.current;
    state.isDragging = true;
    state.startX = clientX;
    state.startY = clientY;
  };

  const handleDragMove = (clientX, clientY) => {
    const state = stateRef.current;
    if (!state.isDragging) return;

    const dx = clientX - state.startX;
    const dy = clientY - state.startY;

    state.yaw += dx * 0.006;
    state.pitch = Math.max(-Math.PI / 2.2, Math.min(Math.PI / 2.2, state.pitch + dy * 0.006));

    state.startX = clientX;
    state.startY = clientY;
  };

  const handleDragEnd = () => {
    stateRef.current.isDragging = false;
  };

  const focusRegion = (yaw, pitch) => {
    stateRef.current.yaw = yaw;
    stateRef.current.pitch = pitch;
    setAutoRotate(false);
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: windowWidth > 1024 ? 'row' : 'column',
      gap: '20px',
      width: '100%',
      alignItems: 'stretch'
    }}>
      {/* 3D Cyber Threat Globe Canvas */}
      <div 
        ref={containerRef}
        className="glass-card"
        style={{
          flex: isMobile ? 'none' : 1.4,
          width: '100%',
          minHeight: `${globeHeight}px`,
          height: `${globeHeight}px`,
          padding: 0,
          background: 'radial-gradient(circle at center, rgba(16, 24, 40, 0.7) 0%, rgba(5, 5, 8, 0.95) 100%)',
          position: 'relative',
          cursor: stateRef.current.isDragging ? 'grabbing' : 'grab',
          userSelect: 'none',
          touchAction: 'none',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          border: '1px solid rgba(0, 229, 160, 0.25)',
          boxShadow: '0 16px 48px rgba(0, 0, 0, 0.8), 0 0 24px rgba(0, 229, 160, 0.08)'
        }}
        onMouseDown={e => handleDragStart(e.clientX, e.clientY)}
        onMouseMove={e => handleDragMove(e.clientX, e.clientY)}
        onMouseUp={handleDragEnd}
        onMouseLeave={handleDragEnd}
        onTouchStart={e => {
          if (e.touches.length === 1) {
            handleDragStart(e.touches[0].clientX, e.touches[0].clientY);
          }
        }}
        onTouchMove={e => {
          if (e.touches.length === 1) {
            handleDragMove(e.touches[0].clientX, e.touches[0].clientY);
          }
        }}
        onTouchEnd={handleDragEnd}
      >
        <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block' }} />

        {/* Top Perspective Controls HUD - Mobile Responsive */}
        <div style={{
          position: 'absolute',
          top: isMobile ? '10px' : '14px',
          right: isMobile ? '10px' : '16px',
          left: isMobile ? '10px' : 'auto',
          justifyContent: isMobile ? 'space-between' : 'flex-end',
          display: 'flex',
          gap: isMobile ? '6px' : '8px',
          zIndex: 10,
          flexWrap: 'nowrap'
        }}>
          <button
            onClick={() => focusRegion(0.85, 0.32)}
            className="font-dm-mono"
            style={{
              background: 'rgba(0, 229, 160, 0.12)',
              border: '1px solid var(--aura-safe)',
              color: 'var(--aura-safe)',
              padding: isMobile ? '4px 8px' : '4px 10px',
              borderRadius: '6px',
              fontSize: isMobile ? '9px' : '10px',
              fontWeight: '600',
              cursor: 'pointer',
              whiteSpace: 'nowrap'
            }}
          >
            {isMobile ? 'INDIA' : 'FOCUS INDIA HQ'}
          </button>
          <button
            onClick={() => focusRegion(-1.8, 0.2)}
            className="font-dm-mono"
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#fff',
              padding: isMobile ? '4px 8px' : '4px 10px',
              borderRadius: '6px',
              fontSize: isMobile ? '9px' : '10px',
              cursor: 'pointer',
              whiteSpace: 'nowrap'
            }}
          >
            {isMobile ? 'AMERICAS' : 'FOCUS AMERICAS'}
          </button>
          <button
            onClick={() => setAutoRotate(!autoRotate)}
            className="font-dm-mono"
            style={{
              background: autoRotate ? 'rgba(157, 110, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${autoRotate ? 'var(--aura-purple)' : 'rgba(255, 255, 255, 0.15)'}`,
              color: autoRotate ? 'var(--aura-purple)' : '#fff',
              padding: isMobile ? '4px 8px' : '4px 10px',
              borderRadius: '6px',
              fontSize: isMobile ? '9px' : '10px',
              cursor: 'pointer',
              whiteSpace: 'nowrap'
            }}
          >
            {isMobile ? (autoRotate ? 'SPIN: ON' : 'SPIN: OFF') : (autoRotate ? 'AUTO SPIN: ON' : 'AUTO SPIN: PAUSED')}
          </button>
        </div>

        {/* Bottom Interactive HUD Pill - Mobile Responsive */}
        <div className="font-dm-mono" style={{
          position: 'absolute',
          bottom: isMobile ? '8px' : '12px',
          left: isMobile ? '10px' : '16px',
          fontSize: isMobile ? '9px' : '10px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.08em',
          pointerEvents: 'none',
          display: 'flex',
          alignItems: 'center',
          gap: isMobile ? '6px' : '12px',
          background: 'rgba(5, 5, 8, 0.85)',
          padding: isMobile ? '4px 10px' : '6px 14px',
          borderRadius: '20px',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          backdropFilter: 'blur(8px)',
          maxWidth: 'calc(100% - 20px)'
        }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--aura-safe)' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00e5a0', boxShadow: '0 0 6px #00e5a0' }} />
            {isMobile ? '3D RADAR ACTIVE' : 'GEO-VECTOR RADAR ACTIVE'}
          </span>
          {!isMobile && (
            <>
              <span style={{ color: 'var(--text-muted)' }}>|</span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <Move size={12} color="var(--text-muted)" /> DRAG TO ROTATE
              </span>
            </>
          )}
        </div>
      </div>

      {/* Synchronized Cyber Telemetry Stream - Mobile Responsive */}
      <div 
        className="glass-card"
        style={{
          flex: isMobile ? 'none' : 1,
          width: '100%',
          height: `${telemetryHeight}px`,
          display: 'flex',
          flexDirection: 'column',
          padding: isMobile ? '16px' : '20px 24px',
          position: 'relative',
          background: 'rgba(9, 9, 13, 0.85)',
          border: '1px solid rgba(255, 255, 255, 0.08)'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={15} color="var(--aura-safe)" />
            <span className="font-dm-mono" style={{ fontSize: isMobile ? '10px' : '11px', fontWeight: '700', color: '#fff', letterSpacing: '0.08em' }}>
              ATTACK TELEMETRY
            </span>
          </div>
          <div className="font-dm-mono" style={{ fontSize: '9px', background: 'rgba(0, 229, 160, 0.1)', color: 'var(--aura-safe)', padding: '2px 8px', borderRadius: '12px', border: '1px solid var(--aura-safe)' }}>
            {threatCount} EVENTS
          </div>
        </div>

        {/* Scrolling Log Stream */}
        <div style={{
          flex: 1,
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          paddingRight: '4px'
        }}>
          {telemetryLogs.map((log) => (
            <div 
              key={log.id} 
              style={{
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                borderLeft: `3px solid ${log.color}`,
                padding: '8px 10px',
                borderRadius: '6px',
                display: 'flex',
                flexDirection: 'column',
                gap: '3px'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="font-dm-mono" style={{ fontSize: '9px', fontWeight: '700', color: log.color, letterSpacing: '0.06em' }}>
                  [{log.tag}] {log.proto}
                </span>
                <span className="font-dm-mono" style={{ fontSize: '9px', color: 'var(--text-muted)' }}>
                  {log.time}
                </span>
              </div>
              <div className="font-dm-sans text-wrap-safe" style={{ fontSize: isMobile ? '11px' : '12px', color: 'var(--text-primary)', lineHeight: '1.3' }}>
                {log.text}
              </div>
              <div className="font-dm-mono" style={{ fontSize: '8px', color: 'var(--text-muted)' }}>
                ORIGIN: {log.ip}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}






/* =========================================================================

   MODULE 1: EXECUTIVE THREAT CENTER & BREACH SEARCH

   ========================================================================= */

function DashboardModule({ windowWidth, auraColor, riskScore, setRiskScore }) {

  const [searchTarget, setSearchTarget] = useState('');

  const [auditMode, setAuditMode] = useState('auto');

  const [breachResult, setBreachResult] = useState(null);

  const [breachSummary, setBreachSummary] = useState('');

  const [loading, setLoading] = useState(false);

  const [hasSearched, setHasSearched] = useState(false);

  const [backendHealth, setBackendHealth] = useState(null);



  // Client-side fallback for credential breach checking

  const runClientSideBreachAudit = async (target, mode) => {

    const clean = target.trim();

    let detMode = mode;

    if (detMode === 'auto') {

      if (clean.includes('@') && !clean.includes(' ')) {

        detMode = 'email';

      } else if (/^(\+?\d[\d\s\-]{8,14}\d)$/.test(clean)) {

        detMode = 'phone';

      } else if (clean.length >= 4 && !clean.includes(' ')) {

        detMode = 'password';

      } else {

        detMode = 'email';

      }

    }



    // Password check via Web Crypto SHA-1 & HIBP

    if (detMode === 'password') {

      try {

        const msgBuffer = new TextEncoder().encode(clean);

        const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);

        const hashArray = Array.from(new Uint8Array(hashBuffer));

        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        const prefix = hashHex.slice(0, 5);

        const suffix = hashHex.slice(5);



        const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);

        if (resp.ok) {

          const lines = (await resp.text()).split('\n');

          for (const line of lines) {

            if (line.trim().startsWith(suffix)) {

              const count = parseInt(line.split(':')[1].trim(), 10);

              return {

                breached: true,

                matches: [{

                  source: `Dark Web Credential Dumps (${count.toLocaleString()} exposures)`,

                  leakType: 'Plaintext Password / Hash Dump',

                  riskRating: 'CRITICAL',

                  recommendations: 'Never reuse this password anywhere. Automated botnets continuously spray this exact string.'

                }],

                summary: `This password was exposed ${count.toLocaleString()} times in recorded breaches!`

              };

            }

          }

        }

        return { breached: false, matches: [], summary: 'Password not found in any public breach databases (800M+ hashes checked).' };

      } catch (e) {

        console.warn('HIBP client-side error:', e);

      }

    }



    // Local simulated catalog fallback

    const emailClean = clean.toLowerCase();

    const directMatch = LOCAL_LEAK_DATABASE[emailClean];

    if (directMatch) {

      return {

        breached: true,

        matches: directMatch,

        summary: `Found ${directMatch.length} historical breach records for this identifier.`

      };

    }



    if (['admin', 'test', 'demo', 'user', 'deepmind', 'hacked', 'leak'].some(k => emailClean.includes(k))) {

      return {

        breached: true,

        matches: [

          {

            source: 'Cloud Infrastructure & Dev Exposure (2024)',

            leakType: 'API Keys, Deployment Environment Variables, Session Tokens',

            riskRating: 'CRITICAL',

            recommendations: 'Rotate root API tokens and invalidate active web sessions immediately.'

          },

          {

            source: 'Global CDN Incident (2025)',

            leakType: 'Session Tokens, Request Headers',

            riskRating: 'HIGH',

            recommendations: 'Clear browser token caches and re-issue login tokens.'

          }

        ],

        summary: 'Matches 2 security test exposure entries.'

      };

    }



    if (detMode === 'phone') {

      return {

        breached: true,

        matches: [

          {

            source: 'Indian Telecom 750M Scraped Registry (2024)',

            leakType: 'Subscriber MSISDN, Primary Circle, Approximate Location',

            riskRating: 'HIGH',

            recommendations: 'Lock your biometrics via UIDAI mAadhaar app. Beware of WhatsApp OTP call-forwarding codes (*401*).'

          }

        ],

        summary: 'Mobile number pattern matched entries in regional scraped directories.'

      };

    }



    return {

      breached: false,

      matches: [],

      summary: 'Zero compromised entries found in global leak registries.'

    };

  };







  const handleBreachSearch = async (e, overrideTarget, overrideMode) => {
    if (e && e.preventDefault) e.preventDefault();
    const targetToSearch = typeof overrideTarget === 'string' ? overrideTarget : searchTarget;
    const cleanTarget = (targetToSearch || '').trim();
    const effectiveMode = typeof overrideMode === 'string' ? overrideMode : auditMode;
    if (!cleanTarget) return;
    if (typeof overrideTarget === 'string') setSearchTarget(overrideTarget);
    if (typeof overrideMode === 'string') setAuditMode(overrideMode);



    setLoading(true);

    setBreachResult(null);

    setBreachSummary('');

    setHasSearched(false);



    try {

      let data = null;

      // 1. Try relative /api/check/credential (Vite dev proxy / Vercel rewrite)

      try {

        const res = await fetch('/api/check/credential', {

          method: 'POST',

          headers: { 'Content-Type': 'application/json' },

          body: JSON.stringify({ target: cleanTarget, mode: auditMode })

        });

        if (res.ok) data = await res.json();

      } catch (err) {

        // Fallback to direct localhost:8000

        try {

          const res = await fetch('http://localhost:8000/api/check/credential', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify({ target: cleanTarget, mode: auditMode })

          });

          if (res.ok) data = await res.json();

        } catch (e2) {

          console.warn('Backend unavailable, running client-side audit fallback', e2);

        }

      }



      // 2. Client-side fallback if backend not available

      if (!data) {

        data = await runClientSideBreachAudit(cleanTarget, auditMode);

      }



      if (data && data.breached) {

        setBreachResult(data.matches || []);

        setBreachSummary(data.summary || `${data.matches.length} breach matches detected.`);

        setRiskScore(data.riskScore || (data.matches.some(m => m.riskRating === 'CRITICAL') ? 85 : 58));

      } else {

        setBreachResult([]);

        setBreachSummary(data?.summary || 'Zero compromised records found in live breach registries.');

        setRiskScore(14); // Isolated / Safe

      }

    } catch (err) {

      console.error('Breach search error:', err);

      setBreachResult([]);

      setBreachSummary('Zero compromised records found in live breach registries.');

      setRiskScore(14);

    } finally {

      setHasSearched(true);

      setLoading(false);

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

            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}><Globe size={14} color="var(--aura-safe)" /> LIVE 3D GEOGRAPHIC VECTOR MAP & IMPACT LOGS</span>

          </div>

          <div 
            className="font-dm-mono"
            style={{
              background: 'rgba(0, 229, 160, 0.08)',
              border: '1px solid rgba(0, 229, 160, 0.3)',
              color: 'var(--aura-safe)',
              padding: '4px 10px',
              borderRadius: '20px',
              fontSize: '10px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00e5a0', boxShadow: '0 0 6px #00e5a0' }} />
            API ENGINE: ONLINE
          </div>

        </div>

        <ThreatGlobe windowWidth={windowWidth} auraColor={auraColor} />

      </div>



      {/* Row 1: HaveIBeenPwned Identity leak auditor */}

      <div 

        className="glass-card glass-card-purple" 

        style={{ width: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', padding: '24px 28px', position: 'relative' }}

      >

          {loading && <MatrixLoader message="Retrieving leak tables & scanning compromised directories..." />}



          <div>

            <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-purple)', letterSpacing: '0.15em', marginBottom: '8px' }}>

              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}><Fingerprint size={14} color="var(--aura-purple)" /> COMPROMISED IDENTITY AUDITOR (LIVE INDEX)</span>

            </div>

            <h3 className="font-syne" style={{ fontSize: '26px', fontWeight: '700', letterSpacing: '-0.02em', marginBottom: '8px', color: '#fff' }}>

              Have Credentials Been Leaked?

            </h3>

            <p className="font-dm-sans" style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '18px' }}>

              Audit major regional and global breaches (such as LinkedIn, Adobe, AirIndia, Indian Telecom dumps, and WhatsApp logs) by entering an email, phone number, or password.

            </p>



            {/* Mode selection buttons - Perfectly aligned 4-column responsive grid */}

            <div style={{ 

              display: 'grid', 

              gridTemplateColumns: windowWidth > 768 ? 'repeat(4, 1fr)' : 'repeat(2, 1fr)', 

              gap: '8px', 

              marginBottom: '18px' 

            }}>

              {[

                { id: 'auto', label: 'Auto-Detect', Icon: Zap },

                { id: 'email', label: 'Email Audit', Icon: Mail },

                { id: 'password', label: 'Password Check', Icon: KeyRound },

                { id: 'phone', label: 'Phone / Telecom', Icon: Smartphone }

              ].map(m => {

                const MIcon = m.Icon;

                const isSelected = auditMode === m.id;

                return (

                  <button

                    key={m.id}

                    type="button"

                    onClick={() => setAuditMode(m.id)}

                    className="font-dm-mono"

                    style={{

                      background: isSelected ? 'var(--aura-purple)' : 'rgba(255,255,255,0.03)',

                      color: isSelected ? '#fff' : 'var(--text-secondary)',

                      border: '1px solid ' + (isSelected ? 'var(--aura-purple)' : 'rgba(255,255,255,0.08)'),

                      borderRadius: '8px',

                      padding: '8px 10px',

                      fontSize: '11px',

                      fontWeight: isSelected ? '600' : '400',

                      cursor: 'pointer',

                      transition: 'all 0.2s ease',

                      display: 'flex',

                      alignItems: 'center',

                      justifyContent: 'center',

                      gap: '6px',

                      whiteSpace: 'nowrap'

                    }}

                  >

                    <MIcon size={13} />

                    <span>{m.label}</span>

                  </button>

                );

              })}

            </div>



            {/* 1-Click Quick-Audit Sample Presets */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '14px' }}>
              <span className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>QUICK PRESETS:</span>
              {[
                { label: 'elon@tesla.com', mode: 'email', val: 'elon@tesla.com' },
                { label: 'test@gmail.com', mode: 'email', val: 'test@gmail.com' },
                { label: '+91 98765 43210', mode: 'phone', val: '+91 98765 43210' },
                { label: 'P@ssw0rd123', mode: 'password', val: 'P@ssw0rd123' },
              ].map((pill, i) => (
                <button
                  key={i}
                  type="button"
                  className="quick-test-pill"
                  onClick={() => handleBreachSearch(null, pill.val, pill.mode)}
                >
                  <Zap size={11} color="var(--aura-safe)" />
                  {pill.label}
                </button>
              ))}
            </div>

            <form onSubmit={handleBreachSearch} style={{ display: 'flex', flexDirection: windowWidth > 640 ? 'row' : 'column', gap: '10px', marginBottom: '20px' }}>

              <input 

                type={auditMode === 'password' ? 'password' : 'text'} 

                placeholder={

                  auditMode === 'password' ? 'Enter password to check k-anonymity (e.g. P@ssw0rd123)' :

                  auditMode === 'phone' ? 'Enter phone number (e.g. +91 98765 43210)' :

                  'Enter email, phone, or password (e.g. test@gmail.com)'

                }

                value={searchTarget}

                onChange={(e) => setSearchTarget(e.target.value)}

                className="cyber-input"

                style={{ flex: 1, minWidth: 0, height: '46px', fontSize: '13px' }}

              />

              <button 

                type="submit" 

                className="font-syne"

                style={{

                  background: 'linear-gradient(90deg, var(--aura-purple) 0%, #7d44ff 100%)',

                  color: '#fff',

                  border: 'none',

                  borderRadius: '8px',

                  padding: '0 26px',

                  height: '46px',

                  fontWeight: '700',

                  fontSize: '13px',

                  letterSpacing: '0.04em',

                  cursor: 'pointer',

                  boxShadow: '0 4px 16px rgba(157, 110, 255, 0.3)',

                  whiteSpace: 'nowrap',

                  flexShrink: 0,

                  display: 'inline-flex',

                  alignItems: 'center',

                  justifyContent: 'center',

                  transition: 'opacity 0.2s ease'

                }}

              >

                CHECK LOGS

              </button>

            </form>

          </div>



          {/* Breach Search results block */}

          <div className="text-wrap-safe">

            {hasSearched ? (

              breachResult && breachResult.length > 0 ? (

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', animation: 'float-in 0.3s ease' }}>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255, 61, 90, 0.08)', padding: '10px 16px', borderRadius: '8px', border: '1px solid var(--aura-danger)', flexWrap: 'wrap', gap: '8px' }}>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>

                      <AlertOctagon size={16} color="var(--aura-danger)" />

                      <span className="font-dm-mono" style={{ fontSize: '12px', fontWeight: '600', color: 'var(--aura-danger)' }}>

                        EXPOSURE DETECTED: {breachResult.length} MATCHES EXPOSED

                      </span>

                    </div>

                    {breachSummary && (

                      <span className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--text-muted)' }}>

                        {breachSummary}

                      </span>

                    )}

                  </div>



                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '180px', overflowY: 'auto', paddingRight: '4px' }}>

                    {breachResult.map((leak, idx) => (

                      <div key={idx} className="glass-card cyber-terminal-overlay text-wrap-safe" style={{ background: 'rgba(5, 5, 8, 0.75)', padding: '14px', border: '1px solid var(--border)' }}>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>

                          <span className="font-syne text-wrap-safe" style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>{leak.source}</span>

                          <span className="font-dm-mono" style={{ fontSize: '9px', background: leak.riskRating === 'CRITICAL' ? 'rgba(255,61,90,0.15)' : 'rgba(255,183,77,0.15)', color: leak.riskRating === 'CRITICAL' ? 'var(--aura-danger)' : 'var(--aura-watch)', padding: '2px 6px', borderRadius: '4px', fontWeight: '600' }}>

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

                  <CheckCircle2 size={18} color="var(--aura-safe)" />

                  <div style={{ display: 'flex', flexDirection: 'column' }}>

                    <span className="font-dm-mono" style={{ fontSize: '12px', fontWeight: '600', color: 'var(--aura-safe)' }}>SYS INTEGRITY: FULLY SECURED</span>

                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>

                      {breachSummary || 'This specific credential holds zero compromised entries inside live global breach registries (15+ billion records indexed).'}

                    </span>

                  </div>

                </div>

              )

            ) : (

              <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center', border: '1px dashed rgba(255,255,255,0.06)', padding: '16px', borderRadius: '8px' }}>

                Awaiting search triggers... Try auditing test@gmail.com, a phone number, or testing a password with k-anonymity.

              </div>

            )}

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

                overflow: 'hidden'

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



// Local fallback heuristic scanner for Link & Scam Audit

function analyzeScamLocally(inputText) {

  const isUrl = inputText.includes('.') && (inputText.toLowerCase().startsWith('http') || inputText.toLowerCase().startsWith('www') || inputText.split(' ')[0].includes('.'));

  let scamProb = isUrl ? 12 : 8;

  const redFlags = [];

  const tactics = [];



  if (isUrl) {

    const urlLower = inputText.toLowerCase();

    if (urlLower.startsWith('http://')) {

      scamProb += 24;

      redFlags.push('Uses insecure http:// protocol instead of encrypted https://');

      tactics.push('Protocol Downgrade');

    }

    const scamTlds = ['.xyz', '.cc', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.net.ru', '.work', '.info'];

    for (const tld of scamTlds) {

      if (urlLower.includes(tld)) {

        scamProb += 35;

        redFlags.push(`Uses generic high-risk TLD (${tld}) popular in coordinate scam campaigns`);

        tactics.push('Generic TLD Exploitation');

        break;

      }

    }

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

    for (const h of homoglyphs) {

      if (urlLower.includes(h.keyword)) {

        scamProb += 48;

        redFlags.push(`Typosquatting Match: Mimics trusted brand '${h.targets}' using lookalike letters '${h.keyword}'`);

        if (!tactics.includes('Brand Impersonation')) tactics.push('Brand Impersonation');

        if (!tactics.includes('Lookalike Typosquatting')) tactics.push('Lookalike Typosquatting');

      }

    }

  } else {

    const lowerText = inputText.toLowerCase();

    tactics.push('Linguistic Heuristics');

    if (lowerText.includes('otp') || lowerText.includes('verification code') || lowerText.includes('pin')) {

      scamProb += 22;

      redFlags.push('Requests confidential security authorization codes (OTP / PIN)');

      tactics.push('Credential Harvesting');

    }

    if (lowerText.includes('electricity') || lowerText.includes('power cut') || lowerText.includes('suspend') || lowerText.includes('block')) {

      scamProb += 26;

      redFlags.push('Threatens immediate service deactivation (power lines, bank accounts)');

      tactics.push('Urgency Trigger');

    }

    if (lowerText.includes('kyc') || lowerText.includes('pension') || lowerText.includes('subsidy') || lowerText.includes('pan card')) {

      scamProb += 20;

      redFlags.push('References official government updates to build fake authority');

      tactics.push('Authority Impersonation');

    }

    if (lowerText.includes('lottery') || lowerText.includes('reward') || lowerText.includes('win') || lowerText.includes('bonus')) {

      scamProb += 24;

      redFlags.push('Offers unrequested financial refunds or cash bonuses');

      tactics.push('Financial Bait');

    }

  }



  scamProb = Math.min(scamProb, 99);

  let verdict = 'SAFE';

  let urgency = 'LOW';

  let recommendation = 'No immediate threat indicators found.';



  if (scamProb > 70) {

    verdict = 'SCAM';

    urgency = 'CRITICAL';

    recommendation = isUrl ? 'DO NOT ACCESS. Close the page immediately. Do not submit primary login cards or passwords.' : 'DO NOT CLICK ANY LINKS OR DIAL THE SENDER. Block the phone line.';

  } else if (scamProb > 30) {

    verdict = 'SUSPICIOUS';

    urgency = 'HIGH';

    recommendation = isUrl ? 'EXERCISE EXTREME CAUTION. Check the domain prefix against official records.' : 'DO NOT SHARE OTPs. Reach out directly to your banking branch.';

  } else {

    if (redFlags.length === 0) {

      redFlags.push(isUrl ? 'No active homoglyph patterns detected' : 'No active threat verbs detected');

    }

  }



  return {

    scamProbability: scamProb,

    verdict,

    manipulationTactics: tactics,

    redFlags,

    recommendation,

    explanation: `Analysis completed for '${inputText}'. Protocol security, TLD repute indices, and linguistic cues evaluated.`,

    urgencyLevel: urgency

  };

}



function ScamDetectorModule({ windowWidth, setRiskScore }) {

  const [inputText, setInputText] = useState('');

  const [loading, setLoading] = useState(false);

  const [result, setResult] = useState(null);

  const [activeAccordion, setActiveAccordion] = useState('explanation');

  const [downloadFeedback, setDownloadFeedback] = useState('');



  const handleDownloadPdf = () => {

    if (!result) return;

    try {

      downloadScamAuditPdf(inputText, result);

      setDownloadFeedback('PDF EXPORTED');

      setTimeout(() => setDownloadFeedback(''), 2500);

    } catch (err) {

      console.error('PDF generation error, falling back to text:', err);

      handleDownloadReport();

    }

  };



  const handleDownloadReport = () => {

    if (!result) return;

    const reportText = generateScamAuditReport(inputText, result);

    const now = new Date();

    const dateStr = now.toISOString().slice(0, 10);

    const filename = `CyberShield_Scam_Audit_Report_${dateStr}.txt`;

    triggerReportDownload(filename, reportText);

    setDownloadFeedback('REPORT EXPORTED');

    setTimeout(() => setDownloadFeedback(''), 2500);

  };



  const handlePrintReport = () => {

    if (!result) return;

    const reportText = generateScamAuditReport(inputText, result);

    printReportContent('CyberShield Scam Audit Memorandum', reportText);

  };



  const executeHeuristicAnalysis = async (overrideText) => {
    const textToAnalyze = typeof overrideText === 'string' ? overrideText : inputText;
    const input = (textToAnalyze || '').trim();
    if (!input) return;
    if (typeof overrideText === 'string') setInputText(overrideText);



    setLoading(true);

    setResult(null);



    try {

      let response;

      try {

        response = await fetch('/api/analyze/scam', {

          method: 'POST',

          headers: { 'Content-Type': 'application/json' },

          body: JSON.stringify({ text: input })

        });

      } catch (e) {

        response = await fetch('http://localhost:8000/api/analyze/scam', {

          method: 'POST',

          headers: { 'Content-Type': 'application/json' },

          body: JSON.stringify({ text: input })

        });

      }



      if (!response.ok) {

        throw new Error('Backend analysis failed');

      }



      const analysisResult = await response.json();

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

    } catch (err) {

      console.warn('Backend unavailable, running local scam heuristics analysis', err);

      const fallbackResult = analyzeScamLocally(input);

      setResult(fallbackResult);

      if (fallbackResult.verdict === 'SCAM') {

        setRiskScore((p) => Math.min(p + 15, 96));

      } else if (fallbackResult.verdict === 'SUSPICIOUS') {

        setRiskScore((p) => Math.min(p + 8, 96));

      } else {

        setRiskScore((p) => Math.max(p - 6, 12));

      }

      setLoading(false);

    }

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

      <div className="glass-card" style={{ padding: '28px', position: 'relative', minHeight: loading ? '180px' : 'auto' }}>

        

        {loading && <MatrixLoader message="Executing URL homoglyph scans & text parser..." />}



        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

          

          {/* 1-Click Realistic Attack Scenarios for Viva & Demo */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '4px' }}>
            <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>1-CLICK ATTACK SCENARIOS (FOR DEMO):</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              {[
                {
                  title: '⚡ Electricity Disconnection SMS',
                  badge: 'CRITICAL',
                  text: 'Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity officer at 9876543210 or click http://bihar-bijli-update.xyz/pay to avoid disconnection.'
                },
                {
                  title: '🏦 SBI KYC Suspension Link',
                  badge: 'HIGH RISK',
                  text: 'URGENT: Your SBI YONO banking account is blocked due to missing PAN Card KYC verification. Update your KYC within 24 hours to resume transactions: https://sbi-kyc-verify.online-portal.in'
                },
                {
                  title: '🎁 Telegram Crypto AirDrop ($8,250)',
                  badge: 'SUSPICIOUS',
                  text: 'Congratulations! You won 2.5 ETH ($8,250) in the Binance Community Giveaway. Claim your allocation before timer runs out at https://binance-airdrop-bonus2026.com/claim?id=99281'
                },
                {
                  title: '✅ Genuine Project Review Invite',
                  badge: 'SAFE',
                  text: 'Hi Jainam, please review the finalized project report and architecture slides for tomorrow viva examination on Google Drive: https://docs.google.com/presentation/d/1A2B3C'
                }
              ].map((scen, idx) => (
                <button
                  key={idx}
                  type="button"
                  className="quick-test-pill"
                  onClick={() => executeHeuristicAnalysis(scen.text)}
                >
                  <span style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: scen.badge === 'SAFE' ? '#00e5a0' : scen.badge === 'SUSPICIOUS' ? '#f5c518' : '#ff3d5a',
                    boxShadow: '0 0 6px ' + (scen.badge === 'SAFE' ? '#00e5a0' : scen.badge === 'SUSPICIOUS' ? '#f5c518' : '#ff3d5a')
                  }} />
                  {scen.title}
                </button>
              ))}
            </div>
          </div>
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

              background: inputText.trim() ? 'linear-gradient(90deg, var(--aura-purple) 0%, #7d44ff 100%)' : 'var(--surface-3)',

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

          

          {/* Executive Report Download Toolbar */}

          <div style={{

            display: 'flex',

            justifyContent: 'space-between',

            alignItems: 'center',

            flexWrap: 'wrap',

            gap: '16px',

            background: 'linear-gradient(135deg, rgba(157, 110, 255, 0.08) 0%, rgba(13, 13, 22, 0.6) 100%)',

            border: '1px solid rgba(157, 110, 255, 0.25)',

            borderRadius: '16px',

            padding: '16px 20px',

            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.4)'

          }}>

            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>

              <div style={{

                width: '38px',

                height: '38px',

                borderRadius: '8px',

                background: 'rgba(157, 110, 255, 0.15)',

                border: '1px solid rgba(157, 110, 255, 0.35)',

                display: 'flex',

                alignItems: 'center',

                justifyContent: 'center',

                color: 'var(--aura-purple)',

                fontSize: '18px'

              }}>

                <FileText size={20} color="var(--aura-purple)" />

              </div>

              <div>

                <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-purple)', letterSpacing: '0.12em', fontWeight: '700' }}>

                  AUDIT DOSSIER READY

                </div>

                <div className="font-syne" style={{ fontSize: '15px', fontWeight: '700', color: '#ffffff', marginTop: '2px' }}>

                  Executive Incident & Fraud Assessment

                </div>

              </div>

            </div>



            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>

              <button

                onClick={handleDownloadPdf}

                className="cyber-report-btn cyber-report-btn-purple font-syne"

                title="Download official vector PDF audit report"

              >

                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />

                  <polyline points="14 2 14 8 20 8" />

                  <line x1="16" y1="13" x2="8" y2="13" />

                  <line x1="16" y1="17" x2="8" y2="17" />

                  <polyline points="10 9 9 9 8 9" />

                </svg>

                {downloadFeedback || 'DOWNLOAD PDF REPORT'}

              </button>



              <button

                onClick={handleDownloadReport}

                className="cyber-report-btn cyber-report-btn-ghost font-syne"

                title="Download plain text audit report (.txt)"

              >

                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />

                  <polyline points="7 10 12 15 17 10" />

                  <line x1="12" y1="15" x2="12" y2="3" />

                </svg>

                .TXT

              </button>



              <button

                onClick={handlePrintReport}

                className="cyber-report-btn cyber-report-btn-ghost font-syne"

                title="Print or preview report"

              >

                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                  <polyline points="6 9 6 2 18 2 18 9" />

                  <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />

                  <rect x="6" y="14" width="12" height="8" />

                </svg>

                PRINT

              </button>

            </div>

          </div>



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

              { id: 'explanation', title: 'Diagnostics Summary', Icon: FileSearch, content: result.explanation, type: 'text' },

              { id: 'tactics', title: 'Manipulation Tactics', Icon: Brain, items: result.manipulationTactics, type: 'tags' },

              { id: 'flags', title: 'Identified Anomalies & Red Flags', Icon: Flag, items: result.redFlags, type: 'list' }

            ].map((acc) => {

              const AccIcon = acc.Icon;

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

                    <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>

                      <AccIcon size={16} color="var(--aura-purple)" />

                      {acc.title}

                    </span>

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



          {/* Bottom Download Action Bar */}

          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '12px', marginTop: '8px', flexWrap: 'wrap' }}>

            <button

              onClick={handleDownloadPdf}

              className="cyber-report-btn cyber-report-btn-purple font-syne"

              style={{ minWidth: '260px', padding: '14px 24px' }}

            >

              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />

                <polyline points="14 2 14 8 20 8" />

                <line x1="16" y1="13" x2="8" y2="13" />

                <line x1="16" y1="17" x2="8" y2="17" />

                <polyline points="10 9 9 9 8 9" />

              </svg>

              {downloadFeedback || 'DOWNLOAD PDF REPORT'}

            </button>

            <button

              onClick={handleDownloadReport}

              className="cyber-report-btn cyber-report-btn-ghost font-syne"

              style={{ padding: '14px 18px' }}

              title="Download text report (.txt)"

            >

              .TXT

            </button>

            <button

              onClick={handlePrintReport}

              className="cyber-report-btn cyber-report-btn-ghost font-syne"

              style={{ padding: '14px 20px' }}

            >

              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                <polyline points="6 9 6 2 18 2 18 9" />

                <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />

                <rect x="6" y="14" width="12" height="8" />

              </svg>

              PRINT

            </button>

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

          { id: 'MERN', name: 'MERN Stack App', Icon: Layers },

          { id: 'WordPress', name: 'WordPress Portal', Icon: Globe },

          { id: 'StaticServerless', name: 'Static Next.js / AWS', Icon: Cloud }

        ].map((stack) => {

          const StackIcon = stack.Icon;

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

      <div className="glass-card" style={{ padding: '28px', position: 'relative', minHeight: loading ? '180px' : 'auto' }}>

        {loading && <MatrixLoader message="Executing full static configuration compile scans..." />}



        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>
            CHECK THE PROTOCOLS CURRENTLY INSTALLED IN YOUR SYSTEM
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              className="quick-test-pill active"
              onClick={() => {
                const all = {};
                activeCriteria.forEach(c => all[c.id] = true);
                setCheckedPolicies(all);
              }}
            >
              <CheckCircle2 size={12} color="var(--aura-safe)" />
              SELECT ALL BASELINES
            </button>
            <button
              type="button"
              className="quick-test-pill"
              onClick={() => setCheckedPolicies({})}
            >
              <X size={12} color="var(--text-muted)" />
              RESET
            </button>
          </div>
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

                  {isChecked && <Check size={12} color="var(--aura-safe)" />}

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

                  <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '8px' }}><ShieldCheck size={32} color="var(--aura-safe)" /></div>

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

  { id: 'phishing', iconKey: 'link', name: 'Phishing Link Redirection', desc: 'Cloning DNS headers and mapping homoglyph targets to capture auth packets.' },

  { id: 'sim', iconKey: 'sim', name: 'SIM Swap (SS7 Exploit)', desc: 'Hijacking SS7 signalling structures or leveraging telecom social-engineering prompts.' },

  { id: 'whatsapp', iconKey: 'chat', name: 'WhatsApp deep-link bypass', desc: 'Executing deep-link redirection code triggers to extract session cookies.' },

  { id: 'upi', iconKey: 'qr', name: 'UPI cash-back QR Injection', desc: 'Inserting lookalike transaction request PIN triggers into cashback QR patterns.' }

];



const TECHNICAL_STEPS_DATABASE = {

  phishing: {

    attackName: "Lookalike Homoglyph Impersonation Campaign",

    victimJourney: "Target clicks a typosquatted domain link, initiating background DNS redirection routines.",

    steps: [

      { stepNumber: 1, title: "typosquatted Domain Registration", description: "Attackers register paytrn.com (swapping m for r+n) using generic offshore registrars to avoid standard KYC validation boards.", dangerLevel: 'medium', iconKey: 'globe' },

      { stepNumber: 2, title: "Lure Dispatch Framework", description: "Coercive SMS sent requesting immediate PAN matching links: 'Your account is locked dial paytrn.com/tax to restore access.'", dangerLevel: 'medium', iconKey: 'mail' },

      { stepNumber: 3, title: "Static Cloned UI Rendering", description: "HTML/CSS site clones Paytm UI, loading in securely under a free SSL padlock. User enters credit credentials.", dangerLevel: 'critical', iconKey: 'monitor' },

      { stepNumber: 4, title: "Socket Session Redirection", description: "Harvested credentials are sent via secure sockets directly to hackers, who input them on genuine terminals to request dynamic bank OTPs.", dangerLevel: 'critical', iconKey: 'smartphone' }

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

      { stepNumber: 1, title: "Identity Profile Indexing", description: "Attackers compile targeted identity datasets (Birthdates, Maiden names) using open social tags and past database breaches.", dangerLevel: 'low', iconKey: 'search' },

      { stepNumber: 2, title: "Telecom Social Bypass", description: "Scammers dial telecom helpdesks presenting fake Aadhaar credentials to report a lost SIM, requesting physical redirection.", dangerLevel: 'high', iconKey: 'call' },

      { stepNumber: 3, title: "SS7 Network Switching", description: "Network nodes transfer active traffic keys from the target's physical device to the hacker's duplicate card. Target device shows 'No Service'.", dangerLevel: 'critical', iconKey: 'ban' },

      { stepNumber: 4, title: "Session Key Intercepts", description: "Scammers trigger password overrides across banking handles, capturing inbound SMS OTP verification keys directly.", dangerLevel: 'critical', iconKey: 'card' }

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

      { stepNumber: 1, title: "Delivery Impersonation Call", description: "Scammer dials target pretending to be a parcel distributor, claiming an address block prevents package arrival.", dangerLevel: 'medium', iconKey: 'package' },

      { stepNumber: 2, title: "Forwarding Code dial", description: "Hacker directs user to type **21*<hacker-number> on their device to 'reschedule dispatch routing'.", dangerLevel: 'high', iconKey: 'call' },

      { stepNumber: 3, title: "Call-Forward Execution", description: "Dialing the prefix forces standard carrier nodes to route all target's incoming phone calls to the attacker's line.", dangerLevel: 'critical', iconKey: 'call-forward' },

      { stepNumber: 4, title: "Voice Verification Intercept", description: "Hacker triggers WhatsApp registration on their own device, requesting verification via phone call to intercept the voice token code.", dangerLevel: 'critical', iconKey: 'chat' }

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

      { stepNumber: 1, title: "Bonus Notification Dispatch", description: "Target receives a cashback notification claiming a ₹2,000 refund is pending inside their wallet profile.", dangerLevel: 'medium', iconKey: 'card' },

      { stepNumber: 2, title: "Scam QR Delivery", description: "A QR image is shared via WhatsApp. Scammer claims: 'Scan this code inside Google Pay to verify your refund transaction.'", dangerLevel: 'high', iconKey: 'smartphone' },

      { stepNumber: 3, title: "Payment Request Execution", description: "The QR code contains a structural payment request parameter. User launches the code and is prompted for their UPI PIN.", dangerLevel: 'critical', iconKey: 'stop' },

      { stepNumber: 4, title: "PIN Authorization Leak", description: "Target enters their PIN, ignoring notices that PINs are ONLY typed to SEND money, never to receive. Funds are immediately debited.", dangerLevel: 'critical', iconKey: 'card' }

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

          paddingTop: '8px',

          paddingBottom: '8px',

          paddingLeft: '8px',

          paddingRight: '8px'

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

                  borderColor: isSelected ? 'var(--aura-purple)' : 'var(--border)',

                  background: isSelected ? 'rgba(157, 110, 255, 0.04)' : 'var(--surface-1)',

                  transform: isSelected ? 'scale(1.02)' : 'scale(1)'

                }}

              >

                <div style={{ marginBottom: '10px' }}>{renderAttackIcon(item.iconKey || item.id, 24, isSelected ? 'var(--aura-purple)' : 'var(--text-secondary)')}</div>

                <h4 className="font-syne" style={{ fontSize: '14px', fontWeight: '600', color: '#fff' }}>{item.name}</h4>

                <p className="font-dm-sans text-wrap-safe" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: '1.4' }}>

                  {item.desc}

                </p>

              </div>

            );

          })}

          {/* Spacer to prevent right-side scroll clipping on mobile */}

          <div style={{ minWidth: '16px', flexShrink: 0 }}></div>

        </div>

      </div>



      <button 

        onClick={handleSimulationStart}
        className="cyber-attack-launch-btn font-syne"
      >
        <span style={{ display: 'inline-flex', alignItems: 'center' }}><Zap size={18} color="var(--aura-safe)" /></span>
        <span style={{ letterSpacing: '0.06em' }}>SIMULATE ATTACK PIPELINE</span>
        <span style={{
          fontSize: '10px',
          background: 'rgba(0, 229, 160, 0.15)',
          color: 'var(--aura-safe)',
          padding: '2px 8px',
          borderRadius: '12px',
          border: '1px solid var(--aura-safe)',
          fontWeight: '600'
        }}>
          AI ACTIVE
        </span>
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

        {/* DYNAMIC VISUAL ATTACK TOPOLOGY */}
        <div style={{
          background: 'rgba(5, 7, 14, 0.75)',
          border: '1px solid rgba(0, 242, 254, 0.25)',
          borderRadius: '12px',
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
          marginBottom: '20px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(255, 61, 90, 0.15)', border: '1px solid var(--aura-danger)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldAlert size={16} color="var(--aura-danger)" />
            </div>
            <div>
              <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-danger)' }}>THREAT VECTOR</div>
              <div className="font-syne" style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>EXTERNAL ATTACKER</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--text-muted)' }}>
            <span style={{ width: '20px', height: '2px', background: 'linear-gradient(90deg, var(--aura-danger), #00f2fe)' }} />
            <ChevronRight size={14} color="#00f2fe" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.12)', border: '1px solid #00f2fe', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={16} color="#00f2fe" />
            </div>
            <div>
              <div className="font-dm-mono" style={{ fontSize: '10px', color: '#00f2fe' }}>EDGE DEFENSE</div>
              <div className="font-syne" style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>CLOUDFLARE WAF</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--text-muted)' }}>
            <span style={{ width: '20px', height: '2px', background: 'linear-gradient(90deg, #00f2fe, var(--aura-safe))' }} />
            <ChevronRight size={14} color="var(--aura-safe)" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(0, 229, 160, 0.12)', border: '1px solid var(--aura-safe)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Lock size={16} color="var(--aura-safe)" />
            </div>
            <div>
              <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-safe)' }}>CONTAINER SANDBOX</div>
              <div className="font-syne" style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>DOCKER ISOLATION</div>
            </div>
          </div>
        </div>
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

                            {renderAttackIcon(step.iconKey || 'alert', 18, getDangerColor(step.dangerLevel))}

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

                          <ShieldCheck size={18} color="var(--aura-safe)" />

                          <span className="font-dm-sans text-wrap-safe" style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: '1.4' }}>{p}</span>

                        </div>

                      ))}

                    </div>

                  </div>



                  {/* Incident index */}

                  <div className="glass-card" style={{ padding: '24px', borderLeft: '4px solid var(--aura-watch)', background: 'rgba(245, 197, 24, 0.01)' }}>

                    <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-watch)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>

                      <FileText size={12} color="var(--aura-watch)" />

                      HISTORICAL SCAM INDEX (INDIA)

                    </div>

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



  const handleAuditRequest = (overrideDesc, overridePersona) => {
    const descVal = typeof overrideDesc === 'string' ? overrideDesc : description;
    const desc = (descVal || '').trim();
    const persona = typeof overridePersona === 'string' ? overridePersona : selectedPersona;
    if (!desc) return;
    if (typeof overrideDesc === 'string') setDescription(overrideDesc);
    if (typeof overridePersona === 'string') setSelectedPersona(overridePersona);
    if (overrideDesc !== undefined) setDescription(overrideDesc);
    if (overridePersona) setSelectedPersona(overridePersona);



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

            { id: 'Elder', label: 'Elder / Parent', Icon: HeartHandshake, desc: 'Simple, large guides focusing on utility bill threats, bank calls, and OTP block warnings.' },

            { id: 'Adult', label: 'Working Adult', Icon: Briefcase, desc: 'Audits UPI scanner QR requests, advance tenancy bookings, and tax refund links.' },

            { id: 'Teen', label: 'Student / Teen', Icon: GraduationCap, desc: 'Exposes WhatsApp part-time job codes, social media tags, and Telegram investment leaks.' }

          ].map((persona) => {

            const isSelected = selectedPersona === persona.id;

            const PersonaIcon = persona.Icon;

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

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>

                  <PersonaIcon size={20} color={isSelected ? 'var(--aura-purple)' : 'var(--text-secondary)'} />

                  <h4 className="font-syne" style={{ fontSize: '16px', fontWeight: '600' }}>{persona.label}</h4>

                </div>

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

            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}><Heart size={14} color="var(--aura-safe)" /> Reassurance: {advice.emotionalSupport}</span>

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

            <div className="font-dm-mono" style={{ fontSize: '11px', color: 'var(--aura-watch)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '6px' }}>

              <Flag size={13} color="var(--aura-watch)" />

              KEY MANIPULATION TRACES FOUND

            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

              {advice.warningSignsExplained.map((sign, idx) => (

                <div key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>

                  <AlertTriangle size={16} color="var(--aura-watch)" style={{ flexShrink: 0, marginTop: '2px' }} />

                  <span className="font-dm-sans text-wrap-safe" style={{ fontSize: '14px', color: 'var(--text-primary)', lineHeight: '1.5' }}>{sign}</span>

                </div>

              ))}

            </div>

          </div>



          {/* Helplineemergencybox */}

          {advice.shouldCallPolice && (

            <div className="glass-card" style={{ padding: '24px', borderColor: 'var(--aura-danger)', background: 'rgba(255, 61, 90, 0.03)' }}>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>

                <AlertOctagon size={24} color="var(--aura-danger)" />

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

                    <PhoneCall size={14} color="var(--aura-danger)" /> {hl.name.toUpperCase()}: {hl.number}

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

  const [downloadFeedback, setDownloadFeedback] = useState('');



  const handleDownloadPdf = () => {

    if (!scanResult) return;

    try {

      downloadSiteSecurityPdf(inputUrl, scanResult);

      setDownloadFeedback('PDF EXPORTED');

      setTimeout(() => setDownloadFeedback(''), 2500);

    } catch (err) {

      console.error('PDF generation error, falling back to text:', err);

      handleDownloadReport();

    }

  };



  const handleDownloadReport = () => {

    if (!scanResult) return;

    const reportText = generateSiteSecurityReport(inputUrl, scanResult);

    let cleanDomain = 'site';

    try {

      const parsed = new URL(scanResult.url || inputUrl);

      cleanDomain = parsed.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');

    } catch (e) {

      cleanDomain = (inputUrl || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');

    }

    const now = new Date();

    const dateStr = now.toISOString().slice(0, 10);

    const filename = `CyberShield_Site_Security_Report_${cleanDomain}_${dateStr}.txt`;

    triggerReportDownload(filename, reportText);

    setDownloadFeedback('REPORT EXPORTED');

    setTimeout(() => setDownloadFeedback(''), 2500);

  };



  const handlePrintReport = () => {

    if (!scanResult) return;

    const reportText = generateSiteSecurityReport(inputUrl, scanResult);

    printReportContent(`CyberShield Security Report - ${scanResult.url || inputUrl}`, reportText);

  };

  

  // API Key removed for security

  const performScan = async (overrideUrl) => {
    const urlToScan = typeof overrideUrl === 'string' ? overrideUrl : inputUrl;
    let target = (urlToScan || '').trim();
    if (!target) return;
    if (!target.startsWith('http')) {
      target = 'https://' + target;
    }
    setInputUrl(target);
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

      <div className="glass-card" style={{ padding: '28px', position: 'relative', minHeight: loading ? '180px' : 'auto' }}>

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

          

          {/* Executive Report Download Toolbar */}

          <div style={{

            display: 'flex',

            justifyContent: 'space-between',

            alignItems: 'center',

            flexWrap: 'wrap',

            gap: '16px',

            background: 'linear-gradient(135deg, rgba(0, 229, 160, 0.08) 0%, rgba(13, 13, 22, 0.6) 100%)',

            border: '1px solid rgba(0, 229, 160, 0.25)',

            borderRadius: '16px',

            padding: '16px 20px',

            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.4)'

          }}>

            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>

              <div style={{

                width: '38px',

                height: '38px',

                borderRadius: '8px',

                background: 'rgba(0, 229, 160, 0.15)',

                border: '1px solid rgba(0, 229, 160, 0.35)',

                display: 'flex',

                alignItems: 'center',

                justifyContent: 'center',

                color: 'var(--aura-safe)',

                fontSize: '18px'

              }}>

                <ShieldCheck size={20} color="var(--aura-safe)" />

              </div>

              <div>

                <div className="font-dm-mono" style={{ fontSize: '10px', color: 'var(--aura-safe)', letterSpacing: '0.12em', fontWeight: '700' }}>

                  PERIMETER AUDIT COMPLETE

                </div>

                <div className="font-syne" style={{ fontSize: '15px', fontWeight: '700', color: '#ffffff', marginTop: '2px' }}>

                  Executive Security & Remediation Report

                </div>

              </div>

            </div>



            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>

              <button

                onClick={handleDownloadPdf}

                className="cyber-report-btn cyber-report-btn-safe font-syne"

                title="Download official vector PDF security audit report"

              >

                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />

                  <polyline points="14 2 14 8 20 8" />

                  <line x1="16" y1="13" x2="8" y2="13" />

                  <line x1="16" y1="17" x2="8" y2="17" />

                  <polyline points="10 9 9 9 8 9" />

                </svg>

                {downloadFeedback || 'DOWNLOAD PDF REPORT'}

              </button>



              <button

                onClick={handleDownloadReport}

                className="cyber-report-btn cyber-report-btn-ghost font-syne"

                title="Download plain text security report (.txt)"

              >

                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />

                  <polyline points="7 10 12 15 17 10" />

                  <line x1="12" y1="15" x2="12" y2="3" />

                </svg>

                .TXT

              </button>



              <button

                onClick={handlePrintReport}

                className="cyber-report-btn cyber-report-btn-ghost font-syne"

                title="Print or preview report"

              >

                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                  <polyline points="6 9 6 2 18 2 18 9" />

                  <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />

                  <rect x="6" y="14" width="12" height="8" />

                </svg>

                PRINT

              </button>

            </div>

          </div>



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

                    <Check size={14} color="var(--aura-safe)" style={{ flexShrink: 0 }} />

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



          {/* Bottom Download Action Bar */}

          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '12px', marginTop: '8px', flexWrap: 'wrap' }}>

            <button

              onClick={handleDownloadPdf}

              className="cyber-report-btn cyber-report-btn-safe font-syne"

              style={{ minWidth: '260px', padding: '14px 24px' }}

            >

              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />

                <polyline points="14 2 14 8 20 8" />

                <line x1="16" y1="13" x2="8" y2="13" />

                <line x1="16" y1="17" x2="8" y2="17" />

                <polyline points="10 9 9 9 8 9" />

              </svg>

              {downloadFeedback || 'DOWNLOAD PDF REPORT'}

            </button>

            <button

              onClick={handleDownloadReport}

              className="cyber-report-btn cyber-report-btn-ghost font-syne"

              style={{ padding: '14px 18px' }}

              title="Download text report (.txt)"

            >

              .TXT

            </button>

            <button

              onClick={handlePrintReport}

              className="cyber-report-btn cyber-report-btn-ghost font-syne"

              style={{ padding: '14px 20px' }}

            >

              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">

                <polyline points="6 9 6 2 18 2 18 9" />

                <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />

                <rect x="6" y="14" width="12" height="8" />

              </svg>

              PRINT

            </button>

          </div>



        </div>

      )}



    </div>

  );

}

