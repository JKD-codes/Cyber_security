/**
 * CyberShield Security Operations Center (SOC)
 * Professional Audit Report Generator & PDF Exporter
 * 
 * Generates well-defined, executive-grade vector PDF audit reports
 * and structured plain text files without AI markers, double dashes (--),
 * or awkward comma patterns (", and" or "and,").
 */

import { jsPDF } from 'jspdf';


export function getSecureAuditId(prefix) {
  let randVal = 100000;
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    randVal = 100000 + (arr[0] % 900000);
  } else {
    randVal = 100000 + Math.floor(Math.random() * 900000);
  }
  return `${prefix}-${new Date().getFullYear()}-${randVal}`;
}

export function cleanHumanText(text) {
  if (!text) return '';
  let cleaned = String(text);
  
  // 1. Remove AI references, model tokens, and automated bot phrasing
  cleaned = cleaned.replace(/AI Engine detected anomalous scam phrasing \(\d+%\s*confidence\)/gi, 'Linguistic pattern analysis identified fraudulent phrasing structures');
  cleaned = cleaned.replace(/\bAI[\s_-]*engine\b/gi, 'Heuristic Inspection Engine');
  cleaned = cleaned.replace(/\bAI[\s_-]*assisted\b/gi, 'Heuristic-Assisted');
  cleaned = cleaned.replace(/\bAI[\s_-]*pattern\s*match\b/gi, 'Heuristic Pattern Analysis');
  cleaned = cleaned.replace(/\bAI\b/g, 'Heuristic');
  cleaned = cleaned.replace(/\bai\b/g, 'heuristic');
  cleaned = cleaned.replace(/machine\s+learning\s+contextual\s+confidence:\s*\d+%/gi, '');
  cleaned = cleaned.replace(/machine\s+learning/gi, 'behavioral pattern correlation');
  cleaned = cleaned.replace(/groq\s*\([^)]*\)/gi, 'defensive perimeter evaluation');
  cleaned = cleaned.replace(/llama\s*3/gi, 'heuristic rule matrix');
  cleaned = cleaned.replace(/stream the data through [^.]+\./gi, 'evaluate the data against established security baselines.');

  // 2. Remove double dashes (--) and em dashes (—)
  cleaned = cleaned.replace(/--+/g, ' - ');
  cleaned = cleaned.replace(/—/g, ' - ');
  cleaned = cleaned.replace(/–/g, ' - ');

  // 3. Remove comma after 'and' (e.g. "and," -> "and") and comma before 'and' (e.g. ", and" -> " and")
  cleaned = cleaned.replace(/\band,\s*/gi, 'and ');
  cleaned = cleaned.replace(/,\s*and\b/gi, ' and');

  // 4. Clean up any trailing or double spaces
  cleaned = cleaned.replace(/[ \t]+/g, ' ').trim();

  return cleaned;
}

/**
 * Builds and downloads a well-defined vector PDF audit report for Link & Scam Audit.
 */
export function downloadScamAuditPdf(targetInput, result) {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric'
  });
  const timeStr = now.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });
  const fullDateStr = now.toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
  const auditId = getSecureAuditId('CS-AUD');

  const cleanInput = (targetInput || '').trim();
  const isUrl = cleanInput.startsWith('http') || (cleanInput.includes('.') && !cleanInput.includes(' '));
  const targetLabel = isUrl ? 'Uniform Resource Locator (URL)' : 'Communication Payload (SMS / Text Message)';

  const verdict = result.verdict || 'SUSPICIOUS';
  const score = result.scamProbability ?? 50;
  const urgency = result.urgencyLevel || 'HIGH';

  function checkAddPage(neededHeight = 40) {
    if (y + neededHeight > pageHeight - margin - 30) {
      doc.addPage();
      y = margin + 20;
      drawHeaderMini();
    }
  }

  function drawHeaderMini() {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(120, 130, 145);
    doc.text('CYBERSHIELD SECURITY OPERATIONS CENTER | AUDIT DOSSIER ' + auditId, margin, margin);
    doc.setDrawColor(220, 225, 235);
    doc.setLineWidth(0.5);
    doc.line(margin, margin + 6, margin + contentWidth, margin + 6);
  }

  // --- TOP HEADER BAR ---
  const headerHeight = 58;
  // Deep Executive Navy (eliminating harsh pitch black)
  doc.setFillColor(18, 26, 44);
  doc.roundedRect(margin, y, contentWidth, headerHeight, 6, 6, 'F');

  // Accent Line at top: CyberShield Teal
  doc.setFillColor(0, 229, 160);
  doc.roundedRect(margin, y, contentWidth, 3.5, 2, 2, 'F');

  // Header Typography with generous inner padding
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12.5);
  doc.setTextColor(255, 255, 255);
  doc.text('CYBERSHIELD SECURITY OPERATIONS CENTER', margin + 18, y + 25);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(165, 182, 208);
  doc.text('PERIMETER SURVEILLANCE & FRAUD MITIGATION MEMORANDUM', margin + 18, y + 43);

  // Security Classification Tag (Pill)
  const badgeWidth = 105;
  const badgeHeight = 22;
  const badgeX = margin + contentWidth - badgeWidth - 16;
  const badgeY = y + 18;
  doc.setFillColor(28, 40, 68);
  doc.setDrawColor(48, 68, 110);
  doc.setLineWidth(0.8);
  doc.roundedRect(badgeX, badgeY, badgeWidth, badgeHeight, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 195, 70);
  doc.text('RESTRICTED / SOC', badgeX + badgeWidth / 2, badgeY + 14, { align: 'center' });

  // Advance y past header with generous vertical breathing room (prevents title overlap)
  y += headerHeight + 42;

  // --- REPORT TITLE ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(18, 26, 44);
  doc.text('Communication Security & Fraud Audit Report', margin, y);
  y += 24;

  // --- METADATA CARD ---
  const metaCardHeight = 82;
  doc.setFillColor(248, 250, 253);
  doc.setDrawColor(222, 228, 238);
  doc.setLineWidth(1);
  doc.roundedRect(margin, y, contentWidth, metaCardHeight, 6, 6, 'FD');

  const col1LabelX = margin + 18;
  const col1ValX = margin + 104;
  const col2LabelX = margin + 276;
  const col2ValX = margin + 358;

  const cardStartY = y;
  const r1Y = cardStartY + 20;
  const r2Y = cardStartY + 41;
  const r3Y = cardStartY + 62;

  doc.setFontSize(8.5);

  // Row 1
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Report Identifier:', col1LabelX, r1Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text(auditId, col1ValX, r1Y);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Auditing Body:', col2LabelX, r1Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text('Threat Intelligence Desk', col2ValX, r1Y);

  // Row 2
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Audit Timestamp:', col1LabelX, r2Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text(`${dateStr} • ${timeStr}`, col1ValX, r2Y);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Target Payload:', col2LabelX, r2Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  const truncTarget = cleanInput.length > 28 ? cleanInput.substring(0, 26) + '...' : cleanInput;
  doc.text(truncTarget, col2ValX, r2Y);

  // Row 3
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Target Category:', col1LabelX, r3Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  const truncCategory = targetLabel.length > 28 ? targetLabel.substring(0, 26) + '...' : targetLabel;
  doc.text(truncCategory, col1ValX, r3Y);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Compliance Level:', col2LabelX, r3Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text('Authorized Incident Review', col2ValX, r3Y);

  y += metaCardHeight + 24;

  // --- VERDICT STATUS CARD ---
  let statusBg = [255, 240, 240];
  let statusBorder = [240, 60, 80];
  let statusTextCol = [180, 20, 40];
  let verdictTitle = 'CRITICAL MALICIOUS FRAUD DETECTED';

  if (verdict === 'SUSPICIOUS') {
    statusBg = [255, 250, 235];
    statusBorder = [230, 160, 20];
    statusTextCol = [170, 100, 0];
    verdictTitle = 'SUSPICIOUS BEHAVIORAL INDICATORS FLAGGED';
  } else if (verdict === 'SAFE') {
    statusBg = [238, 252, 246];
    statusBorder = [0, 180, 120];
    statusTextCol = [0, 130, 80];
    verdictTitle = 'VERIFIED SECURE COMMUNICATION PROFILE';
  }

  doc.setFillColor(...statusBg);
  doc.setDrawColor(...statusBorder);
  doc.setLineWidth(1.2);
  doc.roundedRect(margin, y, contentWidth, 48, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...statusTextCol);
  doc.text(verdictTitle, margin + 14, y + 20);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(60, 70, 85);
  doc.text(`Threat Confidence: ${score}% Risk Index   |   Operational Urgency: ${urgency} Level Priority`, margin + 14, y + 36);

  y += 62;

  // --- SECTION 1: EXECUTIVE SUMMARY ---
  checkAddPage(70);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text('1. EXECUTIVE SUMMARY & POSTURE EVALUATION', margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  let execText = '';
  if (verdict === 'SCAM') {
    execText = `During the formal audit performed on ${fullDateStr}, the incident investigation desk verified dangerous social engineering and deceptive markers in the submitted target. The examination noted specific attempts to manipulate user trust and bypass standard security verifications. Immediate protective measures are advised to prevent credential theft or unauthorized financial loss.`;
  } else if (verdict === 'SUSPICIOUS') {
    execText = `During the formal audit performed on ${fullDateStr}, the incident investigation desk identified irregular behavioral indicators in the submitted asset. While outright system intrusion was not conclusively established, the anomalous markers warrant serious vigilance. Users should not provide security tokens or authenticate identity until confirmed by an independent official authority.`;
  } else {
    execText = `During the formal audit performed on ${dateStr}, the inspection desk confirmed that the evaluated communication conforms to standard legitimate transmission patterns. No overt malicious redirection or social engineering triggers were observed. Personnel should continue following regular operational security practices.`;
  }

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(45, 55, 70);
  const splitExec = doc.splitTextToSize(execText, contentWidth);
  doc.text(splitExec, margin, y);
  y += splitExec.length * 13 + 14;

  // --- SECTION 2: IDENTIFIED ANOMALIES & RED FLAGS ---
  checkAddPage(60);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text('2. TECHNICAL FINDINGS & ANOMALIES', margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  const redFlags = (result.redFlags || [])
    .map(f => cleanHumanText(f))
    .filter(f => f && !f.toLowerCase().includes('failed to execute') && !f.toLowerCase().includes('backend'));

  if (redFlags.length > 0) {
    redFlags.forEach((flag, idx) => {
      checkAddPage(30);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(190, 40, 50);
      doc.text(`[Anomaly ${idx + 1}]`, margin, y);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(40, 45, 60);
      const splitFlag = doc.splitTextToSize(flag, contentWidth - 70);
      doc.text(splitFlag, margin + 65, y);
      y += Math.max(splitFlag.length * 13, 16) + 4;
    });
  } else {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(70, 80, 95);
    doc.text('No active anomalous threat triggers were discovered during this assessment.', margin, y);
    y += 18;
  }
  y += 10;

  // --- SECTION 3: OBSERVED MANIPULATION TACTICS ---
  const tactics = (result.manipulationTactics || [])
    .map(t => cleanHumanText(t))
    .filter(t => t && !t.toLowerCase().includes('backend') && !t.toLowerCase().includes('error'));

  if (tactics.length > 0) {
    checkAddPage(50);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(20, 25, 38);
    doc.text('3. BEHAVIORAL PROFILE & OBSERVED TACTICS', margin, y);
    doc.setDrawColor(210, 218, 230);
    doc.setLineWidth(0.75);
    doc.line(margin, y + 4, margin + contentWidth, y + 4);
    y += 18;

    tactics.forEach((tactic) => {
      checkAddPage(20);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(60, 75, 110);
      doc.text('*', margin + 6, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(40, 50, 65);
      doc.text(tactic, margin + 18, y);
      y += 15;
    });
    y += 10;
  }

  // --- SECTION 4: REMEDIATION & DEFENSIVE DIRECTIVES ---
  checkAddPage(80);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text('4. OPERATIONAL RECOMMENDATIONS & DEFENSIVE PROTOCOL', margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  const recommendation = cleanHumanText(result.recommendation) || 'Exercise caution and verify sender identity.';
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(30, 35, 50);
  doc.text('Primary Mitigation Directive:', margin, y);
  y += 14;

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(45, 55, 70);
  const splitRec = doc.splitTextToSize(recommendation, contentWidth);
  doc.text(splitRec, margin, y);
  y += splitRec.length * 13 + 12;

  const actionSteps = verdict === 'SCAM' ? [
    'Immediately cease interaction with the sender, link or telephone endpoint.',
    'Do not transmit credentials, passwords, one-time security codes or card identifiers.',
    'Execute credential reset procedures on any services where identical credentials were used.',
    'Submit an incident report to the National Cyber Crime Portal (Helpline 1930) and your corporate security office.'
  ] : verdict === 'SUSPICIOUS' ? [
    'Confirm identity through an independent, pre-authenticated corporate directory.',
    'Verify root domain syntax in the browser address bar before interacting with input fields.',
    'Never approve two-factor authentication prompts without direct initiation from your session.'
  ] : [
    'Continue maintaining standard organizational security vigilance.',
    'Verify transport encryption (HTTPS) prior to submitting confidential organizational records.'
  ];

  actionSteps.forEach((step, idx) => {
    checkAddPage(24);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(40, 50, 70);
    doc.text(`${idx + 1}.`, margin + 6, y);
    doc.setFont('helvetica', 'normal');
    const splitStep = doc.splitTextToSize(step, contentWidth - 24);
    doc.text(splitStep, margin + 22, y);
    y += Math.max(splitStep.length * 12, 14) + 3;
  });

  y += 14;

  // --- SECTION 5: AUDITOR SIGN-OFF ---
  checkAddPage(75);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text('5. AUDITOR SIGN-OFF & ATTESTATION', margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  doc.setFillColor(248, 250, 253);
  doc.roundedRect(margin, y, contentWidth, 54, 4, 4, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(70, 80, 100);
  doc.text('Lead Threat Auditor:', margin + 14, y + 18);
  doc.text('Operational Division:', margin + 14, y + 36);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(30, 35, 45);
  doc.text('Senior Incident Response & Deception Analysis Lead', margin + 125, y + 18);
  doc.text('CyberShield Information Security & Perimeter Defense Operations', margin + 125, y + 36);

  // --- FOOTERS ON ALL PAGES ---
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(140, 150, 165);
    doc.setDrawColor(225, 230, 240);
    doc.setLineWidth(0.5);
    doc.line(margin, pageHeight - 30, margin + contentWidth, pageHeight - 30);
    doc.text('CyberShield Security Operations Center | Official Technical Audit Document', margin, pageHeight - 18);
    doc.text(`Page ${i} of ${totalPages}`, margin + contentWidth, pageHeight - 18, { align: 'right' });
  }

  const dateFile = now.toISOString().slice(0, 10);
  doc.save(`CyberShield_Scam_Audit_Report_${dateFile}.pdf`);
  return doc;
}

/**
 * Builds and downloads a well-defined vector PDF audit report for Site Security Scanner.
 */
export function downloadSiteSecurityPdf(targetUrl, scanResult) {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric'
  });
  const timeStr = now.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });
  const fullDateStr = now.toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
  const scanId = getSecureAuditId('CS-SCAN');

  const cleanUrl = (targetUrl || scanResult.url || '').trim();
  const grade = scanResult.grade || 'C';
  const passed = (scanResult.passedChecks || []).map(p => cleanHumanText(p));
  const issues = (scanResult.issues || []).map(issue => ({
    title: cleanHumanText(issue.title),
    severity: issue.severity || 'MEDIUM',
    description: cleanHumanText(issue.description),
    solution: cleanHumanText(issue.solution)
  }));

  function checkAddPage(neededHeight = 40) {
    if (y + neededHeight > pageHeight - margin - 30) {
      doc.addPage();
      y = margin + 20;
      drawHeaderMini();
    }
  }

  function drawHeaderMini() {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(120, 130, 145);
    doc.text('CYBERSHIELD SECURITY OPERATIONS CENTER | PERIMETER AUDIT ' + scanId, margin, margin);
    doc.setDrawColor(220, 225, 235);
    doc.setLineWidth(0.5);
    doc.line(margin, margin + 6, margin + contentWidth, margin + 6);
  }

  // --- TOP HEADER BAR ---
  const headerHeight = 58;
  // Deep Executive Navy (eliminating harsh pitch black)
  doc.setFillColor(18, 26, 44);
  doc.roundedRect(margin, y, contentWidth, headerHeight, 6, 6, 'F');

  // Accent Line at top: CyberShield Teal
  doc.setFillColor(0, 229, 160);
  doc.roundedRect(margin, y, contentWidth, 3.5, 2, 2, 'F');

  // Header Typography with generous inner padding
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12.5);
  doc.setTextColor(255, 255, 255);
  doc.text('CYBERSHIELD SECURITY OPERATIONS CENTER', margin + 18, y + 25);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(165, 182, 208);
  doc.text('PERIMETER DEFENSE & VULNERABILITY AUDIT MEMORANDUM', margin + 18, y + 43);

  // Security Tag (Pill)
  const badgeWidth = 98;
  const badgeHeight = 22;
  const badgeX = margin + contentWidth - badgeWidth - 16;
  const badgeY = y + 18;
  doc.setFillColor(28, 40, 68);
  doc.setDrawColor(48, 68, 110);
  doc.setLineWidth(0.8);
  doc.roundedRect(badgeX, badgeY, badgeWidth, badgeHeight, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(0, 229, 160);
  doc.text('OFFICIAL AUDIT', badgeX + badgeWidth / 2, badgeY + 14, { align: 'center' });

  // Advance y past header with generous vertical breathing room (prevents title overlap)
  y += headerHeight + 42;

  // --- TITLE ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(18, 26, 44);
  doc.text('Perimeter Security & Vulnerability Assessment', margin, y);
  y += 24;

  // --- METADATA CARD ---
  const metaCardHeight = 82;
  doc.setFillColor(248, 250, 253);
  doc.setDrawColor(222, 228, 238);
  doc.setLineWidth(1);
  doc.roundedRect(margin, y, contentWidth, metaCardHeight, 6, 6, 'FD');

  const col1LabelX = margin + 18;
  const col1ValX = margin + 104;
  const col2LabelX = margin + 276;
  const col2ValX = margin + 358;

  const cardStartY = y;
  const r1Y = cardStartY + 20;
  const r2Y = cardStartY + 41;
  const r3Y = cardStartY + 62;

  doc.setFontSize(8.5);

  // Row 1
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Audit Reference:', col1LabelX, r1Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text(scanId, col1ValX, r1Y);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Target Host:', col2LabelX, r1Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  const truncUrl = cleanUrl.length > 28 ? cleanUrl.substring(0, 26) + '...' : cleanUrl;
  doc.text(truncUrl, col2ValX, r1Y);

  // Row 2
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Audit Timestamp:', col1LabelX, r2Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text(`${dateStr} • ${timeStr}`, col1ValX, r2Y);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Assessing Unit:', col2LabelX, r2Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text('Perimeter Vulnerability Team', col2ValX, r2Y);

  // Row 3
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Inspection Type:', col1LabelX, r3Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text('HTTP Headers & Probing', col1ValX, r3Y);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(90, 102, 120);
  doc.text('Document Status:', col2LabelX, r3Y);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(20, 26, 38);
  doc.text('Confidential Technical Directive', col2ValX, r3Y);

  y += metaCardHeight + 24;

  // --- GRADE & POSTURE BANNER ---
  let statusBg = [255, 240, 240];
  let statusBorder = [240, 60, 80];
  let statusTextCol = [180, 20, 40];
  let gradeTitle = `SECURITY POSTURE: GRADE ${grade} (CRITICAL ATTENTION REQUIRED)`;

  if (['A', 'B'].includes(grade)) {
    statusBg = [238, 252, 246];
    statusBorder = [0, 180, 120];
    statusTextCol = [0, 130, 80];
    gradeTitle = `SECURITY POSTURE: GRADE ${grade} (HARDENED DEFENSE POSTURE)`;
  } else if (grade === 'C') {
    statusBg = [255, 250, 235];
    statusBorder = [230, 160, 20];
    statusTextCol = [170, 100, 0];
    gradeTitle = `SECURITY POSTURE: GRADE ${grade} (DEFENSIVE GAPS DETECTED)`;
  }

  doc.setFillColor(...statusBg);
  doc.setDrawColor(...statusBorder);
  doc.setLineWidth(1.2);
  doc.roundedRect(margin, y, contentWidth, 48, 4, 4, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...statusTextCol);
  doc.text(gradeTitle, margin + 14, y + 20);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(60, 70, 85);
  doc.text(`Verified Safe Controls: ${passed.length} Standards   |   Documented Vulnerabilities: ${issues.length} Deficiencies`, margin + 14, y + 36);

  y += 62;

  // --- SECTION 1: EXECUTIVE SUMMARY ---
  checkAddPage(70);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text('1. EXECUTIVE POSTURE EVALUATION', margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  let execText = '';
  if (['A', 'B'].includes(grade)) {
    execText = `A comprehensive perimeter security assessment was completed on ${fullDateStr} for target host ${cleanUrl}. The site demonstrates solid defensive configurations with core transport and browser protection controls effectively deployed. A few preventative recommendations are noted below to further solidify perimeter posture.`;
  } else if (grade === 'C') {
    execText = `A comprehensive perimeter security assessment was completed on ${fullDateStr} for target host ${cleanUrl}. The assessment revealed moderate configuration gaps in HTTP defense headers and browser hardening mechanisms. While no immediate system breach was observed, these omissions leave the application exposed to cross-site scripting and unauthorized framing.`;
  } else {
    execText = `A comprehensive perimeter security assessment was completed on ${fullDateStr} for target host ${cleanUrl}. The target exhibited critical security deficiencies and missing baseline defense mechanisms. Immediate administrative intervention is required to patch high-severity exposure points before production traffic continues.`;
  }

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(45, 55, 70);
  const splitExec = doc.splitTextToSize(execText, contentWidth);
  doc.text(splitExec, margin, y);
  y += splitExec.length * 13 + 14;

  // --- SECTION 2: VERIFIED SAFE CONTROLS ---
  checkAddPage(50);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text(`2. VERIFIED DEFENSIVE CONTROLS (${passed.length} PASSED)`, margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  if (passed.length > 0) {
    passed.forEach(chk => {
      checkAddPage(20);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(0, 160, 95);
      doc.text('[PASS]', margin + 4, y);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(40, 50, 65);
      const splitChk = doc.splitTextToSize(chk, contentWidth - 55);
      doc.text(splitChk, margin + 50, y);
      y += Math.max(splitChk.length * 13, 16) + 2;
    });
  } else {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(70, 80, 95);
    doc.text('No primary security headers were detected in compliant state.', margin, y);
    y += 18;
  }
  y += 10;

  // --- SECTION 3: VULNERABILITY FINDINGS ---
  checkAddPage(70);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text(`3. TECHNICAL VULNERABILITY FINDINGS & REMEDIATION (${issues.length} ISSUES)`, margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  if (issues.length > 0) {
    issues.forEach((issue, idx) => {
      checkAddPage(80);

      // Issue Card
      doc.setFillColor(250, 251, 254);
      doc.setDrawColor(220, 226, 238);
      doc.setLineWidth(0.75);

      const cardStartY = y;
      
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(20, 25, 35);
      doc.text(`Finding ${idx + 1}: ${issue.title}`, margin + 12, y + 16);

      // Severity badge
      const sevCol = issue.severity === 'HIGH' || issue.severity === 'CRITICAL' ? [200, 30, 40] : (issue.severity === 'LOW' ? [40, 120, 220] : [210, 140, 10]);
      doc.setFillColor(...sevCol);
      doc.roundedRect(margin + contentWidth - 75, y + 6, 65, 15, 2, 2, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(255, 255, 255);
      doc.text(`${issue.severity} RISK`, margin + contentWidth - 42, y + 17, { align: 'center' });

      y += 30;

      // Description
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(80, 90, 105);
      doc.text('Risk Description:', margin + 12, y);
      y += 12;

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(45, 55, 70);
      const splitDesc = doc.splitTextToSize(issue.description, contentWidth - 24);
      doc.text(splitDesc, margin + 12, y);
      y += splitDesc.length * 12 + 8;

      // Solution
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(0, 130, 80);
      doc.text('Remediation Directive:', margin + 12, y);
      y += 12;

      doc.setFont('courier', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(30, 35, 45);
      const splitSol = doc.splitTextToSize(issue.solution, contentWidth - 28);

      doc.setFillColor(242, 244, 249);
      doc.roundedRect(margin + 10, y - 8, contentWidth - 20, splitSol.length * 11 + 14, 3, 3, 'F');
      doc.text(splitSol, margin + 16, y + 4);
      y += splitSol.length * 11 + 18;

      // Card outline
      const cardHeight = y - cardStartY;
      doc.setDrawColor(220, 226, 238);
      doc.roundedRect(margin, cardStartY, contentWidth, cardHeight, 4, 4, 'D');

      y += 14;
    });
  } else {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(70, 80, 95);
    doc.text('No active vulnerabilities identified. System complies with baseline perimeter requirements.', margin, y);
    y += 18;
  }

  // --- SECTION 4: ROADMAP ---
  checkAddPage(75);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text('4. ENGINEERING REMEDIATION ROADMAP', margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  const planSteps = [
    'Immediately remediate all High and Critical risk findings noted in Section 3.',
    'Configure web server configurations (Nginx, Apache or Cloudflare) with modern security headers including Strict-Transport-Security and Content-Security-Policy.',
    'Ensure sensitive configuration files like .env and .git directories are strictly inaccessible over public HTTP endpoints.',
    'Schedule a recurring perimeter sweep following implementation to verify full remediation compliance.'
  ];

  planSteps.forEach((step, idx) => {
    checkAddPage(22);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(40, 50, 70);
    doc.text(`${idx + 1}.`, margin + 6, y);
    doc.setFont('helvetica', 'normal');
    const splitStep = doc.splitTextToSize(step, contentWidth - 24);
    doc.text(splitStep, margin + 22, y);
    y += Math.max(splitStep.length * 12, 14) + 3;
  });

  y += 14;

  // --- SECTION 5: SIGN-OFF ---
  checkAddPage(75);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(20, 25, 38);
  doc.text('5. AUDITOR SIGN-OFF & ATTESTATION', margin, y);
  doc.setDrawColor(210, 218, 230);
  doc.setLineWidth(0.75);
  doc.line(margin, y + 4, margin + contentWidth, y + 4);
  y += 18;

  doc.setFillColor(248, 250, 253);
  doc.roundedRect(margin, y, contentWidth, 54, 4, 4, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(70, 80, 100);
  doc.text('Audit Lead:', margin + 14, y + 18);
  doc.text('Department:', margin + 14, y + 36);

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(30, 35, 45);
  doc.text('Senior Application Security Engineer', margin + 105, y + 18);
  doc.text('Perimeter Defense & Vulnerability Management Operations', margin + 105, y + 36);

  // --- FOOTERS ON ALL PAGES ---
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(140, 150, 165);
    doc.setDrawColor(225, 230, 240);
    doc.setLineWidth(0.5);
    doc.line(margin, pageHeight - 30, margin + contentWidth, pageHeight - 30);
    doc.text('CyberShield Security Operations Center | Official Technical Audit Document', margin, pageHeight - 18);
    doc.text(`Page ${i} of ${totalPages}`, margin + contentWidth, pageHeight - 18, { align: 'right' });
  }

  let cleanDomain = 'site';
  try {
    const parsed = new URL(scanResult.url || targetUrl);
    cleanDomain = parsed.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  } catch (e) {
    cleanDomain = (targetUrl || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
  }
  const dateFile = now.toISOString().slice(0, 10);
  doc.save(`CyberShield_Site_Security_Report_${cleanDomain}_${dateFile}.pdf`);
  return doc;
}

/**
 * Text version for legacy plain-text fallback
 */
export function generateScamAuditReport(targetInput, result) {
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
  const auditId = getSecureAuditId('CS-AUD');
  const cleanInput = (targetInput || '').trim();
  const isUrl = cleanInput.startsWith('http') || (cleanInput.includes('.') && !cleanInput.includes(' '));
  const targetLabel = isUrl ? 'Uniform Resource Locator (URL)' : 'Communication Payload (SMS / Text Message)';
  const verdict = result.verdict || 'SUSPICIOUS';
  const score = result.scamProbability ?? 50;
  const urgency = result.urgencyLevel || 'HIGH';

  let executiveAssessment = verdict === 'SCAM' 
    ? `During the security audit conducted on ${dateStr}, the inspection desk confirmed high-risk malicious characteristics in the provided target. Immediate protective action is recommended.`
    : verdict === 'SUSPICIOUS'
    ? `During the security audit conducted on ${dateStr}, the inspection desk identified irregular behavioral markers. Users should exercise vigilance.`
    : `During the security audit conducted on ${dateStr}, the inspection desk observed no overt malicious patterns.`;

  const tactics = (result.manipulationTactics || []).map(t => cleanHumanText(t)).filter(t => t && !t.toLowerCase().includes('backend'));
  const redFlags = (result.redFlags || []).map(f => cleanHumanText(f)).filter(f => f && !f.toLowerCase().includes('backend'));
  const recommendation = cleanHumanText(result.recommendation) || 'Exercise caution and verify sender identity.';

  const divider = '='.repeat(80);
  const subDivider = '_'.repeat(80);

  let report = `${divider}\nCYBERSHIELD SECURITY OPERATIONS CENTER\nCOMMUNICATION SECURITY & HEURISTIC FRAUD AUDIT REPORT\n${divider}\n\n`;
  report += `Report Reference   : ${auditId}\nAssessment Subject : ${targetLabel}\nTarget Asset       : ${cleanInput}\nAudit Timestamp    : ${dateStr} at ${timeStr}\n\n`;
  report += `1. EXECUTIVE SUMMARY\n${subDivider}\n${executiveAssessment}\n\nThreat Probability: ${score}%\nVerdict: ${verdict}\nUrgency: ${urgency}\n\n`;
  report += `2. ANOMALIES & RED FLAGS\n${subDivider}\n` + (redFlags.map((f, i) => `  [${i+1}] ${f}`).join('\n') || 'None') + '\n\n';
  report += `3. OBSERVED TACTICS\n${subDivider}\n` + (tactics.map(t => `  * ${t}`).join('\n') || 'None') + '\n\n';
  report += `4. RECOMMENDATIONS\n${subDivider}\n${recommendation}\n\n${divider}\nEND OF REPORT - ${auditId}\n${divider}\n`;

  return report.replace(/--+/g, ' - ').replace(/,\s*and\b/gi, ' and').replace(/\band,\s*/gi, 'and ');
}

export function generateSiteSecurityReport(targetUrl, scanResult) {
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
  const scanId = getSecureAuditId('CS-SCAN');
  const cleanUrl = (targetUrl || scanResult.url || '').trim();
  const grade = scanResult.grade || 'C';
  const passed = (scanResult.passedChecks || []).map(p => cleanHumanText(p));
  const issues = (scanResult.issues || []).map(issue => ({
    title: cleanHumanText(issue.title),
    severity: issue.severity || 'MEDIUM',
    description: cleanHumanText(issue.description),
    solution: cleanHumanText(issue.solution)
  }));

  const divider = '='.repeat(80);
  const subDivider = '_'.repeat(80);

  let report = `${divider}\nCYBERSHIELD SECURITY OPERATIONS CENTER\nPERIMETER DEFENSE & VULNERABILITY AUDIT REPORT\n${divider}\n\n`;
  report += `Report Reference   : ${scanId}\nTarget Asset       : ${cleanUrl}\nAudit Timestamp    : ${dateStr} at ${timeStr}\n\n`;
  report += `1. EXECUTIVE EVALUATION\n${subDivider}\nSecurity Grade: ${grade}\nPassed Checks: ${passed.length}\nIssues: ${issues.length}\n\n`;
  report += `2. VERIFIED DEFENSIVE CONTROLS\n${subDivider}\n` + (passed.map((p, i) => `  [${i+1}] PASS: ${p}`).join('\n') || 'None') + '\n\n';
  report += `3. TECHNICAL VULNERABILITY FINDINGS\n${subDivider}\n` + (issues.map((it, i) => `Finding ${i+1}: ${it.title} [${it.severity}]\n${it.description}\nRemediation:\n${it.solution}\n`).join('\n') || 'None') + '\n\n';
  report += `${divider}\nEND OF REPORT - ${scanId}\n${divider}\n`;

  return report.replace(/--+/g, ' - ').replace(/,\s*and\b/gi, ' and').replace(/\band,\s*/gi, 'and ');
}

export function triggerReportDownload(filename, textContent) {
  const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function printReportContent(title, textContent) {
  const printWindow = window.open('', '_blank');
  if (!printWindow || !printWindow.document) return;
  
  const printDoc = printWindow.document;
  printDoc.title = String(title || 'CyberShield Audit Report');

  // Secure DOM construction without document.write or raw innerHTML injection (CR-XSS-001)
  const styleEl = printDoc.createElement('style');
  styleEl.textContent = `
    @page { margin: 20mm; }
    body {
      font-family: 'Courier New', Courier, monospace;
      font-size: 11pt;
      line-height: 1.45;
      color: #0b0b0f;
      background: #ffffff;
      padding: 24px;
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
    }
    @media print {
      body { padding: 0; }
    }
  `;
  if (printDoc.head) {
    printDoc.head.appendChild(styleEl);
  }

  const preEl = printDoc.createElement('pre');
  preEl.textContent = String(textContent || '');
  preEl.style.margin = '0';
  preEl.style.fontFamily = 'inherit';
  preEl.style.whiteSpace = 'pre-wrap';

  if (printDoc.body) {
    printDoc.body.innerHTML = '';
    printDoc.body.appendChild(preEl);
  }

  printWindow.focus();
  setTimeout(() => {
    try {
      printWindow.print();
    } catch (e) {
      console.warn('Print command cancelled or unsupported:', e);
    }
  }, 300);
}
