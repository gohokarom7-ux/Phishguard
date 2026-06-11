/* =====================================================
   PhishGuard — script.js
   AI-style phishing email analysis engine
   ===================================================== */

'use strict';

/* ---------- Keyword / Pattern Definitions ---------- */

const PHISHING_KEYWORDS = [
  { term: /urgent(ly)?/i,              label: 'Urgency language',       weight: 8  },
  { term: /verify\s+(your\s+)?account/i, label: 'Account verify prompt', weight: 12 },
  { term: /password/i,                 label: 'Password reference',      weight: 10 },
  { term: /click\s+here/i,             label: '"Click here" CTA',        weight: 9  },
  { term: /bank\s+account/i,           label: 'Bank account mention',    weight: 14 },
  { term: /login\s+immediately/i,      label: 'Forced login pressure',   weight: 15 },
  { term: /confirm\s+(your\s+)?identity/i, label: 'Identity confirm request', weight: 12 },
  { term: /suspend(ed|ion)?/i,         label: 'Account suspension threat', weight: 10 },
  { term: /update\s+(your\s+)?(billing|payment|card)/i, label: 'Payment update request', weight: 13 },
  { term: /act\s+now|immediate\s+action|action\s+required/i, label: 'Immediate action demand', weight: 11 },
  { term: /you\s+have\s+(won|been\s+selected)/i, label: 'Prize/winner claim', weight: 10 },
  { term: /free\s+(gift|prize|reward|money)/i, label: 'Free reward offer', weight: 8 },
  { term: /security\s+(alert|warning|breach)/i, label: 'Fake security alert', weight: 9 },
  { term: /\$\d+/,                     label: 'Monetary amount',         weight: 5  },
];

const LINK_PATTERNS = [
  { test: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, label: 'IP-based URL detected',    weight: 18, level: 'detected' },
  { test: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly/i, label: 'Shortened URL detected', weight: 14, level: 'detected' },
  { test: /https?:\/\/[a-z0-9\-]+\.(tk|ml|ga|cf|click|download|zip|review|country)/i, label: 'Suspicious TLD found', weight: 12, level: 'detected' },
  { test: /https?:\/\//i,              label: 'URL(s) present in email',  weight: 3,  level: 'warn'     },
  { test: /\.(exe|zip|rar|bat|cmd|js|vbs|ps1)\b/i, label: 'Dangerous file extension', weight: 20, level: 'detected' },
];

const SENDER_PATTERNS = [
  { test: /from:.*@(?!gmail|yahoo|outlook|hotmail|icloud|apple|microsoft|amazon|google|paypal|bank)[a-z0-9\-]+\.(com|net|org|io)/i, label: 'Unknown sender domain', weight: 8, level: 'warn'     },
  { test: /noreply|no-reply|donotreply/i, label: 'No-reply sender detected', weight: 4, level: 'warn' },
  { test: /from:.*paypal.*@(?!paypal\.com)/i, label: 'PayPal spoofing attempt', weight: 22, level: 'detected' },
  { test: /from:.*apple.*@(?!apple\.com)/i,   label: 'Apple spoofing attempt',  weight: 22, level: 'detected' },
  { test: /from:.*amazon.*@(?!amazon\.com)/i, label: 'Amazon spoofing attempt', weight: 22, level: 'detected' },
  { test: /from:.*microsoft.*@(?!microsoft\.com)/i, label: 'Microsoft spoofing', weight: 22, level: 'detected' },
  { test: /from:.*irs.*@(?!irs\.gov)/i,       label: 'IRS spoofing attempt',    weight: 25, level: 'detected' },
];

/* ---------- Recommendation Bank ---------- */

const RECO_POOL = {
  danger: [
    { icon: '🚫', text: 'Do not click any links in this email under any circumstances.' },
    { icon: '🗑️', text: 'Delete this email immediately and empty your trash folder.' },
    { icon: '📢', text: 'Report this email to your IT/security team or email provider.' },
    { icon: '🔐', text: 'If you clicked a link, change your passwords immediately and enable 2FA.' },
    { icon: '🏦', text: 'Contact your bank directly if financial information was requested.' },
    { icon: '🛡️', text: 'Run a full antivirus scan if any attachment was opened.' },
  ],
  warn: [
    { icon: '⚠️', text: 'Verify the sender via a separate channel before responding.' },
    { icon: '🔗', text: 'Do not click links — navigate to the website directly via browser.' },
    { icon: '📞', text: 'Call the organization directly to confirm this email is legitimate.' },
    { icon: '👁️', text: 'Check the reply-to address carefully for signs of spoofing.' },
    { icon: '📧', text: 'Forward to your email provider\'s abuse/spam reporting address.' },
  ],
  safe: [
    { icon: '✅', text: 'No immediate threats detected. Exercise standard caution.' },
    { icon: '🔍', text: 'Verify the sender if you were not expecting this email.' },
    { icon: '📎', text: 'Be cautious with any attachments, even from trusted senders.' },
    { icon: '🔔', text: 'Keep your email client and antivirus software up to date.' },
  ],
};

/* ---------- Utility Helpers ---------- */

/**
 * Animate a number from `start` to `end` over `duration`ms.
 */
function animateNumber(el, start, end, duration) {
  const startTime = performance.now();
  function step(now) {
    const elapsed = Math.min(now - startTime, duration);
    const progress = elapsed / duration;
    // ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (end - start) * eased);
    if (elapsed < duration) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/**
 * Return a risk descriptor object based on a 0–100 score.
 */
function getRiskLevel(score) {
  if (score >= 60) return { id: 'danger', label: 'Phishing Detected',  color: 'var(--red)',    barClass: 'bar-danger', riskClass: 'risk-danger', icon: '🚨' };
  if (score >= 30) return { id: 'warn',   label: 'Suspicious Email',   color: 'var(--yellow)', barClass: 'bar-warn',   riskClass: 'risk-warn',   icon: '⚠️' };
  return              { id: 'safe',   label: 'Email Appears Safe', color: 'var(--green)',  barClass: 'bar-safe',   riskClass: 'risk-safe',   icon: '✅' };
}

/**
 * Build risk label string + CSS class from sub-score.
 */
function subRiskLabel(score) {
  if (score >= 60) return { text: '⬤ High Risk',   cls: 'risk-danger' };
  if (score >= 25) return { text: '⬤ Medium Risk', cls: 'risk-warn'   };
  return                   { text: '⬤ Low Risk',   cls: 'risk-safe'   };
}

/* ---------- Core Analysis Engine ---------- */

function analyzeEmail() {
  const emailText = document.getElementById('emailInput').value.trim();
  if (!emailText) {
    shakeInput();
    return;
  }

  // UI: scanning state
  setScanningState(true);

  // Simulate async AI processing (UX beat)
  setTimeout(() => {
    const result = runAnalysis(emailText);
    renderResults(result);
    setScanningState(false);
  }, 1600);
}

function runAnalysis(text) {
  /* -- Content Analysis -- */
  const contentHits = PHISHING_KEYWORDS.filter(kw => kw.term.test(text));
  const contentScore = Math.min(100, contentHits.reduce((sum, kw) => sum + kw.weight, 0));

  const contentChecks = [
    buildCheck('Urgent / pressure language',    contentHits.some(k => /urgent|act now|immediate/i.test(k.label)), 'detected', 'clear'),
    buildCheck('Credential / password request', contentHits.some(k => /password|verify|confirm/i.test(k.label)),  'detected', 'clear'),
    buildCheck('Social engineering indicators', contentHits.some(k => /prize|won|selected|free/i.test(k.label)),  'detected', 'clear'),
    buildCheck('Monetary / financial lure',     contentHits.some(k => /bank|billing|payment|\$/i.test(k.label)),  'warn',     'clear'),
  ];

  /* -- Link Analysis -- */
  const linkHits = LINK_PATTERNS.filter(p => p.test.test(text));
  const linkScore = Math.min(100, linkHits.reduce((sum, p) => sum + p.weight, 0));

  const linkChecks = [
    buildCheckFromHit('Suspicious / malicious URLs', linkHits, ['IP-based', 'Suspicious TLD']),
    buildCheckFromHit('Shortened / redirect URLs',   linkHits, ['Shortened']),
    buildCheckFromHit('Dangerous file extension',    linkHits, ['Dangerous file']),
    buildCheck('URLs present in email', /https?:\/\//i.test(text), 'warn', 'clear'),
  ];

  /* -- Sender Analysis -- */
  const senderHits = SENDER_PATTERNS.filter(p => p.test.test(text));
  const senderScore = Math.min(100, senderHits.reduce((sum, p) => sum + p.weight, 0)
    + (text.length < 50 ? 10 : 0));   // very short = no sender info

  const spoofed = senderHits.some(h => /spoofing/i.test(h.label));
  const trustScore = spoofed ? 'Low' : senderScore > 20 ? 'Medium' : 'High';

  const senderChecks = [
    buildCheck('Unknown / unrecognized sender', senderHits.length > 0 && !spoofed, 'warn', 'clear'),
    buildCheck('Brand spoofing indicators',     spoofed, 'detected', 'clear'),
    { label: `Trust score: ${trustScore}`, level: trustScore === 'High' ? 'clear' : trustScore === 'Medium' ? 'warn' : 'detected' },
  ];

  /* -- Overall Score -- */
  const rawScore = Math.round(contentScore * 0.45 + linkScore * 0.35 + senderScore * 0.20);
  const riskScore = Math.min(99, Math.max(0, rawScore));

  /* -- Keyword hit summary for verdict indicators -- */
  const indicators = contentHits.slice(0, 4).map(k => k.label);

  /* -- Recommendations -- */
  const riskLevel = getRiskLevel(riskScore);
  const recoSet = RECO_POOL[riskLevel.id];

  return {
    riskScore,
    riskLevel,
    indicators,
    content: { score: contentScore, checks: contentChecks },
    link:    { score: linkScore,    checks: linkChecks    },
    sender:  { score: senderScore,  checks: senderChecks  },
    recommendations: recoSet,
  };
}

/* -- Check builders -- */
function buildCheck(label, detected, detectedLevel, clearLevel) {
  return { label, level: detected ? detectedLevel : clearLevel };
}

function buildCheckFromHit(label, hits, keywords) {
  const hit = hits.find(h => keywords.some(k => h.label.includes(k)));
  return { label, level: hit ? hit.level : 'clear' };
}

/* ---------- Render Results ---------- */

function renderResults(result) {
  /* Score */
  const scoreEl = document.getElementById('scoreNumber');
  animateNumber(scoreEl, 0, result.riskScore, 900);
  scoreEl.style.color = result.riskLevel.color;
  scoreEl.style.textShadow = `0 0 24px ${result.riskLevel.color}`;

  /* Risk bar */
  const barFill = document.getElementById('riskBarFill');
  const barWrap = document.getElementById('riskBarWrap');
  barWrap.setAttribute('aria-valuenow', result.riskScore);
  barFill.className = `risk-bar-fill ${result.riskLevel.barClass}`;
  setTimeout(() => { barFill.style.width = result.riskScore + '%'; }, 100);

  /* Verdict */
  document.getElementById('verdictIcon').textContent  = result.riskLevel.icon;
  const verdictLabel = document.getElementById('verdictLabel');
  verdictLabel.textContent  = result.riskLevel.label;
  verdictLabel.className    = `verdict-label ${result.riskLevel.riskClass}`;

  const verdictDescs = {
    danger: 'Multiple high-confidence phishing signals detected. This email is almost certainly malicious.',
    warn:   'Several suspicious patterns found. Treat with caution and do not interact before verifying.',
    safe:   'No major threats detected. Standard email hygiene is still recommended.',
  };
  document.getElementById('verdictDesc').textContent = verdictDescs[result.riskLevel.id];

  const indicatorsEl = document.getElementById('verdictIndicators');
  indicatorsEl.innerHTML = '';
  result.indicators.forEach(ind => {
    const pill = document.createElement('span');
    pill.className = `indicator-pill ${result.riskLevel.riskClass}`;
    pill.style.borderColor = result.riskLevel.color;
    pill.textContent = ind;
    indicatorsEl.appendChild(pill);
  });

  /* Sub-analysis */
  renderSubAnalysis('content', result.content);
  renderSubAnalysis('link',    result.link   );
  renderSubAnalysis('sender',  result.sender );

  /* Recommendations */
  const recoList = document.getElementById('recoList');
  recoList.innerHTML = '';
  result.recommendations.forEach((reco, i) => {
    const li = document.createElement('li');
    li.className = 'reco-item';
    li.style.animationDelay = `${i * 60}ms`;
    li.innerHTML = `<span class="reco-icon" aria-hidden="true">${reco.icon}</span><span>${reco.text}</span>`;
    recoList.appendChild(li);
  });

  /* Show results section */
  const section = document.getElementById('resultsSection');
  section.classList.add('visible');
  setTimeout(() => section.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200);
}

function renderSubAnalysis(type, data) {
  const riskInfo = subRiskLabel(data.score);
  const riskLabel = document.getElementById(`${type}Risk`);
  riskLabel.textContent  = riskInfo.text;
  riskLabel.className    = `analysis-risk-label ${riskInfo.cls}`;

  const list = document.getElementById(`${type}Checks`);
  list.innerHTML = '';
  data.checks.forEach((check, i) => {
    const li = document.createElement('li');
    li.className = `check-item ${check.level}`;
    li.style.animationDelay = `${i * 50}ms`;
    li.innerHTML = `<span class="check-dot"></span><span>${check.label}</span>`;
    list.appendChild(li);
  });
}

/* ---------- UX Helpers ---------- */

function setScanningState(active) {
  const btn      = document.getElementById('analyzeBtn');
  const scanLine = document.getElementById('scanLine');
  const input    = document.getElementById('emailInput');

  if (active) {
    btn.disabled = true;
    btn.textContent = 'Scanning…';
    btn.classList.add('scanning-state');
    scanLine.classList.remove('scanning');
    void scanLine.offsetWidth;              // force reflow to restart animation
    scanLine.classList.add('scanning');
    input.style.opacity = '0.6';
  } else {
    btn.disabled = false;
    btn.innerHTML = `
      <svg class="btn-icon" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <circle cx="9" cy="9" r="6" stroke="currentColor" stroke-width="1.8"/>
        <path d="M15 15L19 19" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <path d="M9 6V12M6 9H12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      Analyze Email`;
    btn.classList.remove('scanning-state');
    input.style.opacity = '1';
  }
}

function shakeInput() {
  const input = document.getElementById('emailInput');
  input.style.animation = 'none';
  void input.offsetWidth;
  input.style.animation = 'shake 0.4s ease';
  input.focus();
  setTimeout(() => { input.style.animation = ''; }, 450);
}

function clearAll() {
  document.getElementById('emailInput').value = '';
  document.getElementById('charCount').textContent = '0 characters';
  const section = document.getElementById('resultsSection');
  section.classList.remove('visible');
}

/* ---------- Character Counter ---------- */

document.getElementById('emailInput').addEventListener('input', function () {
  const len = this.value.length;
  document.getElementById('charCount').textContent =
    len === 0 ? '0 characters' : `${len.toLocaleString()} character${len !== 1 ? 's' : ''}`;
});

/* ---------- Shake keyframe (injected once) ---------- */

(function injectShakeKeyframe() {
  const style = document.createElement('style');
  style.textContent = `
    @keyframes shake {
      0%,100% { transform: translateX(0); }
      20%      { transform: translateX(-6px); }
      40%      { transform: translateX(6px); }
      60%      { transform: translateX(-4px); }
      80%      { transform: translateX(4px); }
    }
  `;
  document.head.appendChild(style);
})();