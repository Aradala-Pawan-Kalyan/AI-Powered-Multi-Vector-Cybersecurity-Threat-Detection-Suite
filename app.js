/* ============================================================
   Sentinel — frontend logic
   Talks to the FastAPI backend at the same origin (/api/*).
   ============================================================ */

const DIAL_CIRCUMFERENCE = 2 * Math.PI * 82; // r=82 from the SVG

// ---------------- Tab navigation ----------------
const tabs = document.querySelectorAll('.tab');
const views = document.querySelectorAll('.view');
tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    views.forEach(v => v.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`view-${tab.dataset.tab}`).classList.add('active');

    if (tab.dataset.tab === 'dashboard') loadDashboard();
    if (tab.dataset.tab === 'history') loadHistory();
    if (tab.dataset.tab === 'about') loadImportance();
    if (tab.dataset.tab === 'files') loadFileHistory();
    if (tab.dataset.tab === 'email') loadEmailHistory();
    if (tab.dataset.tab === 'threats') { document.getElementById('threatTabDot').style.display = 'none'; loadThreats(); }
  });
});

// ---------------- API health check ----------------
async function checkHealth() {
  const dot = document.getElementById('apiDot');
  const text = document.getElementById('apiStatusText');
  try {
    const res = await fetch('/api/health');
    if (!res.ok) throw new Error('bad status');
    const data = await res.json();
    dot.classList.add('ok');
    text.textContent = `API online · ${data.model_features} features`;
  } catch (e) {
    dot.classList.add('err');
    text.textContent = 'API unreachable';
  }
}
checkHealth();

// ---------------- Single scan ----------------
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const scanBtnLabel = document.getElementById('scanBtnLabel');
const dialArc = document.getElementById('dialArc');
const dialValue = document.getElementById('dialValue');
const verdictBadge = document.getElementById('verdictBadge');
const reasonsBlock = document.getElementById('reasonsBlock');
const thresholdSlider = document.getElementById('thresholdSlider');
const thresholdValue = document.getElementById('thresholdValue');

thresholdSlider.addEventListener('input', () => {
  thresholdValue.textContent = parseFloat(thresholdSlider.value).toFixed(2);
});

document.querySelectorAll('.chip[data-example]').forEach(chip => {
  chip.addEventListener('click', () => {
    urlInput.value = chip.dataset.example;
    runScan();
  });
});

scanBtn.addEventListener('click', runScan);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') runScan(); });

function setDial(pct, isPhish) {
  const offset = DIAL_CIRCUMFERENCE - (pct / 100) * DIAL_CIRCUMFERENCE;
  dialArc.style.strokeDashoffset = offset;
  dialArc.style.stroke = isPhish ? 'var(--danger)' : 'var(--safe)';
  dialValue.textContent = `${pct}%`;
}

async function runScan() {
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }

  scanBtn.disabled = true;
  scanBtnLabel.textContent = 'Scanning…';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, threshold: parseFloat(thresholdSlider.value) }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Scan failed');
    const data = await res.json();

    const isPhish = data.prediction === 'Phishing';
    setDial(data.risk_score_pct, isPhish);
    verdictBadge.textContent = isPhish ? '⚠ Phishing detected' : '✓ Looks safe';
    verdictBadge.className = `verdict ${isPhish ? 'is-phish' : 'is-safe'}`;

    reasonsBlock.innerHTML = data.reasons.map(r => `
      <div class="reason-item"><span class="reason-marker">▸</span><span>${escapeHtml(r)}</span></div>
    `).join('');
  } catch (e) {
    verdictBadge.textContent = 'Error';
    verdictBadge.className = 'verdict is-phish';
    reasonsBlock.innerHTML = `<p class="empty-hint">${escapeHtml(e.message)}. Is the backend running?</p>`;
  } finally {
    scanBtn.disabled = false;
    scanBtnLabel.textContent = 'Scan URL';
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---------------- Batch scan ----------------
const batchTextarea = document.getElementById('batchTextarea');
const batchScanBtn = document.getElementById('batchScanBtn');
const batchSummary = document.getElementById('batchSummary');
const batchTableBody = document.querySelector('#batchTable tbody');
const downloadBatchCsv = document.getElementById('downloadBatchCsv');
const csvUpload = document.getElementById('csvUpload');
let lastBatchResults = [];

csvUpload.addEventListener('change', async () => {
  const file = csvUpload.files[0];
  if (!file) return;
  const text = await file.text();
  const lines = text.split(/\r?\n/).filter(Boolean);
  // find a "url" column if there's a header, else treat every line as a URL
  const header = lines[0].split(',').map(h => h.trim().toLowerCase());
  const urlColIdx = header.indexOf('url');
  let urls;
  if (urlColIdx !== -1) {
    urls = lines.slice(1).map(l => l.split(',')[urlColIdx]?.trim()).filter(Boolean);
  } else {
    urls = lines.map(l => l.trim()).filter(Boolean);
  }
  batchTextarea.value = urls.join('\n');
});

batchScanBtn.addEventListener('click', async () => {
  const urls = batchTextarea.value.split('\n').map(l => l.trim()).filter(Boolean);
  if (!urls.length) return;

  batchScanBtn.disabled = true;
  batchScanBtn.textContent = 'Scanning…';
  batchSummary.innerHTML = `<div class="empty-hint">Scanning ${urls.length} URLs…</div>`;

  try {
    const res = await fetch('/api/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls, threshold: parseFloat(thresholdSlider.value) }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Batch scan failed');
    const data = await res.json();
    lastBatchResults = data.results;

    batchSummary.innerHTML = `
      <div class="summary-row"><span>Total scanned</span><span class="val">${data.total}</span></div>
      <div class="summary-row"><span style="color:var(--danger)">Phishing</span><span class="val" style="color:var(--danger)">${data.phishing_count}</span></div>
      <div class="summary-row"><span style="color:var(--safe)">Safe</span><span class="val" style="color:var(--safe)">${data.safe_count}</span></div>
    `;

    batchTableBody.innerHTML = data.results.map(r => `
      <tr>
        <td class="url-cell" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</td>
        <td><span class="verdict-tag ${r.prediction === 'Phishing' ? 'phish' : 'safe'}">${r.prediction}</span></td>
        <td class="mono">${r.risk_score_pct}%</td>
        <td>${escapeHtml(r.reasons[0] || '')}</td>
      </tr>
    `).join('');

    downloadBatchCsv.style.display = 'inline-block';
  } catch (e) {
    batchSummary.innerHTML = `<div class="empty-hint">${escapeHtml(e.message)}</div>`;
  } finally {
    batchScanBtn.disabled = false;
    batchScanBtn.textContent = 'Scan all';
  }
});

downloadBatchCsv.addEventListener('click', () => {
  const rows = [['url', 'prediction', 'risk_score_pct', 'reasons']];
  lastBatchResults.forEach(r => rows.push([r.url, r.prediction, r.risk_score_pct, r.reasons.join(' | ')]));
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'phishing_scan_results.csv';
  link.click();
});

// ---------------- Dashboard ----------------
let pieChartInstance, timelineChartInstance;

async function loadDashboard() {
  const res = await fetch('/api/stats');
  const data = await res.json();

  document.getElementById('statTotal').textContent = data.total_scans;
  document.getElementById('statPhish').textContent = data.phishing_count;
  document.getElementById('statFiles').textContent = data.total_files;
  document.getElementById('statFilesFlagged').textContent = data.flagged_files;
  document.getElementById('statEmails').textContent = data.total_emails;
  document.getElementById('statEmailsFlagged').textContent = data.flagged_emails;
  document.getElementById('statThreats').textContent = data.total_threats;
  document.getElementById('statCritical').textContent = data.critical_threats;

  const pieCtx = document.getElementById('pieChart');
  if (pieChartInstance) pieChartInstance.destroy();
  pieChartInstance = new Chart(pieCtx, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Phishing'],
      datasets: [{ data: [data.safe_count, data.phishing_count], backgroundColor: ['#3FB98D', '#FF6B5B'], borderWidth: 0 }],
    },
    options: { plugins: { legend: { labels: { color: '#7E8BA3' } } } },
  });

  const recent = [...data.recent].reverse();
  const timelineCtx = document.getElementById('timelineChart');
  if (timelineChartInstance) timelineChartInstance.destroy();
  timelineChartInstance = new Chart(timelineCtx, {
    type: 'bar',
    data: {
      labels: recent.map((_, i) => i + 1),
      datasets: [{
        label: 'Phishing = 1 / Safe = 0',
        data: recent.map(r => (r.prediction === 'Phishing' ? 1 : 0)),
        backgroundColor: recent.map(r => (r.prediction === 'Phishing' ? '#FF6B5B' : '#3FB98D')),
      }],
    },
    options: {
      scales: {
        x: { display: false },
        y: { ticks: { stepSize: 1, color: '#7E8BA3' }, grid: { color: '#1A2436' } },
      },
      plugins: { legend: { display: false } },
    },
  });
}

// ---------------- History ----------------
async function loadHistory() {
  const res = await fetch('/api/history');
  const rows = await res.json();
  const tbody = document.querySelector('#historyTable tbody');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="mono">${escapeHtml(r.timestamp)}</td>
      <td class="url-cell" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</td>
      <td><span class="verdict-tag ${r.prediction === 'Phishing' ? 'phish' : 'safe'}">${r.prediction}</span></td>
      <td class="mono">${Math.round(r.phishing_probability * 100)}%</td>
      <td>${escapeHtml(r.reasons)}</td>
    </tr>
  `).join('') || '<tr><td colspan="5"><div class="empty-hint">No scans yet.</div></td></tr>';
}

document.getElementById('clearHistoryBtn').addEventListener('click', async () => {
  await fetch('/api/history', { method: 'DELETE' });
  loadHistory();
});

// ---------------- Files tab ----------------
const fileDrop = document.getElementById('fileDrop');
const fileInput = document.getElementById('fileInput');
const fileResult = document.getElementById('fileResult');

fileDrop.addEventListener('click', () => fileInput.click());
['dragover', 'dragleave', 'drop'].forEach(evt => {
  fileDrop.addEventListener(evt, e => {
    e.preventDefault();
    if (evt === 'dragover') fileDrop.classList.add('dragover');
    if (evt === 'dragleave' || evt === 'drop') fileDrop.classList.remove('dragover');
  });
});
fileDrop.addEventListener('drop', e => {
  const f = e.dataTransfer.files[0];
  if (f) scanFile(f);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) scanFile(fileInput.files[0]);
});

function verdictClass(v) {
  if (v === 'Malicious' || v === 'Phishing / Spam' || v === 'Phishing') return 'malicious';
  if (v === 'Suspicious') return 'suspicious';
  return 'safe';
}

async function scanFile(file) {
  fileResult.innerHTML = `<div class="empty-hint">Analyzing ${escapeHtml(file.name)}…</div>`;
  const formData = new FormData();
  formData.append('file', file);
  try {
    const res = await fetch('/api/scan-file', { method: 'POST', body: formData });
    if (!res.ok) throw new Error((await res.json()).detail || 'Scan failed');
    const data = await res.json();
    const vClass = verdictClass(data.verdict);
    const deep = data.deep_analysis;
    let deepPanel = '';
    if (deep) {
      if (deep.kind === 'pdf') {
        deepPanel = `<div class="deep-panel">
          <span class="deep-panel-title">PDF deep scan</span>
          <div class="deep-row">JavaScript: <b>${deep.details.has_javascript ? 'Yes' : 'No'}</b></div>
          <div class="deep-row">Auto-run action: <b>${deep.details.has_auto_action ? 'Yes' : 'No'}</b></div>
          <div class="deep-row">Launch action: <b>${deep.details.has_launch_action ? 'Yes' : 'No'}</b></div>
          <div class="deep-row">Embedded file: <b>${deep.details.has_embedded_file ? 'Yes' : 'No'}</b></div>
          <div class="deep-row">Encrypted: <b>${deep.details.is_encrypted ? 'Yes' : 'No'}</b></div>
          ${deep.details.uris.length ? `<div class="deep-row">Links: ${deep.details.uris.map(escapeHtml).join(', ')}</div>` : ''}
        </div>`;
      } else if (deep.kind === 'image') {
        deepPanel = `<div class="deep-panel">
          <span class="deep-panel-title">Image steganography scan</span>
          <div class="deep-row">Trailing bytes after end marker: <b>${deep.details.trailing_bytes}</b></div>
          ${deep.details.lsb_entropy !== null ? `<div class="deep-row">LSB entropy: <b>${deep.details.lsb_entropy}/1.0</b></div>` : ''}
        </div>`;
      } else if (deep.kind === 'apk') {
        deepPanel = `<div class="deep-panel">
          <span class="deep-panel-title">APK permission scan</span>
          <div class="deep-row">Manifest found: <b>${deep.details.has_manifest ? 'Yes' : 'No'}</b></div>
          <div class="deep-row">DEX files: <b>${deep.details.dex_count}</b></div>
          ${deep.details.permissions_found.length ? `<div class="deep-row">Sensitive permissions: ${deep.details.permissions_found.map(p => escapeHtml(p.split('.').pop())).join(', ')}</div>` : ''}
        </div>`;
      }
    }
    fileResult.innerHTML = `
      <div class="result-card">
        <div class="result-top">
          <span class="result-verdict ${vClass}">${escapeHtml(data.verdict)}</span>
          <span class="result-score">${data.risk_score}<span style="font-size:13px;color:var(--text-muted);">/100</span></span>
        </div>
        <div class="result-meta">${escapeHtml(data.filename)} · ${data.size_bytes.toLocaleString()} bytes · detected as ${escapeHtml(data.detected_type)}</div>
        <div class="result-meta" style="margin-bottom:14px;">SHA-256: ${data.sha256}</div>
        <div class="reasons-block">
          ${data.reasons.map(r => `<div class="reason-item"><span class="reason-marker">▸</span><span>${escapeHtml(r)}</span></div>`).join('')}
        </div>
        ${deepPanel}
      </div>`;
    loadFileHistory();
    if (data.verdict !== 'Likely Safe') flashThreatDot();
  } catch (e) {
    fileResult.innerHTML = `<div class="empty-hint">${escapeHtml(e.message)}</div>`;
  }
}

async function loadFileHistory() {
  const res = await fetch('/api/file-history?limit=50');
  const rows = await res.json();
  const tbody = document.querySelector('#fileHistoryTable tbody');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="mono">${escapeHtml(r.timestamp)}</td>
      <td>${escapeHtml(r.filename)}</td>
      <td><span class="verdict-tag ${r.verdict === 'Likely Safe' ? 'safe' : 'phish'}">${escapeHtml(r.verdict)}</span></td>
      <td class="mono">${r.risk_score}</td>
      <td class="mono url-cell" title="${r.sha256}">${r.sha256.slice(0, 16)}…</td>
    </tr>
  `).join('') || '<tr><td colspan="5"><div class="empty-hint">No files scanned yet.</div></td></tr>';
}

// ---------------- Email tab ----------------
const emailTextarea = document.getElementById('emailTextarea');
const emailScanBtn = document.getElementById('emailScanBtn');
const emailResult = document.getElementById('emailResult');

document.getElementById('emailExampleBtn').addEventListener('click', () => {
  emailTextarea.value = `From: PayPal Security <security@paypa1-alerts.xyz>
Reply-To: scammer@totally-different-domain.ru
Subject: URGENT: Your account has been suspended!!!

Dear Customer,

We noticed UNUSUAL ACTIVITY on your account. Your account has been suspended.
You must verify your account immediately by clicking the link below or it will be closed.

http://secure-login-paypal-verification.xyz/verify

Act now! This is your FINAL NOTICE.

Thank you,
PayPal Security Team`;
});

emailScanBtn.addEventListener('click', async () => {
  const content = emailTextarea.value.trim();
  if (!content) return;
  emailScanBtn.disabled = true;
  emailScanBtn.textContent = 'Analyzing…';
  emailResult.innerHTML = `<div class="empty-hint">Analyzing email…</div>`;

  try {
    const res = await fetch('/api/scan-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Analysis failed');
    const data = await res.json();
    const vClass = verdictClass(data.verdict);
    emailResult.innerHTML = `
      <div class="result-card">
        <div class="result-top">
          <span class="result-verdict ${vClass}">${escapeHtml(data.verdict)}</span>
          <span class="result-score">${data.risk_score}<span style="font-size:13px;color:var(--text-muted);">/100</span></span>
        </div>
        <div class="result-meta">Subject: ${escapeHtml(data.subject || '(none)')}</div>
        <div class="result-meta" style="margin-bottom:14px;">From: ${escapeHtml(data.from || '(none)')}</div>
        <div class="reasons-block">
          ${data.reasons.map(r => `<div class="reason-item"><span class="reason-marker">▸</span><span>${escapeHtml(r)}</span></div>`).join('')}
        </div>
        ${data.urls_found.length ? `<div style="margin-top:14px;"><strong style="font-size:13px;color:var(--text-muted);">Links found:</strong>
          ${data.urls_found.map(u => `<div class="reason-item"><span class="mono" style="font-size:12px;">${escapeHtml(u.url)}</span><span class="mono" style="margin-left:auto;color:var(--danger);">${u.heuristic_risk}%</span></div>`).join('')}
        </div>` : ''}
      </div>`;
    loadEmailHistory();
    if (data.verdict !== 'Likely Legitimate') flashThreatDot();
  } catch (e) {
    emailResult.innerHTML = `<div class="empty-hint">${escapeHtml(e.message)}</div>`;
  } finally {
    emailScanBtn.disabled = false;
    emailScanBtn.textContent = 'Analyze email';
  }
});

async function loadEmailHistory() {
  const res = await fetch('/api/email-history?limit=50');
  const rows = await res.json();
  const tbody = document.querySelector('#emailHistoryTable tbody');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="mono">${escapeHtml(r.timestamp)}</td>
      <td>${escapeHtml(r.subject || '(none)')}</td>
      <td class="url-cell">${escapeHtml(r.sender || '(none)')}</td>
      <td><span class="verdict-tag ${r.verdict === 'Likely Legitimate' ? 'safe' : 'phish'}">${escapeHtml(r.verdict)}</span></td>
      <td class="mono">${r.risk_score}</td>
    </tr>
  `).join('') || '<tr><td colspan="5"><div class="empty-hint">No emails analyzed yet.</div></td></tr>';
}

// ---------------- Threats / log analysis tab ----------------
const logTextarea = document.getElementById('logTextarea');
const logScanBtn = document.getElementById('logScanBtn');
const logSummary = document.getElementById('logSummary');
const logUpload = document.getElementById('logUpload');

document.getElementById('logExampleBtn').addEventListener('click', () => {
  logTextarea.value = `192.168.1.50 - - [12/Sep/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
45.33.22.11 - - [12/Sep/2026:10:00:05 +0000] "GET /admin' OR '1'='1 HTTP/1.1" 403 0 "-" "sqlmap/1.6"
45.33.22.11 - - [12/Sep/2026:10:00:06 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0 "-" "sqlmap/1.6"
77.88.99.10 - - [12/Sep/2026:10:00:10 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "Mozilla/5.0"
Sep 12 10:05:01 server sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 4444 ssh2
Sep 12 10:05:03 server sshd[123]: Failed password for invalid user root from 203.0.113.5 port 4445 ssh2
Sep 12 10:05:05 server sshd[123]: Failed password for invalid user test from 203.0.113.5 port 4446 ssh2
Sep 12 10:05:07 server sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 4447 ssh2
Sep 12 10:05:09 server sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 4448 ssh2
Sep 12 10:05:11 server sshd[124]: Accepted password for root from 203.0.113.5 port 4449 ssh2`;
});

logUpload.addEventListener('change', async () => {
  const f = logUpload.files[0];
  if (f) logTextarea.value = await f.text();
});

logScanBtn.addEventListener('click', async () => {
  const content = logTextarea.value.trim();
  if (!content) return;
  logScanBtn.disabled = true;
  logScanBtn.textContent = 'Analyzing…';
  logSummary.innerHTML = `<div class="empty-hint">Parsing log…</div>`;

  try {
    const formData = new FormData();
    formData.append('content', content);
    const res = await fetch('/api/analyze-log', { method: 'POST', body: formData });
    if (!res.ok) throw new Error((await res.json()).detail || 'Analysis failed');
    const data = await res.json();

    logSummary.innerHTML = `
      <div class="summary-row"><span>Lines parsed</span><span class="val">${data.total_lines}</span></div>
      <div class="summary-row"><span style="color:var(--danger)">Threat events</span><span class="val" style="color:var(--danger)">${data.total_events}</span></div>
      <div class="summary-row"><span>Flagged IPs</span><span class="val">${data.flagged_ip_count}</span></div>
    `;
    if (data.total_events > 0) flashThreatDot();
    loadThreats();
  } catch (e) {
    logSummary.innerHTML = `<div class="empty-hint">${escapeHtml(e.message)}</div>`;
  } finally {
    logScanBtn.disabled = false;
    logScanBtn.textContent = 'Analyze log';
  }
});

document.getElementById('clearThreatsBtn').addEventListener('click', async () => {
  await fetch('/api/threats', { method: 'DELETE' });
  loadThreats();
});

async function loadThreats() {
  const res = await fetch('/api/threats');
  const data = await res.json();
  const tbody = document.querySelector('#threatsTable tbody');
  tbody.innerHTML = data.events.map(e => `
    <tr>
      <td class="mono">${escapeHtml(e.timestamp)}</td>
      <td class="mono">${escapeHtml(e.source)}</td>
      <td class="mono">${escapeHtml(e.ip || '—')}</td>
      <td>${escapeHtml(e.type)}</td>
      <td><span class="severity-tag ${e.severity}">${e.severity}</span></td>
      <td>${escapeHtml(e.detail)}</td>
    </tr>
  `).join('') || '<tr><td colspan="6"><div class="empty-hint">No threats detected yet. Try analyzing a log, or upload a suspicious file/email.</div></td></tr>';
}

function flashThreatDot() {
  const dot = document.getElementById('threatTabDot');
  const activeTab = document.querySelector('.tab.active');
  if (activeTab && activeTab.dataset.tab !== 'threats') {
    dot.style.display = 'inline-block';
  }
}

// Poll the live threat feed periodically so self-monitoring events show up
// even if the person never uploads a log.
setInterval(async () => {
  const activeTab = document.querySelector('.tab.active');
  if (activeTab && activeTab.dataset.tab === 'threats') {
    loadThreats();
  } else {
    try {
      const res = await fetch('/api/threats?limit=1');
      const data = await res.json();
      if (data.events.length) flashThreatDot();
    } catch (e) { /* ignore */ }
  }
}, 15000);

// ---------------- Feature importance ----------------
let importanceChartInstance;
async function loadImportance() {
  const res = await fetch('/api/feature-importance');
  const data = await res.json();
  const ctx = document.getElementById('importanceChart');
  if (importanceChartInstance) importanceChartInstance.destroy();
  importanceChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d.feature),
      datasets: [{ data: data.map(d => d.importance), backgroundColor: '#4FD1C5' }],
    },
    options: {
      indexAxis: 'y',
      scales: {
        x: { ticks: { color: '#7E8BA3' }, grid: { color: '#1A2436' } },
        y: { ticks: { color: '#E8EDF4', font: { family: 'IBM Plex Mono', size: 11 } }, grid: { display: false } },
      },
      plugins: { legend: { display: false } },
    },
  });
}
