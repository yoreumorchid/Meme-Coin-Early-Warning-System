/*
 * Meme-Coin Early Warning System – Frontend
 * ---------------------------------------------------
 * This is a presentation-ready frontend. It runs entirely
 * in the browser and currently uses a deterministic mock
 * to simulate the agent pipeline (MCP fetch → NetworkX
 * features → AST scan → CatBoost inference → weighted
 * synthesis). When the backend API is ready, replace the
 * `runAgentMock()` call inside `handleSubmit()` with a
 * real `fetch('/api/audit', ...)` call returning the same
 * report schema documented below.
 *
 * Report schema:
 * {
 *   address, chain, timestamp,
 *   riskScore: 0-100,
 *   mlProbability: 0-1,
 *   ast: [{severity:'high'|'med'|'low', pattern, detail}],
 *   graph: { degree_centrality, in_degree, out_degree,
 *            clustering, num_nodes, num_edges, betweenness },
 *   transactions: [{hash, from, to, value, time}],
 *   verdict: string
 * }
 */

const $ = (sel) => document.querySelector(sel);

const form = $('#auditForm');
const addressInput = $('#address');
const chainSelect = $('#chain');
const analyzeBtn = $('#analyzeBtn');
const pipelineEl = $('#pipeline');
const reportEl = $('#report');

// ---------- Sample chips ----------
document.querySelectorAll('.chip[data-sample]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const v = btn.dataset.sample.replace(/^0x/i, '');
    addressInput.value = v;
    addressInput.focus();
  });
});

// ---------- Export buttons ----------
let lastReport = null;
document.getElementById('exportPdfBtn').addEventListener('click', () => {
  if (!lastReport) return;
  // Set a useful default filename for "Save as PDF"
  const prevTitle = document.title;
  const shortAddr = lastReport.address.slice(0, 10) + '_' + lastReport.address.slice(-6);
  document.title = `RugPull_Audit_${shortAddr}_${lastReport.chain.toUpperCase()}`;
  document.body.classList.add('exporting');
  // Give the browser a tick to settle the gauge animation before printing
  setTimeout(() => {
    window.print();
    document.title = prevTitle;
    document.body.classList.remove('exporting');
  }, 200);
});
document.getElementById('exportJsonBtn').addEventListener('click', () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit_${lastReport.address}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

// ---------- Form submit ----------
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const raw = addressInput.value.trim();
  const address = raw.startsWith('0x') ? raw : '0x' + raw;
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    flashError('Invalid address: must be 40 hex chars (0x-prefixed).');
    return;
  }
  await handleSubmit(address, chainSelect.value);
});

function flashError(msg) {
  addressInput.style.borderColor = 'var(--red)';
  addressInput.parentElement.title = msg;
  setTimeout(() => {
    addressInput.style.borderColor = '';
    addressInput.parentElement.title = '';
  }, 2500);
}

// ---------- Main flow ----------
// Set USE_MOCK=true to force the offline demo without backend.
// Auto-detect: if we're served from http(s) (i.e. uvicorn), call the real API.
const USE_MOCK = !(location.protocol === 'http:' || location.protocol === 'https:');
const API_URL = '/api/audit';

async function handleSubmit(address, chain) {
  analyzeBtn.classList.add('loading');
  analyzeBtn.disabled = true;
  reportEl.hidden = true;
  pipelineEl.hidden = false;

  // animate pipeline steps
  const steps = pipelineEl.querySelectorAll('.step');
  steps.forEach((s) => s.classList.remove('active', 'done'));

  // Kick off the real API call in parallel with the animation when not mocking
  const apiPromise = USE_MOCK ? null : fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address, chain }),
  }).then(async (r) => {
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      throw new Error(`HTTP ${r.status}: ${text || r.statusText}`);
    }
    return r.json();
  });

  for (let i = 0; i < steps.length; i++) {
    steps[i].classList.add('active');
    await sleep(450 + Math.random() * 250);
    steps[i].classList.remove('active');
    steps[i].classList.add('done');
  }

  let report;
  try {
    report = USE_MOCK ? runAgentMock(address, chain) : await apiPromise;
  } catch (err) {
    console.error(err);
    alert(
      `Audit failed:\n${err.message}\n\n` +
      `Falling back to offline mock report.`,
    );
    report = runAgentMock(address, chain);
  }

  lastReport = report;
  renderReport(report);

  analyzeBtn.classList.remove('loading');
  analyzeBtn.disabled = false;
  reportEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- Deterministic mock agent ----------
function runAgentMock(address, chain) {
  // Seed from address so the same input always returns the same result
  const seed = hashSeed(address.toLowerCase());
  const rand = mulberry32(seed);

  // Flag "known fraud" sample addresses as high risk
  const knownFraud = address.toLowerCase().startsWith('0x00e25f0f')
    || address.toLowerCase().startsWith('0x010496d8');
  const knownLegit = address.toLowerCase() === '0xdac17f958d2ee523a2206206994597c13d831ec7';

  let mlProb;
  if (knownFraud)      mlProb = 0.88 + rand() * 0.10;
  else if (knownLegit) mlProb = 0.02 + rand() * 0.08;
  else                 mlProb = rand();

  const ast = generateAstFindings(rand, mlProb);
  const astWeight = ast.reduce((s, f) => s + (f.severity === 'high' ? 0.20 : f.severity === 'med' ? 0.08 : 0.02), 0);

  // Weighted synthesis: ML probability is dominant, AST adds offset
  const riskScore = Math.min(100, Math.round(mlProb * 75 + astWeight * 100));

  return {
    address,
    chain,
    timestamp: new Date().toISOString(),
    riskScore,
    mlProbability: mlProb,
    ast,
    graph: {
      'Nodes': Math.round(40 + rand() * 200),
      'Edges': Math.round(60 + rand() * 400),
      'Avg degree centrality': (0.05 + rand() * 0.35).toFixed(4),
      'Max in-degree': Math.round(5 + rand() * 60),
      'Max out-degree': Math.round(5 + rand() * 60),
      'Clustering coeff.': (rand() * 0.6).toFixed(4),
      'Betweenness (peak)': (rand() * 0.4).toFixed(4),
    },
    transactions: generateTxns(rand, address),
    verdict: buildVerdict(riskScore, mlProb, ast),
  };
}

function generateAstFindings(rand, mlProb) {
  const catalog = [
    { sev: 'high', pat: 'Hidden mint()', det: 'Owner-only function can inflate total supply post-launch.' },
    { sev: 'high', pat: 'Blacklist modifier', det: 'Owner can prevent specific addresses from selling.' },
    { sev: 'high', pat: 'Disable trading switch', det: '`tradingEnabled` flag toggled by owner; can freeze sells.' },
    { sev: 'med',  pat: 'Tax rate setter', det: 'Owner can raise transfer fee up to 100% at any time.' },
    { sev: 'med',  pat: 'Ownership not renounced', det: 'Contract owner retains privileged controls.' },
    { sev: 'med',  pat: 'Unverified external call', det: 'Low-level call to unverified contract address.' },
    { sev: 'low',  pat: 'Floating pragma', det: 'Pragma allows multiple compiler versions.' },
    { sev: 'low',  pat: 'Missing event emission', det: 'State change without event log.' },
  ];
  // Higher mlProb → more / severer findings
  const count = Math.max(1, Math.round(mlProb * 5 + rand() * 2));
  const picks = [];
  const pool = [...catalog];
  for (let i = 0; i < count && pool.length; i++) {
    const idx = Math.floor(rand() * pool.length);
    const f = pool.splice(idx, 1)[0];
    picks.push({ severity: f.sev, pattern: f.pat, detail: f.det });
  }
  picks.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  return picks;
}

const sevRank = (s) => ({ high: 3, med: 2, low: 1 }[s] || 0);

function generateTxns(rand, address) {
  const rows = [];
  for (let i = 0; i < 6; i++) {
    rows.push({
      hash: '0x' + randHex(rand, 64),
      from: i === 0 ? address : '0x' + randHex(rand, 40),
      to: i === 1 ? address : '0x' + randHex(rand, 40),
      value: (rand() * 12).toFixed(4),
      time: relTime(i),
    });
  }
  return rows;
}

function relTime(i) {
  const mins = [2, 7, 15, 38, 64, 122][i] || 200;
  return `${mins} min ago`;
}

function randHex(rand, len) {
  const chars = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(rand() * 16)];
  return s;
}

function buildVerdict(score, mlProb, ast) {
  const highCount = ast.filter((f) => f.severity === 'high').length;
  if (score >= 70) {
    return `HIGH RISK — Strong rug-pull signature detected. CatBoost reports ${(mlProb * 100).toFixed(1)}% fraud probability and the AST scan flagged ${highCount} critical vulnerability pattern(s). The agent recommends LP providers withdraw immediately and avoid any new deposits to this contract.`;
  }
  if (score >= 40) {
    return `MEDIUM RISK — Mixed signals. The forensic model shows elevated probability (${(mlProb * 100).toFixed(1)}%) and the contract contains owner-privileged operations. Treat with caution, monitor on-chain activity, and avoid concentrated exposure.`;
  }
  return `LOW RISK — No strong fraud signature detected. Model probability is ${(mlProb * 100).toFixed(1)}% and no critical AST pattern was triggered. This is not financial advice — continued on-chain monitoring is still recommended.`;
}

// ---------- Render ----------
function renderReport(r) {
  reportEl.hidden = false;
  $('#reportAddress').textContent = r.address;
  $('#reportChain').textContent = r.chain.toUpperCase();
  $('#reportTime').textContent = `Audited ${new Date(r.timestamp).toLocaleString()}`;

  // Gauge
  const score = r.riskScore;
  $('#riskScore').textContent = score;
  const label = score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MEDIUM RISK' : 'LOW RISK';
  const color = score >= 70 ? 'var(--error)' : score >= 40 ? 'var(--gold)' : 'var(--success)';
  $('#riskLabel').textContent = label;
  $('#riskLabel').style.color = color;
  const fill = $('#gaugeFill');
  const circumference = 2 * Math.PI * 52;
  fill.style.strokeDasharray = circumference;
  // start from full offset then animate
  fill.style.strokeDashoffset = circumference;
  fill.style.stroke = color;
  requestAnimationFrame(() => {
    fill.style.strokeDashoffset = circumference * (1 - score / 100);
  });

  // ML bar
  const pct = (r.mlProbability * 100).toFixed(1);
  $('#mlProb').textContent = `${pct}%`;
  $('#mlBar').style.width = '0%';
  requestAnimationFrame(() => { $('#mlBar').style.width = `${pct}%`; });

  // AST
  const astList = $('#astList');
  astList.innerHTML = '';
  if (!r.ast.length) {
    astList.innerHTML = '<li class="muted">No suspicious patterns detected.</li>';
  } else {
    r.ast.forEach((f) => {
      const li = document.createElement('li');
      li.innerHTML = `
        <span class="sev ${f.severity === 'high' ? 'high' : f.severity === 'med' ? 'med' : 'low'}">${f.severity.toUpperCase()}</span>
        <div><strong>${escapeHtml(f.pattern)}</strong><br><span class="muted small">${escapeHtml(f.detail)}</span></div>
      `;
      astList.appendChild(li);
    });
  }

  // Graph features
  const gf = $('#graphFeatures');
  gf.innerHTML = '';
  for (const [k, v] of Object.entries(r.graph)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td>`;
    gf.appendChild(tr);
  }

  // Transactions
  const tx = $('#txTable');
  tx.innerHTML = '';
  r.transactions.forEach((t) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${shorten(t.hash, 10, 6)}</td>
      <td>${shorten(t.from)}</td>
      <td>${shorten(t.to)}</td>
      <td class="right">${t.value}</td>
      <td>${escapeHtml(t.time)}</td>
    `;
    tx.appendChild(tr);
  });

  // Verdict
  $('#verdictText').textContent = r.verdict;
}

function shorten(s, head = 8, tail = 6) {
  if (!s) return '';
  return s.length > head + tail + 2 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- Seeded PRNG so the same address gives the same report ----------
function hashSeed(str) {
  let h = 1779033703 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  return (h >>> 0) || 1;
}
function mulberry32(a) {
  return function () {
    let t = (a += 0x6D2B79F5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
