'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
const { redactSecrets } = require('./rules');

const ZN_DIR = path.join(os.homedir(), '.zn');
const EVIDENCE_FILE = path.join(ZN_DIR, 'evidence.jsonl');
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// The ledger directory is private to the user; modes are POSIX only (ignored on Windows).
const LEDGER_DIR_MODE = 0o700;
const LEDGER_FILE_MODE = 0o600;

function ensureZnDir(filePath = EVIDENCE_FILE) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: LEDGER_DIR_MODE });
  }
}

/**
 * Appends one line to the ledger. The file is created with mode 0600, and an
 * existing ledger that others can read or write is restricted to 0600 through
 * the open descriptor before the line is written (POSIX only), so a symlink
 * swapped in between cannot redirect the chmod.
 */
function appendLedgerLine(filePath, line) {
  const fd = fs.openSync(filePath, 'a', LEDGER_FILE_MODE);
  try {
    if (process.platform !== 'win32') {
      try {
        if ((fs.fstatSync(fd).mode & 0o077) !== 0) fs.fchmodSync(fd, LEDGER_FILE_MODE);
      } catch {
        // Best effort: a file system without POSIX modes keeps its own.
      }
    }
    fs.writeSync(fd, line, null, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Reads the last record's hash from the ledger.
 */
function getLastHash(filePath = EVIDENCE_FILE) {
  if (!fs.existsSync(filePath)) {
    return GENESIS_HASH;
  }
  try {
    const data = fs.readFileSync(filePath, 'utf8').trim();
    if (!data) return GENESIS_HASH;
    const lines = data.split('\n');
    const lastLine = lines[lines.length - 1];
    const parsed = JSON.parse(lastLine);
    return parsed.record_hash || GENESIS_HASH;
  } catch {
    return GENESIS_HASH;
  }
}

/**
 * Records a security event with cryptographic hash-chaining.
 *
 * @param {object} event - Event details (agent, phase, tool_name, payload, verdict, rule, reason, latency_us, engine)
 * @param {string} [filePath] - Optional ledger path
 * @returns {object} The recorded evidence record
 */
function logEvidence(event, filePath = EVIDENCE_FILE) {
  ensureZnDir(filePath);
  if (filePath === EVIDENCE_FILE) {
    require('./stats').record({
      layer: 'shield', agent: event.agent || event.agent_environment || 'other', checked: 1,
      blocked: String(event.verdict || '').toLowerCase() === 'block' ? 1 : 0,
    });
  }

  const prevHash = getLastHash(filePath);
  const timestamp = new Date().toISOString();
  const id = 'ev_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
  
  const payloadStr = typeof event.payload === 'string' ? event.payload : JSON.stringify(event.payload || '');
  const payloadSha256 = crypto.createHash('sha256').update(payloadStr).digest('hex');

  const baseRecord = {
    id,
    timestamp,
    agent_environment: event.agent || event.agent_environment || 'unknown',
    phase: event.phase || 'tool-call',
    tool_name: event.tool_name || event.tool || 'unknown',
    payload_sha256: payloadSha256,
    // Redact the full payload first, then cut, so a secret straddling the cut is not leaked.
    payload_preview: String(redactSecrets(payloadStr).sanitized || '').slice(0, 120),
    verdict: event.verdict || 'allow',
    rule: event.rule || null,
    reason: event.reason || null,
    confidence: event.confidence || 1.0,
    latency_us: event.latency_us || 0,
    engine: event.engine || 'oss-deterministic',
    prev_hash: prevHash,
  };

  // Compute record hash over prev_hash + canonical serialized content
  const recordHash = crypto
    .createHash('sha256')
    .update(prevHash + ':' + JSON.stringify(baseRecord))
    .digest('hex');

  const finalRecord = { ...baseRecord, record_hash: recordHash };

  appendLedgerLine(filePath, JSON.stringify(finalRecord) + '\n');
  return finalRecord;
}

/**
 * Verifies the cryptographic integrity of the entire evidence chain.
 *
 * @param {string} [filePath] - Optional ledger path
 * @returns {object} { valid: boolean, total: number, verified: number, broken_index: number|null, error: string|null }
 */
function verifyEvidenceLedger(filePath = EVIDENCE_FILE) {
  if (!fs.existsSync(filePath)) {
    return { valid: true, total: 0, verified: 0, broken_index: null, error: null };
  }

  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < lines.length; i++) {
    let rec;
    try {
      rec = JSON.parse(lines[i]);
    } catch (e) {
      return { valid: false, total: lines.length, verified: i, broken_index: i, error: `Malformed JSON at line ${i + 1}: ${e.message}` };
    }

    if (rec.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        total: lines.length,
        verified: i,
        broken_index: i,
        error: `Broken chain link at line ${i + 1} (record ${rec.id}): expected prev_hash ${expectedPrevHash.slice(0, 8)}... but found ${rec.prev_hash?.slice(0, 8)}...`
      };
    }

    const { record_hash, ...baseRecord } = rec;
    const computedHash = crypto
      .createHash('sha256')
      .update(expectedPrevHash + ':' + JSON.stringify(baseRecord))
      .digest('hex');

    if (computedHash !== record_hash) {
      return {
        valid: false,
        total: lines.length,
        verified: i,
        broken_index: i,
        error: `Tamper detected at line ${i + 1} (record ${rec.id}): hash mismatch. The content of this log was altered!`
      };
    }

    expectedPrevHash = record_hash;
  }

  return { valid: true, total: lines.length, verified: lines.length, broken_index: null, error: null };
}

/**
 * Generates aggregated metrics from the ledger.
 */
function getEvidenceStats(filePathOrLimit = EVIDENCE_FILE, maybeLimit = 50) {
  let filePath = EVIDENCE_FILE;
  let limit = 50;

  if (typeof filePathOrLimit === 'number') {
    limit = filePathOrLimit;
  } else if (typeof filePathOrLimit === 'string') {
    filePath = filePathOrLimit;
    if (typeof maybeLimit === 'number') limit = maybeLimit;
  }

  if (!fs.existsSync(filePath)) {
    return { total: 0, blocks: 0, blocked: 0, allows: 0, allowed: 0, shadows: 0, valid: true, top_rules: {}, top_tools: {}, recent: [] };
  }

  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  let blocked = 0;
  let allowed = 0;
  let shadows = 0;
  const topRules = {};
  const topTools = {};
  const recent = [];

  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const rec = JSON.parse(lines[i]);
      if (rec.verdict === 'shadow') {
        shadows++;
      } else if (rec.verdict === 'block') {
        blocked++;
        if (rec.rule) topRules[rec.rule] = (topRules[rec.rule] || 0) + 1;
      } else {
        allowed++;
      }
      if (rec.tool_name) topTools[rec.tool_name] = (topTools[rec.tool_name] || 0) + 1;
      if (recent.length < limit) {
        recent.push(rec);
      }
    } catch {}
  }

  const check = verifyEvidenceLedger(filePath);

  return {
    total: lines.length,
    blocks: blocked,
    blocked,
    allows: allowed,
    allowed,
    shadows,
    valid: check.valid,
    top_rules: topRules,
    top_tools: topTools,
    recent,
  };
}

/**
 * Exports the evidence ledger into JSONL or CSV with cryptographic verification.
 * Suitable for enterprise compliance audits (SOC 2, ISO 27001, EU AI Act Art. 12).
 *
 * @param {string} [filePath]
 * @param {('jsonl'|'csv')} [format='jsonl']
 * @returns {{ content: string, format: string, valid: boolean, tip_hash: string, total: number }}
 */
function exportEvidenceLedger(filePath = EVIDENCE_FILE, format = 'jsonl') {
  const normFormat = (format || 'jsonl').toLowerCase() === 'csv' ? 'csv' : 'jsonl';

  if (!fs.existsSync(filePath)) {
    return {
      content: normFormat === 'csv' ? 'timestamp,verdict,phase,tool_name,agent_environment,rule,reason,payload_sha256,record_hash,prev_hash,latency_us\n' : '',
      format: normFormat,
      valid: true,
      tip_hash: GENESIS_HASH,
      total: 0,
    };
  }

  const raw = fs.readFileSync(filePath, 'utf8');
  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
  const verifyResult = verifyEvidenceLedger(filePath);

  let tipHash = GENESIS_HASH;
  if (lines.length > 0) {
    try {
      tipHash = JSON.parse(lines[lines.length - 1]).record_hash || GENESIS_HASH;
    } catch {}
  }

  if (normFormat === 'csv') {
    const headers = [
      'timestamp',
      'verdict',
      'phase',
      'tool_name',
      'agent_environment',
      'rule',
      'reason',
      'payload_sha256',
      'record_hash',
      'prev_hash',
      'latency_us'
    ];
    const rows = [headers.join(',')];
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        const row = headers.map(h => {
          const val = obj[h] !== undefined && obj[h] !== null ? String(obj[h]) : '';
          return `"${val.replace(/"/g, '""')}"`;
        });
        rows.push(row.join(','));
      } catch {}
    }

    return {
      content: rows.join('\n') + '\n',
      format: 'csv',
      valid: verifyResult.valid,
      tip_hash: tipHash,
      total: lines.length,
    };
  }

  return {
    content: raw.endsWith('\n') ? raw : raw + '\n',
    format: 'jsonl',
    valid: verifyResult.valid,
    tip_hash: tipHash,
    total: lines.length,
  };
}

/**
 * Escapes a value for use in HTML text and double-quoted attributes.
 * Ledger fields come from tool calls and must never be interpreted as markup.
 * Serialized into the dashboard page, so it must stay self-contained.
 */
function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Renders one ledger record as a table row. Every field is escaped.
 * Serialized into the dashboard page, so it may only call escapeHtml.
 */
function renderAuditRow(r) {
  const verdict = String(r.verdict || 'allow');
  const tagClass = verdict === 'block' ? 'tag-block' : (verdict === 'shadow' ? 'tag-shadow' : 'tag-allow');
  const ruleCell = (r.rule || r.reason) ? escapeHtml(r.rule || r.reason) : '<span style="color:var(--muted);">-</span>';
  const sha = String(r.payload_sha256 || '');
  const latency = typeof r.latency_us === 'number' && r.latency_us ? r.latency_us + ' µs' : '< 1 ms';
  return '<tr>' +
    '<td class="mono">' + escapeHtml(String(r.timestamp || '').replace('T', ' ').slice(0, 19)) + '</td>' +
    '<td><span class="tag ' + tagClass + '">' + escapeHtml(verdict.toUpperCase()) + '</span></td>' +
    '<td><strong>' + escapeHtml(r.tool_name || 'call') + '</strong> <span style="color:var(--muted); font-size:0.8rem;">(' + escapeHtml(r.agent_environment || 'agent') + ')</span></td>' +
    '<td>' + ruleCell + '</td>' +
    '<td class="mono" title="' + escapeHtml(sha) + '">' + escapeHtml(sha.slice(0, 12)) + '...</td>' +
    '<td class="mono">' + escapeHtml(latency) + '</td>' +
  '</tr>';
}

/**
 * Starts a zero-dependency local dashboard at 127.0.0.1:<port> (loopback only)
 */
function startEvidenceUi(port = 3100, filePath = EVIDENCE_FILE) {
  const server = http.createServer((req, res) => {
    // Only answer requests addressed to the loopback name and port, so a web
    // page cannot reach the dashboard through DNS rebinding.
    const addr = server.address();
    const boundPort = addr && typeof addr === 'object' ? addr.port : port;
    const host = String(req.headers.host || '').toLowerCase();
    if (host !== `127.0.0.1:${boundPort}` && host !== `localhost:${boundPort}`) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }
    // 1. API: Aggregated stats
    if (req.url === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getEvidenceStats(filePath)));
      return;
    }

    // 2. API: Cryptographic verification
    if (req.url === '/api/verify') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(verifyEvidenceLedger(filePath)));
      return;
    }

    // 3. API: Compliance Audit Exporter (/api/export?format=jsonl|csv)
    if (req.url.startsWith('/api/export')) {
      const urlObj = new URL(req.url, `http://127.0.0.1:${port}`);
      const format = urlObj.searchParams.get('format') === 'csv' ? 'csv' : 'jsonl';
      const exportData = exportEvidenceLedger(filePath, format);

      const contentType = format === 'csv' ? 'text/csv; charset=utf-8' : 'application/x-ndjson; charset=utf-8';
      const filename = `zn-audit-ledger-${new Date().toISOString().slice(0, 10)}.${format}`;

      res.writeHead(200, {
        'Content-Type': contentType,
        'Content-Disposition': `attachment; filename="${filename}"`,
        'X-Evidence-Integrity': exportData.valid ? 'valid' : 'tampered',
        'X-Evidence-Tip-Hash': exportData.tip_hash,
        'X-Evidence-Total': String(exportData.total),
      });
      res.end(exportData.content);
      return;
    }

    // 4. Single-page dashboard HTML
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>zn Evidence Engine - Cryptographic AI Audit Ledger</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card: #151c2e;
      --border: #263554;
      --accent: #10b981;
      --danger: #ef4444;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --mono: 'JetBrains Mono', 'Fira Code', monospace;
    }
    body {
      margin: 0;
      padding: 2rem;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { margin: 0; font-size: 1.5rem; display: flex; align-items: center; gap: 0.75rem; }
    .header-actions { display: flex; align-items: center; gap: 0.75rem; }
    .btn-export {
      background: var(--card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.45rem 0.85rem;
      border-radius: 6px;
      font-size: 0.82rem;
      text-decoration: none;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      transition: all 0.2s ease;
    }
    .btn-export:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: var(--muted);
      color: #fff;
    }
    .status-badge { padding: 0.35rem 0.8rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; gap: 0.5rem; }
    .badge-valid { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-invalid { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
    .card h3 { margin: 0 0 0.5rem 0; font-size: 0.85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .metric { font-size: 2rem; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    th { background: rgba(255, 255, 255, 0.03); color: var(--muted); font-weight: 600; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .mono { font-family: var(--mono); font-size: 0.82rem; }
    .tag { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .tag-block { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
    .tag-allow { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }
    .tag-shadow { background: rgba(245, 158, 11, 0.2); color: #fcd34d; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1><span>🛡️</span> zn Evidence Engine Dashboard</h1>
      <div class="header-actions">
        <a href="/api/export?format=jsonl" download class="btn-export">⬇ Export JSONL</a>
        <a href="/api/export?format=csv" download class="btn-export">⬇ Export CSV</a>
        <div id="integrity-badge" class="status-badge badge-valid">● SHA-256 Ledger Verified</div>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <h3>Total Audit Events</h3>
        <div class="metric" id="m-total">-</div>
      </div>
      <div class="card">
        <h3>Threats Intercepted</h3>
        <div class="metric" style="color: var(--danger);" id="m-blocks">-</div>
      </div>
      <div class="card">
        <h3>Operations Allowed</h3>
        <div class="metric" style="color: var(--accent);" id="m-allows">-</div>
      </div>
      <div class="card">
        <h3>Shadow Alerts</h3>
        <div class="metric" style="color: #f59e0b;" id="m-shadows">-</div>
      </div>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
      <h2 style="margin: 0; font-size: 1.15rem;">Recent Security Records (SHA-256 Chained)</h2>
      <span style="color: var(--muted); font-size: 0.85rem;">Live polling every 3s</span>
    </div>

    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Verdict</th>
          <th>Tool & Environment</th>
          <th>Rule / Detail</th>
          <th>Payload Hash</th>
          <th>Latency</th>
        </tr>
      </thead>
      <tbody id="audit-table">
        <tr><td colspan="6" style="text-align:center; color: var(--muted); padding: 2rem;">Loading evidence ledger...</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    ${escapeHtml.toString()}
    ${renderAuditRow.toString()}
    async function fetchData() {
      try {
        const [statsRes, verifyRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/verify')
        ]);
        const d = await statsRes.json();
        const v = await verifyRes.json();

        document.getElementById('m-total').textContent = d.total || 0;
        document.getElementById('m-blocks').textContent = d.blocks || 0;
        document.getElementById('m-allows').textContent = d.allows || 0;
        document.getElementById('m-shadows').textContent = d.shadows || 0;

        const badge = document.getElementById('integrity-badge');
        if (v.valid) {
          badge.className = 'status-badge badge-valid';
          badge.textContent = '● SHA-256 Chain Verified (Tamper-Free)';
        } else {
          badge.className = 'status-badge badge-invalid';
          badge.textContent = '✖ TAMPER DETECTED at record ' + v.broken_index;
        }

        const tbody = document.getElementById('audit-table');
        if (!d.recent || d.recent.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--muted); padding: 2rem;">No evidence records logged yet. Run an MCP tool call to see live data.</td></tr>';
          return;
        }

        tbody.innerHTML = d.recent.map(renderAuditRow).join('');
      } catch (err) {
        console.error('Failed fetching data:', err);
      }
    }
    fetchData();
    setInterval(fetchData, 3000);
  </script>
</body>
</html>`);
  });

  // Loopback only: the ledger must not be reachable from the network.
  server.listen(port, '127.0.0.1', () => {
    process.stdout.write(`
🛡️  zn Evidence Engine Dashboard running at http://127.0.0.1:${server.address().port}
Ledger location: ${filePath}
Press Ctrl+C to stop dashboard.
\n`);
  });
  return server;
}

module.exports = {
  logEvidence,
  verifyEvidenceLedger,
  getEvidenceStats,
  exportEvidenceLedger,
  startEvidenceUi,
  escapeHtml,
  renderAuditRow,
  EVIDENCE_FILE,
  GENESIS_HASH,
};
