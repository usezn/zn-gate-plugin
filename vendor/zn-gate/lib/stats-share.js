'use strict';

/**
 * Opt-in sharing of pseudonymous daily counts (`zn-gate stats share on|off|status|show`).
 *
 * Off unless you turn it on. When on, `zn-gate stats` sends one report per complete day (at most the last
 * 3 days, which is what the server accepts) to https://api.usezn.com/v1/telemetry, after printing it.
 * A report holds a random installation id (rotated by `share off` then `share on`), the day, the zn-gate
 * version, the OS, the Node.js major version, the agent and layer used most that day, and the number of
 * detections per secret type. Never values, prompts, paths, file names, repository names, hosts or emails.
 * These are the only fields the server accepts (its /v1/telemetry schema).
 *
 * Settings live in ~/.zn/config.json under "stats": { "share": true, "install_id": "...", "sent_until": "YYYY-MM-DD" }.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const stats = require('./stats');

const ENDPOINT = 'https://api.usezn.com/v1/telemetry';
const MAX_TYPES = 100;
const LAYERS = new Set(['hook', 'shield', 'mcp', 'broker', 'cli']);
const MAX_DAYS_BACK = 3;
// Only known agent names are shared; anything else (a name passed on the command line, for example) is sent as "other".
const KNOWN_AGENTS = new Set(['claude-code', 'codex', 'cursor', 'opencode', 'mcp-client', 'mcp-server']);

function configFile() {
  return path.join(path.dirname(stats.statsFile()), 'config.json');
}

function readConfig() {
  try { return JSON.parse(fs.readFileSync(configFile(), 'utf8')) || {}; } catch { return {}; }
}

function writeConfig(cfg) {
  const file = configFile();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function status() {
  const s = readConfig().stats || {};
  return { share: s.share === true, install_id: s.share === true ? s.install_id || null : null, sent_until: s.sent_until || null };
}

function setShare(on) {
  const cfg = readConfig();
  const prev = cfg.stats || {};
  // A new random id each time sharing is turned on: turning it off and on again unlinks old reports.
  if (on && prev.share === true && prev.install_id) return status();
  cfg.stats = on
    ? { ...prev, share: true, install_id: crypto.randomUUID(), sent_until: stats.today() }
    : { ...prev, share: false, install_id: undefined };
  writeConfig(cfg);
  return status();
}

function osName() {
  const p = process.platform;
  return p === 'linux' || p === 'darwin' || p === 'win32' ? p : 'other';
}

function version() {
  try { return require('../package.json').version; } catch { return '0.0.0'; }
}

/** The reports that sharing would send now: complete days after sent_until, within the last 3 days. */
function pendingReports(now = new Date(), { preview = false } = {}) {
  const st = preview ? { share: true, install_id: '<random id>', sent_until: null } : status();
  if (!st.share || !st.install_id) return [];
  const data = stats.load();
  const today = stats.today(now);
  const oldest = stats.today(new Date(now.getTime() - MAX_DAYS_BACK * 86400000));
  const out = [];
  for (const day of Object.keys(data.days).sort()) {
    if (day >= today || day < oldest || (st.sent_until && day < st.sent_until)) continue;
    const entries = data.days[day] || {};
    let best = null;
    const detections = {};
    for (const [key, c] of Object.entries(entries)) {
      if (!best || (c.checked || 0) > (entries[best].checked || 0)) best = key;
      for (const [t, n] of Object.entries(c.detections || {})) {
        const v = Number(n);
        if (!Number.isFinite(v) || v <= 0) continue;
        const k = stats.normType(t);
        detections[k] = (detections[k] || 0) + Math.floor(v);
      }
    }
    if (!best) continue;
    const [rawLayer, rawAgent] = best.split(':');
    const layer = LAYERS.has(rawLayer) ? rawLayer : 'cli';
    const agent = KNOWN_AGENTS.has(rawAgent) ? rawAgent : 'other';
    const report = {
      install_id: st.install_id, day, zn_gate_version: version(), os: osName(),
      node_major: Number(process.versions.node.split('.')[0]), agent, layer,
    };
    const sorted = Object.entries(detections).sort((a, b) => b[1] - a[1]);
    const kept = Object.fromEntries(sorted.slice(0, MAX_TYPES - 1));
    const rest = sorted.slice(MAX_TYPES - 1).reduce((n, [, v]) => n + v, 0);
    if (rest) kept.OTHER = (kept.OTHER || 0) + rest;
    for (const k of Object.keys(kept)) kept[k] = Math.min(kept[k], 100000000);
    if (Object.keys(kept).length) report.detections = kept;
    out.push(report);
  }
  return out;
}

function post(report) {
  return new Promise((resolve) => {
    const body = JSON.stringify(report);
    const u = new URL(ENDPOINT);
    const req = https.request({
      method: 'POST', hostname: u.hostname, path: u.pathname, port: u.port || 443,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'user-agent': `zn-gate/${version()}` },
      timeout: 5000,
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode >= 200 && res.statusCode < 300)); });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end(body);
  });
}

/** Send the pending reports; sent_until moves past each day sent. Returns { sent, failed }. */
async function sendPending({ now = new Date(), print = () => {} } = {}) {
  const reports = pendingReports(now);
  let sent = 0;
  let failed = 0;
  for (const r of reports) {
    print(r);
    if (await post(r)) {
      sent++;
      const cfg = readConfig();
      cfg.stats = { ...(cfg.stats || {}), sent_until: stats.today(new Date(Date.parse(r.day + 'T00:00:00Z') + 86400000)) };
      writeConfig(cfg);
    } else {
      failed++;
    }
  }
  return { sent, failed };
}

module.exports = { status, setShare, pendingReports, sendPending, ENDPOINT };
