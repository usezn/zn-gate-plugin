'use strict';

/**
 * Local counts of what zn-gate did on this machine (`zn-gate stats`).
 *
 * ~/.zn/stats.json (0600; ZN_HOME overrides ~/.zn) holds counts only, per day and per layer and agent:
 * checks, blocked, warned, redacted and the number of detections per secret type (AWS_KEY, GITHUB_TOKEN...).
 * Never values, prompts, paths, file names, hosts or hashes of any of them. Nothing here is sent anywhere:
 * sharing pseudonymous counts is a separate, explicit opt-in (`zn-gate stats share on`, lib/stats-share.js).
 *
 * Recording is best effort and must never slow down or change a decision: every error is swallowed, and
 * concurrent writers may lose an increment (counts are approximate). ZN_STATS=off turns recording off.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const KEEP_DAYS = 90;
const TYPE_RE = /^[A-Z0-9](?:[A-Z0-9_]{0,62}[A-Z0-9])?$/;
const NAME_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const LAYERS = new Set(['hook', 'shield', 'mcp', 'broker', 'cli']);

function znHome() {
  if (process.env.ZN_HOME) return path.resolve(process.env.ZN_HOME);
  return path.join(os.homedir(), '.zn');
}

function statsFile() {
  return path.join(znHome(), 'stats.json');
}

function enabled() {
  return String(process.env.ZN_STATS || '').toLowerCase() !== 'off';
}

function today(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

// MCP rule ids that name the same secret as a scrubber type.
const TYPE_ALIASES = { AWS_ACCESS_KEY: 'AWS_KEY', AWS_SECRET_KEY: 'AWS_SECRET', DB_URL_PASSWORD: 'DB_PASSWORD', JWT_TOKEN: 'JWT' };
let knownTypes = null;

/** Built-in detector types only (scrubber secret and PII types, rule ids). Anything else is never stored. */
function known() {
  if (knownTypes) return knownTypes;
  knownTypes = new Set(['DB_PASSWORD', 'CREDENTIAL', 'SECRET', 'ENV_VALUE', 'OTHER']);
  try {
    const p = require('./scrub/patterns');
    for (const t of [...(p.SECRET_TYPES || []), ...(p.PII_TYPES || [])]) knownTypes.add(String(t).toUpperCase());
  } catch { /* scrubber missing: built-ins above */ }
  try {
    for (const r of require('./rules').SECRET_PATTERNS || []) knownTypes.add(String(r.id || '').replace(/^secret:/, '').toUpperCase());
  } catch { /* rules missing */ }
  return knownTypes;
}

/**
 * A detector type for the counts. Only built-in types are kept: a value matched by its variable name
 * (ENV_<NAME>) becomes ENV_VALUE, and any other name (a variable typed in a prompt, a secret's own name,
 * an organization's custom detector) becomes OTHER, so no name a user chose is stored or shared.
 */
function normType(t) {
  let s = String(t || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 64);
  s = TYPE_ALIASES[s] || s;
  if (s.startsWith('ENV_')) return 'ENV_VALUE';
  return TYPE_RE.test(s) && known().has(s) ? s : 'OTHER';
}

function normName(a) {
  const s = String(a || '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+/, '').slice(0, 32);
  return NAME_RE.test(s) ? s : 'other';
}

function empty() {
  return { version: 1, days: {}, events: {} };
}

function load(file = statsFile()) {
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!data || typeof data !== 'object' || typeof data.days !== 'object') return empty();
    if (typeof data.events !== 'object' || !data.events) data.events = {};
    return data;
  } catch {
    return empty();
  }
}

function save(data, file = statsFile()) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } finally {
    try { fs.unlinkSync(tmp); } catch { /* renamed: nothing left */ }
  }
}

function prune(data, now = new Date()) {
  const cutoff = today(new Date(now.getTime() - KEEP_DAYS * 86400000));
  for (const day of Object.keys(data.days)) if (day < cutoff) delete data.days[day];
}

/**
 * Add one entry: { layer, agent, checked, blocked, warned, redacted, detections: { TYPE: n } }.
 * Never throws.
 */
function record(entry, opts = {}) {
  if (!enabled() || !entry) return;
  try {
    const file = opts.file || statsFile();
    const now = opts.now || new Date();
    const data = load(file);
    const layer = LAYERS.has(entry.layer) ? entry.layer : 'cli';
    const key = `${layer}:${normName(entry.agent)}`;
    const day = (data.days[today(now)] ||= {});
    const c = (day[key] ||= { checked: 0, blocked: 0, warned: 0, redacted: 0, detections: {} });
    for (const f of ['checked', 'blocked', 'warned', 'redacted']) {
      const n = Number(entry[f] || 0);
      if (Number.isFinite(n) && n > 0) c[f] += Math.floor(n);
    }
    for (const [t, n] of Object.entries(entry.detections || {})) {
      const v = Number(n);
      if (!Number.isFinite(v) || v <= 0) continue;
      const k = normType(t);
      c.detections[k] = (c.detections[k] || 0) + Math.floor(v);
    }
    prune(data, now);
    save(data, file);
  } catch {
    /* best effort: never affect the caller */
  }
}

/** Count a local event that is not a check (for example a request for a planned feature). Never throws. */
function recordEvent(name, opts = {}) {
  if (!enabled()) return;
  try {
    const file = opts.file || statsFile();
    const data = load(file);
    const k = normName(name);
    data.events[k] = (data.events[k] || 0) + 1;
    save(data, file);
  } catch {
    /* best effort */
  }
}

/** Totals over the last `days` days (today included): overall, per layer:agent and per detection type. */
function summary({ days = 30, now = new Date(), file } = {}) {
  const data = load(file || statsFile());
  const cutoff = today(new Date(now.getTime() - (days - 1) * 86400000));
  const total = { checked: 0, blocked: 0, warned: 0, redacted: 0 };
  const byKey = {};
  const detections = {};
  let first = null;
  for (const [day, entries] of Object.entries(data.days)) {
    if (day < cutoff) continue;
    if (!first || day < first) first = day;
    for (const [key, c] of Object.entries(entries)) {
      const k = (byKey[key] ||= { checked: 0, blocked: 0, warned: 0, redacted: 0 });
      for (const f of Object.keys(total)) { total[f] += c[f] || 0; k[f] += c[f] || 0; }
      for (const [t, n] of Object.entries(c.detections || {})) detections[t] = (detections[t] || 0) + n;
    }
  }
  return { days, since: first, total, byKey, detections, events: { ...data.events } };
}

module.exports = { record, recordEvent, summary, load, statsFile, enabled, normType, normName, today, KEEP_DAYS, known };
