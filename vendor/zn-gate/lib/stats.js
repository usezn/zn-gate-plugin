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

/*
 * The .zn folder in the home directory of the operating-system account running this process, or null when the system
 * does not report one. Used for settings a project must not be able to redirect (the opt-in cloud check of tool output).
 * os.homedir() is not used here: it follows HOME (and USERPROFILE on Windows), which a project can set for the agent.
 * os.userInfo().homedir comes from the account itself: the passwd entry (getpwuid_r) on Linux and macOS, the profile
 * directory of the process token (GetUserProfileDirectoryW) on Windows. ZN_HOME is not read either. When os.userInfo()
 * throws (no passwd entry for the uid, as in some containers), the answer is null and callers treat it as "off".
 */
let realHomeForTests = null;
function userHome() {
  try {
    const home = realHomeForTests ? realHomeForTests() : os.userInfo().homedir;
    return typeof home === 'string' && home ? path.join(path.resolve(home), '.zn') : null;
  } catch (_) {
    return null;
  }
}

/** Tests only: a function returning the account home userHome() should use, or null to restore os.userInfo(). */
function _useRealHome(fn) { realHomeForTests = typeof fn === 'function' ? fn : null; }

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

/**
 * A stats file that cannot be read is replaced by a fresh one on the next write. Keep the first unreadable copy
 * next to it (stats.damaged.json) so the history is not lost without a trace. Best effort, never throws.
 */
function keepDamagedCopy(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
  try {
    const data = JSON.parse(text);
    if (data && typeof data === 'object' && typeof data.days === 'object') return;
  } catch { /* unreadable: keep a copy below */ }
  try {
    fs.copyFileSync(file, path.join(path.dirname(file), 'stats.damaged.json'), fs.constants.COPYFILE_EXCL);
  } catch { /* a copy is already there, or the folder is not writable */ }
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

const DAY_MS = 86400000;
// A day more than this far ahead of now was written under a wrong clock: it never counts and never moves the prune.
const FUTURE_SLACK_DAYS = 1;
// If now is further ahead of the newest stored day than this, the clock is not believed: nothing is pruned.
const IMPLAUSIBLE_GAP_DAYS = 400;

function isFutureDay(day, now) {
  return day > today(new Date(now.getTime() + FUTURE_SLACK_DAYS * DAY_MS));
}

/**
 * Drop days older than KEEP_DAYS. Future-dated days are ignored (kept, not counted), and when the clock is far
 * ahead of the newest real day nothing is deleted: history lost to a wrong clock cannot be restored.
 */
function prune(data, now = new Date()) {
  const todayKey = today(now);
  let newest = null;
  for (const day of Object.keys(data.days)) {
    if (day === todayKey || isFutureDay(day, now)) continue;
    if (!newest || day > newest) newest = day;
  }
  if (newest && now.getTime() - Date.parse(newest + 'T00:00:00Z') > IMPLAUSIBLE_GAP_DAYS * DAY_MS) return;
  const cutoff = today(new Date(now.getTime() - KEEP_DAYS * DAY_MS));
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
    keepDamagedCopy(file);
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
    if (entry.latencyMs !== undefined) pushLatency(data, entry.latencyMs);
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
    if (day < cutoff || isFutureDay(day, now)) continue;
    if (!first || day < first) first = day;
    for (const [key, c] of Object.entries(entries)) {
      const k = (byKey[key] ||= { checked: 0, blocked: 0, warned: 0, redacted: 0 });
      for (const f of Object.keys(total)) { total[f] += c[f] || 0; k[f] += c[f] || 0; }
      for (const [t, n] of Object.entries(c.detections || {})) detections[t] = (detections[t] || 0) + n;
    }
  }
  return { days, since: first, total, byKey, detections, events: { ...data.events } };
}

// Decision time per tool call: the last LATENCY_KEEP durations (ms, one decimal) of the hook decisions on pre and
// post tool events. It stops before the response is written and before stats and evidence are saved. Only numbers are kept: never a command, a prompt, a path or a name.
const LATENCY_KEEP = 100;
const LATENCY_MAX_MS = 60000;

function latencySamples(data) {
  const raw = data && data.latency && Array.isArray(data.latency.samples) ? data.latency.samples : [];
  return raw.map(Number).filter((v) => Number.isFinite(v) && v >= 0 && v <= LATENCY_MAX_MS);
}

function pushLatency(data, ms) {
  const v = Number(ms);
  if (!Number.isFinite(v) || v < 0) return;
  const samples = latencySamples(data);
  samples.push(Math.min(LATENCY_MAX_MS, Math.round(v * 10) / 10));
  data.latency = { samples: samples.slice(-LATENCY_KEEP) };
}

/** Nearest-rank percentile of an ascending array (p in 0..100). null for an empty array. */
function percentile(sorted, p) {
  if (!sorted.length) return null;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1];
}

/** { count, p50, p95 } over the last `last` stored durations, or null when there are none. */
function latencySummary({ file, last = LATENCY_KEEP } = {}) {
  const samples = latencySamples(load(file || statsFile())).slice(-last);
  if (!samples.length) return null;
  const sorted = [...samples].sort((a, b) => a - b);
  return { count: samples.length, p50: percentile(sorted, 50), p95: percentile(sorted, 95) };
}

/** The line `zn-gate check` / `doctor` prints. `off` is true when recording was turned off by ZN_STATS=off. */
function latencyReport({ file, off = false } = {}) {
  if (off) return 'Decision time per tool call: off (ZN_STATS=off), nothing is measured.';
  const s = latencySummary({ file });
  if (!s) return 'Decision time per tool call: no data yet. It is measured on each tool call your agent makes through zn.';
  const fmt = (v) => v.toFixed(1);
  return 'Decision time per tool call (last ' + s.count + ' calls, measured on this machine): p50 ' + fmt(s.p50) + ' ms, p95 ' + fmt(s.p95) + ' ms. Excludes process startup, writing the response, and saving stats and evidence.';
}

const TOP_RULES_DAYS = 7;
const TOP_RULES_LIMIT = 5;
const TOP_RULE_NAME = 'Built-in detector';

/**
 * The most frequent detector ids over the last `days` days (default 7): [{ id, name, count }], highest count first,
 * ties by id. Ids only, from the counts already stored; nothing new is recorded. `name` is always the generic
 * label 'Built-in detector' (the same as Python's GENERIC_RULE_NAME): detector ids never match rule-explanations.
 */
function topRules({ days = TOP_RULES_DAYS, limit = TOP_RULES_LIMIT, now = new Date(), file } = {}) {
  const s = summary({ days, now, file });
  return Object.entries(s.detections)
    .filter(([id, n]) => TYPE_RE.test(id) && Number.isFinite(n) && n > 0)
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, limit)
    .map(([id, count]) => ({ id, name: TOP_RULE_NAME, count }));
}

module.exports = { topRules, TOP_RULES_DAYS, znHome, userHome, _useRealHome, record, recordEvent, summary, load, statsFile, enabled, normType, normName, today, KEEP_DAYS, known,
  percentile, latencySummary, latencyReport, LATENCY_KEEP };
