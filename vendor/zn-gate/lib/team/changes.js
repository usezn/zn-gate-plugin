'use strict';
/**
 * What a new organization policy removes or loosens on this machine.
 *
 * A signed policy can lift a restriction the previous one had (an admin
 * unblocks a secret, widens a host list, drops a custom detector). Nothing
 * on the machine can tell a change the organization meant from one it did
 * not, so zn-gate does not refuse it: it shows the person what was lifted
 * (`zn team status`, one line in the agent's next hook message) and writes
 * an audit record. See docs/team.md ("When the organization lifts a
 * restriction").
 *
 * restrictionChanges(oldPolicy, newPolicy) is pure. The result is stored in
 * the vault and mirrored (without the token) in the readable copy, so
 * everything read back from a file goes through cleanChange() first: only
 * values of a closed set of shapes survive, because the hooks show a line
 * built from it.
 */

const fs = require('fs');
const path = require('path');
const { secretMatches, hostCovered } = require('./effective');

const RESTRICTIVE_MODE = 'proxy';
const MAX_ITEMS = 20;
const MAX_VALUES = 5;
const SECRET_PATTERN_RE = /^(?:\*|[A-Z][A-Z0-9_]{0,63}|[A-Z][A-Z0-9_]{0,62}\*)$/;
const HOST_RE = /^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*$/;
const COMMAND_RE = /^[A-Za-z0-9_.+\-/ *]{1,128}$/;
const DETECTOR_ID_RE = /^[a-z0-9_]{1,64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const PLACEMENTS = ['header', 'query', 'body'];

const rulesOf = (policy) => ((policy && Array.isArray(policy.rules)) ? policy.rules : []);
const hasPort = (h) => /:\d+$/.test(String(h));
const coveredCommand = (list, c) => list.some((l) => c === l || c.startsWith(l + ' '));

/* What the matching rules of `policy` restrict for a secret called `probe`
 * (null: no rule limits it), combined like effective() does. */
function summaryOf(policy, probe) {
  const s = { deny: false, warn: false, proxy: false, hosts: null, commands: null, placements: null };
  for (const r of rulesOf(policy)) {
    if (!secretMatches(r.secret, probe)) continue;
    if (r.deny === true) s.deny = true;
    if (r.warn === true) s.warn = true;
    if (r.mode === RESTRICTIVE_MODE) s.proxy = true;
    if (Array.isArray(r.allowHosts)) {
      // A host with a port is never matched by the broker: it only restricts.
      const own = r.allowHosts.filter((h) => !hasPort(h));
      s.hosts = s.hosts === null ? own : own.filter((h) => hostCovered(s.hosts, h));
    }
    if (Array.isArray(r.allowCommands)) {
      s.commands = s.commands === null ? r.allowCommands.slice() : r.allowCommands.filter((c) => coveredCommand(s.commands, c));
    }
    if (r.injectAt !== undefined) s.placements = s.placements === null ? [r.injectAt] : s.placements.filter((p) => p === r.injectAt);
  }
  return s;
}

function widened(before, after, covered) {
  if (before === null) return null; // nothing was limited before: nothing can be lifted
  if (after === null) return { limit_removed: true, added: [] };
  const added = after.filter((v) => !covered(before, v));
  return added.length ? { limit_removed: false, added } : null;
}

/**
 * restrictionChanges(oldPolicy, newPolicy) -> {items, more}
 * items: [{kind, secret?, values?}] (at most MAX_ITEMS), more: how many were left out.
 * Kinds: block_removed, warn_removed, proxy_removed, hosts_unlimited,
 * hosts_widened, commands_unlimited, commands_widened, placement_unlimited,
 * placement_widened, detector_removed.
 */
function restrictionChanges(oldPolicy, newPolicy) {
  const all = [];
  const probes = new Set();
  for (const r of rulesOf(oldPolicy)) probes.add(r.secret);
  for (const r of rulesOf(newPolicy)) probes.add(r.secret);
  for (const secret of [...probes].sort()) {
    const a = summaryOf(oldPolicy, secret);
    const b = summaryOf(newPolicy, secret);
    if (a.deny && !b.deny) all.push({ kind: 'block_removed', secret });
    if (a.warn && !a.deny && !b.warn && !b.deny) all.push({ kind: 'warn_removed', secret });
    if (a.proxy && !b.proxy) all.push({ kind: 'proxy_removed', secret });
    const h = widened(a.hosts, b.hosts, hostCovered);
    if (h) all.push(h.limit_removed ? { kind: 'hosts_unlimited', secret } : { kind: 'hosts_widened', secret, values: h.added });
    const c = widened(a.commands, b.commands, coveredCommand);
    if (c) all.push(c.limit_removed ? { kind: 'commands_unlimited', secret } : { kind: 'commands_widened', secret, values: c.added });
    const p = widened(a.placements, b.placements, (list, v) => list.includes(v));
    if (p) all.push(p.limit_removed ? { kind: 'placement_unlimited', secret } : { kind: 'placement_widened', secret, values: p.added });
  }
  const kept = new Set(((newPolicy && newPolicy.detectors) || []).map((d) => d.id));
  for (const d of (oldPolicy && oldPolicy.detectors) || []) {
    if (!kept.has(d.id)) all.push({ kind: 'detector_removed', values: [d.id] });
  }
  const items = all.slice(0, MAX_ITEMS).map((i) => (i.values ? Object.assign({}, i, { values: i.values.slice(0, MAX_VALUES) }) : i));
  return { items, more: all.length - items.length };
}

/** The record kept for a change: {from, to, at, count, items, more}, or null when nothing was lifted. */
function changeRecord(oldPolicy, newPolicy, at) {
  if (!oldPolicy || !newPolicy) return null;
  const r = restrictionChanges(oldPolicy, newPolicy);
  if (!r.items.length) return null;
  return { from: oldPolicy.version, to: newPolicy.version, at: at || new Date().toISOString(), count: r.items.length + r.more, items: r.items, more: r.more };
}

const VALUE_CHECK = {
  hosts_widened: (v) => HOST_RE.test(v) && v.length <= 253,
  commands_widened: (v) => COMMAND_RE.test(v),
  placement_widened: (v) => PLACEMENTS.includes(v),
  detector_removed: (v) => DETECTOR_ID_RE.test(v),
};
const NO_SECRET = new Set(['detector_removed']);
const KINDS = new Set([
  'block_removed', 'warn_removed', 'proxy_removed', 'hosts_unlimited', 'hosts_widened', 'commands_unlimited',
  'commands_widened', 'placement_unlimited', 'placement_widened', 'detector_removed',
]);

/**
 * cleanChange(raw) -> a change record made only of values of the expected
 * shapes, or null. Used for everything read from a file or from the daemon.
 */
function cleanChange(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const int = (n) => Number.isSafeInteger(n) && n >= 0 && n < 1e9;
  if (!int(raw.from) || !int(raw.to) || typeof raw.at !== 'string' || !ISO_RE.test(raw.at) || !Array.isArray(raw.items)) return null;
  const items = [];
  for (const i of raw.items.slice(0, MAX_ITEMS)) {
    if (!i || typeof i !== 'object' || !KINDS.has(i.kind)) continue;
    const out = { kind: i.kind };
    if (!NO_SECRET.has(i.kind)) {
      if (typeof i.secret !== 'string' || !SECRET_PATTERN_RE.test(i.secret)) continue;
      out.secret = i.secret;
    }
    const check = VALUE_CHECK[i.kind];
    if (check) {
      const values = Array.isArray(i.values) ? i.values.slice(0, MAX_VALUES).filter((v) => typeof v === 'string' && check(v)) : [];
      if (!values.length) continue;
      out.values = values;
    }
    items.push(out);
  }
  const count = int(raw.count) ? raw.count : items.length;
  return { from: raw.from, to: raw.to, at: raw.at, count: Math.max(count, items.length), items, more: Math.max(0, Math.max(count, items.length) - items.length) };
}

const SECRET_WORDS = {
  block_removed: 'is no longer blocked',
  warn_removed: 'no longer warns',
  proxy_removed: 'no longer has to use proxy mode',
  hosts_unlimited: 'is no longer limited to a list of hosts',
  commands_unlimited: 'is no longer limited to a list of commands',
  placement_unlimited: 'is no longer limited in where it can be put in an HTTP request',
};

/** One printable line for a change item. */
function describeItem(i) {
  const who = i.secret === '*' ? 'every secret' : 'secret ' + i.secret;
  if (SECRET_WORDS[i.kind]) return who + ' ' + SECRET_WORDS[i.kind];
  if (i.kind === 'hosts_widened') return who + ' may now go to more hosts: ' + i.values.join(', ');
  if (i.kind === 'commands_widened') return who + ' may now be used with more commands: ' + i.values.join(', ');
  if (i.kind === 'placement_widened') return who + ' may now be put in more places in an HTTP request: ' + i.values.join(', ');
  if (i.kind === 'detector_removed') return 'custom secret format ' + i.values[0] + ' is no longer redacted';
  return '';
}

/** Lines for `zn team status`. */
function describeChange(c) {
  const lines = ['version ' + c.from + ' to ' + c.to + ' (' + c.at + ') removed or loosened ' + c.count + (c.count === 1 ? ' restriction:' : ' restrictions:')];
  for (const i of c.items) lines.push('  - ' + describeItem(i));
  if (c.more > 0) lines.push('  - and ' + c.more + ' more');
  return lines;
}

/* ------------------------------------------------------------------ */
/* The line shown once in the agent's hook message                     */
/* ------------------------------------------------------------------ */

const NOTICE_FILE = 'team-notice.json';
const DETECTORS_NOTICE_EVERY_MS = 3600000;

function noticePath(home) { return path.join(home, NOTICE_FILE); }

function readNotice(home) {
  try {
    const n = JSON.parse(fs.readFileSync(noticePath(home), 'utf8'));
    return n && typeof n === 'object' && !Array.isArray(n) ? n : {};
  } catch (err) { return {}; }
}

function writeNotice(home, n) {
  try {
    fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    const file = noticePath(home);
    const tmp = file + '.' + process.pid + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(n) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch (err) { /* the notice is best effort */ }
}

/**
 * takeNotices({home, org, change, detectorsMissing, statusCommand, syncCommand, now}) -> [lines]
 * The change line is given once per change; the "detectors not applied" line
 * at most once an hour. What was shown is remembered in ~/.zn/team-notice.json.
 */
function takeNotices(o) {
  const lines = [];
  const now = o.now == null ? Date.now() : o.now;
  const seen = readNotice(o.home);
  const next = Object.assign({}, seen);
  let dirty = false;
  const change = cleanChange(o.change);
  if (change && !(seen.change_to === change.to && seen.change_org === (o.org || null))) {
    lines.push('zn: your organization changed its policy (version ' + change.to + ') and removed or loosened ' + change.count +
      (change.count === 1 ? ' restriction' : ' restrictions') + ' on this machine. See which with: ' + o.statusCommand + '.');
    next.change_to = change.to;
    next.change_org = o.org || null;
    dirty = true;
  }
  if (o.detectorsMissing && !(Number.isFinite(seen.detectors_at) && now - seen.detectors_at < DETECTORS_NOTICE_EVERY_MS)) {
    lines.push('zn: Team detectors not applied. Your organization\'s custom secret formats are not active here because its policy is missing or does not verify on this machine. Run: ' + o.syncCommand + '.');
    next.detectors_at = now;
    dirty = true;
  }
  if (dirty) writeNotice(o.home, next);
  return lines;
}

module.exports = { restrictionChanges, changeRecord, cleanChange, describeChange, describeItem, takeNotices, MAX_ITEMS };
