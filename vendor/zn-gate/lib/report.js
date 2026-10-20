'use strict';

/**
 * zn-gate report            what zn-gate did on this machine in the last 7 days
 * zn-gate report --since Nd another window (1-90 days)
 * zn-gate report --json     the same as JSON
 * zn-gate report --no-team-line   leave out the closing line about zn Team
 *
 * Reads only local files (~/.zn/stats.json and the MCP pins). It writes nothing,
 * opens no network connection and never prints payloads, paths, arguments or secret names.
 * Files are read with a size cap and without ever blocking (a pipe or a device is treated as absent),
 * and every value is checked before use: nothing in those files can crash or hang the report.
 */

const fs = require('fs');
const path = require('path');
const stats = require('./stats');
const pins = require('./mcp-pins');

const USAGE = 'Usage: zn-gate report [--since 1d-90d] [--json] [--no-team-line]\n';
const DEFAULT_DAYS = 7;
const TEAM_LINE = 'Teams can see this for everyone in one place: usezn.com/team  (hide this line: zn-gate report --no-team-line)';
const STATS_CAP = 4 * 1024 * 1024;
const PIN_CAP = 256 * 1024;
const MAX_PIN_FILES = 500;
const MAX_ENTRIES = 200;
const MAX_COUNT = 1e9;
const LAYERS = new Set(['hook', 'shield', 'mcp', 'broker', 'cli']);
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

function fmt(n) {
  return Number(n || 0).toLocaleString('en-US');
}

function parse(args) {
  const o = { days: DEFAULT_DAYS, json: false, teamLine: true, bad: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let v = null;
    if (a === '--json') o.json = true;
    else if (a === '--no-team-line') o.teamLine = false;
    else if (a === '--since') v = args[++i];
    else if (a.startsWith('--since=')) v = a.slice(8);
    else o.bad = true;
    if (v !== null) {
      const m = /^(\d{1,3})d$/.exec(String(v));
      const n = m ? Number(m[1]) : NaN;
      if (!m || n < 1 || n > stats.KEEP_DAYS) o.bad = true;
      else o.days = n;
    }
  }
  return o;
}

/** A regular file of at most `cap` bytes, read without blocking and without following a final symlink; anything else is null. */
function readSmall(file, cap) {
  const K = fs.constants;
  let fd;
  try {
    fd = fs.openSync(file, K.O_RDONLY | (K.O_NONBLOCK || 0) | (K.O_NOFOLLOW || 0));
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > cap) return null;
    const buf = Buffer.alloc(Math.min(st.size, cap) + 1);
    let n = 0;
    while (n < buf.length) {
      const r = fs.readSync(fd, buf, n, buf.length - n, null);
      if (!r) break;
      n += r;
    }
    return n > cap ? null : buf.toString('utf8', 0, n);
  } catch (_) {
    return null;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (_) { /* closed */ } }
  }
}

function readJson(file, cap) {
  const s = readSmall(file, cap);
  if (s === null) return null;
  try { return JSON.parse(s); } catch (_) { return null; }
}

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
/** A finite, non-negative whole number, capped; anything else is 0. */
const num = (x) => (typeof x === 'number' && Number.isFinite(x) && x > 0 ? Math.min(Math.floor(x), MAX_COUNT) : 0);
const own = (o) => Object.entries(o).slice(0, MAX_ENTRIES);

const RUNNERS = new Set(['npx', 'bunx', 'uvx', 'pipx', 'node', 'nodejs', 'deno', 'bun', 'python', 'python3', 'py', 'tsx', 'ts-node', 'pnpm', 'yarn', 'npm', 'uv']);
// Options of each runner that take no value (from their --help). Any other option is assumed to take one.
const NPM_FLAGS = ['-y', '--yes', '-n', '--no', '-q', '--quiet', '--no-install', '--prefer-offline', '--offline', '--ignore-scripts', '--no-progress', '--silent'];
const FLAG_ONLY = {
  npx: new Set(NPM_FLAGS),
  npm: new Set(NPM_FLAGS),
  pnpm: new Set(['-s', '--silent', '--shell-mode', '-y', '--yes']),
  yarn: new Set(['-q', '--quiet', '--silent']),
  bunx: new Set(['--bun', '--no-install', '--silent', '--verbose']),
  bun: new Set(['--bun', '--silent']),
  uvx: new Set(['--isolated', '--no-cache', '-n', '--no-progress', '--quiet', '-q', '--verbose', '-v', '--offline', '--native-tls', '--no-config', '--refresh', '--no-managed-python', '--managed-python']),
  uv: new Set(['--isolated', '--no-cache', '--quiet', '-q', '--verbose', '-v', '--offline', '--native-tls', '--no-config']),
  pipx: new Set(['--quiet', '-q', '--verbose', '-v', '--no-cache']),
  node: new Set(['--no-warnings', '--harmony', '--enable-source-maps', '--trace-warnings']),
  nodejs: new Set(['--no-warnings']),
  python: new Set(['-u', '-B', '-E', '-s', '-S', '-I', '-O', '-OO', '-q', '-v', '-b']),
  python3: new Set(['-u', '-B', '-E', '-s', '-S', '-I', '-O', '-OO', '-q', '-v', '-b']),
  deno: new Set(['-A', '--allow-all', '-q', '--quiet', '--no-prompt']),
};
const SKIP_WORDS =new Set(['run', 'dlx', 'exec', 'x', 'tool']);

/**
 * How a server is named in the report: the program and the package or script file, with NO arguments
 * (a command line can hold a token in any form). Folders are dropped; anything odd is left out.
 */
function safeName(cmd) {
  const tokens = String(cmd || '').split(/\s+/).filter(Boolean);
  const base = (t) => path.posix.basename(t.split('\\').join('/')).replace(/\.exe$/i, '');
  const ok = (t) => /^[A-Za-z0-9@][A-Za-z0-9@._/+-]{0,59}$/.test(t) && !/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(t);
  let i = 0;
  while (i < tokens.length && (tokens[i].includes('=') || base(tokens[i]) === 'env' || tokens[i].startsWith('-'))) i++;
  if (i >= tokens.length) return 'MCP server';
  const program = base(tokens[i]);
  if (!ok(program)) return 'MCP server';
  if (!RUNNERS.has(program)) return program;
  const flagOnly = FLAG_ONLY[program] || new Set();
  for (let j = i + 1; j < tokens.length; j++) {
    const t = tokens[j];
    if (t.startsWith('-')) {
      // An option written without "=" takes the next word as its value, unless it is known to take none:
      // a value must never be mistaken for the package.
      if (!t.includes('=') && !flagOnly.has(t)) j++;
      continue;
    }
    if (t.includes('=') || SKIP_WORDS.has(t)) continue;
    const isPath = /[\\/]/.test(t) && !t.startsWith('@');
    const target = isPath ? base(t) : t;
    return ok(target) ? `${program} ${target}` : program;
  }
  return program;
}

function inTeam() {
  try { return Boolean(require('./team/policy').readTeam()); } catch (_) { return false; }
}

function dayMinus(now, n) {
  return stats.today(new Date(now.getTime() - n * 86400000));
}

function readStats(r, from, until) {
  const data = readJson(stats.statsFile(), STATS_CAP);
  if (!isObj(data) || !isObj(data.days)) return;
  for (const [day, entries] of Object.entries(data.days)) {
    if (!DAY_RE.test(day) || day < from || day > until || !isObj(entries)) continue;
    let dayBlocked = 0;
    for (const [key, c] of own(entries)) {
      if (!isObj(c)) continue;
      const [layer, agentRaw] = String(key).split(':');
      if (!LAYERS.has(layer)) continue;
      const agent = stats.normName(agentRaw);
      const blocked = num(c.blocked);
      r.checked += num(c.checked);
      r.warned += num(c.warned);
      r.blocked += blocked;
      dayBlocked += blocked;
      if (blocked > 0) r.byAgent[agent] = (r.byAgent[agent] || 0) + blocked;
      let found = 0;
      if (isObj(c.detections)) {
        for (const [t, n] of own(c.detections)) {
          const k = stats.normType(t);
          const v = num(n);
          if (!v) continue;
          r.secretTypes[k] = (r.secretTypes[k] || 0) + v;
          found += v;
        }
      }
      // One counter: the total is always the sum of the breakdown; values hidden without a known type count as OTHER.
      const extra = num(c.redacted) - found;
      if (extra > 0) r.secretTypes.OTHER = (r.secretTypes.OTHER || 0) + extra;
    }
    if (dayBlocked > 0 && (!r.busiest || dayBlocked > r.busiest.blocked)) r.busiest = { day, blocked: dayBlocked };
  }
}

function readPins(r, from, until) {
  let names = [];
  try { names = fs.readdirSync(pins.pinsDir()).filter((n) => /^[0-9a-f]{16}\.json$/.test(n)).slice(0, MAX_PIN_FILES); } catch (_) { return; }
  for (const n of names) {
    const s = readJson(path.join(pins.pinsDir(), n), PIN_CAP);
    if (!isObj(s)) continue;
    if (isObj(s.pending)) r.pending += Math.min(Object.keys(s.pending).length, MAX_ENTRIES);
    // Pins written before firstPinnedAt existed are not counted as new: when they were first seen is unknown.
    const first = typeof s.firstPinnedAt === 'string' && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(s.firstPinnedAt) ? s.firstPinnedAt : null;
    if (first && first.slice(0, 10) >= from && first.slice(0, 10) <= until) r.newServers.push({ name: safeName(s.command), first_pinned_at: first });
  }
}

function collect(days, now) {
  const from = dayMinus(now, days - 1);
  const until = stats.today(now);
  const r = { since: from, until, days, checked: 0, blocked: 0, warned: 0, byAgent: {}, secretTypes: {}, busiest: null, newServers: [], pending: 0 };
  readStats(r, from, until);
  readPins(r, from, until);
  r.redacted = Object.values(r.secretTypes).reduce((a, b) => a + b, 0);
  return r;
}

function top(obj, n) {
  return Object.entries(obj).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, n);
}

function toJson(r) {
  return {
    since: r.since,
    until: r.until,
    days: r.days,
    blocked: r.blocked,
    redacted: r.redacted,
    by_agent: r.byAgent,
    secret_types: r.secretTypes,
    new_mcp_servers: r.newServers,
    pending_tool_changes: r.pending,
    busiest_day: r.busiest ? { day: r.busiest.day, blocked: r.busiest.blocked } : null,
    sources: ['stats.json', 'mcp-pins'],
    sent: false,
  };
}

function run(args, out = (s) => process.stdout.write(s), { now = new Date() } = {}) {
  const o = parse(args);
  if (o.bad) { out(USAGE); return 2; }
  const r = collect(o.days, now);
  if (o.json) { out(JSON.stringify(toJson(r), null, 2) + '\n'); return 0; }

  const team = o.teamLine && !inTeam() ? TEAM_LINE + '\n' : '';
  const off = stats.enabled() ? '' : '\nCounting is off on this computer (ZN_STATS=off), so these numbers may be incomplete.\n';
  const title = `zn-gate report: ${r.since} to ${r.until} (this computer only; nothing was sent)\n\n`;
  const empty = !r.checked && !r.blocked && !r.redacted && !r.warned && !r.newServers.length && !r.pending;
  if (empty && off) {
    out(title + '  Counting is off on this computer (ZN_STATS=off), so there are no numbers to show.\n\n' + team);
    return 0;
  }
  if (empty) {
    out(title + '  Nothing to report yet. zn-gate counts once it checks something (agent hooks, MCP tools or wrapped MCP servers).\n\n' + team);
    return 0;
  }
  out(title);
  const agents = top(r.byAgent, 5).map(([a, n]) => `${a} ${fmt(n)}`).join(', ');
  const types = top(r.secretTypes, 5).map(([t, n]) => `${t} ${fmt(n)}`).join(', ');
  out(`  Blocked actions   : ${fmt(r.blocked)}${agents ? `  (${agents})` : ''}\n`);
  out(`  Secrets hidden    : ${fmt(r.redacted)}${types ? `  (${types})` : ''}\n`);
  if (r.newServers.length) {
    out(`  New MCP servers   : ${r.newServers.length}  (${r.newServers.slice(0, 5).map((s) => s.name).join('; ')}${r.newServers.length > 5 ? '; ...' : ''})\n`);
  } else {
    out('  New MCP servers   : 0  (only servers wrapped by zn-gate are listed)\n');
  }
  if (r.pending) out(`  Tools changed, waiting for your approval: ${fmt(r.pending)}  (run: zn-gate pins)\n`);
  if (r.busiest) out(`\n  Busiest day: ${r.busiest.day} (${fmt(r.busiest.blocked)} blocked)\n`);
  out(off + '\nThis report was built from files on your computer. Nothing left it.\n' + team);
  return 0;
}

module.exports = { run, parse, TEAM_LINE, safeName };
