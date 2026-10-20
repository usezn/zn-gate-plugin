'use strict';
/**
 * zn-gate reach: what the coding agents on this machine can reach.
 *
 *   reach({ root, home, env }) -> { tool, version, root, agents, findings, counts, truncated }
 *
 * Read only, no network, nothing written (with --remember, only its counts). It puts together what zn already
 * knows: which agents are set up (zn-gate check, setup only: no hook is
 * started), the .env files of the folder (names of their secrets), the
 * credential files of the user (whether they exist: they are never opened),
 * the names of environment variables that look like secrets, and what
 * `zn audit` finds in the agent configuration of the folder and the user.
 *
 * No secret value ever enters the result: .env values are only measured,
 * environment values only tested, and audit findings come redacted.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const VERSION = 1;
const SEVERITIES = ['high', 'medium', 'low', 'info'];
const DOTENV_MAX_BYTES = 256 * 1024;
const AUDIT_BUDGET_MS = 2500;
const AUDIT_MAX_ENTRIES = 20000;

// Credential files zn protects (lib/hooks/policy.js), relative to the home folder.
const CREDENTIAL_FILES = [
  '.aws/credentials', '.ssh/id_rsa', '.ssh/id_ed25519', '.ssh/id_ecdsa', '.ssh/id_dsa', '.netrc', '_netrc',
  '.docker/config.json', '.config/gh/hosts.yml', '.config/gh/hosts.yaml', '.git-credentials', '.pgpass', '.kube/config',
  '.config/gcloud/application_default_credentials.json', '.config/gcloud/credentials.db', '.config/gcloud/access_tokens.db',
  '.azure/accessTokens.json', '.azure/msal_token_cache.json', '.npmrc', '.pypirc',
];

// Environment variable names that hold a secret, matched on the end of the name so TOKEN_LIMIT or KEY_ID are not.
const SECRET_ENV_NAME_RE = /(?:^|_)(?:API_?KEY|ACCESS_KEY|SECRET_ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET|SECRET|TOKEN|PAT|PASSWORD|PASSWD|CREDENTIALS?)$/i;
// Variables set by agents, shells and zn itself, never a user's secret.
const NOT_SECRET_ENV = new Set(['ZN_TOKEN_MAP', 'TERM_SESSION_TOKEN']);

// zn audit rules about MCP servers; the other findings are about what the project runs.
const MCP_RULES = new Set(['ZNA003', 'ZNA004', 'ZNA005', 'ZNA006']);

const DOTENV_RE = /^\.env(\.[A-Za-z0-9_.-]+)?$/;
const DOTENV_SAFE_RE = /\.(example|sample|template|dist|defaults|schema)$/i;

// Control and bidirectional characters: a file or server name from a repository could otherwise move the
// cursor, clear the screen or reorder the text in the user's terminal.
const UNSAFE_CHARS_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
// Characters that end a line or a column: in a one-line field they become a space, so a name cannot start
// a line of its own in the report.
const LINE_BREAK_RE = /[\r\n\t\u2028\u2029]+/g;
// Zero-width, invisible and tag characters: they hide text from the reader and can split a value so that
// it is not recognised, so they are removed before the value is hidden and again after.
const INVISIBLE_RE = /[\u200b-\u200d\u2060-\u2064\ufeff\u{e0000}-\u{e007f}]/gu;

/** Text that is safe to show on one line: invisible characters removed, secret values redacted (as zn audit
 * does), line breaks turned into spaces and other unsafe characters replaced. */
function safeText(s) {
  const { redact } = require('../audit');
  const clean = String(s == null ? '' : s).replace(INVISIBLE_RE, '').replace(LINE_BREAK_RE, ' ');
  return redact(clean).replace(INVISIBLE_RE, '').replace(LINE_BREAK_RE, ' ').replace(UNSAFE_CHARS_RE, '?');
}

function displayHome(rel) {
  return '~/' + rel.replace(/\\/g, '/');
}

function plural(n, word) {
  return n + ' ' + word + (n === 1 ? '' : 's');
}

/** Names of the secrets in the .env files of `root` (not below it), and how many are already zn markers. */
function dotenvFiles(root) {
  const dotenv = require('../broker/dotenv');
  const { readBounded } = require('../audit')._internal;
  let names;
  try { names = fs.readdirSync(root); } catch (_) { return []; }
  const out = [];
  for (const base of names.sort()) {
    if (!DOTENV_RE.test(base) || DOTENV_SAFE_RE.test(base)) continue;
    const r = readBounded(path.join(root, base), DOTENV_MAX_BYTES, false);
    // A link is not followed: it could lead anywhere on the machine.
    if (r.skip === 'symlink') { out.push({ file: base, secrets: [], markers: 0, link: true }); continue; }
    if (r.text === undefined) continue;
    const secrets = [];
    let markers = 0;
    for (const e of dotenv.parseDotenv(r.text).entries) {
      if (!dotenv.isSensitiveKey(e.key) || !e.value) continue;
      if (e.value.includes('__ZN_')) { markers++; continue; }
      const pw = dotenv.connectionPassword(e.value);
      if (!pw && /^[a-z][a-z0-9+.-]*:\/\//i.test(e.value)) continue; // a URL without credentials
      if ((pw ? pw.end - pw.start : e.value.length) < dotenv.MIN_SECRET_LEN) continue;
      if (!secrets.includes(e.key)) secrets.push(e.key);
    }
    out.push({ file: base, secrets, markers });
  }
  return out;
}

/** Credential files of the user that exist: only stat, never read. */
function credentialFiles(home, env, cwd) {
  const policy = require('../hooks/policy');
  const rels = new Set(CREDENTIAL_FILES);
  // Other SSH private keys: names only.
  try {
    for (const n of fs.readdirSync(path.join(home, '.ssh'))) if (/^id_|_key$/.test(n) && !n.endsWith('.pub')) rels.add('.ssh/' + n);
  } catch (_) { /* no ~/.ssh */ }
  const out = [];
  for (const rel of [...rels].sort()) {
    const abs = path.join(home, rel);
    let st;
    try { st = fs.statSync(abs); } catch (_) { continue; }
    if (!st.isFile()) continue;
    const c = policy.classifyPath(abs, { home, env, cwd });
    if (!c || c.kind !== 'credential') continue;
    out.push({ path: displayHome(rel), what: c.reason });
  }
  return out;
}

/** Names of environment variables that hold a secret. The values are tested, never kept. */
function secretEnvNames(env) {
  const rules = require('../rules');
  const out = [];
  for (const [name, raw] of Object.entries(env || {})) {
    const value = String(raw == null ? '' : raw);
    if (NOT_SECRET_ENV.has(name.toUpperCase()) || value.length < 8 || value.includes('__ZN_')) continue;
    if (/^(?:\d+|true|false|yes|no|on|off)$/i.test(value)) continue;
    let byValue = false;
    try { byValue = rules.redactSecrets(value).sanitized !== value; } catch (_) { byValue = false; }
    if (SECRET_ENV_NAME_RE.test(name) || byValue) out.push(name);
  }
  return out.sort();
}

function auditFindings(root, home, env) {
  try {
    const { audit } = require('../audit');
    const r = audit({ root, home, env, includeHome: true, timeBudgetMs: AUDIT_BUDGET_MS, maxEntries: AUDIT_MAX_ENTRIES });
    return { findings: r.findings, truncated: r.truncated };
  } catch (err) {
    return { findings: [], truncated: true };
  }
}

async function agentsOf(root, home, env) {
  const { check } = require('../check');
  const { results } = await check({ home, env, cwd: root, live: false });
  return results.map((r) => ({
    id: r.id,
    name: r.name,
    found: r.state !== 'not-set-up' || r.found !== false,
    state: r.state,
    problem: r.problem || '',
    fix: r.fix || '',
  }));
}

/** Everything the agents on this machine can reach. */
async function reach(opts = {}) {
  const root = path.resolve(opts.root || '.');
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const findings = [];
  const add = (f) => findings.push(f);

  const agents = await agentsOf(root, home, env);
  const found = agents.filter((a) => a.found);
  const unprotected = found.filter((a) => a.state !== 'protected');
  // Without any agent on this machine nothing reads these files yet: a low finding, so it is known before one is installed.
  const level = (high) => (unprotected.length ? high : found.length ? 'info' : 'low');
  const reads = unprotected.length ? unprotected.map((a) => a.name).join(', ') + ' can read them today.'
    : found.length ? 'zn stops your agents from reading them.'
      : 'No coding agent was found here yet; one you install would be able to read them.';

  for (const a of found) {
    if (a.state === 'protected') continue;
    if (a.state === 'not-set-up') {
      add({ section: 'agents', severity: 'high', title: a.name + ' is on this machine and zn does not protect it', detail: 'It can read any file and run any command you allow.', fix: 'npx -y zn-gate init' });
    } else if (a.state === 'project-only') {
      add({ section: 'agents', severity: 'medium', title: a.name + ' is protected in one project only', detail: 'zn is set up for one folder, not for your user.', fix: a.fix });
    } else {
      add({ section: 'agents', severity: 'high', title: a.name + ' is set up, but zn does not protect it', detail: a.problem, fix: a.fix });
    }
  }

  for (const d of dotenvFiles(root)) {
    if (d.link) {
      add({ section: 'reach', kind: 'dotenv-link', severity: 'info', file: d.file, title: d.file + ' in this folder is a link, so zn-gate reach did not read it', detail: 'An agent that follows the link can read the file it points to.', fix: '' });
      continue;
    }
    if (!d.secrets.length) continue;
    const shown = d.secrets.slice(0, 5).join(', ') + (d.secrets.length > 5 ? ', ...' : '');
    add({
      section: 'reach', kind: 'dotenv', severity: level('high'), file: d.file,
      title: d.file + ' in this folder has ' + plural(d.secrets.length, 'secret') + ' (' + shown + ')',
      detail: reads,
      fix: 'npx -y zn-gate env shadow ' + d.file,
      names: d.secrets,
    });
  }

  const creds = credentialFiles(home, env, root);
  if (creds.length) {
    add({
      section: 'reach', kind: 'credential-files', severity: level('medium'),
      title: plural(creds.length, 'credential file') + ' in your home folder (' + creds.slice(0, 4).map((c) => c.path).join(', ') + (creds.length > 4 ? ', ...' : '') + ')',
      detail: reads,
      fix: unprotected.length ? 'npx -y zn-gate init' : '',
      files: creds,
    });
  }

  const names = secretEnvNames(env);
  if (names.length) {
    add({
      section: 'reach', kind: 'environment', severity: 'low',
      title: plural(names.length, 'environment variable') + ' with a secret (' + names.slice(0, 5).join(', ') + (names.length > 5 ? ', ...' : '') + ')',
      detail: 'An agent started from this terminal gets their values.',
      fix: 'keep them in zn\'s vault: run `npx -y zn-gate secret set NAME` in your own terminal, then use __ZN_NAME__ where the value goes',
      names,
    });
  }

  const au = auditFindings(root, home, env);
  for (const f of au.findings) {
    add({
      // zn audit names the files of the home folder ~/...: they apply to every project.
      section: MCP_RULES.has(f.id) ? 'mcp' : String(f.file).startsWith('~/') ? 'user' : 'project', kind: 'audit',
      severity: f.severity === 'critical' ? 'high' : f.severity,
      id: f.id, file: f.file, line: f.line,
      title: f.title, detail: f.detail, fix: f.fix,
    });
  }

  // Every text that reaches the report, whatever its source, goes through the same redaction and cleaning.
  for (const f of findings) for (const k of ['title', 'detail', 'fix', 'file']) if (f[k] != null) f[k] = safeText(f[k]);
  for (const f of findings) if (f.files) f.files = f.files.map((c) => ({ path: safeText(c.path), what: safeText(c.what) }));
  for (const f of findings) if (f.names) f.names = f.names.map(safeText);
  for (const a of agents) { a.problem = safeText(a.problem); a.fix = safeText(a.fix); }
  const rank = (s) => SEVERITIES.indexOf(s);
  findings.sort((a, b) => rank(a.severity) - rank(b.severity));
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const r = { tool: 'zn-gate reach', version: VERSION, root, agents, findings, counts, truncated: au.truncated };
  if (opts.remember) r.previous = remember(root, counts, home, env);
  return r;
}

/*
 * --remember: the counts of the last run for this folder, kept in ~/.zn/reach-last.json (ZN_HOME overrides
 * ~/.zn), so the next run can say "was N". Only counts and a date, under a hash of the folder path: no
 * path, name or value. Without --remember nothing is read or written.
 */
const MAX_MEMORY_BYTES = 1024 * 1024;

function memoryFile(home, env) {
  return path.join(env.ZN_HOME ? path.resolve(env.ZN_HOME) : path.join(home, '.zn'), 'reach-last.json');
}

/**
 * The text of a regular file of at most `max` bytes, or null (absent, a folder, a pipe or a device, a link,
 * too big, unreadable). The file is opened without following a link and without waiting for a writer, and
 * the size is checked on the open file, so a named pipe or /dev/zero cannot make the run hang or grow.
 */
function readSmallFile(file, max) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  } catch (_) {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > max) return null;
    const buf = Buffer.allocUnsafe(max + 1);
    let got = 0;
    while (got <= max) {
      const r = fs.readSync(fd, buf, got, max + 1 - got, null);
      if (r <= 0) break;
      got += r;
    }
    return got > max ? null : buf.toString('utf8', 0, got);
  } catch (_) {
    return null;
  } finally {
    try { fs.closeSync(fd); } catch (_) { /* closed */ }
  }
}

function remember(root, counts, home, env) {
  const file = memoryFile(home, env);
  const crypto = require('crypto');
  const key = crypto.createHash('sha256').update(root).digest('hex').slice(0, 32);
  // Only well-formed entries are kept: anything else in the file is dropped, never a reason to fail.
  const data = {};
  try {
    const text = readSmallFile(file, MAX_MEMORY_BYTES);
    const parsed = text === null ? null : JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [k, e] of Object.entries(parsed)) {
        if (/^[0-9a-f]{32}$/.test(k) && e && typeof e === 'object' && !Array.isArray(e)) data[k] = e;
      }
    }
  } catch (_) { /* no file, or not JSON: start again */ }
  const was = data[key] || null;
  // Whatever the file holds, only numbers and a YYYY-MM-DD date reach the report.
  const count = (n) => (Number.isSafeInteger(+n) && +n >= 0 ? +n : 0);
  const day = typeof (was && was.at) === 'string' && was.at.length <= 40 && /^\d{4}-\d{2}-\d{2}$/.test(was.at) ? was.at : 'an earlier run';
  const previous = was ? { high: count(was.high), medium: count(was.medium), low: count(was.low), at: day } : null;
  data[key] = { high: counts.high, medium: counts.medium, low: counts.low, at: new Date().toISOString().slice(0, 10) };
  // Up to 200 folders: the oldest go first.
  const keys = Object.keys(data).sort((a, b) => String(data[a].at).localeCompare(String(data[b].at)));
  while (keys.length > 200) delete data[keys.shift()];
  // A new temporary file with a random name, created exclusively (never through a planted link), then renamed
  // over the old one. Two runs at the same time: the last one to finish wins; the file is never half written.
  let fd = null;
  let tmp = null;
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    tmp = file + '.' + crypto.randomBytes(8).toString('hex') + '.tmp';
    fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    fs.writeSync(fd, JSON.stringify(data));
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(tmp, file);
    tmp = null;
  } catch (_) {
    /* a report that cannot remember is still a report */
  } finally {
    if (fd !== null) try { fs.closeSync(fd); } catch (_) { /* closed */ }
    if (tmp !== null) try { fs.unlinkSync(tmp); } catch (_) { /* gone */ }
  }
  return previous;
}

const SECTIONS = [
  ['agents', 'AGENTS', ''],
  ['reach', 'WHAT THEY CAN REACH', 'secrets and credential files an agent could read; names only, never values'],
  ['mcp', 'MCP SERVERS', 'extra tools your agent can call'],
  ['user', 'YOUR AGENT SETTINGS', 'settings in your home folder that apply to every project'],
  ['project', 'PROJECT FILES THE AGENT RUNS', 'settings in this folder that an agent loads or runs'],
];

/** Plain-language report; returns 0 (the command line turns --fail-on into the exit code). */
function report(r, write) {
  const w = write || ((s) => process.stdout.write(s));
  w('\nzn-gate reach: what can the coding agents on this machine reach?\n');
  w('Read: agent settings in your home folder and this folder, .env files here, names of environment variables. Nothing was sent anywhere.\n\n');
  w('AGENTS\n');
  for (const a of r.agents) {
    const state = !a.found ? 'not found on this machine'
      : a.state === 'protected' ? 'protected by zn (run `zn-gate check` to test it)'
        : a.state === 'project-only' ? 'protected in one project only'
          : 'not protected';
    w('  ' + a.name.padEnd(12) + ' ' + state + '\n');
  }
  if (!r.findings.some((f) => f.section === 'agents')) w('\n');
  const truncated = 'Some files were not checked in time; `npx -y zn-gate audit --include-home` checks them all.\n\n';
  const actionable = r.findings.filter((f) => f.severity !== 'info');
  if (!actionable.length) {
    // An incomplete check never says that nothing needs fixing.
    if (r.truncated) w('Nothing found in what was checked. ' + truncated);
    else w(r.agents.some((a) => a.found)
      ? 'Nothing to fix. Your agents run with zn-gate.\n\n'
      : 'No supported coding agent was found on this machine, and nothing here needs fixing.\n\n');
    return 0;
  }
  for (const [key, title, what] of SECTIONS) {
    const list = r.findings.filter((f) => f.section === key);
    if (!list.length) continue;
    // The agent findings go right under the list of agents.
    if (key !== 'agents') w(title + ' (' + what + ')\n');
    for (const f of list) line(w, f);
    w('\n');
  }
  if (r.truncated) w(truncated);
  const next = [];
  if (r.findings.some((f) => f.fix === 'npx -y zn-gate init' && f.severity === 'high')) next.push('npx -y zn-gate init');
  const env = r.findings.find((f) => f.severity === 'high' && f.kind === 'dotenv');
  if (env) next.push(env.fix);
  if (next.length) {
    w('NEXT: fix the high ones\n');
    next.forEach((c, i) => w('  ' + (i + 1) + '. ' + c + '\n'));
    w('\n');
  }
  const p = r.previous;
  const was = p ? ' (last time, ' + safeText(p.at).replace(/[\r\n]+/g, ' ').slice(0, 40) + ': ' + p.high + ' high, ' + p.medium + ' medium, ' + p.low + ' low)' : '';
  w(r.counts.high + ' high, ' + r.counts.medium + ' medium, ' + r.counts.low + ' low' + was + '.\n\n');
  return 0;
}

function line(w, f) {
  w('  ' + f.severity.toUpperCase().padEnd(6) + ' ' + f.title + (f.file && f.line ? ' [' + f.file + ':' + f.line + ']' : '') + '\n');
  if (f.detail) w('         ' + f.detail + '\n');
  if (f.fix) w('         Fix: ' + f.fix + '\n');
}

const FAIL_ON = ['high', 'medium', 'low', 'none'];

/** Whether a finding at or above failOn was found (never for 'none'; info findings never count). */
function failed(r, failOn) {
  if (!failOn || failOn === 'none') return false;
  const limit = SEVERITIES.indexOf(failOn);
  return r.findings.some((f) => f.severity !== 'info' && SEVERITIES.indexOf(f.severity) <= limit);
}

module.exports = { reach, report, failed, FAIL_ON, VERSION, _internal: { dotenvFiles, credentialFiles, secretEnvNames, SECRET_ENV_NAME_RE, memoryFile } };
