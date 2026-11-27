'use strict';
/**
 * zn-gate reach --history: did your coding agents keep a secret of yours in their local session history?
 *
 *   history({ home, env, maxSeconds }) -> { tool, version, agents, findings, incomplete, totals, ... }
 *
 * Read only, no network, nothing written (the evidence log included). Each history file is read in streaming
 * mode, one line at a time, and every string in it goes through the same secret patterns as the scrubber
 * (lib/scrub, secrets only: no personal data, no exact values).
 *
 * The result holds a closed vocabulary only: agent, file path, secret type, a count and an action. A value,
 * a part of a value, a prefix or a hash of a value never leaves the scanning function.
 *
 * The home folder of the current user is read, plus the folder CLAUDE_CONFIG_DIR or CODEX_HOME names, wherever it
 * points. No link is followed: a link at any level below the home folder, a config folder that is a link, or a
 * history file that is a link, is skipped and listed.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const VERSION = 1;
const DEFAULT_MAX_SECONDS = 120;
const MAX_SECONDS_LIMIT = 3600;
const CHUNK = 1024 * 1024;
// A line longer than this is not scanned (a pasted binary, for example): the file is reported as incomplete.
const MAX_LINE_BYTES = 32 * 1024 * 1024;
const MAX_DEPTH = 6;
const MAX_FILES = 50000;
const MAX_LISTED = 200;
const MAX_STRINGS_PER_LINE = 200000;
// A very long line is scanned in slices of about this many characters, with the deadline checked between slices,
// so one huge line cannot run far past --max-seconds. Lines shorter than this are scanned whole.
const SLICE_CHARS = 4 * 1024 * 1024;
// Each slice is scanned with this many characters of the next slice after it, so a secret that crosses a cut is seen
// whole by the slice it starts in. See overlapChars() for how the size comes from the secret rules.
const OVERLAP_FLOOR = 64 * 1024;
let overlap = 0;

/**
 * Longest match of a secret rule, as an upper bound: for each rule, the sum of the upper bounds of its bounded
 * repeats ({n} and {m,n}; an open {m,} counts as m) plus the length of its source (which bounds its fixed text).
 * The overlap is twice that, and at least OVERLAP_FLOOR: the part of a slice that is read twice is then at least
 * two of the longest secrets long, so a secret that crosses a cut fits in it and the two seams never meet.
 * The other secret scanners of lib/scrub (config lines, quoted values) read at most 4096 characters plus the key.
 * A rule with an open repeat ({m,}, +, *) can match a longer token: such a token is the one case a cut can miss.
 */
function longestSecretMatch(sources) {
  const q = /(?<!\\)\{(\d+)(?:,(\d*))?\}/g;
  let best = 0;
  for (const src of sources) {
    let n = src.length;
    let m;
    q.lastIndex = 0;
    while ((m = q.exec(src)) !== null) n += Number(m[2] ? m[2] : m[1]);
    if (n > best) best = n;
  }
  return best;
}

function overlapChars() {
  if (!overlap) {
    const { PATTERNS } = require('../scrub/patterns');
    const sources = PATTERNS.filter((p) => p.re instanceof RegExp).map((p) => p.re.source);
    overlap = Math.max(OVERLAP_FLOOR, 2 * longestSecretMatch(sources));
  }
  return overlap;
}

// Agents whose history is a plain JSON Lines file and documented. Cursor and OpenCode keep theirs in a
// database (SQLite), which this version does not read: they are reported as not scanned.
const AGENTS = [
  {
    id: 'claude-code', name: 'Claude Code', envDir: 'CLAUDE_CONFIG_DIR', defaultDir: ['.claude'],
    // Session transcripts (any depth below projects/) and the prompt history.
    trees: [{ dir: ['projects'], ext: '.jsonl' }], files: [['history.jsonl']],
  },
  {
    id: 'codex', name: 'Codex CLI', envDir: 'CODEX_HOME', defaultDir: ['.codex'],
    trees: [{ dir: ['sessions'], ext: '.jsonl' }], files: [['history.jsonl']],
  },
];
// Gemini CLI, Copilot, Antigravity and ZCode are supported by zn-gate, but this version does not read their
// history yet: the report says so, so an empty result is never read as "nothing leaked".
const NOT_SCANNED = [
  { id: 'cursor', name: 'Cursor', reason: 'database' },
  { id: 'opencode', name: 'OpenCode', reason: 'database' },
  { id: 'gemini-cli', name: 'Gemini CLI', reason: 'not-yet' },
  { id: 'copilot', name: 'Copilot', reason: 'not-yet' },
  { id: 'antigravity', name: 'Antigravity', reason: 'not-yet' },
  { id: 'zcode', name: 'ZCode', reason: 'not-yet' },
];

// What to do about a secret of this type: closed text, never taken from the file.
const LABELS = {
  AWS_KEY: ['AWS access key', 'in the AWS console (IAM)'],
  AWS_SECRET: ['AWS secret access key', 'in the AWS console (IAM)'],
  ANTHROPIC_KEY: ['Anthropic API key', 'in the Anthropic Console'],
  OPENAI_KEY: ['OpenAI API key', 'in the OpenAI dashboard'],
  GITHUB_TOKEN: ['GitHub token', 'in your GitHub settings'],
  GITHUB_PAT: ['GitHub personal access token', 'in your GitHub settings'],
  GITLAB_TOKEN: ['GitLab token', 'in your GitLab settings'],
  SLACK_TOKEN: ['Slack token', 'in your Slack app settings'],
  STRIPE_KEY: ['Stripe key', 'in the Stripe dashboard'],
  GOOGLE_API_KEY: ['Google API key', 'in the Google Cloud console'],
  NPM_TOKEN: ['npm token', 'on npmjs.com'],
  PYPI_TOKEN: ['PyPI token', 'on pypi.org'],
  HF_TOKEN: ['Hugging Face token', 'in your Hugging Face settings'],
  PRIVATE_KEY: ['private key', 'by creating a new key pair and removing the old public key where it is installed'],
  JWT: ['JSON Web Token', 'by signing out of that service, or asking it to revoke the token'],
  SECRET: ['password, token or key', 'at the service it belongs to'],
};
const DELETE_STEP = 'then delete this session file if you do not need it.';

function actionFor(type) {
  const l = LABELS[type];
  if (l) return 'Rotate this ' + l[0] + ' ' + l[1] + ', ' + DELETE_STEP;
  return 'Rotate this ' + type.toLowerCase().replace(/_/g, ' ') + ' at the service it belongs to, ' + DELETE_STEP;
}

/** Text that is safe to print: the cleaning reach uses for any text that comes from the disk. */
function clean(s) {
  return require('./index')._internal.safeText(s);
}

function lstatOrNull(p) {
  try { return fs.lstatSync(p); } catch (_) { return null; }
}

/**
 * Directory `parts` below `base`, walking down one level at a time with lstat: null when a level is missing,
 * is not a folder, or is a link (a link could lead out of the home folder).
 */
function realDirBelow(base, parts) {
  let cur = base;
  for (const p of parts) {
    cur = path.join(cur, p);
    const st = lstatOrNull(cur);
    if (!st || st.isSymbolicLink() || !st.isDirectory()) return null;
  }
  return cur;
}

/**
 * The agent's config folder: the one the environment names, wherever it points (the user chose it), or the
 * default below home. { parts } when it is below home (walked level by level, no link followed), { abs } when
 * the environment names a folder outside home (the folder itself must be a real folder, not a link).
 */
function configDir(agent, home, env) {
  const named = env && env[agent.envDir];
  if (named && typeof named === 'string') {
    const abs = path.resolve(named);
    const rel = path.relative(home, abs);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return { parts: rel.split(path.sep) };
    return { abs };
  }
  return { parts: agent.defaultDir };
}

function display(home, abs) {
  const rel = path.relative(home, abs);
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return clean('~/' + rel.split(path.sep).join('/'));
  return clean(abs);
}

// Entries are visited in byte order of their names (UTF-8), the same order as the Python package. readdir returns
// the order of the directory on disk, which differs between machines, and the cap below cuts the walk short.
function byNameBytes(a, b) {
  return Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8'));
}

function walk(dir, ext, depth, out, skipped, agent, home, limit) {
  if (depth > MAX_DEPTH) {
    skipped.push({ agent: agent.id, file: display(home, dir), reason: 'too-deep', limit: MAX_DEPTH });
    return;
  }
  if (out.length >= limit) {
    skipped.push({ agent: agent.id, file: display(home, dir), reason: 'too-many-files', limit });
    return;
  }
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }).sort(byNameBytes); } catch (_) { return; }
  for (const e of entries) {
    const abs = path.join(dir, e.name);
    if (e.isSymbolicLink()) { skipped.push({ agent: agent.id, file: display(home, abs), reason: 'symlink' }); continue; }
    if (e.isDirectory()) { walk(abs, ext, depth + 1, out, skipped, agent, home, limit); continue; }
    if (!e.isFile() || !e.name.endsWith(ext)) continue;
    const st = lstatOrNull(abs);
    if (!st || !st.isFile()) continue;
    if (out.length >= limit) {
      skipped.push({ agent: agent.id, file: display(home, dir), reason: 'too-many-files', limit });
      return;
    }
    out.push({ abs, size: st.size, mtime: st.mtimeMs });
  }
}

function collect(agent, home, env, skipped, limit) {
  const c = configDir(agent, home, env);
  let base;
  let basePath;
  if (c.parts) {
    basePath = path.join(home, ...c.parts);
    base = realDirBelow(home, c.parts);
  } else {
    basePath = c.abs;
    const st0 = lstatOrNull(c.abs);
    base = st0 && !st0.isSymbolicLink() && st0.isDirectory() ? c.abs : null;
  }
  if (!base) {
    // The folder itself being a link is said, so a user is not told "nothing found" for a folder that exists.
    const st = lstatOrNull(basePath);
    if (st && st.isSymbolicLink()) skipped.push({ agent: agent.id, file: display(home, basePath), reason: 'symlink' });
    return { base: null, files: [] };
  }
  const files = [];
  for (const f of agent.files) {
    const abs = path.join(base, ...f);
    const st = lstatOrNull(abs);
    if (!st) continue;
    if (st.isSymbolicLink()) { skipped.push({ agent: agent.id, file: display(home, abs), reason: 'symlink' }); continue; }
    if (st.isFile()) files.push({ abs, size: st.size, mtime: st.mtimeMs });
  }
  for (const t of agent.trees) {
    const root = realDirBelow(base, t.dir);
    if (!root) continue;
    walk(root, t.ext, 0, files, skipped, agent, home, limit);
  }
  return { base, files };
}

/** Every string of 8 characters or more inside a parsed JSON value (not the keys). */
function strings(v, out) {
  const stack = [v];
  while (stack.length && out.length < MAX_STRINGS_PER_LINE) {
    const x = stack.pop();
    if (typeof x === 'string') {
      if (x.length >= 8) out.push(x);
    } else if (Array.isArray(x)) {
      for (let i = 0; i < x.length; i++) stack.push(x[i]);
    } else if (x && typeof x === 'object') {
      for (const k in x) stack.push(x[k]);
    }
  }
  return out;
}

/** Adds the secret types found in one line to counts ({ TYPE: n }). Values are dropped here. */
class TimeUp extends Error {}

/** Cut points of a text: [0, c1, ..., length]. A cut is moved back to a line break or a space when one is near. */
function cuts(text) {
  const out = [0];
  let pos = 0;
  while (pos < text.length) {
    let end = Math.min(pos + SLICE_CHARS, text.length);
    if (end < text.length) {
      const cut = Math.max(text.lastIndexOf('\n', end - 1), text.lastIndexOf(' ', end - 1));
      if (cut >= pos && cut > end - 65536) end = cut + 1;
    }
    out.push(end);
    pos = end;
  }
  return out;
}

function addSecrets(engine, text, delta, sign) {
  for (const s of engine.scan(text, { exact: false, pii: false })) {
    if (s.source === 'pii') continue;
    delta[s.type] = (delta[s.type] || 0) + sign;
  }
}

/**
 * A line longer than SLICE_CHARS is scanned slice by slice, with the deadline checked between slices. Slice i
 * runs from cut c(i) to cut c(i+1) and is scanned together with the next `overlap` characters, so a secret that
 * crosses c(i+1) is seen whole. What that extra text holds is counted again by slice i+1, so the findings of the
 * text from c(i+1) to c(i+1) + overlap, scanned alone, are taken away from slice i+1: both texts start at the same
 * cut, so what each finds there (including a piece of a secret cut at c(i+1)) is the same and cancels out. Each
 * secret is then counted once, by the slice it starts in, without needing positions.
 */
function scanLine(engine, line, counts, expired) {
  let text = line;
  const t = line.trimStart().charCodeAt(0);
  if (t === 123 || t === 91) { // { or [
    try {
      text = strings(JSON.parse(line), []).join('\n');
    } catch (_) { text = line; }
  }
  if (text.length < 8) return;
  if (text.length <= SLICE_CHARS) {
    const delta = {};
    addSecrets(engine, text, delta, 1);
    for (const k of Object.keys(delta)) counts[k] = (counts[k] || 0) + delta[k];
    return;
  }
  const extra = overlapChars();
  const at = cuts(text);
  const inLine = {};
  try {
    for (let i = 0; i + 1 < at.length; i++) {
      if (i > 0 && expired && expired()) throw new TimeUp();
      const delta = {};
      addSecrets(engine, text.slice(at[i], Math.min(text.length, at[i + 1] + extra)), delta, 1);
      if (i > 0) addSecrets(engine, text.slice(at[i], Math.min(text.length, at[i] + extra)), delta, -1);
      for (const k of Object.keys(delta)) inLine[k] = (inLine[k] || 0) + delta[k];
    }
  } finally {
    // A count below zero can only come from a rule that matches a cut piece but not the whole secret: never negative.
    for (const k of Object.keys(inLine)) if (inLine[k] > 0) counts[k] = (counts[k] || 0) + inLine[k];
  }
}

/**
 * Stream one file. Returns { counts, bytes, complete, reason }.
 * `deadline` is a timestamp in ms: past it the file is left half read and reported so. It is checked after every
 * chunk that was read (never on the final empty read, so a file read to the end is complete) and between slices
 * of a very long line. `now` is the clock (tests only).
 */
function scanFile(engine, abs, deadline, now = Date.now) {
  const counts = {};
  let fd;
  try {
    fd = fs.openSync(abs, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  } catch (_) {
    return { counts, bytes: 0, complete: false, reason: 'unreadable' };
  }
  let bytes = 0;
  let complete = true;
  let reason = null;
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { counts, bytes: 0, complete: false, reason: 'unreadable' };
    const buf = Buffer.allocUnsafe(CHUNK);
    let carry = [];
    let carryLen = 0;
    let dropping = false;
    const flush = (b) => scanLine(engine, b.toString('utf8'), counts, () => now() > deadline);
    for (;;) {
      const n = fs.readSync(fd, buf, 0, CHUNK, null);
      if (n <= 0) break;
      if (now() > deadline) { complete = false; reason = 'time-limit'; break; }
      bytes += n;
      let start = 0;
      for (;;) {
        const nl = start < n ? buf.subarray(0, n).indexOf(10, start) : -1;
        if (nl < 0) break;
        if (dropping) {
          dropping = false;
        } else {
          const piece = buf.subarray(start, nl);
          if (carryLen + piece.length <= MAX_LINE_BYTES) {
            carry.push(Buffer.from(piece));
            flush(carry.length === 1 ? carry[0] : Buffer.concat(carry));
          } else { complete = false; reason = 'line-too-long'; }
        }
        carry = []; carryLen = 0;
        start = nl + 1;
      }
      if (start < n && !dropping) {
        const rest = n - start;
        if (carryLen + rest > MAX_LINE_BYTES) {
          dropping = true; carry = []; carryLen = 0; complete = false; reason = 'line-too-long';
        } else {
          carry.push(Buffer.from(buf.subarray(start, n)));
          carryLen += rest;
        }
      }
    }
    if (carryLen > 0 && reason !== 'time-limit') flush(Buffer.concat(carry));
  } catch (e) {
    complete = false;
    reason = e instanceof TimeUp ? 'time-limit' : (reason || 'unreadable');
  } finally {
    try { fs.closeSync(fd); } catch (_) { /* closed */ }
  }
  return { counts, bytes, complete, reason };
}

function history(opts = {}) {
  const home = path.resolve(opts.home || os.homedir());
  const env = opts.env || process.env;
  const maxSeconds = Math.min(MAX_SECONDS_LIMIT, Math.max(1, Number(opts.maxSeconds) || DEFAULT_MAX_SECONDS));
  const started = Date.now();
  const deadline = started + (Number.isFinite(opts._maxMs) ? opts._maxMs : maxSeconds * 1000); // _maxMs: tests only
  const limit = Number.isInteger(opts._maxFiles) ? opts._maxFiles : MAX_FILES; // _maxFiles: tests only
  const engine = require('../scrub/engine');

  const skipped = [];
  const plan = [];
  const agents = [];
  for (const a of AGENTS) {
    const c = collect(a, home, env, skipped, limit);
    agents.push({ id: a.id, name: a.name, scanned: !!c.base, reason: c.base ? null : 'not-found', files: 0, bytes: 0 });
    // Newest first: the sessions most likely to hold a live key.
    c.files.sort((x, y) => y.mtime - x.mtime);
    for (const f of c.files) plan.push({ agent: a.id, ...f });
  }
  for (const n of NOT_SCANNED) agents.push({ id: n.id, name: n.name, scanned: false, reason: n.reason, files: 0, bytes: 0 });

  const findings = [];
  const incomplete = [];
  let notReached = 0;
  let timeLimitHit = false;
  const byAgent = new Map(agents.map((a) => [a.id, a]));
  for (const f of plan) {
    const shown = display(home, f.abs);
    if (timeLimitHit || Date.now() > deadline) {
      timeLimitHit = true;
      notReached++;
      if (incomplete.length < MAX_LISTED) incomplete.push({ agent: f.agent, file: shown, reason: 'time-limit' });
      continue;
    }
    const r = scanFile(engine, f.abs, deadline);
    const a = byAgent.get(f.agent);
    a.files++;
    a.bytes += r.bytes;
    if (!r.complete) {
      if (r.reason === 'time-limit') { timeLimitHit = true; notReached++; }
      if (incomplete.length < MAX_LISTED) incomplete.push({ agent: f.agent, file: shown, reason: r.reason });
    }
    for (const type of Object.keys(r.counts).sort()) {
      if (!/^[A-Z0-9_]{1,48}$/.test(type)) continue;
      findings.push({ agent: f.agent, file: shown, type, count: r.counts[type], action: actionFor(type) });
    }
  }
  for (const s of skipped) if (incomplete.length < MAX_LISTED) incomplete.push(s);

  findings.sort((x, y) => (x.agent < y.agent ? -1 : x.agent > y.agent ? 1 : y.count - x.count));
  const withSecrets = new Set(findings.map((f) => f.agent + '\n' + f.file));
  return {
    tool: 'zn-gate reach --history',
    version: VERSION,
    agents,
    findings,
    incomplete,
    totals: {
      files_scanned: agents.reduce((n, a) => n + a.files, 0),
      bytes_scanned: agents.reduce((n, a) => n + a.bytes, 0),
      files_with_secrets: withSecrets.size,
      secrets: findings.reduce((n, f) => n + f.count, 0),
      files_not_reached: notReached,
    },
    time_limit_hit: timeLimitHit,
    max_seconds: maxSeconds,
    elapsed_ms: Date.now() - started,
    notes: [
      'A key listed here may already be rotated. Check before you rotate.',
      'zn-gate cannot see what was already sent to your model provider.',
    ],
  };
}

function mb(n) { return (n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0) + ' MB'; }

const REASONS = {
  'too-deep': 'not scanned: it is nested too deep (the limit is {limit} levels below the history folder)',
  'too-many-files': 'not scanned: there are too many history files (the limit is {limit} files per agent)',
  'time-limit': 'not fully scanned: the time limit was reached',
  'line-too-long': 'partly scanned: a line was too long to read',
  unreadable: 'not scanned: it could not be read',
  symlink: 'not scanned: it is a link, and links are never followed',
};

function report(r, write) {
  const w = write || ((s) => process.stdout.write(s));
  const plural = (n, word) => n + ' ' + word + (n === 1 ? '' : 's');
  w('\nzn-gate reach --history: did your coding agents keep a secret of yours in their session history?\n');
  w('Read: the local history files of your agents. Nothing was sent anywhere, nothing was changed, and no value is shown.\n\n');
  for (const a of r.agents) {
    const state = a.scanned ? plural(a.files, 'file') + ', ' + mb(a.bytes) + ' scanned'
      : a.reason === 'database' ? 'not scanned: its history is a database, which this version does not read'
        : a.reason === 'not-yet' ? 'not scanned yet: this version does not read its history'
          : 'no history found';
    w('  ' + a.name.padEnd(12) + ' ' + state + '\n');
  }
  w('\n');
  if (!r.findings.length) {
    w(r.incomplete.length ? 'Nothing found in what was scanned. Some files were not fully scanned (below).\n\n' : 'No secret found in the history files that were scanned.\n\n');
  } else {
    let last = null;
    for (const f of r.findings) {
      if (f.agent !== last) { w(r.agents.find((a) => a.id === f.agent).name.toUpperCase() + '\n'); last = f.agent; }
      w('  ' + f.file + '\n');
      w('    ' + f.count + ' x ' + f.type + '\n');
      w('    Do this: ' + f.action + '\n');
    }
    w('\n' + plural(r.totals.secrets, 'secret') + ' in ' + plural(r.totals.files_with_secrets, 'file') + '.\n\n');
  }
  if (r.incomplete.length) {
    w('NOT FULLY SCANNED\n');
    for (const i of r.incomplete) w('  ' + i.file + ': ' + (REASONS[i.reason] || i.reason).replace('{limit}', String(i.limit)) + '\n');
    if (r.totals.files_not_reached > r.incomplete.length) w('  and more files not reached\n');
    if (r.time_limit_hit) w('Run again with a larger --max-seconds to scan them (now ' + r.max_seconds + ').\n');
    w('\n');
  }
  for (const n of r.notes) w(n + '\n');
  w('\n');
  return 0;
}

module.exports = { history, report, VERSION, DEFAULT_MAX_SECONDS, MAX_SECONDS_LIMIT, _internal: { actionFor, scanFile, scanLine, cuts, overlapChars, longestSecretMatch, AGENTS, SLICE_CHARS } };
