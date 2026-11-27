'use strict';

/**
 * Tool pinning for the MCP servers that `zn-gate shield` wraps.
 *
 * A server can change what a tool says it does after you started using it
 * (a "rug pull"): a new description that tells the model to send files
 * somewhere, or a new parameter. The shield records a SHA-256 of each tool
 * definition (the whole tool object, with sorted keys) the first time it sees
 * the server, and compares every later tools/list with those pins.
 *
 *   warn  (default) a changed or new tool stays usable; its description starts
 *         with a notice for the model, and the shield writes a warning for you.
 *         This relies on the model reading the notice.
 *   block a changed or new tool is removed from the list and calls to it are
 *         refused until you approve the change. This is the control to use.
 *   off   no pinning
 *
 * The mode is the strictest of ZN_MCP_PINNING and "mcpPinning" in
 * ~/.zn/config.json: the environment of an MCP server can raise it, never
 * lower it. Approve changes with `zn-gate pins approve` in your own terminal.
 *
 * Limits: pins cover tool definitions, not the server's code; the first list
 * of a server is trusted as it is (trust on first use); a server started as
 * `npx foo@latest` can change its code under the same pins. Pin package
 * versions in your MCP configuration.
 *
 * Pins live in ~/.zn/mcp-pins/<server>.json, one file per server, mode 0600
 * on POSIX systems. They hold the program name, its arguments with secrets
 * redacted, tool names and hashes, never tool text.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MODES = ['off', 'warn', 'block']; // weakest to strictest
const MAX_NAME = 80;

/** The account's real home folder, from the system, not from $HOME (which an MCP server's environment can set). */
function accountHome() {
  try {
    const h = os.userInfo().homedir;
    if (h) return h;
  } catch (_) { /* no passwd entry */ }
  return os.homedir();
}

/** ~/.zn as the environment names it ($HOME, ZN_HOME): where pins are kept. */
function znHome() {
  if (process.env.ZN_HOME) return path.resolve(process.env.ZN_HOME);
  return path.join(os.homedir(), '.zn');
}

function pinsDir() {
  return path.join(znHome(), 'mcp-pins');
}

/** True when pins are kept somewhere else than the account's own ~/.zn (only tests and unusual setups do that). */
function pinsMoved() {
  return path.resolve(znHome()) !== path.resolve(path.join(accountHome(), '.zn'));
}

function modeName(m) {
  return typeof m === 'string' && MODES.includes(m.trim().toLowerCase()) ? m.trim().toLowerCase() : null;
}

function configMode(dir) {
  try {
    return modeName(JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8')).mcpPinning);
  } catch (_) {
    return null;
  }
}

/**
 * The mode: "mcpPinning" in the account's ~/.zn/config.json (warn when it is
 * not set), raised by a config in $HOME/ZN_HOME, ZN_MCP_PINNING or the shield
 * options when they are stricter. Only the account's own config can lower it,
 * since an MCP server's environment is written in project files an agent can
 * edit.
 */
function mode(options = {}) {
  let best = configMode(path.join(accountHome(), '.zn')) || 'warn';
  for (const m of [configMode(znHome()), modeName(options.pinning), modeName(process.env.ZN_MCP_PINNING)]) {
    if (m && MODES.indexOf(m) > MODES.indexOf(best)) best = m;
  }
  return best;
}

/** JSON with sorted object keys, so the same definition always hashes the same. */
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value === undefined ? null : value);
}

/** The whole tool object: new fields of the protocol are covered without a code change. */
function toolHash(tool) {
  return crypto.createHash('sha256').update(canonical(tool)).digest('hex');
}

/**
 * Hashes of the parts of a tool, so a change can be named: its text (name, title, description), its parameters
 * (inputSchema and outputSchema) and everything else (annotations, _meta, new protocol fields). Stored next to the whole-tool
 * hash, which stays what decides whether a tool changed.
 */
const PART_NAMES = { t: 'description', p: 'parameters', o: 'other fields' };
function partHashes(tool) {
  const rest = Object.assign({}, tool);
  const text = { name: rest.name, title: rest.title, description: rest.description };
  const params = { inputSchema: rest.inputSchema, outputSchema: rest.outputSchema };
  for (const k of ['name', 'title', 'description', 'inputSchema', 'outputSchema']) delete rest[k];
  const h = (v) => crypto.createHash('sha256').update(canonical(v)).digest('hex').slice(0, 16);
  return { t: h(text), p: h(params), o: h(rest) };
}

/** Which parts differ between the approved parts and the current ones; ['whole tool'] when no parts were recorded. */
function changedParts(before, now) {
  if (!before || typeof before !== 'object') return ['whole tool'];
  const out = Object.keys(PART_NAMES).filter((k) => before[k] !== now[k]).map((k) => PART_NAMES[k]);
  return out.length ? out : ['whole tool'];
}

/** A server name for messages: no control or format characters, bounded length. */
function displayName(name) {
  const s = String(name).replace(/[\p{C}]/gu, '?');
  return s.length > MAX_NAME ? s.slice(0, MAX_NAME) + '...' : s;
}

/** Arguments that name a file are resolved, so `node server.js` in two projects are two servers. */
function serverArgv(command, args) {
  const argv = [String(command), ...(args || []).map(String)];
  return argv.map((a, i) => {
    if (a.startsWith('-') || path.isAbsolute(a)) return a;
    if (i === 0 && !a.includes('/') && !a.includes('\\')) return a; // a program on PATH
    try {
      if (fs.statSync(path.resolve(a)).isFile()) return path.resolve(a);
    } catch (_) { /* not a file here */ }
    return a;
  });
}

function serverKey(command, args) {
  return crypto.createHash('sha256').update(JSON.stringify(serverArgv(command, args))).digest('hex').slice(0, 16);
}

/** The command for display and storage: program name and arguments with secrets redacted. */
function label(command, args) {
  const { redactSecrets } = require('./rules');
  const argv = serverArgv(command, args);
  const text = [path.basename(argv[0]), ...argv.slice(1)].join(' ');
  return displayName(redactSecrets(text).sanitized).slice(0, 200);
}

function fileOf(key) {
  return path.join(pinsDir(), key + '.json');
}

/** A map without a prototype: a tool named __proto__ or constructor is just a name. */
function dict(from) {
  const d = Object.create(null);
  if (from && typeof from === 'object') for (const k of Object.keys(from)) d[k] = from[k];
  return d;
}

/**
 * A server's pins, null when there are none, or { corrupt: true } when the file
 * is not valid pins. A read error (permissions, too many open files) is thrown,
 * so the shield treats the list as unapproved without discarding the pins.
 */
function loadServer(key) {
  let raw;
  try {
    raw = fs.readFileSync(fileOf(key), 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  try {
    const s = JSON.parse(raw);
    if (s && typeof s === 'object' && s.tools && typeof s.tools === 'object' && s.pending && typeof s.pending === 'object') {
      s.tools = dict(s.tools);
      s.pending = dict(s.pending);
      s.parts = dict(s.parts);
      return s;
    }
  } catch (_) { /* below */ }
  return { corrupt: true };
}

function saveServer(key, s) {
  const dir = pinsDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = fileOf(key);
  const tmp = file + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
  try {
    fs.writeFileSync(tmp, JSON.stringify(s, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    for (let attempt = 0; ; attempt++) {
      try {
        fs.renameSync(tmp, file);
        break;
      } catch (err) {
        // Windows refuses to replace a file another process is reading; retry briefly.
        if (attempt >= 4 || !['EPERM', 'EBUSY', 'EACCES'].includes(err.code)) throw err;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20 * (attempt + 1));
      }
    }
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) { /* renamed */ }
  }
}

/**
 * Compare one tools/list page with the pins of this server and record what
 * changed. `session.first` is set when this session pinned the server, so
 * later pages of the same session are pinned too.
 * Returns { first, flagged: Set of tool names, invalid: count }: flagged holds
 * changed, new and duplicated names; invalid counts tools without a valid name.
 */
function check(command, args, tools, session = {}) {
  const key = serverKey(command, args);
  const now = new Date().toISOString();
  const flagged = new Set();
  let invalid = 0;
  const current = dict();
  const currentParts = dict();
  const counts = dict();
  for (const t of tools) {
    if (!t || typeof t !== 'object' || typeof t.name !== 'string' || !t.name) {
      invalid++;
      continue;
    }
    counts[t.name] = (counts[t.name] || 0) + 1;
    current[t.name] = toolHash(t);
    currentParts[t.name] = partHashes(t);
  }
  for (const [name, n] of Object.entries(counts)) {
    if (n > 1) {
      flagged.add(name);
      delete current[name];
      delete currentParts[name];
    }
  }
  let s = loadServer(key);
  if (s && s.corrupt) {
    // Never trust again silently: keep the bad file aside and treat every tool as unapproved.
    try { fs.renameSync(fileOf(key), fileOf(key) + '.corrupt-' + Date.now()); } catch (_) { /* gone */ }
    s = { command: label(command, args), pinnedAt: null, tools: dict(), pending: dict(), corruptAt: now };
    session.corrupt = true;
  }
  if (!s || session.first) {
    const base = s || { command: label(command, args), pinnedAt: now, firstPinnedAt: now, tools: dict(), pending: dict() };
    Object.assign(base.tools, current);
    base.parts = Object.assign(dict(base.parts), currentParts);
    saveServer(key, base);
    if (!s) session.first = true;
    return { first: true, flagged, invalid };
  }
  let dirty = false;
  for (const [name, hash] of Object.entries(current)) {
    if (s.tools[name] === hash) {
      if (s.pending[name]) { delete s.pending[name]; dirty = true; }
      continue;
    }
    flagged.add(name);
    if (!s.pending[name] || s.pending[name].hash !== hash) {
      const known = Object.prototype.hasOwnProperty.call(s.tools, name);
      s.pending[name] = { hash, seenAt: now, parts: currentParts[name], changed: known ? changedParts(s.parts && s.parts[name], currentParts[name]) : ['new tool'] };
      dirty = true;
    }
  }
  if (dirty || session.corrupt) saveServer(key, s);
  return { first: false, flagged, invalid };
}

/** The approved names of a server, or null when the server has no pins. */
function approvedTools(command, args) {
  const s = loadServer(serverKey(command, args));
  if (!s || s.corrupt) return s && s.corrupt ? dict() : null;
  const ok = dict();
  for (const name of Object.keys(s.tools)) if (!s.pending[name]) ok[name] = true;
  return ok;
}

const MENTION_MIN = 6; // a tool name this short is an ordinary word too often to mean anything in a description
const MENTION_FIELD_CAP = 1024 * 1024;   // characters of one field read for mentions; a longer field is reported, not skipped silently

// Letters of other alphabets that look like a Latin one (Cyrillic and Greek are the usual ones), for the name comparison only.
const LOOKALIKES = {
  'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l',
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'ı': 'i', 'ɑ': 'a', 'օ': 'o', 'ɡ': 'g', 'ɩ': 'i', 'ᴅ': 'd', 'ᴏ': 'o', 'ꞇ': 't',
};
/** The form names and text are compared in: compatibility-normalised (full-width letters), lower case, no invisible format characters, lookalikes folded. */
function fold(value) {
  return String(value).normalize('NFKC').replace(/\p{Default_Ignorable_Code_Point}|\p{Cf}/gu, '').toLowerCase().replace(/[^\u0000-\u007f]/g, (c) => LOOKALIKES[c] || c);
}

/** A name that is not a single plain word (it has _, -, a digit or camel case): `send_email` is a mention in a text, `update` or `commit` is only a word. */
function distinctive(name) {
  return /[_\-0-9]/.test(name) || /[a-z][A-Z]/.test(name);
}

/**
 * Tool shadowing across servers: the other pinned servers' approved tools against this list.
 *   collisions: tools that carry exactly the name of an approved tool of another server (a later server can take over calls meant for the first)
 *   similar:    tools whose name is that of one only after folding case, full-width letters, lookalike letters and invisible characters
 *   mentions:   tools whose text (description, title, annotation title, input and output schema) names an approved tool of another server, also as
 *               mcp__<server>__<tool>, or with invisible characters inside the name (a description that steers how that other tool is used);
 *               only names that are not a single plain word (they hold _, -, a digit or camel case), since a word such as `update` is in every text
 *   tooLong:    tools with a field over MENTION_FIELD_CAP characters, of which only the first part was read
 * Warn-only: the same name on two servers can be legitimate. Only names, never text, are returned.
 */
function shadows(command, args, tools) {
  const own = serverKey(command, args);
  const others = dict();
  for (const k of servers()) {
    if (k === own) continue;
    let s;
    try { s = loadServer(k); } catch (_) { continue; }
    if (!s || s.corrupt) continue;
    for (const n of Object.keys(s.tools)) if (!s.pending[n]) (others[n] = others[n] || []).push(s.command);
  }
  const folded = dict();
  for (const n of Object.keys(others)) (folded[fold(n)] = folded[fold(n)] || []).push(n);
  const collisions = [];
  const similar = [];
  const mentions = [];
  const tooLong = [];
  const names = Object.keys(folded);
  for (const t of tools) {
    if (!t || typeof t !== 'object' || typeof t.name !== 'string') continue;
    if (others[t.name]) collisions.push({ tool: t.name, servers: others[t.name].slice(0, 5) });
    else if (folded[fold(t.name)]) similar.push({ tool: t.name, servers: others[folded[fold(t.name)][0]].slice(0, 5) });
    // Each field is read on its own, so one long field cannot push the others out of the scan.
    const parts = [t.description, t.title, t.annotations && t.annotations.title, t.inputSchema && canonical(t.inputSchema), t.outputSchema && canonical(t.outputSchema)].filter((x) => typeof x === 'string');
    if (parts.some((x) => x.length > MENTION_FIELD_CAP)) tooLong.push({ tool: t.name });
    const text = parts.map((x) => fold(x.slice(0, MENTION_FIELD_CAP))).join('\n');
    const self = fold(t.name);
    for (const n of names) {
      if (n === self || n.length < MENTION_MIN || !distinctive(folded[n][0]) || !text.includes(n)) continue;
      const esc = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (new RegExp('(^|[^a-z0-9_]|__)' + esc + '($|[^a-z0-9_])').test(text)) mentions.push({ tool: t.name, mentions: folded[n][0], servers: others[folded[n][0]].slice(0, 5) });
    }
  }
  return { collisions, similar, mentions, tooLong };
}

function servers() {
  let names = [];
  try {
    names = fs.readdirSync(pinsDir()).filter((n) => /^[0-9a-f]{16}\.json$/.test(n));
  } catch (_) { /* none */ }
  return names.map((n) => n.slice(0, 16));
}

/** Accept the pending changes of one server (full key) or of every server ('--all'). */
function approve(which) {
  const keys = which === '--all' ? servers() : servers().filter((k) => k === which);
  if (which !== '--all' && keys.length !== 1) return { approved: [], error: 'no server ' + displayName(which) };
  const approved = [];
  for (const k of keys) {
    const s = loadServer(k);
    if (!s || s.corrupt) continue;
    const names = Object.keys(s.pending);
    if (!names.length) continue;
    s.parts = dict(s.parts);
    for (const n of names) {
      s.tools[n] = s.pending[n].hash;
      if (s.pending[n].parts && typeof s.pending[n].parts === 'object') s.parts[n] = s.pending[n].parts;
      else delete s.parts[n];       // approved by a version that kept no parts: the next change names the whole tool
    }
    s.pending = {};
    s.pinnedAt = new Date().toISOString();
    saveServer(k, s);
    approved.push({ key: k, command: s.command, tools: names.map(displayName) });
  }
  return { approved };
}

function list() {
  return servers().map((key) => {
    const s = loadServer(key);
    if (!s || s.corrupt) return { key, command: '(unreadable pins file)', pinnedAt: null, tools: 0, pending: [] };
    return { key, command: s.command, pinnedAt: s.pinnedAt, firstPinnedAt: s.firstPinnedAt || null, tools: Object.keys(s.tools).length, pending: Object.keys(s.pending).map(displayName), changes: Object.keys(s.pending).slice(0, 20).map((n) => ({ tool: displayName(n), what: Array.isArray(s.pending[n].changed) ? s.pending[n].changed.filter((x) => typeof x === 'string').map(displayName).join(' and ') : 'changed' })) };
  });
}

module.exports = { mode, check, shadows, partHashes, approve, approvedTools, list, toolHash, serverKey, label, displayName, pinsDir, pinsMoved, canonical };
