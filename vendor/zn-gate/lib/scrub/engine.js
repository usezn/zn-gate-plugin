'use strict';
/**
 * Scrubber engine: scan / tokenize / detokenize. Detection is 100 % local.
 *
 *   scan(text, ctx)        -> Span[]   synchronous and pure (no vault, no I/O)
 *       Span = {start, end, type, source: 'exact'|'pattern'|'pii', name?}
 *   tokenize(text, ctx)    -> Promise<{text, replaced: [{type, token, source}]}>
 *   detokenize(text, ctx)  -> Promise<{text, restored: [token], withheld: [{token, reason, action}]}>
 *
 *   ctx = {project, agent, tool, destination, vault}
 *     destination: 'assistant'|'write_ignored'|'write_tracked'|'bash_local'|'bash_network'|'mcp_input'
 *     vault: VaultClient (lib/vault/client.js or any object with the same calls)
 *   Optional ctx fields:
 *     cwd          project root for .env* / .znrules (defaults to project when it is a directory)
 *     env, home    sources for the exact-value layer (default process.env, os.homedir())
 *     exact        false to disable the exact-value layer
 *     exactFiles   false to read the environment only (no credential files)
 *     exactValues  [{name, type, value|values}] extra exact values (scan uses these)
 *     pii          false to disable PII, or {email, phone, iban, card, dni, ssn, ipv4}
 *     detectors    compiled custom formats (lib/team/detectors.js compile()), from
 *                  a zn Team policy; they run with the secret patterns
 *
 * Layers run in this order and, on overlap, the earlier layer wins:
 *   1. exact values (known secrets; zero false positives by construction)
 *   2. secret patterns (prefix or verifiable structure)
 *   3. PII with checksum or structural validation
 *
 * Tokens: __ZN_<TYPE>_<n>__ for detected values (ordinal per project and
 * type, assigned by the vault so the same value always gets the same
 * token), __ZN_<NAME>__ for named vault secrets.
 *
 * Vault locked or absent (ctx.vault = null, or the daemon is not running):
 * tokenize never fails open. Every layer that does not need the vault still
 * runs (patterns, PII, and exact values from local sources such as the
 * environment and .env files), and each value becomes an irreversible
 * __ZN_REDACTED_<TYPE>__ marker. The result carries `locked: true` and a
 * `warning` telling the user to run `zn unlock`.
 */

const fs = require('fs');
const path = require('path');
const { findPatterns, findPii, hintsIn, SECRET_TYPES, PII_TYPES } = require('./patterns');
const { collectSources, buildMatcher } = require('./exact');
const { find: findCustom } = require('../team/detectors');
const { CODES } = require('../errors');
const { invisibleView } = require('../rules');

const TOKEN_SOURCE = '__ZN_([A-Z0-9](?:[A-Z0-9_]*[A-Z0-9])?)__';
const TOKEN_RE = new RegExp(TOKEN_SOURCE, 'g');
const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const DESTINATIONS = Object.freeze(['assistant', 'write_ignored', 'write_tracked', 'bash_local', 'bash_network', 'mcp_input']);
const PRIORITY = { exact: 0, pattern: 1, pii: 2 };
const CACHE_TTL_MS = 2000;
const EMPTY = Object.freeze([]);

/* ------------------------------------------------------------------ */
/* scan                                                                */
/* ------------------------------------------------------------------ */

const matcherCache = new WeakMap();

function matcherFor(ctx) {
  if (!ctx || ctx.exact === false) return null;
  if (ctx.exactMatcher) return ctx.exactMatcher;
  if (Array.isArray(ctx.exactValues) && ctx.exactValues.length > 0) {
    let m = matcherCache.get(ctx.exactValues);
    if (!m) { m = buildMatcher(ctx.exactValues); matcherCache.set(ctx.exactValues, m); }
    return m;
  }
  return null;
}

const KNOWN_TYPES = new Set([...SECRET_TYPES, ...PII_TYPES].map((t) => normalizeType(t)));

/* Only tokens zn could have written are protected from re-detection:
 * __ZN_<TYPE>_<n>__ and __ZN_REDACTED_<TYPE>__ for a known detector type or
 * a vault name, and __ZN_<NAME>__ for a vault name. Anything else with the
 * same shape (e.g. a key wrapped as __ZN_<key>__ to slip past) is scanned. */
function tokenRanges(text, names) {
  const ranges = [];
  if (text.indexOf('__ZN_') < 0) return ranges;
  const re = new RegExp(TOKEN_SOURCE, 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    const inner = m[1];
    const red = /^REDACTED_(.+)$/.exec(inner);
    const ord = /^(.+)_[1-9][0-9]{0,8}$/.exec(inner);
    const known = (t) => KNOWN_TYPES.has(t) || names.has(t);
    if ((red && known(red[1])) || (ord && known(ord[1])) || names.has(inner)) ranges.push([m.index, m.index + m[0].length]);
  }
  return ranges;
}

function namesOf(ctx) {
  const names = new Set();
  for (const e of (ctx && Array.isArray(ctx.exactValues) ? ctx.exactValues : EMPTY)) if (e && e.name) names.add(String(e.name));
  for (const n of (ctx && Array.isArray(ctx.secretNames) ? ctx.secretNames : EMPTY)) names.add(String(n));
  return names;
}

function insideRange(span, ranges) {
  for (const [a, b] of ranges) if (span.start >= a && span.end <= b) return true;
  return false;
}

/* Overlapping spans are grouped into clusters. A span covering the whole
 * cluster wins (highest-priority layer first); otherwise the cluster is
 * replaced as one merged span typed after its highest-priority member, so
 * no byte of any detected value survives. */
function resolveOverlaps(spans) {
  spans.sort((a, b) => a.start - b.start || b.end - a.end || PRIORITY[a.source] - PRIORITY[b.source]);
  const out = [];
  let cluster = null;
  const flush = () => {
    if (!cluster) return;
    const { start, end, members } = cluster;
    if (members.length === 1) { out.push(members[0]); return; }
    const covering = members.filter((m) => m.start === start && m.end === end);
    const pool = covering.length > 0 ? covering : members;
    let best = pool[0];
    for (const m of pool) {
      if (PRIORITY[m.source] < PRIORITY[best.source] ||
          (PRIORITY[m.source] === PRIORITY[best.source] && (m.end - m.start) > (best.end - best.start))) best = m;
    }
    if (covering.length > 0) { out.push(best); return; }
    const merged = { start, end, type: best.type, source: best.source, merged: true };
    if (best.name) merged.name = best.name;
    out.push(merged);
  };
  for (const s of spans) {
    if (!cluster || s.start >= cluster.end) {
      flush();
      cluster = { start: s.start, end: s.end, members: [s] };
    } else {
      cluster.end = Math.max(cluster.end, s.end);
      cluster.members.push(s);
    }
  }
  flush();
  return out;
}

/**
 * scan(text, ctx) -> Span[]. Synchronous and pure: it never calls the vault.
 * The exact-value layer only sees what the caller already resolved in
 * ctx.exactValues (or ctx.exactMatcher). Callers that use scan directly,
 * such as the UserPromptSubmit hook (decidePrompt), must first run
 * `ctx = await prepare(ctx)`, which fetches vault and local exact values;
 * otherwise only patterns and PII are checked.
 */
function scan(text, ctx) {
  if (typeof text !== 'string') throw new TypeError('scan(text, ctx): text must be a string');
  if (text.length === 0) return [];
  const c = ctx || {};
  // Invisible characters (zero-width, variation selectors, tag characters) can
  // split a value or a token. The text is scanned as it is and without them;
  // the spans of the second scan are mapped back to the original text, and the
  // union is resolved as one set of spans.
  const direct = scanText(text, c);
  const view = invisibleView(text);
  if (!view) return direct;
  const viaView = scanText(view.clean, c).map((s) => ({
    ...s,
    start: view.map[s.start],
    end: s.end > s.start ? view.map[s.end - 1] + 1 : view.map[s.start],
  }));
  return resolveOverlaps(direct.concat(viaView));
}

function scanText(text, c) {
  let spans = [];
  const matcher = matcherFor(c);
  if (matcher) spans = spans.concat(matcher.find(text));
  const opts = { pii: c.pii, _hints: hintsIn(text) };
  spans = spans.concat(findPatterns(text, opts));
  if (Array.isArray(c.detectors) && c.detectors.length) spans = spans.concat(findCustom(text, c.detectors));
  if (c.pii !== false) spans = spans.concat(findPii(text, opts));
  if (spans.length === 0) return spans;
  const ranges = tokenRanges(text, namesOf(c));
  if (ranges.length > 0) spans = spans.filter((s) => !insideRange(s, ranges));
  return resolveOverlaps(spans).map((s) => {
    const out = { start: s.start, end: s.end, type: normalizeType(s.type), source: s.source };
    if (s.name) out.name = s.name;
    if (s.vault) out.vault = true;
    if (s.variant) out.variant = s.variant;
    if (s.merged) out.merged = true;
    return out;
  });
}

function normalizeType(type) {
  return String(type || 'SECRET').toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'SECRET';
}

/* ------------------------------------------------------------------ */
/* prepare: exact-value sources (local files + vault), cached briefly  */
/* ------------------------------------------------------------------ */

const localCache = new Map();   // key -> {at, entries}
const vaultCache = new WeakMap(); // vault -> Map(project -> {at, entries, locked})

function projectDir(ctx) {
  if (ctx.cwd) return ctx.cwd;
  if (typeof ctx.project === 'string' && path.isAbsolute(ctx.project)) {
    try { if (fs.statSync(ctx.project).isDirectory()) return ctx.project; } catch (err) { /* not a dir */ }
  }
  return null;
}

function localEntries(ctx) {
  const cwd = projectDir(ctx);
  const key = [cwd || '', ctx.home || '', ctx.exactFiles === false ? 'env' : 'all', ctx.env ? 'custom' : 'process'].join('\0');
  const now = Date.now();
  const hit = localCache.get(key);
  if (hit && hit.env === (ctx.env || process.env) && now - hit.at < CACHE_TTL_MS) return hit.entries;
  const entries = collectSources({ env: ctx.env, cwd, home: ctx.home, files: ctx.exactFiles !== false });
  localCache.set(key, { at: now, entries, env: ctx.env || process.env });
  return entries;
}

async function vaultEntries(ctx) {
  const vault = ctx.vault;
  if (!vault || typeof vault.exactValues !== 'function') return { entries: [], locked: !vault };
  let perVault = vaultCache.get(vault);
  if (!perVault) { perVault = new Map(); vaultCache.set(vault, perVault); }
  const project = String(ctx.project || '');
  const now = Date.now();
  const hit = perVault.get(project);
  if (hit && now - hit.at < CACHE_TTL_MS) return hit;
  let res;
  try {
    const list = await vault.exactValues(project);
    res = { at: now, entries: (Array.isArray(list) ? list : []).map((e) => Object.assign({}, e, { vault: true })), locked: false };
  } catch (err) {
    res = { at: now, entries: [], locked: true, error: err };
  }
  perVault.set(project, res);
  return res;
}

/**
 * prepare(ctx) -> Promise<ctx'> with the exact-value matcher attached, so
 * callers can run the synchronous scan() with every layer.
 */
async function prepare(ctx) {
  const c = Object.assign({}, ctx || {});
  if (c.exact === false || c.exactPrepared) return c;
  const local = localEntries(c);
  const fromVault = await vaultEntries(c);
  const extra = Array.isArray(c.exactValues) ? c.exactValues : EMPTY;
  const all = fromVault.entries.concat(local, extra);
  // scan() stays pure: it receives the resolved exact values in
  // ctx.exactValues (and their compiled matcher, cached here).
  c.exactValues = all;
  c.exactMatcher = all.length > 0 ? cachedMatcher(all, fromVault, local, extra) : null;
  c.exactPrepared = true;
  c.vaultLocked = fromVault.locked;
  return c;
}

let lastMatcher = { parts: null, matcher: null };
function cachedMatcher(all, fromVault, local, extra) {
  const parts = [fromVault.entries, local, extra];
  const prev = lastMatcher.parts;
  if (prev && prev[0] === parts[0] && prev[1] === parts[1] && prev[2] === parts[2]) return lastMatcher.matcher;
  const matcher = buildMatcher(all);
  lastMatcher = { parts, matcher };
  return matcher;
}

/* ------------------------------------------------------------------ */
/* tokenize                                                            */
/* ------------------------------------------------------------------ */

function isToken(s) {
  return typeof s === 'string' && new RegExp('^' + TOKEN_SOURCE + '$').test(s);
}

const { znCommand } = require('../zn-command');

const LOCKED_WARNING = 'Your secret vault is locked, so the hidden secret values cannot be put back afterwards. ' +
  'To keep them restorable next time, unlock it in your terminal with: ' + znCommand('unlock');

function expectedToken(type) {
  return new RegExp('^__ZN_' + normalizeType(type) + '_[1-9][0-9]{0,8}__$');
}

/* Irreversible marker used when the vault cannot mint a token. */
function lockedToken(type) {
  return '__ZN_REDACTED_' + type + '__';
}

async function tokenize(text, ctx) {
  if (typeof text !== 'string') throw new TypeError('tokenize(text, ctx): text must be a string');
  const c = await prepare(ctx);
  const spans = scan(text, c);
  if (spans.length === 0) return { text, replaced: [] };

  const vault = c.vault;
  const project = String(c.project || '');
  const memo = new Map();
  let locked = false;

  async function tokenFor(span, value) {
    if (span.vault && span.variant === 'raw' && !span.merged && NAME_RE.test(String(span.name || ''))) {
      return '__ZN_' + span.name + '__';
    }
    const type = span.vault && NAME_RE.test(String(span.name || '')) ? span.name : span.type;
    const key = type + '\0' + value;
    if (memo.has(key)) return memo.get(key);
    let token = null;
    if (vault && typeof vault.mapToken === 'function') {
      try {
        token = await vault.mapToken(project, type, value);
      } catch (err) {
        token = null;
        locked = true;
      }
    } else {
      locked = true;
    }
    // Fail closed: only the exact shape __ZN_<TYPE>_<n>__ for the type we
    // asked for is accepted. Anything else (which could smuggle the value
    // in any encoding) becomes an irreversible redaction.
    if (!isToken(token) || !expectedToken(type).test(token)) token = lockedToken(type);
    memo.set(key, token);
    return token;
  }

  let out = '';
  let last = 0;
  const replaced = [];
  for (const s of spans) {
    const value = text.slice(s.start, s.end);
    const token = await tokenFor(s, value);
    out += text.slice(last, s.start) + token;
    last = s.end;
    replaced.push({ type: s.type, token, source: s.source });
  }
  out += text.slice(last);
  const result = { text: out, replaced };
  if (locked) {
    result.locked = true;
    result.warning = LOCKED_WARNING;
  }
  return result;
}

/* ------------------------------------------------------------------ */
/* detokenize                                                          */
/* ------------------------------------------------------------------ */

/* Restoration policy per destination.
 *   detected: __ZN_<TYPE>_<n>__   named: __ZN_<NAME>__ (vault secrets)
 * Values are reasons for withholding; 'restore' restores. */
const POLICY = Object.freeze({
  assistant:     { detected: 'restore', named: 'restore' },
  write_ignored: { detected: 'restore', named: 'restore' },
  write_tracked: { detected: 'tracked_file', named: 'tracked_file' },
  bash_local:    { detected: 'restore', named: 'use_broker' },
  bash_network:  { detected: 'network', named: 'network' },
  mcp_input:     { detected: 'mcp_input', named: 'mcp_input' },
});

/* What the caller should do with a withheld token. */
const ACTIONS = Object.freeze({
  tracked_file: 'keep',        // leave the token in the versioned file and warn
  use_broker: 'broker',        // named secret in a command: run it through `zn run`
  network: 'ask',              // network command: ask the user
  mcp_input: 'ask',
  unknown_destination: 'keep',
  unknown_token: 'keep',
  not_restorable: 'keep',
  locked: 'keep',
  vault_error: 'keep',
});

const NET_COMMANDS = new RegExp('(?:^|[\\s;&|()`$\'"])(?:' + [
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ssh', 'scp', 'sftp', 'rsync', 'ftp', 'tftp',
  'nslookup', 'dig', 'ping', 'ping6', 'traceroute', 'xh', 'httpie', 'aria2c', 'lynx', 'w3m',
  'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm', 'Start-BitsTransfer', 'bitsadmin', 'certutil',
  'gh', 'aws', 'gcloud', 'gsutil', 'az', 'doctl', 'heroku', 'vercel', 'netlify', 'flyctl', 'kubectl', 'helm',
].join('|') + ')(?=$|[\\s;&|)\'"`])', 'i');
const NET_SUBCOMMANDS = /\b(?:git\s+(?:push|fetch|pull|clone|ls-remote|remote\s+(?:add|set-url)|submodule)|docker\s+(?:push|login|pull)|podman\s+(?:push|login)|npm\s+(?:publish|login|adduser)|yarn\s+(?:publish|npm\s+publish)|pnpm\s+publish|twine\s+upload|openssl\s+s_client)\b/i;
const NET_URL = /\b(?:https?|ftps?|wss?|sftp|ssh|git|smb|ldaps?|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?):\/\/[^\s/]*[A-Za-z0-9]/i;
const NET_SOCKET = /\/dev\/(?:tcp|udp)\/|\b(?:Net\.WebClient|System\.Net\.|urllib\.request|http\.client|requests\.(?:get|post|put|patch|delete)|socket\.socket|net\.connect|fetch\s*\()/;
// HTTP and socket libraries in inline code (node -e, python -c, ruby -e ...),
// where no URL or network command appears on the command line.
const NET_CODE = new RegExp([
  'require\\s*\\(\\s*[\'"`](?:node:)?(?:https?|http2|net|tls|dgram|dns|undici|axios|node-fetch|got|ws|request)[\'"`]\\s*\\)',
  'import\\s*\\(?\\s*[\'"`](?:node:)?(?:https?|http2|net|tls|dgram|undici|axios|node-fetch|got|ws)[\'"`]',
  'from\\s+[\'"`](?:node:)?(?:https?|http2|net|tls|dgram|undici|axios|node-fetch|got|ws)[\'"`]',
  '\\b(?:import|from)\\s+(?:requests|urllib3?|httpx|aiohttp|socket|http\\.client|httplib2|pycurl|smtplib|ftplib|websockets?)\\b',
  '\\b(?:https?|http2|net|tls|dgram)\\.(?:request|get|connect|createConnection|createSocket)\\s*\\(',
  '\\b(?:axios|got|superagent|undici)(?:\\.\\w+)?\\s*\\(',
  '\\b(?:XMLHttpRequest|WebSocket|EventSource)\\b',
  '\\bNet::HTTP\\b|\\bTCPSocket\\b|\\bopen-uri\\b|\\bIO::Socket\\b|\\bLWP::|\\bHTTP::Tiny\\b|\\bfile_get_contents\\s*\\(\\s*[\'"]https?:',
].join('|'));

/** true when a shell command shows network signals (commands, URLs, sockets). */
function isNetworkCommand(cmd) {
  if (typeof cmd !== 'string' || !cmd) return false;
  return NET_COMMANDS.test(cmd) || NET_SUBCOMMANDS.test(cmd) || NET_URL.test(cmd) || NET_SOCKET.test(cmd) || NET_CODE.test(cmd);
}

function effectiveDestination(ctx, text) {
  const dest = ctx && ctx.destination;
  if (!DESTINATIONS.includes(dest)) return null;
  // Defence in depth: a "local" command with network signals is treated as
  // a network command, whatever the caller classified it as.
  if (dest === 'bash_local' && isNetworkCommand(text)) return 'bash_network';
  return dest;
}

async function safeAudit(vault, event) {
  if (!vault || typeof vault.audit !== 'function') return;
  try { await vault.audit(event); } catch (err) { /* audit is best effort here */ }
}

async function detokenize(text, ctx) {
  if (typeof text !== 'string') throw new TypeError('detokenize(text, ctx): text must be a string');
  const c = ctx || {};
  const restored = [];
  const withheld = [];
  if (text.indexOf('__ZN_') < 0) return { text, restored, withheld };

  const dest = effectiveDestination(c, text);
  const vault = c.vault;
  const project = String(c.project || '');
  const decisions = new Map(); // token -> {value} | {reason}

  const re = new RegExp(TOKEN_SOURCE, 'g');
  const found = [];
  let m;
  while ((m = re.exec(text)) !== null) found.push({ start: m.index, end: m.index + m[0].length, token: m[0], inner: m[1] });

  for (const f of found) {
    if (decisions.has(f.token)) continue;
    const ordinal = /_(\d+)$/.exec(f.inner);
    const kind = ordinal ? 'detected' : 'named';
    let reason = null;
    if (f.inner.startsWith('REDACTED_') || (ordinal && ordinal[1] === '0')) reason = 'not_restorable';
    else if (!dest) reason = 'unknown_destination';
    else if (POLICY[dest][kind] !== 'restore') reason = POLICY[dest][kind];
    // A versioned file keeps tokens, except when the value is already in
    // that file (an edit near an existing literal): restoring it adds no
    // new exposure and keeps the edit from corrupting the file.
    const trackedCheck = reason === 'tracked_file' && typeof c.trackedContent === 'string' && c.trackedContent.length > 0;
    if (trackedCheck) reason = null;
    let value = null;
    if (!reason) {
      if (!vault || typeof vault.resolve !== 'function') {
        reason = 'locked';
      } else {
        try {
          value = await vault.resolve(project, f.token, { destination: dest, agent: c.agent, tool: c.tool });
          if (value === null || value === undefined) reason = 'unknown_token';
          else if (typeof value !== 'string') { reason = 'vault_error'; value = null; }
        } catch (err) {
          reason = err && err.code === CODES.LOCKED ? 'locked' : 'vault_error';
        }
      }
      if (trackedCheck && !reason && !c.trackedContent.includes(value)) { reason = 'tracked_file'; value = null; }
      if (trackedCheck && reason && reason !== 'tracked_file') reason = 'tracked_file';
    }
    decisions.set(f.token, reason ? { reason } : { value });
    await safeAudit(vault, {
      secret: f.inner,
      mode: kind === 'named' ? 'named' : 'detected',
      agent: c.agent,
      tool: c.tool,
      decision: reason ? (ACTIONS[reason] === 'ask' ? 'ask' : 'withhold') : 'restore',
      reason: reason || dest,
    });
  }

  let out = '';
  let last = 0;
  const seenRestored = new Set();
  const seenWithheld = new Set();
  for (const f of found) {
    const d = decisions.get(f.token);
    out += text.slice(last, f.start);
    if (d.reason) {
      out += f.token;
      if (!seenWithheld.has(f.token)) {
        seenWithheld.add(f.token);
        withheld.push({ token: f.token, reason: d.reason, action: ACTIONS[d.reason] || 'keep' });
      }
    } else {
      out += d.value;
      if (!seenRestored.has(f.token)) { seenRestored.add(f.token); restored.push(f.token); }
    }
    last = f.end;
  }
  out += text.slice(last);
  return { text: out, restored, withheld };
}

module.exports = {
  scan,
  tokenize,
  detokenize,
  // helpers for hooks and broker (not part of the frozen contract)
  prepare,
  isNetworkCommand,
  TOKEN_RE,
  DESTINATIONS,
  POLICY,
  ACTIONS,
  LOCKED_WARNING,
};
