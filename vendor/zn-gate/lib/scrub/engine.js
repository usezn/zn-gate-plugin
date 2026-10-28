'use strict';
/**
 * Scrubber engine: scan / tokenize / detokenize. Detection is 100 % local.
 *
 *   scan(text, ctx)        -> Span[]   synchronous and pure (no vault, no I/O)
 *   scanAsync(text, ctx)   -> Promise<Span[]>   scan with the vault's values too (the daemon matches them)
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
 *     pii          false to disable PII, or {email, phone, iban, card, dni, ssn, ipv4, name, address, username}
 *     types        a Set (or Map) of span types: only spans of these types are kept, before
 *                  overlaps are resolved, so a span of another type cannot hide one of them
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
const { collectSources, buildMatcher, MIN_LENGTH } = require('./exact');
const { find: findCustom } = require('../team/detectors');
const { CODES } = require('../errors');
const { warnNotice, WARN_REASON } = require('../team/effective');
/* The vault's resolve-policy answer version this engine understands. */
const RESOLVE_POLICY = 1;
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
  // The vault's own values are matched in the daemon (scanAsync fetched where they occur in this text). A prepared
  // context that has no answer for this text means the caller used scan() where it needed scanAsync(): refuse.
  if (c.vaultRemote) {
    const fromVault = c.vaultSpans && c.vaultSpans.get(text);
    if (fromVault === undefined) throw new Error('scan: the vault matches for this text were not fetched (use scanAsync)');
    spans = spans.concat(fromVault);
  }
  const opts = { pii: c.pii, _hints: hintsIn(text) };
  spans = spans.concat(findPatterns(text, opts));
  if (Array.isArray(c.detectors) && c.detectors.length) spans = spans.concat(findCustom(text, c.detectors));
  if (c.pii !== false) spans = spans.concat(findPii(text, opts));
  if (spans.length === 0) return spans;
  const ranges = tokenRanges(text, namesOf(c));
  if (ranges.length > 0) spans = spans.filter((s) => !insideRange(s, ranges));
  if (c.types) spans = spans.filter((s) => c.types.has(normalizeType(s.type)));
  return resolveOverlaps(spans).map((s) => {
    const out = { start: s.start, end: s.end, type: normalizeType(s.type), source: s.source };
    if (s.name) out.name = s.name;
    if (s.vault) out.vault = true;
    if (s.variant) out.variant = s.variant;
    if (s.merged) out.merged = true;
    if (s.quote && !s.merged) out.quote = s.quote;
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

function vaultUnavailableOnPurpose(err) {
  return !!err && err.code === CODES.LOCKED && err.vaultUnanswered !== true;
}

function vaultInfoFailure(err) {
  const why = String((err && err.message) || 'unknown error');
  return Object.assign(new Error('zn could not read what your secret vault protects (' + why + '), so it cannot check this against your vault values. ' +
    'Make sure the vault is running and unlocked (zn unlock), then try again.'), { code: CODES.LOCKED, vaultFailed: true, vaultUnanswered: true, cause: err });
}


/* What the vault contributes to the exact layer. The values never leave the vault daemon: maskInfo says which secret
 * names and how many needles it has (and the longest, for the streaming scrubber), and scanAsync asks maskSpans
 * where they occur in each text. {remote, names, longest, count, entries, locked}. `entries` is only filled by a vault
 * started by an older zn-gate, which answers no maskInfo and hands its values to exactValues instead. */
async function vaultEntries(ctx) {
  const vault = ctx.vault;
  const none = { remote: false, entries: [], names: [], longest: 0, count: 0, shortCount: 0 };
  if (!vault || (typeof vault.maskInfo !== 'function' && typeof vault.exactValues !== 'function')) return Object.assign({ locked: !vault }, none);
  let perVault = vaultCache.get(vault);
  if (!perVault) { perVault = new Map(); vaultCache.set(vault, perVault); }
  const project = String(ctx.project || '');
  const now = Date.now();
  const hit = perVault.get(project);
  if (hit && now - hit.at < CACHE_TTL_MS) return hit;
  const legacy = async () => {
    const list = await vault.exactValues(project);
    return Object.assign({}, none, { at: now, locked: false, entries: (Array.isArray(list) ? list : []).map((e) => Object.assign({}, e, { vault: true })) });
  };
  let res;
  try {
    if (typeof vault.maskInfo === 'function') {
      try {
        const info = await vault.maskInfo(project, { agent: ctx.agent, tool: ctx.tool });
        // A wrong shape (null, a string, names that are not a list) is not an empty vault: it is a failure.
        if (!info || typeof info !== 'object' || Array.isArray(info) || (info.names !== undefined && !Array.isArray(info.names))) {
          throw vaultInfoFailure(new Error('the vault answered with an unexpected reply'));
        }
        res = {
          at: now, locked: false, remote: true, entries: [],
          names: Array.isArray(info && info.names) ? info.names.map(String) : [],
          longest: Number(info && info.longest) || 0,
          count: Number(info && info.count) || 0,
          shortCount: Number(info && info.shortCount) || 0,
        };
      } catch (err) {
        if (!(err && err.message === 'unknown operation') || typeof vault.exactValues !== 'function') throw err;
        res = await legacy();
      }
    } else {
      res = await legacy();
    }
  } catch (err) {
    // Not available on purpose (the daemon is not running, or it says it is locked): the vault adds nothing and the
    // built-in layers still run. Anything else (no answer, bad reply, a refusal) is a failure to read what the vault
    // protects: propagate it, so the hook denies instead of scanning without the vault's values.
    if (!vaultUnavailableOnPurpose(err)) throw (err && err.vaultFailed ? err : vaultInfoFailure(err));
    res = Object.assign({}, none, { at: now, locked: true, error: err });
  }
  perVault.set(project, res);
  return res;
}

const SPAN_CHUNK = 2 * 1024 * 1024;
const SPAN_REQUEST_CHARS = 4 * 1024 * 1024;
const SPAN_REQUEST_TEXTS = 1024;

/* Where the vault's values occur in each of `texts`, from the daemon: Map text -> Span[] (a text too short to hold a
 * value maps to none). A text over SPAN_CHUNK goes in overlapping pieces, so a value on a cut is still found. When the
 * vault does not answer, `failed` is true and scanChecked throws, so no text is passed as clean. */
async function fetchVaultSpans(c, texts) {
  const r = c.vaultRemote;
  const map = new Map();
  const pieces = []; // {text, base, piece}
  for (const t of texts) {
    if (map.has(t)) continue;
    // A text under the minimum can only be a short value from an older version (compared exactly, whole text).
    if (t.length === 0 || (t.length < MIN_LENGTH && !(r.shortCount > 0))) { map.set(t, EMPTY); continue; }
    const mine = { parts: [], spans: [] };
    map.set(t, mine);
    if (t.length <= SPAN_CHUNK) { pieces.push({ text: t, base: 0, owner: mine }); continue; }
    const step = Math.max(SPAN_CHUNK - Math.max(r.longest, 1), SPAN_CHUNK / 2);
    for (let base = 0; base < t.length; base += step) {
      pieces.push({ text: t.slice(base, base + SPAN_CHUNK), base, owner: mine });
      if (base + SPAN_CHUNK >= t.length) break;
    }
  }
  let failed = false;
  const batches = [];
  let cur = [];
  let chars = 0;
  for (const p of pieces) {
    if (cur.length && (cur.length >= SPAN_REQUEST_TEXTS || chars + p.text.length > SPAN_REQUEST_CHARS)) { batches.push(cur); cur = []; chars = 0; }
    cur.push(p);
    chars += p.text.length;
  }
  if (cur.length) batches.push(cur);
  await Promise.all(batches.map(async (batch) => {
    try {
      const got = await r.vault.maskSpans(r.project, batch.map((p) => p.text), r.claim);
      if (!Array.isArray(got) || got.length !== batch.length) throw new Error('unexpected maskSpans answer');
      batch.forEach((p, i) => { p.owner.parts.push({ base: p.base, spans: Array.isArray(got[i]) ? got[i] : [] }); });
    } catch (err) {
      failed = true;
    }
  }));
  for (const [t, v] of map) {
    if (v === EMPTY) continue;
    const seen = new Set();
    const spans = [];
    for (const part of v.parts.sort((a, b) => a.base - b.base)) {
      for (const s of part.spans) {
        const span = Object.assign({}, s, { start: s.start + part.base, end: s.end + part.base, vault: true });
        const key = span.start + ':' + span.end + ':' + span.name + ':' + span.variant + ':' + span.type;
        if (seen.has(key)) continue;
        seen.add(key);
        spans.push(span);
      }
    }
    map.set(t, spans);
  }
  return { map, failed };
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
  // scan() stays pure: it receives the local exact values in ctx.exactValues
  // (and their compiled matcher, cached here). The vault's own values are
  // matched by the daemon: scanAsync() fetches the spans of each text.
  c.exactValues = all;
  c.exactMatcher = all.length > 0 ? cachedMatcher(all, fromVault, local, extra) : null;
  c.exactPrepared = true;
  c.vaultLocked = fromVault.locked;
  if (fromVault.names.length) c.secretNames = (Array.isArray(c.secretNames) ? c.secretNames : EMPTY).concat(fromVault.names);
  c.vaultLongest = fromVault.longest;
  c.vaultRemote = fromVault.remote && (fromVault.count > 0 || fromVault.shortCount > 0) ? { vault: c.vault, project: String(c.project || ''), claim: { agent: c.agent, tool: c.tool }, longest: fromVault.longest, shortCount: fromVault.shortCount } : null;
  return c;
}

/* scan() for a prepared context, with the vault's matches: the daemon says where its values occur in the text (and in
 * the text without invisible characters, which scan() also reads). -> {spans}. When the vault does not answer it throws
 * (ZN_LOCKED, vaultFailed): a text scanned without the vault's values would look clean, so the caller must hold the
 * text back (the post-hook withholds it, the other hooks follow their fail mode, the stream writes a notice). */
async function scanChecked(text, c) {
  if (!c.vaultRemote || text.length === 0) return { spans: scan(text, c) };
  const view = invisibleView(text);
  const want = view ? [text, view.clean] : [text];
  const memo = c.vaultMemo;
  const missing = memo ? want.filter((t) => !memo.has(t)) : want;
  const got = missing.length ? await fetchVaultSpans(c, missing) : { map: new Map(), failed: false };
  if (got.failed) throw Object.assign(new Error('the vault did not answer, so this text was not checked against its values'), { code: CODES.LOCKED, vaultFailed: true });
  const map = new Map();
  for (const t of want) map.set(t, memo && memo.has(t) ? memo.get(t) : got.map.get(t));
  return { spans: scan(text, Object.assign({}, c, { vaultSpans: map })) };
}

/**
 * warm(ctx, texts) -> Promise<ctx'>: asks the vault daemon about all of `texts` in one request, so that the scanAsync()
 * calls that follow on the returned context do not make one round trip each. Optional: scanAsync fetches what is
 * missing. When the vault does not answer, nothing is remembered and scanAsync reports it.
 */
async function warm(ctx, texts) {
  const c = await prepare(ctx);
  if (!c.vaultRemote) return c;
  const all = new Set();
  for (const t of texts) {
    if (typeof t !== 'string' || t.length === 0 || (t.length < MIN_LENGTH && !(c.vaultRemote.shortCount > 0))) continue;
    all.add(t);
    const view = invisibleView(t);
    if (view) all.add(view.clean);
  }
  if (all.size === 0) return c;
  const { map, failed } = await fetchVaultSpans(c, [...all]);
  if (failed) return c;
  return Object.assign({}, c, { vaultMemo: new Map([...(c.vaultMemo || []), ...map]) });
}

/**
 * scanAsync(text, ctx) -> Promise<Span[]>: scan() with every layer, the vault's included. Prepares the context when
 * it is not, and asks the vault daemon where its values occur in `text`. Use it wherever the vault may be unlocked.
 */
async function scanAsync(text, ctx) {
  if (typeof text !== 'string') throw new TypeError('scanAsync(text, ctx): text must be a string');
  return (await scanChecked(text, await prepare(ctx))).spans;
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
  return tokenizeWith(text, ctx);
}

// tokenize, for a caller that has already scanned this text with the same context (it passes the spans, so the
// text is not scanned twice). Not part of the public contract.
async function tokenizeWith(text, ctx, spansOfText) {
  if (typeof text !== 'string') throw new TypeError('tokenize(text, ctx): text must be a string');
  const c = await prepare(ctx);
  // A caller that has already scanned this text with the same context can pass the spans, so the text is not scanned twice.
  let locked = false;
  let spans = spansOfText;
  if (!Array.isArray(spans)) spans = (await scanChecked(text, c)).spans;
  if (spans.length === 0) return { text, replaced: [] };

  const vault = c.vault;
  const project = String(c.project || '');
  const memo = new Map();

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
    // A bare JSON number under a quoted key becomes a string, so the JSON stays valid.
    out += text.slice(last, s.start) + (s.quote ? s.quote + token + s.quote : token);
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
  org_deny: 'keep',            // the organization policy blocks this secret
  vault_outdated: 'keep',      // the vault process predates the organization policy check
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
    let warn = null;
    if (!reason) {
      if (!vault || typeof vault.resolve !== 'function') {
        reason = 'locked';
      } else {
        try {
          // withPolicy: the vault applies the organization policy and says so
          // ({value, policy: 1, ...}). A vault that answers with the bare value
          // (a daemon started before an update) cannot have checked the policy:
          // nothing is restored (fail closed, vault_outdated) until it is restarted.
          value = await vault.resolve(project, f.token, { destination: dest, agent: c.agent, tool: c.tool, withPolicy: true });
          if (typeof value === 'string' || (value !== null && typeof value === 'object' && value.policy === undefined)) {
            reason = 'vault_outdated';
            value = null;
          } else if (value !== null && typeof value === 'object' && value.policy !== RESOLVE_POLICY) {
            reason = 'vault_error';
            value = null;
          } else if (value !== null && typeof value === 'object') {
            const got = value;
            value = got.deny === true ? null : got.value;
            if (got.deny === true) reason = 'org_deny';
            else if (got.warn === true) {
              // A scrubber token names the stored secret it matched (warnName) in the notice.
              const name = kind === 'named' || typeof got.warnName !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(got.warnName) ? f.inner : got.warnName;
              warn = { reason: typeof got.warnReason === 'string' ? got.warnReason : undefined, name };
            }
          }
          if (reason) value = null;
          else if (value === null || value === undefined) reason = 'unknown_token';
          else if (typeof value !== 'string') { reason = 'vault_error'; value = null; }
        } catch (err) {
          reason = err && err.code === CODES.LOCKED ? 'locked' : 'vault_error';
        }
      }
      if (trackedCheck && !reason && !c.trackedContent.includes(value)) { reason = 'tracked_file'; value = null; }
      if (trackedCheck && reason && reason !== 'tracked_file') reason = 'tracked_file';
    }
    if (reason) warn = null;
    decisions.set(f.token, reason ? { reason } : { value, warn });
    await safeAudit(vault, {
      secret: f.inner,
      mode: kind === 'named' ? 'named' : 'detected',
      agent: c.agent,
      tool: c.tool,
      decision: reason ? (ACTIONS[reason] === 'ask' ? 'ask' : 'withhold') : (warn ? 'warn' : 'restore'),
      reason: reason || (warn ? WARN_REASON : dest),
    });
  }

  let out = '';
  let last = 0;
  const seenRestored = new Set();
  const seenWithheld = new Set();
  const notices = [];
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
      if (!seenRestored.has(f.token)) {
        seenRestored.add(f.token);
        restored.push(f.token);
        if (d.warn) notices.push(warnNotice(d.warn.name || f.inner, d.warn.reason));
      }
    }
    last = f.end;
  }
  out += text.slice(last);
  // notices: lines for the user and the agent (a `warn` rule of the organization policy).
  return notices.length ? { text: out, restored, withheld, notices } : { text: out, restored, withheld };
}

module.exports = {
  tokenizeWith,
  scanAsync,
  warm,
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
