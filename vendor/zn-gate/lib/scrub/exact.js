'use strict';
/**
 * Exact-value layer: values the user already holds as secrets.
 *
 * Sources (local only, read on the user's machine, never sent anywhere):
 *   - process environment variables with a sensitive name
 *   - .env* files in the project root (not .env.example / .sample / .template / .dist)
 *   - ~/.aws/credentials, ~/.npmrc, ~/.netrc, ~/.docker/config.json, ~/.config/gh/hosts.yml
 *   - `secret:` lines of the project's .znrules
 *   - the vault (named secrets), passed in by the caller
 *
 * Rules:
 *   - values shorter than 8 characters are ignored
 *   - URLs with credentials contribute only their password (host, port and
 *     database stay readable)
 *   - values that are obviously not secrets (booleans, numbers, plain URLs,
 *     paths, host names) are ignored even under a sensitive name
 *   - each value is searched as raw, base64 (padded, unpadded, url-safe),
 *     hex (lower and upper) and URL-encoded
 *
 * Search is Aho-Corasick over all variants at once: one pass over the text,
 * independent of the number of values.
 *
 * Nothing here writes to disk. Collected values live in memory only.
 */

const fs = require('fs');
const { stripInlineComment, trimTrailing, npmAuth, znrulesValue } = require('../linear-text');
const os = require('os');
const path = require('path');

const MIN_LENGTH = 8;
const MAX_FILE_BYTES = 256 * 1024;

/* ------------------------------------------------------------------ */
/* Names and values                                                    */
/* ------------------------------------------------------------------ */

/* A name segment that ends in a sensitive word: API_KEY, PGPASSWORD,
 * GITHUB_TOKEN, SENTRY_DSN, DB_PASS... */
const SENSITIVE_NAME_RE = /(?:^|_)[A-Z0-9]*(?:KEY|SECRET|SECRETS|TOKEN|TOKENS|PASS|PASSWD|PASSWORD|PASSPHRASE|PWD|CREDENTIAL|CREDENTIALS|AUTH|DSN)(?:_|$)|(?:^|_)DATABASE_URL$/i;
const NON_SECRET_NAMES = new Set(['PWD', 'OLDPWD', 'SSH_AUTH_SOCK', 'GPG_AGENT_INFO', 'XAUTHORITY', 'KEYTIMEOUT', 'GNUPGHOME', 'GIT_ASKPASS', 'SSH_ASKPASS', 'SUDO_ASKPASS', 'AUTH_SOCK', 'KEYBOARD', 'KEYMAP', 'TOKENIZERS_PARALLELISM']);

function isSensitiveName(name) {
  if (!name) return false;
  const upper = String(name).toUpperCase();
  if (NON_SECRET_NAMES.has(upper)) return false;
  if (/(?:_PATH|_FILE|_DIR|_HOME|_URL_BASE|_ENDPOINT|_HOST|_PORT|_REGION|_ID|_USER|_USERNAME|_NAME|_TYPE|_MODE|_ENABLED|_TIMEOUT|_TTL|_SOCK)$/.test(upper) && !/DATABASE_URL$/.test(upper)) {
    return false;
  }
  return SENSITIVE_NAME_RE.test(upper);
}

function shannon(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

/* Values that are not secrets even under a sensitive name. */
function looksNonSecret(value) {
  const v = value.trim();
  if (v.length < MIN_LENGTH) return true;
  if (/^(?:true|false|yes|no|on|off|null|none|undefined|enabled|disabled|production|development|staging|localhost)$/i.test(v)) return true;
  if (/^-?\d+(?:\.\d+)?$/.test(v) && v.length < 12) return true;
  if (/^(?:[a-z][a-z0-9+.-]*:)?\/\/[^@\s]*$/i.test(v)) return true;            // URL without userinfo
  if (/^(?:\/|~\/|\.{1,2}\/|[A-Za-z]:\\)[^\s]*$/.test(v) && !/[A-Za-z0-9+/]{32,}/.test(v)) return true; // path
  if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}$/.test(v) && !/\d{4,}/.test(v)) return true; // host name
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v)) return true;                // ${OTHER_VAR}
  if (/^__ZN_[A-Z0-9_]+__$/.test(v)) return true;                              // already a token
  return false;
}

/* High-entropy value for .env files whose key name is not sensitive. */
function looksRandomValue(value) {
  if (value.length < 16) return false;
  let classes = 0;
  if (/[a-z]/.test(value)) classes++;
  if (/[A-Z]/.test(value)) classes++;
  if (/[0-9]/.test(value)) classes++;
  return classes >= 2 && shannon(value) >= 3.5 && !/\s/.test(value);
}

function sanitizeType(name) {
  return String(name).toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 48) || 'VALUE';
}

/* scheme://user:password@host -> password, or null. */
function urlPassword(value) {
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:@/?#]*:([^\s@/?#]+)@/.exec(value.trim());
  if (!m) return null;
  let pw = m[1];
  try { pw = decodeURIComponent(pw); } catch (err) { /* keep raw */ }
  return pw;
}

/* Turn one (name, value) pair into exact entries. URLs with credentials
 * contribute their password only; plain URLs and non-secrets contribute
 * nothing. */
function entriesFor(name, value, typeHint, origin) {
  if (typeof value !== 'string') return [];
  const v = value.trim();
  if (!v) return [];
  const pw = urlPassword(v);
  if (pw !== null) {
    if (pw.length < MIN_LENGTH) return [];
    const out = [{ name, type: 'DB_PASSWORD', value: pw, origin }];
    // The raw (percent-encoded) form as it appears in the URL is covered by
    // the url-encoded variant of the decoded password.
    return out;
  }
  if (looksNonSecret(v)) return [];
  return [{ name, type: typeHint || ('ENV_' + sanitizeType(name)), value: v, origin }];
}

/* ------------------------------------------------------------------ */
/* Sources                                                             */
/* ------------------------------------------------------------------ */

function readSmall(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(file, 'utf8');
  } catch (err) {
    return null;
  }
}

function unquote(v) {
  const t = v.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    const inner = t.slice(1, -1);
    return t[0] === '"' ? inner.replace(/\\n/g, '\n').replace(/\\"/g, '"') : inner;
  }
  // strip trailing inline comment on unquoted values (linear: a .env line can be long)
  return stripInlineComment(t);
}

function parseDotenv(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*)$/.exec(line);
    if (!m) continue;
    out.push([m[1], unquote(m[2])]);
  }
  return out;
}

function fromEnv(env) {
  const out = [];
  for (const [name, value] of Object.entries(env || {})) {
    if (!isSensitiveName(name)) continue;
    out.push(...entriesFor(name, value, null, 'env'));
  }
  return out;
}

const DOTENV_SKIP = /\.(?:example|sample|template|dist|defaults?|schema|tpl)$/i;

function fromDotenvFiles(dir) {
  const out = [];
  if (!dir) return out;
  let names;
  try { names = fs.readdirSync(dir); } catch (err) { return out; }
  for (const f of names) {
    if (!/^\.env(?:\..+)?$/.test(f) || DOTENV_SKIP.test(f)) continue;
    const text = readSmall(path.join(dir, f));
    if (text === null) continue;
    for (const [name, value] of parseDotenv(text)) {
      if (isSensitiveName(name) || urlPassword(value) !== null || looksRandomValue(value)) {
        out.push(...entriesFor(name, value, null, 'dotenv'));
      }
    }
  }
  return out;
}

function fromAwsCredentials(home) {
  const text = readSmall(path.join(home, '.aws', 'credentials'));
  if (!text) return [];
  const out = [];
  const types = { aws_access_key_id: 'AWS_KEY', aws_secret_access_key: 'AWS_SECRET', aws_session_token: 'AWS_SESSION_TOKEN' };
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*(aws_access_key_id|aws_secret_access_key|aws_session_token)\s*=\s*(\S+)\s*$/i.exec(raw);
    if (m) out.push(...entriesFor(m[1].toUpperCase(), m[2], types[m[1].toLowerCase()], 'aws'));
  }
  return out;
}

function fromNpmrc(home, dir) {
  const out = [];
  for (const file of [path.join(home, '.npmrc'), dir ? path.join(dir, '.npmrc') : null]) {
    if (!file) continue;
    const text = readSmall(file);
    if (!text) continue;
    for (const raw of text.split(/\r?\n/)) {
      const m = npmAuth(raw.trim());
      if (!m || /^\$\{/.test(m[1])) continue;
      out.push(...entriesFor('NPM' + m[0].toUpperCase(), unquote(m[1]), 'NPM_TOKEN', 'npmrc'));
      if (m[0] !== '_authToken') {
        // _auth and _password are base64; the decoded secret can leak too.
        const decoded = Buffer.from(unquote(m[1]), 'base64').toString('utf8');
        const pw = decoded.includes(':') ? decoded.slice(decoded.indexOf(':') + 1) : decoded;
        if (/^[\x20-\x7e]+$/.test(pw)) out.push(...entriesFor('NPM_PASSWORD', pw, 'NPM_PASSWORD', 'npmrc'));
      }
    }
  }
  return out;
}

function fromNetrc(home) {
  const text = readSmall(path.join(home, '.netrc')) || readSmall(path.join(home, '_netrc'));
  if (!text) return [];
  const out = [];
  const words = text.split(/\s+/);
  for (let i = 0; i < words.length - 1; i++) {
    if (words[i] === 'password') out.push(...entriesFor('NETRC_PASSWORD', words[i + 1], 'NETRC_PASSWORD', 'netrc'));
  }
  return out;
}

function fromDockerConfig(home) {
  const text = readSmall(path.join(home, '.docker', 'config.json'));
  if (!text) return [];
  const out = [];
  let cfg;
  try { cfg = JSON.parse(text); } catch (err) { return out; }
  for (const auth of Object.values((cfg && cfg.auths) || {})) {
    if (!auth || typeof auth !== 'object') continue;
    if (typeof auth.auth === 'string') {
      out.push(...entriesFor('DOCKER_AUTH', auth.auth, 'DOCKER_AUTH', 'docker'));
      const decoded = Buffer.from(auth.auth, 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      if (i > 0) out.push(...entriesFor('DOCKER_PASSWORD', decoded.slice(i + 1), 'DOCKER_PASSWORD', 'docker'));
    }
    for (const k of ['identitytoken', 'registrytoken', 'password']) {
      if (typeof auth[k] === 'string') out.push(...entriesFor('DOCKER_' + k.toUpperCase(), auth[k], 'DOCKER_TOKEN', 'docker'));
    }
  }
  return out;
}

function fromGhHosts(home, env) {
  const base = (env && env.GH_CONFIG_DIR) || (env && env.XDG_CONFIG_HOME ? path.join(env.XDG_CONFIG_HOME, 'gh') : path.join(home, '.config', 'gh'));
  const text = readSmall(path.join(base, 'hosts.yml'));
  if (!text) return [];
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*oauth_token:\s*(\S+)\s*$/.exec(raw);
    if (m) out.push(...entriesFor('GH_OAUTH_TOKEN', unquote(m[1]), 'GITHUB_TOKEN', 'gh'));
  }
  return out;
}

/* .znrules: `secret: VALUE` or `secret: NAME=VALUE`. */
function fromZnrules(dir) {
  if (!dir) return [];
  const text = readSmall(path.join(dir, '.znrules'));
  if (!text) return [];
  const out = [];
  let n = 0;
  for (const raw of text.split(/\r?\n/)) {
    const secret = znrulesValue(raw);
    if (secret === null) continue;
    n++;
    const named = /^([A-Z][A-Z0-9_]{0,63})=(.+)$/.exec(secret);
    const name = named ? named[1] : 'ZNRULES_SECRET_' + n;
    const value = unquote(named ? named[2] : secret);
    if (value.length >= MIN_LENGTH) out.push({ name, type: 'SECRET', value, origin: 'znrules' });
  }
  return out;
}

/**
 * collectSources({env, cwd, home, files}) -> [{name, type, value, origin}]
 *   env   environment to inspect (default process.env)
 *   cwd   project root for .env* / .znrules / project .npmrc (optional)
 *   home  home directory (default os.homedir())
 *   files false to skip every file source (environment only)
 */
function collectSources(opts) {
  const o = opts || {};
  const env = o.env || process.env;
  const home = o.home || os.homedir();
  const out = fromEnv(env);
  if (o.files !== false) {
    out.push(...fromDotenvFiles(o.cwd));
    out.push(...fromZnrules(o.cwd));
    out.push(...fromAwsCredentials(home));
    out.push(...fromNpmrc(home, o.cwd));
    out.push(...fromNetrc(home));
    out.push(...fromDockerConfig(home));
    out.push(...fromGhHosts(home, env));
  }
  // De-duplicate by value: first source wins (env before files).
  const seen = new Set();
  return out.filter((e) => {
    if (e.value.length < MIN_LENGTH || seen.has(e.value)) return false;
    seen.add(e.value);
    return true;
  });
}

/* ------------------------------------------------------------------ */
/* Variants                                                            */
/* ------------------------------------------------------------------ */

/**
 * variants(value) -> [raw, b64, hex, url, ...] (unique, each >= 8 chars).
 * Order: raw first; then base64 (padded), base64 unpadded, base64url,
 * hex lower, hex upper, URL-encoded.
 */
function variants(value) {
  const out = [value];
  const buf = Buffer.from(value, 'utf8');
  const b64 = buf.toString('base64');
  out.push(b64, trimTrailing(b64, '='), buf.toString('base64url'));
  const hex = buf.toString('hex');
  out.push(hex, hex.toUpperCase());
  out.push(encodeURIComponent(value));
  const seen = new Set();
  return out.filter((v) => {
    if (v.length < MIN_LENGTH || seen.has(v)) return false;
    seen.add(v);
    return true;
  });
}

const VARIANT_KINDS = ['raw', 'b64', 'b64', 'b64url', 'hex', 'hex', 'url'];

/* ------------------------------------------------------------------ */
/* Aho-Corasick                                                        */
/* ------------------------------------------------------------------ */

/* Only the first AC_PREFIX code units of each needle go into the automaton;
 * a prefix hit is confirmed against the full needle with startsWith. Long
 * values (registry tokens of several KB) would otherwise blow up the
 * automaton and its build time. */
const AC_PREFIX = 32;

/**
 * Aho-Corasick compiled to a dense DFA: code units are mapped to a small
 * alphabet (the characters that occur in the needles, plus "other"), and
 * every state has a precomputed transition for every symbol, so the scan is
 * one table lookup per code unit with no failure-link walking.
 */
class AhoCorasick {
  /** @param {Array<{text: string, payload: any}>} needles */
  constructor(needles) {
    this.payloads = [];
    this.lengths = [];
    this.prefixLengths = [];
    this.needles = [];
    const prefixes = [];
    for (const n of needles || []) {
      if (!n || typeof n.text !== 'string' || n.text.length === 0) continue;
      const plen = Math.min(n.text.length, AC_PREFIX);
      prefixes.push(n.text.slice(0, plen));
      this.payloads.push(n.payload);
      this.lengths.push(n.text.length);
      this.prefixLengths.push(plen);
      this.needles.push(n.text);
    }
    this._compile(prefixes);
  }

  _compile(prefixes) {
    // Alphabet: symbol 0 = any code unit that appears in no needle.
    const symbolOf = new Map();
    for (const p of prefixes) {
      for (let i = 0; i < p.length; i++) {
        const c = p.charCodeAt(i);
        if (!symbolOf.has(c)) symbolOf.set(c, symbolOf.size + 1);
      }
    }
    const A = symbolOf.size + 1;
    this.A = A;
    this.classOf = new Uint16Array(65536);
    for (const [c, s] of symbolOf) this.classOf[c] = s;

    // Trie.
    const children = [new Map()];
    const out = [null];
    prefixes.forEach((p, idx) => {
      let node = 0;
      for (let i = 0; i < p.length; i++) {
        const s = symbolOf.get(p.charCodeAt(i));
        let nxt = children[node].get(s);
        if (nxt === undefined) {
          nxt = children.length;
          children.push(new Map());
          out.push(null);
          children[node].set(s, nxt);
        }
        node = nxt;
      }
      (out[node] || (out[node] = [])).push(idx);
    });

    // Dense transitions with failure links folded in (BFS order).
    const n = children.length;
    const delta = new Int32Array(n * A);
    const fail = new Int32Array(n);
    const queue = [];
    for (const [s, child] of children[0]) { delta[s] = child; fail[child] = 0; queue.push(child); }
    for (let qi = 0; qi < queue.length; qi++) {
      const u = queue[qi];
      const base = u * A;
      const fbase = fail[u] * A;
      for (let s = 0; s < A; s++) {
        const v = children[u].get(s);
        if (v !== undefined) {
          delta[base + s] = v;
          fail[v] = delta[fbase + s];
          const inherited = out[fail[v]];
          if (inherited) out[v] = (out[v] || []).concat(inherited);
          queue.push(v);
        } else {
          delta[base + s] = delta[fbase + s];
        }
      }
    }
    this.delta = delta;
    this.out = out;
    this.states = n;
  }

  /** All (possibly overlapping) matches: [{start, end, payload}] */
  find(text) {
    const hits = [];
    if (this.payloads.length === 0 || !text) return hits;
    const { delta, out, classOf, A } = this;
    let state = 0;
    for (let i = 0; i < text.length; i++) {
      state = delta[state * A + classOf[text.charCodeAt(i)]];
      const o = out[state];
      if (o === null || o === undefined) continue;
      for (const idx of o) {
        const start = i + 1 - this.prefixLengths[idx];
        const len = this.lengths[idx];
        if (len > this.prefixLengths[idx] && !text.startsWith(this.needles[idx], start)) continue;
        hits.push({ start, end: start + len, payload: this.payloads[idx] });
      }
    }
    return hits;
  }

  /** Set of payloads with at least one match (for hint prefilters). */
  present(text) {
    const seen = new Set();
    if (this.payloads.length === 0 || !text) return seen;
    const { delta, out, classOf, A } = this;
    let state = 0;
    for (let i = 0; i < text.length; i++) {
      state = delta[state * A + classOf[text.charCodeAt(i)]];
      const o = out[state];
      if (o === null || o === undefined) continue;
      for (const idx of o) seen.add(this.payloads[idx]);
    }
    return seen;
  }
}

/**
 * buildMatcher(entries) -> {find(text) -> Span[], size}
 *
 * entries: [{name, type, value}] (local sources) and/or
 *          [{name, type, values: [...]}] (vault, variants precomputed)
 *          Vault entries carry `vault: true`.
 * Spans: {start, end, type, source: 'exact', name, vault?, variant}
 */
function buildMatcher(entries) {
  const needles = [];
  for (const e of entries || []) {
    if (!e) continue;
    // The 8-character minimum applies to the value itself, not to its
    // (longer) encodings. values[0] is the raw value by contract.
    const raw = typeof e.value === 'string' ? e.value : (Array.isArray(e.values) ? e.values[0] : null);
    if (typeof raw !== 'string' || raw.length < MIN_LENGTH) continue;
    const list = Array.isArray(e.values) ? e.values : variants(e.value);
    list.forEach((text, i) => {
      if (typeof text !== 'string' || text.length < MIN_LENGTH) return;
      needles.push({
        text,
        payload: { type: e.type || 'SECRET', name: e.name, vault: !!e.vault, variant: i === 0 ? 'raw' : (VARIANT_KINDS[i] || 'enc') },
      });
    });
  }
  const ac = new AhoCorasick(needles);
  return {
    size: needles.length,
    find(text) {
      return ac.find(text).map((h) => {
        const span = { start: h.start, end: h.end, type: h.payload.type, source: 'exact', name: h.payload.name, variant: h.payload.variant };
        if (h.payload.vault) span.vault = true;
        return span;
      });
    },
  };
}

module.exports = {
  MIN_LENGTH,
  AC_PREFIX,
  collectSources,
  variants,
  buildMatcher,
  isSensitiveName,
  looksNonSecret,
  urlPassword,
  parseDotenv,
  AhoCorasick,
};
