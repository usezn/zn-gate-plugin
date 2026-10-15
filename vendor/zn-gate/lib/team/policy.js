'use strict';
/**
 * Organization policy on this machine: shape check, Ed25519 signature check
 * against the key pinned at `zn team join`, and the local cache
 * (~/.zn/org-policy.json).
 *
 * The server signs `canonicalJson(policy)` (keys sorted recursively, no
 * whitespace, integers only) with the organization's Ed25519 key. A policy is
 * accepted only if the signature verifies with the pinned key, its `kid`
 * matches, it is not expired, it was not issued in the future and its
 * version is not lower than the last one accepted. Clock skew of up to five
 * minutes is tolerated on both dates.
 *
 * The cache is checked again every time it is read: a file edited by hand
 * does not verify and is ignored.
 *
 * States:
 *   none      not in an organization, or no policy received yet
 *   active    a valid, unexpired policy
 *   expired   the last valid policy expired (offline for more than its
 *             lifetime): only the parts that restrict still apply
 *   invalid   the cache does not verify (edited, or the pinned key changed)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const store = require('../vault/store');

const SKEW_MS = 5 * 60 * 1000;
const MAX_LIFETIME_MS = 7 * 86400000;
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const ORG_RE = /^org_[A-Za-z0-9]{8,32}$/;
const SECRET_PATTERN_RE = /^(?:\*|[A-Z][A-Z0-9_]{0,63}|[A-Z][A-Z0-9_]{0,62}\*)$/;
const AGENT_RE = /^(?:\*|[a-z0-9][a-z0-9-]{0,31})$/;
const HOST_RE = /^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*(?::\d{1,5})?$/;
const COMMAND_RE = /^[A-Za-z0-9_.+\-/ *]{1,128}$/;
const DETECTOR_ID_RE = /^[a-z0-9_]{1,64}$/;
const TYPE_RE = /^[A-Z0-9](?:[A-Z0-9_]{0,62}[A-Z0-9])?$/;
const KID_RE = /^[0-9a-f]{16}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const MODES = ['proxy', 'env', 'file', 'backup'];
const INJECT_AT = ['header', 'query', 'body'];

/* ------------------------------------------------------------------ */
/* Canonical JSON and keys                                             */
/* ------------------------------------------------------------------ */

/** Keys sorted recursively, no whitespace. Same bytes as the server. */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isInteger(value)) throw new Error('canonicalJson: only integers are allowed');
    if (value === undefined) throw new Error('canonicalJson: undefined is not allowed');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

/** kid = first 16 hex characters of SHA-256 of the raw 32-byte public key. */
function kidOf(rawB64u) {
  return crypto.createHash('sha256').update(Buffer.from(rawB64u, 'base64url')).digest('hex').slice(0, 16);
}

function publicKeyFromRaw(rawB64u) {
  const raw = Buffer.from(String(rawB64u || ''), 'base64url');
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki' });
}

/** A pinned key as received at join time: {alg: 'Ed25519', kid, key}. */
function checkPin(pin) {
  if (!pin || pin.alg !== 'Ed25519' || !KID_RE.test(pin.kid || '') || !KEY_RE.test(pin.key || '')) return false;
  return kidOf(pin.key) === pin.kid;
}

/* ------------------------------------------------------------------ */
/* Shape (mirror of org-policy.schema.json, no dependencies)           */
/* ------------------------------------------------------------------ */

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const onlyKeys = (o, allowed) => Object.keys(o).every((k) => allowed.includes(k));
const uniqueStrings = (a, re, max) => Array.isArray(a) && a.length <= max &&
  a.every((x) => typeof x === 'string' && re.test(x)) && new Set(a).size === a.length;

function checkRule(r) {
  if (!isObj(r) || !onlyKeys(r, ['secret', 'agents', 'mode', 'allowHosts', 'allowCommands', 'injectAt', 'deny', 'reason'])) return 'unknown field';
  if (typeof r.secret !== 'string' || !SECRET_PATTERN_RE.test(r.secret)) return 'invalid secret pattern';
  if (!uniqueStrings(r.agents, AGENT_RE, 16) || r.agents.length < 1) return 'invalid agents';
  if (r.mode !== undefined && !MODES.includes(r.mode)) return 'invalid mode';
  if (r.allowHosts !== undefined && (!uniqueStrings(r.allowHosts, HOST_RE, 64) || r.allowHosts.some((h) => h.length > 253))) return 'invalid allowHosts';
  if (r.allowCommands !== undefined && !uniqueStrings(r.allowCommands, COMMAND_RE, 64)) return 'invalid allowCommands';
  if (r.injectAt !== undefined && !INJECT_AT.includes(r.injectAt)) return 'invalid injectAt';
  if (r.deny !== undefined && typeof r.deny !== 'boolean') return 'invalid deny';
  if (r.reason !== undefined && (typeof r.reason !== 'string' || r.reason.length < 1 || r.reason.length > 200 || /[\u0000-\u001f]/.test(r.reason))) return 'invalid reason';
  return null;
}

function checkDetector(d) {
  if (!isObj(d) || !onlyKeys(d, ['id', 'pattern', 'type'])) return 'unknown field';
  if (typeof d.id !== 'string' || !DETECTOR_ID_RE.test(d.id)) return 'invalid id';
  if (typeof d.pattern !== 'string' || d.pattern.length < 4 || d.pattern.length > 256) return 'invalid pattern';
  if (typeof d.type !== 'string' || !TYPE_RE.test(d.type)) return 'invalid type';
  return null;
}

/** checkShape(policy) -> null when valid, or a short reason. */
function checkShape(p) {
  if (!isObj(p) || !onlyKeys(p, ['org', 'version', 'issued_at', 'expires_at', 'rules', 'detectors', 'redaction'])) return 'unknown field';
  if (typeof p.org !== 'string' || !ORG_RE.test(p.org)) return 'invalid org';
  if (!Number.isSafeInteger(p.version) || p.version < 1) return 'invalid version';
  if (typeof p.issued_at !== 'string' || !ISO_RE.test(p.issued_at) || Number.isNaN(Date.parse(p.issued_at))) return 'invalid issued_at';
  if (typeof p.expires_at !== 'string' || !ISO_RE.test(p.expires_at) || Number.isNaN(Date.parse(p.expires_at))) return 'invalid expires_at';
  const life = Date.parse(p.expires_at) - Date.parse(p.issued_at);
  if (!(life > 0) || life > MAX_LIFETIME_MS) return 'invalid lifetime';
  if (!Array.isArray(p.rules) || p.rules.length > 200) return 'invalid rules';
  for (let i = 0; i < p.rules.length; i++) {
    const why = checkRule(p.rules[i]);
    if (why) return 'rule ' + i + ': ' + why;
  }
  if (p.detectors !== undefined) {
    if (!Array.isArray(p.detectors) || p.detectors.length > 50) return 'invalid detectors';
    const ids = new Set();
    for (let i = 0; i < p.detectors.length; i++) {
      const why = checkDetector(p.detectors[i]);
      if (why) return 'detector ' + i + ': ' + why;
      if (ids.has(p.detectors[i].id)) return 'detector ' + i + ': duplicate id';
      ids.add(p.detectors[i].id);
    }
  }
  if (p.redaction !== undefined) {
    if (!isObj(p.redaction) || !onlyKeys(p.redaction, ['pii', 'ner'])) return 'invalid redaction';
    for (const k of Object.keys(p.redaction)) if (typeof p.redaction[k] !== 'boolean') return 'invalid redaction';
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Verification                                                        */
/* ------------------------------------------------------------------ */

/**
 * verifyEnvelope(envelope, pin, {now, minVersion, org, allowExpired})
 *   -> {ok: true, policy, expired} | {ok: false, error}
 * envelope: {policy, signature: {alg, kid, sig}} as GET /v1/org/policy returns it.
 * pin: the organization's public key from `zn team join`.
 * allowExpired: used when reading the cache, so an expired policy can still
 * restrict (strict mode); a downloaded policy must never be expired.
 */
function verifyEnvelope(envelope, pin, opts) {
  const o = opts || {};
  const now = o.now == null ? Date.now() : o.now;
  if (!isObj(envelope) || !onlyKeys(envelope, ['policy', 'signature']) || !isObj(envelope.signature)) return { ok: false, error: 'invalid envelope' };
  const s = envelope.signature;
  if (!onlyKeys(s, ['alg', 'kid', 'sig']) || s.alg !== 'Ed25519' || !KID_RE.test(s.kid || '') || !SIG_RE.test(s.sig || '')) return { ok: false, error: 'invalid signature block' };
  if (!checkPin(pin)) return { ok: false, error: 'no valid pinned key' };
  if (s.kid !== pin.kid) return { ok: false, error: 'unknown key id' };
  const shape = checkShape(envelope.policy);
  if (shape) return { ok: false, error: 'invalid policy: ' + shape };
  let good = false;
  try {
    good = crypto.verify(null, Buffer.from(canonicalJson(envelope.policy), 'utf8'), publicKeyFromRaw(pin.key), Buffer.from(s.sig, 'base64url'));
  } catch (err) {
    good = false;
  }
  if (!good) return { ok: false, error: 'bad signature' };
  const p = envelope.policy;
  if (o.org && p.org !== o.org) return { ok: false, error: 'policy is for another organization' };
  if (Date.parse(p.issued_at) - SKEW_MS > now) return { ok: false, error: 'policy issued in the future' };
  const expired = Date.parse(p.expires_at) + SKEW_MS <= now;
  if (expired && !o.allowExpired) return { ok: false, error: 'policy expired' };
  if (o.minVersion && p.version < o.minVersion) return { ok: false, error: 'policy version rollback' };
  return { ok: true, policy: p, expired };
}

/* ------------------------------------------------------------------ */
/* Files                                                               */
/* ------------------------------------------------------------------ */

function paths(opts) {
  const home = store.paths(opts).home;
  return {
    home,
    teamFile: path.join(home, 'team.json'),
    policyFile: path.join(home, 'org-policy.json'),
    uploadState: path.join(home, 'team-upload.json'),
    uploadLock: path.join(home, 'team-upload.lock'),
  };
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (err) { return null; }
}

/* Atomic write, private file. */
function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = file + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
  if (process.platform !== 'win32') { try { fs.chmodSync(file, 0o600); } catch (err) { /* ignore */ } }
}

function removeFile(file) {
  try { fs.unlinkSync(file); return true; } catch (err) { return false; }
}

/**
 * ~/.zn/team.json, the readable copy of what `zn team join` received
 * (organization, API base, install id, pinned key). The install token is not
 * here: it stays in the encrypted vault.
 */
function readTeam(opts) {
  const t = readJson(paths(opts).teamFile);
  if (!isObj(t) || t.v !== 1 || typeof t.org !== 'string' || !ORG_RE.test(t.org) || !checkPin(t.policy_public_key)) return null;
  return t;
}

function writeTeam(team, opts) { writeJson(paths(opts).teamFile, Object.assign({ v: 1 }, team)); }

/* Cache record: {v: 1, envelope, etag, fetched_at, accepted_version}. */
function readCache(opts) {
  const c = readJson(paths(opts).policyFile);
  return isObj(c) && c.v === 1 && isObj(c.envelope) ? c : null;
}

/**
 * state({now, team}) -> {state, policy, version, expires_at, error?}
 * Reads team.json and the cache and verifies the cache with the pinned key.
 */
function state(opts) {
  const o = opts || {};
  const team = o.team || readTeam(o);
  if (!team) return { state: 'none', policy: null };
  const cache = readCache(o);
  if (!cache) return { state: 'none', policy: null, org: team.org };
  const v = verifyEnvelope(cache.envelope, o.pin || team.policy_public_key, { now: o.now, org: team.org, allowExpired: true });
  if (!v.ok) return { state: 'invalid', policy: null, org: team.org, error: v.error };
  return {
    state: v.expired ? 'expired' : 'active',
    policy: v.policy,
    org: team.org,
    version: v.policy.version,
    expires_at: v.policy.expires_at,
    etag: typeof cache.etag === 'string' ? cache.etag : null,
    fetched_at: cache.fetched_at || null,
  };
}

/**
 * accept(envelope, etag, {now, team, pin}) -> {ok, policy?, error?}
 * Verifies a downloaded policy and, if it is good, replaces the cache. A
 * policy that does not verify, is expired or rolls the version back is
 * refused and the cache is left as it was.
 */
function accept(envelope, etag, opts) {
  const o = opts || {};
  const team = o.team || readTeam(o);
  if (!team) return { ok: false, error: 'not in an organization' };
  const pin = o.pin || team.policy_public_key;
  const prev = readCache(o);
  let minVersion = Number(team.min_policy_version) || 0;
  if (prev) {
    const pv = verifyEnvelope(prev.envelope, pin, { now: o.now, org: team.org, allowExpired: true });
    if (pv.ok) minVersion = Math.max(minVersion, pv.policy.version);
  }
  const v = verifyEnvelope(envelope, pin, { now: o.now, org: team.org, minVersion });
  if (!v.ok) return { ok: false, error: v.error };
  writeJson(paths(o).policyFile, {
    v: 1, envelope, etag: typeof etag === 'string' && etag.length <= 200 ? etag : null,
    fetched_at: new Date(o.now == null ? Date.now() : o.now).toISOString(), accepted_version: v.policy.version,
  });
  return { ok: true, policy: v.policy };
}

/** Write the readable copy of an accepted policy (the vault daemon keeps the original). */
function writeCache(envelope, etag, opts) {
  const o = opts || {};
  writeJson(paths(o).policyFile, {
    v: 1, envelope, etag: typeof etag === 'string' && etag.length <= 200 ? etag : null,
    fetched_at: new Date(o.now == null ? Date.now() : o.now).toISOString(), accepted_version: envelope.policy.version,
  });
}

/** Keep the cache but record that the server answered 304 (still current). */
function touchCache(opts) {
  const o = opts || {};
  const c = readCache(o);
  if (!c) return false;
  c.fetched_at = new Date(o.now == null ? Date.now() : o.now).toISOString();
  writeJson(paths(o).policyFile, c);
  return true;
}

module.exports = {
  canonicalJson,
  kidOf,
  checkPin,
  checkShape,
  verifyEnvelope,
  paths,
  readTeam,
  writeTeam,
  readCache,
  state,
  accept,
  writeCache,
  touchCache,
  writeJson,
  removeFile,
  SKEW_MS,
};
