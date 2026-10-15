'use strict';
/**
 * Pattern layer (secrets with a known prefix or a verifiable structure) and
 * PII layer (regex + checksum or structural validation).
 *
 * Design rules:
 *   - Every pattern needs a literal hint (a prefix or a keyword) that is
 *     checked with String#includes before the regex runs. Text without the
 *     hint costs one native substring search per pattern.
 *   - Bodies are bounded by lookarounds on the token alphabet, so a match
 *     never starts or ends in the middle of a longer random string (base64
 *     blobs, hashes, lockfile integrity fields).
 *   - Random-looking bodies must actually look random (character classes and
 *     entropy). Hex-only bodies of git SHAs, UUIDs and digests never qualify
 *     as base64-style secrets.
 *   - Connection strings: only the password segment is a span; scheme, user,
 *     host, port and database stay readable.
 *
 * The regex sources are assembled from fragments on purpose: a literal
 * private-key header in this file would trip secret scanners that read the
 * package.
 *
 * findPatterns(text, opts) -> [{start, end, type, source: 'pattern'}]
 * findPii(text, opts)      -> [{start, end, type, source: 'pii'}]
 *   opts.pii = {email, phone, iban, card, dni, ssn, ipv4}  (booleans; ipv4 off by default)
 */

// Version of the type catalogue (secret and PII patterns, validators). Bump it
// when a pattern, validator or type name changes; see CONTRIBUTING.md.
const SCRUB_RULES_VERSION = '2026-10-14.2';

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function shannon(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function charClasses(s) {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/[0-9]/.test(s)) n++;
  if (/[^A-Za-z0-9]/.test(s)) n++;
  return n;
}

/* A body that should be machine-generated: at least `classes` character
 * classes and at least `bits` of Shannon entropy per character. */
function looksRandom(s, classes = 2, bits = 3.0) {
  return charClasses(s) >= classes && shannon(s) >= bits;
}

const PLACEHOLDER_RE = /^(?:x{3,}|\*{3,}|\.{3,}|-+|_+|<[^>]*>|\$\{?[^}]*\}?|\{\{?[^}]*\}?\}|%\(?[a-z_]*\)?s|:[a-z_]+|\[[^\]]*\])$/i;
const PLACEHOLDER_WORDS = /(?:^|[^a-z])(?:password|passwd|passw0rd|secret|changeme|change_me|example|placeholder|your[_-]?|redacted|dummy|sample|foobar|hunter2|xxxx|todo|insert|replace|mypass|pass(?:word)?123)(?:[^a-z]|$)/i;

function isPlaceholder(s) {
  if (!s) return true;
  if (PLACEHOLDER_RE.test(s)) return true;
  if (PLACEHOLDER_WORDS.test(s)) return true;
  if (/^(.)\1+$/.test(s)) return true;
  if (/^(?:0123456789|1234567890|abcdef|qwerty)/i.test(s)) return true;
  return false;
}

/* ------------------------------------------------------------------ */
/* Checksums and validators                                            */
/* ------------------------------------------------------------------ */

function luhnValid(number) {
  let sum = 0;
  let dbl = false;
  for (let i = number.length - 1; i >= 0; i--) {
    let d = number.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function mod97(value) {
  let rem = 0;
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      const n = code - 55; // A=10 .. Z=35
      rem = (rem * 100 + n) % 97;
    } else {
      rem = (rem * 10 + (code - 48)) % 97;
    }
  }
  return rem;
}

/* IBAN lengths per country (ISO 13616 registry, SEPA and common others). */
const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29,
  CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24,
  FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HR: 21,
  HU: 28, IE: 22, IL: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21,
  LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30,
  NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24,
  SE: 24, SI: 19, SK: 24, SM: 27, TN: 24, TR: 26, UA: 29, VG: 24, XK: 20,
};

function ibanValid(raw) {
  const iban = String(raw).replace(/[\s-]+/g, '').toUpperCase();
  const len = IBAN_LENGTHS[iban.slice(0, 2)];
  if (!len || iban.length !== len) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) return false;
  return mod97(iban.slice(4) + iban.slice(0, 4)) === 1;
}

const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';

function dniValid(raw) {
  const v = String(raw).replace(/-/g, '').toUpperCase();
  const m = /^(\d{8})([A-Z])$/.exec(v);
  if (!m) return false;
  return DNI_LETTERS[Number(m[1]) % 23] === m[2];
}

function nieValid(raw) {
  const v = String(raw).replace(/-/g, '').toUpperCase();
  const m = /^([XYZ])(\d{7})([A-Z])$/.exec(v);
  if (!m) return false;
  const n = 'XYZ'.indexOf(m[1]) * 10000000 + Number(m[2]);
  return DNI_LETTERS[n % 23] === m[3];
}

/* US SSN: area 001-899 except 666, group 01-99, serial 0001-9999. */
function ssnValid(raw) {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(raw);
  if (!m) return false;
  const area = Number(m[1]);
  if (area === 0 || area === 666 || area >= 900) return false;
  if (m[2] === '00' || m[3] === '0000') return false;
  return true;
}

/* Card networks by IIN prefix and allowed lengths. */
function cardNetworkOk(d) {
  const len = d.length;
  const p2 = Number(d.slice(0, 2));
  const p3 = Number(d.slice(0, 3));
  const p4 = Number(d.slice(0, 4));
  const p6 = Number(d.slice(0, 6));
  if (d[0] === '4') return len === 13 || len === 16 || len === 19;                  // Visa
  if ((p2 >= 51 && p2 <= 55) || (p6 >= 222100 && p6 <= 272099)) return len === 16; // Mastercard
  if (p2 === 34 || p2 === 37) return len === 15;                                    // Amex
  if (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649)) return len >= 16 && len <= 19; // Discover
  if (p4 >= 3528 && p4 <= 3589) return len >= 16 && len <= 19;                     // JCB
  if (p2 === 36 || p2 === 38 || p2 === 39 || (p3 >= 300 && p3 <= 305)) return len >= 14 && len <= 19; // Diners
  if (p2 === 62) return len >= 16 && len <= 19;                                     // UnionPay
  return false;
}

function cardValid(raw) {
  const d = String(raw).replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(d)) return false;
  if (/^(\d)\1+$/.test(d)) return false;
  return cardNetworkOk(d) && luhnValid(d);
}

/* E.164: + then 8..15 digits. NANP (+1) must be exactly 10 national
 * digits with valid area and exchange codes; a few large plans get their
 * national lengths checked. */
const E164_LENGTHS = { 44: [10], 34: [9], 33: [9], 49: [7, 8, 9, 10, 11], 39: [9, 10], 351: [9], 31: [9], 32: [8, 9], 41: [9], 43: [7, 8, 9, 10, 11, 12, 13], 52: [10], 55: [10, 11], 61: [9], 81: [9, 10], 91: [10] };

function e164Valid(raw) {
  const m = /^\+(\d{8,15})$/.exec(raw);
  if (!m) return false;
  const digits = m[1];
  if (/^(\d)\1+$/.test(digits) || /(?:0123456789|1234567890|9876543210)/.test(digits)) return false;
  if (digits[0] === '0') return false;
  if (digits[0] === '1') {
    const nat = digits.slice(1);
    return nat.length === 10 && /^[2-9]\d{2}[2-9]\d{6}$/.test(nat);
  }
  for (const ccLen of [3, 2]) {
    const cc = digits.slice(0, ccLen);
    if (E164_LENGTHS[cc]) return E164_LENGTHS[cc].includes(digits.length - ccLen);
  }
  return digits.length >= 10 && digits.length <= 15;
}

function ipv4Public(raw) {
  const parts = raw.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !(p >= 0 && p <= 255))) return false;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 192 && b === 0) return false;     // 192.0.0.0/24 and TEST-NET-1
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
  if (a === 203 && b === 0) return false;
  return true;
}

/* ------------------------------------------------------------------ */
/* Secret patterns                                                     */
/* ------------------------------------------------------------------ */

/* Boundaries on the token alphabet. */
const NB = '(?<![A-Za-z0-9_-])';        // not preceded by a token char
const NA = '(?![A-Za-z0-9_-])';         // not followed by a token char
const NB64 = '(?<![A-Za-z0-9+/_-])';
const NA64 = '(?![A-Za-z0-9+/=_-])';

function re(src, flags) { return new RegExp(src, 'gd' + (flags || '')); }

const KEY_WORD = 'PRIVATE' + ' KEY';
const PEM_BEGIN = '-----BEGIN ';
const PEM_LABEL = '((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?' + KEY_WORD + '(?: BLOCK)?)';

/**
 * Pattern table. Fields:
 *   type     token type (__ZN_<TYPE>_<n>__)
 *   hints    literal substrings; the regex only runs if one is present
 *   re       global regex; `group` selects the span (default: whole match)
 *   check    optional (value, text, index) -> boolean
 */
const { AhoCorasick, isSensitiveName, looksNonSecret } = require('./exact');

/* ------------------------------------------------------------------ */
/* Structured config values (YAML, docker-compose, Dockerfile, shell)  */
/* ------------------------------------------------------------------ */

/* Names that contain a sensitive word but do not hold a secret value:
 * public keys, references and metadata (*_ARN, *_HEADER, *_VERSION...),
 * names ending in a fingerprint or hash word (signing_key_fingerprint,
 * token_hash, password_sha256), timestamps (*_AT), and storage or cache keys
 * (cache_key, idempotency_key, s3_key, objectKey, partition and sort keys).
 * A hash word elsewhere in the name does not count: HASH_KEY, hashKey and
 * HMAC_SHA256_SECRET hold secrets. */
const STRUCT_NAME_SKIP_EXTRA = /(?:^|_)(?:FINGERPRINT|FINGERPRINTS|HASH|HASHED|SHA1|SHA256|SHA384|SHA512|MD5|DIGEST|CHECKSUM)$|_AT$|(?:^|_)(?:CACHE|IDEMPOTENCY|S3|OBJECT|PARTITION|SORT|ROUTING|DEDUP|DEDUPLICATION)_KEY$/;
/* GPG / PGP key ids and fingerprints (16 or 40 hex digits), as in
 * `ENV GPG_KEY <fingerprint>` of official Docker images. */
const GPG_NAME = /(?:^|_)(?:GPG|PGP)_KEY(?:_ID)?$/;
const GPG_ID = /^(?:[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40})$/;
const STRUCT_NAME_SKIP = /(?:^|_)(?:PUBLIC|PUB)(?:_|$)|PUBKEY|_(?:ARN|REF|REFS|HEADER|HEADERS|POLICY|PROVIDER|ALGORITHM|ALG|LENGTH|EXPIRY|EXPIRES|EXPIRES_IN|EXPIRATION|LIFETIME|VERSION|URI|SCOPE|SCOPES|FORMAT|FIELD|PARAM|PARAMS|PREFIX|PATTERN|REGEX|METHOD|COUNT|SIZE|LIMIT|STORE|BACKEND|KIND)$/;

/* Key of a YAML map, a compose environment entry, an ENV line or a
 * `docker run -e` flag: camelCase, dots and dashes are read as `_`, then the
 * exact-value layer's list of sensitive names applies (API_KEY,
 * POSTGRES_PASSWORD, clientSecret, auth-token...). A bare `key` is too
 * generic in YAML (caches, Kubernetes selectors) to count. */
function sensitiveKey(name) {
  if (!name) return false;
  const n = String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[-.]+/g, '_').toUpperCase();
  if (n === 'KEY' || n === 'KEYS') return false;
  if (STRUCT_NAME_SKIP.test(n) || STRUCT_NAME_SKIP_EXTRA.test(n)) return false;
  return isSensitiveName(n);
}

/* Name and value together: a GPG / PGP key id is not a secret. */
function structuredPair(name, value) {
  if (!sensitiveKey(name) || !structuredValue(value)) return false;
  const n = String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[-.]+/g, '_').toUpperCase();
  return !(GPG_NAME.test(n) && GPG_ID.test(value));
}

/* Hex-only value: at least 32 digits (128 bits), with letters and digits.
 * Shorter hex (abbreviated commit hashes, colors) never qualifies. */
function hexSecret(v) {
  return /^[0-9a-fA-F]{32,}$/.test(v) && /[0-9]/.test(v) && /[a-fA-F]/.test(v) && shannon(v) >= 3.0 && !isPlaceholder(v);
}

/* Identifiers, slugs, versions and dotted references: every segment is a
 * word (camelCase humps of two or more letters), a short number, or a word
 * with a short numeric suffix. */
const WORD_SEGMENT = /^(?:[A-Za-z]?[a-z]+(?:[A-Z][a-z]{2,})*|[A-Z]+)\d{0,2}$|^v?\d{1,4}$/;
function wordy(v) {
  return v.split(/[-_./:@+]+/).every((s) => s === '' || WORD_SEGMENT.test(s));
}

/* Unquoted or quoted value under a sensitive key: machine-generated, not a
 * reference, a placeholder, a URL, a path, a number or an identifier. */
function structuredValue(v) {
  if (v.length < 12 || v.length > 200) return false;
  if (/[^\x21-\x7e]/.test(v)) return false;                        // printable ASCII only
  if (isPlaceholder(v) || looksNonSecret(v)) return false;
  if (/^[$%<{[(*&!|>@~=-]/.test(v)) return false;                 // ${VAR}, $VAR, templates, YAML tags/anchors
  if (/[(){}[\];,<>`\\]/.test(v)) return false;                    // code, lists, interpolation
  if (/__ZN_[A-Z0-9_]+__/.test(v)) return false;
  if (/^(?:process\.env|os\.environ|env\.|secrets\.|vars\.|arn:)/i.test(v)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return false;           // URLs: passwords inside are DB_PASSWORD's job
  if (/^[0-9a-fA-F]+$/.test(v)) return hexSecret(v);
  if (/^\d+(?:[.:]\d+)*$/.test(v)) return false;
  if (wordy(v)) return false;
  const upper = /[A-Z]/.test(v);
  const kinds = (/[a-z]/.test(v) ? 1 : 0) + (upper ? 1 : 0) + (/[0-9]/.test(v) ? 1 : 0);
  if (kinds < 2) return false;
  if (!upper && !/[^A-Za-z0-9]/.test(v) && v.length < 16) return false;
  return shannon(v) >= 3.3;
}

/* Line tail: optional trailing comma or semicolon, optional comment. */
const S_TAIL = '(?:[ \\t]*[,;])?(?:[ \\t]+(?:#|//)[^\\r\\n]*)?$';
const S_PREFILTER = /(?:pass|pwd|secret|token|key|credential|auth|dsn)/i;
const structuredCheck = (nameGroup) => (v, text, index, m) => structuredPair(m[nameGroup], v);

/* Whole-line forms, matched one line at a time and only on lines that
 * contain a sensitive word. Each entry: [regex, name group, value group]. */
const S_LINES = [
  /* YAML / docker-compose map entry: `key: value`, `- key: value`, quoted or
   * not, with an optional trailing comment (also JSON `"key": "value"`). */
  [new RegExp('^[ \\t]*(?:-[ \\t]+)?(["\']?)([A-Za-z_][A-Za-z0-9_.-]{0,127})\\1[ \\t]*:[ \\t]+(["\']?)([^\\s"\'`]{1,512})\\3' + S_TAIL, 'd'), 2, 4],
  /* docker-compose environment list: `- KEY=value` or `- "KEY=value"`. */
  [new RegExp('^[ \\t]*-[ \\t]+(["\']?)([A-Za-z_][A-Za-z0-9_.-]{0,127})=([^\\s"\'`]{1,512})\\1' + S_TAIL, 'd'), 2, 3],
  /* KEY=value lines: dotenv, `export`, Dockerfile `ENV` / `ARG`, `set`. */
  [new RegExp('^[ \\t]*(?:(?:export|ENV|ARG|set)[ \\t]+)?([A-Za-z_][A-Za-z0-9_]{0,127})[ \\t]*=[ \\t]*(["\']?)([^\\s"\'`]{1,512})\\2' + S_TAIL, 'd'), 1, 3],
  /* Dockerfile `ENV KEY value` (legacy form, one pair per line). */
  [new RegExp('^[ \\t]*ENV[ \\t]+([A-Za-z_][A-Za-z0-9_]{0,127})[ \\t]+(["\']?)([^\\s"\'`=]{1,512})\\2' + S_TAIL, 'd'), 1, 3],
];
const S_LINE_HINT = /pass|pwd|secret|token|key|credential|auth|dsn/gi;

/* One pass of the hint regex over the text; each line that holds a hint is
 * tried once. Every line regex is anchored at the line start and its
 * quantifiers are bounded, so the work stays linear in the text length. */
function findStructured(text, out) {
  S_LINE_HINT.lastIndex = 0;
  let h;
  while ((h = S_LINE_HINT.exec(text)) !== null) {
    const ls = text.lastIndexOf('\n', h.index) + 1;
    let le = text.indexOf('\n', h.index);
    if (le < 0) le = text.length;
    S_LINE_HINT.lastIndex = le + 1;
    if (le - ls < 12) continue;  // too short to hold a 12-character value
    let e2 = le; while (e2 > ls && (text[e2 - 1] === ' ' || text[e2 - 1] === '\t' || text[e2 - 1] === '\r')) e2--;
    const line = text.slice(ls, e2);
    for (const [r, nameGroup, valueGroup] of S_LINES) {
      const m = r.exec(line);
      if (!m || !m.indices[valueGroup]) continue;
      if (!structuredPair(m[nameGroup], m[valueGroup])) continue;
      out.push({ start: ls + m.indices[valueGroup][0], end: ls + m.indices[valueGroup][1] });
      break;
    }
    if (le >= text.length) break;
  }
}

const PATTERNS = [
  { type: 'ANTHROPIC_KEY', hints: ['sk-ant-'], re: re(NB + 'sk-ant-[a-z]{3,8}\\d{2}-[A-Za-z0-9_-]{32,200}' + NA) },
  { type: 'OPENAI_KEY', hints: ['sk-'], re: re(NB + 'sk-(?!ant-)(?:proj-|svcacct-|admin-|or-v1-)?[A-Za-z0-9_-]{40,200}' + NA),
    check: (v) => looksRandom(v.replace(/^sk-(?:proj-|svcacct-|admin-|or-v1-)?/, ''), 2, 3.5) },
  /* Legacy DeepSeek-style key: `sk-` + 32 hex digits. The length and charset
   * are not stated in the provider's docs (checked 2026-10-14); the shape
   * follows rules.js secret:openai_key, which already accepts it. */
  { type: 'OPENAI_KEY', hints: ['sk-'], re: re(NB + 'sk-[0-9a-f]{32}' + NA),
    check: (v) => hexSecret(v.slice(3)) },
  { type: 'AWS_KEY', hints: ['AKIA', 'ASIA', 'ABIA', 'ACCA'], re: re('(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])'),
    check: (v) => !/^(.)\1+$/.test(v.slice(4)) && !/EXAMPLE$/.test(v) },
  { type: 'AWS_SECRET', hints: ['ecret', 'ECRET'], re: re(NB64 + '[A-Za-z0-9+/]{40}' + NA64),
    check: (v, text, index) => looksRandom(v, 3, 4.0) &&
      /(?:aws|secret[_ -]?access[_ -]?key|SecretAccessKey)/i.test(text.slice(Math.max(0, index - 160), index)) &&
      /secret/i.test(text.slice(Math.max(0, index - 160), index)) },
  { type: 'GITHUB_TOKEN', hints: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'], re: re(NB + 'gh[pousr]_[A-Za-z0-9]{36,255}' + NA),
    check: (v) => looksRandom(v.slice(4), 2, 3.5) },
  { type: 'GITHUB_PAT', hints: ['github_pat_'], re: re(NB + 'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59,}' + NA) },
  { type: 'GITLAB_TOKEN', hints: ['glpat-', 'gldt-', 'glrt-', 'glptt-', 'glcbt-', 'glft-', 'glsoat-'], re: re(NB + 'gl(?:pat|dt|rt|ptt|cbt|ft|soat)-[A-Za-z0-9_-]{20,}' + NA),
    check: (v) => looksRandom(v.slice(v.indexOf('-') + 1), 2, 3.3) },
  { type: 'SLACK_TOKEN', hints: ['xox', 'xapp-'], re: re(NB + '(?:xox[abeprs]-[0-9]{6,}-[A-Za-z0-9-]{8,}|xapp-\\d-[A-Z0-9]{6,}-\\d{6,}-[a-f0-9]{32,})' + NA) },
  { type: 'SLACK_WEBHOOK', hints: ['hooks.slack.com'], re: re('https://hooks\\.slack\\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}') },
  { type: 'DISCORD_WEBHOOK', hints: ['/api/webhooks/'], re: re('https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d{15,20}/[A-Za-z0-9_-]{60,}') },
  { type: 'STRIPE_KEY', hints: ['_live_', '_test_', '_prod_'], re: re(NB + '(?:sk|rk)_(?:live|test|prod)_[A-Za-z0-9]{20,247}' + NA),
    check: (v) => looksRandom(v.slice(8), 2, 3.5) },
  { type: 'STRIPE_WEBHOOK_SECRET', hints: ['whsec_'], re: re(NB + 'whsec_[A-Za-z0-9+/]{32,}' + NA) },
  { type: 'GOOGLE_API_KEY', hints: ['AIza'], re: re(NB + 'AIza[0-9A-Za-z_-]{35}' + NA) },
  { type: 'GOOGLE_OAUTH_SECRET', hints: ['GOCSPX-'], re: re(NB + 'GOCSPX-[A-Za-z0-9_-]{28}' + NA) },
  /* Letters-only tokens are exactly 34 characters (gitleaks
   * huggingface-access-token rule). Identifier-like bodies (CamelCase words)
   * are rejected so that a 34-letter class or function name is not a token;
   * mixed tokens keep the random-body check. */
  { type: 'HF_TOKEN', hints: ['hf_'], re: re(NB + 'hf_[A-Za-z0-9]{34,40}' + NA),
    check: (v) => (/^[A-Za-z]{34}$/.test(v.slice(3)) && !/^[a-z]*(?:[A-Z][a-z]{2,})*[A-Z]{0,3}[a-z]{0,2}$/.test(v.slice(3))) ||
      looksRandom(v.slice(3), 3, 3.8) },
  { type: 'NPM_TOKEN', hints: ['npm_'], re: re(NB + 'npm_[A-Za-z0-9]{36}' + NA),
    check: (v) => looksRandom(v.slice(4), 3, 3.8) },
  { type: 'PYPI_TOKEN', hints: ['pypi-'], re: re(NB + 'pypi-AgE[A-Za-z0-9_-]{50,}' + NA) },
  { type: 'SENDGRID_KEY', hints: ['SG.'], re: re(NB + 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}' + NA) },
  /* Twilio API key SID: `SK` + 32 hex digits in one case only (lower or
   * upper; mixed case is not a SID). Same shape as gitleaks twilio-api-key. */
  { type: 'TWILIO_KEY', hints: ['SK', 'AC'], re: re('(?<![A-Za-z0-9])SK(?:[0-9a-f]{32}|[0-9A-F]{32})(?![A-Za-z0-9])'),
    check: (v) => /\d/.test(v.slice(2)) && /[a-fA-F]/.test(v.slice(2)) },
  { type: 'MAILGUN_KEY', hints: ['key-'], re: re(NB + 'key-[0-9a-f]{32}' + NA),
    check: (v) => /\d/.test(v.slice(4)) && /[a-f]/.test(v.slice(4)) },
  { type: 'SHOPIFY_TOKEN', hints: ['shpat_', 'shpca_', 'shppa_', 'shpss_'], re: re(NB + 'shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}' + NA) },
  { type: 'DIGITALOCEAN_TOKEN', hints: ['_v1_'], re: re(NB + 'do[opr]_v1_[a-f0-9]{64}' + NA) },
  { type: 'LINEAR_KEY', hints: ['lin_api_'], re: re(NB + 'lin_api_[A-Za-z0-9]{40}' + NA) },
  { type: 'TELEGRAM_BOT_TOKEN', hints: [':AA'], re: re('(?<![A-Za-z0-9])\\d{8,10}:AA[A-Za-z0-9_-]{33}' + NA) },
  { type: 'AZURE_STORAGE_KEY', hints: ['AccountKey='], re: re('AccountKey=([A-Za-z0-9+/]{86}==)'), group: 1 },
  { type: 'DATABRICKS_TOKEN', hints: ['dapi'], re: re(NB + 'dapi[a-f0-9]{32}(?:-\\d)?' + NA),
    check: (v) => /\d/.test(v.slice(4)) && /[a-f]/.test(v.slice(4)) },
  { type: 'VAULT_TOKEN', hints: ['hvs.', 'hvb.'], re: re(NB + 'hv[sb]\\.[A-Za-z0-9_-]{24,}' + NA) },
  { type: 'DOPPLER_TOKEN', hints: ['dp.'], re: re(NB + 'dp\\.(?:st|pt|sa|scim|audit|ct)\\.[A-Za-z0-9_.-]{40,}' + NA) },
  { type: 'NEWRELIC_KEY', hints: ['NRAK-', 'NRII-'], re: re(NB + 'NR(?:AK|II)-[A-Z0-9]{27}' + NA) },
  { type: 'GROQ_KEY', hints: ['gsk_'], re: re(NB + 'gsk_[A-Za-z0-9]{52}' + NA) },
  { type: 'XAI_KEY', hints: ['xai-'], re: re(NB + 'xai-[A-Za-z0-9]{80}' + NA) },
  /* Docker Hub personal (`dckr_pat_`) and organization (`dckr_oat_`) access
   * tokens: prefix + URL-safe characters. Docker's docs do not state the
   * length (checked 2026-10-14); the body minimum of 20 is assumed. */
  { type: 'DOCKERHUB_PAT', hints: ['dckr_pat_', 'dckr_oat_'], re: re(NB + 'dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}' + NA),
    check: (v) => looksRandom(v.replace(/^dckr_(?:pat|oat)_/, ''), 2, 3.3) },
  /* Tavily API key: `tvly-` + alphanumeric body. No length or charset in the
   * official docs (checked 2026-10-14); the body minimum of 20 and the digit
   * requirement are assumed. */
  { type: 'TAVILY_KEY', hints: ['tvly-'], re: re(NB + 'tvly-[A-Za-z0-9_-]{20,}' + NA),
    check: (v) => /\d/.test(v.slice(5)) && looksRandom(v.slice(5), 2, 3.3) },
  /* Firecrawl API key: `fc-` + alphanumeric body. No length in the docs
   * (checked 2026-10-14); a body minimum of 20 with a digit is assumed. The
   * boundaries keep slugs and CSS classes such as `fc-icon-...` apart. */
  { type: 'FIRECRAWL_KEY', hints: ['fc-'], re: re(NB + 'fc-[A-Za-z0-9]{20,}' + NA),
    check: (v) => /\d/.test(v.slice(3)) && looksRandom(v.slice(3), 2, 3.3) },
  /* Polar tokens: organization access tokens (`polar_oat_`), personal
   * tokens (`polar_pat_`), user and organization access tokens (`polar_at_u_`,
   * `polar_at_o_`), refresh tokens (`polar_rt_u_`, `polar_rt_o_`), client IDs
   * (`polar_ci_`) and client secrets (`polar_cs_`). The prefixes come from
   * Polar's docs (checked 2026-10-14); the body length is not stated, so a
   * minimum of 20 is assumed. */
  { type: 'POLAR_TOKEN', hints: ['polar_'], re: re(NB + 'polar_(?:oat|pat|(?:at|rt)_[uo]|ci|cs)_[A-Za-z0-9_-]{20,}' + NA),
    check: (v) => looksRandom(v.replace(/^polar_(?:oat|pat|(?:at|rt)_[uo]|ci|cs)_/, ''), 2, 3.3) },
  /* Replicate API token: `r8_` + 37 characters, 40 in total (official API
   * token docs, checked 2026-10-14). */
  { type: 'REPLICATE_TOKEN', hints: ['r8_'], re: re(NB + 'r8_[A-Za-z0-9]{37}' + NA),
    check: (v) => looksRandom(v.slice(3), 2, 3.3) },
  /* Supabase personal access token: `sbp_`, scoped ones as `sbp_fc...`. No
   * length in the docs (checked 2026-10-14); a body minimum of 30 with a
   * digit is assumed. */
  { type: 'SUPABASE_PAT', hints: ['sbp_'], re: re(NB + 'sbp_[A-Za-z0-9_-]{30,}' + NA),
    check: (v) => /\d/.test(v.slice(4)) && looksRandom(v.slice(4), 2, 3.3) },
  /* Azure AD client secret, as in gitleaks' azure-ad-client-secret rule:
   * three characters, a digit, `Q~`, then 31-34 characters. The body may
   * hold dots but ends on a non-dot character, so a full stop that closes a
   * sentence is not part of the span; the trailing lookahead still rejects
   * a dotted continuation such as `.json`. */
  { type: 'AZURE_AD_CLIENT_SECRET', hints: ['Q~'], re: re('(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{30,33}[A-Za-z0-9_~-](?![A-Za-z0-9_~-])(?!\\.[A-Za-z0-9_~-])'),
    check: (v) => looksRandom(v, 3, 3.5) },
  { type: 'JWT', hints: ['eyJ'], re: re(NB + 'eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{16,}' + NA) },
  { type: 'PRIVATE_KEY', hints: [PEM_BEGIN],
    re: re(PEM_BEGIN + PEM_LABEL + '-----[\\s\\S]{16,16384}?-----END \\1-----') },
  /* A private-key header whose END line was cut off (truncated output):
   * cover the header and the base64 lines that follow it. */
  { type: 'PRIVATE_KEY', hints: [PEM_BEGIN], truncated: true,
    re: re(PEM_BEGIN + PEM_LABEL + '-----(?:[ \\t]*\\r?\\n[ \\t>#*/"\'-]*(?:[A-Za-z0-9+/=:,-]+[ \\t]*))*') },
  /* Password segment of scheme://user:password@host (any scheme). */
  { type: 'DB_PASSWORD', hints: ['://'],
    re: re('\\b([a-zA-Z][a-zA-Z0-9+.-]{1,24}):\\/\\/([^\\s:@\\/?#\'"`<>]{0,128}):([^\\s@\\/?#\'"`<>]{1,256})@([A-Za-z0-9.-]+|\\[[0-9a-fA-F:]+\\])'),
    group: 3,
    check: (pw, text, index, m) => {
      const user = m[2];
      const scheme = m[1].toLowerCase();
      if (pw.length < 6) return false;
      if (isPlaceholder(pw) || pw === user || pw.toLowerCase() === scheme) return false;
      if (/^[A-Za-z]{1,8}$/.test(pw)) return false;           // short dictionary-like words in docs
      if (/^(?:%[0-9A-Fa-f]{2}){1,2}$/.test(pw)) return false;
      return true;
    },
    typeOf: (m) => (/^(?:https?|ftps?|wss?|sftp|ssh|git)$/i.test(m[1]) ? 'URL_PASSWORD' : 'DB_PASSWORD') },
  /* Generic assignment: sensitive key = quoted high-entropy value. */
  { type: 'SECRET', hints: null, prefilter: /(?:pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)/i,
    re: re('(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)[A-Za-z0-9_]{0,64}["\']?\\s*(?:=|:|=>|:=)\\s*["\'`]([^"\'`\\s\\\\]{12,200})["\'`]', 'i'),
    group: 1,
    check: (v) => !isPlaceholder(v) && looksRandom(v, 3, 3.7) && !/^[a-z]+(?:[_.-][a-z]+)+$/i.test(v) &&
      !/^(?:process\.env|os\.environ|\$|\{|%|<|https?:)/.test(v) && !/[()\[\]{};,]/.test(v) },
  /* Generic dotenv line: SENSITIVE_NAME=unquoted high-entropy value. */
  { type: 'SECRET', hints: null, prefilter: /(?:PASS|SECRET|TOKEN|KEY|CREDENTIAL|AUTH)/,
    re: re('^[ \\t]*(?:export[ \\t]+)?[A-Z][A-Z0-9_]{0,64}(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?|AUTH)[A-Z0-9_]{0,64}[ \\t]*=[ \\t]*([^\\s"\'`#]{16,200})[ \\t]*$', 'm'),
    group: 1,
    check: (v) => !isPlaceholder(v) && looksRandom(v, 3, 3.7) && !/^(?:\$|\{|%|<|https?:)/.test(v) },
  /* Sensitive key in structured config: YAML, docker-compose (map and
   * list), dotenv, Dockerfile ENV / ARG (see S_LINES). */
  { type: 'SECRET', hints: null, prefilter: S_PREFILTER, find: findStructured },
  /* `docker run -e KEY=value` / `--env KEY=value` / `--env=KEY=value`. */
  { type: 'SECRET', hints: ['-e', '--env'],
    re: re('(?<![^\\s])(?:-e|--env)(?:[ \\t]+|=)(["\']?)([A-Za-z_][A-Za-z0-9_]{0,127})=([^\\s"\'`;&|]{1,512})\\1(?![^\\s;&|)])'),
    group: 3, check: structuredCheck(2) },
];

const SECRET_TYPES = Array.from(new Set(PATTERNS.map((p) => p.type).concat(['URL_PASSWORD'])));

/* All literal hints (patterns and PII) in one automaton: a single pass over
 * the text tells which patterns can possibly match. */
let HINTS = null;
function hintsIn(text) {
  if (!HINTS) {
    const all = new Set();
    for (const p of PATTERNS.concat(PII)) for (const h of p.hints || []) all.add(h);
    HINTS = new AhoCorasick(Array.from(all).map((h) => ({ text: h, payload: h })));
  }
  return HINTS.present(text);
}

function hasHint(text, p, present) {
  if (p.prefilter) return p.prefilter.test(text);
  for (const h of p.hints) if (present.has(h)) return true;
  return false;
}

function findPatterns(text, opts) {
  const spans = [];
  if (!text) return spans;
  const present = (opts && opts._hints) || hintsIn(text);
  for (const p of PATTERNS) {
    if (!hasHint(text, p, present)) continue;
    if (p.find) {
      const found = [];
      p.find(text, found);
      for (const f of found) spans.push({ start: f.start, end: f.end, type: p.type, source: 'pattern' });
      continue;
    }
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(text)) !== null) {
      if (m[0].length === 0) { p.re.lastIndex++; continue; }
      let start = m.index;
      let value = m[0];
      if (p.group) {
        value = m[p.group];
        if (value === undefined || !m.indices || !m.indices[p.group]) continue;
        start = m.indices[p.group][0];
      }
      if (p.check && !p.check(value, text, start, m)) continue;
      let end = start + value.length;
      if (p.type === 'PRIVATE_KEY') {
        // Trim trailing whitespace captured by the truncated-block variant.
        while (end > start && /\s/.test(text[end - 1])) end--;
        value = text.slice(start, end);
        if (value.length < 40) continue;
        // The truncated-block variant only applies where no complete block matched.
        if (p.truncated && spans.some((s) => s.type === 'PRIVATE_KEY' && s.start === start)) continue;
      }
      spans.push({ start, end, type: p.typeOf ? p.typeOf(m) : p.type, source: 'pattern' });
    }
  }
  return spans;
}

/* ------------------------------------------------------------------ */
/* PII                                                                 */
/* ------------------------------------------------------------------ */

const FILE_TLDS = new Set(['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'css', 'scss', 'map', 'json', 'html', 'htm', 'md', 'txt', 'py', 'rb', 'go', 'rs', 'java', 'lock', 'yml', 'yaml', 'toml', 'xml', 'pdf', 'zip', 'gz', 'tgz', 'wasm', 'node', 'so', 'dll']);
const EMAIL_LOCAL_SKIP = new Set(['git', 'noreply', 'no-reply']);
const PRIVATE_TLDS = new Set(['internal', 'local', 'localdomain', 'localhost', 'lan', 'intranet', 'corp', 'home', 'invalid']);

/* E-mail search anchored on '@' (code is full of decorators and '@'
 * mentions; a regex tried at every position is several times slower).
 * Equivalent to: (?<![local])[alnum](?:[local]{0,62}[alnum])?@<domain>. */
const LOCAL_CHARS = new Uint8Array(128);
for (const ch of 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-') LOCAL_CHARS[ch.charCodeAt(0)] = 1;
function isAlnum(c) { return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122); }
const EMAIL_DOMAIN = /(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9-])/y;

function findEmails(text, check, out) {
  let at = text.indexOf('@');
  while (at >= 0) {
    let s = at;
    while (s > 0 && at - s < 64 && text.charCodeAt(s - 1) < 128 && LOCAL_CHARS[text.charCodeAt(s - 1)]) s--;
    const boundaryOk = s === 0 || !(text.charCodeAt(s - 1) < 128 && LOCAL_CHARS[text.charCodeAt(s - 1)]);
    if (s < at && boundaryOk && isAlnum(text.charCodeAt(s)) && isAlnum(text.charCodeAt(at - 1))) {
      EMAIL_DOMAIN.lastIndex = at + 1;
      const m = EMAIL_DOMAIN.exec(text);
      if (m) {
        const v = text.slice(s, at + 1 + m[0].length);
        if (check(v, text, s)) out.push({ start: s, end: s + v.length });
      }
    }
    at = text.indexOf('@', at + 1);
  }
}

const PII = [
  { type: 'EMAIL', key: 'email', hints: ['@'], find: findEmails,
    check: (v, text, index) => {
      // user@host inside a URL (scheme://user@host) is not an e-mail address
      if (index >= 3 && text.slice(index - 3, index) === '://') return false;
      if (/^:\d/.test(text.slice(index + v.length, index + v.length + 2))) return false;
      const at = v.indexOf('@');
      const local = v.slice(0, at).toLowerCase();
      const tld = v.slice(v.lastIndexOf('.') + 1).toLowerCase();
      if (EMAIL_LOCAL_SKIP.has(local)) return false;
      if (FILE_TLDS.has(tld) || PRIVATE_TLDS.has(tld)) return false;
      if (/\.\./.test(v)) return false;
      return true;
    } },
  { type: 'PHONE', key: 'phone', hints: ['+'], re: re('(?<![A-Za-z0-9+])\\+[1-9]\\d{7,14}(?![0-9])'), check: (v) => e164Valid(v) },
  { type: 'IBAN', key: 'iban', hints: null, prefilter: /[A-Z]{2}\d{2}/,
    re: re('(?<![A-Za-z0-9])[A-Z]{2}\\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?(?![A-Za-z0-9])'),
    check: (v) => ibanValid(v) },
  { type: 'CARD', key: 'card', hints: null, prefilter: /\d{4}/,
    re: re('(?<![0-9A-Za-z.,_-])(?:\\d{4}[ -]?){2,3}\\d{1,4}(?:[ -]?\\d{1,3})?(?![0-9A-Za-z_]|[.,]\\d)'),
    check: (v) => {
      const sep = v.match(/[ -]/g);
      if (sep && new Set(sep).size > 1) return false;
      return cardValid(v);
    } },
  { type: 'DNI', key: 'dni', hints: null, prefilter: /\d{8}-?[A-Za-z]/,
    re: re('(?<![A-Za-z0-9_.-])\\d{8}-?[A-Z](?![A-Za-z0-9_])'), check: (v) => dniValid(v) },
  { type: 'NIE', key: 'dni', hints: ['X', 'Y', 'Z'],
    re: re('(?<![A-Za-z0-9_.-])[XYZ]-?\\d{7}-?[A-Z](?![A-Za-z0-9_])'), check: (v) => nieValid(v) },
  { type: 'SSN', key: 'ssn', hints: ['-'],
    re: re('(?<![0-9A-Za-z.-])\\d{3}-\\d{2}-\\d{4}(?![0-9A-Za-z]|-\\d)'), check: (v) => ssnValid(v) },
  { type: 'IPV4', key: 'ipv4', hints: ['.'],
    re: re('(?<![0-9.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![0-9.])'), check: (v) => ipv4Public(v) },
];

const PII_DEFAULTS = { email: true, phone: true, iban: true, card: true, dni: true, ssn: true, ipv4: false };
const PII_TYPES = PII.map((p) => p.type);

function findPii(text, opts) {
  const spans = [];
  if (!text) return spans;
  const enabled = Object.assign({}, PII_DEFAULTS, (opts && typeof opts.pii === 'object' && opts.pii) || {});
  const present = (opts && opts._hints) || hintsIn(text);
  for (const p of PII) {
    if (!enabled[p.key]) continue;
    if (!hasHint(text, p, present)) continue;
    if (p.find) {
      const found = [];
      p.find(text, p.check, found);
      for (const f of found) spans.push({ start: f.start, end: f.end, type: p.type, source: 'pii' });
      continue;
    }
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(text)) !== null) {
      if (p.check && !p.check(m[0], text, m.index)) continue;
      spans.push({ start: m.index, end: m.index + m[0].length, type: p.type, source: 'pii' });
    }
  }
  return spans;
}

module.exports = {
  SCRUB_RULES_VERSION,
  findPatterns,
  hintsIn,
  findPii,
  PATTERNS,
  SECRET_TYPES,
  PII_TYPES,
  PII_DEFAULTS,
  // validators (exported for tests and for the exact-value layer)
  luhnValid,
  ibanValid,
  dniValid,
  nieValid,
  ssnValid,
  cardValid,
  e164Valid,
  ipv4Public,
  shannon,
  looksRandom,
  isPlaceholder,
  sensitiveKey,
  structuredValue,
  hexSecret,
};
