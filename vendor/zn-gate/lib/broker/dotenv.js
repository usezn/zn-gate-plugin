'use strict';

/**
 * Minimal .env parser that keeps byte positions, so `zn env shadow` can
 * rewrite only the value part of a line and leave comments, ordering,
 * quoting and `export` prefixes exactly as they were.
 *
 * Supported: KEY=value, export KEY=value, 'single', "double" (with \n
 * escapes left as written), unquoted values with trailing # comments.
 * Multi-line quoted values are reported as such and never rewritten.
 */

const SENSITIVE_KEY_RE = /(KEY|SECRET|TOKEN|PASS|PWD|CREDENTIAL|AUTH|DSN|DATABASE_URL|_URL$|_URI$|CONN)/i;
const MIN_SECRET_LEN = 8;

const LINE_RE = /^([ \t]*(?:export[ \t]+)?)([A-Za-z_][A-Za-z0-9_.-]*)([ \t]*=[ \t]*)(.*)$/;

/**
 * Parse text into entries: {line, key, value, quote, start, end, multiline}
 * where start/end are offsets of the value (inside quotes) within the line.
 */
function parseDotenv(text) {
  const lines = String(text).split(/(\r?\n)/);
  const entries = [];
  // lines alternates [content, sep, content, sep, ...]
  for (let i = 0; i < lines.length; i += 2) {
    const line = lines[i];
    const m = LINE_RE.exec(line);
    if (!m) continue;
    const prefixLen = m[1].length + m[2].length + m[3].length;
    const rest = m[4];
    let value;
    let quote = '';
    let start;
    let end;
    let multiline = false;
    if (rest.startsWith('"') || rest.startsWith("'") || rest.startsWith('`')) {
      quote = rest[0];
      const close = rest.indexOf(quote, 1);
      if (close === -1) {
        multiline = true;
        value = rest.slice(1);
        start = prefixLen + 1;
        end = line.length;
      } else {
        value = rest.slice(1, close);
        start = prefixLen + 1;
        end = prefixLen + close;
      }
    } else {
      const hash = rest.search(/[ \t]#/);
      const raw = hash === -1 ? rest : rest.slice(0, hash);
      value = raw.trimEnd();
      start = prefixLen;
      end = prefixLen + value.length;
    }
    entries.push({ lineIndex: i, key: m[2], value, quote, start, end, multiline });
  }
  return { lines, entries };
}

function isSensitiveKey(key) {
  return SENSITIVE_KEY_RE.test(key);
}

/**
 * For connection strings, only the password is secret. Returns
 * {start, end} of the password inside value, or null.
 */
function connectionPassword(value) {
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^:@/\s]*):([^@/\s]+)@/i.exec(value);
  if (!m) return null;
  const start = m[1].length + m[2].length + 1;
  return { start, end: start + m[3].length };
}

/** Rebuild text after replacing value ranges. edits: [{lineIndex, start, end, text}] */
function applyEdits(parsed, edits) {
  const lines = parsed.lines.slice();
  const byLine = new Map();
  for (const e of edits) {
    if (!byLine.has(e.lineIndex)) byLine.set(e.lineIndex, []);
    byLine.get(e.lineIndex).push(e);
  }
  for (const [idx, list] of byLine) {
    list.sort((a, b) => b.start - a.start);
    let line = lines[idx];
    for (const e of list) line = line.slice(0, e.start) + e.text + line.slice(e.end);
    lines[idx] = line;
  }
  return lines.join('');
}

/**
 * Names of the sensitive variables that still hold a real value: not empty,
 * not a __ZN_ marker (or a connection string whose password is one), whatever
 * the length. Names only, never values.
 */
function plainSecretNames(text) {
  const { entries } = parseDotenv(text);
  const names = [];
  for (const e of entries) {
    if (!isSensitiveKey(e.key)) continue;
    if (e.value === '') continue; // nothing to leak
    if (/^__ZN_[A-Z0-9_]+__$/.test(e.value)) continue; // the whole value must be a marker: x__ZN_ is a real value
    const pw = connectionPassword(e.value);
    if (pw && /^__ZN_[A-Z0-9_]+__$/.test(e.value.slice(pw.start, pw.end))) continue;
    // A URL without credentials is not a secret, but only under a _URL or _URI name: API_KEY=https://example.com still is one.
    if (!pw && /_UR[LI]$/i.test(e.key) && /^[a-z][a-z0-9+.-]*:\/\//i.test(e.value)) continue;
    if (!names.includes(e.key)) names.push(e.key);
  }
  return names;
}

/**
 * Is this .env already shadowed? True when no sensitive variable still holds a
 * plain value. Short values count too: a 3-character password is still a password.
 */
function isShadowed(text) {
  return plainSecretNames(text).length === 0;
}

module.exports = {
  SENSITIVE_KEY_RE,
  MIN_SECRET_LEN,
  parseDotenv,
  isSensitiveKey,
  connectionPassword,
  applyEdits,
  plainSecretNames,
  isShadowed,
};
