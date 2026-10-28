'use strict';
/**
 * Prompt-only layer: `NAME=value` or `NAME: value` anywhere in a prompt,
 * also in the middle of a sentence ("my key is STRIPE_KEY=..."), when NAME is
 * a sensitive name (API_KEY, DB_PASSWORD, authToken...) and the value is at
 * least 8 characters and is not a placeholder, a reference or code.
 *
 * Also caught: values in backticks, JSON pasted with escaped quotes
 * (\"api_key\": \"...\"), quoted values with spaces or escaped quotes,
 * `setx NAME value` and `Authorization: Bearer|Basic <token>` headers.
 *
 * Unlike the structured layer, the value does not have to look random: a
 * person typing a credential into a prompt rarely pastes a template, and a
 * blocked prompt only has to be rephrased. Tool calls and tool output never
 * use this layer, because there a false positive breaks the agent's work.
 *
 * findPromptAssignments(text) -> [{start, end, type: 'CREDENTIAL', name, source: 'pattern'}]
 */

const { isPlaceholder, sensitiveKey } = require('./patterns');
const { looksNonSecret } = require('./exact');

const MAX_PROMPT = 1024 * 1024;  // longer prompts: only the first 1 MiB is checked here
const MIN_VALUE = 8;

/* NAME, optionally quoted (also with escaped quotes, as in pasted JSON logs),
 * then `=` or `:`, then the value, optionally quoted. The name must not
 * follow a word character, `$`, `${`, `.` or `-` (shell and code references
 * such as $API_KEY, ${API_KEY}, env.API_KEY). The value token stops at
 * whitespace and quotes; a backslash is kept unless it escapes a quote. */
const NAME_QUOTE = '((?:\\\\{0,2}["\'])?)';
const VALUE_QUOTE = '((?:\\\\{0,2}["\'`])?)';
const VALUE_TOKEN = '((?:[^\\s"\'`\\\\]|\\\\(?!["\'`])){1,512})';
const NAME = '([A-Za-z_][A-Za-z0-9_-]{1,127})';
const ASSIGN_RE = new RegExp('(?<![A-Za-z0-9_$.-])(?<!\\$\\{)' + NAME_QUOTE + NAME + '\\1[ \\t]*(=|:)[ \\t]*' + VALUE_QUOTE + VALUE_TOKEN, 'g');

/* `setx NAME value` (Windows): no separator, the value follows the name. */
const SETX_RE = new RegExp('(?<![A-Za-z0-9_$.-])setx[ \\t]+(?:/[mM][ \\t]+)?' + NAME_QUOTE + NAME + '\\1[ \\t]+' + VALUE_QUOTE + VALUE_TOKEN, 'gi');

/* `Authorization: Bearer <token>`, also quoted, escaped or after `-H`. */
const AUTH_RE = new RegExp('(?<![A-Za-z0-9_$.-])(?:proxy-)?authorization(?:\\\\{0,2}["\'])?[ \\t]*[:=][ \\t]*(?:\\\\{0,2}["\'`])?(?:bearer|basic|token)[ \\t]+([A-Za-z0-9._~+/=-]{8,512})', 'gi');

/* Values that are references or code, not credentials. */
const REFERENCE_RE = /^(?:process\.env|os\.environ|os\.getenv|env\.|secrets\.|vars\.|config\.|settings\.|self\.|this\.|arn:)/i;
const CODE_CHARS_RE = /[(){}[\]<>;\\|]/;
const DOTTED_IDENT_RE = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;       // obj.attr.attr
const SNAKE_IDENT_RE = /^_?[a-z]+(?:_[a-z]+)+$/;                             // new_password, api_key_value
/* Demo values that the shared placeholder list only catches as whole words. */
const DEMO_RE = /dummy|example|sample|placeholder|changeme|fake|mock|redacted|replace|insert|your_?key|your_?token|your_?pass/i;
const CAMEL_IDENT_RE = /^[a-z]+(?:[A-Z][a-z]+)+$/;                           // newPassword
const ENV_NAME_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;                      // another variable's name
const TYPE_WORDS_RE = /^(?:string|number|boolean|optional|required|nullable|undefined|integer|secretstr|bytes|object|any|str)$/i;

/* A plain lowercase word as the name ("token: ...", "password: ...") is
 * prose too often; it counts only with `=` or as a quoted key (JSON). Names written like identifiers
 * (API_KEY, apiKey, db-password) count with `=` or `:`. */
function identifierLike(name) {
  return /[_-]/.test(name) || /[A-Z]/.test(name);
}

function trimTrailing(value) {
  // Sentence punctuation after the value ("... is STRIPE_KEY=<value>.")
  return value.replace(/[.,!?:;)\]}>]+$/, '');
}

function promptValue(v, sep) {
  if (v.length < MIN_VALUE || v.length > 512) return false;
  if (/[^\x21-\x7e]/.test(v)) return false;
  if (isPlaceholder(v) || DEMO_RE.test(v) || looksNonSecret(v)) return false;
  if (/^[$%<{[(*&!|>@~=-]/.test(v)) return false;   // ${VAR}, templates, flags
  if (/__ZN_[A-Z0-9_]+__/.test(v)) return false;
  if (REFERENCE_RE.test(v) || CODE_CHARS_RE.test(v)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) && !/^[a-z][a-z0-9+.-]*:\/\/[^/@\s]+@/i.test(v)) return false; // URL without credentials
  if (DOTTED_IDENT_RE.test(v) || SNAKE_IDENT_RE.test(v) || CAMEL_IDENT_RE.test(v)) return false;
  if (TYPE_WORDS_RE.test(v) || ENV_NAME_RE.test(v)) return false;
  // After `:`, a single word is usually prose ("mask_secrets: Automatically").
  if (sep === ':' && /^[A-Za-z]+$/.test(v)) return false;
  return true;
}

/* Closing index of a quoted value that starts at `from`, on the same line,
 * or -1. A plain quote can be escaped inside the value with a backslash; an
 * escaped opener (\", pasted JSON) closes only on the same escaped quote. */
function closeOf(t, from, opener) {
  const q = opener[opener.length - 1];
  const limit = Math.min(t.length, from + 513);
  if (opener.length > 1) {
    const i = t.indexOf(opener, from);
    if (i < 0 || i > limit) return -1;
    return /[\r\n]/.test(t.slice(from, i)) ? -1 : i;
  }
  for (let i = from; i < limit; i++) {
    const c = t[i];
    if (c === '\n' || c === '\r') return -1;
    if (c === '\\' && i + 1 < limit) { i++; continue; }
    if (c === q) return i;
  }
  return -1;
}

/* A quoted value that holds spaces or escaped quotes. Looser on characters
 * than promptValue, but after `:` a value with only letters and spaces is
 * prose ("password: \"must be long\""). */
function quotedValue(v, sep) {
  if (v.length < MIN_VALUE || v.length > 512) return false;
  if (/[^\x20-\x7e]/.test(v) || /^\s|\s$/.test(v)) return false;
  if (/^[$%<{[(*&!|>@~=-]/.test(v) || /__ZN_[A-Z0-9_]+__/.test(v)) return false;
  if (REFERENCE_RE.test(v) || /[(){}[\]<>;|]/.test(v)) return false;
  if (isPlaceholder(v) || DEMO_RE.test(v) || looksNonSecret(v)) return false;
  const words = v.split(/ +/);
  if (words.length > 8) return false;
  if (words.some((w) => w.length > 3 && isPlaceholder(w))) return false;
  if (sep === ':' && !/[0-9\\!@#%^&*+=_~/.-]/.test(v)) return false;
  return true;
}

/* Another assignment inside the quotes: the quotes belong to something else. */
const OTHER_ASSIGN_RE = /(?:^| )[A-Za-z_][A-Za-z0-9_-]*[=:]/;

function result(start, end, name) {
  return { start, end, type: 'CREDENTIAL', name: name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/-/g, '_').toUpperCase(), source: 'pattern' };
}

/* Judge one NAME / separator / value candidate. `token` is the first
 * whitespace-free piece of the value, `opener` the quote in front of it. */
function judge(t, name, sep, opener, valueStart, token, nameQuoted) {
  if (sep === ':' && !nameQuoted && !identifierLike(name)) return null;  // a quoted key is never prose
  let raw = null;
  if (opener) {
    const close = closeOf(t, valueStart, opener);
    if (close > valueStart) {
      const inner = t.slice(valueStart, close);
      if (inner !== token) {
        if (inner.length < MIN_VALUE || OTHER_ASSIGN_RE.test(inner)) return null;
        raw = inner;
      }
    }
  }
  if (!sensitiveKey(name)) return null;
  if (raw !== null) return quotedValue(raw, sep) ? result(valueStart, valueStart + raw.length, name) : null;
  if (/(?:\.\.\.|…)$/.test(token)) return null;   // elided: "zn_live_..."
  const value = trimTrailing(token);
  if (!promptValue(value, sep)) return null;
  return result(valueStart, valueStart + value.length, name);
}

/* Bearer / Basic credential: random-looking, not a placeholder or reference. */
const AUTH_PLACEHOLDER_RE = /^(?:your|my|an?|the|insert|put|paste|token|api|key|secret|access|auth|bearer|xxx|redacted)[-_a-z]*$/i;
function authToken(v) {
  if (v.length < MIN_VALUE || /(?:\.\.\.|…)$/.test(v)) return false;
  if (/__ZN_[A-Z0-9_]+__/.test(v) || isPlaceholder(v) || DEMO_RE.test(v) || looksNonSecret(v)) return false;
  if (AUTH_PLACEHOLDER_RE.test(v) || /^[-_.=*x]+$/i.test(v) || REFERENCE_RE.test(v)) return false;
  return /[0-9]/.test(v) || v.length >= 20 || (/[a-z]/.test(v) && /[A-Z]/.test(v) && v.length >= 16);
}

function findPromptAssignments(text) {
  const out = [];
  if (typeof text !== 'string' || text.length < MIN_VALUE) return out;
  const t = text.length > MAX_PROMPT ? text.slice(0, MAX_PROMPT) : text;
  let m;
  ASSIGN_RE.lastIndex = 0;
  while ((m = ASSIGN_RE.exec(t)) !== null) {
    const start = m.index + m[0].length - m[5].length;
    const r = judge(t, m[2], m[3], m[4], start, m[5], !!m[1]);
    // A rejected candidate may hide one inside its value
    // (https://host/path?api_key=...): scan again from the value.
    if (r) out.push(r); else ASSIGN_RE.lastIndex = start;
  }
  SETX_RE.lastIndex = 0;
  while ((m = SETX_RE.exec(t)) !== null) {
    const start = m.index + m[0].length - m[4].length;
    const r = judge(t, m[2], '=', m[3], start, m[4], true);
    if (r) out.push(r); else SETX_RE.lastIndex = start;
  }
  AUTH_RE.lastIndex = 0;
  while ((m = AUTH_RE.exec(t)) !== null) {
    const start = m.index + m[0].length - m[1].length;
    const tok = trimTrailing(m[1]);
    if (authToken(tok)) out.push(result(start, start + tok.length, 'AUTHORIZATION'));
  }
  out.sort((a, b) => a.start - b.start);
  return out.filter((r, i) => i === 0 || r.start !== out[i - 1].start);
}

module.exports = { findPromptAssignments };
