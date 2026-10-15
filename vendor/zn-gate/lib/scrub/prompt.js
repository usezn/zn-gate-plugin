'use strict';
/**
 * Prompt-only layer: `NAME=value` or `NAME: value` anywhere in a prompt,
 * also in the middle of a sentence ("my key is STRIPE_KEY=..."), when NAME is
 * a sensitive name (API_KEY, DB_PASSWORD, authToken...) and the value is at
 * least 8 characters and is not a placeholder, a reference or code.
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

/* NAME, optionally quoted, then `=` or `:`, then the value, optionally
 * quoted. The name must not follow a word character, `$`, `${`, `.` or `-`
 * (shell and code references such as $API_KEY, ${API_KEY}, env.API_KEY). */
const ASSIGN_RE = /(?<![A-Za-z0-9_$.-])(?<!\$\{)(["']?)([A-Za-z_][A-Za-z0-9_-]{1,127})\1[ \t]*(=|:)[ \t]*(["']?)([^\s"'`]{1,512})/g;

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

function findPromptAssignments(text) {
  const out = [];
  if (typeof text !== 'string' || text.length < MIN_VALUE) return out;
  const t = text.length > MAX_PROMPT ? text.slice(0, MAX_PROMPT) : text;
  ASSIGN_RE.lastIndex = 0;
  let m;
  while ((m = ASSIGN_RE.exec(t)) !== null) {
    const name = m[2];
    const sep = m[3];
    const start = m.index + m[0].length - m[5].length;
    // A rejected candidate may hide one inside its value
    // (https://host/path?api_key=...): scan again from the value.
    const retry = () => { ASSIGN_RE.lastIndex = start; };
    if (sep === ':' && !m[1] && !identifierLike(name)) { retry(); continue; }  // a quoted key is never prose
    if (!sensitiveKey(name)) { retry(); continue; }
    if (/(?:\.\.\.|…)$/.test(m[5])) { retry(); continue; }   // elided: "zn_live_..."
    const value = trimTrailing(m[5]);
    if (!promptValue(value, sep)) { retry(); continue; }
    out.push({ start, end: start + value.length, type: 'CREDENTIAL', name: name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/-/g, '_').toUpperCase(), source: 'pattern' });
  }
  return out;
}

module.exports = { findPromptAssignments };
