'use strict';
/**
 * Custom secret formats from the organization policy (`detectors`), run by
 * the local scrubber next to the built-in patterns. They only add
 * redactions; they can never stop a built-in one.
 *
 * A pattern comes from the network, so it is treated as untrusted. A
 * JavaScript regular expression cannot be interrupted once it runs, so the
 * client accepts only a grammar whose cost is bounded before it runs, and
 * checks it with a parser, not with regular expressions:
 *
 *   pattern  = ["^"] item+ ["$"]
 *   item     = atom [ "{" n "}" | "{" m "," n "}" ]
 *   atom     = literal | "\" escape | "." | "[" class "]"
 *
 * That is a flat sequence of characters and character classes, each with an
 * optional bounded repetition: no groups, no alternatives, no `?`, `*` or
 * `+`, no back-references or lookaround. At most one repetition may vary in
 * length ({m,n} with m < n, spanning at most 64), n is at most 256, and
 * (span + 1) x (longest possible match) is at most 4096. A regular
 * expression of this shape tries at most that many steps per start
 * position, so one 4096-character window costs at most about 1.7e7 steps.
 * Token formats fit (`ACME-[A-Z0-9]{24}`, `ghp_[A-Za-z0-9]{36}`,
 * `xoxb-[0-9]{10,13}-...`); a pattern outside the grammar is skipped on
 * this machine.
 *
 * Text is scanned one line at a time, in windows of at most 4096
 * characters. A value split across two windows of a very long line is not
 * found by a custom detector; the built-in layers are not affected. All
 * custom detectors together get 200 ms per call and 1 s per process (a hook
 * is one short process); past either, their remaining work is skipped. A detector whose run on one window takes
 * longer than 50 ms is switched off for the rest of the process.
 */

const WINDOW = 4096;
const SLOW_MS = 50;
const TYPE_RE = /^[A-Z0-9](?:[A-Z0-9_]{0,62}[A-Z0-9])?$/;
const ID_RE = /^[a-z0-9_]{1,64}$/;

const MAX_VARIABLE = 1;
const MAX_SPAN = 64;
const MAX_REPEAT = 256;
const MAX_COST = 4096;
const CALL_BUDGET_MS = 200;
const PROCESS_BUDGET_MS = 1000;
let spentMs = 0;
const SPECIAL = '\\^$.|?*+()[]{}';
// Escapes that stand for one character or a class of one character.
const ESCAPES = /^[dDwWsStrnfv.\\^$|?*+()[\]{}\/-]$/;

/** Why a pattern is outside the grammar, or null. */
function checkPattern(pattern) {
  if (typeof pattern !== 'string' || pattern.length < 4 || pattern.length > 256) return 'invalid length';
  const p = pattern;
  let i = 0;
  let items = 0;
  let variable = 0;
  let span = 0;
  let maxLen = 0;
  if (p[i] === '^') i++;
  while (i < p.length) {
    if (p[i] === '$' && i === p.length - 1) { i++; break; }
    // atom
    const ch = p[i];
    if (ch === '\\') {
      const e = p[i + 1];
      if (e === undefined || !ESCAPES.test(e)) return 'unsupported escape \\' + (e || '');
      i += 2;
    } else if (ch === '[') {
      let j = i + 1;
      if (p[j] === '^') j++;
      if (p[j] === ']') return 'empty character class';
      while (j < p.length && p[j] !== ']') {
        if (p[j] === '\\') {
          if (p[j + 1] === undefined || !ESCAPES.test(p[j + 1])) return 'unsupported escape in a class';
          j += 2;
        } else if (p[j] === '[') {
          return 'nested character class';
        } else {
          j++;
        }
      }
      if (p[j] !== ']') return 'unterminated character class';
      i = j + 1;
    } else if (ch === '.') {
      i++;
    } else if (SPECIAL.includes(ch)) {
      return 'only characters, character classes and {n} or {m,n} repetitions are allowed (no ' + ch + ')';
    } else {
      i++;
    }
    items++;
    // optional bounded repetition
    let hi = 1;
    if (p[i] === '{') {
      const m = /^\{(\d{1,3})(?:,(\d{1,3}))?\}/.exec(p.slice(i));
      if (!m) return 'repetitions are written {n} or {m,n}';
      const lo = Number(m[1]);
      hi = m[2] === undefined ? lo : Number(m[2]);
      if (hi < lo || hi > MAX_REPEAT || hi === 0) return 'repetition bounds must be 1 to ' + MAX_REPEAT;
      if (hi > lo) {
        if (hi - lo > MAX_SPAN) return 'a variable repetition can span at most ' + MAX_SPAN;
        variable++;
        span = Math.max(span, hi - lo);
      }
      i += m[0].length;
      if (p[i] === '?' || p[i] === '+' || p[i] === '{') return 'repetition modifiers are not allowed';
    }
    maxLen += hi;
  }
  if (i !== p.length) return 'unexpected text after $';
  if (items === 0) return 'empty pattern';
  if (variable > MAX_VARIABLE) return 'at most ' + MAX_VARIABLE + ' variable-length repetition is allowed';
  if ((span + 1) * maxLen > MAX_COST) return 'pattern too costly: (repetition span + 1) x longest match must be at most ' + MAX_COST;
  let re;
  try { re = new RegExp(p); } catch (err) { return 'invalid regular expression'; }
  if (re.test('')) return 'pattern must not match the empty string';
  return null;
}

/** compile(detectors) -> [{id, type, re}] for the ones that pass the checks. */
function compile(detectors) {
  const out = [];
  for (const d of Array.isArray(detectors) ? detectors.slice(0, 50) : []) {
    if (!d || !ID_RE.test(d.id || '') || !TYPE_RE.test(d.type || '') || checkPattern(d.pattern)) continue;
    out.push({ id: d.id, type: d.type, re: new RegExp(d.pattern, 'g'), off: false });
  }
  return out;
}

function* windows(text) {
  let pos = 0;
  while (pos < text.length) {
    let end = text.indexOf('\n', pos);
    if (end < 0) end = text.length;
    for (let s = pos; s < end; s += WINDOW) yield [s, Math.min(end, s + WINDOW)];
    if (end === pos) yield [pos, pos];
    pos = end + 1;
  }
}

/** find(text, compiled) -> [{start, end, type, source: 'pattern', detector}] */
function find(text, compiled) {
  const spans = [];
  if (!compiled || compiled.length === 0 || typeof text !== 'string' || text.length === 0) return spans;
  if (spentMs > PROCESS_BUDGET_MS) return spans;
  const start = Date.now();
  try {
    scan(text, compiled, spans, start);
  } finally {
    spentMs += Date.now() - start;
    // A hook runs as one short process and may scan many strings: once the
    // detectors used up the budget of the whole process, they all stop.
    if (spentMs > PROCESS_BUDGET_MS) for (const d of compiled) d.off = true;
  }
  return spans;
}

function scan(text, compiled, spans, start) {
  for (const d of compiled) {
    if (d.off) continue;
    for (const [a, b] of windows(text)) {
      if (Date.now() - start > CALL_BUDGET_MS) return;
      if (b - a < 1) continue;
      const chunk = text.slice(a, b);
      d.re.lastIndex = 0;
      const t0 = Date.now();
      let m;
      while ((m = d.re.exec(chunk)) !== null) {
        if (m[0].length === 0) { d.re.lastIndex++; continue; }
        spans.push({ start: a + m.index, end: a + m.index + m[0].length, type: d.type, source: 'pattern', detector: d.id });
      }
      if (Date.now() - t0 > SLOW_MS) { d.off = true; break; }
    }
  }
}

/** For tests: start a new process budget. */
function resetBudget() { spentMs = 0; }

module.exports = { checkPattern, compile, find, resetBudget, WINDOW, MAX_VARIABLE, MAX_SPAN, MAX_COST, CALL_BUDGET_MS, PROCESS_BUDGET_MS };
