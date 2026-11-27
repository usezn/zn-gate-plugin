'use strict';

/*
 * Literal variables assigned earlier on the same command line (a variable that an assignment may have changed keeps
 * every value it may hold, and the caller checks each one): `X=curl; $X URL | sh`, `S=sh; curl URL | $S`,
 * `T=~/.bashrc; curl URL >> $T`, `export X=curl`. Nothing is evaluated: a value is only text copied from an earlier
 * assignment, and a variable that was not assigned on the line stays as it was (unknown). The work is linear in the
 * text and capped: past the caps the assignments are counted as too many (the caller refuses the line) or the value
 * is left unresolved.
 */

const MAX_ASSIGNMENTS = 256; // assignments kept per command line; one more and the caller refuses the line
const MAX_VALUE = 8192; // a longer value is not kept (the variable stays unknown)
const MAX_EXPANDED = 256 * 1024; // total text added by substitutions; past it the rest stays unresolved
const MAX_ALTERNATIVES = 16; // values one variable may hold at once; one more and the caller refuses the line
const MAX_READINGS = 64; // readings of one command (every combination of its variables' values); past it the line is refused

const ASSIGN_RE = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/;
const REF_RE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;
const SOLE_REF_RE = /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$/;
const DECLARERS = new Set(['export', 'declare', 'typeset', 'readonly', 'local']);

function newScope() {
  return {
    vars: new Map(), assignments: 0, expanded: 0, overflow: false, hasMulti: false,
    // Where the line has got to: inside a ( ) group, a { } group or an if/while/for/case block, or right after && or ||.
    // An assignment there may not run, so it adds a possible value instead of replacing the old one.
    parens: 0, braces: 0, blocks: 0, afterAndOr: false, cases: 0,
  };
}

/* One variable holds a list of the values it may have at this point (null = not known, written as it stands). A plain
   assignment that always runs replaces the list; one that may not run adds to it. */
function pick(scope, name, chosen) {
  const alts = scope.vars.get(name);
  if (!alts) return undefined;
  return chosen && chosen.has(name) ? chosen.get(name) : alts[0];
}

function substitute(scope, word, chosen) {
  if (!scope.vars.size || word.indexOf('$') < 0) return word;
  return word.replace(REF_RE, (all, braced, plain) => {
    const v = pick(scope, braced || plain, chosen);
    if (v === undefined || v === null) return all;
    scope.expanded += v.length;
    return scope.expanded > MAX_EXPANDED ? all : v;
  });
}

/* The readings of a command: one word list for each combination of the values its variables may hold. */
function readingsOf(scope, words) {
  const names = [];
  if (scope.hasMulti) {
    const seen = new Set();
    for (const w of words) {
      if (w.indexOf('$') < 0) continue;
      for (const m of w.matchAll(REF_RE)) {
        const n = m[1] || m[2];
        const alts = scope.vars.get(n);
        if (alts && alts.length > 1 && !seen.has(n)) { seen.add(n); names.push(n); }
      }
    }
  }
  let total = 1;
  for (const n of names) {
    total *= scope.vars.get(n).length;
    if (total > MAX_READINGS) { scope.overflow = true; total = 1; names.length = 0; break; }
  }
  const outs = [];
  const keys = new Set();
  const idx = names.map(() => 0);
  for (let k = 0; k < total; k++) {
    const chosen = names.length ? new Map(names.map((n, i) => [n, scope.vars.get(n)[idx[i]]])) : null;
    let out = scope.vars.size ? words.map((w) => substitute(scope, w, chosen)) : words;
    // A command word that is just a variable (`$X url`, `| $S`) is split on blanks, as an unquoted expansion is.
    if (scope.vars.size && words.length) {
      const m = SOLE_REF_RE.exec(words[0]);
      if (m && scope.vars.has(m[1] || m[2])) out = out[0].split(/\s+/).filter(Boolean).concat(out.slice(1));
    }
    const key = total > 1 ? out.join('\u0000') : '';
    if (!keys.has(key)) { keys.add(key); outs.push(out); }
    for (let i = idx.length - 1; i >= 0; i--) { if (++idx[i] < scope.vars.get(names[i]).length) break; idx[i] = 0; }
  }
  return outs;
}

const countTicks = (w) => { let n = 0; for (let i = 0; i < w.length; i++) if (w[i] === '`') n++; return n; };

/* An assignment whose value is a `...` substitution is split into words by the tokenizer (X=`curl URL`): the words
   up to the closing backtick are joined into the value again. One pass. */
function joinBackticks(words) {
  let joined = null;
  for (let i = 0; i < words.length; i++) {
    if (!ASSIGN_RE.test(words[i]) || countTicks(words[i]) % 2 === 0) { if (joined) joined.push(words[i]); continue; }
    if (!joined) joined = words.slice(0, i);
    let w = words[i];
    while (i + 1 < words.length && countTicks(w) % 2 === 1) w += ' ' + words[++i];
    joined.push(w);
  }
  return joined || words;
}

const OPEN_BLOCK = new Set(['if', 'while', 'until', 'for', 'case', 'select']);
const CLOSE_BLOCK = new Set(['fi', 'done', 'esac']);
// Words after which a new command starts in the same segment.
const CMD_LEADERS = new Set(['then', 'do', 'else', 'elif', '{', '!', 'time', 'if', 'while', 'until']);
const OPENER_WORDS = new Set(['then', 'else', 'elif', 'do', 'function']);
// Words that can stand in front of an assignment without making it part of another command.
const BEFORE_ASSIGN = new Set(['if', 'then', 'else', 'elif', 'while', 'until', 'do', '!', '{', 'time']);

/* The assignments a command makes, as [name, value] pairs, or null when it is not only assignments. */
function assignmentsOf(out) {
  let i = 0;
  while (i < out.length && BEFORE_ASSIGN.has(out[i])) i++;
  if (i < out.length && DECLARERS.has(out[i])) {
    i++;
    while (i < out.length && /^-[A-Za-z]+$/.test(out[i])) i++;
  }
  if (i >= out.length) return null;
  const pairs = [];
  for (let j = i; j < out.length; j++) {
    const m = ASSIGN_RE.exec(out[j]);
    if (!m) return null;
    pairs.push([m[1], m[2]]);
  }
  return pairs;
}

const unique = (list) => Array.from(new Set(list));

function record(scope, name, values, conditional) {
  let alts = unique(values.map((v) => (v.length > MAX_VALUE ? null : v)));
  if (conditional) alts = unique((scope.vars.get(name) || [null]).concat(alts));
  if (alts.every((v) => v === null)) { scope.vars.delete(name); return; }
  if (alts.length > MAX_ALTERNATIVES) { scope.overflow = true; return; }
  scope.vars.set(name, alts);
  if (alts.length > 1) scope.hasMulti = true;
}

function track(scope, words, sep, opens) {
  // Every block word that starts a command counts: first in the segment, or after then/do/else/elif/{/!/time (a block
  // nested as `then if b`, `do for j in 1`, `else case ...`), so its fi/done/esac closes the right block.
  for (let i = 0; i < words.length; i++) {
    if (i > 0 && !CMD_LEADERS.has(words[i - 1])) continue;
    const w = words[i];
    if (OPEN_BLOCK.has(w)) scope.blocks++;
    else if (CLOSE_BLOCK.has(w)) scope.blocks = Math.max(0, scope.blocks - 1);
    if (w === 'case') scope.cases++;
    else if (w === 'esac') scope.cases = Math.max(0, scope.cases - 1);
    // A } closes a group only in command position; elsewhere it is a plain argument (echo }, echo '}').
    if (w === '}') scope.braces = Math.max(0, scope.braces - 1);
  }
  // Every { word of the segment counts, not only a leading one (a function body opens after f() or function f): an
  // extra { only keeps later assignments conditional, which fails closed.
  for (const w of words) if (w === '{') scope.braces++;
  if (sep === '(') scope.parens++;
  scope.parens += opens;
  // Inside a case block a ')' may close a pattern (a) ...) rather than a group: it never lowers the group count there,
  // so the assignments after it stay conditional (fail-safe).
  if (sep === ')' && scope.cases === 0) scope.parens = Math.max(0, scope.parens - 1);
  scope.afterAndOr = sep === '&&' || sep === '||';
}

function readAndRecord(scope, words, sep, conditional) {
  const outs = readingsOf(scope, words);
  // An assignment in a pipe or a background command runs in a subshell: the rest of the line does not see it.
  if (sep === '|' || sep === '|&' || sep === '&') return outs;
  const lists = [];
  for (let k = 0; k < outs.length; k++) {
    outs[k] = joinBackticks(outs[k]);
    const pairs = assignmentsOf(outs[k]);
    if (pairs) lists.push(pairs);
  }
  if (!lists.length) return outs;
  scope.assignments += Math.max(...lists.map((l) => l.length));
  if (scope.assignments > MAX_ASSIGNMENTS) { scope.overflow = true; return outs; }
  // Every value a name may take across the readings, in order of appearance.
  const byName = new Map();
  for (const pairs of lists) for (const [n, v] of pairs) { if (!byName.has(n)) byName.set(n, []); byName.get(n).push(v); }
  for (const [n, values] of byName) record(scope, n, values, conditional);
  return outs;
}

/* The readings of one simple command with the known variables filled in (one word list for each value its variables
   may hold: the first is the one when every variable has a single value), and any assignment it makes recorded.
   `sep` is the operator after the command; `opens` counts the ( the tokenizer dropped after it.
   An assignment that always runs replaces the old value (D=a; D=b is b). One that may not run adds a possible value
   instead: after && or ||, inside ( ), { }, if, while, until, for or case (a function body is a { } group), so the
   variable holds both and every reading is checked. */
function applyVariants(scope, words, sep, opens = 0) {
  // A group or block opened in this same segment (f() { D=x; }, { D=x; }, if ...; then D=x) makes it conditional too.
  const opensHere = words.some((w) => w === '{' || w === '(' || OPEN_BLOCK.has(w) || OPENER_WORDS.has(w) || /\(\)$/.test(w));
  const conditional = scope.afterAndOr || scope.parens > 0 || scope.braces > 0 || scope.blocks > 0 || opensHere || sep === '(' || opens > 0;
  try {
    return readAndRecord(scope, words, sep, conditional);
  } finally {
    track(scope, words, sep, opens);
  }
}

module.exports = { newScope, applyVariants, substitute, MAX_ASSIGNMENTS, MAX_VALUE, MAX_EXPANDED, MAX_ALTERNATIVES, MAX_READINGS };
