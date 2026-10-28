'use strict';

// Linear-time matcher for the custom patterns of a project (.znrules, zn.config.json).
//
// A project's own pattern must never be able to hang the hook that checks every
// command, so it is not compiled with the JavaScript RegExp engine, whose
// backtracking can take exponential time. This file accepts a safe subset of the
// syntax and runs it as an NFA simulation: the time is proportional to the input
// length times the pattern size, whatever the pattern is. The size is bounded too:
// a pattern may have at most MAX_PROGRAM instructions once its counted repeats are
// expanded and all the patterns of one file together at most MAX_TOTAL_PROGRAM, so the
// cost of one scan has a fixed ceiling (about MAX_TOTAL_PROGRAM steps per character).
//
// Accepted: literals, `.`, classes `[a-z]` `[^x]`, `\d \w \s` (and the negations),
// `\b \B`, `^`, `$`, groups `( )` and `(?: )`, alternation `|`, and the quantifiers
// `? * + {n} {n,} {n,m}` (a trailing `?` for a lazy match is accepted and has no
// effect on whether a text matches). Matching is always case-insensitive for ASCII
// letters; letters of other scripts are matched as written (plus their simple
// upper/lower case pair, as in a class). Rejected, with a message that says why:
// backreferences, lookahead and lookbehind, named groups, `\p{..}`, flags, a
// quantifier on a group that already holds a quantifier (`(a+)+`), repeat counts above
// MAX_REPEAT, two quantifiers in a row, and patterns that are too long or too large
// once the counted repeats are expanded.

const MAX_PATTERN_LENGTH = 500;
const MAX_PATTERNS = 100;
const MAX_REPEAT = 100;
const MAX_PROGRAM = 500;
const MAX_TOTAL_PROGRAM = 600;
const MAX_COMPILED_CACHE = 400;
const MAX_TABLES = 2500;
const LITERAL_COST = 3; // what a plain-text pattern takes off the file's budget

class UnsupportedPattern extends Error {}

const WS = new Set([9, 10, 11, 12, 13, 32, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]);
const isWs = (c) => WS.has(c) || (c >= 0x2000 && c <= 0x200a);
const isDigit = (c) => c >= 48 && c <= 57;
const isWord = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const isLineEnd = (c) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;
const QUANT_BRACES = /^\{\d+(?:,\d*)?\}/;

// ---- character tables ------------------------------------------------------
// Every character set becomes a bit table over the 65536 UTF-16 code units, built
// once, so a step is one array read (no closures, no toLowerCase per character).

let lowerTab = null;
let upperTab = null;
function foldTables() {
  if (lowerTab) return;
  lowerTab = new Uint16Array(65536);
  upperTab = new Uint16Array(65536);
  for (let c = 0; c < 65536; c++) {
    const ch = String.fromCharCode(c);
    const lo = ch.toLowerCase();
    const up = ch.toUpperCase();
    lowerTab[c] = lo.length === 1 ? lo.charCodeAt(0) : c;
    upperTab[c] = up.length === 1 ? up.charCodeAt(0) : c;
  }
}

const TABLES = new Map();
function packedTable(key, make) {
  let t = TABLES.get(key);
  if (!t) {
    if (TABLES.size >= MAX_TABLES) TABLES.clear();
    foldTables();
    const m = make();
    t = new Uint8Array(8192);
    for (let c = 0; c < 65536; c++) if (m[c]) t[c >> 3] |= 1 << (c & 7);
    TABLES.set(key, t);
  }
  return t;
}

function byTest(test) {
  return () => { const m = new Uint8Array(65536); for (let c = 0; c < 65536; c++) m[c] = test(c) ? 1 : 0; return m; };
}

// ---- parser ---------------------------------------------------------------

function fail(msg) { throw new UnsupportedPattern(msg); }

function parse(src) {
  let i = 0;
  const peek = () => src[i];

  function parseAlt() {
    const branches = [parseSeq()];
    while (peek() === '|') { i++; branches.push(parseSeq()); }
    return branches.length === 1 ? branches[0] : { t: 'alt', branches };
  }

  function parseSeq() {
    const items = [];
    while (i < src.length && peek() !== '|' && peek() !== ')') {
      let atom = parseAtom();
      const q = parseQuant();
      if (q) {
        if (atom.t === 'assert') fail('a quantifier cannot follow ^, $ or \\b');
        if (q.max > 1 && hasRepeat(atom)) fail('a quantifier on a group that already contains a quantifier (for example (a+)+) is not allowed: it can take exponential time');
        atom = { t: 'rep', child: atom, min: q.min, max: q.max };
      }
      items.push(atom);
    }
    return { t: 'seq', items };
  }

  function hasRepeat(n) {
    if (n.t === 'rep') return n.max > 1 || hasRepeat(n.child);
    if (n.t === 'seq') return n.items.some(hasRepeat);
    if (n.t === 'alt') return n.branches.some(hasRepeat);
    return false;
  }

  function parseQuant() {
    const c = peek();
    let q = null;
    if (c === '*') { i++; q = { min: 0, max: Infinity }; }
    else if (c === '+') { i++; q = { min: 1, max: Infinity }; }
    else if (c === '?') { i++; q = { min: 0, max: 1 }; }
    else if (c === '{') {
      // Any digit count is a quantifier in JavaScript, so a huge one is an error here, not a literal.
      const m = /^\{(\d+)(?:(,)(\d*))?\}/.exec(src.slice(i, i + 40));
      if (m) {
        if (m[1].length > 6 || (m[3] && m[3].length > 6)) fail('a repeat count above ' + MAX_REPEAT + ' is not allowed');
        const min = Number(m[1]);
        const max = m[2] ? (m[3] === '' ? Infinity : Number(m[3])) : min;
        if (min > MAX_REPEAT || (max !== Infinity && max > MAX_REPEAT)) fail('a repeat count above ' + MAX_REPEAT + ' is not allowed');
        if (max < min) fail('the repeat count {' + min + ',' + max + '} is out of order');
        i += m[0].length;
        q = { min, max };
      }
    }
    if (q && peek() === '?') i++; // lazy: same set of matching texts
    if (q && (peek() === '*' || peek() === '+' || peek() === '?' || (peek() === '{' && QUANT_BRACES.test(src.slice(i, i + 40))))) fail('two quantifiers in a row');
    return q;
  }

  function parseAtom() {
    const c = src[i];
    if (c === '(') {
      i++;
      if (src[i] === '?') {
        if (src.startsWith('?:', i)) i += 2;
        else if (src.startsWith('?=', i) || src.startsWith('?!', i)) fail('lookahead (?= ) and (?! ) are not supported');
        else if (src.startsWith('?<=', i) || src.startsWith('?<!', i)) fail('lookbehind is not supported');
        else if (src.startsWith('?<', i)) fail('named groups are not supported');
        else fail('this group syntax is not supported');
      }
      const inner = parseAlt();
      if (src[i] !== ')') fail('a group is not closed');
      i++;
      return inner;
    }
    if (c === ')') fail('an unmatched )');
    if (c === '*' || c === '+' || c === '?') fail('a quantifier has nothing to repeat');
    if (c === '{' && QUANT_BRACES.test(src.slice(i, i + 40))) fail('a quantifier has nothing to repeat');
    if (c === '[') return parseClass();
    if (c === '.') { i++; return { t: 'set', key: '.', make: byTest((x) => !isLineEnd(x)) }; }
    if (c === '^') { i++; return { t: 'assert', kind: 0 }; }
    if (c === '$') { i++; return { t: 'assert', kind: 1 }; }
    if (c === '\\') return parseEscape(false);
    i++;
    return literal(c.charCodeAt(0));
  }

  function literal(code) {
    return {
      t: 'set', key: 'L' + code,
      make: () => { const m = new Uint8Array(65536); m[code] = 1; m[lowerTab[code]] = 1; m[upperTab[code]] = 1; return m; },
    };
  }

  // Returns a node (outside a class) or a {code}|{test} item (inside one).
  function parseEscape(inClass) {
    i++; // the backslash
    const c = src[i];
    if (c === undefined) fail('a pattern cannot end with a backslash');
    i++;
    const wrap = (test) => (inClass ? { test } : { t: 'set', key: 'E' + c, make: byTest(test) });
    switch (c) {
      case 'd': return wrap(isDigit);
      case 'D': return wrap((x) => !isDigit(x));
      case 'w': return wrap(isWord);
      case 'W': return wrap((x) => !isWord(x));
      case 's': return wrap(isWs);
      case 'S': return wrap((x) => !isWs(x));
      case 'b':
        if (inClass) return { code: 8 };
        return { t: 'assert', kind: 2 };
      case 'B':
        if (inClass) fail('\\B is not allowed inside a class');
        return { t: 'assert', kind: 3 };
      case 't': return code(9);
      case 'n': return code(10);
      case 'r': return code(13);
      case 'f': return code(12);
      case 'v': return code(11);
      case '0':
        if (isDigit((src.charCodeAt(i)))) fail('octal escapes are not supported');
        return code(0);
      case 'x': {
        const m = /^[0-9a-fA-F]{2}/.exec(src.slice(i, i + 2));
        if (!m) fail('a bad \\x escape');
        i += 2;
        return code(parseInt(m[0], 16));
      }
      case 'u': {
        const m = /^[0-9a-fA-F]{4}/.exec(src.slice(i, i + 4));
        if (!m) fail('a bad \\u escape');
        i += 4;
        return code(parseInt(m[0], 16));
      }
      case 'p': case 'P': fail('\\p{..} classes are not supported');
      // eslint-disable-next-line no-fallthrough
      case 'k': fail('named backreferences are not supported');
      // eslint-disable-next-line no-fallthrough
      case 'c': fail('\\c escapes are not supported');
      // eslint-disable-next-line no-fallthrough
      default:
        if (c >= '1' && c <= '9') fail('backreferences (\\1 ...) are not supported');
        if (/[A-Za-z]/.test(c)) fail('the escape \\' + c + ' is not supported');
        return code(c.charCodeAt(0));
    }
    function code(n) { return inClass ? { code: n } : literal(n); }
  }

  function parseClass() {
    const start = i;
    i++; // [
    let negate = false;
    if (src[i] === '^') { negate = true; i++; }
    const items = [];
    let closed = false;
    while (i < src.length) {
      if (src[i] === ']') { i++; closed = true; break; }
      const a = classAtom();
      if (src[i] === '-' && src[i + 1] !== ']' && src[i + 1] !== undefined && a.code !== undefined) {
        i++;
        const b = classAtom();
        if (b.code === undefined) fail('a class range ends in a class escape');
        if (b.code < a.code) fail('a class range is out of order');
        items.push({ lo: a.code, hi: b.code });
      } else if (a.code !== undefined) items.push({ lo: a.code, hi: a.code });
      else items.push(a);
    }
    if (!closed) fail('a class is not closed');
    const make = () => {
      // Ranges are painted with a difference array, tests are applied once per character.
      const diff = new Int32Array(65537);
      const tests = [];
      for (const it of items) {
        if (it.test) tests.push(it.test);
        else { diff[it.lo]++; diff[it.hi + 1]--; }
      }
      const base = new Uint8Array(65536);
      let run = 0;
      for (let c = 0; c < 65536; c++) {
        run += diff[c];
        let hit = run > 0;
        for (let k = 0; !hit && k < tests.length; k++) hit = tests[k](c);
        base[c] = hit ? 1 : 0;
      }
      const out = new Uint8Array(65536);
      for (let c = 0; c < 65536; c++) {
        const folded = base[c] || base[lowerTab[c]] || base[upperTab[c]];
        out[c] = (negate ? !folded : folded) ? 1 : 0;
      }
      return out;
    };
    return { t: 'set', key: 'C' + src.slice(start, i), make };
  }

  function classAtom() {
    if (src[i] === '\\') return parseEscape(true);
    const code = src.charCodeAt(i);
    i++;
    return { code };
  }

  const ast = parseAlt();
  if (i < src.length) fail('an unmatched )');
  return ast;
}

// ---- compiler (Thompson NFA) ---------------------------------------------

const CHAR = 0; const SPLIT = 1; const JMP = 2; const ASSERT = 3; const MATCH = 4;
const A_BOL = 0; const A_EOL = 1; const A_WB = 2;

function compileProgram(ast) {
  const op = []; const x = []; const y = [];
  const tabs = []; const tabIndex = new Map();
  const push = (o, a, b) => {
    if (op.length >= MAX_PROGRAM) fail('the pattern is too large once its repeat counts are expanded (more than ' + MAX_PROGRAM + ' steps)');
    op.push(o); x.push(a); y.push(b);
    return op.length - 1;
  };
  function emit(n) {
    switch (n.t) {
      case 'set': {
        const pc = push(CHAR, 0, 0);
        let idx = tabIndex.get(n.key);
        if (idx === undefined) { idx = tabs.length; tabs.push(packedTable(n.key, n.make)); tabIndex.set(n.key, idx); }
        x[pc] = idx;
        break;
      }
      case 'assert': push(ASSERT, n.kind, 0); break;
      case 'seq': n.items.forEach(emit); break;
      case 'alt': {
        const jumps = [];
        for (let b = 0; b < n.branches.length; b++) {
          if (b < n.branches.length - 1) {
            const s = push(SPLIT, 0, 0);
            x[s] = op.length;
            emit(n.branches[b]);
            jumps.push(push(JMP, 0, 0));
            y[s] = op.length;
          } else emit(n.branches[b]);
        }
        for (const j of jumps) x[j] = op.length;
        break;
      }
      case 'rep': {
        for (let k = 0; k < n.min; k++) emit(n.child);
        if (n.max === Infinity) {
          const s = push(SPLIT, 0, 0);
          x[s] = op.length;
          emit(n.child);
          push(JMP, s, 0);
          y[s] = op.length;
        } else {
          const splits = [];
          for (let k = n.min; k < n.max; k++) {
            const s = push(SPLIT, 0, 0);
            x[s] = op.length;
            splits.push(s);
            emit(n.child);
          }
          for (const s of splits) y[s] = op.length;
        }
        break;
      }
      default: fail('internal error');
    }
  }
  emit(ast);
  push(MATCH, 0, 0);
  return { op: Int32Array.from(op), x: Int32Array.from(x), y: Int32Array.from(y), tabs };
}

function makeMatcher(prog) {
  const { op, x, y, tabs } = prog;
  const size = op.length;
  const mark = new Int32Array(size);
  const stack = new Int32Array(size * 2 + 2);
  let clist = new Int32Array(size);
  let nlist = new Int32Array(size);
  // The table of each CHAR instruction, looked up by program counter.
  const ctab = new Array(size).fill(null);
  for (let pc = 0; pc < size; pc++) if (op[pc] === CHAR) ctab[pc] = tabs[x[pc]];
  let s = '';
  let n = 0;

  // Adds the closure of `pc0` at position `pos`; returns the new count, or -1 when MATCH is reached.
  // Each instruction is visited at most once per position (the mark), so one call costs O(size) in all.
  function add(list, count, pc0, pos) {
    const tag = pos + 1;
    let sp = 0;
    let pc = pc0;
    for (;;) {
      if (mark[pc] !== tag) {
        mark[pc] = tag;
        const o = op[pc];
        if (o === CHAR) list[count++] = pc;
        else if (o === JMP) { pc = x[pc]; continue; }
        else if (o === SPLIT) { stack[sp++] = y[pc]; pc = x[pc]; continue; } else if (o === MATCH) return -1;
        else {
          const kind = x[pc];
          let ok;
          if (kind === A_BOL) ok = pos === 0;
          else if (kind === A_EOL) ok = pos === n;
          else {
            const a = pos > 0 && isWord(s.charCodeAt(pos - 1));
            const b = pos < n && isWord(s.charCodeAt(pos));
            ok = kind === A_WB ? a !== b : a === b;
          }
          if (ok) { pc++; continue; }
        }
      }
      if (sp === 0) return count;
      pc = stack[--sp];
    }
  }

  return function test(text) {
    s = text;
    n = text.length;
    mark.fill(0);
    let cn = 0;
    let nn = 0;
    for (let pos = 0; pos <= n; pos++) {
      cn = add(clist, cn, 0, pos);
      if (cn === -1) return true;
      if (pos === n) break;
      const c = s.charCodeAt(pos);
      const byte = c >> 3;
      const bit = c & 7;
      nn = 0;
      // Threads that read char `pos` move to the closure at pos + 1.
      for (let k = 0; k < cn; k++) {
        const pc = clist[k];
        if ((ctab[pc][byte] >> bit) & 1) {
          const q = pc + 1;
          if (op[q] === CHAR) {
            // The common case, a character followed by a character: no jumps to follow.
            if (mark[q] !== pos + 2) { mark[q] = pos + 2; nlist[nn++] = q; }
          } else {
            nn = add(nlist, nn, q, pos + 1);
            if (nn === -1) return true;
          }
        }
      }
      const t = clist; clist = nlist; nlist = t;
      cn = nn;
    }
    return false;
  };
}

// ---- public API -----------------------------------------------------------

const compiled = new Map();

// A pattern with no special character (the usual rule: a name, a path, a phrase) is plain
// text. It is searched with the KMP algorithm, one array read per character of the text, so
// a file of many such rules stays cheap whatever the text. Letters match without regard to
// case (ASCII only, as in the general matcher); the other characters match as written.
const PLAIN_RE = /^[\x20-\x7e]+$/;
const SPECIAL_RE = /[\\^$.|?*+()[\]{}]/;
function makePlainMatcher(source) {
  const pat = Array.from(source, (ch) => { const c = ch.charCodeAt(0); return c >= 65 && c <= 90 ? c | 32 : c; });
  const m = pat.length;
  const fall = new Int32Array(m);
  for (let i = 1, k = 0; i < m; i++) {
    while (k > 0 && pat[i] !== pat[k]) k = fall[k - 1];
    if (pat[i] === pat[k]) k++;
    fall[i] = k;
  }
  return function test(text) {
    const n = text.length;
    let k = 0;
    for (let i = 0; i < n; i++) {
      let c = text.charCodeAt(i);
      if (c >= 65 && c <= 90) c |= 32;
      while (k > 0 && pat[k] !== c) k = fall[k - 1];
      if (pat[k] === c) { k++; if (k === m) return true; }
    }
    return false;
  };
}

/**
 * Compiles one custom pattern. Returns { ok: true, rule } where rule has `source`
 * and `test(text)`, or { ok: false, error } with a message for the user.
 * `budget` ({ left }) is the instruction budget of the whole file: the size of the
 * pattern is taken off it, and the pattern is rejected when it does not fit.
 */
function compileCustomPattern(source, budget) {
  if (typeof source !== 'string') return { ok: false, error: 'a pattern must be a string' };
  if (source.length === 0) return { ok: false, error: 'a pattern cannot be empty' };
  if (source.length > MAX_PATTERN_LENGTH) return { ok: false, error: 'the pattern is longer than ' + MAX_PATTERN_LENGTH + ' characters' };
  let entry = compiled.get(source);
  if (!entry) {
    try {
      if (PLAIN_RE.test(source) && !SPECIAL_RE.test(source)) {
        entry = { ok: true, size: LITERAL_COST, rule: { source, test: makePlainMatcher(source) } };
      } else {
        const prog = compileProgram(parse(source));
        entry = { ok: true, size: prog.op.length, rule: { source, test: makeMatcher(prog) } };
      }
    } catch (err) {
      if (!(err instanceof UnsupportedPattern)) throw err;
      entry = { ok: false, error: err.message };
    }
    if (compiled.size >= MAX_COMPILED_CACHE) compiled.clear();
    compiled.set(source, entry);
  }
  if (!entry.ok) return { ok: false, error: entry.error };
  if (budget) {
    if (entry.size > budget.left) {
      return { ok: false, error: 'the patterns of this file are too large together (the limit is ' + MAX_TOTAL_PROGRAM + ' steps in all, so that scanning stays fast): shorten or remove some' };
    }
    budget.left -= entry.size;
  }
  return { ok: true, rule: entry.rule };
}

module.exports = { compileCustomPattern, MAX_PATTERN_LENGTH, MAX_PATTERNS, MAX_PROGRAM, MAX_TOTAL_PROGRAM };
