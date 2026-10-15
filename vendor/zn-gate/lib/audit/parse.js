'use strict';
/**
 * Parsers for the agent config formats `zn audit` reads. No dependencies:
 *   parseJsonc(text)  JSON with // and /* comments and trailing commas
 *                     (VS Code, OpenCode and Claude Code accept both).
 *   parseToml(text)   the TOML subset agent configs use: tables, arrays of
 *                     tables, dotted and quoted keys, strings (all four
 *                     kinds), numbers, booleans, dates (kept as strings),
 *                     arrays and inline tables.
 * Both throw an Error with a `line` property on invalid input.
 */

/* ------------------------------ JSONC ------------------------------ */

/** End index (exclusive) of the JSON string that starts at `i`. */
function stringEnd(text, i) {
  const n = text.length;
  let j = i + 1;
  while (j < n && text[j] !== '"') {
    if (text[j] === '\\') j++;
    j++;
  }
  return Math.min(n, j + 1);
}

/** Pass 1: comments become spaces (newlines kept, so line numbers stay right). */
function stripComments(text) {
  const parts = [];
  let i = 0;
  let last = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '"') { i = stringEnd(text, i); continue; }
    if (c === '/' && (text[i + 1] === '/' || text[i + 1] === '*')) {
      const end = text[i + 1] === '/' ? (text.indexOf('\n', i) < 0 ? n : text.indexOf('\n', i)) : (text.indexOf('*/', i + 2) < 0 ? n : text.indexOf('*/', i + 2) + 2);
      parts.push(text.slice(last, i), text.slice(i, end).replace(/[^\n]/g, ' '));
      i = end;
      last = end;
      continue;
    }
    i++;
  }
  parts.push(text.slice(last));
  return parts.join('');
}

/** Pass 2: trailing commas (before } or ]) become spaces. */
function stripTrailingCommas(text) {
  const out = text.split('');
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === '"') { i = stringEnd(text, i); continue; }
    if (c === ',') {
      let j = i + 1;
      while (j < n && /\s/.test(text[j])) j++;
      if (text[j] === '}' || text[j] === ']') out[i] = ' ';
      i = j;
      continue;
    }
    i++;
  }
  return out.join('');
}

function stripJsonc(text) {
  return stripTrailingCommas(stripComments(text));
}

function parseJsonc(text) {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const clean = stripJsonc(src);
  try {
    return JSON.parse(clean);
  } catch (err) {
    const e = new Error(err.message);
    const m = /position (\d+)/.exec(err.message);
    const l = /line (\d+)/.exec(err.message);
    e.line = m ? clean.slice(0, Number(m[1])).split('\n').length : l ? Number(l[1]) : 1;
    throw e;
  }
}

/* ------------------------------ TOML ------------------------------- */

const BARE_KEY = /[A-Za-z0-9_-]/;

function parseToml(text) {
  const s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const n = s.length;
  let i = 0;
  let line = 1;
  const root = Object.create(null);
  const lines = Object.create(null);
  let current = root;
  let currentPath = [];

  function fail(msg) {
    const e = new Error(msg + ' (line ' + line + ')');
    e.line = line;
    throw e;
  }
  function skipWs() {
    while (i < n && (s[i] === ' ' || s[i] === '\t')) i++;
  }
  function skipComment() {
    if (s[i] === '#') while (i < n && s[i] !== '\n') i++;
  }
  function skipWsNl() {
    for (;;) {
      skipWs();
      skipComment();
      if (s[i] === '\n') { line++; i++; continue; }
      if (s[i] === '\r' && s[i + 1] === '\n') { line++; i += 2; continue; }
      break;
    }
  }
  function endOfLine() {
    skipWs();
    skipComment();
    if (i < n && s[i] !== '\n' && s[i] !== '\r') fail('unexpected text after value');
  }
  function basicString() {
    i++; // opening quote
    let out = '';
    while (i < n && s[i] !== '"') {
      if (s[i] === '\n') fail('newline in string');
      if (s[i] === '\\') {
        const e = s[i + 1];
        i += 2;
        if (e === 'n') out += '\n';
        else if (e === 't') out += '\t';
        else if (e === 'r') out += '\r';
        else if (e === 'b') out += '\b';
        else if (e === 'f') out += '\f';
        else if (e === 'u' || e === 'U') {
          const len = e === 'u' ? 4 : 8;
          const hex = s.slice(i, i + len);
          if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) fail('bad unicode escape');
          out += String.fromCodePoint(parseInt(hex, 16));
          i += len;
        } else out += e;
        continue;
      }
      out += s[i++];
    }
    if (s[i] !== '"') fail('unterminated string');
    i++;
    return out;
  }
  function literalString() {
    i++;
    const end = s.indexOf("'", i);
    const nl = s.indexOf('\n', i);
    if (end < 0 || (nl >= 0 && nl < end)) fail('unterminated string');
    const out = s.slice(i, end);
    i = end + 1;
    return out;
  }
  function multiline(quote) {
    i += 3;
    if (s[i] === '\r' && s[i + 1] === '\n') { i += 2; line++; } else if (s[i] === '\n') { i++; line++; }
    let end = s.indexOf(quote, i);
    if (end < 0) fail('unterminated multi-line string');
    // Up to two quotes may sit right before the closing delimiter ("""a"""").
    for (let extra = 0; extra < 2 && s[end + 3] === quote[0]; extra++) end++;
    let body = s.slice(i, end);
    line += (body.match(/\n/g) || []).length;
    i = end + 3;
    if (quote === '"""') {
      body = body.replace(/\\\r?\n\s*/g, '').replace(/\\(["\\nt])/g, (m, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
    }
    return body;
  }
  function key() {
    const parts = [];
    for (;;) {
      skipWs();
      if (s[i] === '"') parts.push(basicString());
      else if (s[i] === "'") parts.push(literalString());
      else {
        const start = i;
        while (i < n && BARE_KEY.test(s[i])) i++;
        if (i === start) fail('expected a key');
        parts.push(s.slice(start, i));
      }
      const last = parts[parts.length - 1];
      if (last === '__proto__' || last === 'constructor' || last === 'prototype') fail('reserved key ' + JSON.stringify(last));
      skipWs();
      if (s[i] === '.') { i++; continue; }
      return parts;
    }
  }
  function value() {
    const c = s[i];
    if (c === '"') return s.startsWith('"""', i) ? multiline('"""') : basicString();
    if (c === "'") return s.startsWith("'''", i) ? multiline("'''") : literalString();
    if (c === '[') {
      i++;
      const arr = [];
      for (;;) {
        skipWsNl();
        if (s[i] === ']') { i++; return arr; }
        arr.push(value());
        skipWsNl();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') { i++; return arr; }
        fail('expected , or ] in array');
      }
    }
    if (c === '{') {
      i++;
      const obj = Object.create(null);
      skipWs();
      if (s[i] === '}') { i++; return obj; }
      for (;;) {
        const k = key();
        if (s[i] !== '=') fail('expected = in inline table');
        i++;
        skipWs();
        setPath(obj, k, value());
        skipWs();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') { i++; return obj; }
        fail('expected , or } in inline table');
      }
    }
    const start = i;
    while (i < n && !/[,\]\}\s#]/.test(s[i])) i++;
    const raw = s.slice(start, i);
    // A date-time may contain one space between date and time.
    if (/^\d{4}-\d{2}-\d{2}$/.test(raw) && /^ \d{2}:/.test(s.slice(i, i + 4))) {
      const st = i;
      i++;
      while (i < n && !/[,\]\}\s#]/.test(s[i])) i++;
      return raw + s.slice(st, i);
    }
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    if (raw === '') fail('expected a value');
    const num = Number(raw.replace(/_/g, ''));
    if (!Number.isNaN(num) && /^[+-]?[0-9.]/.test(raw)) return num;
    if (/^[+-]?(inf|nan)$/.test(raw)) return Number(raw.replace(/inf/, 'Infinity').replace(/nan/, 'NaN'));
    if (/^\d{4}-\d{2}-\d{2}|^\d{2}:\d{2}/.test(raw)) return raw;
    return fail('invalid value ' + JSON.stringify(raw.slice(0, 40)));
  }
  function setPath(obj, parts, val) {
    let o = obj;
    for (let k = 0; k < parts.length - 1; k++) {
      if (o[parts[k]] === undefined || o[parts[k]] === null || typeof o[parts[k]] !== 'object') o[parts[k]] = Object.create(null);
      o = o[parts[k]];
      if (Array.isArray(o)) o = o[o.length - 1];
    }
    o[parts[parts.length - 1]] = val;
  }
  function table(parts, isArray) {
    let o = root;
    for (let k = 0; k < parts.length; k++) {
      const last = k === parts.length - 1;
      if (last && isArray) {
        if (!Array.isArray(o[parts[k]])) o[parts[k]] = [];
        const t = Object.create(null);
        o[parts[k]].push(t);
        return t;
      }
      if (o[parts[k]] === undefined || typeof o[parts[k]] !== 'object' || o[parts[k]] === null) o[parts[k]] = Object.create(null);
      o = o[parts[k]];
      if (Array.isArray(o)) o = o[o.length - 1] || Object.create(null);
    }
    return o;
  }

  for (;;) {
    skipWsNl();
    if (i >= n) break;
    if (s[i] === '[') {
      const isArray = s[i + 1] === '[';
      i += isArray ? 2 : 1;
      const parts = key();
      if (isArray ? !s.startsWith(']]', i) : s[i] !== ']') fail('unterminated table header');
      i += isArray ? 2 : 1;
      current = table(parts, isArray);
      currentPath = parts;
      lines[parts.join('.')] = lines[parts.join('.')] || line;
      endOfLine();
      continue;
    }
    const startLine = line;
    const k = key();
    if (s[i] !== '=') fail('expected =');
    i++;
    skipWs();
    const v = value();
    setPath(current, k, v);
    lines[currentPath.concat(k).join('.')] = startLine;
    endOfLine();
  }
  return { data: root, lines };
}

module.exports = { parseJsonc, parseToml, stripJsonc };
