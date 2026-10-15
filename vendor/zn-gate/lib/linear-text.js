'use strict';

// Linear-time replacements for a few regexes that backtrack quadratically on
// long runs of one character (spaces, newlines, '*', '=', '/'). Each returns
// exactly what the regex it replaces returned; test/redos_linear.test.js checks
// that against the old regex on random inputs.

const LINE_BREAKS = new Set(['\n', '\r', '\u2028', '\u2029']);

/** s without the run of characters from `chars` at its end (was s.replace(/[<chars>]+$/, '')). */
function trimTrailing(s, chars) {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1])) end--;
  return s.slice(0, end);
}

/**
 * Unquoted value without its trailing inline comment (was t.replace(/\s+#.*$/, '')):
 * cut at the whitespace before the first " #" whose comment runs to the end of
 * the value without a line break.
 */
function stripInlineComment(t) {
  let from = 0;
  for (let i = t.length - 1; i >= 0; i--) {
    if (LINE_BREAKS.has(t[i])) {
      from = i;
      break;
    }
  }
  const re = /\s#/g;
  re.lastIndex = from;
  const m = re.exec(t);
  return m ? t.slice(0, m.index).trimEnd() : t;
}

/** Lines of s, split at every character a regex treats as a line break. */
function lines(s) {
  return s.split(/[\n\r\u2028\u2029]/);
}

const NPM_AUTH_KEYS = ['_authToken', '_auth', '_password'];

/**
 * [key, value] of an npm auth line (trimmed), or null. Same result as
 * /(?:^|:)(_authToken|_auth|_password)\s*=\s*(\S+)\s*$/ in linear time: the key
 * starts the line or follows a ':' (leftmost first), and the value is the rest
 * of the line after '=', with no whitespace in it.
 */
function npmAuth(line) {
  let lastSpace = -1;
  for (let i = line.length - 1; i >= 0; i--) {
    if (/\s/.test(line[i])) {
      lastSpace = i;
      break;
    }
  }
  const skipSpace = (i) => {
    while (i < line.length && /\s/.test(line[i])) i++;
    return i;
  };
  for (let start = 0; start <= line.length; start = line.indexOf(':', start) + 1) {
    for (const key of NPM_AUTH_KEYS) {
      if (!line.startsWith(key, start)) continue;
      const eq = skipSpace(start + key.length);
      if (line[eq] !== '=') continue;
      const v = skipSpace(eq + 1);
      if (v < line.length && v > lastSpace) return [key, line.slice(v)];
    }
    if (line.indexOf(':', start) < 0) break;
  }
  return null;
}

/**
 * The value after "secret:" on a .znrules line, or null. Same result as
 * /^\s*secret:\s*(.+?)\s*$/.exec(raw)?.[1] in linear time (the lazy group with a
 * trailing \s* backtracked over long runs of spaces).
 */
function znrulesValue(raw) {
  const head = /^\s*secret:/.exec(raw);
  if (!head) return null;
  const rest = raw.slice(head[0].length);
  const t = rest.trim();
  if (t) return /[\n\r\u2028\u2029]/.test(t) ? null : t;
  // Only whitespace: the group takes the last character that is not a line break.
  for (let i = rest.length - 1; i >= 0; i--) if (!LINE_BREAKS.has(rest[i])) return rest[i];
  return null;
}

module.exports = { LINE_BREAKS, trimTrailing, stripInlineComment, lines, npmAuth, znrulesValue };
