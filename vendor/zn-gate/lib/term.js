'use strict';

// Plain output for screen readers, terminals that cannot show colors, and logs.
// Colors and symbols are used only when stdout is a terminal and the environment
// does not ask for plain text: NO_COLOR set to any non-empty value (no-color.org)
// or TERM=dumb. The status words (ALLOWED, BLOCKED, FAILED, ...) carry the
// meaning in every mode, so dropping colors and symbols loses nothing.

const CODES = { red: '31', green: '32', yellow: '33', gray: '90' };

/** True when the environment asks for plain text: NO_COLOR or TERM=dumb. */
function plainText(env) {
  return Boolean(env && (env.NO_COLOR || env.TERM === 'dumb'));
}

/** True when this stream may get colors: a terminal, and no request for plain text. */
function colorEnabled(stream, env) {
  return !plainText(env) && Boolean(stream) && stream.isTTY === true;
}

/** Color functions for one output: t.red('x') is colored only when colorEnabled says so. */
function styles(stream, env) {
  const on = colorEnabled(stream, env);
  const out = {};
  for (const name of Object.keys(CODES)) {
    out[name] = (s) => (on ? '\x1b[' + CODES[name] + 'm' + s + '\x1b[0m' : String(s));
  }
  return out;
}

/**
 * A symbol followed by its gap (for example "✔ "), or '' in plain text, where
 * the status word next to it says the same. `style` colors the symbol.
 */
function sym(env, ch, style, gap = ' ') {
  if (plainText(env)) return '';
  return (style ? style(ch) : ch) + gap;
}

/** A horizontal rule: dashes in plain text, box-drawing characters otherwise. */
function ruleLine(env, width) {
  return (plainText(env) ? '-' : '─').repeat(width);
}

module.exports = { plainText, colorEnabled, styles, sym, ruleLine };
