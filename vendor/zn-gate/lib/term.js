'use strict';

// Plain output for screen readers, terminals that cannot show colors, and logs.
// Colors are used only when stdout is a terminal and the environment does not
// ask for plain text: NO_COLOR set to any non-empty value (no-color.org) or
// TERM=dumb. Emoji and box-drawing symbols are used only on a terminal that
// is not asked for plain text and not in CI (CI set to any non-empty value).
// Everywhere else each symbol becomes a short ASCII marker such as "[ok]" or
// "[!]", so pipes and logs never receive characters outside printable ASCII.
// The status words (ALLOWED, BLOCKED, FAILED, ...) carry the meaning in every mode.

const CODES = { red: '31', green: '32', yellow: '33', gray: '90' };

// ASCII stand-ins for the symbols the CLI prints, used when symbols are off.
const ASCII_MARKERS = {
  '\u{1F6E1}\uFE0F': '[+]',
  '\u{1F512}': '[ok]',
  '✔': '[ok]',
  '✖': '[x]',
  '↳': '->',
  '!': '[!]',
};

/** True when the environment asks for plain text: NO_COLOR or TERM=dumb. */
function plainText(env) {
  return Boolean(env && (env.NO_COLOR || env.TERM === 'dumb'));
}

/** True when this stream may get colors: a terminal, and no request for plain text. */
function colorEnabled(stream, env) {
  return !plainText(env) && Boolean(stream) && stream.isTTY === true;
}

/**
 * True when this stream may get emoji and box-drawing symbols: a terminal, no
 * request for plain text, and not a CI run. Defaults to process.stdout.
 */
function symbolsEnabled(env, stream = process.stdout) {
  return colorEnabled(stream, env) && !(env && env.CI);
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
 * A symbol followed by its gap (for example "✔ "). `style` colors the symbol.
 * Where symbols are off (see symbolsEnabled), the ASCII marker for it takes its
 * place ("[ok]" for "✔"), or nothing when the symbol has no marker.
 * `stream` is the stream the line is written to: pass process.stderr for stderr
 * lines. It defaults to process.stdout.
 */
function sym(env, ch, style, gap = ' ', stream = process.stdout) {
  if (!symbolsEnabled(env, stream)) {
    const marker = ASCII_MARKERS[ch];
    return marker ? marker + gap : '';
  }
  return (style ? style(ch) : ch) + gap;
}

/**
 * A horizontal rule: box-drawing characters where symbols are on, dashes otherwise.
 * `stream` is the stream the line is written to (process.stdout by default).
 */
function ruleLine(env, width, stream = process.stdout) {
  return (symbolsEnabled(env, stream) ? '─' : '-').repeat(width);
}

module.exports = { plainText, colorEnabled, symbolsEnabled, styles, sym, ruleLine };
