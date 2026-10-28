'use strict';

// The one table of invisible characters. lib/rules.js, lib/reach and lib/audit build their patterns from it,
// and the Python package (zn_gate/rules.py) and the Rust engine (src/engine/rules.rs) keep an identical list: a
// test in each language compares its list with test/fixtures/invisible_chars.json.
//
// BMP_CLASS: zero-width spaces and joiners, word joiner, BOM, soft hyphen, variation selectors, the Mongolian
// vowel separator, the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) and the left-to-right, right-to-left and
// Arabic letter marks (U+200E, U+200F, U+061C).
// ASTRAL_CLASS: the Unicode tag characters (U+E0000-E007F) and the supplementary variation selectors
// (U+E0100-E01EF).
const BMP_CLASS = '\\u200B-\\u200D\\u2060\\uFEFF\\u00AD\\uFE00-\\uFE0F\\u061C\\u180E\\u200E\\u200F\\u115F\\u1160\\u3164\\uFFA0';
const ASTRAL_CLASS = '\\u{E0000}-\\u{E007F}\\u{E0100}-\\u{E01EF}';

const ZERO_WIDTH_RE = new RegExp('[' + BMP_CLASS + ']', 'g');
const INVISIBLE_ASTRAL_RE = new RegExp('[' + ASTRAL_CLASS + ']', 'gu');

// The text with every invisible character replaced by spaces, one space per UTF-16 code unit (an astral
// character becomes two), so an index in the result is the same index in `str`. It is the view that catches an
// invisible character used as a space between two words.
function spaceInvisible(str) {
  return str.replace(ZERO_WIDTH_RE, ' ').replace(INVISIBLE_ASTRAL_RE, '  ');
}

// The same view with one space per code point (an astral character becomes one space), the way the Python and
// Rust rules read it. The rules that run on the whole text need single spaces between words ("send me the api
// keys"), so they use this one; only the secret rules, which need the original indexes, use spaceInvisible.
function spaceInvisibleForMatch(str) {
  return str.replace(ZERO_WIDTH_RE, ' ').replace(INVISIBLE_ASTRAL_RE, ' ');
}

module.exports = { BMP_CLASS, ASTRAL_CLASS, ZERO_WIDTH_RE, INVISIBLE_ASTRAL_RE, spaceInvisible, spaceInvisibleForMatch };
