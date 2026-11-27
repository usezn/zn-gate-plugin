'use strict';
/**
 * Normalised view for secret detection.
 *
 * Two plain-text encodings split or hide a secret without changing what a
 * shell or a URL parser sees:
 *   - shell quoting: AKIA""rest, 'AKIA''rest', key='part''part'
 *   - percent-encoding: %41KIA..., api_key=%66ake..., api_key%3Dvalue
 *
 * normalisedView(text) returns the text with adjacent same-type quote pairs
 * between word characters removed (one shell word) and valid %XX sequences
 * decoded when the decoded byte is a printable, non-space ASCII character
 * (so %20 and non-ASCII bytes stay as they are). The detectors run on this
 * view and the spans are mapped back to the original text, so the whole
 * original word or encoded value is replaced.
 *
 * The view also lists `marks`: the offsets in `clean` where a quote pair was
 * removed or a sequence decoded, so a caller can rescan only around them.
 *
 * Linear time: one left-to-right pass. There is no cap on the number of decoded
 * sequences: a cap would leave the rest of a long text encoded, and a secret
 * after it would look clean.
 */

const Q_SINGLE = 0x27;
const Q_DOUBLE = 0x22;
const PERCENT = 0x25;

function hex(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;
}

// Characters of a shell word on either side of a quote pair that joins it.
function wordish(c) {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) ||
    c === 0x5f || c === 0x2d || c === 0x2b || c === 0x2f || c === 0x2e || c === PERCENT;
}

// End index of the quote-pair run that starts at i and joins two shell word
// parts, or 0 when the quotes at i do not join a word.
function quoteRunEnd(text, n, i) {
  const ch = text.charCodeAt(i);
  if ((ch !== Q_SINGLE && ch !== Q_DOUBLE) || i === 0 || i + 1 >= n || text.charCodeAt(i + 1) !== ch ||
    !wordish(text.charCodeAt(i - 1))) return 0;
  let j = i;
  while (j + 1 < n && text.charCodeAt(j) === ch && text.charCodeAt(j + 1) === ch) j += 2;
  return j < n && wordish(text.charCodeAt(j)) ? j : 0;
}

// The decoded byte of a %XX at i when it is printable, non-space ASCII, else -1.
function percentByte(text, n, i) {
  if (text.charCodeAt(i) !== PERCENT || i + 2 >= n) return -1;
  const h = hex(text.charCodeAt(i + 1));
  const l = h < 0 ? -1 : hex(text.charCodeAt(i + 2));
  if (l < 0) return -1;
  const b = h * 16 + l;
  return b > 0x20 && b < 0x7f ? b : -1;
}

// Where a decodable %XX or a doubled quote can start: the only positions the view has to look at.
const CANDIDATE_RE = /%[0-9A-Fa-f]{2}|''|""/g;

function normalisedView(text) {
  const n = text.length;
  // Fast path: most inputs (source code with empty strings or a stray %) have
  // no joining quote pair and no decodable %XX; return before allocating.
  // The native regex jumps to the only places that can matter (%XX, '' and ""); each candidate is then checked exactly.
  let first = -1;
  CANDIDATE_RE.lastIndex = 0;
  let cand;
  while ((cand = CANDIDATE_RE.exec(text)) !== null) {
    const i = cand.index;
    const ch = text.charCodeAt(i);
    if (ch === PERCENT ? percentByte(text, n, i) >= 0 : quoteRunEnd(text, n, i) > 0) { first = i; break; }
    CANDIDATE_RE.lastIndex = i + 1;
  }
  if (first < 0) return null;

  const starts = new Int32Array(n + 1);
  const ends = new Int32Array(n + 1);
  const parts = [];
  const marks = [];
  let c = 0;
  let changed = false;
  let lit = 0; // start of the literal run not yet copied to parts
  for (let k = 0; k < first; k++) { starts[c] = k; ends[c] = k + 1; c++; }
  let i = first;
  while (i < n) {
    const ch = text.charCodeAt(i);
    if (ch === Q_SINGLE || ch === Q_DOUBLE) {
      const j = quoteRunEnd(text, n, i);
      if (j > 0) {
        if (i > lit) parts.push(text.slice(lit, i));
        marks.push(c);
        lit = j; i = j; changed = true;
        continue;
      }
    } else if (ch === PERCENT) {
      const b = percentByte(text, n, i);
      if (b >= 0) {
        if (i > lit) parts.push(text.slice(lit, i));
        parts.push(String.fromCharCode(b));
        marks.push(c);
        starts[c] = i; ends[c] = i + 3; c++;
        lit = i + 3; i += 3; changed = true;
        continue;
      }
    }
    starts[c] = i; ends[c] = i + 1; c++;
    i++;
  }
  if (!changed) return null;
  if (n > lit) parts.push(text.slice(lit, n));
  starts[c] = n; ends[c] = n;
  return { clean: parts.join(''), marks, starts: starts.subarray(0, c + 1), ends: ends.subarray(0, c + 1) };
}

module.exports = { normalisedView, CANDIDATE_RE };
