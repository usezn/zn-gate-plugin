'use strict';

/**
 * Output masking for values the broker injected.
 *
 * For every secret value we mask the raw bytes and the encodings a command
 * is likely to print: base64 (standard and url-safe, at all three byte
 * alignments, so a value embedded in a larger base64 blob such as
 * `user:password` in Basic auth is still caught), hex (lower and upper) and
 * percent-encoding. Matching works on latin1 strings, which map 1:1 to
 * bytes, so binary output passes through unchanged.
 *
 * This protects against accidental printing. It is not a security boundary:
 * a process that holds a value can always transform it before printing.
 */


const MIN_VARIANT_LEN = 8;

function b64Cores(buf) {
  const cores = [];
  for (let k = 0; k < 3; k++) {
    const padded = Buffer.concat([Buffer.alloc(k), buf]);
    const std = padded.toString('base64');
    const start = Math.ceil((8 * k) / 6);
    const end = Math.floor((8 * (k + buf.length)) / 6);
    const core = std.slice(start, end);
    if (core.length >= MIN_VARIANT_LEN) {
      cores.push(core);
      cores.push(core.replace(/\+/g, '-').replace(/\//g, '_'));
    }
  }
  return cores;
}

/** Byte-level (latin1) variants of one value. */
function variantsOf(value) {
  const out = new Set();
  const str = String(value);
  if (str.length === 0) return [];
  const buf = Buffer.from(str, 'utf8');
  out.add(buf.toString('latin1'));
  for (const core of b64Cores(buf)) out.add(core);
  const hex = buf.toString('hex');
  out.add(hex);
  out.add(hex.toUpperCase());
  const enc = encodeURIComponent(str);
  if (enc !== str) {
    out.add(enc);
    out.add(enc.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
  }
  const formEnc = enc.replace(/%20/g, '+');
  if (formEnc !== enc) out.add(formEnc);
  return [...out].filter((v) => v.length >= Math.min(MIN_VARIANT_LEN, Buffer.byteLength(str)));
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Build a masker from [{name, value}]. Each match is replaced by the
 * secret's marker (__ZN_<NAME>__).
 */
function createMasker(secrets) {
  const table = new Map();
  for (const s of secrets || []) {
    if (!s || s.value == null || String(s.value).length === 0) continue;
    for (const v of variantsOf(s.value)) {
      if (!table.has(v)) table.set(v, '__ZN_' + s.name + '__');
    }
  }
  const variants = [...table.keys()].sort((a, b) => b.length - a.length);
  const re = variants.length ? new RegExp(variants.map(escapeRe).join('|'), 'g') : null;
  const maxLen = variants.reduce((m, v) => Math.max(m, v.length), 0);

  function maskLatin1(str) {
    if (!re) return str;
    return str.replace(re, (m) => table.get(m));
  }

  /** Mask a whole string (utf8 text). */
  function maskText(text) {
    if (!re || typeof text !== 'string') return text;
    return Buffer.from(maskLatin1(Buffer.from(text, 'utf8').toString('latin1')), 'latin1').toString('utf8');
  }

  /**
   * Streaming masker: write(Buffer) returns the Buffer that is safe to emit
   * now; end() returns the rest. Holds back at most maxLen-1 bytes so a
   * value split across chunks is still caught.
   */
  function stream() {
    let pending = '';
    return {
      write(chunk) {
        if (!re) return Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
        pending += (Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))).toString('latin1');
        let cut = pending.length - (maxLen - 1);
        if (cut <= 0) return Buffer.alloc(0);
        re.lastIndex = 0;
        let m;
        let out = '';
        let last = 0;
        while ((m = re.exec(pending)) !== null) {
          if (m.index >= cut) break;
          out += pending.slice(last, m.index) + table.get(m[0]);
          last = m.index + m[0].length;
          if (last > cut) cut = last;
        }
        re.lastIndex = 0;
        out += pending.slice(last, cut);
        pending = pending.slice(cut);
        return Buffer.from(out, 'latin1');
      },
      end() {
        const out = maskLatin1(pending);
        pending = '';
        return Buffer.from(out, 'latin1');
      },
    };
  }

  return { maskText, stream, size: variants.length };
}

module.exports = { createMasker, variantsOf };
