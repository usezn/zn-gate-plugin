'use strict';

/*
 * Text that must never reach a file, process or network call.
 *
 * On Windows, Node hands every file name to libuv as UTF-8 and libuv converts it back to UTF-16 with
 * uv_wtf8_to_utf16 (src/idna.c). That function checks its own work with assert(), and an assert that fails
 * ends the process on the spot (exit code 0xC0000409): no JavaScript handler runs, no exit code 2 reaches the
 * agent, and the agent lets the action through. The assertions fail for U+10000 (the length it counted for
 * the pair does not match what it writes) and for U+10FFFF (the check is "< 0x10FFFF" where "<=" was meant).
 * Names with a lone surrogate or a NUL are not file names at all. zn refuses such text before any call:
 * the hook denies, it does not stop.
 *
 * Also refused: the non-characters (U+FDD0..U+FDEF and U+xxFFFE/U+xxFFFF), which no real path or command
 * holds. Written without String.prototype.isWellFormed so that it works on Node.js 18.
 */

const UNSAFE = new RegExp([
  '\\u0000',
  '[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])', // a high surrogate with no low one after it
  '(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]', // a low surrogate with no high one before it
  '[\\uFFFE\\uFFFF\\uFDD0-\\uFDEF]',
].join('|'));

/** true when the string holds anything that could stop the process in a native call. */
function isUnsafeText(s) {
  if (typeof s !== 'string') return false;
  if (UNSAFE.test(s)) return true;
  // Outside the first plane: U+10000, and the last two code points of every plane (U+1FFFE ... U+10FFFF).
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0xD800 || c > 0xDBFF) continue;
    const cp = s.codePointAt(i);
    if (cp === 0x10000 || (cp & 0xFFFE) === 0xFFFE) return true;
    i++;
  }
  return false;
}

/** true when any string in a JSON value (a key or a value, at any depth) is unsafe. */
function hasUnsafeText(value, depth = 0) {
  if (typeof value === 'string') return isUnsafeText(value);
  if (value === null || typeof value !== 'object') return false;
  if (depth > 64) return true; // nothing real nests this deep: refuse rather than stop looking
  if (Array.isArray(value)) return value.some((v) => hasUnsafeText(v, depth + 1));
  for (const k of Object.keys(value)) {
    if (isUnsafeText(k) || hasUnsafeText(value[k], depth + 1)) return true;
  }
  return false;
}

module.exports = { isUnsafeText, hasUnsafeText };
