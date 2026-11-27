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

const MAX_DEPTH = 64;

/** Why a JSON value is refused: 'deep' (nested more than 64 levels), 'text' (an unsafe string, a key or a value), or null. */
function unsafeKind(value, depth = 0) {
  if (typeof value === 'string') return isUnsafeText(value) ? 'text' : null;
  if (value === null || typeof value !== 'object') return null;
  if (depth > MAX_DEPTH) return 'deep'; // nothing real nests this deep: refuse rather than stop looking
  const items = Array.isArray(value) ? value : null;
  const keys = items ? null : Object.keys(value);
  let found = null;
  for (let i = 0; i < (items ? items.length : keys.length); i++) {
    if (keys && isUnsafeText(keys[i])) { found = found || 'text'; continue; }
    const k = unsafeKind(items ? items[i] : value[keys[i]], depth + 1);
    if (k === 'deep') return 'deep';
    if (k) found = found || k;
  }
  return found;
}

/** true when any string in a JSON value (a key or a value, at any depth) is unsafe, or the value nests absurdly deep. */
function hasUnsafeText(value) {
  return unsafeKind(value) !== null;
}

module.exports = { isUnsafeText, hasUnsafeText, unsafeKind };
