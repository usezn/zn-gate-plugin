'use strict';
/*
 * Process warnings that zn-gate hides on purpose.
 *
 * Node 18 prints an ExperimentalWarning on stderr each time the X25519 algorithm is used, and the
 * vault uses it for its age identities. The warning is noise for the person running `zn unlock`, so
 * it is dropped here. Only that one warning is dropped: every other warning, and every other
 * ExperimentalWarning, is printed as before. Never use --no-warnings for this.
 *
 * The filter wraps process.emitWarning, so a matching warning is never emitted at all.
 */

const FILTERED_NAME = 'ExperimentalWarning';
const FILTERED_MESSAGE = /X25519/;
const MARK = Symbol.for('zn-gate.x25519-warning-filter');

/** The name of a warning, the way process.emitWarning reads it (an Error, a type string, or an options object). */
function warningName(warning, type) {
  if (warning && typeof warning === 'object') return String(warning.name || 'Error');
  if (typeof type === 'string') return type;
  if (type && typeof type === 'object' && typeof type.type === 'string') return type.type;
  return 'Warning';
}

function warningMessage(warning) {
  if (typeof warning === 'string') return warning;
  return warning && typeof warning.message === 'string' ? warning.message : '';
}

/** True only for the Node 18 X25519 ExperimentalWarning. */
function isX25519ExperimentalWarning(warning, type) {
  return warningName(warning, type) === FILTERED_NAME && FILTERED_MESSAGE.test(warningMessage(warning));
}

/**
 * Wraps proc.emitWarning once so that the X25519 ExperimentalWarning is not emitted.
 * Returns true when the filter was installed by this call, false when it was already there.
 */
function installX25519WarningFilter(proc) {
  const target = proc || process;
  if (typeof target.emitWarning !== 'function' || target[MARK]) return false;
  const original = target.emitWarning;
  const filtered = function emitWarning(warning, type, ...rest) {
    if (isX25519ExperimentalWarning(warning, type)) return undefined;
    return original.call(this, warning, type, ...rest);
  };
  Object.defineProperty(target, MARK, { value: true });
  target.emitWarning = filtered;
  return true;
}

module.exports = { installX25519WarningFilter, isX25519ExperimentalWarning };
