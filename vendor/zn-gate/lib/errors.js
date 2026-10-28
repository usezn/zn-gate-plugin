'use strict';
/**
 * Error codes shared by the scrubber, the vault and the broker.
 *
 *   ZN_LOCKED            the vault daemon is not running (run `zn unlock`)
 *   ZN_POLICY_DENIED     the request was refused by policy
 *   ZN_NOT_FOUND         the secret or token does not exist
 *   ZN_NOT_IMPLEMENTED   placeholder for a module that is not built yet
 */

const CODES = Object.freeze({
  LOCKED: 'ZN_LOCKED',
  POLICY_DENIED: 'ZN_POLICY_DENIED',
  NOT_FOUND: 'ZN_NOT_FOUND',
  NOT_IMPLEMENTED: 'ZN_NOT_IMPLEMENTED',
});

function znError(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

function notImplemented(what) {
  const err = znError(CODES.NOT_IMPLEMENTED, what + ' is not implemented yet');
  err.znNotImplemented = true;
  return err;
}

/* The text a person sees for an error: what happened, then the detail. The
 * code is printed only with ZN_VERBOSE=1 or DEBUG=zn. */
function humanError(err, env = process.env) {
  const code = err && typeof err.code === 'string' && err.code.startsWith('ZN_') ? err.code : '';
  const detail = String((err && err.message) || '');
  let text;
  if (code === CODES.LOCKED && err.vaultNotRunning === true) {
    // Only the plain "the vault is not unlocked" case gets the unlock steps;
    // integrity and keychain failures keep their own detail.
    const { znCommand } = require('./zn-command');
    text = 'Your secret vault is locked. Unlock it in this terminal with: ' + znCommand('unlock') +
      '. Then run this command again.';
  } else if (code === CODES.LOCKED) {
    text = 'zn could not use your secret vault: ' + (detail || 'unknown error');
  } else if (code === CODES.POLICY_DENIED) {
    text = 'Not allowed: ' + (detail || 'zn blocked this request');
  } else if (code === CODES.NOT_FOUND) {
    text = 'Not found: ' + (detail || 'the item does not exist');
  } else {
    text = detail;
  }
  return code && require('./verbose').isVerbose(env) ? '[' + code + '] ' + text : text;
}

/* The message of an error for a command line, with the unlock hint added once: a locked-vault
 * message that already says how to unlock is returned as it is. */
function messageWithUnlockHint(err) {
  const msg = String((err && err.message) || err);
  // A message that already gives its next step (unlock, or a vault reset for a damaged file) is returned as it is.
  if (!(err && err.code === CODES.LOCKED) || /unlock|vault reset/i.test(msg)) return msg;
  const { znCommand } = require('./zn-command');
  return msg.replace(/[.\s]+$/, '') + '; run `' + znCommand('unlock') + '`';
}

module.exports = { CODES, znError, notImplemented, humanError, messageWithUnlockHint };
