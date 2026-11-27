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

// File system errors, in plain words: what is wrong with the path, and what to do about it.
const FS_ERRORS = {
  EACCES: (p) => 'Your account is not allowed to read or change ' + p + '. Check who owns it and its permissions, then try again.',
  EPERM: (p) => 'Your account is not allowed to read or change ' + p + '. Check who owns it and its permissions, then try again.',
  ENOENT: (p) => p + ' does not exist, or a folder on its path is missing.',
  ENOTDIR: (p) => 'A part of the path ' + p + ' is a file where a folder should be. Move or remove that file, then try again.',
  EISDIR: (p) => p + ' is a folder where a file should be.',
  ENOSPC: (p) => 'The disk that holds ' + p + ' is full. Free some space, then try again.',
  EDQUOT: (p) => 'Your disk quota is used up, so ' + p + ' cannot be written. Free some space, then try again.',
  EROFS: (p) => p + ' is on a read-only disk.',
  ENAMETOOLONG: (p, platform) => 'The folder path ' + p + ' is too long' + (platform === 'win32' ? ' (Windows stops at about 260 characters)' : '') + '. Move the folder to a shorter path, then try again.',
  ELOOP: (p) => 'The links in the path ' + p + ' lead in a circle.',
};

/* zn writes a file through a temporary one next to it (.name.zn-tmp.<pid>.<time>, .name.<pid>.<hex>.zn-tmp):
 * the message names the file the person knows. */
function shownPath(p) {
  const s = String(p || '');
  const path = require('path');
  const m = /^\.(.+?)\.(?:zn-tmp\..*|\d+\.[0-9a-f]+\.zn-tmp)$/.exec(path.basename(s));
  return m ? path.join(path.dirname(s), m[1]) : s;
}

/* Node has no name for errno 122 (EDQUOT) on Linux: a full quota comes back as code 'UNKNOWN' with errno -122. */
function fsCodeOf(err, platform) {
  const code = err && typeof err.code === 'string' ? err.code : '';
  const edquot = require('os').constants.errno.EDQUOT;
  if (code === 'UNKNOWN' && platform === 'linux' && typeof edquot === 'number' && err.errno === -edquot) return 'EDQUOT';
  return code;
}

/* The plain text of a file system error (EACCES, ENOENT, ENOSPC...), or null for any other error. `file` names the
 * path when the error does not carry one. The code is added only with ZN_VERBOSE=1 or DEBUG=zn. */
function fsErrorText(err, file, env = process.env, platform = process.platform) {
  let code = fsCodeOf(err, platform);
  const shown = shownPath((err && err.path) || file || 'a file');
  // Windows answers a path of 260 characters or more with "not found" or "invalid argument", not with ENAMETOOLONG.
  if (platform === 'win32' && shown.length >= 260 && ['ENOENT', 'EINVAL'].includes(code)) code = 'ENAMETOOLONG';
  const make = FS_ERRORS[code];
  if (!make) return null;
  const text = make(shown, platform);
  return require('./verbose').isVerbose(env) ? '[' + code + '] ' + text : text;
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
    // A file system error (EACCES, ENOSPC...) in plain words; it carries its own code for ZN_VERBOSE.
    const fsText = fsErrorText(err, null, env);
    if (fsText) return fsText;
    text = detail;
  }
  return code && require('./verbose').isVerbose(env) ? '[' + code + '] ' + text : text;
}

/* The message of an error for a command line, with the unlock hint added once: a locked-vault
 * message that already says how to unlock is returned as it is. */
function messageWithUnlockHint(err) {
  const fsText = fsErrorText(err);
  if (fsText) return fsText;
  const msg = String((err && err.message) || err);
  // A message that already gives its next step (unlock, or a vault reset for a damaged file) is returned as it is.
  if (!(err && err.code === CODES.LOCKED) || /unlock|vault reset/i.test(msg)) return msg;
  const { znCommand } = require('./zn-command');
  return msg.replace(/[.\s]+$/, '') + '; run `' + znCommand('unlock') + '`';
}

module.exports = { CODES, znError, notImplemented, humanError, messageWithUnlockHint, fsErrorText };
