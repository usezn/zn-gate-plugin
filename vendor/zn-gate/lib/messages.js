'use strict';
/**
 * The error and refusal messages people read at the terminal, in one place.
 *
 * Each message says what happened, why when it helps, and what to do next, in
 * one short line of plain English. The wording is pinned by test/messages.test.js,
 * so a change here shows up in review. Callers must not rebuild these strings.
 * Other code and tests match on parts of some of them (for example
 * "needs an interactive terminal"), so keep those phrases when you reword.
 *
 * This module has no dependencies, so any module can load it.
 */

/* ------------------------- terminal and AI agents ------------------------- */

/* The end of a refusal, in words for someone who does not program. */
function agentNote(agent) {
  if (/^started from /.test(agent)) {
    return ' (zn found it was ' + agent + '). If you are not using an AI agent, open a new terminal window and try again.';
  }
  return ' (detected ' + agent + ').';
}

function agentRefusal(what, agent) {
  return what + ' must be run by you in your own terminal, not by an AI agent' + agentNote(agent);
}

function notInteractive(what) {
  return what + ' needs an interactive terminal. Open a terminal window yourself and run it there.';
}

const PROMPT_CANCELLED = 'Cancelled: nothing was entered. Run the command again when you are ready.';

const CLIPBOARD_NO_POWERSHELL = 'could not read the clipboard: the system PowerShell (Windows PowerShell 5.1) was not found. ' +
  'Run the command without --clipboard to type the value at the hidden prompt.';

function clipboardUnreadable(tried) {
  return 'could not read the clipboard (tried ' + tried.join(', ') + '). ' +
    'Copy the value again, or run the command without --clipboard to type it at the hidden prompt.';
}

/* ------------------------------ the vault ------------------------------ */

function invalidDuration(value) {
  return 'invalid duration "' + value + '" (use e.g. 30m, 8h)';
}

const DURATION_RANGE = 'The --ttl and --idle times must be between 1m and 24h, for example 8h.';

function unknownBackend(name, known) {
  return 'Unknown vault backend "' + name + '". Use one of: ' + known.join(', ') + '.';
}

/* The command a person types, in the form that works on their machine (`zn`, or the npx form when zn is not on PATH). */
function zn(args) {
  return require('./zn-command').znCommand(args);
}

/* The technical detail is for ZN_VERBOSE=1 (or DEBUG=zn): a person gets the plain sentence and one next step. */
const { isVerbose } = require('./verbose');

function verboseDetail(detail, env = process.env) {
  return detail && isVerbose(env) ? ' Detail: ' + String(detail).slice(0, 120) + '.' : '';
}

function unlockNeedsTerminal() {
  return zn('unlock') + ' needs an interactive terminal: run it in your own terminal window';
}

const FOREGROUND_NEEDS_TERMINAL = '--foreground needs an interactive terminal (it asks you there). Run it in your own terminal window.';

const PASSPHRASE_NEEDS_TERMINAL = 'zn needs a terminal to ask for the passphrase. Run this command in your terminal, or pass it with --passphrase-stdin.';

function passphraseCancelled() {
  return 'Cancelled: no passphrase was entered. Run `' + zn('unlock') + '` again when you are ready.';
}

function passphraseMismatch() {
  return 'The two passphrases do not match. Nothing was created; run `' + zn('unlock') + '` again.';
}

function forgetLockFirst() {
  return 'Lock the vault first (`' + zn('lock') + '`): the daemon may hold this project in memory.';
}

function vaultAlreadyUnlocked() {
  return 'The vault is already unlocked, so there is nothing to do. To unlock it again, run `' + zn('lock') + '` in your own terminal first.';
}

/* ----------------------- the system keychain and the vault process ----------------------- */

const KEYCHAIN_NAMES = {
  macos: 'the macOS Keychain',
  windows: 'the Windows Credential Manager',
  libsecret: 'your Linux keyring (Secret Service)',
};

const KEYCHAIN_HELP = {
  macos: 'If a Keychain window asked for permission, choose Allow, or open Keychain Access and allow zn to use the item "zn-vault".',
  windows: 'Check that Credential Manager works for your Windows account (open it from the Start menu), then try again.',
  libsecret: 'Make sure your keyring is unlocked (log in to your desktop session), then try again.',
};

/* The system keychain refused or failed. doing: 'save' | 'read'; slotIsVault: the vault key (not the connect key).
 * Only saving the vault key offers a passphrase, because that is the one choice made when the vault is created. */
function keychainProblem(backend, doing, opts = {}) {
  const what = opts.slotIsVault === false ? 'the zn-gate connect key' : 'the vault key';
  const where = KEYCHAIN_NAMES[backend] || 'the system keychain';
  const alt = doing === 'save' && opts.slotIsVault !== false
    ? ' Or create the vault with a passphrase instead: `' + zn('unlock --backend passphrase') + '`.' : '';
  return 'zn could not ' + doing + ' ' + what + ' in ' + where + '. ' + (KEYCHAIN_HELP[backend] || '') + alt +
    verboseDetail(opts.detail, opts.env);
}

function secretToolMissing() {
  return 'zn needs the secret-tool program to use your Linux keyring, and it is not installed. ' +
    'Install the libsecret-tools package (for example: sudo apt install libsecret-tools), ' +
    'or create the vault with a passphrase instead: `' + zn('unlock --backend passphrase') + '`.';
}

function powershellMissing() {
  return 'zn could not find Windows PowerShell, which it needs to use the Windows Credential Manager. ' +
    'Create the vault with a passphrase instead: `' + zn('unlock --backend passphrase') + '`.';
}

function keychainHelperFailed(detail, env) {
  return 'zn could not start the system program that holds its key. Close this terminal, open a new one and try again. ' +
    'If it keeps failing, create the vault with a passphrase instead: `' + zn('unlock --backend passphrase') + '`.' +
    verboseDetail(detail, env);
}

function keychainLostKey(backend, env) {
  return keychainProblem(backend, 'save', { detail: 'the keychain did not return the key it was given', env });
}

function vaultStartTimeout() {
  return 'The vault did not start in time. Run `' + zn('lock') + '`, then `' + zn('unlock') + '` again. More: ' + TROUBLESHOOTING_URL;
}

function vaultStartExited(code, env) {
  return 'The vault stopped while it was starting. Run `' + zn('unlock') + '` again. More: ' + TROUBLESHOOTING_URL +
    verboseDetail('exit code ' + code, env);
}

/* The vault process is there but does not answer (slow, or a leftover from a crash): lock it, then unlock. */
function vaultNotAnswering(detail, env) {
  return 'The vault is not answering. Run `' + zn('lock') + '`, then `' + zn('unlock') + '`.' + verboseDetail(detail, env);
}

function auditFailed(record, error, env) {
  return 'The audit log did not pass its check (at record ' + record + '). Do not delete or edit it: it is the proof of what happened. ' +
    'More: ' + TROUBLESHOOTING_URL + verboseDetail(error, env);
}

/* Why a running vault locked itself, in words. */
function vaultLockedBecause(reason, idleMinutes) {
  if (reason === 'idle') return 'Vault locked: it was not used for ' + idleMinutes + ' min.';
  if (reason === 'expired') return 'Vault locked: the time you set with --ttl ran out.';
  return 'Vault locked.';
}

/* --------------------------- zn-gate connect --------------------------- */

const CONNECT_KEY_ON_COMMAND_LINE = 'Never put the key on the command line. Run `zn-gate connect` and paste it at the hidden prompt.';

const CONNECT_CANCELLED = 'Cancelled. Nothing was saved.';

const CONNECT_NOT_A_KEY = 'That does not look like a zn API key (they start with zn_). Nothing was saved. Run `zn-gate connect` and paste the key again.';

const CONNECT_REJECTED = 'usezn.com did not accept this key (it may be revoked or mistyped). Nothing was saved. Run `zn-gate connect` and paste a valid key.';

function connectFullAccess(url) {
  return 'This key can do more than analyze text, and zn-gate only accepts a key limited to analyzing. ' +
    'Create an analysis-only key on the connect page and paste that one: ' + url + '\nNothing was saved.';
}

/* Anything that is not a sentence about this computer's settings or an HTTP status is a failure to reach the server
 * (a Node error code, "timed out", a TLS error): the plain words are the same, the detail is for ZN_VERBOSE=1. */
function isNetworkFailure(detail) {
  const d = String(detail || '');
  return !(/^HTTP [0-9]+$/.test(d) || / is set\b/.test(d));
}

/* The check with usezn.com did not finish: no answer (network), a server error (HTTP 5xx), or a refusal on this computer.
 * detail is the Node error code or "HTTP nnn" (shown only with ZN_VERBOSE=1), or a full sentence from cloud-key.tlsRefusal. */
function connectUnverified(detail, env) {
  const d = String(detail || '');
  if (!d || isNetworkFailure(d)) {
    return 'Could not reach usezn.com, so the key was not checked and nothing was saved. ' +
      'Check your internet connection, then run `zn-gate connect` again.' + verboseDetail(d, env);
  }
  if (/^HTTP \d+$/.test(d)) {
    return 'usezn.com is not answering properly right now, so the key was not checked and nothing was saved. ' +
      'Try `zn-gate connect` again in a few minutes.' + verboseDetail(d, env);
  }
  // A refusal sentence from this computer's environment: it already names the setting and the way out.
  return d + ' Nothing was saved.';
}

/* The same for the revoke request, where a key is already saved. */
function revokeNotReached(detail, shownKey, dashboard, env) {
  const d = String(detail || '');
  if (!d || isNetworkFailure(d)) {
    return 'Could not reach usezn.com, so key ' + shownKey + ' was not revoked. Check your internet connection and run `zn-gate disconnect --revoke` again, ' +
      'or revoke it yourself at ' + dashboard + '.' + verboseDetail(d, env);
  }
  if (/^HTTP \d+$/.test(d)) {
    return 'usezn.com is not answering properly right now, so key ' + shownKey + ' may still work. Revoke it at ' + dashboard + '.' + verboseDetail(d, env);
  }
  return d + ' Key ' + shownKey + ' was not revoked. Revoke it at ' + dashboard + '.';
}

function connectNoStore(unlockCmd) {
  return 'zn-gate keeps the key only in your system keychain or the zn vault, never in a plain file. ' +
    'This computer has no system keychain and the vault is locked, so nothing was saved.\n' +
    'Next step: run `' + unlockCmd + '` (it asks you for a passphrase), then run `zn-gate connect` again.';
}

/* The environment of this terminal could change how the key travels, so it is not sent.
 * name is the variable; why says in plain words what it could do; saved is true when a key is already saved. */
function environmentRefusal(name, why, saved) {
  return name + ' is set in this terminal, so zn-gate will not send ' + (saved ? 'the saved' : 'the') + ' key: ' + why + '. ' +
    'Remove it (macOS or Linux: `unset ' + name + '`; Windows PowerShell: `Remove-Item Env:' + name + '`) and try again.';
}

function connectSaveFailed(detail) {
  return 'Could not save the key: ' + detail + '. Nothing was kept. Run `zn-gate connect` to try again.';
}

const DISCONNECT_UNLOCK_FIRST = (cmd) => 'Could not read the saved key from the zn vault, so nothing was removed or revoked. Run `' + cmd + '` and try again.';

/* The vault could not be removed from: say it once, with the unlock step only when the detail does not already give it. */
function disconnectVaultNotRemoved(detail, unlockCmd, retryCmd) {
  const d = String(detail || 'unknown error').replace(/[.\s]+$/, '');
  return 'Could not remove the saved key from the zn vault: ' + d + '. ' +
    (/unlock/i.test(d) ? '' : 'Unlock the vault with `' + unlockCmd + '`. ') + 'Then run `' + retryCmd + '` again.';
}

/* The system keychain could not be reached or cleaned, so only zn's own setting was removed. */
function disconnectKeychainLeft(reason, dashboard, canRevoke) {
  return 'Removed the connect setting from zn. The cloud check is off; zn-gate runs only on your computer.\n' +
    'Could not clean your system keychain (' + reason + '), so a saved key may still be there. ' +
    'To remove it, open your keychain app and delete the item named "zn-cloud".\n' +
    (canRevoke ? '' : 'The key itself still works until you revoke it. Revoke it at ' + dashboard + '.');
}

/* ------------------------------ damaged vault files ------------------------------ */

const TROUBLESHOOTING_URL = 'https://usezn.com/docs/zn-gate/troubleshooting/';

/* One sentence for a vault file that cannot be read: what is damaged, what zn did, the real next step.
 * `detail` (a library message) is shown only with ZN_VERBOSE=1 or DEBUG=zn. */
function vaultDamaged(file, what, detail, env = process.env) {
  const znCommand = require('./zn-command').znCommand;
  const more = detail && isVerbose(env) ? ' Detail: ' + String(detail).slice(0, 120) + '.' : '';
  return 'Your vault file ' + file + ' ' + what + '. zn did not change it and will not start a new vault over it. ' +
    'Restore it from a backup. With no backup, run `' + znCommand('vault reset') + '`: it sets the old vault aside and starts empty, ' +
    'so the secrets saved in it are lost. More: ' + TROUBLESHOOTING_URL + more;
}

/* ------------------------------ MCP pins ------------------------------ */

const PINS_USAGE_APPROVE = 'usage: zn-gate pins approve <server>|--all';

function pinsAgentRefusal(agent) {
  return agentRefusal('zn-gate pins approve', agent);
}

const PINS_NEEDS_TERMINAL = 'zn-gate pins approve runs only in your own terminal, so that an agent cannot approve tool changes. Run it there.';

const PINS_NOT_APPROVED = 'Not approved: what you typed did not match, so nothing was changed. Run the command again to retry.';

function pinsError(reason) {
  return 'zn-gate pins: ' + reason + '. Run `zn-gate pins` to see the servers and their full keys.';
}

/* ------------------------------- teams ------------------------------- */

const TEAM_INVALID_JOIN_TOKEN = 'invalid join token (expected znj_...). Copy it again from the invitation your administrator sent.';

const TEAM_INVALID_REQUEST = 'invalid request: the name, kind or value is not valid, so nothing was approved.';

const TEAM_NOTHING_TO_APPROVE = 'nothing to approve: this machine has no organization policy waiting for your answer. Run `zn team status` to check.';

const TEAM_NOT_ASKED = 'the organization policy does not ask for this, so nothing was approved.';

const TEAM_INVALID_ORG_KEY = 'the server sent an invalid organization key, so this machine was not connected. Ask your administrator.';

function teamJoinFailed(why) {
  return 'join failed (' + why + '). This machine was not connected.';
}

module.exports = {
  agentNote, agentRefusal, notInteractive, PROMPT_CANCELLED, CLIPBOARD_NO_POWERSHELL, clipboardUnreadable,
  invalidDuration, DURATION_RANGE, unknownBackend, unlockNeedsTerminal, FOREGROUND_NEEDS_TERMINAL,
  PASSPHRASE_NEEDS_TERMINAL, passphraseCancelled, passphraseMismatch, forgetLockFirst, vaultAlreadyUnlocked,
  keychainProblem, secretToolMissing, powershellMissing, keychainHelperFailed, keychainLostKey,
  verboseDetail, vaultStartTimeout, vaultStartExited, vaultNotAnswering, auditFailed, vaultLockedBecause,
  CONNECT_KEY_ON_COMMAND_LINE, CONNECT_CANCELLED, CONNECT_NOT_A_KEY, CONNECT_REJECTED,
  connectFullAccess, connectUnverified, connectSaveFailed, revokeNotReached, connectNoStore, environmentRefusal, isNetworkFailure,
  PINS_USAGE_APPROVE, pinsAgentRefusal, PINS_NEEDS_TERMINAL, PINS_NOT_APPROVED, pinsError,
  TEAM_INVALID_JOIN_TOKEN, TEAM_INVALID_REQUEST, TEAM_NOTHING_TO_APPROVE, TEAM_NOT_ASKED, TEAM_INVALID_ORG_KEY,
  teamJoinFailed,
  DISCONNECT_UNLOCK_FIRST, disconnectVaultNotRemoved, disconnectKeychainLeft, TROUBLESHOOTING_URL, vaultDamaged,
};
