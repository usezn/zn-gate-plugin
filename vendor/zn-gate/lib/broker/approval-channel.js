'use strict';

/**
 * The person's own channel for the commands only they may run (`zn audit --approve`, `zn-gate pins approve`).
 *
 * At a terminal is not enough: a process an agent started inside a pseudo-terminal (setsid + script) is at a terminal too, and
 * once reparented it has no agent among its ancestors. When a vault is unlocked its daemon asks the person on its own channel
 * (its terminal or an OS dialog), which the command's terminal cannot answer.
 *
 * The terminal check stands alone only when no vault is running: the client says so itself (err.vaultNotRunning), at the vault
 * folder this process uses and at the account's own ~/.zn. Every other failure (a timeout, a connection that closed while the
 * person was being asked, a daemon that did not answer, a refused or unknown reply) is a refusal, never an approval. The
 * caller's environment cannot shorten the wait or point the check elsewhere: ZN_HOOK_VAULT_WAIT_MS is what an agent's hook sets,
 * and a person's terminal does not have it.
 *
 * Returns { ok: true, via: 'vault' | 'terminal' } or { ok: false, error }.
 */
const os = require('os');
const path = require('path');

function refusal(detail) {
  const err = new Error('the vault did not confirm' + (detail ? ' (' + String(detail).slice(0, 200) + ')' : '') + ', so nothing was approved. ' +
    'Next step: run the command again in your own terminal and answer the question the vault asks there or in a dialog.');
  err.code = 'ZN_POLICY_DENIED';
  return err;
}

/** The vault client of the account's own ~/.zn when this process looks somewhere else (ZN_HOME), else null. */
function accountVaultClient(io) {
  try {
    const store = require('../vault/store');
    let own;
    try { own = path.join(os.userInfo().homedir, '.zn'); } catch (_) { own = path.join(os.homedir(), '.zn'); }
    if (path.resolve(own) === path.resolve(store.paths({}).home)) return null;
    return require('../vault/client').createClient({ home: own });
  } catch (_) {
    return null;
  }
}

async function ask(vault, kind, project, summary) {
  try {
    await vault.confirmApproval(kind, project, summary);
    return { ok: true, via: 'vault' };
  } catch (err) {
    if (err && err.vaultNotRunning === true) return { notRunning: true };
    return { ok: false, error: err && err.code === 'ZN_POLICY_DENIED' ? err : refusal(err && (err.vaultUnanswered ? 'it did not answer' : err.message)) };
  }
}

async function confirmApproval(kind, project, summary, io = {}) {
  const env = io.env || process.env;
  if (env.ZN_HOOK_VAULT_WAIT_MS !== undefined) return { ok: false, error: refusal('this environment limits the wait for the vault, as an agent\'s hook does') };
  let r = await ask(io.vault || require('../vault/client'), kind, project, summary);
  if (!r.notRunning) return r;
  const other = io.accountVault !== undefined ? io.accountVault : accountVaultClient(io);
  if (other) {
    r = await ask(other, kind, project, summary);
    if (!r.notRunning) return r;
  }
  return { ok: true, via: 'terminal' };
}

module.exports = { confirmApproval };
