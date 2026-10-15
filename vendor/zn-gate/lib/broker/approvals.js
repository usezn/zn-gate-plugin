'use strict';

/**
 * First-use approvals for (secret, command) pairs used by `zn run`.
 *
 * Approvals live only in the vault daemon (inside the encrypted vault),
 * bound to the real path and file identity of the executable. Recording one
 * makes the daemon ask the user on its own channel (its terminal or an OS
 * dialog), never on the terminal of the command that asked, so an agent's
 * shell cannot approve on the user's behalf. There is no file fallback: a
 * vault without these calls cannot approve anything.
 */

const { znError } = require('../deps');

function approvalStore({ vault } = {}) {
  if (!vault || typeof vault.isApproved !== 'function' || typeof vault.recordApproval !== 'function') {
    return {
      kind: 'none',
      async isApproved() { return false; },
      async recordApproval() {
        throw znError('ZN_LOCKED', 'the vault cannot record approvals; run `zn unlock` with this version of zn');
      },
    };
  }
  // ctx = {project, executable: {real, fp}} from `zn run`: the project it
  // computed and the file it resolved and opened. The daemon checks that
  // file, not whatever the name resolves to in the daemon or the client.
  const full = (s, c, ctx) => (ctx && ctx.project != null ? [ctx.project, s, c, ctx.executable || undefined] : [s, c]);
  return {
    kind: 'vault',
    isApproved: (s, c, ctx) => vault.isApproved(...full(s, c, ctx)),
    recordApproval: (s, c, ctx) => vault.recordApproval(...full(s, c, ctx)),
  };
}

module.exports = { approvalStore };
