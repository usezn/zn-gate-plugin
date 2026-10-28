'use strict';
/**
 * zn Team on this machine:
 *
 *   zn team join <znj_token> [--api https://...] [--agent claude-code|codex|...] [--include-history]
 *   zn team status [--json]
 *   zn team sync                      download the policy now and upload the audit log
 *   zn team leave
 *
 * and the local OpenTelemetry export of the audit log (free, no account):
 *
 *   zn vault log export --otlp [--since 7d] [--out FILE]
 *
 * Join and leave need the vault unlocked and are confirmed on the vault's own
 * channel, not here: an agent can type in this terminal.
 */

const fs = require('fs');
const policy = require('./policy');
const { pendingCount } = require('./upload');
const { syncOutcome } = require('./sync-outcome');
const { cleanChange, describeChange } = require('./changes');
const { exportAuditFile } = require('./otel');
const store = require('../vault/store');
const { createClient } = require('../vault/client');
const { messageWithUnlockHint } = require('../errors');
const { znCommand } = require('../zn-command');

const USAGE = 'usage: zn team join <token> [--api URL] [--agent ID] [--include-history] | zn team status [--json] | zn team sync | zn team leave | zn team managed-config [--agent ID|all] [--os macos|linux|windows|all] [--managed-hooks-only] [--exclusive-mcp] [--json]';
const EXPORT_USAGE = 'usage: zn vault log export --otlp [--since 7d] [--out FILE]';

const out = (s) => process.stdout.write(s + '\n');
const err = (s) => process.stderr.write(s + '\n');

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function withClient(fn) {
  const c = createClient({});
  return Promise.resolve(fn(c)).finally(() => c.close());
}

function describePolicy(p) {
  if (!p || p.state === 'none') return 'none received yet (PENDING: the organization policy is not applied; run `zn team sync`)';
  if (p.state === 'invalid') return 'cached copy does not verify (' + (p.error || 'invalid') + '); run `zn team sync`';
  const base = 'version ' + p.version + ', valid until ' + p.expires_at;
  if (p.state === 'expired') return base + ' -- EXPIRED: strict mode (only restrictions apply) until zn can reach the server';
  return base;
}

async function joinCmd(args) {
  const token = args[2];
  if (!token || token.startsWith('--')) { err(USAGE); return 2; }
  // Audit records written before joining stay on this machine unless this flag asks to send them too.
  const joinArgs = { join_token: token, api_base: flag(args, '--api'), agent: flag(args, '--agent') };
  if (args.includes('--include-history')) joinArgs.include_history = true;
  const r = await withClient((c) => c.teamJoin(joinArgs));
  out('Joined ' + (r.org_name ? r.org_name + ' (' + r.org + ')' : r.org) + '. Installation ' + r.install_id + '.');
  // The join is complete only when the organization's first valid policy is applied.
  let why;
  try {
    const s = await withClient((c) => c.teamSync({}));
    const pol = s.policy || {};
    out('Policy: ' + (pol.status === 'updated' ? 'version ' + pol.version : pol.status) + '.');
    if (syncOutcome(s).policyOk) return 0;
    why = syncOutcome({ policy: pol }).problems[0];
  } catch (e) {
    why = 'not downloaded yet (' + (e.message || e) + ')';
    out('Policy: ' + why + '.');
  }
  err('[zn] The join is not finished: this machine is registered, but no valid policy is applied yet (' + why + '). ' +
    "The organization's restrictions do not apply until one is. `zn team status` shows it as pending; run `zn team sync` to retry (zn also retries while the vault is unlocked).");
  return 1;
}

async function statusCmd(args) {
  const json = args.includes('--json');
  const p = policy.paths();
  const team = policy.readTeam();
  let info = null;
  try { info = await withClient((c) => c.teamInfo()); } catch (e) { info = null; }
  const st = info && info.joined ? info.policy : (team ? policy.state({ team }) : null);
  let pending = null;
  const afterSeq = info && Number.isInteger(info.upload_after_seq) ? info.upload_after_seq : (team && Number.isInteger(team.upload_after_seq) ? team.upload_after_seq : 0);
  try { pending = pendingCount({ auditFile: store.paths().auditFile, stateFile: p.uploadState, startAfterSeq: afterSeq }); } catch (e) { pending = null; }
  let upload = null;
  try { upload = JSON.parse(fs.readFileSync(p.uploadState, 'utf8')); } catch (e) { upload = null; }
  // What the last policy version removed or loosened: from the vault, or from the readable copy when it is locked.
  let change = null;
  if (info && info.joined) change = cleanChange(info.policy && info.policy.change);
  else { const c = policy.readCache(); change = c ? cleanChange(c.change) : null; }
  const joined = info ? info.joined : Boolean(team);
  const res = {
    joined,
    vault: info ? 'unlocked' : 'locked',
    org: (info && info.org) || (team && team.org) || null,
    org_name: (info && info.org_name) || (team && team.org_name) || null,
    install_id: (info && info.install_id) || (team && team.install_id) || null,
    api_base: (info && info.api_base) || (team && team.api_base) || null,
    revoked_at: info ? info.revoked_at : null,
    policy: st ? { state: st.state, version: st.version || null, expires_at: st.expires_at || null, change } : null,
    upload: { pending, last_upload: upload && upload.last_upload, last_status: upload && upload.last_status },
    // true until a valid organization policy has been applied on this machine
    join_pending: joined && (!st || st.state === 'none' || st.state === 'invalid'),
    last_sync: (info && info.last_sync) || null,
    // The server was not told yet that an installation left: kept in the vault and retried.
    revocation_pending: (info && Array.isArray(info.revocations)) ? info.revocations : [],
  };
  if (json) { out(JSON.stringify(res, null, 2)); return 0; }
  if (!joined) {
    out('Not in a zn organization. Join with: zn team join <token> (from your organization admin).');
    for (const l of describeRevocations(res.revocation_pending)) out(l);
    return 0;
  }
  out('Organization: ' + (res.org_name ? res.org_name + ' (' + res.org + ')' : res.org));
  out('Installation: ' + res.install_id + ' via ' + res.api_base);
  if (res.revoked_at) out('REMOVED FROM ORG on ' + res.revoked_at + ': this machine no longer reports; the cached policy applies until it expires, then strict mode.');
  out('Policy:       ' + describePolicy(st));
  if (change) { const lines = describeChange(change); out('Policy change: ' + lines[0]); for (const l of lines.slice(1)) out(l); }
  out('Audit upload: ' + (pending == null ? 'unknown' : pending + ' records pending') +
    (res.upload.last_upload ? ', last upload ' + res.upload.last_upload + ' (' + res.upload.last_status + ')' : ''));
  const ls = res.last_sync;
  if (ls) {
    out('Last sync:    ' + (ls.ok ? 'ok, ' + ls.at : 'FAILED ' + ls.at + ': ' + (ls.problems.join('; ') || 'unknown') +
      (ls.last_ok_at ? ' (last success ' + ls.last_ok_at + ')' : ' (never succeeded)') + '; run `zn team sync` to retry'));
  }
  for (const l of describeRevocations(res.revocation_pending)) out(l);
  if (!info) out('The vault is locked: policy downloads and uploads resume after `' + znCommand('unlock') + '`.');
  return 0;
}

/* Lines for `zn team status` about installations that left but whose revocation the server has not taken yet. */
function describeRevocations(list) {
  const lines = [];
  for (const r of Array.isArray(list) ? list : []) {
    lines.push('Revocation pending since ' + r.since + ' (installation ' + r.install_id + (r.org ? ', ' + r.org : '') + '): last error ' + (r.last_error || 'unknown') +
      (r.last_try_at ? ' (last try ' + r.last_try_at + ')' : '') + '.');
    lines.push('  The server was not told that this installation left, so its token still works there. Next step: `zn team sync` retries now (zn also retries every 15 minutes while the vault is unlocked)' +
      (r.give_up_at ? ' until ' + r.give_up_at + ', when it stops; an admin can then remove the installation from the dashboard' : '') + '.');
  }
  return lines;
}

async function syncCmd() {
  const r = await withClient((c) => c.teamSync({}));
  const pol = r.policy || {};
  out('Policy: ' + (pol.status === 'updated' || pol.status === 'current' ? pol.status + ' (version ' + pol.version + ')' : pol.status + (pol.error ? ': ' + pol.error : '')));
  if (r.upload) out('Audit upload: ' + r.upload.status + ', ' + (r.upload.uploaded || 0) + ' sent, ' + (r.upload.pending > 0 ? r.upload.pending : 0) + ' pending');
  if (r.revocations && r.revocations.pending) out('Revocation: the server has not taken the earlier leave yet (' + r.revocations.pending + ' pending); see `zn team status`.');
  else if (r.revocations && r.revocations.done) out('Revocation: the server has now been told that the earlier installation left.');
  if (r.upload && r.upload.status === 'tampered') out('Nothing was uploaded: ' + r.upload.error + '. Keep a copy of the audit log, look into the change, then run `' + znCommand('vault verify --acknowledge') + '` in your own terminal.');
  // Exit 0 only with a valid policy applied and no failed upload.
  const o = syncOutcome(r);
  if (!o.ok) err('[zn] sync incomplete: ' + o.problems.join('; '));
  return o.ok ? 0 : 1;
}

async function leaveCmd() {
  const r = await withClient((c) => c.teamLeave());
  const stuck = Array.isArray(r.pending_files) ? r.pending_files : [];
  if (stuck.length) {
    // The vault no longer holds the organization, but a copy is still on disk: say which, so it can be removed by hand.
    out(r.left ? 'Left ' + r.left + ' in the vault.' : 'Not in an organization.');
    err('[zn] Some local files could not be deleted. Delete them yourself, because the hooks still read them: ' + stuck.join(', '));
    return 1;
  }
  out(r.left ? 'Left ' + r.left + '. The organization policy no longer applies on this machine.' : 'Not in an organization.');
  // The server is told first (see teamLeave in daemon-ops.js); what it answered is said below.
  const rev = r.revocation;
  if (r.left && rev && rev.status === 'done') {
    out(rev.reason === 'token_invalid'
      ? 'The server no longer accepted this installation\'s token (an admin may have removed it already): nothing is left to revoke.'
      : 'The server was told: installation ' + r.install_id + ' is revoked and its token no longer works.');
  } else if (r.left && rev && rev.status === 'pending') {
    out('The server was NOT told yet that you left (' + rev.error + '): installation ' + r.install_id + ' stays on the organization\'s list, and its token still works there, until a retry succeeds.');
    out('zn keeps the token in your vault only for that retry and nothing else: no policy, no uploads, no detectors. It retries on `zn team sync` and every 15 minutes while the vault is unlocked, and stops on ' + rev.give_up_at + '. `zn team status` shows it.');
  } else if (!r.left && Array.isArray(r.revocations) && r.revocations.length) {
    for (const l of describeRevocations(r.revocations)) out(l);
  }
  return 0;
}

/** Returns the process exit code. */
async function runTeamCommand(args) {
  try {
    const sub = args[1];
    if (args.slice(1).some((a) => a === '-h' || a === '--help')) { out(USAGE); return 0; }
    if (sub === 'join') return await joinCmd(args);
    if (sub === 'status' || sub === undefined) return await statusCmd(args);
    if (sub === 'sync') return await syncCmd();
    if (sub === 'leave') return await leaveCmd();
    if (sub === 'managed-config') return require('./managed-config').run(args.slice(2));
    err(USAGE);
    return 2;
  } catch (e) {
    err('[zn] ' + messageWithUnlockHint(e));
    return 1;
  }
}

/** zn vault log export --otlp: args after "export". Returns the exit code. */
async function runLogExport(args) {
  if (!args.includes('--otlp')) { err(EXPORT_USAGE); return 2; }
  try {
    const team = policy.readTeam();
    const opts = {
      auditFile: store.paths().auditFile,
      since: flag(args, '--since'),
      installId: team ? team.install_id : undefined,
      orgId: team ? team.org : undefined,
    };
    // An unlocked vault verifies the chain first and refuses a log that does not verify.
    // A locked vault cannot: the export then says so, loudly, and is not a verified copy.
    let r = null;
    const probe = createClient({});
    try {
      let unlocked = false;
      try { unlocked = await probe.isUnlocked(); } catch (e) { unlocked = false; }
      if (unlocked) {
        r = await probe.auditExport({ since: opts.since, installId: opts.installId, orgId: opts.orgId });
        if (!r.ok) {
          err('[zn] Not exported: ' + r.error + '. Keep a copy of ~/.zn/audit.jsonl as evidence, look into the change, then run `' + znCommand('vault verify --acknowledge') + '` in your own terminal.');
          return 1;
        }
      }
    } finally { probe.close(); }
    let unverified = false;
    if (!r) {
      unverified = true;
      r = exportAuditFile(opts);
    }
    const warn = () => {
      if (unverified) err('[zn] Warning: the vault is locked or unreachable, so the audit log chain was NOT verified. Unlock it (`' + znCommand('unlock') + '`) and export again for a verified copy.');
    };
    const file = flag(args, '--out');
    if (file) {
      fs.writeFileSync(file, r.content, { mode: 0o600 });
      err('Exported ' + r.records + ' records to ' + file + ' (OTLP/JSON Lines, sha256 ' + r.sha256 + ').');
    } else {
      process.stdout.write(r.content);
    }
    warn();
    return 0;
  } catch (e) {
    err('[zn] ' + (e && e.message ? e.message : e));
    return 1;
  }
}

module.exports = { runTeamCommand, runLogExport };
