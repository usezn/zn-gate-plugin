'use strict';
/**
 * zn Team on this machine:
 *
 *   zn team join <znj_token> [--api https://...] [--agent claude-code|codex|...]
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
const { exportAuditFile } = require('./otel');
const store = require('../vault/store');
const { createClient } = require('../vault/client');
const { CODES } = require('../errors');

const USAGE = 'usage: zn team join <token> [--api URL] [--agent ID] | zn team status [--json] | zn team sync | zn team leave';
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
  if (!p || p.state === 'none') return 'none received yet';
  if (p.state === 'invalid') return 'cached copy does not verify (' + (p.error || 'invalid') + '); run `zn team sync`';
  const base = 'version ' + p.version + ', valid until ' + p.expires_at;
  if (p.state === 'expired') return base + ' -- EXPIRED: strict mode (only restrictions apply) until zn can reach the server';
  return base;
}

async function joinCmd(args) {
  const token = args[2];
  if (!token || token.startsWith('--')) { err(USAGE); return 2; }
  const r = await withClient((c) => c.teamJoin({ join_token: token, api_base: flag(args, '--api'), agent: flag(args, '--agent') }));
  out('Joined ' + (r.org_name ? r.org_name + ' (' + r.org + ')' : r.org) + '. Installation ' + r.install_id + '.');
  try {
    const s = await withClient((c) => c.teamSync({}));
    out('Policy: ' + (s.policy.status === 'updated' ? 'version ' + s.policy.version : s.policy.status) + '.');
  } catch (e) {
    out('Policy: not downloaded yet (' + (e.message || e) + '); zn retries while the vault is unlocked.');
  }
  return 0;
}

async function statusCmd(args) {
  const json = args.includes('--json');
  const p = policy.paths();
  const team = policy.readTeam();
  let info = null;
  try { info = await withClient((c) => c.teamInfo()); } catch (e) { info = null; }
  const st = info && info.joined ? info.policy : (team ? policy.state({ team }) : null);
  let pending = null;
  try { pending = pendingCount({ auditFile: store.paths().auditFile, stateFile: p.uploadState }); } catch (e) { pending = null; }
  let upload = null;
  try { upload = JSON.parse(fs.readFileSync(p.uploadState, 'utf8')); } catch (e) { upload = null; }
  const joined = info ? info.joined : Boolean(team);
  const res = {
    joined,
    vault: info ? 'unlocked' : 'locked',
    org: (info && info.org) || (team && team.org) || null,
    org_name: (info && info.org_name) || (team && team.org_name) || null,
    install_id: (info && info.install_id) || (team && team.install_id) || null,
    api_base: (info && info.api_base) || (team && team.api_base) || null,
    revoked_at: info ? info.revoked_at : null,
    policy: st ? { state: st.state, version: st.version || null, expires_at: st.expires_at || null } : null,
    upload: { pending, last_upload: upload && upload.last_upload, last_status: upload && upload.last_status },
  };
  if (json) { out(JSON.stringify(res, null, 2)); return 0; }
  if (!joined) { out('Not in a zn organization. Join with: zn team join <token> (from your organization admin).'); return 0; }
  out('Organization: ' + (res.org_name ? res.org_name + ' (' + res.org + ')' : res.org));
  out('Installation: ' + res.install_id + ' via ' + res.api_base);
  if (res.revoked_at) out('REMOVED FROM ORG on ' + res.revoked_at + ': this machine no longer reports; the cached policy applies until it expires, then strict mode.');
  out('Policy:       ' + describePolicy(st));
  out('Audit upload: ' + (pending == null ? 'unknown' : pending + ' records pending') +
    (res.upload.last_upload ? ', last upload ' + res.upload.last_upload + ' (' + res.upload.last_status + ')' : ''));
  if (!info) out('The vault is locked: policy downloads and uploads resume after `zn unlock`.');
  return 0;
}

async function syncCmd() {
  const r = await withClient((c) => c.teamSync({}));
  const pol = r.policy || {};
  out('Policy: ' + (pol.status === 'updated' || pol.status === 'current' ? pol.status + ' (version ' + pol.version + ')' : pol.status + (pol.error ? ': ' + pol.error : '')));
  if (r.upload) out('Audit upload: ' + r.upload.status + ', ' + (r.upload.uploaded || 0) + ' sent, ' + (r.upload.pending > 0 ? r.upload.pending : 0) + ' pending');
  return pol.status === 'rejected' || pol.status === 'revoked' ? 1 : 0;
}

async function leaveCmd() {
  const r = await withClient((c) => c.teamLeave());
  out(r.left ? 'Left ' + r.left + '. The organization policy no longer applies on this machine.' : 'Not in an organization.');
  return 0;
}

/** Returns the process exit code. */
async function runTeamCommand(args) {
  try {
    const sub = args[1];
    if (sub === 'join') return await joinCmd(args);
    if (sub === 'status' || sub === undefined) return await statusCmd(args);
    if (sub === 'sync') return await syncCmd();
    if (sub === 'leave') return await leaveCmd();
    err(USAGE);
    return 2;
  } catch (e) {
    const hint = e && e.code === CODES.LOCKED ? ' (vault locked: run `zn unlock`)' : '';
    err('[zn] ' + (e && e.message ? e.message : e) + hint);
    return 1;
  }
}

/** zn vault log export --otlp: args after "export". Returns the exit code. */
function runLogExport(args) {
  if (!args.includes('--otlp')) { err(EXPORT_USAGE); return 2; }
  try {
    const team = policy.readTeam();
    const r = exportAuditFile({
      auditFile: store.paths().auditFile,
      since: flag(args, '--since'),
      installId: team ? team.install_id : undefined,
      orgId: team ? team.org : undefined,
    });
    const file = flag(args, '--out');
    if (file) {
      fs.writeFileSync(file, r.content, { mode: 0o600 });
      err('Exported ' + r.records + ' records to ' + file + ' (OTLP/JSON Lines, sha256 ' + r.sha256 + ').');
    } else {
      process.stdout.write(r.content);
    }
    return 0;
  } catch (e) {
    err('[zn] ' + (e && e.message ? e.message : e));
    return 1;
  }
}

module.exports = { runTeamCommand, runLogExport };
