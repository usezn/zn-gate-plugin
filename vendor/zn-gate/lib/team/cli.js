'use strict';
/**
 * zn Team on this machine:
 *
 *   zn team join <znj_token> | - | (ZN_TEAM_JOIN_TOKEN) [--api https://...] [--agent claude-code|codex|...] [--include-history]
 *   zn team status [--json] [--rules]
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
const readline = require('readline');
const policy = require('./policy');
const { pendingCount } = require('./upload');
const { syncOutcome } = require('./sync-outcome');
const { cleanChange, describeChange } = require('./changes');
const { exportAuditStream } = require('./otel');
const { rulesView, rulesLines } = require('./rules-view');
const store = require('../vault/store');
const { createClient } = require('../vault/client');
const { messageWithUnlockHint, fsErrorText } = require('../errors');
const { isVerbose } = require('../verbose');
const messages = require('../messages');
const { znCommand } = require('../zn-command');

const USAGE = 'usage: zn team join <token> | zn team join - | ZN_TEAM_JOIN_TOKEN=... zn team join [--api URL] [--agent ID] [--include-history] | zn team status [--json] [--rules] | zn team sync | zn team leave | zn team managed-config [--agent ID|all] [--os macos|linux|windows|all] [--managed-hooks-only] [--exclusive-mcp] [--json]';
const JOIN_TOKEN_ENV = 'ZN_TEAM_JOIN_TOKEN';
// Largest export kept in memory before it is written to stdout (larger logs: --out FILE).
let STDOUT_EXPORT_MAX_BYTES = 64 * 1024 * 1024;
const EXPORT_USAGE = 'usage: zn vault log export --otlp [--since 7d] [--out FILE] [--unverified]';

const out = (s) => process.stdout.write(s + '\n');
const err = (s) => process.stderr.write(s + '\n');

/* A failure for the command line: the plain text first; a "details:" line (HTTP status, internal code) only with ZN_VERBOSE=1. */
function printError(e) {
  const [main, detail] = messageWithUnlockHint(e).split('\ndetails: ');
  err('[zn] ' + main);
  if (detail && isVerbose()) err('[zn] details: ' + detail);
}

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
  if (p.state === 'invalid') return 'the stored copy could not be verified (' + (p.error || 'invalid') + ') -- INVALID: strict mode (every secret is blocked, nothing is opened) until a valid policy arrives; run `zn team sync`';
  const base = 'version ' + p.version + ', valid until ' + p.expires_at;
  if (p.state === 'expired' && p.clock === 'behind') return base + " -- STRICT MODE (only restrictions apply): this computer's clock is behind the time this policy was issued. Check the computer's date and time.";
  if (p.state === 'expired') return base + " -- EXPIRED: strict mode (only restrictions apply) until zn can reach the server. If this computer is online, check its date and time.";
  return base;
}

/* First non-empty line of standard input, trimmed. Never echoed. */
function readStdinToken() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    let done = false;
    const finish = (v) => { if (done) return; done = true; rl.close(); resolve(v); };
    if (process.stdin.isTTY) err('Paste the join token and press Enter:');
    rl.on('line', (l) => { if (l.trim()) finish(l.trim()); });
    rl.on('close', () => finish(''));
    rl.on('error', () => finish(''));
  });
}

/*
 * Where the join token comes from. Precedence: an argument beats the environment; the argument `-` means "read one
 * line from standard input" (it is the explicit choice, so a script with no terminal and no input never blocks);
 * with no argument, ZN_TEAM_JOIN_TOKEN. A token given as an argument stays in the shell history and in `ps`, so zn
 * says so (the token is never printed). Returns { token, via } or { error }.
 */
async function joinTokenFrom(args, io) {
  const arg = args[2];
  if (arg && arg !== '-' && !arg.startsWith('--')) return { token: arg, via: 'argument' };
  if (arg === '-') {
    const t = await (io.readStdin || readStdinToken)();
    return t ? { token: t, via: 'stdin' } : { error: 'no join token on standard input. Pipe it in, for example: printf %s "$TOKEN" | zn team join -' };
  }
  const env = String((io.env || process.env)[JOIN_TOKEN_ENV] || '').trim();
  return env ? { token: env, via: 'env' } : {};
}

async function joinCmd(args, io) {
  const got = await joinTokenFrom(args, io || {});
  if (got.error) { err('[zn] ' + got.error); return 2; }
  if (!got.token) { err('[zn] ' + messages.TEAM_JOIN_NO_TOKEN); return 2; }
  const token = got.token;
  // The invitation email's link is not a join token: say what to do instead of a generic invalid-token error.
  if (messages.looksLikeEmailInvite(token)) { err('[zn] ' + messages.TEAM_INVITE_NOT_A_JOIN_TOKEN); return 2; }
  if (got.via === 'argument') {
    err('[zn] Note: a join token given as an argument stays in your shell history and is visible in the process list. Next time use `zn team join -` (token on standard input) or set ' + JOIN_TOKEN_ENV + '.');
  }
  // Audit records written before joining stay on this machine unless this flag asks to send them too.
  const joinArgs = { join_token: token, api_base: flag(args, '--api'), agent: flag(args, '--agent') };
  if (args.includes('--include-history')) joinArgs.include_history = true;
  const r = await withClient((c) => c.teamJoin(joinArgs));
  const orgLabel = r.org_name ? r.org_name + ' (' + r.org + ')' : r.org;
  out('Joined ' + orgLabel + '. Installation ' + r.install_id + '.');
  // The join is complete only when the organization's first valid policy is applied.
  let why;
  try {
    const s = await withClient((c) => c.teamSync({}));
    const pol = s.policy || {};
    // No policy published yet is expected, but the join stays pending, so it exits 1 (see docs/cli.md).
    if (pol.status === 'none') { err('[zn] ' + messages.teamJoinNoPolicyYet()); return 1; }
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
  const wantRules = args.includes('--rules');
  const p = policy.paths();
  const team = policy.readTeam();
  let info = null;
  // --rules never asks the vault (and so never the server): only the local join state and the verified local copy are used.
  if (!wantRules) { try { info = await withClient((c) => c.teamInfo()); } catch (e) { info = null; } }
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
    vault: wantRules ? 'not checked' : (info ? 'unlocked' : 'locked'),
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
    // Pending revocations that were dropped because more than 8 were waiting: the server was never told about them.
    revocations_dropped: (info && info.revocations_dropped) || null,
  };
  // --rules: read from the readable copy and verified again here with the pinned key; no network, no vault needed.
  if (wantRules) res.rules = rulesView(team ? policy.state({ team }) : null);
  if (json) { out(JSON.stringify(res, null, 2)); return 0; }
  if (!joined) {
    out('Not in a zn organization. Join with: zn team join <token> (from your organization admin).');
    if (wantRules) out('Rules: none, because this machine has not joined an organization.');
    for (const l of describeRevocations(res.revocation_pending)) out(l);
    for (const l of describeDropped(res.revocations_dropped)) out(l);
    return 0;
  }
  out('Organization: ' + (res.org_name ? res.org_name + ' (' + res.org + ')' : res.org));
  out('Installation: ' + res.install_id + ' via ' + res.api_base);
  if (res.revoked_at) out('REMOVED FROM ORG on ' + res.revoked_at + '. ' + messages.TEAM_REMOVED + ' Note: the cached policy still applies until it expires, then strict mode.');
  out('Policy:       ' + describePolicy(st));
  if (wantRules) for (const l of rulesLines(res.rules)) out(l);
  if (change) { const lines = describeChange(change); out('Policy change: ' + lines[0]); for (const l of lines.slice(1)) out(l); }
  out('Audit upload: ' + (pending == null ? 'unknown' : pending + ' records pending') +
    (res.upload.last_upload ? ', last upload ' + res.upload.last_upload + ' (' + res.upload.last_status + ')' : ''));
  const ls = res.last_sync;
  if (ls) {
    out('Last sync:    ' + (ls.ok ? 'ok, ' + ls.at : 'FAILED ' + ls.at + ': ' + (ls.problems.join('; ') || 'unknown') +
      (ls.last_ok_at ? ' (last success ' + ls.last_ok_at + ')' : ' (never succeeded)') +
      // A removed installation cannot sync again: retrying would not help.
      (res.revoked_at ? '' : '; run `zn team sync` to retry')));
  }
  for (const l of describeRevocations(res.revocation_pending)) out(l);
  for (const l of describeDropped(res.revocations_dropped)) out(l);
  if (wantRules) out('Local view only: with --rules the vault and the server were not contacted, so upload counts, last sync and removal status are left out. Run `zn team status` without --rules for those.');
  else if (!info) out('The vault is locked: policy downloads and uploads resume after `' + znCommand('unlock') + '`.');
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

/* Warning for `zn team status` when pending revocations were dropped to make room (at most 8 are kept). */
function describeDropped(d) {
  if (!d || !(d.count > 0)) return [];
  return [
    'WARNING: ' + d.count + ' pending revocation' + (d.count === 1 ? ' was' : 's were') + ' dropped (last on ' + d.last_at + (d.last_install_id ? ', installation ' + d.last_install_id : '') + '): more than 8 installations left while the server could not be reached.',
    '  The server was never told about ' + (d.count === 1 ? 'it' : 'them') + ', so ' + (d.count === 1 ? 'that installation token' : 'those installation tokens') + ' still work there. Ask an admin to remove ' + (d.count === 1 ? 'it' : 'them') + ' from the dashboard.',
  ];
}

async function syncCmd() {
  const r = await withClient((c) => c.teamSync({}));
  const pol = r.policy || {};
  const o = syncOutcome(r);
  // The three failures with one plain cause and one next step: removed, offline, organization inactive.
  const inactive = Boolean(r.upload) && r.upload.status === 'inactive';
  const special = pol.status === 'revoked' ? 'revoked' : inactive ? 'inactive' : pol.status === 'offline' && !(r.upload && r.upload.status === 'tampered') ? 'offline' : null;
  if (!special) out('Policy: ' + (pol.status === 'updated' || pol.status === 'current' ? pol.status + ' (version ' + pol.version + ')' : pol.status + (pol.error ? ': ' + pol.error : '')));
  if (r.upload && !special) out('Audit upload: ' + r.upload.status + ', ' + (r.upload.uploaded || 0) + ' sent, ' + (r.upload.pending > 0 ? r.upload.pending : 0) + ' pending');
  if (r.revocations && r.revocations.pending) out('Revocation: the server has not taken the earlier leave yet (' + r.revocations.pending + ' pending); see `zn team status`.');
  else if (r.revocations && r.revocations.done) out('Revocation: the server has now been told that the earlier installation left.');
  if (r.upload && r.upload.status === 'error' && r.upload.error) out('Nothing was uploaded: ' + r.upload.error);
  if (r.upload && r.upload.status === 'tampered') out('Nothing was uploaded: ' + r.upload.error + '. Keep a copy of the audit log, look into the change, then run `' + znCommand('vault verify --acknowledge') + '` in your own terminal.');
  // Exit 0 only with a valid policy applied and no failed upload.
  if (special === 'revoked') err('[zn] ' + messages.TEAM_REMOVED);
  else if (special === 'inactive') err('[zn] ' + messages.teamSyncInactive(r.upload.pending));
  else if (special === 'offline') {
    err('[zn] ' + messages.teamSyncNoNetwork().split('\ndetails: ')[0]);
    if (isVerbose() && pol.error) err('[zn] details: ' + pol.error);
  } else if (!o.ok) err('[zn] sync incomplete: ' + o.problems.join('; '));
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
async function runTeamCommand(args, io) {
  try {
    const sub = args[1];
    if (args.slice(1).some((a) => a === '-h' || a === '--help')) { out(USAGE); return 0; }
    if (sub === 'join') return await joinCmd(args, io);
    if (sub === 'status' || sub === undefined) return await statusCmd(args);
    if (sub === 'sync') return await syncCmd();
    if (sub === 'leave') return await leaveCmd();
    if (sub === 'managed-config') return require('./managed-config').run(args.slice(2));
    err('[zn] ' + messages.teamNotACommand(sub));
    return 2;
  } catch (e) {
    printError(e);
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
        r = await probe.auditExport({ since: opts.since, installId: opts.installId, orgId: opts.orgId, verifyOnly: true });
        if (!r.ok && !r.tampered) {
          // The log could not be read: a read error, not a sign that it was changed.
          err('[zn] Not exported: ' + r.error);
          return 1;
        }
        if (!r.ok) {
          err('[zn] Not exported: ' + r.error + '. Keep a copy of ~/.zn/audit.jsonl as evidence, look into the change, then run `' + znCommand('vault verify --acknowledge') + '` in your own terminal.');
          return 1;
        }
      }
    } finally { probe.close(); }
    const unverified = !r;
    // A copy that was not verified is only made when asked for: it could be a log that was changed.
    if (unverified && !args.includes('--unverified')) {
      err('[zn] Not exported: the vault is locked or unreachable, so the audit log chain cannot be verified. Unlock it (`' + znCommand('unlock') + '`) and export again, or add --unverified to export a copy that is NOT verified.');
      return 1;
    }
    // The vault verified these exact bytes; the export read the file again. A different answer means the log changed in between.
    const sameBytes = (res) => {
      if (unverified || (res.fileSha256 === r.sha256 && res.fileBytes === r.bytes)) return;
      // A vault started by an older version answers without the hash of what it checked.
      if (r.sha256 === undefined) {
        throw new Error('Not exported: the running vault is from an older version of zn-gate and cannot confirm which bytes it verified. Run `' + znCommand('lock') + '`, then `' + znCommand('unlock') + '`, and export again. Nothing from this run should be used.');
      }
      throw new Error('Not exported: the audit log changed after the vault verified it (a new record may have been written), so this copy is not the verified log. Nothing from this run should be used; run the export again.');
    };
    const warn = () => {
      if (unverified) err('[zn] Warning: the vault is locked or unreachable, so the audit log chain was NOT verified. Unlock it (`' + znCommand('unlock') + '`) and export again for a verified copy.');
    };
    const file = flag(args, '--out');
    if (file) {
      // --out is never a link or a folder: a link would send the audit to whatever it points at.
      let existing = null;
      try { existing = fs.lstatSync(file); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      if (existing && !existing.isFile()) {
        err('[zn] Not exported: ' + file + ' is ' + (existing.isSymbolicLink() ? 'a symbolic link' : 'not a regular file') + '. Choose a path that is a new file or a regular file.');
        return 1;
      }
      // Written piece by piece to a temporary file and moved into place when complete: a read error leaves no partial export.
      const tmp = file + '.' + process.pid + '.tmp';
      const fd = fs.openSync(tmp, 'wx', 0o600);
      let res;
      try {
        res = exportAuditStream(opts, (s) => fs.writeSync(fd, s));
        sameBytes(res);
        fs.closeSync(fd);
        fs.renameSync(tmp, file);
      } catch (e) {
        try { fs.closeSync(fd); } catch (e2) { /* closed */ }
        try { fs.unlinkSync(tmp); } catch (e2) { /* gone */ }
        throw e;
      }
      err('Exported ' + res.records + ' records to ' + file + ' (OTLP/JSON Lines, sha256 ' + res.sha256 + ').');
    } else {
      // Nothing reaches stdout until the bytes are confirmed: the records are kept in memory (no copy of the audit
      // on disk), then written out. A log that changed in between leaves stdout empty and the command fails. A log
      // larger than STDOUT_EXPORT_MAX_BYTES is not buffered: --out FILE writes it to a private file instead.
      const parts = [];
      let size = 0;
      sameBytes(exportAuditStream(opts, (s) => {
        size += Buffer.byteLength(s);
        if (size > STDOUT_EXPORT_MAX_BYTES) {
          throw new Error('the audit log is larger than ' + (STDOUT_EXPORT_MAX_BYTES / 1048576) + ' MiB, too large to export to the terminal. Export it to a file with --out FILE.');
        }
        parts.push(s);
      }));
      for (const p of parts) process.stdout.write(p);
    }
    warn();
    return 0;
  } catch (e) {
    err('[zn] ' + (fsErrorText(e) || (e && e.message ? e.message : e)));
    return 1;
  }
}

module.exports = { runTeamCommand, runLogExport, describePolicy, _internal: { setStdoutExportMax(n) { STDOUT_EXPORT_MAX_BYTES = n; } } };
