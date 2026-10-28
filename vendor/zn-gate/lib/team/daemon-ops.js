'use strict';
/**
 * zn Team operations of the vault daemon.
 *
 * The install token, the organization's pinned public key and the last
 * accepted policy live in the encrypted vault (secrets.team), so only an
 * unlocked daemon can fetch the policy or upload the audit log, the token
 * never leaves this process, and editing or deleting files under ~/.zn does
 * not remove the organization's restrictions. ~/.zn/team.json and
 * ~/.zn/org-policy.json are readable copies, without the token, for the
 * hooks and `zn team status`.
 *
 * Joining and leaving are confirmed on the daemon's own channel: an agent
 * that runs `zn team join <token>` could otherwise send this machine's audit
 * records to an organization of its choosing, and `zn team leave` would drop
 * the organization's restrictions.
 */

const crypto = require('crypto');
const policy = require('./policy');
const audit = require('../vault/audit');
const { effective, approvalKey, detectorsOf } = require('./effective');
const changes = require('./changes');
const { createApi, checkBase } = require('./api');
const { uploadPending } = require('./upload');
const { syncOutcome } = require('./sync-outcome');
const { CODES, znError } = require('../errors');
const messages = require('../messages');
const { INVISIBLE } = require('../vault/confirm');

const VERSION = require('../../package.json').version;
const DEFAULT_API = 'https://api.usezn.com';
const JOIN_TOKEN_RE = /^znj_[A-Za-z0-9]{32,64}$/;
const AGENT_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const ALERT_EVERY_MS = 6 * 3600 * 1000; // a sync that keeps failing leaves one local alert every 6 hours
const REVOCATION_GIVE_UP_MS = 30 * 24 * 3600 * 1000; // a revocation the server never confirms is dropped after 30 days
const MAX_PENDING_REVOCATIONS = 8;

const osName = () => (['linux', 'darwin', 'win32'].includes(process.platform) ? process.platform : 'other');
/* Text from the server shown in dialogs and in `zn team status`: printable only (same invisible set as the dialogs). */
const INVISIBLE_RE = new RegExp('[' + INVISIBLE + ']', 'g');
const printable = (s, max) => (typeof s === 'string' ? s.replace(INVISIBLE_RE, '').trim().slice(0, max) : null);

function makeTeamOps(ctx) {
  const { state, writeAudit, confirmOutOfBand } = ctx;
  const verifyChain = typeof ctx.verifyChain === 'function' ? ctx.verifyChain : null;
  const fetchImpl = ctx.fetchImpl;
  const isClosed = typeof ctx.isClosed === 'function' ? ctx.isClosed : () => false;
  const files = () => policy.paths(state.opts);

  async function team() {
    const secrets = await state.loadSecrets();
    return secrets.team && typeof secrets.team === 'object' ? secrets.team : null;
  }

  /* Policy state from the copy held in the vault, verified with the pinned key. */
  async function policyState(now) {
    const t = await team();
    if (!t) return { state: 'none', policy: null };
    const held = t.policy && t.policy.envelope;
    if (!held) return { state: 'none', policy: null, org: t.org };
    const v = policy.verifyEnvelope(held, t.pin, { now, org: t.org, allowExpired: true });
    if (!v.ok) return { state: 'invalid', policy: null, org: t.org, error: v.error };
    return {
      state: v.expired ? 'expired' : 'active', policy: v.policy, org: t.org, version: v.policy.version,
      expires_at: v.policy.expires_at, etag: t.policy.etag || null, fetched_at: t.policy.fetched_at || null,
    };
  }

  function apiFor(t) {
    return createApi({ base: t.api_base, token: t.install_token, fetchImpl, userAgent: 'zn-gate/' + VERSION });
  }

  const teamRecord = (t) => ({
    org: t.org, org_name: t.org_name || null, api_base: t.api_base, install_id: t.install_id,
    policy_public_key: t.pin, joined_at: t.joined_at, upload_after_seq: Number.isInteger(t.upload_after_seq) ? t.upload_after_seq : 0,
  });
  /* Options for the readable policy copy: the date it was fetched and what it lifted, as held in the vault. */
  const cacheOpts = (t) => Object.assign({}, state.opts, { now: Date.parse(t.policy.fetched_at) || undefined, change: t.policy.change || undefined });
  const sameJson = (a, b) => { try { return policy.canonicalJson(a) === policy.canonicalJson(b); } catch (err) { return false; } };

  function mirror(t) {
    policy.writeTeam(teamRecord(t), state.opts);
    if (t.policy && t.policy.envelope) policy.writeCache(t.policy.envelope, t.policy.etag || null, cacheOpts(t));
  }

  /* Put back the readable copies (~/.zn/team.json and org-policy.json) from the vault when one was
   * deleted or edited: the hooks read them, and a missing team.json would leave the organization's
   * custom detectors off. Best effort (strict = throw, used by the sync); the vault stays the source of truth.
   * It runs in the serialised section and only while `m` (a membership snapshot) is still the current one, so a
   * request that started before a leave or a join of another organization cannot bring a copy back (false). */
  async function ensureCopies(m, strict) {
    try {
      return await state.serial(async () => {
        const cur = await team();
        if (!sameMembership(cur, m)) return false;
        writeCopies(cur, strict);
        return true;
      });
    } catch (err) {
      if (strict) throw err;
      return false; // best effort: the vault closed meanwhile, nothing to put back
    }
  }

  function writeCopies(t, strict) {
    try {
      const disk = policy.readTeam(state.opts);
      if (!disk || !sameJson(disk, Object.assign({ v: 1 }, teamRecord(t)))) policy.writeTeam(teamRecord(t), state.opts);
      if (t.policy && t.policy.envelope) {
        const c = policy.readCache(state.opts);
        if (!c || !sameJson(c.envelope, t.policy.envelope) || !sameJson(c.change || null, t.policy.change || null)) {
          policy.writeCache(t.policy.envelope, t.policy.etag || null, cacheOpts(t));
        }
      }
    } catch (err) { if (strict) throw err; /* the copies are not the source of truth */ }
  }

  /* Deletes the readable copies, the upload state and the upload lock; returns the paths that are still there. */
  function removeLocalCopies() {
    const f = files();
    return ['teamFile', 'policyFile', 'uploadState', 'uploadLock'].map((k) => f[k]).filter((file) => !policy.removeFile(file));
  }

  /* The last sync result as `zn team status` shows it: printable text only. */
  function lastSyncOf(t) {
    const l = t.last_sync;
    if (!l || typeof l !== 'object') return null;
    return {
      at: typeof l.at === 'string' ? l.at : null, ok: l.ok === true,
      last_ok_at: typeof l.last_ok_at === 'string' ? l.last_ok_at : null,
      problems: Array.isArray(l.problems) ? l.problems.map((p) => printable(String(p), 200)).filter(Boolean) : [],
    };
  }

  /* What a new policy has to beat: the version held and its canonical digest (same version, other content = refused). */
  function heldFloor(p) {
    if (!p) return { minVersion: 0, heldDigest: null, heldExpiresAt: null };
    const pol = p.envelope && p.envelope.policy;
    let heldDigest = typeof p.digest === 'string' ? p.digest : null;
    let heldExpiresAt = null;
    try {
      if (pol && pol.version === p.version) {
        heldDigest = policy.digestOf(pol);
        heldExpiresAt = Date.parse(pol.expires_at);
      }
    } catch (err) { /* keep the stored digest */ }
    return { minVersion: Number(p.version) || 0, heldDigest, heldExpiresAt: Number.isFinite(heldExpiresAt) ? heldExpiresAt : null };
  }

  /*
   * Membership generation. s.teamGen lives in the vault next to s.team but
   * outlives it: joining and leaving each add one, so a sync that started
   * under an earlier membership can never be mistaken for the current one.
   */
  const membership = (t) => ({ org: t.org, install_id: t.install_id, token: t.install_token, gen: Number.isInteger(t.gen) ? t.gen : 0 });
  const sameMembership = (t, m) => !!t && t.org === m.org && t.install_id === m.install_id && t.install_token === m.token &&
    (Number.isInteger(t.gen) ? t.gen : 0) === m.gen;

  /*
   * Runs fn on the team record inside the serialised section; with `snap`, only if the membership is still the one
   * that was snapshotted. Returns false when nothing was applied, else {value: what fn returned}. `after(team, value)`
   * runs in the same section once the vault is saved (the readable copies go there).
   */
  async function updateTeam(fn, snap, after) {
    return state.serial(async () => {
      const s = await state.loadSecrets();
      if (!s.team || (snap && !sameMembership(s.team, snap))) return false;
      const value = fn(s.team);
      await state.saveSecrets();
      if (after) after(s.team, value);
      return { value };
    });
  }

  /* fn runs in the serialised section only while the membership is still the snapshotted one: {stale: true} otherwise. */
  const guardedBy = (snap) => (fn) => state.serial(async () => {
    if (!sameMembership(await team(), snap)) return { stale: true };
    return { value: fn() };
  });

  /*
   * Revocations still to be told to the server. `zn team leave` calls POST /v1/org/install/leave with the
   * installation's own token before it deletes anything. When the server cannot be told (offline, 5xx, 429, an older
   * server without the endpoint), the machine still stops being a member at once; this record (s.pendingRevocations,
   * in the vault) keeps only what the retry needs: the token, the organization, the API base and the time. It is
   * not a membership: no policy, no uploads, no detectors. Each record is retried with its own token only, on every
   * sync, and dropped on 200, on 401 (nothing is left to revoke with that token) or after REVOCATION_GIVE_UP_MS.
   */
  const pendingList = (s) => (Array.isArray(s.pendingRevocations) ? s.pendingRevocations : []);
  const sameRevocation = (a, b) => a.install_id === b.install_id && a.install_token === b.install_token;

  async function askServerToRevoke(rec) {
    try {
      return await createApi({ base: rec.api_base, token: rec.install_token, fetchImpl, userAgent: 'zn-gate/' + VERSION }).leaveInstall();
    } catch (err) {
      return { done: false, error: 'could not ask the server (' + printable(String((err && err.message) || err), 80) + ')' };
    }
  }

  /* Runs fn(list) in the serialised section on the pending list and saves it. */
  function updatePending(fn) {
    return state.serial(async () => {
      const s = await state.loadSecrets();
      const list = pendingList(s).slice();
      const r = fn(list, s);
      if (list.length) s.pendingRevocations = list; else delete s.pendingRevocations;
      await state.saveSecrets();
      return r;
    });
  }

  /* What `zn team status` shows: no token. */
  function revocationsView(s) {
    return pendingList(s).map((r) => ({
      org: printable(r.org, 40), org_name: printable(r.org_name, 100) || null, install_id: printable(r.install_id, 64),
      since: printable(r.since, 40), last_try_at: printable(r.last_try_at, 40) || null,
      last_error: printable(r.last_error, 200) || null, tries: Number.isInteger(r.tries) ? r.tries : 0,
      next_try_at: printable(r.next_try_at, 40) || null,
      give_up_at: Number.isFinite(Date.parse(r.since)) ? new Date(Date.parse(r.since) + REVOCATION_GIVE_UP_MS).toISOString() : null,
    }));
  }

  /*
   * Tell the server about every pending revocation that is due. {tried, done, pending, abandoned}. Network calls
   * are made outside the serialised section. `skip` is a record that was just tried.
   */
  async function retryRevocations(skip) {
    const sum = { tried: 0, done: 0, pending: 0, abandoned: 0 };
    const s0 = await state.loadSecrets();
    for (const rec of pendingList(s0).map((r) => ({ ...r }))) {
      if (isClosed()) break;
      const now = Date.now();
      const since = Date.parse(rec.since);
      if (!Number.isFinite(since) || now - since > REVOCATION_GIVE_UP_MS) {
        await updatePending((list) => {
          const i = list.findIndex((r) => sameRevocation(r, rec));
          if (i >= 0) { list.splice(i, 1); writeAudit({ mode: 'remove', decision: 'error', reason: 'team_revocation_abandoned' }); }
        });
        sum.abandoned += 1;
        continue;
      }
      if ((skip && sameRevocation(skip, rec)) || (Date.parse(rec.next_try_at) > now)) { sum.pending += 1; continue; }
      const r = await askServerToRevoke(rec);
      sum.tried += 1;
      await updatePending((list) => {
        const i = list.findIndex((x) => sameRevocation(x, rec));
        if (i < 0) return;
        if (r.done) {
          list.splice(i, 1);
          writeAudit({ mode: 'remove', decision: 'allow', reason: 'team_revocation_done' });
        } else {
          list[i] = {
            ...list[i], last_try_at: new Date(now).toISOString(), last_error: printable(r.error, 200) || 'unknown', tries: (Number.isInteger(list[i].tries) ? list[i].tries : 0) + 1,
            next_try_at: r.retryAfterSeconds ? new Date(now + r.retryAfterSeconds * 1000).toISOString() : null,
          };
        }
      });
      if (r.done) sum.done += 1; else sum.pending += 1;
    }
    return sum;
  }

  const retrySafe = () => retryRevocations().catch(() => null);
  const worthSaying = (sum) => Boolean(sum && (sum.done || sum.pending || sum.abandoned));

  const ops = {
    /**
     * teamJoin({join_token, api_base, agent}) -> {org, org_name, install_id, api_base}
     * Registers this installation with the organization of the join token.
     */
    async teamJoin(args) {
      const a = args && typeof args === 'object' ? args : {};
      const joinToken = String(a.join_token || '');
      if (!JOIN_TOKEN_RE.test(joinToken)) throw znError(CODES.POLICY_DENIED, messages.TEAM_INVALID_JOIN_TOKEN);
      let base;
      try { base = checkBase(a.api_base || DEFAULT_API); } catch (err) { throw znError(CODES.POLICY_DENIED, 'invalid API address: ' + String(err.message).slice(0, 120)); }
      const agent = a.agent && AGENT_RE.test(String(a.agent)) ? String(a.agent) : undefined;
      const current = await team();
      if (current && current.api_base !== base) throw znError(CODES.POLICY_DENIED, 'this machine is already in organization ' + current.org + '; run `zn team leave` first');
      const host = new URL(base).host;
      const warnings = [];
      if (base !== DEFAULT_API) warnings.push('This is not the zn service (api.usezn.com). Only continue if your organization runs its own server at ' + host + '.');
      const api = createApi({ base, fetchImpl, userAgent: 'zn-gate/' + VERSION });
      // Which organization the token is for, shown in the dialog before anything is shared.
      // The preview does not use up the token; an unusable token stops here, without a dialog.
      // Only against the zn service, and only after the user agreed to the lookup above; another
      // server gets the token only after the user confirms the join.
      if (base === DEFAULT_API) {
        // The token leaves this machine only after the user agrees: ask first, on the vault's own
        // channel (it refuses when there is none), and only then look the organization up.
        await confirmOutOfBand({
          kind: 'team',
          title: 'look up the organization for this join token?',
          warnings: [],
          fields: [
            ['Server', host],
            ['Join token', 'ends in ' + joinToken.slice(-6) + ' (check it against the one your administrator sent you)'],
            ['Sends', 'the join token, to ' + host + ', to find out which organization it is for. This does not use up the token and does not connect this machine.'],
          ],
          footer: 'If you did not just run `zn team join` yourself with a token from your administrator, choose Deny.',
        }, { mode: 'set', reason: 'team_join_lookup' });
      }
      const pv = base === DEFAULT_API ? await api.preview(joinToken) : { ok: false, reason: 'unavailable', detail: 'not checked on a server other than api.usezn.com' };
      if (!pv.ok && (pv.reason === 'invalid' || pv.reason === 'no_subscription')) {
        writeAudit({ mode: 'set', decision: 'deny', reason: 'team_join_failed' });
        throw znError(CODES.POLICY_DENIED, messages.teamJoinFailed(pv.reason === 'invalid'
          ? 'this join token is invalid, expired or used up; ask your administrator for a new one'
          : 'this organization has no active Team subscription'));
      }
      const previewOrg = pv.ok ? printable(pv.org_name, 100) || null : null;
      const previewBy = pv.ok ? printable(pv.invited_by, 60) || null : null;
      if (!previewOrg) {
        const why = pv.ok ? 'the server sent an empty name' : printable(String(pv.detail || ''), 80);
        warnings.push('Could not check which organization this token is for (' + why + '); its name appears after joining.');
      }
      const orgFields = previewOrg
        ? [['Organization', previewOrg + ' (as reported by ' + host + ')'], ['Invited by', previewBy ? previewBy + ' (their display name)' : 'not shown (no display name set)']]
        : [];
      // Audit records written before joining stay on this machine unless the user asks, in this dialog, to send them too.
      if (current && a.include_history === true && current.upload_history === 'since_join') {
        throw znError(CODES.POLICY_DENIED, 'this machine joined without its earlier audit records, and the audit chain on the server has moved on, so they cannot be added now. Run `zn team leave` and join again with --include-history.');
      }
      const history = a.include_history === true ? 'included' : current ? (current.upload_history || 'all') : 'since_join';
      if (history === 'included') warnings.push('You asked to send the audit records already on this machine too (written before you joined). Choose Deny if you did not ask for that.');
      const shares = history === 'since_join'
        ? 'audit records written from now on: secret names, agents, tools, commands, hosts and decisions. Never secret values. The records already on this machine stay here.'
        : 'audit records, including the ones already on this machine: secret names, agents, tools, commands, hosts and decisions. Never secret values.';
      await confirmOutOfBand({
        kind: 'team',
        title: current
          ? 'reconnect this machine to organization ' + (previewOrg || current.org) + '?'
          : previewOrg ? 'connect this machine to ' + previewOrg + '?' : 'connect this machine to a zn organization?',
        warnings,
        fields: [
          ...orgFields,
          ['Server', host],
          ['Join token', 'ends in ' + joinToken.slice(-6) + ' (check it against the one your administrator sent you)'],
          ['Shares', shares],
          ['Applies', "the organization's signed policy for secrets (it can restrict; a new host for a secret asks you first)"],
        ],
        footer: 'If you did not just run `zn team join` yourself with a token from your administrator, choose Deny.',
      }, { mode: 'set', reason: 'team_join' });

      // "Since joining": the records up to here never leave this machine. Read before anything is sent, so an unreadable log stops the join cleanly.
      let afterSeq = 0;
      if (history === 'since_join') {
        if (current) {
          afterSeq = Number.isInteger(current.upload_after_seq) ? current.upload_after_seq : 0;
        } else {
          try {
            const last = audit.lastRecord(state.paths.auditFile);
            afterSeq = last ? last.seq : 0;
          } catch (err) {
            throw znError(CODES.POLICY_DENIED, 'join refused: zn could not read the local audit log, so it cannot tell which records came before you joined. This machine was not connected.');
          }
        }
      }

      const secrets = await state.loadSecrets();
      const installId = current ? current.install_id : crypto.randomUUID();
      let res;
      try {
        res = await api.join({ join_token: joinToken, install_id: installId, audit_key: secrets.auditKey, agent, zn_gate_version: VERSION, os: osName() });
      } catch (err) {
        const why = err && err.status ? 'HTTP ' + err.status + (err.body && err.body.error ? ': ' + printable(String(err.body.error), 160) : '') : (err && err.code) || 'network error';
        writeAudit({ mode: 'set', decision: 'deny', reason: 'team_join_failed' });
        throw znError(CODES.POLICY_DENIED, messages.teamJoinFailed(why));
      }
      if (current && res.org !== current.org) throw znError(CODES.POLICY_DENIED, 'the token is for another organization; run `zn team leave` first');
      if (!policy.checkPin(res.policy_public_key)) throw znError(CODES.POLICY_DENIED, messages.TEAM_INVALID_ORG_KEY);
      if (current && current.pin.kid !== res.policy_public_key.kid) throw znError(CODES.POLICY_DENIED, "the organization's signing key changed; run `zn team leave` and join again to accept the new key");
      const orgName = printable(res.org_name, 100) || null;
      // The organization joined must be the one shown in the dialog.
      if (previewOrg && orgName !== previewOrg) {
        writeAudit({ mode: 'set', decision: 'deny', reason: 'team_join_failed' });
        throw znError(CODES.POLICY_DENIED, 'join refused: the server joined a different organization than the one you confirmed; this machine was not connected. Ask your administrator.');
      }
      return state.serial(async () => {
        const s = await state.loadSecrets();
        s.teamGen = (Number.isInteger(s.teamGen) ? s.teamGen : 0) + 1;
        s.team = {
          gen: s.teamGen,
          org: res.org, org_name: orgName, api_base: base, install_id: installId,
          install_token: res.install_token, pin: res.policy_public_key,
          joined_at: current ? current.joined_at : new Date().toISOString(), revoked_at: null,
          policy: current && current.policy ? current.policy : null,
          // Records up to this sequence number are never uploaded (0: everything may be).
          upload_after_seq: afterSeq,
          upload_history: history,
        };
        writeAudit({ mode: 'set', decision: 'allow', reason: current ? 'team_rejoined' : 'team_joined' });
        await state.saveSecrets();
        mirror(s.team);
        return { org: res.org, org_name: orgName, install_id: installId, api_base: base };
      });
    },

    /**
     * teamLeave() -> {left: org | null, install_id, pending_files: [paths still on disk], revocation?}. Confirmed: it removes
     * the organization's restrictions. The server is told first, with this installation's own token
     * (revocation: {status: 'done', reason} or {status: 'pending', since, error}); the vault entry is then deleted and
     * every local copy is deleted and checked one by one. A revocation the server could not take stays pending in the
     * vault and is retried (see retryRevocations); it never keeps the machine in the organization.
     */
    async teamLeave() {
      const t = await team();
      if (!t) {
        const stuck = removeLocalCopies();
        await retrySafe();
        const s = await state.loadSecrets();
        return pendingList(s).length ? { left: null, pending_files: stuck, revocations: revocationsView(s) } : { left: null, pending_files: stuck };
      }
      await confirmOutOfBand({
        kind: 'team',
        title: 'disconnect this machine from organization ' + t.org + '?',
        warnings: ["The organization's policy stops applying here, and your administrators will see this machine stop reporting."],
        fields: [['Organization', t.org_name ? t.org_name + ' (' + t.org + ')' : t.org]],
        footer: 'If you did not just run `zn team leave` yourself, choose Deny.',
      }, { mode: 'set', reason: 'team_leave' });
      const snap = membership(t);
      const told = await askServerToRevoke({ api_base: t.api_base, install_token: t.install_token });
      const res = await state.serial(async () => {
        const s = await state.loadSecrets();
        if (!s.team) return { left: null, pending_files: removeLocalCopies() };
        if (!sameMembership(s.team, snap)) throw znError(CODES.POLICY_DENIED, 'the organization membership changed while leaving; run `zn team leave` again');
        delete s.team;
        s.teamGen = (Number.isInteger(s.teamGen) ? s.teamGen : 0) + 1;
        delete s.orgApprovals;
        writeAudit({ mode: 'remove', decision: 'allow', reason: 'team_left' });
        let revocation = { status: 'done', reason: told.done ? told.reason : null };
        let rec = null;
        if (!told.done) {
          const at = new Date().toISOString();
          rec = {
            org: t.org, org_name: t.org_name || null, install_id: t.install_id, api_base: t.api_base, install_token: t.install_token,
            since: at, last_try_at: at, last_error: printable(told.error, 200) || 'unknown', tries: 1,
            next_try_at: told.retryAfterSeconds ? new Date(Date.now() + told.retryAfterSeconds * 1000).toISOString() : null,
          };
          const list = pendingList(s).filter((r) => !sameRevocation(r, rec));
          list.push(rec);
          s.pendingRevocations = list.slice(-MAX_PENDING_REVOCATIONS);
          writeAudit({ mode: 'set', decision: 'error', reason: 'team_revocation_pending' });
          revocation = { status: 'pending', since: at, error: rec.last_error, give_up_at: new Date(Date.parse(at) + REVOCATION_GIVE_UP_MS).toISOString() };
        }
        await state.saveSecrets();
        return { rec, out: { left: t.org, install_id: t.install_id, pending_files: removeLocalCopies(), revocation } };
      });
      if (!res.out) return res;
      // Revocations of earlier memberships that are still pending get their turn too (not the one just tried).
      await retryRevocations(res.rec).catch(() => null);
      return res.out;
    },

    /** teamInfo() -> what `zn team status` shows. Never the token. */
    async teamInfo() {
      const t = await team();
      const secrets0 = await state.loadSecrets();
      if (!t) return pendingList(secrets0).length ? { joined: false, revocations: revocationsView(secrets0) } : { joined: false };
      const st = await policyState();
      await ensureCopies(membership(t));
      return {
        joined: true, org: t.org, org_name: t.org_name, install_id: t.install_id, api_base: t.api_base,
        joined_at: t.joined_at, revoked_at: t.revoked_at || null, kid: t.pin.kid,
        policy: {
          state: st.state, version: st.version || null, expires_at: st.expires_at || null, fetched_at: st.fetched_at || null, error: st.error || null,
          change: changes.cleanChange(t.policy && t.policy.change),
        },
        // The join is pending until a valid policy has been applied.
        join_pending: st.state === 'none' || st.state === 'invalid',
        upload_after_seq: Number.isInteger(t.upload_after_seq) ? t.upload_after_seq : 0,
        last_sync: lastSyncOf(t),
        ...(pendingList(secrets0).length ? { revocations: revocationsView(secrets0) } : {}),
      };
    },

    /**
     * teamHookInfo() -> what a hook needs when its readable copies are missing or do not verify:
     * the custom detectors of the policy held in the vault, and what the last version lifted.
     * It also puts the copies back. Never the token.
     */
    async teamHookInfo() {
      const t = await team();
      if (!t) return { joined: false };
      await ensureCopies(membership(t));
      const st = await policyState();
      return {
        joined: true, org: t.org, state: st.state, version: st.version || null,
        detectors: detectorsOf(st), change: changes.cleanChange(t.policy && t.policy.change),
      };
    },

    /**
     * teamSync({upload}) -> {policy: {status, version?, error?}, upload: {...}}
     * Downloads the policy (ETag) and uploads pending audit records.
     */
    async teamSyncNow(args, onSnapshot) {
      const a = args && typeof args === 'object' ? args : {};
      const t = await team();
      if (!t) throw znError(CODES.NOT_FOUND, 'this machine is not in an organization (zn team join <token>)');
      const api = apiFor(t);
      const snap = membership(t);
      if (typeof onSnapshot === 'function') onSnapshot(snap);
      const isCurrent = async () => sameMembership(await team(), snap);
      const guard = guardedBy(snap);
      const stale = () => ({ policy: { status: 'stale' }, upload: null });
      const out = { policy: null, upload: null };
      const held = await policyState();
      try {
        const r = await api.getPolicy({ etag: held.state === 'active' ? held.etag : undefined });
        if (isClosed()) return { policy: { status: 'stopped' }, upload: null };
        // The answer belongs to the membership that asked; if this machine left, rejoined or changed token meanwhile, drop it.
        if (!(await isCurrent())) return stale();
        if (r.status === 304) {
          if (!(await updateTeam((tt) => { if (tt.policy) tt.policy.fetched_at = new Date().toISOString(); }, snap, () => policy.touchCache(state.opts)))) return stale();
          out.policy = { status: 'current', version: held.version };
        } else if (r.status === 404) {
          out.policy = { status: 'none' };
        } else {
          // The rollback floor is the version held in the vault, not a file.
          let v = policy.verifyEnvelope(r.body, t.pin, { org: t.org, ...heldFloor(t.policy) });
          let applied = false;
          let rec = null;
          let newVersion = false;
          let lifted = null;
          if (v.ok) {
            rec = { envelope: r.body, etag: typeof r.etag === 'string' && r.etag.length <= 200 ? r.etag : null, version: v.policy.version, digest: policy.digestOf(v.policy), fetched_at: new Date().toISOString() };
            // One serialized write, only while this is still the membership that started the sync. Inside it the
            // version and digest are checked again against what the vault holds now (the policy held may have
            // changed since the download began) and what this version removes or loosens is computed against
            // that same held policy. The same version again keeps what was recorded for it. The readable copy is
            // written in the same section.
            const w = await updateTeam((tt) => {
              const again = policy.verifyEnvelope(r.body, tt.pin, { org: tt.org, ...heldFloor(tt.policy) });
              if (!again.ok) return { error: again.error };
              const prev = tt.policy && tt.policy.envelope ? policy.verifyEnvelope(tt.policy.envelope, tt.pin, { org: tt.org, allowExpired: true }) : null;
              const prevPolicy = prev && prev.ok ? prev.policy : null;
              const isNew = !prevPolicy || prevPolicy.version !== v.policy.version;
              const change = isNew ? (prevPolicy ? changes.changeRecord(prevPolicy, v.policy, rec.fetched_at) : null) : ((tt.policy && tt.policy.change) || null);
              if (change) rec.change = change; else delete rec.change;
              tt.policy = rec;
              return { ok: true, isNew, lifted: isNew ? change : null };
            }, snap, (tt, res) => {
              if (res && res.ok) policy.writeCache(rec.envelope, rec.etag, Object.assign({}, state.opts, { change: rec.change }));
            });
            if (!w) return stale();
            if (w.value && w.value.ok) { applied = true; newVersion = w.value.isNew; lifted = w.value.lifted; } else v = { ok: false, error: (w.value && w.value.error) || 'the policy could not be applied' };
          }
          if (applied) {
            out.policy = { status: 'updated', version: v.policy.version };
            if (lifted) out.policy.lifted = lifted.count;
            if (newVersion) writeAudit({ mode: 'set', decision: 'allow', reason: 'org_policy_v' + v.policy.version });
            if (lifted) writeAudit({ mode: 'set', decision: 'allow', reason: 'org_policy_lifted:v' + lifted.from + '-v' + lifted.to + ':n' + lifted.count });
          } else {
            out.policy = { status: 'rejected', error: v.error };
            writeAudit({ mode: 'set', decision: 'deny', reason: 'policy:rejected' });
          }
        }
        if (t.revoked_at) await updateTeam((tt) => { tt.revoked_at = null; }, snap);
      } catch (err) {
        if (err && err.status === 401) {
          if (!(await isCurrent())) return stale();
          out.policy = { status: 'revoked' };
          if (!t.revoked_at) await updateTeam((tt) => { tt.revoked_at = new Date().toISOString(); }, snap);
        } else {
          out.policy = { status: 'offline', error: (err && err.code) || 'error' };
        }
      }
      // Keep the readable copy in line with the vault (it may have been edited or deleted).
      // Keep the readable copy in line with the vault (it may have been edited or deleted), only while this is still
      // the membership that started the sync. A copy that cannot be written fails the sync.
      if (!(await ensureCopies(snap, true))) return stale();
      if (a.upload !== false && out.policy.status !== 'revoked' && !isClosed()) {
        const f = files();
        // The log is checked before anything leaves the machine; one that does not verify is never sent.
        const chain = verifyChain ? verifyChain() : { ok: true };
        if (!chain.ok) {
          out.upload = { status: 'tampered', uploaded: 0, pending: -1, error: chain.error };
          return out;
        }
        out.upload = await uploadPending({
          auditFile: state.paths.auditFile, stateFile: f.uploadState, lockFile: f.uploadLock,
          api, installId: t.install_id, version: VERSION,
          startAfterSeq: Number.isInteger(t.upload_after_seq) ? t.upload_after_seq : 0,
          // Nothing is sent or written once this machine left, rejoined or changed token: every write, the upload lock included, goes through guard.
          shouldStop: async () => isClosed() || !(await isCurrent()), isCurrent, guard,
        });
      }
      return out;
    },

    /**
     * confirmOrgOpening(secret, 'host', value, agent, agentTrusted) -> true
     * The user approves, on this machine, a host the organization's policy
     * opens for a secret. Only openings the current policy asks for, for an
     * agent zn can identify, can be approved.
     */
    async confirmOrgOpening(secret, kind, value, agent, agentTrusted) {
      const name = String(secret || '');
      if (!NAME_RE.test(name) || kind !== 'host' || typeof value !== 'string' || value.length > 253) throw znError(CODES.POLICY_DENIED, messages.TEAM_INVALID_REQUEST);
      const t = await team();
      const st = await policyState();
      const secrets = await state.loadSecrets();
      const local = secrets.secrets[name];
      if (!t || !local) throw znError(CODES.NOT_FOUND, messages.TEAM_NOTHING_TO_APPROVE);
      const eff = effective(name, local, { policy: st.policy, state: st.state, org: t.org, agent: agent || null, agentTrusted: agentTrusted === true, approvals: secrets.orgApprovals });
      if (!eff.pending.some((p) => p.kind === kind && p.value === value)) throw znError(CODES.POLICY_DENIED, messages.TEAM_NOT_ASKED);
      const warnings = ["Your organization's policy (version " + st.version + ') allows this, but this machine never did. It applies only after you approve it here.'];
      if (value.startsWith('*.')) warnings.push('This is a wildcard: it allows every host that ends in ' + value.slice(1) + ', not only the one being used now.');
      await confirmOutOfBand({
        kind: 'policy',
        title: 'let organization ' + t.org + ' send secret ' + name + ' to ' + value + '?',
        warnings,
        fields: [['Secret', name], ['New host', value], ['Agent', agent || 'unknown'], ['Organization', t.org_name ? t.org_name + ' (' + t.org + ')' : t.org]],
        footer: 'If you do not expect your organization to need this, choose Deny.',
      }, { secret: name, mode: 'set', reason: 'org_open' });
      return state.serial(async () => {
        const s = await state.loadSecrets();
        if (!s.orgApprovals || typeof s.orgApprovals !== 'object') s.orgApprovals = {};
        s.orgApprovals[approvalKey(t.org, name, kind, value)] = { ts: new Date().toISOString(), version: st.version };
        writeAudit({ secret: name, mode: 'set', decision: 'ask:yes', reason: 'org_open_host' });
        await state.saveSecrets();
        return true;
      });
    },

    /**
     * effectiveList(list, agent, agentTrusted) -> list with the organization
     * policy applied: each entry gets the settings to enforce, `deny`,
     * `warn` (with the rule's `warnReason`, printable only) and
     * `orgPending`. In a team, a policy that does not verify (or none yet)
     * leaves the local settings: the vault copy cannot be edited from outside.
     */
    async effectiveList(list, agent, agentTrusted) {
      const t = await team();
      if (!t) return list;
      const st = await policyState();
      if (st.state !== 'active' && st.state !== 'expired') return list;
      const secrets = await state.loadSecrets();
      return list.map((entry) => {
        const eff = effective(entry.name, entry, { policy: st.policy, state: st.state, org: t.org, agent: agent || null, agentTrusted: agentTrusted === true, approvals: secrets.orgApprovals });
        return Object.assign({}, entry, eff.meta, {
          name: entry.name,
          deny: eff.deny,
          denyReason: eff.deny ? eff.reason : undefined,
          warn: eff.warn === true,
          warnReason: eff.warn ? printable(eff.warnReason, 200) || undefined : undefined,
          orgPending: eff.pending.length ? eff.pending : undefined,
          orgPolicy: { version: st.version, state: st.state },
        });
      });
    },
  };

  /**
   * teamSync({upload}) -> {policy: {status, version?, error?}, upload: {...}}
   * Runs the sync and keeps its outcome in the vault (`last_sync`, shown by
   * `zn team status`). An exception is recorded too, then thrown again, so
   * the periodic job (which has nobody to tell) leaves a trace of every failure.
   */
  ops.teamSync = async function teamSync(args) {
    let out;
    let snap = null;
    try {
      out = await ops.teamSyncNow(args, (m) => { snap = m; });
    } catch (err) {
      if (snap) await noteSync(['sync failed: ' + printable(String((err && err.message) || (err && err.code) || err), 160)], snap).catch(() => {});
      // Not in an organization (any more): the revocation of the installation left earlier is still retried here.
      const sum = await retrySafe();
      if (!snap && worthSaying(sum) && err && typeof err.message === 'string') {
        const s = await state.loadSecrets().catch(() => ({}));
        const left = pendingList(s)[0];
        err.message += '. ' + (sum.pending
          ? 'The server has not yet been told that installation ' + (left ? left.install_id : '') + ' left (retried now, still pending; see zn team status)'
          : sum.done ? 'The revocation of the installation left earlier was completed'
            : 'zn stopped retrying the revocation of the installation left earlier (30 days): ask an organization admin to remove it from the dashboard');
      }
      throw err;
    }
    if (snap && !(out.policy && out.policy.status === 'stopped')) await noteSync(syncOutcome(out).problems, snap).catch(() => {});
    const sum = isClosed() ? null : await retrySafe();
    if (worthSaying(sum)) out.revocations = sum;
    return out;
  };

  /* Record how the last sync went. A failure leaves one local alert (an audit record), then at most one more every ALERT_EVERY_MS. */
  async function noteSync(problems, snap) {
    const ok = problems.length === 0;
    const at = new Date().toISOString();
    // Only for the membership that ran the sync: after a leave or a join of another organization nothing is written.
    await updateTeam((tt) => {
      const prev = tt.last_sync && typeof tt.last_sync === 'object' ? tt.last_sync : null;
      const next = { at, ok, problems: problems.slice(0, 5), last_ok_at: ok ? at : (prev && prev.last_ok_at) || null };
      if (!ok) {
        const lastAlert = prev && prev.alerted_at ? Date.parse(prev.alerted_at) : 0;
        if (!prev || prev.ok || !(Date.now() - lastAlert < ALERT_EVERY_MS)) {
          next.alerted_at = at;
          writeAudit({ mode: 'set', decision: 'error', reason: 'team_sync_failed' });
        } else {
          next.alerted_at = prev.alerted_at;
        }
      }
      tt.last_sync = next;
    }, snap);
  }

  return ops;
}

module.exports = { makeTeamOps, DEFAULT_API };
