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
const { effective, approvalKey } = require('./effective');
const { createApi, checkBase } = require('./api');
const { uploadPending } = require('./upload');
const { CODES, znError } = require('../errors');
const { INVISIBLE } = require('../vault/confirm');

const VERSION = require('../../package.json').version;
const DEFAULT_API = 'https://api.usezn.com';
const JOIN_TOKEN_RE = /^znj_[A-Za-z0-9]{32,64}$/;
const AGENT_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

const osName = () => (['linux', 'darwin', 'win32'].includes(process.platform) ? process.platform : 'other');
/* Text from the server shown in dialogs and in `zn team status`: printable only (same invisible set as the dialogs). */
const INVISIBLE_RE = new RegExp('[' + INVISIBLE + ']', 'g');
const printable = (s, max) => (typeof s === 'string' ? s.replace(INVISIBLE_RE, '').trim().slice(0, max) : null);

function makeTeamOps(ctx) {
  const { state, writeAudit, confirmOutOfBand } = ctx;
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

  function mirror(t) {
    policy.writeTeam({
      org: t.org, org_name: t.org_name || null, api_base: t.api_base, install_id: t.install_id,
      policy_public_key: t.pin, joined_at: t.joined_at,
    }, state.opts);
    if (t.policy && t.policy.envelope) policy.writeCache(t.policy.envelope, t.policy.etag || null, state.opts);
  }

  async function updateTeam(fn) {
    return state.serial(async () => {
      const s = await state.loadSecrets();
      if (!s.team) return null;
      const r = fn(s.team);
      await state.saveSecrets();
      return r;
    });
  }

  return {
    /**
     * teamJoin({join_token, api_base, agent}) -> {org, org_name, install_id, api_base}
     * Registers this installation with the organization of the join token.
     */
    async teamJoin(args) {
      const a = args && typeof args === 'object' ? args : {};
      const joinToken = String(a.join_token || '');
      if (!JOIN_TOKEN_RE.test(joinToken)) throw znError(CODES.POLICY_DENIED, 'invalid join token (expected znj_...)');
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
      // Only against the zn service: another server gets the token only after the user confirms.
      const pv = base === DEFAULT_API ? await api.preview(joinToken) : { ok: false, reason: 'unavailable', detail: 'not checked on a server other than api.usezn.com' };
      if (!pv.ok && (pv.reason === 'invalid' || pv.reason === 'no_subscription')) {
        writeAudit({ mode: 'set', decision: 'deny', reason: 'team_join_failed' });
        throw znError(CODES.POLICY_DENIED, pv.reason === 'invalid'
          ? 'join failed (this join token is invalid, expired or used up; ask your administrator for a new one)'
          : 'join failed (this organization has no active Team subscription)');
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
          ['Shares', 'audit records, including the ones already on this machine: secret names, agents, tools, commands, hosts and decisions. Never secret values.'],
          ['Applies', "the organization's signed policy for secrets (it can restrict; a new host for a secret asks you first)"],
        ],
        footer: 'If you did not just run `zn team join` yourself with a token from your administrator, choose Deny.',
      }, { mode: 'set', reason: 'team_join' });

      const secrets = await state.loadSecrets();
      const installId = current ? current.install_id : crypto.randomUUID();
      let res;
      try {
        res = await api.join({ join_token: joinToken, install_id: installId, audit_key: secrets.auditKey, agent, zn_gate_version: VERSION, os: osName() });
      } catch (err) {
        const why = err && err.status ? 'HTTP ' + err.status + (err.body && err.body.error ? ': ' + printable(String(err.body.error), 160) : '') : (err && err.code) || 'network error';
        writeAudit({ mode: 'set', decision: 'deny', reason: 'team_join_failed' });
        throw znError(CODES.POLICY_DENIED, 'join failed (' + why + ')');
      }
      if (current && res.org !== current.org) throw znError(CODES.POLICY_DENIED, 'the token is for another organization; run `zn team leave` first');
      if (!policy.checkPin(res.policy_public_key)) throw znError(CODES.POLICY_DENIED, 'the server sent an invalid organization key');
      if (current && current.pin.kid !== res.policy_public_key.kid) throw znError(CODES.POLICY_DENIED, "the organization's signing key changed; run `zn team leave` and join again to accept the new key");
      const orgName = printable(res.org_name, 100) || null;
      // The organization joined must be the one shown in the dialog.
      if (previewOrg && orgName !== previewOrg) {
        writeAudit({ mode: 'set', decision: 'deny', reason: 'team_join_failed' });
        throw znError(CODES.POLICY_DENIED, 'join refused: the server joined a different organization than the one you confirmed; this machine was not connected. Ask your administrator.');
      }
      return state.serial(async () => {
        const s = await state.loadSecrets();
        s.team = {
          org: res.org, org_name: orgName, api_base: base, install_id: installId,
          install_token: res.install_token, pin: res.policy_public_key,
          joined_at: current ? current.joined_at : new Date().toISOString(), revoked_at: null,
          policy: current && current.policy ? current.policy : null,
        };
        writeAudit({ mode: 'set', decision: 'allow', reason: current ? 'team_rejoined' : 'team_joined' });
        await state.saveSecrets();
        mirror(s.team);
        return { org: res.org, org_name: orgName, install_id: installId, api_base: base };
      });
    },

    /** teamLeave() -> {left: org | null}. Confirmed: it removes the organization's restrictions. */
    async teamLeave() {
      const t = await team();
      if (!t) {
        for (const f of ['teamFile', 'policyFile', 'uploadState']) policy.removeFile(files()[f]);
        return { left: null };
      }
      await confirmOutOfBand({
        kind: 'team',
        title: 'disconnect this machine from organization ' + t.org + '?',
        warnings: ["The organization's policy stops applying here, and your administrators will see this machine stop reporting."],
        fields: [['Organization', t.org_name ? t.org_name + ' (' + t.org + ')' : t.org]],
        footer: 'If you did not just run `zn team leave` yourself, choose Deny.',
      }, { mode: 'set', reason: 'team_leave' });
      return state.serial(async () => {
        const s = await state.loadSecrets();
        delete s.team;
        delete s.orgApprovals;
        writeAudit({ mode: 'remove', decision: 'allow', reason: 'team_left' });
        await state.saveSecrets();
        for (const f of ['teamFile', 'policyFile', 'uploadState']) policy.removeFile(files()[f]);
        return { left: t.org };
      });
    },

    /** teamInfo() -> what `zn team status` shows. Never the token. */
    async teamInfo() {
      const t = await team();
      if (!t) return { joined: false };
      const st = await policyState();
      return {
        joined: true, org: t.org, org_name: t.org_name, install_id: t.install_id, api_base: t.api_base,
        joined_at: t.joined_at, revoked_at: t.revoked_at || null, kid: t.pin.kid,
        policy: { state: st.state, version: st.version || null, expires_at: st.expires_at || null, fetched_at: st.fetched_at || null, error: st.error || null },
      };
    },

    /**
     * teamSync({upload}) -> {policy: {status, version?, error?}, upload: {...}}
     * Downloads the policy (ETag) and uploads pending audit records.
     */
    async teamSync(args) {
      const a = args && typeof args === 'object' ? args : {};
      const t = await team();
      if (!t) throw znError(CODES.NOT_FOUND, 'this machine is not in an organization (zn team join <token>)');
      const api = apiFor(t);
      const out = { policy: null, upload: null };
      const held = await policyState();
      try {
        const r = await api.getPolicy({ etag: held.state === 'active' ? held.etag : undefined });
        if (isClosed()) return { policy: { status: 'stopped' }, upload: null };
        if (r.status === 304) {
          await updateTeam((tt) => { if (tt.policy) tt.policy.fetched_at = new Date().toISOString(); });
          policy.touchCache(state.opts);
          out.policy = { status: 'current', version: held.version };
        } else if (r.status === 404) {
          out.policy = { status: 'none' };
        } else {
          // The rollback floor is the version held in the vault, not a file.
          const v = policy.verifyEnvelope(r.body, t.pin, { org: t.org, minVersion: (t.policy && t.policy.version) || 0 });
          if (v.ok) {
            const rec = { envelope: r.body, etag: typeof r.etag === 'string' && r.etag.length <= 200 ? r.etag : null, version: v.policy.version, fetched_at: new Date().toISOString() };
            await updateTeam((tt) => { tt.policy = rec; });
            policy.writeCache(rec.envelope, rec.etag, state.opts);
            out.policy = { status: 'updated', version: v.policy.version };
            if (held.version !== v.policy.version) writeAudit({ mode: 'set', decision: 'allow', reason: 'org_policy_v' + v.policy.version });
          } else {
            out.policy = { status: 'rejected', error: v.error };
            writeAudit({ mode: 'set', decision: 'deny', reason: 'policy:rejected' });
          }
        }
        if (t.revoked_at) await updateTeam((tt) => { tt.revoked_at = null; });
      } catch (err) {
        if (err && err.status === 401) {
          out.policy = { status: 'revoked' };
          if (!t.revoked_at) await updateTeam((tt) => { tt.revoked_at = new Date().toISOString(); });
        } else {
          out.policy = { status: 'offline', error: (err && err.code) || 'error' };
        }
      }
      // Keep the readable copy in line with the vault (it may have been edited or deleted).
      const now = await team();
      if (now && now.policy && now.policy.envelope) {
        const disk = policy.readCache(state.opts);
        if (!disk || JSON.stringify(disk.envelope) !== JSON.stringify(now.policy.envelope)) policy.writeCache(now.policy.envelope, now.policy.etag, state.opts);
      }
      if (a.upload !== false && out.policy.status !== 'revoked' && !isClosed()) {
        const f = files();
        out.upload = await uploadPending({
          auditFile: state.paths.auditFile, stateFile: f.uploadState, lockFile: f.uploadLock,
          api, installId: t.install_id, version: VERSION, shouldStop: isClosed,
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
      if (!NAME_RE.test(name) || kind !== 'host' || typeof value !== 'string' || value.length > 253) throw znError(CODES.POLICY_DENIED, 'invalid request');
      const t = await team();
      const st = await policyState();
      const secrets = await state.loadSecrets();
      const local = secrets.secrets[name];
      if (!t || !local) throw znError(CODES.NOT_FOUND, 'nothing to approve');
      const eff = effective(name, local, { policy: st.policy, state: st.state, org: t.org, agent: agent || null, agentTrusted: agentTrusted === true, approvals: secrets.orgApprovals });
      if (!eff.pending.some((p) => p.kind === kind && p.value === value)) throw znError(CODES.POLICY_DENIED, 'the organization policy does not ask for this');
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
     * policy applied: each entry gets the settings to enforce, `deny`, and
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
          orgPending: eff.pending.length ? eff.pending : undefined,
          orgPolicy: { version: st.version, state: st.state },
        });
      });
    },
  };
}

module.exports = { makeTeamOps, DEFAULT_API };
