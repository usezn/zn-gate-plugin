'use strict';
/**
 * Vault daemon (`zn unlock` / `zn lock`), in the style of ssh-agent.
 *
 * - Holds the age identity in memory for one session: 8 h at most and
 *   30 min without requests (both configurable). On expiry or `zn lock` it
 *   drops its state, removes its socket and session key, and exits.
 * - Listens on a Unix socket (mode 0600, in ~/.zn/run, 0700) or on a
 *   Windows named pipe. Every connection must prove knowledge of the
 *   session key (~/.zn/run/session.key, 0600, random per unlock) with a
 *   mutual HMAC challenge, so a process of another user cannot use the
 *   daemon, and a client never sends anything to a squatted pipe.
 * - Newline-delimited JSON. Requests on one connection run in order; vault
 *   writes are serialised.
 * - Policy is enforced here as well as in the engine: `resolve` refuses
 *   destinations that the restoration policy withholds (network commands,
 *   MCP input, versioned files), and every resolve is audited.
 *
 * Limits (documented in the threat model): any process of the same OS user
 * that can read ~/.zn/run/session.key can talk to the daemon, exactly like
 * ssh-agent. Agent hooks deny agent tool calls that touch ~/.zn; the OS user
 * boundary is the real isolation. JS strings cannot be wiped from memory;
 * state is dropped and left to the garbage collector.
 *
 * The identity reaches the daemon process on stdin, never through argv,
 * environment variables or disk.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const store = require('./store');
const keychain = require('./keychain');
const audit = require('./audit');
const confirmMod = require('./confirm');
const { variants } = require('../scrub/exact');
const exe = require('../exe');
const { makeTeamOps } = require('../team/daemon-ops');
const { CODES, znError } = require('../errors');

const PROTOCOL = 1;
const DEFAULT_TTL_MS = 8 * 3600 * 1000;
const DEFAULT_IDLE_MS = 30 * 60 * 1000;
const DEFAULT_TEAM_SYNC_MS = 15 * 60 * 1000;
const MAX_LINE = 4 * 1024 * 1024;
const MAX_VALUE = 1024 * 1024;
const MAX_DETECTED_EXACT = 256;
const TYPE_RE = /^[A-Z0-9](?:[A-Z0-9_]{0,62}[A-Z0-9])?$/;
const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const TOKEN_RE = /^__ZN_([A-Z0-9](?:[A-Z0-9_]*[A-Z0-9])?)__$/;
const HOST_RE = /^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*(?::\d{1,5})?$/;
const COMMAND_RE = /^[A-Za-z0-9_.+\-/ *]{1,128}$/;
const CLOUD_KEY_SECRET = 'ZN_CLOUD_API_KEY';
const CLOUD_KEY_PURPOSE = 'zn-cloud-key';
const DENIED_RESOLVE = new Set(['bash_network', 'mcp_input', 'write_tracked']);
/* What this vault does beyond the protocol. resolve-policy: resolve() with
 * {withPolicy: true} applies the organization policy and answers
 * {value, policy: RESOLVE_POLICY_VERSION, deny?, warn?, warnReason?}. */
const RESOLVE_POLICY_VERSION = 1;
const PACKAGE_VERSION = require('../../package.json').version;
const VAULT_FEATURES = Object.freeze(['resolve-policy']);
const ALLOW_IN = ['header', 'query', 'body'];
// Commands that run arbitrary code given to them (python3.12, node22, pwsh...):
// approving one lets any script it runs read the secret. The confirmation
// says so. One list for the daemon and the CLI, in lib/exe.js.
const { isInterpreter, isInterpreterPath } = exe;

const { endpoint, hmac, safeEqualHex, createClient } = require('./client');

/* ------------------------------------------------------------------ */
/* Vault state                                                         */
/* ------------------------------------------------------------------ */

class VaultState {
  constructor(identity, recipient, opts) {
    this.identity = identity;
    this.recipient = recipient;
    this.opts = opts;
    this.paths = store.paths(opts);
    this.secrets = null;          // {v, auditKey, auditHead, secrets: {NAME: {...}}}
    this.projects = new Map();    // projectKey -> {data, byValue: Map}
    this.loading = new Map();     // projectKey -> Promise of the entry above
    this.dirtySecrets = false;
    this.writeChain = Promise.resolve();
  }

  serial(fn) {
    const next = this.writeChain.then(fn, fn);
    this.writeChain = next.catch(() => {});
    return next;
  }

  /* Integrity tag of secrets.age. age does not authenticate the sender:
   * anyone who can write ~/.zn/vault could encrypt a forged vault to the
   * public recipient. The tag is an HMAC keyed by the identity, which only
   * the daemon holds, so a forged or edited vault is refused. */
  tagOf(data) {
    const key = crypto.createHmac('sha256', String(this.identity)).update('zn-vault-integrity-v1').digest();
    const body = Object.assign({}, data);
    delete body.mac;
    return crypto.createHmac('sha256', key).update(JSON.stringify(body)).digest('hex');
  }

  async loadSecrets() {
    if (this.secrets) return this.secrets;
    let data = await store.readEncrypted(this.paths.secretsFile, this.identity);
    if (!data) {
      // A missing vault next to an existing audit log or project maps means
      // it was deleted or lost: never start over silently with a new audit key.
      if (store.hasPriorState(this.opts)) {
        throw znError(CODES.LOCKED, 'vault file secrets.age is missing but this vault has history (audit log or project maps). ' +
          'Restore secrets.age from a backup. To start over on purpose, first move ~/.zn/audit.jsonl and the project maps ~/.zn/vault/<hash>.age somewhere else.');
      }
      data = { v: 1, auditKey: crypto.randomBytes(32).toString('hex'), auditHead: null, secrets: {} };
      data.mac = this.tagOf(data);
      await store.writeEncrypted(this.paths.secretsFile, data, this.recipient);
    } else if (typeof data.mac !== 'string' || !/^[0-9a-f]{64}$/.test(data.mac) ||
        !crypto.timingSafeEqual(Buffer.from(data.mac, 'hex'), Buffer.from(this.tagOf(data), 'hex'))) {
      throw znError(CODES.LOCKED, 'vault file secrets.age failed its integrity check: it was edited, forged with the public key, ' +
        'or written by a pre-release build. Restore it from a backup.');
    }
    if (!data.secrets || typeof data.secrets !== 'object') data.secrets = {};
    if (!/^[0-9a-f]{64}$/.test(data.auditKey || '')) data.auditKey = crypto.randomBytes(32).toString('hex');
    this.secrets = data;
    return data;
  }

  async saveSecrets() {
    if (!this.secrets) return;
    this.secrets.mac = this.tagOf(this.secrets);
    await store.writeEncrypted(this.paths.secretsFile, this.secrets, this.recipient);
    this.dirtySecrets = false;
  }

  /* One load per project even with concurrent connections. */
  loadProject(project) {
    const key = store.projectKey(project);
    if (!this.loading.has(key)) {
      const pending = this._loadProject(project, key);
      this.loading.set(key, pending);
      pending.catch(() => this.loading.delete(key));
    }
    return this.loading.get(key);
  }

  async _loadProject(project, key) {
    let p = this.projects.get(key);
    if (p) return p;
    const file = store.projectFile(project, this.opts);
    let data = await store.readEncrypted(file, this.identity);
    if (!data) data = { v: 1, created: new Date().toISOString(), counters: {}, tokens: {} };
    if (!data.counters || typeof data.counters !== 'object') data.counters = {};
    if (!data.tokens || typeof data.tokens !== 'object') data.tokens = {};
    const byValue = new Map();
    for (const [token, value] of Object.entries(data.tokens)) {
      const m = TOKEN_RE.exec(token);
      if (!m) continue;
      const type = m[1].replace(/_\d+$/, '');
      byValue.set(type + '\0' + value, token);
    }
    p = { key, file, data, byValue };
    this.projects.set(key, p);
    store.touch(file);
    return p;
  }

  knownValues() {
    const out = [];
    if (this.secrets) for (const s of Object.values(this.secrets.secrets)) if (s && s.value) out.push(s.value);
    for (const p of this.projects.values()) for (const v of Object.values(p.data.tokens)) out.push(v);
    return out;
  }

  drop() {
    this.identity = null;
    this.secrets = null;
    this.projects.clear();
    this.loading.clear();
  }
}

/* ------------------------------------------------------------------ */
/* Operations                                                          */
/* ------------------------------------------------------------------ */

function str(v, what, max) {
  if (typeof v !== 'string' || v.length === 0 || v.length > (max || MAX_VALUE)) throw znError(CODES.POLICY_DENIED, 'invalid ' + what + '. Next step: check the value and try again.');
  return v;
}

function cleanMeta(meta) {
  const m = meta && typeof meta === 'object' ? meta : {};
  const out = {};
  if (m.type !== undefined) out.type = TYPE_RE.test(String(m.type)) ? String(m.type) : 'SECRET';
  out.mode = ['proxy', 'env', 'file', 'backup'].includes(m.mode) ? m.mode : 'env';
  out.allowHosts = Array.isArray(m.allowHosts) ? m.allowHosts.map((h) => String(h).toLowerCase()).filter((h) => HOST_RE.test(h)).slice(0, 64) : [];
  out.allowCommands = Array.isArray(m.allowCommands) ? m.allowCommands.map(String).filter((c) => COMMAND_RE.test(c)).slice(0, 64) : [];
  if (['header', 'query', 'body'].includes(m.injectAt)) out.injectAt = m.injectAt;
  // Where secrets_http_request may put the value. Absent means headers only.
  if (Array.isArray(m.allowIn)) out.allowIn = ALLOW_IN.filter((k) => m.allowIn.map(String).includes(k));
  out.source = typeof m.source === 'string' && /^(?:local|op:\/\/[^\s]{1,200}|bws:[^\s]{1,200}|infisical:[^\s]{1,200}|import:[^\s]{1,200})$/.test(m.source) ? m.source : 'local';
  return out;
}

/* Secret names: UPPER_SNAKE_CASE; never `<anything>_<number>` (the shape of
 * detected-value tokens) and never REDACTED_* (irreversible markers). */
function checkName(name) {
  const n = str(name, 'name', 64);
  if (!NAME_RE.test(n) || /_\d+$/.test(n) || /^REDACTED(?:_|$)/.test(n)) {
    throw znError(CODES.POLICY_DENIED, 'secret names are UPPER_SNAKE_CASE, cannot end in _<number> and cannot start with REDACTED_. Next step: pick another name, for example MY_API_KEY.');
  }
  return n;
}

function normArgv0(argv0) {
  let a = String(argv0 || '').split(/[\\/]/).pop().trim();
  if (process.platform === 'win32') a = a.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
  if (!/^[A-Za-z0-9_.+-]{1,64}$/.test(a)) throw znError(CODES.POLICY_DENIED, 'invalid command name. Next step: give only the program name, for example psql.');
  return a;
}

function approvalKey(project, secret, argv0) {
  const s = String(secret || '');
  if (!NAME_RE.test(s)) throw znError(CODES.POLICY_DENIED, 'invalid secret name. Next step: use letters, digits and underscores, for example MY_API_KEY.');
  return store.projectKey(String(project == null ? '' : project)) + ':' + s + ':' + normArgv0(argv0);
}

/* File identity of an executable (lib/exe.js). ctime changes on any rewrite
 * or chmod and cannot be set back by an unprivileged user, so an approved
 * binary that is replaced in place (or a symlink retargeted) loses its
 * approval. */
const { fingerprint } = exe;

/* One line about a file for the confirmation text: size and change time. */
function fileFacts(fp) {
  const d = exe.describeFingerprint(fp);
  if (!d) return 'unknown';
  return (d.size == null ? '?' : d.size) + ' bytes, changed ' + (d.changed || '?');
}

/* What a policy change adds. Only additions need confirmation. */
function widening(prev, next) {
  const added = (a, b) => (b || []).filter((x) => !(a || []).includes(x));
  const out = [];
  if (next.mode !== prev.mode) out.push('mode ' + (prev.mode || '-') + ' -> ' + next.mode);
  const h = added(prev.allowHosts, next.allowHosts);
  if (h.length) out.push('hosts + ' + h.join(', '));
  const c = added(prev.allowCommands, next.allowCommands);
  if (c.length) out.push('commands + ' + c.join(', '));
  const i = added(prev.allowIn || ['header'], next.allowIn || ['header']);
  if (i.length) out.push('HTTP placement + ' + i.join(', '));
  return out;
}

function makeOps(state, ctl) {
  const auditFile = state.paths.auditFile;
  const channel = ctl.channel;

  /* Ask the user on the daemon's own channel. Resolves true or throws. */
  async function confirmOutOfBand(req, auditEvent) {
    let ok = false;
    // The rendered text travels with the structured fields (injected channels read it).
    req.message = confirmMod.render(req);
    try {
      ok = await channel.confirm(req);
    } catch (err) {
      writeAudit(Object.assign({}, auditEvent, { decision: 'deny', reason: err && err.noChannel ? 'no_confirmation_channel' : 'confirmation_failed' }));
      throw znError(CODES.POLICY_DENIED, String((err && err.message) || 'confirmation failed').slice(0, 300) + '. Next step: try again; if it keeps failing, check the zn confirmation prompt, or, if you are an agent, ask the user to check it.');
    }
    if (ok !== true) {
      writeAudit(Object.assign({}, auditEvent, { decision: 'deny', reason: 'declined_by_user' }));
      throw znError(CODES.POLICY_DENIED, 'declined by the user. Next step: nothing was changed. Do not retry the same request; finish the task another way.');
    }
    return true;
  }

  /* Synchronous on purpose: audit.append is synchronous file I/O, so two
   * appends can never interleave and break the chain. */
  function writeAudit(event) {
    const secrets = state.secrets;
    if (!secrets) throw znError(CODES.LOCKED, 'vault locked');
    const rec = audit.append(event, { file: auditFile, key: Buffer.from(secrets.auditKey, 'hex'), knownValues: state.knownValues() });
    secrets.auditHead = { seq: rec.seq, mac: rec.mac };
    state.dirtySecrets = true;
    return rec;
  }

  const team = makeTeamOps({ state, writeAudit, confirmOutOfBand, fetchImpl: ctl.fetchImpl, isClosed: () => Boolean(ctl.closed) });

  return {
    async status() {
      return { unlocked: true, protocol: PROTOCOL, pid: process.pid, expiresAt: new Date(ctl.expiresAt).toISOString(), idleMs: ctl.idleMs, confirm: channel.kind, features: VAULT_FEATURES, version: PACKAGE_VERSION };
    },

    async mapToken(project, type, value) {
      str(value, 'value');
      const t = String(type || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
      if (!TYPE_RE.test(t)) throw znError(CODES.POLICY_DENIED, 'invalid type. Next step: use one of the types listed in the tool description.');
      return state.serial(async () => {
        const p = await state.loadProject(String(project == null ? '' : project));
        const key = t + '\0' + value;
        const existing = p.byValue.get(key);
        if (existing) return existing;
        const n = (Number(p.data.counters[t]) || 0) + 1;
        const token = '__ZN_' + t + '_' + n + '__';
        p.data.counters[t] = n;
        p.data.tokens[token] = value;
        p.data.lastUsed = new Date().toISOString();
        p.byValue.set(key, token);
        await store.writeEncrypted(p.file, p.data, state.recipient);
        return token;
      });
    },

    async resolve(project, token, opts) {
      const m = TOKEN_RE.exec(String(token || ''));
      if (!m) throw znError(CODES.POLICY_DENIED, 'invalid token. Next step: use the placeholder exactly as zn gave it, in the form __ZN_NAME__.');
      const o = opts && typeof opts === 'object' ? opts : {};
      const inner = m[1];
      if (o.destination && DENIED_RESOLVE.has(o.destination)) {
        await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: 'policy:' + o.destination });
        throw znError(CODES.POLICY_DENIED, 'destination ' + o.destination + ' does not receive real values. Next step: send the request to a host this secret is allowed for, or use a placeholder instead.');
      }
      // The key `zn-gate connect` keeps here is not handed to hooks, the secrets broker or zn run, so writing its marker
      // in a file or a command never gets the real key back. A program running as the user can still ask for it.
      if (inner === CLOUD_KEY_SECRET && o.purpose !== CLOUD_KEY_PURPOSE) {
        await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: 'policy:zn_cloud_key' });
        if (o.withPolicy === true) return { value: null, policy: RESOLVE_POLICY_VERSION };
        throw znError(CODES.POLICY_DENIED, 'this secret is the key of zn-gate connect and is never put into a file or a command. Next step: ask the user to run zn-gate disconnect if it should stop working.');
      }
      let value = null;
      let org = null;
      const agentId = typeof o.agent === 'string' ? o.agent : null;
      const asLocal = (name, s) => ({ name, mode: s.mode, allowHosts: s.allowHosts || [], allowCommands: s.allowCommands || [], allowIn: s.allowIn || ['header'] });
      // names: the stored secrets the policy blocks (for a detected token, the
      // secrets with the same value): one local audit record each.
      const orgDenied = async (names) => {
        for (const name of names) await writeAudit({ secret: name, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: name === inner ? 'policy:org_deny' : 'policy:org_deny:' + inner.slice(0, 48) });
        if (o.withPolicy === true) return { value: null, policy: RESOLVE_POLICY_VERSION, deny: true };
        throw znError(CODES.POLICY_DENIED, 'secret ' + inner + ' is blocked by your organization policy. Next step: do not use this secret here. If the task needs it, review the organization policy, or, if you are an agent, ask the user.');
      };
      const ordinal = /_(\d+)$/.exec(inner);
      if (ordinal) {
        const p = await state.loadProject(String(project == null ? '' : project));
        value = Object.prototype.hasOwnProperty.call(p.data.tokens, token) ? p.data.tokens[token] : null;
        // A detected value that is also a stored secret: the organization
        // policy for that secret applies, so a blocked secret is not put back
        // through the scrubber's token for the same value.
        if (value !== null && o.destination) {
          const secrets = await state.loadSecrets();
          const same = Object.entries(secrets.secrets)
            .filter(([, s]) => s && typeof s.value === 'string' && s.value === value)
            .map(([name, s]) => asLocal(name, s));
          if (same.length) {
            const effs = await team.effectiveList(same, agentId, false);
            const blocked = effs.filter((e) => e && e.deny).map((e) => e.name);
            if (blocked.length) return orgDenied(blocked);
            // A warn rule for that secret: restored with the notice, as for a named marker.
            const warned = effs.find((e) => e && e.warn === true);
            if (warned) org = { warn: true, warnReason: warned.warnReason, warnName: warned.name };
          }
        }
      } else {
        const secrets = await state.loadSecrets();
        const s = secrets.secrets[inner];
        // A marker the agent hooks put back (they always give a destination):
        // the organization policy applies, as in zn run and the secrets MCP tools.
        if (s && o.destination) {
          const [eff] = await team.effectiveList([asLocal(inner, s)], agentId, false);
          if (eff && eff.deny) return orgDenied([inner]);
          if (eff && eff.warn === true) org = { warn: true, warnReason: eff.warnReason };
        }
        if (s) { value = s.value; s.lastUsed = new Date().toISOString(); state.dirtySecrets = true; }
      }
      await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: value === null ? 'deny' : 'allow', reason: value === null ? 'not_found' : (o.destination || 'unspecified') });
      // withPolicy: {value, policy, deny?, warn?, warnReason?, warnName?} instead of the bare value.
      return o.withPolicy === true ? Object.assign({ value, policy: RESOLVE_POLICY_VERSION }, value === null ? null : org) : value;
    },

    async setSecret(name, value, meta) {
      const n = checkName(name);
      str(value, 'value');
      return state.serial(async () => {
        const secrets = await state.loadSecrets();
        const prev = secrets.secrets[n];
        secrets.secrets[n] = Object.assign(cleanMeta(meta), { value, created: prev ? prev.created : new Date().toISOString(), lastUsed: prev ? prev.lastUsed : null });
        await writeAudit({ secret: n, mode: 'set', decision: 'allow', reason: prev ? 'updated' : 'created' });
        await state.saveSecrets();
        return true;
      });
    },

    /* Change a secret's policy without touching (or reading) its value. */
    /* A change that widens the policy (new hosts, commands, HTTP placements
     * or another mode) is confirmed by the user on the daemon's channel. */
    async updateSecretMeta(name, meta) {
      const n = str(name, 'name', 64);
      const proposed = (prev) => cleanMeta(Object.assign(
        { type: prev.type, mode: prev.mode, allowHosts: prev.allowHosts, allowCommands: prev.allowCommands, injectAt: prev.injectAt, allowIn: prev.allowIn, source: prev.source },
        meta && typeof meta === 'object' ? meta : {}));
      const before = (await state.loadSecrets()).secrets[n];
      if (!before) throw znError(CODES.NOT_FOUND, 'no secret named ' + n + '. Next step: check the name for a typo; if the secret is missing, save it with zn secret set ' + n + ' in your own terminal, or, if you are an agent, ask the user to do it.');
      const target = proposed(before);
      const adds = widening(before, target);
      if (adds.length) {
        const interp = (target.allowCommands || []).filter((c) => !(before.allowCommands || []).includes(c) && isInterpreter(c));
        await confirmOutOfBand({
          kind: 'policy',
          title: 'change the policy of secret ' + n + '?',
          warnings: interp.length ? ['Warning: ' + interp.join(', ') + ' runs any code it is given; every script it runs could read ' + n + '.'] : [],
          fields: [['Secret', n], ['Change', adds.join('; ')]],
          footer: 'If you did not just ask for this in your own terminal, choose Deny.',
        }, { secret: n, mode: 'set' });
      }
      return state.serial(async () => {
        const secrets = await state.loadSecrets();
        const prev = secrets.secrets[n];
        if (!prev) throw znError(CODES.NOT_FOUND, 'no secret named ' + n + '. Next step: check the name for a typo; if the secret is missing, save it with zn secret set ' + n + ' in your own terminal, or, if you are an agent, ask the user to do it.');
        const merged = proposed(prev);
        if (widening(prev, merged).some((x) => !adds.includes(x))) throw znError(CODES.POLICY_DENIED, 'the policy changed while waiting for confirmation; try again. Next step: run the request again.');
        secrets.secrets[n] = Object.assign(merged, { value: prev.value, created: prev.created, lastUsed: prev.lastUsed || null });
        writeAudit({ secret: n, mode: 'set', decision: 'allow', reason: adds.length ? 'policy_widened_confirmed' : 'policy_updated' });
        await state.saveSecrets();
        return true;
      });
    },

    /* First-use approvals of (project, secret, command), kept in the vault. */
    /* Approved only if the stored approval names the same real executable
     * the client resolved now (exePath), with the same file identity. When
     * the client also sends the fingerprint of the file it opened (openFp),
     * that must match too: the approval then covers the exact descriptor zn
     * run is about to start. A changed binary is refused. */
    async isApproved(project, secret, argv0, exePath, openFp) {
      const secrets = await state.loadSecrets();
      const rec = secrets.approvals && secrets.approvals[approvalKey(project, secret, argv0)];
      if (!rec || typeof rec !== 'object' || !rec.exe) return false;
      if (typeof exePath !== 'string' || rec.exe !== exePath) {
        writeAudit({ secret: String(secret), mode: 'env', argv0, decision: 'deny', reason: exePath ? 'exe_changed' : 'exe_not_found' });
        return false;
      }
      if (!rec.fp || rec.fp !== fingerprint(exePath) || (openFp != null && openFp !== rec.fp)) {
        writeAudit({ secret: String(secret), mode: 'env', argv0, decision: 'deny', reason: 'exe_modified' });
        return false;
      }
      return true;
    },

    /* Recording one is confirmed by the user on the daemon's channel, showing
     * the real executable that will receive the value. If the same pair was
     * approved before for another file (or the same file before it changed),
     * the dialog says so, with what changed. A program in a location the
     * current user can write gets a warning: anything running as the user,
     * the agent included, could swap it later. */
    async recordApproval(project, secret, argv0, exePath, openFp) {
      const key = approvalKey(project, secret, argv0);
      if (typeof exePath !== 'string' || !exePath || exePath.length > 4096 || !path.isAbsolute(exePath)) {
        throw znError(CODES.NOT_FOUND, 'command not found on PATH: ' + normArgv0(argv0) + '. Next step: check that the program is installed and on your PATH.');
      }
      const fp = fingerprint(exePath);
      if (!fp) throw znError(CODES.NOT_FOUND, 'command not found: ' + normArgv0(argv0) + '. Next step: check that the program is installed and on your PATH.');
      if (openFp != null && openFp !== fp) throw znError(CODES.POLICY_DENIED, 'the executable changed while it was being checked. Next step: run the command again; if it keeps changing, check where the program is installed.');
      const cmd = normArgv0(argv0);
      const loaded = await state.loadSecrets();
      if (!loaded.secrets[String(secret)]) throw znError(CODES.NOT_FOUND, 'no secret named ' + secret + '. Next step: check the name for a typo; if the secret is missing, save it with zn secret set ' + secret + ' in your own terminal, or, if you are an agent, ask the user to do it.');
      const prev = loaded.approvals && loaded.approvals[key];
      const changed = prev && typeof prev === 'object' && prev.exe && (prev.exe !== exePath || prev.fp !== fp);
      const writable = exe.writableBy(exePath);
      const warnings = [];
      const fields = [['Secret', secret + ' (the value goes into the process)'], ['Command', cmd], ['Runs', exePath], ['Project', String(project)]];
      if (changed) {
        warnings.push('WARNING: this program CHANGED since you approved it' + (prev.ts ? ' on ' + String(prev.ts).slice(0, 10) : '') +
          '. If you did not update or reinstall it yourself, choose Deny.');
        fields.push(['Approved', prev.exe + ' (' + fileFacts(prev.fp) + ')'], ['Now', exePath + ' (' + fileFacts(fp) + ')']);
      }
      if (isInterpreter(cmd) || isInterpreterPath(exePath)) warnings.push('Warning: ' + cmd + ' runs any code it is given; every script it runs could read ' + secret + '.');
      if (writable) {
        warnings.push('Warning: your user account can write to where this program lives, so another program (an agent too) could replace it later.');
        fields.push(['Writable by you', writable]);
      }
      await confirmOutOfBand({
        kind: 'approval',
        title: changed ? '`' + cmd + '` CHANGED since you approved it: let it use secret ' + secret + '?' : 'let `' + cmd + '` use secret ' + secret + '?',
        changed: !!changed,
        warnings,
        fields,
        footer: 'If you did not just start this command, choose Deny.',
      }, { secret: String(secret), mode: 'env', argv0: cmd });
      return state.serial(async () => {
        const secrets = await state.loadSecrets();
        if (fingerprint(exePath) !== fp) throw znError(CODES.POLICY_DENIED, 'the executable changed while waiting for confirmation. Next step: run the command again.');
        if (!secrets.approvals || typeof secrets.approvals !== 'object') secrets.approvals = {};
        secrets.approvals[key] = { ts: new Date().toISOString(), exe: exePath, fp };
        writeAudit({ secret: String(secret), mode: 'env', argv0, decision: 'ask:yes', reason: changed ? 'changed_exe_reapproved' : 'first_use_approved' });
        await state.saveSecrets();
        return true;
      });
    },

    /* secrets_render_file outside the safe case (a new file inside the
     * project): the user confirms on the daemon's channel. */
    async confirmFileWrite(project, file, names, reason) {
      if (typeof file !== 'string' || !file || file.length > 4096 || !path.isAbsolute(file)) throw znError(CODES.POLICY_DENIED, 'invalid file path. Next step: give the full path to the file, not a relative one.');
      const list = (Array.isArray(names) ? names : []).map(String).filter((n) => NAME_RE.test(n)).slice(0, 32);
      if (list.length === 0) throw znError(CODES.POLICY_DENIED, 'no secret names. Next step: list at least one secret name to put in the file.');
      const why = ['the file already exists and would be overwritten', 'the file is outside the project', 'the file is a credential file'].includes(reason) ? reason : 'not a new file inside the project';
      const secrets = await state.loadSecrets();
      for (const n of list) if (!secrets.secrets[n]) throw znError(CODES.NOT_FOUND, 'no secret named ' + n + '. Next step: check the name for a typo; if the secret is missing, save it with zn secret set ' + n + ' in your own terminal, or, if you are an agent, ask the user to do it.');
      await confirmOutOfBand({
        kind: 'file',
        title: 'write ' + list.join(', ') + ' to a file?',
        warnings: ['An agent asked zn to write secret values into a file: ' + why + '.'],
        fields: [['Secrets', list.join(', ')], ['File', file], ['Project', String(project)]],
        footer: 'If you did not ask the agent to create this file, choose Deny.',
      }, { secret: list[0], mode: 'file' });
      writeAudit({ secret: list[0], mode: 'file', decision: 'ask:yes', reason: 'file_write_confirmed' });
      return true;
    },

    /* opts.effective: apply the organization policy for opts.agent (what
     * the broker enforces). Without it, the local settings as stored. */
    async listSecrets(opts) {
      const secrets = await state.loadSecrets();
      const list = Object.entries(secrets.secrets).map(([name, s]) => ({
        name, type: s.type || 'SECRET', mode: s.mode, allowHosts: s.allowHosts || [], allowCommands: s.allowCommands || [],
        allowIn: s.allowIn || ['header'], injectAt: s.injectAt, source: s.source, lastUsed: s.lastUsed || null,
      })).sort((a, b) => a.name.localeCompare(b.name));
      const o = opts && typeof opts === 'object' ? opts : {};
      return o.effective ? team.effectiveList(list, typeof o.agent === 'string' ? o.agent : null, o.agentTrusted === true) : list;
    },

    teamJoin: team.teamJoin,
    teamLeave: team.teamLeave,
    teamInfo: team.teamInfo,
    teamSync: team.teamSync,
    confirmOrgOpening: team.confirmOrgOpening,

    async removeSecret(name) {
      const n = str(name, 'name', 64);
      return state.serial(async () => {
        const secrets = await state.loadSecrets();
        if (!Object.prototype.hasOwnProperty.call(secrets.secrets, n)) return false;
        delete secrets.secrets[n];
        await writeAudit({ secret: n, mode: 'remove', decision: 'allow' });
        await state.saveSecrets();
        return true;
      });
    },

    async exactValues(project) {
      const secrets = await state.loadSecrets();
      const out = [];
      for (const [name, s] of Object.entries(secrets.secrets)) {
        // Backups (whole files kept by `zn env shadow`) are not values to search for.
        if (s && s.mode !== 'backup' && typeof s.value === 'string' && s.value.length >= 8) out.push({ name, type: s.type || 'SECRET', values: variants(s.value) });
      }
      // Values already detected in this project (most recent first): once a
      // value was found, it is caught again even where no pattern matches.
      const p = await state.loadProject(String(project == null ? '' : project));
      const entries = Object.entries(p.data.tokens).slice(-MAX_DETECTED_EXACT).reverse();
      for (const [token, value] of entries) {
        if (typeof value !== 'string' || value.length < 8) continue;
        const m = TOKEN_RE.exec(token);
        out.push({ type: m[1].replace(/_\d+$/, ''), values: variants(value) });
      }
      return out;
    },

    async audit(event) {
      writeAudit(event && typeof event === 'object' ? event : {});
      return true;
    },

    async auditVerify() {
      const secrets = await state.loadSecrets();
      const res = audit.verify({ file: auditFile, key: Buffer.from(secrets.auditKey, 'hex') });
      // Truncation check: the encrypted vault remembers the last record.
      if (res.ok && secrets.auditHead && res.records < secrets.auditHead.seq) {
        return { ok: false, records: res.records, error: 'log truncated (vault expects ' + secrets.auditHead.seq + ' records)' };
      }
      return res;
    },

    async lock() {
      setImmediate(() => ctl.shutdown('lock'));
      return true;
    },
  };
}

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

/**
 * serve({identity, home, ttlMs, idleMs, onExit}) -> Promise<{address, close()}>
 * Runs the daemon in the current process (used by the detached daemon and
 * by tests).
 */
async function serve(opts) {
  const o = opts || {};
  const meta = keychain.readMeta(o);
  if (!meta) throw znError(CODES.NOT_FOUND, 'vault not initialised. Next step: run zn unlock once in your own terminal to create the vault, or, if you are an agent, ask the user to do it.');
  const recipient = await store.recipientOf(o.identity);
  if (recipient !== meta.recipient) throw znError(CODES.LOCKED, 'identity does not match this vault');
  store.ensureLayout(o);
  const ep = endpoint(o);

  if (await isRunning(o)) throw znError(CODES.POLICY_DENIED, 'vault already unlocked. Next step: nothing to do. To unlock again, run zn lock in your own terminal first, or, if you are an agent, ask the user to do it.');
  if (ep.unix) { try { fs.unlinkSync(ep.address); } catch (err) { /* stale socket */ } }

  const state = new VaultState(o.identity, recipient, o);
  await state.loadSecrets();
  store.pruneStale(o);

  const sessionKey = crypto.randomBytes(32);
  const ttlMs = o.ttlMs || DEFAULT_TTL_MS;
  const idleMs = o.idleMs || DEFAULT_IDLE_MS;
  // Confirmation channel: injected (tests), chosen by the caller, or none.
  const channel = typeof o.confirm === 'function' ? { kind: 'injected', confirm: o.confirm }
    : (o.channel && typeof o.channel.confirm === 'function' ? o.channel : confirmMod.noneChannel());
  const ctl = { expiresAt: Date.now() + ttlMs, idleMs, shutdown: null, channel, fetchImpl: o.fetchImpl };
  const ops = makeOps(state, ctl);
  const sockets = new Set();
  let closed = false;
  let idleTimer = null;

  const server = net.createServer((socket) => handleConnection(socket));

  function bumpIdle() {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => shutdown('idle'), idleMs);
    idleTimer.unref();
  }
  const ttlTimer = setTimeout(() => shutdown('expired'), ttlMs);
  ttlTimer.unref();
  // Persist lastUsed and the audit head now and then.
  const flushTimer = setInterval(() => { if (state.dirtySecrets) state.serial(() => state.saveSecrets()).catch(() => {}); }, 60000);
  flushTimer.unref();
  // zn Team: refresh the organization policy and upload the audit log while
  // unlocked (soon after unlock, then every teamSyncMs). No-op outside a team.
  const teamSyncMs = o.teamSyncMs === 0 ? 0 : (o.teamSyncMs || DEFAULT_TEAM_SYNC_MS);
  const teamSync = () => { if (!closed && state.secrets && state.secrets.team) ops.teamSync({}).catch(() => {}); };
  const teamTimer = teamSyncMs ? setInterval(teamSync, teamSyncMs) : null;
  const teamFirst = teamSyncMs ? setTimeout(teamSync, 5000) : null;
  if (teamTimer) teamTimer.unref();
  if (teamFirst) teamFirst.unref();

  async function shutdown(reason) {
    if (closed) return;
    closed = true;
    ctl.closed = true;
    clearTimeout(ttlTimer);
    clearInterval(flushTimer);
    if (teamTimer) clearInterval(teamTimer);
    if (teamFirst) clearTimeout(teamFirst);
    if (idleTimer) clearTimeout(idleTimer);
    try {
      await state.serial(async () => {
        if (state.secrets) {
          const secrets = state.secrets;
          const rec = audit.append({ mode: reason === 'lock' ? 'lock' : 'expire', decision: 'allow', reason },
            { file: state.paths.auditFile, key: Buffer.from(secrets.auditKey, 'hex') });
          secrets.auditHead = { seq: rec.seq, mac: rec.mac };
          await state.saveSecrets();
        }
      });
    } catch (err) { /* best effort */ }
    state.drop();
    sessionKey.fill(0);
    for (const s of sockets) s.destroy();
    try { fs.unlinkSync(ep.keyFile); } catch (err) { /* ignore */ }
    await new Promise((resolve) => server.close(() => resolve()));
    if (ep.unix) { try { fs.unlinkSync(ep.address); } catch (err) { /* ignore */ } }
    if (typeof o.onExit === 'function') o.onExit(reason);
  }
  ctl.shutdown = shutdown;

  function handleConnection(socket) {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.setEncoding('utf8');
    let buf = '';
    let stage = 'hello';
    let serverNonce = null;
    let clientNonce = null;
    let chain = Promise.resolve();
    const send = (obj) => { if (!socket.destroyed) socket.write(JSON.stringify(obj) + '\n'); };

    socket.on('data', (chunk) => {
      buf += chunk;
      if (buf.length > MAX_LINE) { socket.destroy(); return; }
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        let msg;
        try { msg = JSON.parse(line); } catch (err) { socket.destroy(); return; }
        if (stage === 'hello') {
          if (!msg || msg.op !== 'hello' || msg.v !== PROTOCOL || !/^[0-9a-f]{32}$/.test(msg.nonce || '')) { socket.destroy(); return; }
          clientNonce = msg.nonce;
          serverNonce = crypto.randomBytes(16).toString('hex');
          send({ ok: true, v: PROTOCOL, nonce: serverNonce, proof: hmac(sessionKey, 'zn-server', clientNonce, serverNonce) });
          stage = 'auth';
          continue;
        }
        if (stage === 'auth') {
          if (!msg || msg.op !== 'auth' || !safeEqualHex(msg.proof, hmac(sessionKey, 'zn-client', serverNonce, clientNonce))) {
            send({ ok: false, error: { code: CODES.POLICY_DENIED, message: 'authentication failed' } });
            socket.destroy();
            return;
          }
          stage = 'ready';
          send({ ok: true });
          continue;
        }
        const id = msg && msg.id;
        chain = chain.then(async () => {
          if (closed) { send({ id, ok: false, error: { code: CODES.LOCKED, message: 'vault locked' } }); return; }
          bumpIdle();
          const op = msg && typeof msg.op === 'string' && Object.prototype.hasOwnProperty.call(ops, msg.op) ? ops[msg.op] : null;
          if (!op) { send({ id, ok: false, error: { code: CODES.POLICY_DENIED, message: 'unknown operation' } }); return; }
          try {
            const result = await op(...(Array.isArray(msg.args) ? msg.args : []));
            send({ id, ok: true, result });
          } catch (err) {
            const code = err && typeof err.code === 'string' && err.code.startsWith('ZN_') ? err.code : 'ZN_ERROR';
            // Never echo arbitrary error text: it could carry a value.
            const message = err && err.code && err.code.startsWith('ZN_') ? String(err.message).slice(0, 200) : 'internal error';
            send({ id, ok: false, error: { code, message } });
          }
        });
      }
    });
  }

  // Unix: bind with a restrictive umask so the socket is never world-accessible.
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    const oldMask = ep.unix ? process.umask(0o177) : null;
    server.listen(ep.address, () => {
      if (oldMask !== null) process.umask(oldMask);
      server.removeListener('error', reject);
      resolve();
    });
  }).catch((err) => {
    if (err && err.code === 'EADDRINUSE') throw znError(CODES.POLICY_DENIED, 'vault already unlocked. Next step: nothing to do. To unlock again, run zn lock in your own terminal first, or, if you are an agent, ask the user to do it.');
    throw err;
  });
  if (ep.unix) fs.chmodSync(ep.address, 0o600);
  store.writePrivateFile(ep.keyFile, sessionKey.toString('hex'));
  bumpIdle();
  await state.serial(async () => {
    const rec = audit.append({ mode: 'unlock', decision: 'allow', reason: 'ttl:' + Math.round(ttlMs / 60000) + 'm' },
      { file: state.paths.auditFile, key: Buffer.from(state.secrets.auditKey, 'hex') });
    state.secrets.auditHead = { seq: rec.seq, mac: rec.mac };
    await state.saveSecrets();
  });

  return { address: ep.address, close: () => shutdown('lock'), expiresAt: ctl.expiresAt };
}

/* ------------------------------------------------------------------ */
/* Process management (CLI side)                                       */
/* ------------------------------------------------------------------ */

async function isRunning(opts) {
  const client = createClient(opts);
  try {
    await client.call('status', []);
    return true;
  } catch (err) {
    return false;
  } finally {
    client.close();
  }
}

/**
 * unlock({passphrase, backend, ttlMs, idleMs, home, init}) -> {pid, expiresAt, created}
 * Loads (or, with init, creates) the identity and starts the detached daemon.
 */
async function unlock(opts) {
  const o = opts || {};
  if (await isRunning(o)) throw znError(CODES.POLICY_DENIED, 'vault already unlocked. Next step: nothing to do. To unlock again, run zn lock in your own terminal first, or, if you are an agent, ask the user to do it.');
  let created = false;
  let identity;
  if (!keychain.readMeta(o)) {
    if (o.init === false) throw znError(CODES.NOT_FOUND, 'vault not initialised. Next step: run zn unlock once in your own terminal to create the vault, or, if you are an agent, ask the user to do it.');
    identity = (await keychain.initIdentity(o)).identity;
    created = true;
  } else {
    identity = await keychain.loadIdentity(o);
  }
  const args = [__filename, '--serve'];
  if (o.ttlMs) args.push('--ttl-ms', String(o.ttlMs));
  if (o.idleMs) args.push('--idle-ms', String(o.idleMs));
  const env = Object.assign({}, process.env);
  if (o.home) env.ZN_HOME = path.resolve(o.home);
  const child = spawn(process.execPath, args, {
    detached: true,
    stdio: ['pipe', 'ignore', 'ignore', 'ipc'],
    windowsHide: true,
    env,
  });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(znError(CODES.LOCKED, 'daemon did not start in time')), 20000);
    child.once('message', (m) => {
      clearTimeout(timer);
      if (m && m.ready) resolve(m);
      else reject(znError((m && m.code) || CODES.LOCKED, (m && m.message) || 'daemon failed to start'));
    });
    child.once('exit', (code) => { clearTimeout(timer); reject(znError(CODES.LOCKED, 'daemon exited during start (' + code + ')')); });
  });
  child.stdin.end(JSON.stringify({ identity }) + '\n');
  identity = null;
  const info = await ready;
  child.removeAllListeners('exit');
  if (child.connected) child.disconnect();
  child.unref();
  return { pid: child.pid, expiresAt: info.expiresAt, created, confirm: info.confirm || 'none' };
}

/**
 * unlockForeground({passphrase, backend, ttlMs, idleMs, home, input, output, init})
 * Runs the daemon in this process, attached to the user's terminal: it asks
 * there before a secret is used for the first time or a policy widens.
 * Resolves with {expiresAt, created, done} where done resolves on exit.
 */
async function unlockForeground(opts) {
  const o = opts || {};
  if (await isRunning(o)) throw znError(CODES.POLICY_DENIED, 'vault already unlocked. Next step: nothing to do. To unlock again, run zn lock in your own terminal first, or, if you are an agent, ask the user to do it.');
  let created = false;
  let identity;
  if (!keychain.readMeta(o)) {
    if (o.init === false) throw znError(CODES.NOT_FOUND, 'vault not initialised. Next step: run zn unlock once in your own terminal to create the vault, or, if you are an agent, ask the user to do it.');
    identity = (await keychain.initIdentity(o)).identity;
    created = true;
  } else {
    identity = await keychain.loadIdentity(o);
  }
  const channel = confirmMod.ttyChannel({ input: o.input || process.stdin, output: o.output || process.stderr });
  let finish;
  const done = new Promise((resolve) => { finish = resolve; });
  const srv = await serve({ identity, home: o.home, ttlMs: o.ttlMs, idleMs: o.idleMs, channel, onExit: (reason) => finish(reason) });
  identity = null;
  return { expiresAt: new Date(srv.expiresAt).toISOString(), created, close: srv.close, done };
}

/** lock({home}) -> true if a daemon was running. */
async function lock(opts) {
  const client = createClient(opts);
  try {
    await client.call('lock', []);
    return true;
  } catch (err) {
    if (err && err.code === CODES.LOCKED) return false;
    throw err;
  } finally {
    client.close();
  }
}

/* Detached daemon entry point: identity arrives on stdin. */
async function daemonMain(argv) {
  const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? Number(argv[i + 1]) : undefined; };
  let input = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) input += chunk;
  let identity;
  try { identity = JSON.parse(input).identity; } catch (err) { identity = null; }
  input = '';
  try {
    // Detached: no terminal of its own, so confirmations use a native dialog
    // when the platform has one, otherwise they are refused.
    const channel = confirmMod.chooseChannel({ foreground: false });
    const srv = await serve({ identity, ttlMs: opt('--ttl-ms'), idleMs: opt('--idle-ms'), channel, onExit: () => process.exit(0) });
    identity = null;
    if (process.send) process.send({ ready: true, expiresAt: new Date(srv.expiresAt).toISOString(), confirm: channel.kind });
    if (process.connected) process.disconnect();
  } catch (err) {
    if (process.send) process.send({ ready: false, code: err.code || 'ZN_ERROR', message: String(err.message || err).slice(0, 200) });
    process.exit(1);
  }
}

if (require.main === module && process.argv.includes('--serve')) {
  daemonMain(process.argv.slice(2));
}

module.exports = { serve, unlock, unlockForeground, lock, isRunning, endpoint, DEFAULT_TTL_MS, DEFAULT_IDLE_MS, PROTOCOL };
