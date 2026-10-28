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
 * - Policy is enforced here as well as in the engine. `resolve` needs a
 *   context (a restoration destination from the hooks, or a purpose of the
 *   broker: zn run, an HTTP request, a rendered file) that the caller names
 *   and the daemon checks against what it holds. Masking runs inside the
 *   daemon (maskInfo, maskSpans): the scrubber gets positions and secret
 *   names, never values. The other readers are concrete operations
 *   (adoptToken, sameSecretValue, readBackup). Every resolve is audited.
 *
 * Limits (documented in the threat model): any process of the same OS user
 * that can read ~/.zn/run/session.key can talk to the daemon, exactly like
 * ssh-agent, and can name any context. The checks above bind what a request
 * must say (a host the secret allows, a command and an executable the user
 * approved, a mode), not who is asking. Agent hooks deny agent tool calls that
 * touch ~/.zn; the OS user boundary is the real isolation. JS strings cannot
 * be wiped from memory; state is dropped and left to the garbage collector.
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
const winacl = require('./winacl');
const audit = require('./audit');
const confirmMod = require('./confirm');
const { variants, buildMatcher, MIN_LENGTH: MIN_NEEDLE, validateSecretValue } = require('../scrub/exact');
const exe = require('../exe');
const { makeTeamOps } = require('../team/daemon-ops');
const { CODES, znError } = require('../errors');
const messages = require('../messages');

const PROTOCOL = 1;
const DEFAULT_TTL_MS = 8 * 3600 * 1000;
const DEFAULT_IDLE_MS = 30 * 60 * 1000;
const DEFAULT_TEAM_SYNC_MS = 15 * 60 * 1000;
const MAX_LINE = 64 * 1024 * 1024;
const MAX_VALUE = 1024 * 1024;
const MAX_DETECTED_EXACT = 256;
const TYPE_RE = /^[A-Z0-9](?:[A-Z0-9_]{0,62}[A-Z0-9])?$/;
const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const TOKEN_RE = /^__ZN_([A-Z0-9](?:[A-Z0-9_]*[A-Z0-9])?)__$/;
const HOST_RE = /^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*(?::\d{1,5})?$/;
const COMMAND_RE = /^[A-Za-z0-9_.+\-/ *]{1,128}$/;
const CLOUD_KEY_SECRET = 'ZN_CLOUD_API_KEY';
const CLOUD_KEY_PURPOSE = 'zn-cloud-key';
/* Restoration policy by destination (the hooks' contexts). It is the engine's
 * POLICY table with one difference (a test checks both): the engine lets an
 * in-process caller restore into the assistant's own text, but no hook does,
 * and a value put in front of the model defeats the vault, so the daemon,
 * which holds the real values, never hands one out for `assistant`.
 * `detected` is a scrubber token (__ZN_EMAIL_1__), `named` a stored secret
 * (__ZN_NAME__); only 'restore' hands a value out. */
const DESTINATION_POLICY = Object.freeze({
  assistant:     Object.freeze({ detected: 'not_restored', named: 'not_restored' }),
  write_ignored: Object.freeze({ detected: 'restore', named: 'restore' }),
  write_tracked: Object.freeze({ detected: 'tracked_file', named: 'tracked_file' }),
  bash_local:    Object.freeze({ detected: 'restore', named: 'use_broker' }),
  bash_network:  Object.freeze({ detected: 'network', named: 'network' }),
  mcp_input:     Object.freeze({ detected: 'mcp_input', named: 'mcp_input' }),
});
/* Purposes of the broker. Each one has its own checks in resolveFor():
 *   run     zn run: an env-mode secret, a command its allowCommands list names, an executable the user approved
 *   http    secrets_http_request: a host and placements the secret allows
 *   render  secrets_render_file: a file-mode secret
 * and the key of `zn-gate connect`, which only zn-gate's own cloud calls read. */
const BROKER_PURPOSES = Object.freeze(['run', 'http', 'render']);
const MASK_MAX_TEXTS = 4096;
const MASK_MAX_CHARS = 16 * 1024 * 1024;
const MASK_AUDIT_EVERY_MS = 60 * 1000;
const SAME_VALUE_PER_MINUTE = 120;
const BACKUP_REFUSED = 'this is a backup of a .env file: only zn env unshadow can read it, after you confirm. Next step: run zn env unshadow in your own terminal.';
const PROXY_NOT_RESTORED = 'this secret is in proxy mode, so it is never written into a file or a command. Next step: use the secrets_http_request tool, or ask the user to change its mode in their own terminal (zn secret allow).';
const BACKUP_NAME_RE = /^ENVBAK_X[0-9A-F]{8}D\d{12}$/;
/* What this vault does beyond the protocol. resolve-policy: resolve() with
 * {withPolicy: true} applies the organization policy and answers
 * {value, policy: RESOLVE_POLICY_VERSION, deny?, warn?, warnReason?}.
 * capabilities: resolve needs a context, masking runs in the daemon (maskInfo and maskSpans),
 * and adoptToken, sameSecretValue and readBackup exist. */
const RESOLVE_POLICY_VERSION = 1;
const PACKAGE_VERSION = require('../../package.json').version;
const VAULT_FEATURES = Object.freeze(['resolve-policy', 'capabilities']);
const ALLOW_IN = ['header', 'query', 'body'];
// Commands that run arbitrary code given to them (python3.12, node22, pwsh...):
// approving one lets any script it runs read the secret. The confirmation
// says so. One list for the daemon and the CLI, in lib/exe.js.
const { isInterpreter, isInterpreterPath } = exe;

const markers = require('../broker/markers');
const { AGENT_IDS } = require('../agents');
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

/* Each time a secret's value is set or replaced it gets a new random
 * generation id. An approval records the generation it was granted for and
 * counts only for that one, so a new value stored under the same name never
 * inherits an old approval. */
function newGeneration() {
  return crypto.randomBytes(16).toString('hex');
}

/* Approval keys are <project>:<secret>:<command>; none of the parts holds a colon. */
function dropApprovalsOf(secrets, name) {
  if (!secrets.approvals || typeof secrets.approvals !== 'object') return;
  for (const key of Object.keys(secrets.approvals)) {
    if (key.split(':')[1] === name) delete secrets.approvals[key];
  }
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

/* Tamper mark. The audit log is checked against the checkpoint the vault
 * keeps in secrets.age. If the log was changed behind the daemon's back
 * (truncated, replaced), the checkpoint is NOT moved to the new tail: the old
 * one stays, and this mark is stored in the vault. `zn vault verify` fails
 * until the user accepts the log with `zn vault verify --acknowledge`. */
function recordTamper(state, reason, found) {
  const secrets = state.secrets;
  if (!secrets || secrets.auditTamper) return;
  const head = secrets.auditHead;
  secrets.auditTamper = {
    at: new Date().toISOString(),
    reason: String(reason).slice(0, 300),
    expected: head ? { seq: head.seq, mac: head.mac } : null,
    found: found || null,
  };
  state.dirtySecrets = true;
  state.serial(() => state.saveSecrets()).catch(() => {});
}

/* Chain check of the whole log (every MAC, the links, the sequence numbers and
 * the vault's checkpoint). A failure leaves the persistent tamper mark. The
 * result is remembered while the file is unchanged (size, mtime, ctime, inode)
 * and the checkpoint is the same; any append by the daemon drops it, so the
 * next check reads the whole log again. */
function logSignature(file) {
  try {
    const st = fs.statSync(file);
    return [st.size, st.mtimeMs, st.ctimeMs, st.ino].join(':');
  } catch (err) { return 'none'; }
}

function headKey(secrets) {
  return secrets.auditHead ? secrets.auditHead.seq + ':' + secrets.auditHead.mac : '';
}

function chainStatus(state, opts) {
  const secrets = state.secrets;
  if (!secrets) throw znError(CODES.LOCKED, 'vault locked');
  const file = state.paths.auditFile;
  const t = secrets.auditTamper;
  if (t) {
    return {
      ok: false,
      tampered: true,
      records: 0,
      reason: t.reason,
      error: 'the audit log was changed behind the vault (noticed ' + t.at + '): ' + t.reason,
    };
  }
  const sig = logSignature(file);
  const c = state.chainCache;
  if (!(opts && opts.force) && c && c.sig === sig && c.head === headKey(secrets)) return c.result;
  state.chainCache = null;
  let r;
  try {
    r = audit.verify({ file, key: Buffer.from(secrets.auditKey, 'hex'), checkpoint: secrets.auditHead });
  } catch (err) {
    r = { ok: false, records: 0, error: 'the audit log cannot be read' };
  }
  if (!r.ok) {
    recordTamper(state, r.error + (r.line ? ' (record ' + r.line + ')' : ''), null);
    return Object.assign({}, r, {
      tampered: true,
      reason: secrets.auditTamper.reason,
      error: 'the audit log was changed behind the vault (noticed ' + secrets.auditTamper.at + '): ' + secrets.auditTamper.reason,
    });
  }
  state.chainCache = { sig, head: headKey(secrets), result: r };
  return r;
}

/* Every audit write goes through here: the in-memory head must be the last
 * record in the file before the daemon appends, and the whole chain must
 * verify (a change in the middle of the log is not seen by the head alone);
 * if not, the checkpoint stays and the tamper mark is stored. */
function appendChecked(state, event, extra) {
  const secrets = state.secrets;
  if (!secrets) throw znError(CODES.LOCKED, 'vault locked');
  const file = state.paths.auditFile;
  if (!secrets.auditTamper) {
    const h = audit.checkHead(file, secrets.auditHead);
    if (!h.ok) recordTamper(state, h.reason, h.found);
    else {
      chainStatus(state);
    }
  }
  if (state.opts && typeof state.opts._afterChainCheck === 'function') state.opts._afterChainCheck(); // test seam
  state.dirtySecrets = true;
  const rec = audit.append(event, Object.assign({ file, key: Buffer.from(secrets.auditKey, 'hex') }, extra));
  if (!secrets.auditTamper) secrets.auditHead = { seq: rec.seq, mac: rec.mac };
  // Never vouch for the file from a stat taken after our own write: a change made as the file grew
  // would be folded in. The next read, export or upload checks the whole chain again.
  state.chainCache = null;
  return rec;
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
    return appendChecked(state, event, { knownValues: state.knownValues() });
  }

  const team = makeTeamOps({ state, writeAudit, verifyChain: () => chainStatus(state), confirmOutOfBand, fetchImpl: ctl.fetchImpl, isClosed: () => Boolean(ctl.closed) });

  const localOf = (name, s) => ({ name, mode: s.mode, allowHosts: s.allowHosts || [], allowCommands: s.allowCommands || [], allowIn: s.allowIn || ['header'] });
  // When the masking path last called the vault, for each (agent, tool): one audit record a minute, not one per hook.
  const maskAudited = new Map();
  const sameWindow = { start: 0, count: 0 };
  function noteMask(claim) {
    const o = claim && typeof claim === 'object' ? claim : {};
    const who = String(o.agent) + '\0' + String(o.tool);
    const now = Date.now();
    if (maskAudited.has(who) && now - maskAudited.get(who) < MASK_AUDIT_EVERY_MS) return;
    if (maskAudited.size > 256) maskAudited.clear();
    maskAudited.set(who, now);
    writeAudit({ mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'allow', reason: 'mask_text' });
  }

  /* The matcher over every value the masker looks for in one project: the stored secrets (backups are whole files, not
   * values) and the values the scrubber already detected here (most recent first, so a value found once is caught
   * again where no pattern matches). Rebuilt when a secret or a detected value changes. */
  const maskCache = new Map();
  async function maskStateOf(project) {
    const secrets = await state.loadSecrets();
    const p = await state.loadProject(String(project == null ? '' : project));
    const h = crypto.createHash('sha256');
    const live = [];
    for (const [name, s] of Object.entries(secrets.secrets)) {
      // A value under the minimum comes from an older version (new ones are refused): it is compared exactly.
      if (s && s.mode !== 'backup' && typeof s.value === 'string' && s.value.length > 0) {
        live.push([name, s]);
        h.update(name + '\0' + s.value + '\0');
      }
    }
    h.update('tokens:' + p.byValue.size);
    const sig = h.digest('hex');
    const hit = maskCache.get(p.key);
    if (hit && hit.sig === sig) return hit;
    const entries = live.map(([name, s]) => (s.value.length >= MIN_NEEDLE
      ? { name, type: s.type || 'SECRET', values: variants(s.value), vault: true }
      : { name, type: s.type || 'SECRET', values: [s.value], exactShort: true, vault: true }));
    for (const [token, value] of Object.entries(p.data.tokens).slice(-MAX_DETECTED_EXACT).reverse()) {
      if (typeof value !== 'string' || value.length < MIN_NEEDLE) continue;
      const m = TOKEN_RE.exec(token);
      entries.push({ type: m[1].replace(/_\d+$/, ''), values: variants(value), vault: true });
    }
    let longest = 0;
    for (const e of entries) for (const v of e.values) if (v.length > longest) longest = v.length;
    const matcher = buildMatcher(entries);
    const built = { sig, matcher, names: entries.filter((e) => e.name).map((e) => e.name), longest, shortCount: matcher.shortSize, minNeedle: MIN_NEEDLE };
    if (maskCache.size > 64) maskCache.clear();
    maskCache.set(p.key, built);
    return built;
  }

  /* resolve for a purpose of the broker. The checks the broker makes before it asks are made again here, on what the
   * vault itself holds, so a request that skips the broker meets the same limits: the secret's mode, the organization
   * policy, and the settings and approvals the user gave. They do not tell who is asking: a program of the same user
   * can name a host, a command and an executable that fit. */
  async function resolveFor(project, inner, purpose, o) {
    const refuse = async (reason, message) => {
      await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason });
      throw znError(CODES.POLICY_DENIED, message);
    };
    // A backup is the whole .env that zn env shadow set aside: only readBackup, which the user confirms, gives it out.
    if (BACKUP_NAME_RE.test(inner)) return refuse('policy:backup', BACKUP_REFUSED);
    if (/_\d+$/.test(inner)) {
      return refuse('policy:' + purpose + ':detected', 'this request is for a stored secret, not for a value the scrubber found. Next step: store the value with zn secret adopt first.');
    }
    const secrets = await state.loadSecrets();
    const s = secrets.secrets[inner];
    if (!s) {
      await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: 'not_found' });
      return null;
    }
    if (s.mode === 'backup') return refuse('policy:backup', BACKUP_REFUSED);
    // An agent id the client names decides nothing about a secret. The one thing it can change is which hosts the
    // organization policy offers to an agent zn can identify, and those only apply once the user approved them here.
    const agentId = typeof o.agent === 'string' && AGENT_IDS.includes(o.agent) ? o.agent : null;
    const trusted = purpose === 'http' && o.agentTrusted === true && agentId !== null;
    const [eff] = await team.effectiveList([localOf(inner, s)], agentId, trusted);
    if (eff && eff.deny) {
      return refuse('policy:org_deny', 'secret ' + inner + ' is blocked by your organization policy. Next step: do not use this secret here. If the task needs it, review the organization policy, or, if you are an agent, ask the user.');
    }
    const meta = eff || localOf(inner, s);
    if (purpose === 'run') {
      if (meta.mode !== 'env') {
        return refuse('policy:run:mode', 'secret ' + inner + ' is in ' + (meta.mode || 'proxy') + ' mode, so it is never put into a process. Next step: use the secrets_http_request tool for HTTP APIs.');
      }
      const argv = Array.isArray(o.argv) && o.argv.length > 0 && o.argv.length <= 1024 && o.argv.every((a) => typeof a === 'string' && a.length <= 32768) ? o.argv : null;
      const entry = argv ? markers.matchAllowCommands(meta.allowCommands, argv) : null;
      if (!entry) return refuse('policy:run:command', 'this command is not allowed to use ' + inner + '. Next step: the user can allow it from their own terminal with zn secret allow.');
      const real = o.exe && typeof o.exe === 'object' ? o.exe.real : null;
      const fp = o.exe && typeof o.exe === 'object' ? o.exe.fp : null;
      if (typeof real !== 'string' || !real || real.length > 4096 || !path.isAbsolute(real) || typeof fp !== 'string' || !fp) {
        return refuse('policy:run:exe', 'zn run did not name the program it opened. Next step: run the command through zn run.');
      }
      const approved = await ops.isApproved(project, inner, exe.commandWord(entry).split(/[\\/]/).pop(), exe.approvalPath(real), fp);
      if (!approved) return refuse('policy:run:not_approved', 'this program is not approved for ' + inner + ' yet. Next step: run it through zn run and confirm it in the zn vault prompt.');
    } else if (purpose === 'render') {
      if (meta.mode !== 'file') return refuse('policy:render:mode', 'secret ' + inner + ' is in ' + (meta.mode || 'proxy') + ' mode; only file-mode secrets are written to disk.');
    } else {
      // Only a secret the user made available to HTTP requests (proxy mode, the default) leaves through this purpose,
      // whatever its allowHosts say: an env or file secret is meant for a local program, not for the network.
      if ((meta.mode || 'proxy') !== 'proxy') {
        return refuse('policy:http:mode', 'secret ' + inner + ' is in ' + meta.mode + ' mode, so it is never sent over HTTP. Next step: do not use this secret here. If the API really needs it, the user can change its mode in their own terminal with zn secret allow ' + inner + ' --mode proxy.');
      }
      const host = typeof o.host === 'string' ? o.host : '';
      if (!markers.hostAllowed(meta.allowHosts, host)) {
        return refuse('policy:http:host', 'secret ' + inner + ' may not be sent to ' + (host || 'an unnamed host') + '. Next step: the user can allow the host with zn secret allow.');
      }
      const allowIn = Array.isArray(meta.allowIn) ? meta.allowIn : ['header'];
      const where = Array.isArray(o.placements) && o.placements.every((p) => ALLOW_IN.includes(p)) ? o.placements : null;
      if (where === null || where.some((p) => !allowIn.includes(p))) {
        return refuse('policy:http:placement', 'secret ' + inner + ' may only be sent where its settings allow (' + allowIn.join(', ') + '). Next step: the user can widen it with zn secret allow --in.');
      }
    }
    s.lastUsed = new Date().toISOString();
    state.dirtySecrets = true;
    await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'allow', reason: purpose });
    return s.value;
  }

  const ops = {
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
      const ordinal = /_(\d+)$/.exec(inner);
      // What the request says it is for. A purpose wins over a destination; neither is proven by the caller, which is
      // why each one is checked here against what the vault itself holds.
      const purpose = typeof o.purpose === 'string' ? o.purpose : null;
      const dest = !purpose && typeof o.destination === 'string' && Object.prototype.hasOwnProperty.call(DESTINATION_POLICY, o.destination) ? o.destination : null;
      const refuse = async (reason, message) => {
        await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason });
        throw znError(CODES.POLICY_DENIED, message);
      };
      // A backup is the whole .env that zn env shadow set aside: for every destination and purpose, only readBackup
      // (which the user confirms on the vault's own channel) gives it out.
      if (BACKUP_NAME_RE.test(inner)) return refuse('policy:backup', BACKUP_REFUSED);
      if (dest && DESTINATION_POLICY[dest][ordinal ? 'detected' : 'named'] !== 'restore') {
        await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: 'policy:' + dest });
        throw znError(CODES.POLICY_DENIED, 'destination ' + dest + ' does not receive real values. Next step: send the request to a host this secret is allowed for, or use a placeholder instead.');
      }
      // The key `zn-gate connect` keeps here is not handed to hooks, the secrets broker or zn run, so writing its marker
      // in a file or a command never gets the real key back. A program running as the user can still ask for it.
      if (inner === CLOUD_KEY_SECRET && purpose !== CLOUD_KEY_PURPOSE) {
        await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: 'policy:zn_cloud_key' });
        if (o.withPolicy === true) return { value: null, policy: RESOLVE_POLICY_VERSION };
        throw znError(CODES.POLICY_DENIED, 'this secret is the key of zn-gate connect and is never put into a file or a command. Next step: ask the user to run zn-gate disconnect if it should stop working.');
      }
      // There is no context-free resolve: a request that names no destination and no purpose, or one this vault does not
      // know, gets nothing (and the attempt is on the audit log).
      if (purpose ? (purpose !== CLOUD_KEY_PURPOSE && !BROKER_PURPOSES.includes(purpose)) || (purpose === CLOUD_KEY_PURPOSE && inner !== CLOUD_KEY_SECRET) : !dest) {
        await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: 'policy:no_context' });
        throw znError(CODES.POLICY_DENIED, 'this request does not say what the value is for. Next step: restore placeholders through the zn hooks, or use zn run or the secrets MCP tools; a program cannot read values directly.');
      }
      if (BROKER_PURPOSES.includes(purpose)) return resolveFor(project, inner, purpose, o);
      let value = null;
      let org = null;
      const agentId = typeof o.agent === 'string' ? o.agent : null;
      const asLocal = localOf;
      // names: the stored secrets the policy blocks (for a detected token, the
      // secrets with the same value): one local audit record each.
      const orgDenied = async (names) => {
        for (const name of names) await writeAudit({ secret: name, mode: 'resolve', agent: o.agent, tool: o.tool, decision: 'deny', reason: name === inner ? 'policy:org_deny' : 'policy:org_deny:' + inner.slice(0, 48) });
        if (o.withPolicy === true) return { value: null, policy: RESOLVE_POLICY_VERSION, deny: true };
        throw znError(CODES.POLICY_DENIED, 'secret ' + inner + ' is blocked by your organization policy. Next step: do not use this secret here. If the task needs it, review the organization policy, or, if you are an agent, ask the user.');
      };
      if (ordinal) {
        const p = await state.loadProject(String(project == null ? '' : project));
        value = Object.prototype.hasOwnProperty.call(p.data.tokens, token) ? p.data.tokens[token] : null;
        // A detected value that is also a stored secret: the organization
        // policy for that secret applies, so a blocked secret is not put back
        // through the scrubber's token for the same value.
        if (value !== null && dest) {
          const secrets = await state.loadSecrets();
          const same = Object.entries(secrets.secrets)
            .filter(([, s]) => s && typeof s.value === 'string' && s.value === value)
            .map(([name, s]) => asLocal(name, s));
          if (same.length) {
            const effs = await team.effectiveList(same, agentId, false);
            const blocked = effs.filter((e) => e && e.deny).map((e) => e.name);
            if (blocked.length) return orgDenied(blocked);
            const odd = effs.find((e) => e && (e.mode === 'backup' || (e.mode === 'proxy' && (dest === 'write_ignored' || dest === 'bash_local'))));
            if (odd) return odd.mode === 'backup' ? refuse('policy:backup', BACKUP_REFUSED) : refuse('policy:proxy_mode', PROXY_NOT_RESTORED);
            // A warn rule for that secret: restored with the notice, as for a named marker.
            const warned = effs.find((e) => e && e.warn === true);
            if (warned) org = { warn: true, warnReason: warned.warnReason, warnName: warned.name };
          }
        }
      } else {
        const secrets = await state.loadSecrets();
        const s = secrets.secrets[inner];
        if (s && s.mode === 'backup') return refuse('policy:backup', BACKUP_REFUSED);
        // A marker the agent hooks put back (they always give a destination):
        // the organization policy applies, as in zn run and the secrets MCP tools.
        if (s && dest) {
          const [eff] = await team.effectiveList([asLocal(inner, s)], agentId, false);
          if (eff && eff.deny) return orgDenied([inner]);
          // A proxy-mode secret is only ever used by the broker's HTTP tool: it is never written into a file by a restore.
          if (eff && !['env', 'file'].includes(eff.mode) && dest === 'write_ignored') return refuse('policy:proxy_mode', PROXY_NOT_RESTORED);
          if (eff && eff.warn === true) org = { warn: true, warnReason: eff.warnReason };
        }
        if (s) { value = s.value; s.lastUsed = new Date().toISOString(); state.dirtySecrets = true; }
      }
      await writeAudit({ secret: inner, mode: 'resolve', agent: o.agent, tool: o.tool, decision: value === null ? 'deny' : 'allow', reason: value === null ? 'not_found' : (dest || purpose) });
      // withPolicy: {value, policy, deny?, warn?, warnReason?, warnName?} instead of the bare value.
      return o.withPolicy === true ? Object.assign({ value, policy: RESOLVE_POLICY_VERSION }, value === null ? null : org) : value;
    },

    async setSecret(name, value, meta) {
      const n = checkName(name);
      str(value, 'value');
      const backup = meta && typeof meta === 'object' && meta.mode === 'backup'; // whole files kept by `zn env shadow`
      return state.serial(async () => {
        const secrets = await state.loadSecrets();
        const prev = secrets.secrets[n];
        // New values under the minimum are refused; a value an older version stored keeps working.
        if (!backup && !(prev && prev.value === value)) {
          const bad = validateSecretValue(value);
          if (bad) throw znError(CODES.POLICY_DENIED, 'invalid value: ' + bad);
        }
        // The same value again is not a new secret: it keeps its generation and its approvals.
        const sameValue = !!prev && typeof prev.generation === 'string' && prev.generation !== '' && prev.value === value;
        const generation = sameValue ? prev.generation : newGeneration();
        if (!sameValue) dropApprovalsOf(secrets, n);
        secrets.secrets[n] = Object.assign(cleanMeta(meta), { value, generation, created: prev ? prev.created : new Date().toISOString(), lastUsed: prev ? prev.lastUsed : null });
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
      // A value kept as a backup is not checked for its length; once it becomes a secret it is.
      if (before.mode === 'backup' && target.mode !== 'backup') {
        const tooShort = validateSecretValue(before.value);
        if (tooShort) throw znError(CODES.POLICY_DENIED, 'invalid value: ' + tooShort);
      }
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
        if (prev.generation) secrets.secrets[n].generation = prev.generation;
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
      // The approval counts only for the value it was granted for. One recorded
      // before generations existed has none, so it is asked for again once.
      const current = secrets.secrets[String(secret)];
      if (!current || typeof current.generation !== 'string' || current.generation === '' || rec.gen !== current.generation) {
        writeAudit({ secret: String(secret), mode: 'env', argv0, decision: 'deny', reason: 'value_changed' });
        return false;
      }
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
      const generationAsked = loaded.secrets[String(secret)] ? loaded.secrets[String(secret)].generation || null : null;
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
        const current = secrets.secrets[String(secret)];
        if (!current) throw znError(CODES.NOT_FOUND, 'no secret named ' + secret + '. Next step: check the name for a typo; if the secret is missing, save it with zn secret set ' + secret + ' in your own terminal, or, if you are an agent, ask the user to do it.');
        if ((current.generation || null) !== generationAsked) throw znError(CODES.POLICY_DENIED, 'the secret changed while waiting for confirmation. Next step: run the command again.');
        if (!current.generation) current.generation = newGeneration();
        if (!secrets.approvals || typeof secrets.approvals !== 'object') secrets.approvals = {};
        secrets.approvals[key] = { ts: new Date().toISOString(), exe: exePath, fp, gen: current.generation };
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
    teamHookInfo: team.teamHookInfo,
    teamSync: team.teamSync,
    confirmOrgOpening: team.confirmOrgOpening,

    async removeSecret(name) {
      const n = str(name, 'name', 64);
      return state.serial(async () => {
        const secrets = await state.loadSecrets();
        if (!Object.prototype.hasOwnProperty.call(secrets.secrets, n)) return false;
        delete secrets.secrets[n];
        dropApprovalsOf(secrets, n);
        await writeAudit({ secret: n, mode: 'remove', decision: 'allow' });
        await state.saveSecrets();
        return true;
      });
    },

    /* Masking happens here, so the real values never leave the daemon. The
     * scrubber (hooks, prompts, MCP results, the streaming scrubber) asks
     * where the vault's values occur in a text and gets positions, types and
     * secret names back: never a value, an encoding of one or a hash. The
     * calls are recorded (at most one record a minute for each agent and
     * tool). The calls are not rate limited and take megabytes of text, so
     * anyone who can call them can test guesses against the vault (hundreds of
     * thousands a second); they cannot read a value out. */
    async maskInfo(project, claim) {
      noteMask(claim);
      const m = await maskStateOf(project);
      // shortCount: how many values under the minimum (from older versions) are compared exactly. A count, never a value.
      return { names: m.names, longest: m.longest, count: m.matcher.size, shortCount: m.shortCount };
    },

    async maskSpans(project, texts, claim) {
      if (!Array.isArray(texts) || texts.length > MASK_MAX_TEXTS) throw znError(CODES.POLICY_DENIED, 'too many texts. Next step: send fewer texts in one request.');
      let total = 0;
      for (const t of texts) {
        if (typeof t !== 'string') throw znError(CODES.POLICY_DENIED, 'invalid text. Next step: send strings.');
        total += t.length;
      }
      if (total > MASK_MAX_CHARS) throw znError(CODES.POLICY_DENIED, 'text too long. Next step: send it in smaller pieces.');
      noteMask(claim);
      const m = await maskStateOf(project);
      return { spans: texts.map((t) => (t.length < m.minNeedle && m.shortCount === 0 ? [] : m.matcher.find(t))) };
    },


    /* zn secret adopt: store a value the scrubber found as a named secret.
     * The value goes from one table of the vault to another and never to the caller. */
    async adoptToken(project, token, name, meta) {
      const m = TOKEN_RE.exec(String(token || ''));
      if (!m || !/_\d+$/.test(m[1])) throw znError(CODES.POLICY_DENIED, 'invalid token. Next step: give a placeholder the scrubber made, such as __ZN_AWS_KEY_1__.');
      const n = checkName(name);
      return state.serial(async () => {
        const p = await state.loadProject(String(project == null ? '' : project));
        const value = Object.prototype.hasOwnProperty.call(p.data.tokens, String(token)) ? p.data.tokens[String(token)] : null;
        if (typeof value !== 'string' || value.length === 0) throw znError(CODES.NOT_FOUND, String(token) + ' is not known for this project. Next step: check the placeholder name.');
        const tooShort = validateSecretValue(value);
        if (tooShort) throw znError(CODES.POLICY_DENIED, 'invalid value: ' + tooShort);
        const secrets = await state.loadSecrets();
        if (secrets.secrets[n]) throw znError(CODES.POLICY_DENIED, n + ' already exists. Next step: pick another name.');
        // A new secret gets its own generation, as setSecret gives one: an approval never carries over from an older secret of that name.
        dropApprovalsOf(secrets, n);
        secrets.secrets[n] = Object.assign(cleanMeta(meta), { value, generation: newGeneration(), created: new Date().toISOString(), lastUsed: null });
        await writeAudit({ secret: n, mode: 'set', decision: 'allow', reason: 'adopted' });
        await state.saveSecrets();
        return true;
      });
    },

    /* Is this the value stored under that name? Answers yes or no, never the value (zn secret import and
     * zn env shadow). Each answer is recorded and the daemon answers at most SAME_VALUE_PER_MINUTE a minute. That limit
     * only covers this call: maskSpans answers the same question for any text, without a limit (see the threat model). */
    async sameSecretValue(name, value) {
      const n = str(name, 'name', 64);
      str(value, 'value');
      const now = Date.now();
      if (now - sameWindow.start >= 60 * 1000) { sameWindow.start = now; sameWindow.count = 0; }
      if (++sameWindow.count > SAME_VALUE_PER_MINUTE) {
        writeAudit({ secret: NAME_RE.test(n) ? n : undefined, mode: 'resolve', decision: 'deny', reason: 'policy:compare_rate' });
        throw znError(CODES.POLICY_DENIED, 'too many comparisons in a minute. Next step: wait a minute and try again.');
      }
      const stored = (await state.loadSecrets()).secrets[n];
      let same = false;
      if (stored && typeof stored.value === 'string') {
        const a = crypto.createHash('sha256').update(stored.value).digest();
        const b = crypto.createHash('sha256').update(value).digest();
        same = crypto.timingSafeEqual(a, b);
      }
      writeAudit({ secret: NAME_RE.test(n) ? n : undefined, mode: 'resolve', decision: 'allow', reason: 'compare' });
      return same;
    },

    /* zn env unshadow: the user gets the original .env text back. Plain values go out of the vault,
     * so the user confirms on the daemon's own channel, and only the copies `zn env shadow` made can be read. */
    async readBackup(project, name, file) {
      const n = str(name, 'name', 64);
      if (!BACKUP_NAME_RE.test(n)) throw znError(CODES.POLICY_DENIED, 'invalid backup name. Next step: use the name zn env shadow printed.');
      const stored = (await state.loadSecrets()).secrets[n];
      if (!stored || stored.mode !== 'backup' || typeof stored.value !== 'string') throw znError(CODES.NOT_FOUND, n + ' not found. Next step: check the name zn env shadow printed.');
      await confirmOutOfBand({
        kind: 'file',
        title: 'write the original values of ' + path.basename(String(file || '.env')) + ' back in plain text?',
        warnings: ['zn env unshadow takes the values out of the vault and writes them in clear text.'],
        fields: [['Backup', n], ['File', path.basename(String(file || '.env'))], ['Project', String(project)]],
        footer: 'If you did not just run zn env unshadow, choose Deny.',
      }, { secret: n, mode: 'file' });
      writeAudit({ secret: n, mode: 'file', decision: 'ask:yes', reason: 'backup_read_confirmed' });
      return stored.value;
    },

    async audit(event) {
      writeAudit(event && typeof event === 'object' ? event : {});
      return true;
    },

    async auditVerify() {
      await state.loadSecrets();
      // The encrypted vault remembers the last record (sequence number and
      // MAC): a lost tail or a replaced one is reported, and the warning is stored.
      const secrets = state.secrets;
      const r = audit.verify({ file: auditFile, key: Buffer.from(secrets.auditKey, 'hex'), checkpoint: secrets.auditHead });
      if (!r.ok && !secrets.auditTamper) recordTamper(state, r.error + (r.line ? ' (record ' + r.line + ')' : ''), null);
      const t = secrets.auditTamper;
      if (!t) return r;
      return Object.assign({}, r, {
        ok: false,
        tampered: true,
        error: 'the audit log was changed behind the vault (noticed ' + t.at + '): ' + t.reason,
      });
    },

    /* The audit log for display: verified first. A log that does not verify is
     * refused (and the tamper mark is stored), never shown. */
    async auditRead(args) {
      await state.loadSecrets();
      const c = chainStatus(state);
      if (!c.ok) return { ok: false, tampered: c.tampered === true, error: c.error, reason: c.reason, events: [] };
      const a = args && typeof args === 'object' ? args : {};
      return { ok: true, records: c.records, events: audit.read({ file: auditFile, since: a.since, limit: a.limit }) };
    },

    /* The audit log for export (OTLP): verified first, refused otherwise. */
    async auditExport(args) {
      await state.loadSecrets();
      const c = chainStatus(state);
      if (!c.ok) return { ok: false, tampered: c.tampered === true, error: c.error, line: c.line };
      const a = args && typeof args === 'object' ? args : {};
      const r = require('../team/otel').exportAuditFile({ auditFile, since: a.since, installId: a.installId, orgId: a.orgId });
      return Object.assign({ ok: true }, r);
    },

    /* The user accepts the log as it is now, after looking into the change.
     * Needs the vault's own confirmation channel (an agent cannot answer it),
     * and refuses when the chain itself does not verify. */
    async auditAcknowledge() {
      const secrets = await state.loadSecrets();
      const t = secrets.auditTamper;
      if (!t) return { ok: true, cleared: false };
      await confirmOutOfBand({
        kind: 'audit_ack',
        title: 'accept the audit log as it is now?',
        warnings: ['The vault noticed that the audit log was changed behind it. Accepting makes the log as it is now the reference again; the earlier gap stays unexplained.'],
        fields: [['Noticed', t.at], ['What', t.reason]],
        footer: 'If you did not just ask for this in your own terminal, choose Deny.',
      }, { decision: 'deny', reason: 'audit_ack' });
      return state.serial(async () => {
        const cur = state.secrets;
        const key = Buffer.from(cur.auditKey, 'hex');
        const chain = audit.verify({ file: auditFile, key });
        if (!chain.ok) {
          throw znError(CODES.POLICY_DENIED, 'the audit log does not verify on its own (' + chain.error + '), so it cannot be accepted. Next step: keep a copy of ~/.zn/audit.jsonl as evidence; to start a new log on purpose, see zn vault reset.');
        }
        const last = audit.lastRecord(auditFile);
        cur.auditHead = last ? { seq: last.seq, mac: last.mac } : null;
        delete cur.auditTamper;
        state.chainCache = null;
        appendChecked(state, { decision: 'warn', reason: 'audit_tamper_acknowledged' }, {});
        await state.saveSecrets();
        return { ok: true, cleared: true };
      });
    },

    async lock() {
      setImmediate(() => ctl.shutdown('lock'));
      return true;
    },
  };
  return ops;
}

/* POSIX: the socket, the session key and the directory that holds them must be owned by the daemon's user and closed to
 * group and others. The directory is always checked; a file is checked when it exists (a stale one before the daemon
 * starts), and must exist when `strict`. Windows relies on the ACL the user profile gives ~/.zn (see the threat model). */
function assertPrivateEndpoint(ep, strict) {
  if (!ep.unix || typeof process.getuid !== 'function') return;
  const me = process.getuid();
  const dir = path.dirname(ep.address);
  for (const file of [dir, ep.address, ep.keyFile]) {
    let st;
    try { st = fs.lstatSync(file); } catch (err) {
      if (err.code === 'ENOENT' && file !== dir && !strict) continue;
      throw znError(CODES.POLICY_DENIED, 'the vault will not start: cannot check ' + path.basename(file) + ' (' + (err.code || 'error') + '). Next step: check the permissions of ' + dir + ' (it must be yours, mode 0700).');
    }
    if (st.isSymbolicLink() || st.uid !== me || (st.mode & 0o077) !== 0) {
      throw znError(CODES.POLICY_DENIED, 'the vault will not start: ' + path.basename(file) + ' is not private to your user. Next step: check the permissions of ' + dir + ' (it must be yours, mode 0700).');
    }
  }
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

  if (await isRunning(o)) throw znError(CODES.POLICY_DENIED, messages.vaultAlreadyUnlocked());
  // Before anything is bound or written: the folder (and any stale socket or key in it) must be private to this user.
  assertPrivateEndpoint(ep);
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
  // Nobody is waiting for this one: teamSync records its own failures (last_sync, one local alert) before they reach this catch.
  const teamSync = () => {
    const pendingRevocation = state.secrets && Array.isArray(state.secrets.pendingRevocations) && state.secrets.pendingRevocations.length > 0;
    if (!closed && state.secrets && (state.secrets.team || pendingRevocation)) ops.teamSync({}).catch(() => {});
  };
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
          try {
            appendChecked(state, { mode: reason === 'lock' ? 'lock' : 'expire', decision: 'allow', reason }, {});
          } finally {
            await state.saveSecrets();
          }
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
          if (!closed) bumpIdle();
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
    if (err && err.code === 'EADDRINUSE') throw znError(CODES.POLICY_DENIED, messages.vaultAlreadyUnlocked());
    throw err;
  });
  if (ep.unix) fs.chmodSync(ep.address, 0o600);
  // Node cannot read the peer's credentials (SO_PEERCRED) from a Unix socket, so the kernel's file permissions are
  // the peer check: the socket is checked before the session key is written, and all three again after.
  // Windows: the key file and the pipe get explicit owner-only permissions, read back.
  // If any of these cannot be set or checked, the daemon does not stay up.
  try {
    if (ep.unix) assertPrivateEndpoint(ep);
    store.writePrivateFile(ep.keyFile, sessionKey.toString('hex'));
    if (!ep.unix) {
      const acl = o.winacl || winacl;
      acl.ensurePrivate(ep.keyFile, { dir: false });
      acl.ensurePipe(ep.address);
    }
    assertPrivateEndpoint(ep, true);
  } catch (err) { await shutdown('lock'); throw err; }
  let unlockFailure = null;
  let adoptedRecords = 0;
  await state.serial(async () => {
    // Check the log against the vault's checkpoint BEFORE the unlock record is
    // written: that record would otherwise continue from whatever tail is there.
    try {
      const pre = chainStatus(state, { force: true });
      // A failed check has stored the tamper mark (chainStatus).
      if (pre.ok && !state.secrets.auditTamper) {
        // The log verifies and carries the checkpoint record. Records after it were written
        // before a crash or a restored secrets.age could save the newer checkpoint: adopt them.
        const tail = audit.lastRecord(state.paths.auditFile);
        const prior = state.secrets.auditHead;
        if (tail && prior && Number.isInteger(tail.seq) && tail.seq > prior.seq) adoptedRecords = tail.seq - prior.seq;
        if (tail) state.secrets.auditHead = { seq: tail.seq, mac: tail.mac };
      }
    } catch (err) {
      recordTamper(state, 'the audit log cannot be read', null);
    }
    try {
      // Make every adoption visible in the log: those records were written but never checkpointed.
      if (adoptedRecords > 0) appendChecked(state, { mode: 'unlock', decision: 'warn', reason: 'audit_tail_adopted_after_unclean_shutdown:' + adoptedRecords }, {});
      appendChecked(state, { mode: 'unlock', decision: 'allow', reason: 'ttl:' + Math.round(ttlMs / 60000) + 'm' }, {});
    } catch (err) {
      unlockFailure = err;
    } finally {
      await state.saveSecrets();
    }
  });
  if (unlockFailure) {
    // The log cannot be continued (its last line is unreadable): do not leave a half-started daemon.
    await shutdown('error');
    throw znError(CODES.LOCKED, 'the audit log cannot be read, so the vault stays locked. The vault keeps a warning about it. Next step: keep a copy of ~/.zn/audit.jsonl as evidence; to start a new log on purpose, see zn vault reset.');
  }
  // The idle clock starts only now that the daemon is ready to serve, not
  // before the first (possibly slow) write above: otherwise a slow disk can
  // expire the session before the first client connects.
  if (!closed) bumpIdle();

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
  if (await isRunning(o)) throw znError(CODES.POLICY_DENIED, messages.vaultAlreadyUnlocked());
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
    const timer = setTimeout(() => reject(znError(CODES.LOCKED, messages.vaultStartTimeout())), 20000);
    child.once('message', (m) => {
      clearTimeout(timer);
      if (m && m.ready) resolve(m);
      else reject(znError((m && m.code) || CODES.LOCKED, (m && m.message) || 'daemon failed to start'));
    });
    child.once('exit', (code) => { clearTimeout(timer); reject(znError(CODES.LOCKED, messages.vaultStartExited(code))); });
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
  if (await isRunning(o)) throw znError(CODES.POLICY_DENIED, messages.vaultAlreadyUnlocked());
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

module.exports = { serve, unlock, unlockForeground, lock, isRunning, endpoint, DEFAULT_TTL_MS, DEFAULT_IDLE_MS, PROTOCOL, DESTINATION_POLICY, assertPrivateEndpoint };
