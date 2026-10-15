'use strict';
/**
 * IPC client for the vault daemon. The only vault interface other modules use.
 * Every call is async; when the daemon is not running the error code is ZN_LOCKED.
 *
 *   mapToken(project, type, value) -> token          __ZN_<TYPE>_<n>__
 *   resolve(project, token)        -> value|null     broker and detokenize only; never exposed to the agent
 *       optional third argument {destination, agent, tool}: the daemon re-checks
 *       the restoration policy and records it in the audit log
 *   setSecret(name, value, meta) / listSecrets() / removeSecret(name)
 *   exactValues(project)           -> [{name, type, values: [raw, b64, hex, url]}]   in memory only
 *   audit(event)                   {secret, mode, agent, tool, argv0, host, decision, reason}
 *
 *   updateSecretMeta(name, meta)                  policy change; the value is not touched.
 *       A change that widens the policy waits for the user to confirm it
 *       on the daemon's channel (see lib/vault/confirm.js).
 *   isApproved(project, secret, argv0[, executable]) -> bool   first-use approval of a command
 *   recordApproval(project, secret, argv0[, executable])
 *       Also accepted: (secret, command), the broker's form; the project is
 *       then the nearest parent of the current directory with .git.
 *       Recording one waits for the user to confirm it on the daemon's
 *       channel (never on this process's terminal).
 *       The approval is bound to the real path of the executable that argv0
 *       resolves to on this PATH; if it later resolves elsewhere (a shadowing
 *       binary, a replaced symlink), the approval no longer applies.
 *       `zn run` passes executable = {real, fp}: the real path it resolved
 *       and the fingerprint of the file it opened, so the daemon checks the
 *       very file that will be started.
 *   confirmFileWrite(project, file, names, reason)
 *       secrets_render_file when the output is not a new file inside the
 *       project: waits for the user to confirm it on the daemon's channel.
 *
 * Extras: status(), isUnlocked(), lock(), auditVerify(), createClient({home}), close().
 *
 * The connection authenticates both ways with the session key in
 * ~/.zn/run/session.key: the client checks the daemon's proof before it
 * sends any request, so values are never sent to an impostor endpoint.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const store = require('./store');
const exe = require('../exe');
const { CODES, znError } = require('../errors');

const PROTOCOL = 1;
const TIMEOUT_MS = 15000;
// Operations the daemon confirms with the user wait for the answer.
const CONFIRM_TIMEOUT_MS = 150000;
const CONFIRMED_OPS = new Set(['recordApproval', 'updateSecretMeta', 'confirmFileWrite', 'teamJoin', 'teamLeave', 'confirmOrgOpening']);
// Network calls to the zn cloud (policy download and audit upload).
const NETWORK_OPS = new Set(['teamSync']);
const NETWORK_TIMEOUT_MS = 120000;
const MAX_LINE = 64 * 1024 * 1024;

function endpoint(opts) {
  const p = store.paths(opts);
  const keyFile = path.join(p.runDir, 'session.key');
  if (process.platform === 'win32') {
    const tag = crypto.createHash('sha256').update('zn-pipe\0' + p.home.toLowerCase()).digest('hex').slice(0, 24);
    return { address: '\\\\.\\pipe\\zn-vault-' + tag, keyFile, unix: false };
  }
  const address = path.join(p.runDir, 'vault.sock');
  if (Buffer.byteLength(address) > 100) {
    throw znError(CODES.POLICY_DENIED, 'socket path too long (' + address + '); set ZN_HOME to a shorter directory');
  }
  return { address, keyFile, unix: true };
}

function hmac(key, ...parts) {
  return crypto.createHmac('sha256', key).update(parts.join('\0')).digest('hex');
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || !/^[0-9a-f]+$/.test(a)) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/* Real path of the executable argv0 runs, on the given PATH; null if none.
 * Same resolver as `zn run` (lib/exe.js), in the form approvals use. */
function resolveExecutable(argv0, env) {
  const r = exe.resolveExecutable(argv0, env);
  return r ? exe.approvalPath(r.real) : null;
}

function findProjectRoot(dir) {
  let cur = path.resolve(dir || process.cwd());
  for (;;) {
    if (fs.existsSync(path.join(cur, '.git'))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) return path.resolve(dir || process.cwd());
    cur = parent;
  }
}

/* (project, secret, argv0[, executable]) or the broker's (secret, command).
 * executable = {real, fp}: the file `zn run` already resolved and opened.
 * The daemon then checks that exact file (and, with fp, the descriptor zn
 * run holds) instead of resolving the name again. */
function approvalArgs(args) {
  let project;
  let secret;
  let command;
  let executable = null;
  if (args.length >= 3 && args[2] !== undefined) [project, secret, command, executable] = args;
  else { [secret, command] = args; project = findProjectRoot(process.cwd()); }
  const argv0 = exe.commandWord(command);
  const name = argv0.split(/[\\/]/).pop();
  if (executable && typeof executable === 'object' && typeof executable.real === 'string') {
    return [project, secret, name, exe.approvalPath(executable.real), typeof executable.fp === 'string' ? executable.fp : null];
  }
  return [project, secret, name, resolveExecutable(argv0)];
}

// notRunning: the daemon is not running (no session key, or no socket to it),
// the one case the plain "unlock it" message is for.
function lockedError(detail, notRunning = false) {
  const err = znError(CODES.LOCKED, 'vault is locked' + (detail ? ' (' + detail + ')' : '') + '; run `zn unlock`');
  if (notRunning) err.vaultNotRunning = true;
  return err;
}

function readSessionKey(keyFile) {
  let buf;
  try { buf = store.readPrivateFile(keyFile); } catch (err) { throw lockedError(err.code); }
  if (buf === null) throw lockedError(null, true);
  const hex = buf.toString('utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw lockedError('bad session key');
  return Buffer.from(hex, 'hex');
}

class VaultClient {
  constructor(opts) {
    this.opts = opts || {};
    this.conn = null;      // Promise<{socket, pending: Map, nextId}>
  }

  _connect() {
    if (this.conn) return this.conn;
    const ep = endpoint(this.opts);
    this.conn = new Promise((resolve, reject) => {
      let key;
      try { key = readSessionKey(ep.keyFile); } catch (err) { reject(err); return; }
      const socket = net.createConnection(ep.address);
      socket.setEncoding('utf8');
      const state = { socket, pending: new Map(), nextId: 1, stage: 'hello', buf: '', clientNonce: crypto.randomBytes(16).toString('hex'), serverNonce: null };
      const fail = (err) => {
        for (const p of state.pending.values()) p.reject(err);
        state.pending.clear();
        this.conn = null;
        socket.destroy();
        reject(err);
      };
      const timer = setTimeout(() => fail(lockedError('timeout')), TIMEOUT_MS);
      socket.on('error', (err) => { clearTimeout(timer); fail(lockedError(err.code, true)); });
      socket.on('close', () => {
        clearTimeout(timer);
        for (const p of state.pending.values()) p.reject(lockedError('connection closed'));
        state.pending.clear();
        if (this.conn && state.stage !== 'ready') reject(lockedError('connection closed'));
        this.conn = null;
      });
      socket.on('connect', () => {
        socket.write(JSON.stringify({ op: 'hello', v: PROTOCOL, nonce: state.clientNonce }) + '\n');
      });
      socket.on('data', (chunk) => {
        state.buf += chunk;
        if (state.buf.length > MAX_LINE) { fail(lockedError('oversized reply')); return; }
        let nl;
        while ((nl = state.buf.indexOf('\n')) >= 0) {
          const line = state.buf.slice(0, nl);
          state.buf = state.buf.slice(nl + 1);
          let msg;
          try { msg = JSON.parse(line); } catch (err) { fail(lockedError('bad reply')); return; }
          if (state.stage === 'hello') {
            // Verify the daemon before sending anything else.
            if (!msg || !msg.ok || msg.v !== PROTOCOL || !/^[0-9a-f]{32}$/.test(msg.nonce || '') ||
                !safeEqualHex(msg.proof, hmac(key, 'zn-server', state.clientNonce, msg.nonce))) {
              clearTimeout(timer);
              fail(znError(CODES.POLICY_DENIED, 'vault daemon failed authentication'));
              return;
            }
            state.serverNonce = msg.nonce;
            state.stage = 'auth';
            socket.write(JSON.stringify({ op: 'auth', proof: hmac(key, 'zn-client', state.serverNonce, state.clientNonce) }) + '\n');
            continue;
          }
          if (state.stage === 'auth') {
            clearTimeout(timer);
            if (!msg || !msg.ok) { fail(znError(CODES.POLICY_DENIED, 'vault refused this client')); return; }
            state.stage = 'ready';
            key.fill(0);
            socket.unref();
            resolve(state);
            continue;
          }
          const p = state.pending.get(msg && msg.id);
          if (!p) continue;
          state.pending.delete(msg.id);
          if (state.pending.size === 0) socket.unref();
          if (msg.ok) p.resolve(msg.result);
          else p.reject(znError((msg.error && msg.error.code) || 'ZN_ERROR', (msg.error && msg.error.message) || 'vault error'));
        }
      });
    });
    this.conn.catch(() => { this.conn = null; });
    return this.conn;
  }

  async call(op, args) {
    const state = await this._connect();
    return new Promise((resolve, reject) => {
      const id = state.nextId++;
      const timer = setTimeout(() => {
        state.pending.delete(id);
        reject(lockedError('timeout'));
      }, CONFIRMED_OPS.has(op) ? CONFIRM_TIMEOUT_MS : NETWORK_OPS.has(op) ? NETWORK_TIMEOUT_MS : TIMEOUT_MS);
      state.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      state.socket.ref();
      state.socket.write(JSON.stringify({ id, op, args: args || [] }) + '\n');
    });
  }

  close() {
    const c = this.conn;
    this.conn = null;
    if (c) c.then((s) => s.socket.end(), () => {});
  }

  mapToken(project, type, value) { return this.call('mapToken', [project, type, value]); }
  resolve(project, token, opts) { return this.call('resolve', [project, token, opts || {}]); }
  setSecret(name, value, meta) { return this.call('setSecret', [name, value, meta || {}]); }
  // opts {effective, agent}: the organization policy applied for that agent.
  listSecrets(opts) { return this.call('listSecrets', opts ? [opts] : []); }
  removeSecret(name) { return this.call('removeSecret', [name]); }
  exactValues(project) { return this.call('exactValues', [project]); }
  audit(event) { return this.call('audit', [event || {}]); }
  updateSecretMeta(name, meta) { return this.call('updateSecretMeta', [name, meta || {}]); }
  // Optional fourth argument: {real, fp} of the executable zn run resolved.
  isApproved(project, secret, argv0) { return this.call('isApproved', approvalArgs(Array.from(arguments))); }
  recordApproval(project, secret, argv0) { return this.call('recordApproval', approvalArgs(Array.from(arguments))); }
  confirmFileWrite(project, file, names, reason) { return this.call('confirmFileWrite', [project, file, names, reason]); }
  teamJoin(args) { return this.call('teamJoin', [args || {}]); }
  teamLeave() { return this.call('teamLeave', []); }
  teamInfo() { return this.call('teamInfo', []); }
  teamSync(args) { return this.call('teamSync', [args || {}]); }
  confirmOrgOpening(secret, kind, value, agent, agentTrusted) { return this.call('confirmOrgOpening', [secret, kind, value, agent || null, agentTrusted === true]); }
  status() { return this.call('status', []); }
  auditVerify() { return this.call('auditVerify', []); }
  lock() { return this.call('lock', []); }
  async isUnlocked() {
    try { await this.status(); return true; } catch (err) { return false; }
  }
}

/* Default client: one shared connection per process, ZN_HOME read on first use. */
let defaultClient = null;
function client() {
  if (!defaultClient) defaultClient = new VaultClient({});
  return defaultClient;
}

async function mapToken(project, type, value) { return client().mapToken(project, type, value); }
// Contract arity is (project, token); an optional third argument carries
// {destination, agent, tool} for the daemon's policy check and audit.
async function resolve(project, token) { return client().resolve(project, token, arguments[2]); }
async function setSecret(name, value, meta) { return client().setSecret(name, value, meta); }
// Contract arity is 0; an optional argument {effective, agent} applies the
// organization policy for that agent (zn Team).
async function listSecrets() { return client().listSecrets(arguments[0]); }
async function removeSecret(name) { return client().removeSecret(name); }
async function exactValues(project) { return client().exactValues(project); }
async function audit(event) { return client().audit(event); }
async function updateSecretMeta(name, meta) { return client().updateSecretMeta(name, meta); }
async function isApproved(project, secret, argv0) { return client().isApproved(...arguments); }
async function recordApproval(project, secret, argv0) { return client().recordApproval(...arguments); }
async function confirmFileWrite(project, file, names, reason) { return client().confirmFileWrite(project, file, names, reason); }

module.exports = {
  mapToken,
  resolve,
  setSecret,
  listSecrets,
  removeSecret,
  exactValues,
  audit,
  updateSecretMeta,
  isApproved,
  recordApproval,
  confirmFileWrite,
  status: () => client().status(),
  isUnlocked: () => client().isUnlocked(),
  lock: () => client().lock(),
  auditVerify: () => client().auditVerify(),
  close: () => { if (defaultClient) defaultClient.close(); defaultClient = null; },
  createClient: (opts) => new VaultClient(opts),
  resolveExecutable,
  VaultClient,
  endpoint,
  hmac,
  safeEqualHex,
  PROTOCOL,
};
