'use strict';
/**
 * CLI for the vault session:
 *
 *   zn unlock [--ttl 8h] [--idle 30m] [--backend <name>] [--passphrase-stdin] [--foreground]
 *   zn lock
 *   zn vault status
 *   zn vault forget [<project dir>]     (vault must be locked)
 *   zn vault verify                     (audit log: chain, MACs, truncation)
 *   zn vault log [--since 1h]           (audit log: who used which secret; alias: zn secret log)
 *   zn vault log export --otlp          (the same log as OpenTelemetry logs; lib/team/cli.js)
 *
 * The first `zn unlock` creates the vault: a new age identity stored in the
 * OS keychain, or behind a passphrase when no keychain is available.
 * Passphrases are read from the terminal with echo off, or from stdin with
 * --passphrase-stdin; never from arguments or environment variables.
 *
 * Confirmations (first use of a secret by a command, policy changes) happen
 * outside the agent: with --foreground the daemon stays in this terminal and
 * asks here; otherwise it shows a native dialog, or refuses when the system
 * has none (headless Linux, SSH sessions).
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const daemon = require('./daemon');
const keychain = require('./keychain');
const store = require('./store');
const { createClient } = require('./client');
const { agentEnvDetected } = require('../broker/tty');
const { CODES } = require('../errors');

function parseDuration(s, fallback) {
  if (s === undefined) return fallback;
  const m = /^(\d+)(s|m|h)$/.exec(String(s));
  if (!m) throw new Error('invalid duration "' + s + '" (use e.g. 30m, 8h)');
  const n = Number(m[1]) * { s: 1000, m: 60000, h: 3600000 }[m[2]];
  if (n < 60000 || n > 24 * 3600000) throw new Error('duration must be between 1m and 24h');
  return n;
}

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

// One line reader for all the passphrase prompts of a command. A reader per
// prompt loses what was typed or pasted before the second prompt appeared:
// the first reader had already buffered it, and closing it dropped the rest,
// so `zn unlock` waited for ever on "Repeat passphrase".
function createHiddenPrompter(opts) {
  const o = opts || {};
  const input = o.input || process.stdin;
  const output = o.output || process.stderr;
  if (!input.isTTY) throw new Error('zn needs a terminal to ask for the passphrase. Run this command in your terminal, or pass it with --passphrase-stdin.');
  const rl = readline.createInterface({ input, output, terminal: true });
  rl._writeToOutput = () => {}; // never echo what is typed
  const lines = [];
  const waiters = [];
  let closed = false;
  rl.on('line', (line) => {
    const w = waiters.shift();
    if (w) w.resolve(line);
    else lines.push(line);
  });
  const cancelled = () => new Error('Cancelled: no passphrase was entered.');
  rl.on('close', () => {
    closed = true;
    if (waiters.length) output.write('\n');
    while (waiters.length) waiters.shift().reject(cancelled());
  });
  return {
    ask(question) {
      output.write(question);
      return new Promise((resolve, reject) => {
        const done = (line) => { output.write('\n'); resolve(line); };
        if (lines.length) done(lines.shift());
        else if (closed) { output.write('\n'); reject(cancelled()); }
        else waiters.push({ resolve: done, reject });
      });
    },
    close() { rl.close(); },
  };
}

async function readStdin() {
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data.replace(/\r?\n$/, '');
}

async function getPassphrase(args, creating, prompterOpts) {
  if (args.includes('--passphrase-stdin')) return readStdin();
  const prompter = createHiddenPrompter(prompterOpts);
  try {
    const p1 = await prompter.ask(creating ? 'New vault passphrase (min ' + keychain.MIN_PASSPHRASE + ' chars): ' : 'Vault passphrase: ');
    if (creating) {
      const p2 = await prompter.ask('Repeat passphrase: ');
      if (p1 !== p2) throw new Error('The two passphrases do not match. Nothing was created; run zn unlock again.');
    }
    return p1;
  } finally {
    prompter.close();
  }
}

function out(s) { process.stdout.write(s + '\n'); }

async function unlockCmd(args) {
  const agent = agentEnvDetected(process.env);
  if (agent) throw new Error('zn unlock must be run by you in your own terminal, not by an AI agent (detected ' + agent + ')');
  const opts = {
    ttlMs: parseDuration(flag(args, '--ttl'), daemon.DEFAULT_TTL_MS),
    idleMs: parseDuration(flag(args, '--idle'), daemon.DEFAULT_IDLE_MS),
  };
  const meta = keychain.readMeta({});
  const backend = flag(args, '--backend') || (meta && meta.backend) || keychain.detectBackend();
  if (!keychain.BACKENDS.includes(backend)) throw new Error('unknown backend ' + backend);
  opts.backend = backend;
  if (backend === 'passphrase') opts.passphrase = await getPassphrase(args, !meta);
  if (args.includes('--foreground')) return unlockForegroundCmd(opts, backend);
  const res = await daemon.unlock(opts);
  if (res.created) out('Created a new vault (' + backend + ') in ' + store.paths().vaultDir);
  out('Vault unlocked until ' + res.expiresAt + ' (locks after ' + Math.round(opts.idleMs / 60000) + ' min idle). Run `zn lock` to lock now.');
  if (res.confirm === 'gui') out('Confirmations (first use of a secret by a command, policy changes) appear as a system dialog.');
  else {
    out('Note: no system dialog is available here, so first-use approvals and policy changes will be refused.');
    out('      To approve them, run the vault in a terminal of its own instead: zn lock && zn unlock --foreground');
  }
  return 0;
}

async function unlockForegroundCmd(opts, backend) {
  if (!process.stdin.isTTY) throw new Error('--foreground needs an interactive terminal (it asks you there)');
  const res = await daemon.unlockForeground(opts);
  if (res.created) out('Created a new vault (' + backend + ') in ' + store.paths().vaultDir);
  out('Vault unlocked until ' + res.expiresAt + ' (locks after ' + Math.round(opts.idleMs / 60000) + ' min idle).');
  out('Keep this terminal open: zn asks here before a secret is used by a command for the first time or a policy changes.');
  out('Press Ctrl+C or run `zn lock` to lock.');
  const onSig = () => { res.close(); };
  process.on('SIGINT', onSig);
  process.on('SIGTERM', onSig);
  const reason = await res.done;
  out('Vault locked (' + reason + ').');
  return 0;
}

async function lockCmd() {
  const was = await daemon.lock({});
  out(was ? 'Vault locked.' : 'Vault was not unlocked.');
  return 0;
}

async function statusCmd() {
  const meta = keychain.readMeta({});
  if (!meta) { out('Vault: not created yet (run `zn unlock`).'); return 0; }
  const c = createClient({});
  try {
    const s = await c.status();
    out('Vault: unlocked (backend ' + meta.backend + ', expires ' + s.expiresAt + ')');
  } catch (err) {
    out('Vault: locked (backend ' + meta.backend + ')');
  } finally {
    c.close();
  }
  out('Location: ' + store.paths().vaultDir);
  return 0;
}

async function forgetCmd(args) {
  const dir = path.resolve(args[2] || process.cwd());
  const c = createClient({});
  const unlocked = await c.isUnlocked();
  c.close();
  if (unlocked) { process.stderr.write('Lock the vault first (`zn lock`): the daemon may hold this project in memory.\n'); return 1; }
  const real = fs.existsSync(dir) ? fs.realpathSync(dir) : dir;
  out(store.forgetProject(real) ? 'Forgot the token map of ' + real : 'No token map stored for ' + real);
  return 0;
}

async function auditVerifyCmd() {
  const c = createClient({});
  try {
    const r = await c.auditVerify();
    out(r.ok ? 'Audit log OK: ' + r.records + ' records, chain and MACs verified.' : 'Audit log FAILED at record ' + (r.line || r.records) + ': ' + r.error);
    return r.ok ? 0 : 1;
  } finally {
    c.close();
  }
}

/** Returns the process exit code. */
async function runVaultCommand(args) {
  try {
    const [cmd, sub] = args;
    if (cmd === 'unlock') return await unlockCmd(args);
    if (cmd === 'lock') return await lockCmd();
    if (cmd === 'vault' && (sub === 'status' || sub === undefined)) return await statusCmd();
    if (cmd === 'vault' && sub === 'forget') return await forgetCmd(args);
    if (cmd === 'vault' && sub === 'verify') return await auditVerifyCmd();
    if (cmd === 'vault' && sub === 'log') return await require('../broker/cli').dispatch('vault', args.slice(1));
    if (cmd === 'vault' && sub === 'team') {
      require('../stats').recordEvent('team-vault-request');
      process.stdout.write('A shared vault for teams is planned, not available yet. Today the vault is personal: each person keeps their own secrets on their own machine.\n' +
        'Your request was counted on this machine only (see `zn-gate stats`). Nothing was sent.\n');
      return 0;
    }
    process.stderr.write('usage: zn unlock | zn lock | zn vault status | zn vault verify | zn vault log [--since 1h] | zn vault forget [dir]\n');
    return 2;
  } catch (err) {
    const hint = err && err.code === CODES.LOCKED ? ' (vault locked: run `zn unlock`)' : '';
    process.stderr.write('[zn] ' + (err && err.message ? err.message : err) + hint + '\n');
    return 1;
  }
}

module.exports = { runVaultCommand, parseDuration, getPassphrase, createHiddenPrompter };
