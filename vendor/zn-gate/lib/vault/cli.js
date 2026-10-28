'use strict';
/**
 * CLI for the vault session:
 *
 *   zn unlock [--ttl 8h] [--idle 30m] [--backend <name>] [--passphrase-stdin] [--foreground]
 *   zn lock
 *   zn vault status
 *   zn vault forget [<project dir>]     (vault must be locked)
 *   zn vault reset                      (lost passphrase: set the old vault aside, start empty; own terminal only)
 *   zn vault purge [--yes]              (delete the vault, its backups and token maps for good; own terminal, or a script with --yes)
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
const { agentDetected } = require('../broker/tty');
const messages = require('../messages');
const { CODES, messageWithUnlockHint } = require('../errors');
const vaultReset = require('./reset');
const vaultPurge = require('./purge');
const { znCommand } = require('../zn-command');

/* A usage mistake (an unknown option, a bad duration or backend): the command exits 2, as the docs say. */
function usageError(message) {
  const err = new Error(message);
  err.exitCode = 2;
  return err;
}

/* The time a session ends, the way a person says it: "23:09 (in 8 h)", with "tomorrow" when it is past midnight.
 * A value that is not a date is returned as it is. */
function untilText(iso, now) {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return String(iso);
  const nowMs = now === undefined ? Date.now() : now;
  const pad = (n) => String(n).padStart(2, '0');
  const today = new Date(nowMs);
  const sameDay = at.getFullYear() === today.getFullYear() && at.getMonth() === today.getMonth() && at.getDate() === today.getDate();
  const clock = pad(at.getHours()) + ':' + pad(at.getMinutes());
  const minutes = Math.max(0, Math.round((at.getTime() - nowMs) / 60000));
  const left = minutes < 90 ? 'in ' + Math.max(1, minutes) + ' min' : 'in ' + Math.round(minutes / 60) + ' h';
  return (sameDay ? '' : 'tomorrow ') + clock + ' (' + left + ')';
}

function parseDuration(s, fallback) {
  if (s === undefined) return fallback;
  const m = /^(\d+)(s|m|h)$/.exec(String(s));
  if (!m) throw usageError(messages.invalidDuration(s));
  const n = Number(m[1]) * { s: 1000, m: 60000, h: 3600000 }[m[2]];
  if (n < 60000 || n > 24 * 3600000) throw usageError(messages.DURATION_RANGE);
  return n;
}

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

/* The options each command takes: true when the option needs a value after it. */
const OPTIONS = {
  unlock: { '--ttl': true, '--idle': true, '--backend': true, '--passphrase-stdin': false, '--foreground': false },
  lock: {},
  status: {},
  verify: { '--acknowledge': false },
  reset: {},
  purge: { '--yes': false },
  forget: {},
};

/* Checks the arguments after the command name. Returns the first problem as a sentence, or null.
 * Unknown options, options without their value and stray words are usage errors (exit 2), not ignored. */
function argumentProblem(name, rest, maxWords) {
  const allowed = OPTIONS[name];
  let words = 0;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('-')) {
      if (!Object.prototype.hasOwnProperty.call(allowed, a)) return 'Unknown option "' + a.slice(0, 40) + '".';
      if (allowed[a]) {
        const v = rest[i + 1];
        if (v === undefined || v.startsWith('--')) return 'The option ' + a + ' needs a value.';
        i++;
      }
    } else if (++words > (maxWords || 0)) {
      return 'Unexpected argument "' + a.slice(0, 40) + '".';
    }
  }
  return null;
}

const USAGE = {
  unlock: () => 'usage: ' + znCommand('unlock') + ' [--ttl 8h] [--idle 30m] [--backend NAME] [--passphrase-stdin] [--foreground]',
  lock: () => 'usage: ' + znCommand('lock'),
  status: () => 'usage: ' + znCommand('vault status'),
  verify: () => 'usage: ' + znCommand('vault verify') + ' [--acknowledge]',
  reset: () => 'usage: ' + znCommand('vault reset'),
  purge: () => 'usage: ' + znCommand('vault purge') + ' [--yes]',
  forget: () => 'usage: ' + znCommand('vault forget') + ' [dir]',
};

/* Prints the problem and the usage line to stderr and returns the exit code 2. */
function usageFail(name, problem) {
  process.stderr.write('[zn] ' + problem + '\n' + USAGE[name]() + '\n');
  return 2;
}

// One line reader for all the passphrase prompts of a command. A reader per
// prompt loses what was typed or pasted before the second prompt appeared:
// the first reader had already buffered it, and closing it dropped the rest,
// so `zn unlock` waited for ever on "Repeat passphrase".
function createHiddenPrompter(opts) {
  const o = opts || {};
  const input = o.input || process.stdin;
  const output = o.output || process.stderr;
  if (!input.isTTY) throw new Error(messages.PASSPHRASE_NEEDS_TERMINAL);
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
  const cancelled = () => new Error(messages.passphraseCancelled());
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
      if (p1 !== p2) throw new Error(messages.passphraseMismatch());
    }
    return p1;
  } finally {
    prompter.close();
  }
}

function out(s) { process.stdout.write(s + '\n'); }

const RESOLVE_POLICY_FEATURE = 'resolve-policy';
const CAPABILITIES_FEATURE = 'capabilities';

/** The running vault's status, or null when none answers. */
async function runningStatus(clientFactory) {
  const c = (clientFactory || createClient)({});
  try { return await c.status(); } catch (err) { return null; } finally { c.close(); }
}

/** A running vault started by an older zn-gate (it does not check the organization policy on restores, or still
 *  hands out values without a context: zn unlock restarts it). */
function isOutdatedVault(s) {
  return Boolean(s) && !(Array.isArray(s.features) && s.features.includes(RESOLVE_POLICY_FEATURE) && s.features.includes(CAPABILITIES_FEATURE));
}

/* Is the process still there? EPERM means it exists but is not ours to signal. */
function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (err) { return Boolean(err && err.code === 'EPERM'); }
}

const oldVaultStuck = () => 'The old vault did not stop; run `' + znCommand('lock') + '`, wait a moment, then `' + znCommand('unlock') + '`.';

/**
 * zn unlock with an older vault still running: lock it so this version can
 * start. Only from `zn unlock`, which a person runs in their own terminal;
 * never from a hook.
 *
 * The identity is checked first (deps.verify), so a mistyped passphrase
 * leaves the old vault running. lock() answers before the old process has
 * exited (it still writes its files and then removes its socket and session
 * key), so this waits until its pid is gone before a new vault may start.
 */
async function restartIfOutdated(deps) {
  const d = deps || {};
  const s = await runningStatus(d.clientFactory);
  if (!isOutdatedVault(s)) return false;
  if (d.verify) await d.verify();
  (d.out || out)('The running vault is from an older zn-gate; restarting it.');
  const pid = Number.isSafeInteger(s.pid) && s.pid > 0 ? s.pid : null;
  await (d.lock || daemon.lock)({});
  const alive = d.isAlive || pidAlive;
  const sleep = d.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const deadline = (d.timeoutMs == null ? 5000 : d.timeoutMs);
  if (pid === null) throw new Error(oldVaultStuck());
  for (let waited = 0; alive(pid); waited += 100) {
    if (waited >= deadline) throw new Error(oldVaultStuck());
    await sleep(100);
  }
  return true;
}

/**
 * When the vault locks, in words: after a quiet spell, or at the latest at the
 * end of the session. Both limits are real (idle timer and session TTL), so the
 * unlock and status messages share this one sentence.
 */
function lockWhenText(idleMs, expiresAt, now) {
  const until = untilText(expiresAt, now);
  if (!Number.isFinite(idleMs) || idleMs <= 0) return 'expires ' + until;
  return 'locks after ' + Math.max(1, Math.round(idleMs / 60000)) + ' min idle, or at ' + until + ' at the latest';
}

/** The `zn vault status` line for an unlocked vault. */
function unlockedLine(meta, s) {
  const line = 'Vault: unlocked (backend ' + meta.backend + ', ' + lockWhenText(s.idleMs, s.expiresAt) + (s.version ? ', zn-gate ' + s.version : '') + ')';
  return isOutdatedVault(s) ? line + ', outdated: restart with `' + znCommand('lock') + '`, then `' + znCommand('unlock') + '`' : line;
}

async function unlockCmd(args, deps) {
  const d = deps || {};
  // The arguments are checked first, before anything is asked or looked up, so a typo never waits behind a prompt.
  const problem = argumentProblem('unlock', args[0] === 'unlock' ? args.slice(1) : args);
  if (problem) { const err = usageError(problem); err.usage = 'unlock'; throw err; }
  const opts = {
    ttlMs: parseDuration(flag(args, '--ttl'), daemon.DEFAULT_TTL_MS),
    idleMs: parseDuration(flag(args, '--idle'), daemon.DEFAULT_IDLE_MS),
  };
  const asked = flag(args, '--backend');
  if (asked !== undefined && !keychain.BACKENDS.includes(asked)) throw usageError(messages.unknownBackend(asked, keychain.BACKENDS));
  const agent = d.agent !== undefined ? d.agent : agentDetected(process.env);
  if (agent) throw new Error(messages.agentRefusal(znCommand('unlock'), agent));
  // Already unlocked: say so before anything is asked. An outdated vault still goes on to the restart below.
  const running = await runningStatus(d.clientFactory);
  if (running && !isOutdatedVault(running)) throw new Error(messages.vaultAlreadyUnlocked());
  const meta = keychain.readMeta({});
  const backend = asked || (meta && meta.backend) || keychain.detectBackend();
  opts.backend = backend;
  // The keychain unlocks without asking anything, so only a terminal tells a person from a detached process.
  // (The passphrase backend needs the passphrase, which `--passphrase-stdin` reads from a pipe on purpose.)
  if (backend !== 'passphrase' && !process.stdin.isTTY) throw new Error(messages.unlockNeedsTerminal());
  if (backend === 'passphrase') opts.passphrase = await (d.getPassphrase || getPassphrase)(args, !meta);
  // An older vault still running: check the identity (passphrase or keychain)
  // before stopping it, then wait for it to exit.
  await restartIfOutdated({ verify: meta ? () => keychain.loadIdentity(opts).then(() => undefined) : null });
  if (args.includes('--foreground')) return unlockForegroundCmd(opts, backend);
  const res = await daemon.unlock(opts);
  if (res.created) out('Created a new vault (' + backend + ') in ' + store.paths().vaultDir);
  vaultReset.clearUnlockFailures({});
  out('Vault unlocked: ' + lockWhenText(opts.idleMs, res.expiresAt) + '. Run `' + znCommand('lock') + '` to lock now.');
  if (res.confirm === 'gui') out('Confirmations (first use of a secret by a command, policy changes) appear as a system dialog.');
  else {
    out('Note: no system dialog is available here, so first-use approvals and policy changes will be refused.');
    out('      To approve them, run the vault in a terminal of its own instead: ' + znCommand('lock') + ' && ' + znCommand('unlock --foreground'));
  }
  return 0;
}

async function unlockForegroundCmd(opts, backend) {
  if (!process.stdin.isTTY) throw new Error(messages.FOREGROUND_NEEDS_TERMINAL);
  const res = await daemon.unlockForeground(opts);
  if (res.created) out('Created a new vault (' + backend + ') in ' + store.paths().vaultDir);
  out('Vault unlocked: ' + lockWhenText(opts.idleMs, res.expiresAt) + '.');
  out('Keep this terminal open: zn asks here before a secret is used by a command for the first time or a policy changes.');
  out('Press Ctrl+C or run `' + znCommand('lock') + '` to lock.');
  const onSig = () => { res.close(); };
  process.on('SIGINT', onSig);
  process.on('SIGTERM', onSig);
  const reason = await res.done;
  out(messages.vaultLockedBecause(reason, Math.round(opts.idleMs / 60000)));
  return 0;
}

async function lockCmd() {
  const was = await daemon.lock({});
  out(was ? 'Vault locked.' : 'Vault was not unlocked.');
  return 0;
}

async function statusCmd() {
  const meta = keychain.readMeta({});
  if (!meta) { out('Vault: not created yet (run `' + znCommand('unlock') + '`).'); return 0; }
  const c = createClient({});
  try {
    const s = await c.status();
    out(unlockedLine(meta, s));
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
  if (unlocked) { process.stderr.write(messages.forgetLockFirst() + '\n'); return 1; }
  const real = fs.existsSync(dir) ? fs.realpathSync(dir) : dir;
  out(store.forgetProject(real) ? 'Forgot the token map of ' + real : 'No token map stored for ' + real);
  return 0;
}

async function auditVerifyCmd(args) {
  const acknowledge = (args || []).includes('--acknowledge');
  // Accepting a changed log is a decision for a person at a terminal, never an agent.
  if (acknowledge) require('../broker/tty').requireHuman('zn vault verify --acknowledge');
  const c = createClient({});
  try {
    if (acknowledge) {
      const a = await c.auditAcknowledge();
      out(a.cleared ? 'The audit log is accepted as it is now. The earlier change stays recorded as a warning in the log.' : 'Nothing to accept: the vault noticed no change to the audit log.');
      return 0;
    }
    const r = await c.auditVerify();
    if (r.ok) { out('Audit log OK: ' + r.records + ' records, chain and MACs verified.'); return 0; }
    process.stderr.write(messages.auditFailed(r.line || r.records, r.error) + '\n');
    if (r.tampered) {
      process.stderr.write('The vault keeps this warning until you look into it. Keep a copy of the audit log as evidence, then, in your own terminal, run `' + znCommand('vault verify --acknowledge') + '` to accept the log as it is now.\n');
    }
    return 1;
  } finally {
    c.close();
  }
}

/** Returns the process exit code. */
async function runVaultCommand(args) {
  try {
    const [cmd, sub] = args;
    // Options and words the command does not take are a usage error (exit 2), never silently ignored.
    const check = (name, rest, maxWords) => { const p = argumentProblem(name, rest, maxWords); return p ? usageFail(name, p) : null; };
    if (cmd === 'unlock') return await unlockCmd(args);
    if (cmd === 'lock') return check('lock', args.slice(1)) || await lockCmd();
    if (cmd === 'vault' && (sub === 'status' || sub === undefined)) return check('status', args.slice(2)) || await statusCmd();
    if (cmd === 'vault' && sub === 'forget') return check('forget', args.slice(2), 1) || await forgetCmd(args);
    if (cmd === 'vault' && sub === 'verify') return check('verify', args.slice(2)) || await auditVerifyCmd(args.slice(2));
    if (cmd === 'vault' && sub === 'reset') return check('reset', args.slice(2)) || await vaultReset.resetVault({});
    if (cmd === 'vault' && sub === 'purge') return check('purge', args.slice(2)) || await vaultPurge.purgeVault({ yes: args.includes('--yes') });
    if (cmd === 'vault' && sub === 'log') return await require('../broker/cli').dispatch('vault', args.slice(1));
    if (cmd === 'vault' && sub === 'team') {
      require('../stats').recordEvent('team-vault-request');
      process.stdout.write('A shared vault for teams is planned, not available yet. Today the vault is personal: each person keeps their own secrets on their own machine.\n' +
        'Your request was counted on this machine only (see `zn-gate stats`). Nothing was sent.\n');
      return 0;
    }
    const z = znCommand;
    process.stderr.write('usage: ' + z('unlock') + ' | ' + z('lock') + ' | ' + z('vault status') + ' | ' + z('vault verify') + ' | ' + z('vault log [--since 1h]') + ' | ' + z('vault forget [dir]') + ' | ' + z('vault reset') + ' | ' + z('vault purge') + '\n');
    return 2;
  } catch (err) {
    process.stderr.write('[zn] ' + messageWithUnlockHint(err) + '\n');
    if (err && err.usage) process.stderr.write(USAGE[err.usage]() + '\n');
    // A wrong passphrase, again and again: point to the way out.
    if (args[0] === 'unlock' && err && err.code === CODES.LOCKED) {
      const tip = vaultReset.hintForUnlockError(err, {});
      if (tip) process.stderr.write('[zn] ' + tip + '\n');
    }
    return err && err.exitCode === 2 ? 2 : 1;
  }
}

module.exports = { runVaultCommand, unlockCmd, parseDuration, getPassphrase, createHiddenPrompter, restartIfOutdated, isOutdatedVault, unlockedLine, untilText, lockWhenText };
// The sentences that name a command are built when read, so they show the form that works on this computer.
Object.defineProperties(module.exports, {
  ALREADY_UNLOCKED: { enumerable: true, get: () => messages.vaultAlreadyUnlocked() },
  OLD_VAULT_STUCK: { enumerable: true, get: oldVaultStuck },
});
