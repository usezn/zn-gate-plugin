'use strict';

/**
 * Terminal helpers for commands that only a person at the keyboard may run.
 * Values are read from a hidden TTY prompt or the clipboard, never from argv.
 */

const { spawnSync } = require('child_process');
const messages = require('../messages');

/**
 * Environment variables that coding agents set in the shells they spawn.
 * A heuristic second line of defence; the primary guard is the PreToolUse
 * hook that denies these commands, plus the TTY requirement.
 */
const AGENT_ENV_VARS = ['CLAUDECODE', 'CODEX_SANDBOX', 'CODEX_SANDBOX_NETWORK_DISABLED', 'CURSOR_AGENT', 'OPENCODE', 'ZN_AGENT'];

// Present counts, also when empty: `CLAUDECODE= zn ...` is still run from inside an agent.
function agentEnvDetected(env = process.env) {
  return AGENT_ENV_VARS.find((k) => env[k] !== undefined) || null;
}

/*
 * The agent variables, then the parent processes (an agent can remove its variables, not its process).
 * `io.ancestry` replaces the process check in tests. Returns what was detected, for the message, or null.
 */
function agentDetected(env = process.env, io = {}) {
  const v = agentEnvDetected(env);
  if (v) return v;
  const a = (io.ancestry || require('./ancestry').agentAncestor)();
  return a ? 'started from ' + a : null;
}

/* The end of a refusal, in words for someone who does not program. */
const agentNote = messages.agentNote;

/** Throws unless a person is at an interactive terminal. */
function requireHuman(what, io = {}) {
  const stdin = io.stdin || process.stdin;
  const env = io.env || process.env;
  const agent = agentDetected(env, io);
  if (agent) {
    const err = new Error(messages.agentRefusal(what, agent));
    err.code = 'ZN_POLICY_DENIED';
    throw err;
  }
  if (!stdin.isTTY) {
    const err = new Error(messages.notInteractive(what));
    err.code = 'ZN_POLICY_DENIED';
    throw err;
  }
}

/** Read one line without echo. Resolves to the string (without newline). */
function readHidden(prompt, io = {}) {
  const stdin = io.stdin || process.stdin;
  const out = io.stderr || process.stderr;
  return new Promise((resolve, reject) => {
    out.write(prompt);
    let value = '';
    const wasRaw = !!stdin.isRaw;
    if (typeof stdin.setRawMode === 'function') stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    function done(err) {
      stdin.removeListener('data', onData);
      if (typeof stdin.setRawMode === 'function') stdin.setRawMode(wasRaw);
      stdin.pause();
      out.write('\n');
      if (err) reject(err); else resolve(value);
    }
    function onData(chunk) {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done();
        if (ch === '\u0003') { const e = new Error(messages.PROMPT_CANCELLED); e.code = 'ZN_CANCELLED'; return done(e); }
        if (ch === '\u007f' || ch === '\b') { value = value.slice(0, -1); continue; }
        if (ch === '\u0015') { value = ''; continue; }
        value += ch;
      }
    }
    stdin.on('data', onData);
  });
}

/** Ask a yes/no question on the terminal. Default is no. */
function confirm(question, io = {}) {
  const stdin = io.stdin || process.stdin;
  const out = io.stderr || process.stderr;
  return new Promise((resolve) => {
    out.write(question + ' [y/N] ');
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    function onData(chunk) {
      buf += chunk;
      const nl = buf.search(/[\r\n]/);
      if (nl === -1) return;
      stdin.removeListener('data', onData);
      stdin.pause();
      resolve(/^\s*y(es)?\s*$/i.test(buf.slice(0, nl)));
    }
    stdin.on('data', onData);
  });
}

/** Read the clipboard with the platform tool. Returns a string or throws. */
function readClipboard() {
  // Absolute paths only: a clipboard tool planted on PATH would receive the value. On Windows, the system
  // PowerShell from the kernel's \\SystemRoot link, never from SystemRoot (see exe.js).
  const ps = process.platform === 'win32' ? require('../exe').systemPowerShell() : null;
  const candidates = process.platform === 'darwin'
    ? [['/usr/bin/pbpaste', []]]
    : process.platform === 'win32'
      ? (ps ? [[ps, ['-NoProfile', '-Command', 'Get-Clipboard -Raw']]] : [])
      : [['/usr/bin/wl-paste', ['--no-newline']], ['/usr/bin/xclip', ['-selection', 'clipboard', '-o']], ['/usr/bin/xsel', ['--clipboard', '--output']]];
  for (const [cmd, args] of candidates) {
    const r = spawnSync(cmd, args, { encoding: 'utf8', windowsHide: true, ...(cmd === ps ? { env: require('../exe').psEnv(ps) } : {}) });
    if (!r.error && r.status === 0) return String(r.stdout || '').replace(/\r?\n$/, '');
  }
  const err = new Error(candidates.length ? messages.clipboardUnreadable(candidates.map((c) => c[0])) : messages.CLIPBOARD_NO_POWERSHELL);
  err.code = 'ZN_UNAVAILABLE';
  throw err;
}

module.exports = { AGENT_ENV_VARS, agentEnvDetected, agentDetected, agentNote, requireHuman, readHidden, confirm, readClipboard };
