'use strict';

/**
 * Executables that receive secret values: the one place where zn decides
 * which file a command name runs.
 *
 * `zn run`, the vault client and the vault daemon all resolve, fingerprint
 * and check executables here, so the file the user approved is the file that
 * is checked and the file that is started:
 *
 *   resolveExecutable(argv0, env) -> {path, real} | null
 *       path: the PATH entry that matched; real: its real path (symlinks
 *       resolved). zn run starts `real`, never the bare name, so nothing is
 *       looked up on PATH twice.
 *   openExecutable(real) -> {fd, fp, elf}
 *       Opens the file and fingerprints the open descriptor (fstat), so the
 *       fingerprint names the file zn holds, not whatever the path points to
 *       a moment later.
 *   fingerprint(path) / fingerprintOf(stat) -> 'dev:ino:size:ctime'
 *       ctime changes on any rewrite or chmod and an unprivileged user cannot
 *       set it back, so a binary replaced in place gets a new fingerprint.
 *   writableBy(real) -> null | the first path (the file or a directory above
 *       it) that the current user can write, in the spirit of ssh StrictModes.
 *       Whoever can write there can swap the program after it was approved.
 *       zn warns about it but does not refuse: version managers (nvm, volta,
 *       pipx, Homebrew on macOS) install every tool in user-writable
 *       directories.
 *   isInterpreter(command) -> bool, isInterpreterPath(real) -> bool
 *       Programs that run any code they are given (python3.12, node22,
 *       pwsh...): approving one lets every script it runs read the secret.
 *       The daemon judges the resolved program, not only the typed name.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const isWin = process.platform === 'win32';

/* First word of a command, skipping VAR=value assignments and quotes. */
function commandWord(command) {
  const words = String(command || '').trim().split(/\s+/);
  for (const w of words) if (w && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) return w.replace(/^["']|["']$/g, '');
  return '';
}

function hasPathSeparator(s) {
  return /[\\/]/.test(String(s || ''));
}

function pathExts(env) {
  if (!isWin) return [''];
  const e = env || process.env;
  const list = String(e.PATHEXT || '').split(';').filter(Boolean).map((x) => x.toLowerCase());
  return ['', ...(list.length ? list : ['.com', '.exe', '.bat', '.cmd'])];
}

function envPath(env) {
  const e = env || process.env;
  return String(e.PATH || e.Path || '');
}

function candidates(name, env) {
  let exts = pathExts(env);
  // Windows runs a name as written only when it already has a PATHEXT
  // extension: an extensionless file next to its .cmd (npm puts a shell
  // script `claude` beside `claude.cmd`) is not a program there.
  if (isWin && !exts.slice(1).includes(path.extname(name).toLowerCase())) exts = exts.slice(1);
  const out = [];
  if (hasPathSeparator(name)) {
    for (const x of exts) out.push(path.resolve(name + x));
    return out;
  }
  for (const dir of envPath(env).split(path.delimiter)) {
    if (!dir) continue;
    for (const x of exts) out.push(path.join(dir, name + x));
  }
  return out;
}

/**
 * The file argv0 runs on the given PATH: a regular file that is executable
 * (POSIX). Returns {path, real} or null.
 */
function resolveExecutable(argv0, env) {
  const name = commandWord(argv0);
  if (!name) return null;
  for (const c of candidates(name, env)) {
    try {
      const st = fs.statSync(c);
      if (!st.isFile()) continue;
      if (!isWin) fs.accessSync(c, fs.constants.X_OK);
      return { path: c, real: fs.realpathSync(c) };
    } catch (_) { /* next */ }
  }
  return null;
}

/** Locate a program on PATH (for finding agent CLIs; no executable check). */
function whichSync(cmd, pathValue) {
  if (hasPathSeparator(cmd)) return fs.existsSync(cmd) ? path.resolve(cmd) : null;
  for (const c of candidates(cmd, { PATH: pathValue, PATHEXT: process.env.PATHEXT })) {
    try {
      if (fs.statSync(c).isFile()) return c;
    } catch (_) { /* keep looking */ }
  }
  return null;
}

/* The form approvals are stored under: case-insensitive on Windows. */
function approvalPath(real) {
  return isWin ? String(real).toLowerCase() : String(real);
}

function fingerprintOf(st) {
  return [st.dev, st.ino, st.size, Math.round(st.ctimeMs)].join(':');
}

function fingerprint(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return null;
    return fingerprintOf(st);
  } catch (_) {
    return null;
  }
}

/* What a fingerprint says about the file, for messages. */
function describeFingerprint(fp) {
  const parts = String(fp || '').split(':');
  if (parts.length !== 4) return null;
  const size = Number(parts[2]);
  const ctime = Number(parts[3]);
  return {
    size: Number.isFinite(size) ? size : null,
    changed: Number.isFinite(ctime) ? new Date(ctime).toISOString().replace(/\.\d+Z$/, 'Z') : null,
  };
}

/**
 * Open an executable for the final check before it is started. The caller
 * closes fd. elf is true for native Linux/ELF programs, which can be started
 * through the open descriptor itself (see execPath).
 */
function openExecutable(real) {
  const fd = fs.openSync(real, 'r');
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw Object.assign(new Error('not a regular file: ' + real), { code: 'ZN_NOT_FOUND' });
    let elf = false;
    if (process.platform === 'linux') {
      const head = Buffer.alloc(4);
      const n = fs.readSync(fd, head, 0, 4, 0);
      elf = n === 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
    }
    return { fd, fp: fingerprintOf(st), elf };
  } catch (err) {
    try { fs.closeSync(fd); } catch (_) { /* ignore */ }
    throw err;
  }
}

/**
 * Last check before starting the program: the open descriptor still has the
 * expected fingerprint (nothing rewrote the file) and the path still names
 * that same file (nothing swapped it or a directory above it). Returns null
 * or the reason it failed.
 */
function verifyOpen(opened, real, expectedFp) {
  let now;
  try { now = fingerprintOf(fs.fstatSync(opened.fd)); } catch (_) { return 'the program could not be checked'; }
  if (now !== expectedFp) return 'the program changed after it was checked';
  if (fingerprint(real) !== now) return 'the path now leads to a different file';
  return null;
}

/**
 * What to pass to spawn() for an opened, verified executable. On Linux a
 * native (ELF) program is started through /proc/self/fd/<fd>: the kernel runs
 * exactly the file zn opened and checked, whatever happens to its path. The
 * descriptor is close-on-exec, so the program does not inherit it. Scripts
 * (their interpreter opens the script by path again) and other systems start
 * the real path right after verifyOpen().
 */
function execPath(opened, real) {
  if (opened && opened.elf && process.platform === 'linux' && fs.existsSync('/proc/self/fd')) return '/proc/self/fd/' + opened.fd;
  return real;
}

function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!!rel && !rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * The first path the current user can write among the executable and the
 * directories above it, or null. POSIX: access(W_OK) on each. Windows has no
 * cheap equivalent (ACLs), so anything under the user profile or the temp
 * directory counts as writable.
 */
function writableBy(real) {
  if (!real) return null;
  if (isWin) {
    const roots = [os.homedir(), os.tmpdir(), process.env.LOCALAPPDATA, process.env.APPDATA].filter(Boolean);
    for (const r of roots) {
      if (isInside(String(real).toLowerCase(), path.resolve(r).toLowerCase())) return path.resolve(r);
    }
    return null;
  }
  let cur = path.resolve(real);
  for (;;) {
    try {
      fs.accessSync(cur, fs.constants.W_OK);
      return cur;
    } catch (_) { /* not writable: keep going up */ }
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

/* --------------------------- interpreters --------------------------- */

const INTERPRETER_BASES = new Set([
  'node', 'nodejs', 'deno', 'bun', 'tsx', 'ts-node',
  'python', 'py', 'pypy', 'pythonw', 'ruby', 'irb', 'perl', 'php', 'lua', 'luajit', 'tclsh', 'wish',
  'r', 'rscript', 'julia', 'osascript', 'groovy', 'groovysh', 'jshell',
  'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'mksh', 'csh', 'tcsh', 'busybox', 'pwsh', 'powershell', 'cmd', 'wsl',
  'npm', 'npx', 'pnpm', 'pnpx', 'yarn', 'corepack', 'make', 'cargo', 'go', 'java', 'dotnet', 'gradle', 'gradlew', 'mvn',
  'uv', 'uvx', 'pipx', 'poetry', 'pipenv', 'rake', 'bundle', 'awk', 'gawk', 'env', 'xargs', 'sudo', 'doas',
  'nohup', 'timeout', 'nice', 'watch', 'script', 'expect',
]);

/**
 * Name of a program without directory, extension or version suffix:
 * python3.12m -> python, /usr/bin/node22 -> node, C:\Python\pythonw.exe -> pythonw.
 * Takes a file path (spaces allowed), so it never splits on whitespace.
 */
function programBase(file) {
  const b = String(file || '').split(/[\\/]/).pop().toLowerCase().replace(/\.(exe|cmd|bat|com)$/, '');
  // No file system allows a name longer than 255 characters, so such a word
  // cannot name a program; skipping it keeps the suffix pattern below linear.
  if (b.length > 255) return b;
  return b.replace(/[-_]?(?:v?\d+(?:[._-]\d+)*[a-z]?)?(?:[-_](?:preview|beta|nightly))?$/, '');
}

/** The first word of a typed command (`python3.12 script.py`) as a program name. */
function interpreterBase(command) {
  return programBase(String(command || '').trim().split(/\s+/)[0]);
}

/** A typed command word (`python3.12 script.py`): only the first word counts. */
function isInterpreter(command) {
  return INTERPRETER_BASES.has(interpreterBase(command));
}

/**
 * The program that actually runs: the resolved real path, so a symlink is
 * judged by the file it points to. A copy under another name is judged by
 * its own name only.
 */
function isInterpreterPath(file) {
  return INTERPRETER_BASES.has(programBase(file));
}

/*
 * The system PowerShell (Windows PowerShell 5.1), from the kernel's \\SystemRoot link, as broker/run.js finds
 * cmd.exe: never from SystemRoot, PATH or the current directory, which the agent that runs zn controls. It is
 * resolved twice, so a drive letter remapped in this logon session is refused too. The path, or null (also on
 * every other system).
 */
function systemPowerShell() {
  if (process.platform !== 'win32') return null;
  let ps;
  try { ps = fs.realpathSync.native('\\\\?\\GLOBALROOT\\SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'); } catch (_) { return null; }
  if (!/^[A-Za-z]:\\[^%!"]+\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$/i.test(ps)) return null;
  try { if (fs.realpathSync.native(ps).toLowerCase() !== ps.toLowerCase()) return null; } catch (_) { return null; }
  return ps;
}

module.exports = {
  systemPowerShell,
  commandWord,
  hasPathSeparator,
  resolveExecutable,
  whichSync,
  approvalPath,
  fingerprint,
  fingerprintOf,
  describeFingerprint,
  openExecutable,
  verifyOpen,
  execPath,
  isInside,
  writableBy,
  interpreterBase,
  isInterpreter,
  isInterpreterPath,
};
