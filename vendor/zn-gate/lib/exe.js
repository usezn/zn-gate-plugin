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

/*
 * Programs zn itself starts by name (git, sh, an MCP server's command, claude) come from the absolute PATH entries only:
 * a relative or empty entry depends on the folder zn runs in, which is often a project, and so does the current folder,
 * which Windows (cmd.exe, and Node's own lookup) searches first. absolutePath keeps those entries (C:\ or \\server on
 * Windows), programEnv is an environment with that PATH (and no current-folder search on Windows), and findProgram
 * gives the program's absolute path or null (a name with a path in it is used as written); on Windows only an .exe or
 * .com, which starts without a shell.
 */
function absolutePath(pathValue, platform = process.platform, where = {}) {
  const win = platform === 'win32';
  const sep = win ? ';' : ':';
  const keep = (d) => (win ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(d) : d.startsWith('/'));
  const abs = String(pathValue || '').split(sep).filter(keep).join(sep);
  // Spelled for another system (tests): only the lexical rule applies, the places are not on this disk.
  return platform === process.platform ? trustedPath(abs, where.cwd, where.env, platform) : abs;
}

/*
 * An absolute PATH entry can still point into the project zn runs in: its bin/, node_modules/.bin, a folder direnv adds.
 * trustedPath drops the entries whose real path is in the folder zn runs in (`cwd`), the git work tree around it, the
 * project the agent names (CLAUDE_PROJECT_DIR) or a node_modules folder, the rule of the plugins' zn-node.sh. The home
 * folder and the folders above it are never the project (a Node.js from nvm or volta there stays). Real paths and the
 * work tree are looked up once per process: this runs on every hook.
 */
const REAL_KEYS = new Map();
function realKey(p, win) {
  let r = REAL_KEYS.get(p);
  if (r === undefined) {
    r = path.resolve(p);
    try { r = fs.realpathSync.native(r); } catch (_) { /* not there: as written */ }
    if (win) r = r.toLowerCase();
    if (REAL_KEYS.size > 512) REAL_KEYS.clear();
    REAL_KEYS.set(p, r);
  }
  return r;
}

function insideOrSame(p, dir) {
  const rel = path.relative(dir, p);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

const GIT_ROOTS = new Map();
function gitRootOf(dir) {
  const start = path.resolve(dir);
  if (GIT_ROOTS.has(start)) return GIT_ROOTS.get(start);
  let root = null;
  for (let cur = start; ; cur = path.dirname(cur)) {
    try { if (fs.existsSync(path.join(cur, '.git'))) { root = cur; break; } } catch (_) { /* keep going */ }
    if (path.dirname(cur) === cur) break;
  }
  if (GIT_ROOTS.size > 64) GIT_ROOTS.clear();
  GIT_ROOTS.set(start, root);
  return root;
}

/* The folders a program must not come from: the folder zn runs in, its git work tree and the agent's project. */
function projectPlaces(cwd, env, win) {
  const e = env || process.env;
  const here = cwd || process.cwd();
  const home = realKey(e.HOME || e.USERPROFILE || os.homedir(), win);
  const out = [];
  for (const d of [here, gitRootOf(here), e.CLAUDE_PROJECT_DIR]) {
    if (!d || !path.isAbsolute(String(d))) continue;
    const k = realKey(String(d), win);
    if (!insideOrSame(home, k) && !out.includes(k)) out.push(k);
  }
  return out;
}

// A PATH entry (a folder) is untrusted in the project or in any node_modules folder (node_modules/.bin).
function untrustedPlace(real, places) {
  return inProject(real, places) || /(^|[\\/])node_modules([\\/]|$)/i.test(real);
}

// The real file a program name resolves to counts only against the project: a global npm install (npm, nvm, Homebrew,
// fnm) links bin/<prog> to ../lib/node_modules/<package>/..., which is not the project, while a link into the
// project's own node_modules still is.
function inProject(real, places) {
  return places.some((d) => insideOrSame(real, d));
}

// The node_modules folder right in the home folder: packages installed with a package.json in ~, never a global install
// (those live under a prefix such as /usr/local, ~/.nvm or ~/.npm-global). Counts as the project for a program's real file.
function inHomeModules(real, env, win) {
  const e = env || process.env;
  return insideOrSame(real, realKey(path.join(e.HOME || e.USERPROFILE || os.homedir(), 'node_modules'), win));
}

/** Whether the real file of a program found on the PATH is in the project (cwd, its git work tree, CLAUDE_PROJECT_DIR) or in
 * the home folder's node_modules: a link from a trusted PATH folder into there counts as the project's program. */
function programInProject(file, env = process.env, cwd, platform = process.platform) {
  const win = platform === 'win32';
  const real = realKey(file, win);
  return inProject(real, projectPlaces(cwd, env, win)) || inHomeModules(real, env, win);
}

function trustedPath(pathValue, cwd, env, platform = process.platform) {
  const win = platform === 'win32';
  const sep = win ? ';' : ':';
  const places = projectPlaces(cwd, env, win);
  const absolute = (d) => (win ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(d) : d.startsWith('/'));
  return String(pathValue || '').split(sep).filter((d) => d && absolute(d) && !untrustedPlace(realKey(d, win), places)).join(sep);
}

function pathOf(env) {
  const e = Object.entries(env || {}).find(([k]) => k.toUpperCase() === 'PATH');
  return e ? String(e[1] || '') : '';
}

function programEnv(env = process.env, platform = process.platform, cwd) {
  const out = {};
  for (const [k, v] of Object.entries(env || {})) if (k.toUpperCase() !== 'PATH') out[k] = v;
  out.PATH = absolutePath(pathOf(env), platform, { cwd, env });
  if (platform === 'win32') out.NoDefaultCurrentDirectoryInExePath = '1';
  return out;
}

/* opts.strict: the real file may not be in any node_modules folder either: the rule of the plugins' zn-node.sh, which
 * zn-gate check mirrors for the node the plugin hooks start. */
function findProgram(name, env = process.env, cwd, opts = {}) {
  if (hasPathSeparator(name)) return name;
  const file = isWin && !/\.(?:exe|com)$/i.test(name) ? name + '.exe' : name;
  const places = projectPlaces(cwd, env, isWin);
  for (const dir of absolutePath(pathOf(env), process.platform, { cwd, env }).split(path.delimiter)) {
    if (!dir) continue;
    const found = whichSync(file, dir);
    // A program that links into the project counts as the project's.
    const real = found && realKey(found, isWin);
    if (found && (!isWin || /\.(?:exe|com)$/i.test(found)) && !(opts.strict ? untrustedPlace(real, places) : (inProject(real, places) || inHomeModules(real, env, isWin)))) return path.resolve(found);
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
 * through the open descriptor itself (see execPath). script is true for a
 * file that starts with `#!` (POSIX): the kernel hands its path to the
 * interpreter, which opens it again (see scriptRisk).
 */
function openExecutable(real) {
  const fd = fs.openSync(real, 'r');
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw Object.assign(new Error('not a regular file: ' + real), { code: 'ZN_NOT_FOUND' });
    let elf = false;
    let script = isWin && /\.(cmd|bat)$/i.test(real);
    if (!isWin) {
      const head = Buffer.alloc(4);
      const n = fs.readSync(fd, head, 0, 4, 0);
      elf = process.platform === 'linux' && n === 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46;
      script = n >= 2 && head[0] === 0x23 && head[1] === 0x21;
    }
    return { fd, fp: fingerprintOf(st), elf, script };
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
 * A `#!` script (on Windows, a .cmd or .bat file) is started by path: the
 * kernel passes that path to the interpreter, which opens the file again after
 * verifyOpen(), so the check covers a moment that is already over. Whoever can
 * rewrite the script, or a folder above it, in that window could swap it. Two
 * cases are told apart:
 *
 *   - Unsafe: group or others can write the script or a folder above it (a
 *     sticky folder such as /tmp does not count), or the script or a folder
 *     above it belongs to another account (neither root nor the current user).
 *     On Windows: the file or a folder above it lets another principal write,
 *     or is owned by one. The script must not receive secret values.
 *   - Own: only the current user (or an administrator) can write it, as with
 *     scripts installed by nvm, Homebrew, pnpm, pipx or a virtual environment.
 *     It is allowed with a warning: another program running as the same user
 *     can still swap it in that window, which is the same trust zn already
 *     places in everything that runs as you.
 *
 * Returns {deny, warn} or null. deny is the first unsafe path with the reason
 * (or null), warn is the first path only the current user can write (or null).
 * null means nothing to say: not a script, or nobody but root can change it.
 * On Windows the answer is read once per descriptor (it needs PowerShell).
 */
function scriptRisk(opened, real, o) {
  const opt = o || {};
  if (!opened || !opened.script || !real) return null;
  const win = opt.platform ? opt.platform === 'win32' : isWin;
  if (win) {
    if (opened.risk !== undefined && !opt.tools) return opened.risk;
    const r = require('./vault/winacl').scriptWriteRisk(real, { tools: opt.tools });
    const out = r.deny || r.warn ? { deny: r.deny, warn: r.warn } : null;
    if (!opt.tools) opened.risk = out;
    return out;
  }
  const me = typeof process.getuid === 'function' ? process.getuid() : -1;
  let cur = path.resolve(real);
  let warn = null;
  for (;;) {
    let st;
    try { st = fs.statSync(cur); } catch (_) { return { deny: cur + ' (it could not be checked)', warn }; }
    const sticky = st.isDirectory() && (st.mode & 0o1000) !== 0;
    if (st.uid !== 0 && st.uid !== me) return { deny: cur + ' (it belongs to another account)', warn };
    if ((st.mode & 0o022) !== 0 && !sticky) return { deny: cur + ' (group or others can write it)', warn };
    if (!warn && me !== 0 && st.uid === me && !sticky) {
      try { fs.accessSync(cur, fs.constants.W_OK); warn = cur; } catch (_) { /* not writable by us */ }
    }
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return warn ? { deny: null, warn } : null;
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

/*
 * The PSModulePath to give the system PowerShell: its own module folder only. Without a PSModulePath Windows PowerShell 5.1
 * builds one that starts with the user's Documents\WindowsPowerShell\Modules, where a module planted by the same account would
 * replace a cmdlet (ConvertTo-Json, Get-Acl...). `ps` is the path systemPowerShell() returned.
 */
function systemPsModulePath(ps) {
  return path.win32.join(path.win32.dirname(ps), 'Modules');
}

/*
 * The environment for a PowerShell that zn starts: `base` (default the process environment) plus `extra`, with EVERY case variant
 * of PSModulePath removed first and zn's own set once. Windows environment names are case-insensitive but a JS object's keys are
 * not, so an inherited PSMODULEPATH next to a PSModulePath would reach the child as two entries, and the one that wins is not ours.
 */
function psEnv(ps, base, extra) {
  const env = {};
  for (const k of Object.keys(base || process.env)) if (!/^psmodulepath$/i.test(k)) env[k] = (base || process.env)[k];
  for (const k of Object.keys(extra || {})) if (!/^psmodulepath$/i.test(k)) env[k] = extra[k];
  env.PSModulePath = systemPsModulePath(ps);
  return env;
}

module.exports = { programInProject,
  absolutePath,
  projectPlaces,
  trustedPath,
  programEnv,
  findProgram,
  systemPowerShell,
  systemPsModulePath,
  psEnv,
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
  scriptRisk,
  isInside,
  writableBy,
  interpreterBase,
  isInterpreter,
  isInterpreterPath,
};
