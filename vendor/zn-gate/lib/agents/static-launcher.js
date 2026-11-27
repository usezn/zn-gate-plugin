'use strict';

/**
 * The static hook launcher (tools/hook-launcher): a small statically linked program that zn puts in front of the hook on Linux,
 * for the agents that can start a hook program directly, with no shell: Claude Code (a hook with `args`), ZCode (a `process`
 * hook) and Antigravity (the command split on spaces).
 *
 * Why: every dynamically linked program (sh, bash, node) goes through the dynamic loader first, and the loader reads variables
 * from the environment the agent passes on. With LD_TRACE_LOADED_OBJECTS (any value) or LD_DEBUG naming `help` the loader prints
 * text and exits 0 before the hook's first line, and those agents read exit 0 with plain text as "no objection". A statically
 * linked program has no loader, so the launcher runs first, refuses (the deny of the agent and its blocking exit code) when one
 * of those variables or a preload variable is set, and otherwise removes every loader variable and replaces itself with the hook.
 *
 * Shipping: the npm package carries prebuilt binaries in lib/native/<platform>/zn-hook-launcher, built in the release workflow
 * from tools/hook-launcher, and lib/native/hook-launcher.json with the SHA-256 of each one. The installer copies the binary for
 * this machine into zn's hooks folder (next to the launcher scripts, so it outlives an update or removal of the package) only
 * when its SHA-256 matches, then gives it a test run, and puts it in the hook only when that run answers as expected. A copy
 * whose run fails stays in place (hooks written earlier may name it), the hook keeps today's form, and the install says plainly
 * that this protection is not there. macOS and Windows have no such launcher (see docs/threat-model.md).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { writeFileAtomic } = require('../broker/files');
const { shQuote } = require('../shell-quote');

const NAME = 'zn-hook-launcher';
// The agents whose user hooks start through the launcher on Linux: the one list. An adapter asks for the launcher with its id
// (useStatic), and an id that is not in STATIC_ENABLED keeps today's hook form. GitHub Copilot is not here on purpose: it is detection only.
const STATIC_AGENTS = ['claude-code', 'zcode', 'antigravity'];
// The agents that actually get it, on Linux: only those whose hook start with no shell was observed with the real agent. ZCode's
// `process` hook is one, and so is Claude Code's exec form (`args`), run against Claude Code 2.1.331 on x86_64 Linux: the hook's parent
// was Claude Code itself, a loader variable in its settings was refused by the launcher before any dynamic program started, and the
// old shell form let the same call run unchecked. Antigravity's start with no shell was seen on Windows only, so it keeps today's hook
// form (detection only) until a run with the real agent on Linux shows the launcher is started directly. The launcher program already
// answers for it, so enabling it later is a change to this list and its docs.
const STATIC_ENABLED = ['zcode', 'claude-code'];

/** The platform key of the prebuilt binary for this system, '' when none is built for it, null when the system needs none. */
function platformKey(platform = process.platform, arch = process.arch) {
  if (platform !== 'linux') return null;
  return arch === 'x64' ? 'linux-x64' : arch === 'arm64' ? 'linux-arm64' : '';
}

function nativeDir(opts = {}) {
  return opts.nativeDir || path.join(__dirname, '..', 'native');
}

/** Where the launcher is installed: zn's hooks folder (the same folder as the launcher scripts). */
function staticFile(opts = {}) {
  return path.join(require('./launcher').launcherDir(opts), NAME);
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function warningText(why) {
  return 'zn could not set up its static hook launcher on this machine (' + why + '), so the hook starts as before, through a dynamically linked program: ' +
    'a loader variable in the agent\'s environment (LD_TRACE_LOADED_OBJECTS, or LD_DEBUG with help) can still stop the hook before it runs and let the call through. ' +
    'Install zn-gate again from npm (npm install -g zn-gate) and run this command again to get it.';
}

/** The prebuilt binary of this package for this system: {bytes, sha256} or {why}. Nothing is run or written. */
function bundled(key, opts = {}) {
  const dir = nativeDir(opts);
  let list;
  try { list = JSON.parse(fs.readFileSync(path.join(dir, 'hook-launcher.json'), 'utf8')); } catch (_) { return { why: 'this copy of zn-gate has no prebuilt launcher list' }; }
  const want = list && typeof list === 'object' ? list[key] : undefined;
  if (typeof want !== 'string' || !/^[0-9a-f]{64}$/.test(want)) return { why: 'this copy of zn-gate has no prebuilt launcher for ' + key };
  let bytes;
  try {
    const file = path.join(dir, key, NAME);
    if (!fs.lstatSync(file).isFile()) return { why: 'the prebuilt launcher for ' + key + ' is not a regular file' };
    bytes = fs.readFileSync(file);
  } catch (_) { return { why: 'the prebuilt launcher for ' + key + ' is missing from this copy of zn-gate' }; }
  if (sha256(bytes) !== want) return { why: 'the prebuilt launcher for ' + key + ' does not match its recorded SHA-256' };
  return { bytes, sha256: want };
}

/**
 * Copies the launcher for this machine into the hooks folder (which the caller has already created and checked, see
 * launcher.writeLauncher). Returns null where the system needs none (not Linux), {file} when it is in place and answered a test
 * run, or {warning} (the hook must keep today's form). Never throws.
 */
function installStatic(opts = {}) {
  const key = platformKey(opts.platform || process.platform, opts.arch || process.arch);
  if (key === null) return null;
  if (!key) return { warning: warningText('no prebuilt launcher is built for ' + (opts.arch || process.arch) + ' Linux') };
  const b = bundled(key, opts);
  if (!b.bytes) return { warning: warningText(b.why) };
  const file = staticFile(opts);
  try {
    // The hooks folder: created private, or, when ZN_HOOK_DIR names it, checked like the folder of the launcher scripts.
    const dir = path.dirname(file);
    if ((opts.env || process.env).ZN_HOOK_DIR) require('./launcher').ensureSafeHookDir(dir, opts.platform || process.platform, { trustedRoot: opts.hookDirTrustedRoot });
    else fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileAtomic(file, b.bytes, 0o755);
    fs.chmodSync(file, 0o755);
    if (sha256(fs.readFileSync(file)) !== b.sha256) throw new Error('the copy differs from the prebuilt launcher');
  } catch (e) {
    return { warning: warningText('it could not be written to ' + path.dirname(file) + ': ' + (e && e.message ? e.message : String(e))) };
  }
  // A test run: a hook program that does not exist must end in the launcher's own block (ZCode PreToolUse: exit 2 with the reason).
  // This also finds a folder where programs cannot run (noexec) or a binary this kernel cannot start.
  const r = spawnSync(file, ['zcode', 'PreToolUse', path.join(path.dirname(file), '.zn-no-such-hook')], { encoding: 'utf8', env: {}, timeout: 10000, input: '' });
  // The file is left in place: hooks written earlier may name it, and a missing program would let their calls run.
  if (r.status !== 2 || !/its hook failed, so this was blocked/.test(r.stderr || '')) {
    return { warning: warningText('the launcher did not answer its test run') };
  }
  return { file };
}

/**
 * The installed launcher for an adapter: its path, or null when the hook must keep today's form. A warning that says why is
 * added to `notes` (the install report), so the install never claims a protection that is not there.
 */
function useStatic(opts = {}, notes = [], agentId = '') {
  if (!STATIC_ENABLED.includes(agentId)) return null;
  const r = installStatic(opts);
  if (!r) return null;
  if (r.warning) { notes.push(r.warning); return null; }
  return r.file;
}

/** The words of an exec-form hook: the launcher, the agent, the event, then the hook program and its arguments. */
function execParts(file, agentId, event, program, args = []) {
  if (!STATIC_AGENTS.includes(agentId)) throw new Error('zn: no static launcher for ' + agentId);
  return [file, agentId, event, program, ...args];
}

/** True when a program path names the static launcher. */
function isStaticLauncher(p) {
  return typeof p === 'string' && path.posix.basename(p) === NAME && p.startsWith('/');
}

/**
 * An exec-form hook (program + arguments) as one readable command line, for `zn-gate check` and the "is this ours" tests:
 * the program and every path are quoted the way the launcher command of the other agents is; plain words are left bare.
 */
function execText(parts) {
  return parts.map((w, i) => (i === 0 || /[^A-Za-z0-9._-]/.test(String(w)) ? shQuote(String(w)) : String(w))).join(' ');
}

module.exports = { NAME, STATIC_AGENTS, STATIC_ENABLED, platformKey, staticFile, bundled, installStatic, useStatic, execParts, execText, isStaticLauncher };
