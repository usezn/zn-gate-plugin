#!/usr/bin/env node
'use strict';

/**
 * zn-gate plugin launcher.
 *
 * Every hook and MCP server of this plugin goes through this file:
 *
 *   node zn-launch.js hook <agent>     agent hook (event JSON on stdin)
 *   node zn-launch.js secrets-mcp      the "secrets" MCP server (stdio)
 *   node zn-launch.js zn-gate-mcp [claude-code]
 *                                     the "zn-gate" MCP server (stdio): local
 *                                     rules only, unless started for Claude Code
 *                                     with the plugin's api_key option set; then
 *                                     analyze_prompt text (secrets redacted) also
 *                                     goes to api.usezn.com
 *   node zn-launch.js check [agent]    report the installation status; never blocks
 *
 * It does not download, install or update anything. Claude Code installs
 * the zn-gate release pinned by this plugin's package-lock.json into the
 * plugin's own node_modules when the plugin is installed; other agents use
 * a copy the user installed. On every run it:
 *
 *  1. finds the zn-gate package (see candidates);
 *  2. walks the whole package directory and requires it to hold exactly the
 *     files listed in zn-gate.lock.json: no extra file or directory, no
 *     symbolic link, nothing missing, every file with the SHA-256 digest of
 *     the published release;
 *  3. loads zn-gate's hook runner or MCP server from the bytes it just
 *     verified, held in memory, with a module loader that resolves only
 *     within the verified file set. Nothing zn-gate loads in this process is
 *     read from disk again after the check.
 *
 * Any failure, including an exception thrown by zn-gate itself or an exit
 * code other than 0 or 2, refuses the hook event with a message that says how
 * to fix it, and keeps the MCP server from starting. A tool call or prompt is
 * refused with exit code 2; tool output is replaced by a "withheld" note in
 * the agent's own format, because on exit 2 Claude Code and Codex still pass
 * the original output to the model (see refusalFor). The user can let hook events pass instead
 * with {"hooks": {"whenUnavailable": "allow"}} in ~/.zn/config.json.
 *
 * What this does not protect against (see the plugin README):
 *  - Child processes zn-gate starts (the vault daemon, `zn run`, the stream
 *    scrubber) and the ES modules of its bundled dependencies are loaded from
 *    disk by Node after the check, so a change made in between is not seen.
 *  - Whoever controls the environment the agent starts hooks with decides
 *    which `node` runs this file, can preload code with NODE_OPTIONS before
 *    this file starts, and chooses the PATH used to find zn-gate (only an
 *    exact copy of the pinned release passes the check).
 *  - Code running as the user can edit this plugin or ~/.zn/config.json.
 * It reduces what a prompt-injected agent can do through its own tools; it
 * is not a sandbox.
 *
 * No dependencies; Node.js 20.12 or later.
 */

const crypto = require('crypto');
const fs = require('fs');
const Module = require('module');
const os = require('os');
const path = require('path');
const url = require('url');
const vm = require('vm');

const LOCK_FILE = path.join(__dirname, 'zn-gate.lock.json');
// vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER: Node.js 20.12 / 21.7 and later,
// marked experimental in Node's documentation. Without it the launcher
// refuses to run (hooks exit 2, the MCP server does not start) rather than
// load zn-gate another way. CI tests the versions in .github/workflows/plugins.yml.
const NODE_OK = !!(vm.constants && vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER);
const NODE_HINT = 'the zn-gate plugin needs Node.js 20.12 or later with vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER (this is ' + process.version + ').';
const SUPPORTED_AGENTS = new Set(['claude-code', 'codex', 'cursor']);

// zn-gate starts child processes with this process's environment; a preload
// set through NODE_OPTIONS or a module path in NODE_PATH must not reach them.
delete process.env.NODE_OPTIONS;
delete process.env.NODE_PATH;
// Claude Code exports every plugin option, sensitive ones included, to hook
// processes as CLAUDE_PLUGIN_OPTION_<NAME>. zn-gate never needs them, and the
// API key must not reach the hooks or the processes they start.
for (const k of Object.keys(process.env)) if (/^CLAUDE_PLUGIN_OPTION_/i.test(k)) delete process.env[k];

/* The account's home directory from the user database, not from $HOME. */
function homeDir() {
  try {
    const h = os.userInfo().homedir;
    if (h) return h;
  } catch (_) { /* no passwd entry (some containers) */ }
  return os.homedir();
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return null;
  }
}

function znConfig() {
  return readJson(path.join(homeDir(), '.zn', 'config.json')) || {};
}

// A plugin built with zn-gate inside it ("bundled" in the lock file) uses only
// that copy, at this fixed path under the plugin folder.
const BUNDLED_DIR = 'vendor/zn-gate';

function loadLock() {
  const lock = readJson(LOCK_FILE);
  if (!lock || lock.package !== 'zn-gate' || typeof lock.version !== 'string' || !lock.files || typeof lock.files !== 'object' ||
      ('bundled' in lock && lock.bundled !== BUNDLED_DIR)) {
    throw new Error('the plugin lock file (scripts/zn-gate.lock.json) is missing or invalid');
  }
  return lock;
}

function installHint(lock) {
  if (lock.bundled) return 'Reinstall the zn-gate plugin to restore its copy of zn-gate ' + lock.version + '.';
  return 'In Claude Code, the plugin installs it: make sure npm is on your PATH, then run ' +
    'claude plugin update zn-gate@usezn and start a new session. In other agents, install the pinned release with: ' +
    'npm install -g zn-gate@' + lock.version + ' && npm audit signatures (see the plugin README).';
}

/* ----------------------------- lookup ----------------------------- */

function isPackageDir(dir) {
  const pkg = readJson(path.join(dir, 'package.json'));
  return !!(pkg && pkg.name === 'zn-gate');
}

/**
 * Candidate package directories, in order:
 *   1. "plugin": {"packageDir": "<dir>"} in ~/.zn/config.json (only that one);
 *   2. node_modules/zn-gate in the plugin's own directory, where Claude Code
 *      installs the release pinned by the plugin's package-lock.json;
 *   3. for each PATH entry with a zn-gate executable, the npm global layouts
 *      of Linux and macOS (<prefix>/bin -> <prefix>/lib/node_modules) and of
 *      Windows (<prefix>\zn-gate.cmd next to <prefix>\node_modules).
 * Every candidate must still match the lock file exactly (see verify).
 */
function candidates(lock) {
  // Bundled: only the copy inside the plugin (no ~/.zn/config.json packageDir, no PATH).
  if (lock && lock.bundled) return [path.resolve(__dirname, '..', ...BUNDLED_DIR.split('/'))];
  const cfg = znConfig();
  if (cfg.plugin && typeof cfg.plugin.packageDir === 'string') return [path.resolve(cfg.plugin.packageDir)];
  const out = [path.resolve(__dirname, '..', 'node_modules', 'zn-gate')];
  const dirs = String(process.env.PATH || '').split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    const bin = path.join(dir, 'zn-gate');
    try {
      out.push(path.resolve(path.dirname(fs.realpathSync(bin)), '..'));
    } catch (_) { /* not here */ }
    if (fs.existsSync(bin + '.cmd')) out.push(path.join(dir, 'node_modules', 'zn-gate'));
    if (fs.existsSync(bin)) out.push(path.resolve(dir, '..', 'lib', 'node_modules', 'zn-gate'));
  }
  return [...new Set(out)];
}

/* --------------------------- verification --------------------------- */

/**
 * Read the whole package tree and compare it with the lock file.
 * Returns {files: Map<rel, Buffer>} or {error}.
 */
function readVerified(dir, lock) {
  const expected = lock.files;
  const dirs = new Set(['']);
  for (const rel of Object.keys(expected)) {
    const parts = rel.split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  const files = new Map();
  const problems = [];
  const walk = (rel) => {
    const abs = rel ? path.join(dir, ...rel.split('/')) : dir;
    let names;
    try {
      names = fs.readdirSync(abs);
    } catch (err) {
      problems.push('cannot read ' + (rel || '.') + ' (' + err.code + ')');
      return;
    }
    for (const name of names) {
      const r = rel ? rel + '/' + name : name;
      const st = fs.lstatSync(path.join(abs, name));
      if (st.isSymbolicLink()) problems.push(r + ' is a symbolic link');
      else if (st.isDirectory()) {
        if (dirs.has(r)) walk(r);
        else problems.push('unexpected directory ' + r);
      } else if (st.isFile()) {
        if (!Object.prototype.hasOwnProperty.call(expected, r)) problems.push('unexpected file ' + r);
        else {
          const buf = fs.readFileSync(path.join(abs, name));
          if (crypto.createHash('sha256').update(buf).digest('hex') !== expected[r]) problems.push(r + ' was changed');
          else files.set(r, buf);
        }
      } else problems.push(r + ' is not a regular file');
      if (problems.length) return;
    }
  };
  walk('');
  if (!problems.length) {
    const missing = Object.keys(expected).find((r) => !files.has(r));
    if (missing) problems.push(missing + ' is missing');
  }
  if (problems.length) return { error: problems[0] };
  return { files };
}

/**
 * Find the package and verify it. Every candidate is tried; the first one
 * that matches the lock file wins. Returns {dir, files} or {error}.
 */
function verify(lock) {
  if (!NODE_OK) return { error: NODE_HINT };
  if (Object.keys(lock.files).length === 0) {
    return { error: 'this plugin build has no file digests for zn-gate ' + lock.version + ' (development build), so it cannot run. ' +
      'Use a released plugin version.' };
  }
  if (lock.bundled) {
    // verify() follows the package directory to its real path: the bundled
    // folders themselves must not be links to somewhere else.
    const root = path.resolve(__dirname, '..');
    let rel = '';
    for (const part of BUNDLED_DIR.split('/')) {
      rel = rel ? rel + '/' + part : part;
      let st;
      try {
        st = fs.lstatSync(path.join(root, ...rel.split('/')));
      } catch (err) {
        return { error: err.code === 'ENOENT'
          ? 'the plugin\'s copy of zn-gate ' + lock.version + ' (' + BUNDLED_DIR + ') is missing. ' + installHint(lock)
          : 'cannot read the plugin\'s ' + rel + ' folder (' + err.code + '). ' + installHint(lock) };
      }
      if (st.isSymbolicLink()) return { error: 'the plugin\'s ' + rel + ' folder is a symbolic link. ' + installHint(lock) };
      if (!st.isDirectory()) return { error: 'the plugin\'s ' + rel + ' is not a folder. ' + installHint(lock) };
    }
    // The same check without a gap between the steps: the real path must be the expected one.
    if (fs.realpathSync(path.join(root, ...BUNDLED_DIR.split('/'))) !== path.join(fs.realpathSync(root), ...BUNDLED_DIR.split('/'))) {
      return { error: 'the plugin\'s ' + BUNDLED_DIR + ' folder is not inside the plugin. ' + installHint(lock) };
    }
  }
  const reasons = [];
  for (const dir of candidates(lock)) {
    if (!isPackageDir(dir)) {
      if (lock.bundled) return { error: 'the plugin\'s ' + BUNDLED_DIR + ' folder does not hold zn-gate. ' + installHint(lock) };
      continue;
    }
    const real = fs.realpathSync(dir);
    const pkg = readJson(path.join(real, 'package.json')) || {};
    if (pkg.version !== lock.version) {
      reasons.push(real + ' holds zn-gate ' + (pkg.version || 'of an unknown version'));
      continue;
    }
    const res = readVerified(real, lock);
    if (res.files) return { dir: real, files: res.files };
    reasons.push(real + ' does not match the published zn-gate ' + lock.version + ': ' + res.error);
  }
  if (!reasons.length) return { error: 'zn-gate ' + lock.version + ' is not installed (not in the plugin folder, and no zn-gate executable on PATH). ' + installHint(lock) };
  return { error: 'this plugin needs zn-gate ' + lock.version + ', but ' + reasons.join('; ') + '. ' + installHint(lock) };
}

/* ------------------------- in-memory loader ------------------------- */

const isBuiltin = Module.isBuiltin || ((id) => Module.builtinModules.includes(String(id).replace(/^node:/, '')));

/**
 * Keep the modules that Node loads by itself inside the verified package.
 * import() goes to Node's own loader (zn-gate uses it for its encryption
 * library), which resolves names from disk and would look in node_modules
 * folders above the package for a name the package does not hold.
 *
 * With module.registerHooks (Node.js 22.15 and 23.5 or later; synchronous,
 * no measurable cost), every module that Node resolves must be a built-in or
 * one of the verified files, and its source (ES module, CommonJS or JSON) is
 * served from the verified bytes, so a file changed after the check is never
 * run. require() calls inside a CommonJS module loaded this way go through
 * the same hooks.
 *
 * On older Node.js versions, the long-running MCP servers use module.register
 * instead (it starts a loader thread, about 100 ms, too slow for every hook):
 * the same resolve check, and every loaded file is read in the hook, compared
 * with its SHA-256 and served from those bytes. createRequire() is not hooked
 * there. Hooks on those versions rely on the release build, which checks that
 * every import of the shipped files resolves inside the package and refuses
 * createRequire.
 */
function guardModules(dir, files, lock, longRunning) {
  const mod = require('module');
  const { fileURLToPath, pathToFileURL } = require('url');
  const root = path.resolve(dir);
  const relOf = (url) => {
    if (typeof url !== 'string' || !url.startsWith('file:')) return null;
    const rel = path.relative(root, fileURLToPath(url));
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return rel.split(path.sep).join('/');
  };
  const refuse = (url) => {
    throw new Error('zn plugin: refusing to load ' + url + ': it is not one of the verified zn-gate files');
  };
  if (typeof mod.registerHooks === 'function') {
    mod.registerHooks({
      resolve(specifier, context, nextResolve) {
        const r = nextResolve(specifier, context);
        if (!r.url.startsWith('node:') && !files.has(relOf(r.url))) refuse(r.url);
        return r;
      },
      load(url, context, nextLoad) {
        const r = nextLoad(url, context);
        if (url.startsWith('node:')) return r;
        const rel = relOf(url);
        if (!files.has(rel)) refuse(url);
        return { ...r, source: files.get(rel) };
      },
    });
    return 'sync';
  }
  if (!longRunning || typeof mod.register !== 'function') return 'none';
  const hooks = [
    "import { fileURLToPath } from 'node:url';",
    "import { readFileSync } from 'node:fs';",
    "import { createHash } from 'node:crypto';",
    "import path from 'node:path';",
    'let root, digests;',
    'export async function initialize(data) { root = data.root; digests = new Map(Object.entries(data.digests)); }',
    'function relOf(url) {',
    "  if (!url.startsWith('file:')) return null;",
    '  const rel = path.relative(root, fileURLToPath(url));',
    "  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;",
    "  return rel.split(path.sep).join('/');",
    '}',
    "function refuse(url) { throw new Error('zn plugin: refusing to load ' + url + ': it is not one of the verified zn-gate files'); }",
    'export async function resolve(specifier, context, nextResolve) {',
    '  const r = await nextResolve(specifier, context);',
    "  if (!r.url.startsWith('node:') && !digests.has(relOf(r.url))) refuse(r.url);",
    '  return r;',
    '}',
    'export async function load(url, context, nextLoad) {',
    '  const r = await nextLoad(url, context);',
    "  if (url.startsWith('node:')) return r;",
    '  const rel = relOf(url);',
    '  if (!digests.has(rel)) refuse(url);',
    '  // CommonJS comes back without source: read it here, so it is checked and its',
    '  // require() calls go through these hooks too.',
    '  const source = r.source == null ? readFileSync(fileURLToPath(url)) : r.source;',
    "  if (createHash('sha256').update(source).digest('hex') !== digests.get(rel)) {",
    "    throw new Error('zn plugin: ' + rel + ' was changed after it was checked');",
    '  }',
    '  return { ...r, source };',
    '}',
  ].join('\n');
  mod.register('data:text/javascript,' + encodeURIComponent(hooks), {
    parentURL: pathToFileURL(__filename),
    data: { root, digests: lock.files },
  });
  return 'thread';
}

/**
 * A CommonJS loader over the verified file set. require() calls of a relative
 * path or a package are resolved by this loader, only to verified files;
 * built-in modules come from Node. Code that reaches Node's module system
 * directly (the "module" built-in, process.mainModule) is not covered: the
 * release build refuses a bundle that does. import() is handed to Node's own
 * loader (ES modules cannot be evaluated from memory without experimental
 * flags); guardModules() keeps what that loader loads inside the verified
 * files.
 */
function makeLoader(dir, files) {
  const cache = new Map();
  const has = (rel) => files.has(rel);
  const norm = (rel) => path.posix.normalize(rel).replace(/^\.\//, '');

  function packageEntry(pkgRel, sub) {
    const pj = files.get(pkgRel + '/package.json');
    const meta = pj ? JSON.parse(pj.toString('utf8')) : {};
    if (sub) return asFile(pkgRel + '/' + sub);
    const exp = typeof meta.exports === 'string' ? meta.exports
      : meta.exports && typeof meta.exports['.'] === 'string' ? meta.exports['.']
        : meta.exports && meta.exports['.'] && (meta.exports['.'].require || meta.exports['.'].default || meta.exports['.'].import);
    const main = typeof exp === 'string' ? exp : meta.main || 'index.js';
    return asFile(norm(pkgRel + '/' + main)) || asFile(pkgRel + '/index');
  }

  function asFile(rel) {
    rel = norm(rel);
    for (const c of [rel, rel + '.js', rel + '.json', rel + '.cjs', rel + '.mjs']) if (has(c)) return c;
    if (files.has(rel + '/package.json')) return packageEntry(rel, '');
    for (const c of [rel + '/index.js', rel + '/index.json']) if (has(c)) return c;
    return null;
  }

  function resolve(spec, fromRel) {
    const base = path.posix.dirname(fromRel);
    if (spec.startsWith('./') || spec.startsWith('../') || spec === '.' || spec === '..') {
      const rel = norm(path.posix.join(base, spec));
      if (rel.startsWith('..')) return null;
      return asFile(rel);
    }
    if (path.isAbsolute(spec)) {
      const rel = path.relative(dir, spec).split(path.sep).join('/');
      return rel.startsWith('..') || path.isAbsolute(rel) ? null : asFile(rel);
    }
    const m = /^((?:@[^/]+\/)?[^/]+)(?:\/(.*))?$/.exec(spec);
    if (!m) return null;
    let d = base;
    for (;;) {
      const pkgRel = norm((d === '.' ? '' : d + '/') + 'node_modules/' + m[1]);
      if (files.has(pkgRel + '/package.json') || [...files.keys()].some((k) => k.startsWith(pkgRel + '/'))) {
        return packageEntry(pkgRel, m[2] || '');
      }
      if (d === '.' || d === '') break;
      d = path.posix.dirname(d);
    }
    return null;
  }

  function notFound(spec, fromRel) {
    const err = new Error("Cannot find module '" + spec + "' among the verified zn-gate files (required from " + fromRel + ')');
    err.code = 'MODULE_NOT_FOUND';
    return err;
  }

  function load(rel) {
    if (cache.has(rel)) return cache.get(rel).exports;
    const filename = path.join(dir, ...rel.split('/'));
    const mod = { id: filename, filename, loaded: false, exports: {}, children: [], paths: [] };
    cache.set(rel, mod);
    const src = files.get(rel).toString('utf8').replace(/^﻿/, '');
    if (rel.endsWith('.json')) {
      mod.exports = JSON.parse(src);
      mod.loaded = true;
      return mod.exports;
    }
    const req = (spec) => {
      spec = String(spec);
      if (isBuiltin(spec)) return require(spec);
      const target = resolve(spec, rel);
      if (!target) throw notFound(spec, rel);
      return load(target);
    };
    req.resolve = (spec) => {
      if (isBuiltin(spec)) return spec;
      const target = resolve(String(spec), rel);
      if (!target) throw notFound(spec, rel);
      return path.join(dir, ...target.split('/'));
    };
    req.cache = Object.create(null);
    req.main = undefined;
    const code = src.startsWith('#!') ? '//' + src.slice(2) : src;
    const fn = vm.compileFunction(code, ['exports', 'require', 'module', '__filename', '__dirname'], {
      filename,
      // import() goes to Node's own ES module loader, resolved from this
      // file's location inside the verified tree (see the header).
      importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
    });
    fn.call(mod.exports, mod.exports, req, mod, filename, path.dirname(filename));
    mod.loaded = true;
    return mod.exports;
  }

  return { load, resolve };
}

/* ------------------------------ modes ------------------------------ */

function whenUnavailableAllows() {
  const hooks = znConfig().hooks || {};
  return String(hooks.whenUnavailable || '').toLowerCase() === 'allow';
}

/*
 * Hook mode keeps control of what reaches the agent:
 *  - the event is read from stdin before anything of zn-gate is loaded, so a
 *    refusal always knows which event it answers and what output to withhold;
 *  - zn-gate gets that event through a replacement process.stdin, and what it
 *    writes to process.stdout is held back;
 *  - when the process exits, either zn-gate's answer is written out (it ended
 *    normally with 0 or 2), or the launcher's refusal is (anything else).
 */
const hook = { agent: null, raw: '', event: null, refusal: null, captured: [] };

const WITHHELD = '[zn plugin: output withheld because zn could not check it]';
function withhold(v) {
  return typeof v === 'string' ? WITHHELD
    : Array.isArray(v) ? v.map(withhold)
      : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, withhold(x)])) : v;
}

function eventName() {
  return hook.event && typeof hook.event === 'object' ? String(hook.event.hook_event_name || '') : '';
}

/*
 * The refusal for this agent and event: {code, stdout}. A refused tool call
 * or prompt is blocked with exit code 2. A refused tool output cannot be
 * blocked that way (Claude Code and Codex still pass the original output to
 * the model on exit 2), so it is replaced in the format each agent reads.
 */
function refusalFor(msg) {
  const name = eventName();
  const ev = hook.event || {};
  if (hook.agent === 'claude-code' && name === 'PostToolUse') {
    return {
      code: 0,
      stdout: JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PostToolUse',
          updatedToolOutput: ev.tool_response === undefined ? WITHHELD : withhold(ev.tool_response),
          additionalContext: msg,
        },
        systemMessage: msg,
      }),
    };
  }
  if (hook.agent === 'codex' && name === 'PostToolUse') {
    return { code: 0, stdout: JSON.stringify({ decision: 'block', reason: WITHHELD + '\n\n[' + msg + ']' }) };
  }
  if (hook.agent === 'cursor' && name === 'postToolUse') {
    const tool = String(ev.tool_name || '');
    const builtin = ['Shell', 'Read', 'Write', 'Edit', 'Grep', 'Glob', 'WebFetch'].includes(tool) && !/^MCP:/i.test(tool);
    if (!builtin) {
      let out = ev.tool_output;
      if (typeof out === 'string') { try { out = JSON.parse(out); } catch (_) { /* plain text */ } }
      const replaced = withhold(out);
      return {
        code: 0,
        stdout: JSON.stringify({ updated_mcp_tool_output: typeof replaced === 'string' ? { text: replaced } : replaced, additional_context: msg }),
      };
    }
    // Cursor cannot rewrite the output of its built-in tools (docs/compat.md).
  }
  if (hook.agent === 'cursor') {
    return { code: 2, stdout: JSON.stringify({ permission: 'deny', continue: false, user_message: msg, agent_message: msg }) };
  }
  return { code: 2, stdout: '' };
}

function refuseHook(why) {
  if (hook.refusal) return;
  if (whenUnavailableAllows()) {
    hook.refusal = { pass: true, msg: 'zn plugin: ' + why + ' Event passed through (hooks.whenUnavailable is "allow").' };
    return;
  }
  const msg = 'zn plugin: ' + why + ' Until then zn cannot check this call, so it is refused. ' +
    'To let events pass while zn-gate is unavailable, set {"hooks": {"whenUnavailable": "allow"}} in ~/.zn/config.json.';
  hook.refusal = { msg, ...refusalFor(msg) };
}

function writeAll(fd, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  let off = 0;
  while (off < buf.length) {
    try {
      off += fs.writeSync(fd, buf, off, buf.length - off);
    } catch (err) {
      if (err.code !== 'EAGAIN') throw err;
    }
  }
}

/* Decide, once, what the agent gets: zn-gate's answer or the refusal. */
function finishHook(code) {
  if (!hook.refusal && code !== 0 && code !== 2) {
    refuseHook('zn-gate ended with exit code ' + code + '.');
  }
  const r = hook.refusal;
  try {
    if (!r) {
      if (hook.captured.length) writeAll(1, Buffer.concat(hook.captured));
      return code;
    }
    writeAll(2, r.msg + '\n');
    if (r.pass) return 0;
    if (r.stdout) writeAll(1, r.stdout);
    return r.code;
  } catch (_) {
    return 2;
  }
}

function captureStdio(raw) {
  const { Readable, Writable } = require('stream');
  const input = Readable.from([Buffer.from(raw, 'utf8')], { objectMode: false });
  const output = new Writable({
    write(chunk, enc, cb) {
      hook.captured.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, enc));
      cb();
    },
  });
  Object.defineProperty(process, 'stdin', { configurable: true, enumerable: true, get: () => input });
  Object.defineProperty(process, 'stdout', { configurable: true, enumerable: true, get: () => output });
}

function runHook(agent) {
  if (!SUPPORTED_AGENTS.has(agent)) {
    process.stderr.write('zn plugin: unknown agent "' + agent + '"\n');
    process.exitCode = 1;
    return;
  }
  hook.agent = agent;
  process.on('exit', (code) => { process.exitCode = finishHook(code); });
  const onError = (err) => {
    refuseHook('zn-gate failed (' + ((err && err.message) || String(err)) + ').');
    // Exit now: whatever was running is in an unknown state.
    process.exit(2);
  };
  process.on('uncaughtException', onError);
  process.on('unhandledRejection', onError);
  try {
    try { hook.raw = fs.readFileSync(0, 'utf8'); } catch (_) { hook.raw = ''; }
    try { hook.event = JSON.parse(hook.raw.replace(/^﻿/, '')); } catch (_) { hook.event = null; }
    captureStdio(hook.raw);
    const lock = loadLock();
    const res = verify(lock);
    if (res.error) return refuseHook(res.error);
    guardModules(res.dir, res.files, lock, false);
    const runner = makeLoader(res.dir, res.files).load('lib/hooks/runner.js');
    // The runner reads the event from (the replacement) stdin and writes its answer.
    Promise.resolve(runner.main([agent])).catch((err) => {
      refuseHook('zn-gate failed (' + ((err && err.message) || String(err)) + ').');
    });
  } catch (err) {
    refuseHook('zn-gate failed to load (' + ((err && err.message) || String(err)) + ').');
  }
}

function runMcp() {
  const fail = (msg) => {
    process.stderr.write('zn plugin: ' + msg + '\n');
    process.exit(1);
  };
  process.on('uncaughtException', (err) => fail('zn-gate failed (' + ((err && err.message) || String(err)) + ')'));
  process.on('unhandledRejection', (err) => fail('zn-gate failed (' + ((err && err.message) || String(err)) + ')'));
  const lock = loadLock();
  const res = verify(lock);
  if (res.error) return fail(res.error);
  guardModules(res.dir, res.files, lock, true);
  makeLoader(res.dir, res.files).load('lib/broker/mcp.js').startSecretsMcp();
}

/**
 * The plugin's optional zn API key: the "api_key" plugin option, which
 * Claude Code passes to the "zn-gate" MCP server as ZN_PLUGIN_API_KEY. An
 * option left empty, or not expanded by the agent, is not a key.
 */
function pluginApiKey(env) {
  const k = String(env.ZN_PLUGIN_API_KEY || '').trim();
  return /^[A-Za-z0-9._-]{16,256}$/.test(k) ? k : null;
}

/**
 * Only the plugin option turns on the cloud classifier: ZN_CLOUD, ZN_API_KEY,
 * ZN_API_URL and ZN_STAGE from the environment the agent was started with are
 * dropped, so the key can only go to the default zn endpoint. Without a key,
 * local rules only.
 */
function znGateMcpEnv(env, agent) {
  // Only Claude Code passes the option (from .mcp.json); in other agents the
  // server inherits the user's environment, so the variable is not trusted.
  const key = agent === 'claude-code' ? pluginApiKey(env) : null;
  for (const name of ['ZN_PLUGIN_API_KEY', 'ZN_API_KEY', 'ZN_CLOUD', 'ZN_API_URL', 'ZN_STAGE', 'ZN_LOCAL_ONLY']) delete env[name];
  if (key) {
    env.ZN_API_KEY = key;
    env.ZN_CLOUD = '1';
    // The key is sent as a bearer token: certificate checks stay on.
    delete env.NODE_TLS_REJECT_UNAUTHORIZED;
  } else {
    env.ZN_LOCAL_ONLY = 'true';
  }
  return { cloud: Boolean(key) };
}

function runZnGateMcp(agent) {
  const fail = (msg) => {
    process.stderr.write('zn plugin: ' + msg + '\n');
    process.exit(1);
  };
  process.on('uncaughtException', (err) => fail('zn-gate failed (' + ((err && err.message) || String(err)) + ')'));
  process.on('unhandledRejection', (err) => fail('zn-gate failed (' + ((err && err.message) || String(err)) + ')'));
  const { cloud } = znGateMcpEnv(process.env, agent);
  const lock = loadLock();
  const res = verify(lock);
  if (res.error) return fail(res.error);
  guardModules(res.dir, res.files, lock, true);
  makeLoader(res.dir, res.files).load('lib/mcp.js').startMcpServer({ localOnly: !cloud });
}

/* Hooks that `zn hooks install` wrote into the agent's own settings run too. */
function settingsHooks(agent) {
  if (agent !== 'claude-code') return false;
  const re = /(\bhook claude-code|hooks[\\/]runner\.js"? claude-code)\s*$/;
  const dir = process.env.CLAUDE_CONFIG_DIR || path.join(homeDir(), '.claude');
  const data = readJson(path.join(dir, 'settings.json'));
  const events = data && data.hooks && typeof data.hooks === 'object' ? Object.values(data.hooks) : [];
  for (const groups of events) {
    for (const g of Array.isArray(groups) ? groups : []) {
      for (const h of (g && Array.isArray(g.hooks)) ? g.hooks : []) {
        if (h && typeof h.command === 'string' && re.test(h.command)) return true;
      }
    }
  }
  return false;
}

function runCheck(agent) {
  let message;
  try {
    const res = verify(loadLock());
    if (res.error) message = 'zn plugin: ' + res.error;
    else if (settingsHooks(agent)) {
      message = 'zn plugin: zn hooks are also installed in your Claude Code settings, so every event is checked twice. ' +
        'Remove them with: zn hooks uninstall claude-code';
    }
  } catch (err) {
    message = 'zn plugin: ' + err.message + '.';
  }
  if (!message) return;
  if (agent === 'claude-code') process.stdout.write(JSON.stringify({ systemMessage: message }));
  else process.stderr.write(message + '\n');
}

function main(argv) {
  const [mode, agent] = argv;
  if (mode === 'hook') return runHook(agent);
  if (mode === 'secrets-mcp') return runMcp();
  if (mode === 'zn-gate-mcp') return runZnGateMcp(agent);
  if (mode === 'check') return runCheck(agent || '');
  process.stderr.write('usage: zn-launch.js hook <claude-code|codex|cursor> | secrets-mcp | zn-gate-mcp | check [agent]\n');
  process.exitCode = 1;
}

module.exports = { verify, loadLock, makeLoader, readVerified, znGateMcpEnv, guardModules };

if (require.main === module) main(process.argv.slice(2));
