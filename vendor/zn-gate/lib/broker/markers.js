'use strict';

/**
 * Markers and policy matching shared by `zn run`, the `secrets` MCP server
 * and the agent hooks.
 *
 *   __ZN_<NAME>__      a named secret from the vault (e.g. __ZN_GITHUB_TOKEN__)
 *   __ZN_<TYPE>_<n>__  a value the scrubber detected (e.g. __ZN_AWS_KEY_1__)
 *
 * Vault names may not end in `_<digits>`, so the two forms never collide.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const exe = require('../exe');

const NAME_SOURCE = '[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*';
const MARKER_SOURCE = '__ZN_(' + NAME_SOURCE + ')__';
const NAME_RE = new RegExp('^' + NAME_SOURCE + '$');
const DETECTED_RE = /_\d+$/;

function markerRegex() {
  return new RegExp(MARKER_SOURCE, 'g');
}

function markerFor(name) {
  return '__ZN_' + name + '__';
}

function isDetectedName(name) {
  return DETECTED_RE.test(name);
}

/** Validate a vault secret name. Returns an error message or null. */
function validateSecretName(name) {
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    return 'secret names use upper-case letters, digits and single underscores (e.g. GITHUB_TOKEN)';
  }
  if (name.length > 64) return 'secret names are at most 64 characters';
  if (isDetectedName(name)) {
    return 'secret names may not end in _<digits>: that form is reserved for values the scrubber detects';
  }
  return null;
}

/** All markers in a string: [{marker, name, detected}] (deduplicated, in order). */
function findMarkers(text) {
  const out = [];
  const seen = new Set();
  if (typeof text !== 'string' || !text.includes('__ZN_')) return out;
  for (const m of text.matchAll(markerRegex())) {
    if (seen.has(m[0])) continue;
    seen.add(m[0]);
    out.push({ marker: m[0], name: m[1], detected: isDetectedName(m[1]) });
  }
  return out;
}

function findNamedMarkers(text) {
  return findMarkers(text).filter((m) => !m.detected);
}

/** Replace named markers using a Map name -> value. Unknown names stay as they are. */
function substitute(text, values) {
  if (typeof text !== 'string' || !text.includes('__ZN_')) return text;
  return text.replace(markerRegex(), (whole, name) => (values.has(name) ? values.get(name) : whole));
}

/* ---------------------------- commands ---------------------------- */

function normalizeExe(p) {
  let base = path.basename(String(p || ''));
  if (process.platform === 'win32') {
    base = base.toLowerCase().replace(/\.(exe|cmd|bat|ps1|com)$/, '');
  }
  return base;
}

function hasPathSeparator(s) {
  return /[\\/]/.test(String(s || ''));
}

/**
 * Does argv match one allowCommands entry? An entry is a command prefix:
 * "psql" matches `psql ...`; "npm run migrate" matches `npm run migrate ...`.
 * A bare entry only matches a bare argv[0] (resolved on PATH), never an
 * explicit path such as ./psql. A path entry must match argv[0] exactly.
 */
function matchCommandEntry(entry, argv) {
  const words = String(entry || '').trim().split(/\s+/).filter(Boolean);
  if (words.length === 0 || !Array.isArray(argv) || argv.length < words.length) return false;
  const head = words[0];
  if (hasPathSeparator(head)) {
    if (path.resolve(head) !== path.resolve(argv[0])) return false;
  } else {
    if (hasPathSeparator(argv[0])) return false;
    if (normalizeExe(head) !== normalizeExe(argv[0])) return false;
  }
  for (let i = 1; i < words.length; i++) {
    if (words[i] !== argv[i]) return false;
  }
  return true;
}

/** First allowCommands entry that matches argv, or null. */
function matchAllowCommands(allowCommands, argv) {
  for (const entry of allowCommands || []) {
    if (matchCommandEntry(entry, argv)) return String(entry).trim().split(/\s+/).join(' ');
  }
  return null;
}

/** Locate an executable on PATH (PATHEXT aware on Windows). */
function whichSync(cmd, envPath) {
  return exe.whichSync(cmd, envPath);
}

/*
 * The temp folders a binary must not come from. os.tmpdir() follows TMPDIR, TEMP and TMP, which the agent sets for
 * the commands it runs, so the fixed system temp folders and the temp folder of the user profile (read from the
 * system, not from the environment) are always included as well. Every one in its native real form.
 */
function tempRoots() {
  const roots = [os.tmpdir()];
  if (process.platform === 'win32') {
    try { roots.push(path.join(os.userInfo().homedir, 'AppData', 'Local', 'Temp')); } catch (_) { /* no profile */ }
    try { roots.push(fs.realpathSync.native('\\\\?\\GLOBALROOT\\SystemRoot\\Temp')); } catch (_) { /* not there */ }
  } else {
    roots.push('/tmp', '/var/tmp', '/private/tmp', '/private/var/tmp', '/dev/shm', '/var/folders', '/private/var/folders');
  }
  const out = [];
  for (const r of roots) {
    if (!r || !path.isAbsolute(r)) continue;
    const real = realOf(r);
    if (!out.includes(real)) out.push(real);
  }
  return out;
}

function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!!rel && !rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * An allowed command name must not resolve to a binary the agent could have
 * planted: inside the project (node_modules included: the agent can edit it)
 * or in the temp dir. Project tools run through a package runner instead
 * (`npx prisma`, `npm run migrate`), which zn flags as an interpreter.
 * Returns an error message or null.
 */
function checkResolvedExecutable(resolved, projectRoot, resolvedReal) {
  if (!resolved) return 'command not found on PATH';
  // Both sides in the native real form: a Windows 8.3 short name, a subst drive and a \\?\ prefix all
  // name the same folder in more than one way, and a PATH entry may use any of them.
  const real = realOf(resolvedReal || resolved);
  if (tempRoots().some((tmp) => isInside(real, tmp))) return 'resolves to a file in the temp directory';
  // Both the name as found on PATH and the real file are compared with the
  // project's real path: a project reached through a symlink (macOS /var is
  // /private/var) must still count as the project.
  if (projectRoot) {
    const root = realOf(projectRoot);
    if ([resolved, realOf(resolved), real].some((p) => isInside(p, root) || isInside(p, projectRoot))) {
      return 'resolves to a file inside the project, which the agent can edit';
    }
  }
  return null;
}

// The native form also expands a Windows 8.3 short name: os.tmpdir() can be C:\Users\LONGNA~1\..., and a file
// planted in the long form of that folder must still count as inside it.
function realOf(p) {
  try { return fs.realpathSync.native(p); } catch (_) { /* not there: resolve the part that is */ }
  // A path that does not exist (yet) still names its folders in a short, linked or other form: take the native real
  // form of the deepest folder that exists and add the rest, so it compares like the temp and project folders.
  let head = path.resolve(p);
  const rest = [];
  for (;;) {
    const parent = path.dirname(head);
    if (parent === head) return path.resolve(p);
    rest.unshift(path.basename(head));
    head = parent;
    try { return path.join(fs.realpathSync.native(head), ...rest); } catch (_) { /* go one folder up */ }
  }
}

/* ------------------------------ hosts ------------------------------ */

/** allowHosts entries: "api.github.com" (exact) or "*.example.com" (subdomains only). */
function hostAllowed(allowHosts, host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  for (const raw of allowHosts || []) {
    const entry = String(raw || '').toLowerCase().trim().replace(/\.$/, '');
    if (!entry) continue;
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(1);
      if (h.endsWith(suffix) && h.length > suffix.length) return true;
    } else if (entry === h) {
      return true;
    }
  }
  return false;
}

function isLoopbackHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || /^127\.\d+\.\d+\.\d+$/.test(h);
}

module.exports = {
  tempRoots,
  MARKER_SOURCE,
  markerRegex,
  markerFor,
  isDetectedName,
  validateSecretName,
  findMarkers,
  findNamedMarkers,
  substitute,
  normalizeExe,
  matchCommandEntry,
  matchAllowCommands,
  whichSync,
  isInside,
  checkResolvedExecutable,
  hostAllowed,
  isLoopbackHost,
};
