'use strict';
/**
 * Directories that `zn-gate scan` and `zn-gate audit` do not descend into.
 *
 * Most are caches and generated trees that nobody wants listed. A few names
 * are ambiguous: `target` is Rust or Java build output only when a build file
 * sits next to it, and `vendor` is third-party code only next to a package
 * manifest. Without that context they are ordinary directories and are read.
 * Every other pruned name that a project could use for its own files (`dist`,
 * `build`, `out`, ...) is still skipped, but reported, so a prompt or
 * agent file inside it never disappears without a word.
 */

const fs = require('fs');
const path = require('path');

// Name -> files that must sit in the same directory for the name to be build
// output or dependencies. A name that is not listed is pruned unconditionally.
const MARKERS = {
  target: ['Cargo.toml', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'build.sbt'],
  vendor: ['go.mod', 'composer.json', 'Gemfile', 'Cargo.toml'],
};

// Pruned without a report: dependency stores, version control and tool caches.
// Editor and virtual-environment folders (.idea, .venv, venv, __pycache__,
// .eggs) are not here: a project can keep an agent file in them, so they are
// skipped but reported.
const SILENT = new Set([
  'node_modules', '.git', '.hg', '.svn', '.next', '.nuxt', '.turbo',
  '.tox', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.gradle', 'Pods', 'bower_components',
  '.cache', 'site-packages', '.terraform', '.yarn', '.pnpm-store',
]);

// Names `zn-gate scan` considers. The Python scan keeps the same list, the same
// silent subset and the same markers (a parity test compares them). Test
// directories are not here: fixtures and sample configs in them can hold real
// secrets, so scan reads them.
const SCAN_DIRS = new Set([
  'node_modules', '.git', '.next', '.turbo', '.idea', '.venv', 'venv', '__pycache__', '.eggs',
  'dist', 'build', 'target', 'vendor',
]);

// What a reported name is, for the reason shown to the user. A name that is not
// listed is build output. The Python scan keeps the same words.
const KINDS = {
  vendor: 'dependencies',
  '.idea': 'editor settings',
  '.venv': 'virtual environment',
  venv: 'virtual environment',
  __pycache__: 'Python cache',
  '.eggs': 'Python build files',
};

/**
 * Decide whether to skip the directory `name` found inside `parentDir`, given
 * that the caller's list names it. Returns null when it must be read, or
 * { silent, reason } when it is skipped.
 */
function pruneInfo(name, parentDir) {
  let marker = null;
  const needed = MARKERS[name];
  if (needed) {
    marker = needed.find((f) => fs.existsSync(path.join(parentDir, f))) || null;
    if (!marker) return null;
  }
  if (SILENT.has(name)) return { silent: true, reason: 'skipped by name' };
  const kind = KINDS[name] || 'build output';
  if (marker) return { silent: false, reason: 'skipped by name: ' + kind + ' next to ' + marker };
  return { silent: false, reason: 'skipped by name: ' + kind };
}

module.exports = { pruneInfo, MARKERS, SILENT, SCAN_DIRS };
