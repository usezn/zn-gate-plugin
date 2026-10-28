'use strict';

/**
 * Where does a path live relative to git? Used by the restore policy
 * (write to an ignored file: restore; to a tracked file: keep the token) and
 * by secrets_render_file (values only in ignored paths or outside a repo).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// child_process is loaded on the first git call: most hook calls never ask git, and loading it costs a few milliseconds.
let spawnSyncLazy = null;
function spawnSync(...args) {
  if (!spawnSyncLazy) spawnSyncLazy = require('child_process').spawnSync;
  return spawnSyncLazy(...args);
}

function existingDir(p) {
  let cur = path.resolve(p);
  for (;;) {
    try {
      if (fs.statSync(cur).isDirectory()) return cur;
    } catch (_) { /* walk up */ }
    const parent = path.dirname(cur);
    if (parent === cur) return cur;
    cur = parent;
  }
}

/**
 * 'ignored' | 'tracked' | 'outside' | 'unknown'
 *   ignored: inside a git work tree and matched by .gitignore
 *   tracked: inside a git work tree and not ignored (could be committed)
 *   outside: not inside any git work tree
 *   unknown: git is not available; callers treat it as 'tracked'
 */
function gitStatusOf(file) {
  const abs = path.resolve(file);
  const dir = existingDir(path.dirname(abs));
  // git from the absolute PATH entries only: this runs inside hooks, whose current folder is the project.
  const exe = require('../exe');
  const git = exe.findProgram('git');
  if (!git) return 'unknown';
  // English messages (to tell "not a repository" from other failures), and no fsmonitor: core.fsmonitor in the
  // repository's own .git/config names a program that git would otherwise run.
  const env = { ...exe.programEnv(), LC_ALL: 'C', LANGUAGE: 'C' };
  const run = (args) => spawnSync(git, ['-c', 'core.fsmonitor=false', '-C', dir, ...args], { encoding: 'utf8', windowsHide: true, env });
  const top = run(['rev-parse', '--show-toplevel']);
  if (top.error) return 'unknown';
  // Only "not a git repository" means outside; any other failure (a repository git refuses to read, such as one owned by
  // someone else) is unknown, which callers treat as tracked.
  if (top.status !== 0) return /not a git repository/i.test(String(top.stderr || '')) ? 'outside' : 'unknown';
  const ign = run(['check-ignore', '-q', '--', abs]);
  if (ign.error) return 'unknown';
  if (ign.status === 0) return 'ignored';
  if (ign.status === 1) return 'tracked';
  return 'unknown';
}

/**
 * The path a file has, or would have once created: the nearest existing
 * ancestor with its symlinks resolved, then the rest of the path as typed.
 */
function realTargetOf(file) {
  const abs = path.resolve(file);
  const root = path.parse(abs).root;
  const parts = abs.slice(root.length).split(path.sep).filter(Boolean);
  // Walk down to the first name that does not exist (nothing below it can),
  // then resolve that ancestor once: a long path that does not exist costs one
  // check per existing level, not one realpath per missing one.
  let cur = root;
  let i = 0;
  while (i < parts.length) {
    const next = path.join(cur, parts[i]);
    if (!fs.existsSync(next)) break;
    cur = next;
    i++;
  }
  try {
    return path.join(fs.realpathSync(cur), ...parts.slice(i));
  } catch (_) {
    return abs;
  }
}

/**
 * Write a file atomically with mode 0600 (best effort on Windows). The temporary file has an unpredictable name and is created
 * with O_EXCL, so a file that somebody else planted under any name is never opened (it would keep its owner and access list
 * through the rename); the rename then replaces the target in one step.
 */
function writeFileAtomic(file, data, mode = 0o600) {
  const tmp = path.join(path.dirname(file), '.' + path.basename(file) + '.' + process.pid + '.' + crypto.randomBytes(8).toString('hex') + '.zn-tmp');
  const fd = fs.openSync(tmp, 'wx', mode);
  try {
    try { fs.writeFileSync(fd, data); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) { /* best effort */ }
    throw e;
  }
}

module.exports = { gitStatusOf, realTargetOf, writeFileAtomic };
