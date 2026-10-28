'use strict';

/**
 * Node's compile cache for the hook process (Node >= 22.1).
 *
 * A hook is a fresh process on every tool call, so most of its own time goes
 * to compiling the same JavaScript again. module.enableCompileCache() keeps
 * the compiled code on disk and reuses it, which makes the second and later
 * calls start faster.
 *
 * The cache holds code that runs inside every hook, so it is treated like the
 * rest of ~/.zn: it lives in a directory that only this user owns and can
 * write (0700), and it is never shared between users. If the directory is
 * not ours, is a link, or is open to other users, the cache is skipped and
 * the hook runs exactly as before. Any failure is silent; the cache is never
 * required. Set ZN_NO_COMPILE_CACHE=1 to turn it off.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

function cacheRoot(env) {
  const home = env.ZN_HOME ? path.resolve(env.ZN_HOME) : path.join(os.homedir(), '.zn');
  return path.join(home, 'cache', 'compile');
}

/* True when `dir` is a real directory that only the current user can write. */
function isPrivateDir(dir) {
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) return false;
  if (process.platform === 'win32') return true; // the profile's ACLs apply; there is no uid/mode to check
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) return false;
  return (st.mode & 0o022) === 0;
}

/** Make the directory (and its parents up to ~/.zn) private to this user. Returns its path or null. */
function prepare(dir) {
  const home = path.dirname(path.dirname(dir));
  for (const d of [home, path.dirname(dir), dir]) {
    try {
      fs.mkdirSync(d, { mode: 0o700 });
    } catch (err) {
      if (!err || err.code !== 'EEXIST') return null;
    }
    // A directory we did not just create must already be ours and closed to others.
    if (!isPrivateDir(d)) return null;
  }
  return dir;
}

/** Enable the cache when it is safe to. Returns the directory in use, or null. */
function enable(env = process.env) {
  try {
    if (env.ZN_NO_COMPILE_CACHE) return null;
    const mod = require('module');
    if (typeof mod.enableCompileCache !== 'function') return null;
    const dir = prepare(cacheRoot(env));
    if (!dir) return null;
    const r = mod.enableCompileCache(dir);
    return r && r.directory ? r.directory : null;
  } catch (_) {
    return null;
  }
}

module.exports = { enable, cacheRoot, isPrivateDir };
