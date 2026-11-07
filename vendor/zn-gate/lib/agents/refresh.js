'use strict';

/**
 * Runs from the package's `postinstall`: after `npm update -g zn-gate` the runner file is new, so the SHA-256
 * recorded in each hook launcher (lib/agents/launcher.js) no longer matches and the hooks would block until
 * the user runs `zn hooks install <agent>`. This rewrites the launchers zn-gate itself wrote, with this
 * package's runner and digest. It must never fail an install: every error is swallowed.
 *
 * Which launchers are touched:
 *  - only regular files named zn-hook-<agent>.sh in zn's launcher directory (same ZN_HOME / home rules as the
 *    installer) whose second line is the header zn writes for that same agent id;
 *  - only when the launcher points at THIS package's runner (an update in place), or when it points at a
 *    runner that no longer exists and this is a global install. A project-local `npm install zn-gate` has
 *    neither: the launcher keeps pointing at the global copy, so a project's node_modules is never wired into
 *    the user's hooks.
 * The launcher keeps the options it was written with (the deadline of the agents that fail open on a timeout), and
 * Windows is refreshed too: Claude Code runs this sh launcher there (Git Bash); the other agents' Windows hooks are
 * inline PowerShell, with no launcher file. A launcher folder that belongs to another user (`sudo npm i -g` with the
 * user's HOME) is left alone.
 * With `npm install --ignore-scripts` this does not run; `zn hooks install <agent>` is then the fix.
 */

const fs = require('fs');
const path = require('path');

const MAX_BYTES = 64 * 1024;

function realOrSame(p) {
  try { return fs.realpathSync(p); } catch (_) { return path.resolve(p); }
}

// The same file, also when one side is written with / (the launcher keeps C:/... paths on Windows).
function samePath(a, b, win) {
  const k = (p) => (win ? realOrSame(p.replace(/\//g, '\\')).toLowerCase() : realOrSame(p));
  return k(a) === k(b);
}

// The options the launcher was written with, read back from it: its deadline and whether it runs the hook without a timer.
function launcherOptions(text) {
  const d = /\/bin\/sleep (\d+) & ZN_SP=\$!/.exec(text);
  return d ? { deadlineS: Number(d[1]), deadlineSoft: text.includes('[ -x /bin/sleep ] || { zn_cap "$@"; return 0; }') } : {};
}

function isExecutableFile(p) {
  try { return fs.statSync(p).isFile() && (fs.accessSync(p, fs.constants.X_OK), true); } catch (_) { return false; }
}

/** Refreshes the launchers; returns the agent ids whose launcher changed. */
function refreshLaunchers(opts = {}) {
  const env = opts.env || process.env;
  const platform = opts.platform || process.platform;
  const win = platform === 'win32';
  const launcher = require('./launcher');
  const { portablePath } = require('../shell-quote');
  const runner = opts.runnerPath || path.resolve(__dirname, '..', 'hooks', 'runner.js');
  const node = opts.nodePath || process.execPath;
  const isGlobal = opts.global !== undefined ? opts.global : (env.npm_config_global === 'true' || env.npm_config_location === 'global');
  if (!fs.existsSync(runner)) return [];
  const dir = launcher.launcherDir({ env, home: opts.home });
  let names;
  try { names = fs.readdirSync(dir); } catch (_) { return []; }
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  try { if (uid !== null && fs.lstatSync(dir).uid !== uid) return []; } catch (_) { return []; }
  const done = [];
  for (const name of names.sort()) {
    try {
      const m = /^zn-hook-([a-z-]+)\.sh$/.exec(name);
      if (!m) continue;
      const id = m[1];
      const file = path.join(dir, name);
      const st = fs.lstatSync(file);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      const text = fs.readFileSync(file, 'utf8');
      const lines = text.split('\n');
      if (lines[0] !== '#!/bin/sh' || lines[1] !== '# Written by `zn hooks install ' + id + '`; replaced on every install. Do not edit.') continue;
      const r = /^ZN_RUNNER='([^'\n]+)'$/m.exec(text);
      const n = /^ZN_NODE='([^'\n]+)'$/m.exec(text);
      if (!r || !n) continue;
      const same = samePath(r[1], runner, win);
      const gone = !fs.existsSync(r[1]);
      if (!same && !(gone && isGlobal)) continue;
      const useNode = isExecutableFile(n[1]) ? n[1] : node;
      const kept = launcherOptions(text);
      const next = launcher.unixScript(id, portablePath(useNode, platform), portablePath(runner, platform), kept);
      if (next === text) continue;
      launcher.writeLauncher(id, useNode, runner, { env, home: opts.home, platform, ...kept });
      done.push(id);
    } catch (_) { /* one bad file never stops the others or the install */ }
  }
  return done;
}

/** The postinstall entry: quiet, and never throws. */
function main(opts = {}) {
  try {
    const done = refreshLaunchers(opts);
    if (done.length) (opts.out || ((s) => process.stdout.write(s)))('zn-gate: refreshed hook launchers for ' + done.join(', ') + '\n');
  } catch (_) { /* never fail the install */ }
}

module.exports = { refreshLaunchers, main };

if (require.main === module) {
  try { main(); } catch (_) { /* never fail the install */ }
  process.exitCode = 0;
}
