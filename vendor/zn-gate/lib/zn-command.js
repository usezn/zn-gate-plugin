'use strict';
/**
 * The command a person should type to run zn.
 *
 * Users who only installed the plugin may not have `zn` on PATH, so the
 * suggestion falls back to `npx -y zn-gate@<version>`. Every bin of the
 * package points to bin/cli.js, so both forms run the same program.
 */

const path = require('path');
const exe = require('./exe');
const { version } = require('../package.json');

// Only absolute directories count: a relative PATH entry (".", "") would find
// a zn in whatever folder the person happens to be in.
function absoluteDirs(pathValue) {
  return String(pathValue || '').split(path.delimiter).filter((d) => d && path.isAbsolute(d)).join(path.delimiter);
}

function onPath(env) {
  const dirs = absoluteDirs(env.PATH || env.Path || '');
  return exe.resolveExecutable('zn', { PATH: dirs, PATHEXT: env.PATHEXT }) !== null;
}

// The PATH lookup is done once per process for the real environment.
let cachedOnPath = null;

function znOnPath(env) {
  if (env) return onPath(env);
  if (cachedOnPath === null) cachedOnPath = onPath(process.env);
  return cachedOnPath;
}

/** `znCommand('env shadow .env')` -> `zn env shadow .env` or the npx form. */
function znCommand(args, opts = {}) {
  const tail = String(args || '').trim();
  if (znOnPath(opts.env)) return tail ? 'zn ' + tail : 'zn';
  return tail ? 'npx -y zn-gate@' + version + ' ' + tail : 'npx -y zn-gate@' + version;
}

module.exports = { znCommand, znOnPath, PACKAGE_VERSION: version };
