'use strict';
/**
 * The command a person should type to run zn.
 *
 * Users who only installed the plugin may not have `zn` on PATH, so the
 * suggestion falls back to `npx -y zn-gate@<version>`. Every bin of the
 * package points to bin/cli.js, so both forms run the same program.
 *
 * On Windows the suggestions use the `.cmd` shims (`zn.cmd`, `npx.cmd`):
 * with the default Restricted execution policy PowerShell refuses to run
 * the `.ps1` shims that npm also writes, and a bare `zn` or `npx` fails
 * with "running scripts is disabled on this system".
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

/** The program name to type: `cliName('zn')` is `zn.cmd` on Windows, `zn` elsewhere. */
function cliName(name, platform = process.platform) {
  return platform === 'win32' ? name + '.cmd' : name;
}

/** `znCommand('env shadow .env')` -> `zn env shadow .env` or the npx form. */
function znCommand(args, opts = {}) {
  const platform = opts.platform || process.platform;
  const tail = String(args || '').trim();
  if (znOnPath(opts.env)) return tail ? cliName('zn', platform) + ' ' + tail : cliName('zn', platform);
  const npx = cliName('npx', platform) + ' -y zn-gate@' + version;
  return tail ? npx + ' ' + tail : npx;
}

// The zn subcommands that messages tell a person to type after `zn` or `zn-gate`.
const CLI_VERBS = 'hooks|env|secret|unlock|lock|run|hook|init|check|audit|test|status|stats|scan|evidence|vault|connect|disconnect|uninstall|team|pins|secrets-mcp|why';
// `npx -y zn-gate` is handled by NPX_WORD, so the package name after `-y` is skipped here.
const ZN_WORD = new RegExp('(^|[^\\w./-])(?<!-y )(zn-gate|zn)(?= (?:' + CLI_VERBS + ')\\b)', 'g');
const NPX_WORD = /(^|[^\w./-])npx(?= -y zn-gate)/g;

const CODE_SPAN = /`[^`\n]+`/g;

/** A command line (a `manual:` step): every zn and npx command in it is rewritten for Windows. */
function winManualText(text, platform = process.platform) {
  if (platform !== 'win32' || typeof text !== 'string') return text;
  return text.replace(NPX_WORD, '$1npx.cmd').replace(ZN_WORD, (m, pre, name) => pre + name + '.cmd');
}

/**
 * A message that names zn commands, written for the shell the person uses.
 * Only the text between backticks (inline code) changes, so ordinary sentences
 * stay as they are: on Windows `zn hooks install x` becomes `zn.cmd hooks install x`
 * and `npx -y zn-gate init` becomes `npx.cmd -y zn-gate init`, while a sentence
 * that says "no zn check runs" is left alone. Other systems get the text back unchanged.
 */
function winCommandText(text, platform = process.platform) {
  if (platform !== 'win32' || typeof text !== 'string') return text;
  return text.replace(CODE_SPAN, (span) => winManualText(span, platform));
}

module.exports = { znCommand, znOnPath, cliName, winCommandText, winManualText, PACKAGE_VERSION: version };
