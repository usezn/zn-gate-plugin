'use strict';

/**
 * Small helpers shared by the agent adapters to edit their JSON config
 * files: read (missing file = {}), timestamped backup, atomic write, and
 * removal of only the hook entries zn wrote.
 */

const fs = require('fs');
const path = require('path');
const { writeFileAtomic } = require('../broker/files');
const { shQuote, portablePath, windowsCommand, windowsCommandScript } = require('../shell-quote');

/**
 * How a JSON file was written, so it can be written back the same way:
 * { eol: '\n' | '\r\n', indent: number of spaces | '\t', bom: boolean, trailingNewline: boolean }.
 * A file that does not exist (or is blank) gets zn's usual format: LF, two spaces, a final newline.
 */
const DEFAULT_STYLE = Object.freeze({ eol: '\n', indent: 2, bom: false, trailingNewline: true });

function detectStyle(text) {
  const bom = text.charCodeAt(0) === 0xFEFF;
  const body = bom ? text.slice(1) : text;
  const style = { ...DEFAULT_STYLE, bom };
  const nl = body.indexOf('\n');
  if (nl < 0) return style; // one line (minified): written out the usual way
  style.eol = body[nl - 1] === '\r' ? '\r\n' : '\n';
  const m = /\n([ \t]+)\S/.exec(body);
  if (m) style.indent = m[1][0] === '\t' ? '\t' : Math.min(m[1].length, 10);
  style.trailingNewline = /\n$/.test(body);
  return style;
}

/** JSON text for data in the given style (default: LF, two spaces, final newline). */
function formatJson(data, style = DEFAULT_STYLE) {
  let out = JSON.stringify(data, null, style.indent);
  if (style.eol !== '\n') out = out.replace(/\n/g, style.eol);
  if (style.trailingNewline) out += style.eol;
  return (style.bom ? '\uFEFF' : '') + out;
}

// The style each parsed object was read in; writeJson and stringifyJson look it up, so callers keep passing plain data.
const STYLES = new WeakMap();

/** Parses JSON text (a leading BOM is allowed) and remembers its style for the data object. Throws SyntaxError. */
function parseJson(text) {
  const style = detectStyle(text);
  const data = JSON.parse(style.bom ? text.slice(1) : text);
  if (data !== null && typeof data === 'object') STYLES.set(data, style);
  return data;
}

/** JSON text for data, in the style it was read in (see parseJson) or the default one. */
function stringifyJson(data) {
  return formatJson(data, STYLES.get(data) || DEFAULT_STYLE);
}

function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
  if (!text.replace(/^\uFEFF/, '').trim()) return {};
  let data;
  try {
    data = parseJson(text);
  } catch (err) {
    throw new Error('cannot parse ' + file + ': ' + err.message + ' (left unchanged)');
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error(file + ' must hold a JSON object, not ' + (data === null ? 'null' : Array.isArray(data) ? 'an array' : typeof data) + ' (left unchanged)');
  }
  return data;
}

/** The "hooks" object of a config file: missing or null is empty; anything else must be an object. */
function hooksOf(data, file) {
  if (data.hooks === undefined || data.hooks === null) return {};
  if (typeof data.hooks !== 'object' || Array.isArray(data.hooks)) {
    throw new Error('"hooks" in ' + file + ' must be an object, not ' + (Array.isArray(data.hooks) ? 'an array' : typeof data.hooks) + ' (left unchanged)');
  }
  return data.hooks;
}

function backup(file) {
  if (!fs.existsSync(file)) return null;
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const dest = file + '.bak-zn-' + stamp;
  fs.copyFileSync(file, dest);
  return dest;
}

/** Where the config really lives: an existing symlink is followed, so the link itself stays as it is. */
function realFile(file) {
  try { return fs.realpathSync(file); } catch (_) { return file; }
}

function writeJson(file, data) {
  const target = realFile(file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const mode = fs.existsSync(target) ? fs.statSync(target).mode & 0o777 : 0o644;
  writeFileAtomic(target, stringifyJson(data), mode);
}

/** A path as one sh word (single quotes; see lib/shell-quote.js). */
function quoteArg(s, platform = process.platform) {
  return shQuote(portablePath(s, platform));
}

function runnerPath() {
  return path.resolve(__dirname, '..', 'hooks', 'runner.js');
}

/**
 * The command an agent runs for each hook event. A user install names this
 * user's node and runner. A project install is shared through the repository,
 * so it names `zn` on PATH instead of any path of this user.
 */
function hookCommand(agentId, opts = {}) {
  if (opts.command) return opts.command;
  if ((opts.scope || 'user') === 'project') return 'zn hook ' + agentId;
  const platform = opts.platform || process.platform;
  return quoteArg(opts.nodePath || process.execPath, platform) + ' ' + quoteArg(opts.runnerPath || runnerPath(), platform) + ' ' + agentId;
}

/**
 * The same command for a Windows shell that may be cmd.exe or PowerShell:
 * Codex runs `commandWindows` through %COMSPEC% /C (cmd.exe), and Cursor wraps
 * hook commands in PowerShell. It calls powershell.exe with PowerShell-quoted
 * paths, written so that neither cmd.exe nor an outer PowerShell or Git Bash
 * expands anything in them (see windowsCommand in lib/shell-quote.js).
 */
function hookCommandWindows(agentId, opts = {}) {
  if ((opts.scope || 'user') === 'project') return 'zn hook ' + agentId;
  return windowsCommand(opts.nodePath || process.execPath, [opts.runnerPath || runnerPath()], [agentId], { encoded: opts.encodedCommand === true });
}

/**
 * Whether a hook command is one zn wrote for this agent: `zn hook <agent>`,
 * the runner called with double quotes (older versions) or single quotes,
 * or the Windows powershell.exe form.
 */
function isOurs(command, agentId) {
  if (typeof command !== 'string') return false;
  // zn's launcher script (lib/agents/launcher.js): '<dir>/zn-hook-<agent>.sh' <Event>
  if (new RegExp("zn-hook-" + agentId + "\\.sh'? [A-Za-z]+\\s*$").test(command)) return true;
  // The project hook with its own start guard (lib/agents/launcher.js projectShCommand).
  if (require('./launcher').isProjectGuard(command, agentId)) return true;
  const re = new RegExp('(\\bhook ' + agentId + '|hooks[\\\\/]runner\\.js["\']? ' + agentId + ')\\s*$');
  if (re.test(command)) return true;
  const script = windowsCommandScript(command);
  return script !== null && re.test(script);
}

module.exports = { readJson, parseJson, stringifyJson, formatJson, detectStyle, hooksOf, backup, writeJson, quoteArg, runnerPath, hookCommand, hookCommandWindows, isOurs };
