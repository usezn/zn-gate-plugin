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

function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
  if (!text.trim()) return {};
  let data;
  try {
    data = JSON.parse(text);
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
  writeFileAtomic(target, JSON.stringify(data, null, 2) + '\n', mode);
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
  return windowsCommand(opts.nodePath || process.execPath, [opts.runnerPath || runnerPath()], [agentId]);
}

/**
 * Whether a hook command is one zn wrote for this agent: `zn hook <agent>`,
 * the runner called with double quotes (older versions) or single quotes,
 * or the Windows powershell.exe form.
 */
function isOurs(command, agentId) {
  if (typeof command !== 'string') return false;
  const re = new RegExp('(\\bhook ' + agentId + '|hooks[\\\\/]runner\\.js["\']? ' + agentId + ')\\s*$');
  if (re.test(command)) return true;
  const script = windowsCommandScript(command);
  return script !== null && re.test(script);
}

module.exports = { readJson, hooksOf, backup, writeJson, quoteArg, runnerPath, hookCommand, hookCommandWindows, isOurs };
