'use strict';

/**
 * Read-only check of the Claude Code settings that can stop zn's hooks or its
 * "secrets" MCP server from running. Claude Code gives no sign when an
 * organization policy drops a user hook or MCP server, so zn says it.
 *
 * Verified against (read 2026-10-15):
 *  https://code.claude.com/docs/en/managed-settings  (file locations, drop-ins)
 *  https://code.claude.com/docs/en/settings-reference (disableAllHooks, allowManagedHooksOnly)
 *  https://code.claude.com/docs/en/managed-mcp       (managed-mcp.json, allow/deny lists)
 *
 * Only files are read. Policy sent through claude.ai, MDM or the Windows
 * registry is not seen here, and when it exists Claude Code may ignore the
 * files; `claude doctor` shows which source it used. Hooks from plugins that
 * managed settings force-enable also survive allowManagedHooksOnly; zn is not
 * installed that way today.
 */

const fs = require('fs');
const path = require('path');

const MCP_SERVER_NAME = 'secrets';
// Our hook command (same test as the adapter's OUR_COMMAND_RE).
const OUR_COMMAND_RE = /(\bhook claude-code|hooks[\\/]runner\.js["']? claude-code)\s*$/;
const ASK_ADMIN = 'Claude Code does not show this. Ask your administrator to add zn to the managed settings.';

function managedDir(platform) {
  if (platform === 'darwin') return '/Library/Application Support/ClaudeCode';
  if (platform === 'win32') return 'C:\\Program Files\\ClaudeCode';
  return '/etc/claude-code';
}

/* {file, data} | {file, error} | null when the file does not exist. */
function readSource(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'ENOTDIR') return null;
    return { file, error: err.code || err.message };
  }
  try {
    const data = text.trim() ? JSON.parse(text) : {};
    return data && typeof data === 'object' && !Array.isArray(data) ? { file, data } : { file, error: 'not a JSON object' };
  } catch (err) {
    return { file, error: 'invalid JSON' };
  }
}

/* managed-settings.json, then the managed-settings.d/*.json drop-ins in name order. */
function managedSources(dir) {
  const out = [];
  const main = readSource(path.join(dir, 'managed-settings.json'));
  if (main) out.push(main);
  let names = [];
  try { names = fs.readdirSync(path.join(dir, 'managed-settings.d')); } catch (_) { /* none */ }
  for (const name of names.filter((n) => n.endsWith('.json')).sort()) {
    const s = readSource(path.join(dir, 'managed-settings.d', name));
    if (s) out.push(s);
  }
  return out;
}

function hasOurHook(data) {
  const hooks = data && data.hooks;
  if (!hooks || typeof hooks !== 'object') return false;
  for (const groups of Object.values(hooks)) {
    for (const g of Array.isArray(groups) ? groups : []) {
      for (const h of g && Array.isArray(g.hooks) ? g.hooks : []) {
        if (h && typeof h.command === 'string' && OUR_COMMAND_RE.test(h.command)) return true;
      }
    }
  }
  return false;
}

function list(v) {
  return Array.isArray(v) ? v : [];
}

// Commands match exactly: every argument, in order.
function sameCmd(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => String(x) === String(b[i]));
}

function deniesUs(e, cmd) {
  return !!e && typeof e === 'object' && (e.serverName === MCP_SERVER_NAME || (!!cmd && sameCmd(e.serverCommand, cmd)));
}

// A stdio server needs a serverCommand match once the allowlist has any
// serverCommand entry; before that, a serverName match is enough.
function allowsUs(entries, cmd) {
  const hasCmd = entries.some((e) => e && Array.isArray(e.serverCommand));
  return entries.some((e) => !!e && (hasCmd ? (!!cmd && sameCmd(e.serverCommand, cmd)) : e.serverName === MCP_SERVER_NAME));
}

function isTrue(v) {
  return v === true || v === 'true';
}

/**
 * claudeCodePolicyWarnings(opts) -> [string]
 * opts: {platform, managedDir, userSettings: [file], mcp: bool, mcpCommand: [command, ...args]}
 *  userSettings: the user's own settings files (disableAllHooks, MCP allow
 *  and deny lists), e.g. ~/.claude/settings.json.
 *  mcp: false when the "secrets" server is not installed (no MCP checks).
 */
function claudeCodePolicyWarnings(opts = {}) {
  const dir = opts.managedDir || managedDir(opts.platform || process.platform);
  const cmd = Array.isArray(opts.mcpCommand) ? opts.mcpCommand : null;
  const warnings = [];
  const managed = managedSources(dir);
  for (const s of managed.filter((x) => x.error)) {
    warnings.push('could not read the Claude Code managed settings ' + s.file + ' (' + s.error + '), so zn cannot tell whether they turn off its hooks.');
  }
  const ok = managed.filter((x) => x.data);
  const where = (s) => 'Your organization\'s Claude Code policy (' + s.file + ')';
  // A later drop-in replaces a single value set by an earlier file.
  const lastSet = (key) => { let r = null; for (const s of ok) if (s.data[key] !== undefined) r = s; return r; };
  const deployed = ok.some((s) => hasOurHook(s.data));

  const offSrc = lastSet('disableAllHooks');
  const off = offSrc && isTrue(offSrc.data.disableAllHooks) ? offSrc : null;
  if (off) {
    warnings.push(where(off) + ' turns off all hooks (disableAllHooks), so zn\'s hooks do not run. ' + ASK_ADMIN);
  } else {
    const onlySrc = lastSet('allowManagedHooksOnly');
    if (onlySrc && isTrue(onlySrc.data.allowManagedHooksOnly) && !deployed) {
      warnings.push(where(onlySrc) + ' runs only the hooks in its managed settings (allowManagedHooksOnly), so the zn hooks you install do not run. ' + ASK_ADMIN);
    }
  }

  const users = [];
  for (const file of opts.userSettings || []) {
    const s = readSource(file);
    if (s && s.data) users.push(s);
  }
  // A user's disableAllHooks cannot turn off managed hooks.
  if (!off && !deployed) {
    const userOff = users.find((s) => s.data.disableAllHooks === true);
    if (userOff) warnings.push(userOff.file + ' sets disableAllHooks, so no hooks you install run, zn\'s included. Remove that setting to turn them on.');
  }

  if (opts.mcp !== false) {
    const mcpFile = path.join(dir, 'managed-mcp.json');
    const m = readSource(mcpFile);
    let inManagedMcp = false;
    if (m && m.error) {
      warnings.push('could not read ' + mcpFile + ' (' + m.error + '), so zn cannot tell whether it allows the "secrets" MCP server.');
    } else if (m) {
      const servers = m.data.mcpServers && typeof m.data.mcpServers === 'object' ? m.data.mcpServers : {};
      // Servers listed here skip the allowlist, unless their entry uses ${VAR} expansion.
      inManagedMcp = Object.values(servers).some((v) => { const j = JSON.stringify(v || ''); return j.includes('secrets-mcp') && !j.includes('${'); });
      if (!Object.values(servers).some((v) => JSON.stringify(v || '').includes('secrets-mcp'))) {
        warnings.push('Your organization\'s Claude Code policy (' + mcpFile + ') loads only the MCP servers it lists, and zn\'s "secrets" server is not one of them, so it does not start. ' + ASK_ADMIN);
      }
    }
    const denied = [...ok, ...users].find((s) => list(s.data.deniedMcpServers).some((e) => deniesUs(e, cmd)));
    if (denied) {
      const who = ok.includes(denied) ? where(denied) : denied.file;
      warnings.push(who + ' blocks the "secrets" MCP server (deniedMcpServers), so it does not start.');
    } else if (!inManagedMcp) {
      const onlyMcp = ok.find((s) => isTrue(s.data.allowManagedMcpServersOnly));
      const entries = (srcs) => srcs.flatMap((s) => list(s.data.allowedMcpServers));
      const withList = (srcs) => srcs.filter((s) => Array.isArray(s.data.allowedMcpServers));
      if (onlyMcp) {
        // Only the managed lists count; with none, nothing is restricted.
        if (withList(ok).length && !allowsUs(entries(ok), cmd)) {
          warnings.push(where(onlyMcp) + ' allows only the MCP servers on its list (allowManagedMcpServersOnly), and zn\'s "secrets" server is not on it, so it does not start. ' + ASK_ADMIN);
        }
      } else {
        // Allowlists from every scope add up.
        const all = [...ok, ...users];
        const src = withList(all)[0];
        if (src && !allowsUs(entries(all), cmd)) {
          const who = ok.includes(src) ? where(src) : src.file;
          warnings.push(who + ' has an MCP allowlist (allowedMcpServers) that does not include zn\'s "secrets" server, so it does not start. Add it to allowedMcpServers (by its exact command if the list names commands), or ask your administrator.');
        }
      }
    }
  }
  return warnings;
}

/* ------------------------------ Codex CLI ------------------------------ */

/*
 * Codex settings that stop zn's hooks (read 2026-10-17):
 *  https://developers.openai.com/codex/enterprise/managed-configuration (requirements.toml, managed_config.toml)
 *  https://developers.openai.com/codex/hooks ([features] hooks, allow_managed_hooks_only)
 * requirements.toml is enforced; managed_config.toml sets defaults again at every start; the user's config.toml
 * can turn the user's own hooks off. Policy sent through MDM or the cloud is not seen here.
 */
function codexRequirementsFile(platform, env) {
  if (platform === 'win32') return path.join(env.ProgramData || 'C:\\ProgramData', 'OpenAI', 'Codex', 'requirements.toml');
  return '/etc/codex/requirements.toml';
}

function codexManagedConfigFile(platform, codexHome) {
  return platform === 'win32' ? path.join(codexHome, 'managed_config.toml') : '/etc/codex/managed_config.toml';
}

/* {file, data} | {file, error} | null when the file does not exist. */
function readToml(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'ENOTDIR') return null;
    return { file, error: err.code || err.message };
  }
  try {
    return { file, data: require('../audit/parse').parseToml(text).data };
  } catch (err) {
    return { file, error: 'invalid TOML' };
  }
}

/* [features] hooks (or its older name codex_hooks): true, false or undefined. */
function codexHooksFeature(data) {
  const f = data && data.features;
  if (!f || typeof f !== 'object') return undefined;
  const v = f.hooks !== undefined ? f.hooks : f.codex_hooks;
  return v === true || v === 'true' ? true : v === false || v === 'false' ? false : undefined;
}

/* Whether the managed hooks ([[hooks.<Event>]] with [[hooks.<Event>.hooks]]) include one of zn's own commands. */
function codexManagesZn(hooks) {
  const { isOurs } = require('./config-file');
  if (!hooks || typeof hooks !== 'object') return false;
  for (const groups of Object.values(hooks)) {
    for (const g of Array.isArray(groups) ? groups : []) {
      for (const h of g && Array.isArray(g.hooks) ? g.hooks : []) {
        if (h && (isOurs(h.command, 'codex') || isOurs(h.command_windows, 'codex') || isOurs(h.commandWindows, 'codex'))) return true;
      }
    }
  }
  return false;
}

/**
 * codexPolicyWarnings(opts) -> [string]
 * opts: {platform, env, codexHome, requirementsFile, managedConfigFile, userConfig}
 */
function codexPolicyWarnings(opts = {}) {
  const platform = opts.platform || process.platform;
  const env = opts.env || process.env;
  const home = opts.codexHome || path.join(require('os').homedir(), '.codex');
  const reqFile = opts.requirementsFile || codexRequirementsFile(platform, env);
  const managedFile = opts.managedConfigFile || codexManagedConfigFile(platform, home);
  const userFile = opts.userConfig || path.join(home, 'config.toml');
  const warnings = [];
  const ask = 'Codex does not show this. Ask your administrator to allow zn\'s hooks.';

  const req = readToml(reqFile);
  if (req && req.error) warnings.push('could not read the Codex requirements ' + reqFile + ' (' + req.error + '), so zn cannot tell whether they turn off its hooks.');
  const forced = req && req.data ? codexHooksFeature(req.data) : undefined;
  if (forced === false) {
    warnings.push('Your organization\'s Codex requirements (' + reqFile + ') turn hooks off ([features] hooks = false), so zn\'s hooks do not run. ' + ask);
    return warnings;
  }
  if (req && req.data && (req.data.allow_managed_hooks_only === true || req.data.allow_managed_hooks_only === 'true')
    && !codexManagesZn(req.data.hooks)) {
    warnings.push('Your organization\'s Codex requirements (' + reqFile + ') run only the hooks they manage (allow_managed_hooks_only), so the zn hooks you install do not run. ' + ask);
    return warnings;
  }
  if (forced === true) return warnings; // hooks are forced on: nothing below can turn them off.

  const managed = readToml(managedFile);
  if (managed && managed.error) warnings.push('could not read the Codex managed configuration ' + managedFile + ' (' + managed.error + ').');
  const managedHooks = managed && managed.data ? codexHooksFeature(managed.data) : undefined;
  if (managedHooks === false) {
    warnings.push('Your organization\'s Codex managed configuration (' + managedFile + ') turns hooks off ([features] hooks = false) at every start, so zn\'s hooks do not run. ' + ask);
    return warnings;
  }
  if (managedHooks === true) return warnings; // set again at every start, over the user's own config.toml
  const user = readToml(userFile);
  if (user && user.data && codexHooksFeature(user.data) === false) {
    warnings.push(userFile + ' turns hooks off ([features] hooks = false), so no hooks you install run, zn\'s included. Remove that line, or set it to true, to turn them on.');
  }
  return warnings;
}

module.exports = { claudeCodePolicyWarnings, managedDir, codexPolicyWarnings, _internal: { codexRequirementsFile, codexManagedConfigFile } };
