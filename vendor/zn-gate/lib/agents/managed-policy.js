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
    const data = text.trim() ? JSON.parse(text.replace(/^\uFEFF/, '')) : {};
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
        if (h && typeof h.command === 'string' && (OUR_COMMAND_RE.test(h.command) || require('./launcher').isProjectGuard(h.command, 'claude-code'))) return true;
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

/* ------------------------------ Cursor ------------------------------ */

/*
 * Cursor's enterprise hooks.json (read 2026-10-19, https://cursor.com/docs/hooks):
 *  macOS /Library/Application Support/Cursor/hooks.json, Linux and WSL /etc/cursor/hooks.json,
 *  Windows C:\ProgramData\Cursor\hooks.json. Format: {"version": 1, "hooks": {"<event>": [{command, failClosed, ...}]}}.
 *  Priority: Enterprise, Team, Project, User. Hooks from every source run and Cursor merges their responses
 *  (a deny beats an ask, an ask beats an allow), so an enterprise file does not switch off hooks of the user.
 *  failClosed (default false) makes a crash, timeout or empty reply block the action.
 * Team hooks live in Cursor's dashboard and are not seen here.
 */
const CURSOR_FAIL_CLOSED_EVENTS = ['beforeReadFile', 'beforeSubmitPrompt'];

function cursorEnterpriseFile(platform, env) {
  if (platform === 'darwin') return '/Library/Application Support/Cursor/hooks.json';
  if (platform === 'win32') return path.join((env && env.ProgramData) || 'C:\\ProgramData', 'Cursor', 'hooks.json');
  return '/etc/cursor/hooks.json';
}

/**
 * cursorPolicyWarnings(opts) -> [string]
 * opts: {platform, env, hooksFile}  (hooksFile replaces the system path, for tests)
 * Read-only. Empty when the enterprise file does not exist.
 */
function cursorPolicyWarnings(opts = {}) {
  const { isOurs } = require('./config-file');
  const file = opts.hooksFile || cursorEnterpriseFile(opts.platform || process.platform, opts.env || process.env);
  const src = readSource(file);
  if (!src) return [];
  if (src.error) return ['could not read the Cursor enterprise hooks ' + src.file + ' (' + src.error + '), so zn cannot tell whether zn\'s hooks are set to fail closed there.'];
  const hooks = src.data.hooks && typeof src.data.hooks === 'object' ? src.data.hooks : {};
  const entries = (event) => (Array.isArray(hooks[event]) ? hooks[event] : []).filter((h) => h && typeof h === 'object');
  const ours = (h) => isOurs(h.command, 'cursor');
  const hasOurs = Object.keys(hooks).some((ev) => entries(ev).some(ours));
  const hasAny = Object.keys(hooks).some((ev) => entries(ev).length > 0);
  const warnings = [];
  if (hasOurs) {
    for (const ev of CURSOR_FAIL_CLOSED_EVENTS) {
      if (!entries(ev).some((h) => ours(h) && h.failClosed === true)) {
        warnings.push('The Cursor enterprise hooks ' + src.file + ' have no zn hook with "failClosed": true under hooks.' + ev
          + ', so if zn\'s hook crashes or times out Cursor lets the ' + (ev === 'beforeReadFile' ? 'file read' : 'prompt') + ' through. Ask your administrator to add it.');
      }
    }
  } else if (hasAny) {
    warnings.push('The Cursor enterprise hooks ' + src.file + ' do not include zn\'s hook. They do not turn off the zn hooks you install: Cursor runs the hooks of every source and merges their replies, enterprise first. Run `zn team managed-config --agent cursor` to see what an administrator can add so zn fails closed.');
  }
  return warnings;
}

// JSON with the line and block comments that Gemini CLI allows in settings.json (comments outside strings are dropped).
function parseJsonc(text) {
  text = text.replace(/^\uFEFF/, '');
  try { return JSON.parse(text); } catch (_) { /* try without comments */ }
  let out = '';
  let i = 0;
  let inStr = false;
  while (i < text.length) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === '\\') { out += text[i + 1] || ''; i += 2; continue; }
      if (c === '"') inStr = false;
      i++;
    } else if (c === '"') { inStr = true; out += c; i++; }
    else if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; }
    else if (c === '/' && text[i + 1] === '*') { const j = text.indexOf('*/', i + 2); i = j < 0 ? text.length : j + 2; }
    else { out += c; i++; }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
}

/**
 * geminiPolicyWarnings({files: [{file, label}]}) -> [string]
 * Read-only: Gemini CLI settings that stop hooks from running (read 2026-10-19):
 *   hooksConfig.enabled false ("no hooks will be executed"), hooksConfig.disabled (hook names or commands that
 *   do not run even when configured), and the older tools.enableHooks / hooks.enabled / hooks.disabled switches.
 * The docs rank project over user over system settings; zn reports a switch in any of them, since a list is a
 * union and a scalar from a higher file would only hide a lower one by turning hooks back on.
 */
function geminiPolicyWarnings(opts = {}) {
  const { isOurs } = require('./config-file');
  const warnings = [];
  const named = (v) => typeof v === 'string' && (v === 'zn-gate' || isOurs(v, 'gemini'));
  for (const { file, label } of opts.files || []) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch (err) {
      if (err.code === 'ENOENT' || err.code === 'ENOTDIR') continue;
      warnings.push('could not read ' + file + ' (' + (err.code || 'error') + '), so zn cannot tell whether it turns off its hooks.');
      continue;
    }
    let data;
    try { data = parseJsonc(text.replace(/^\uFEFF/, '')); } catch (_) {
      warnings.push('could not read ' + file + ' (invalid JSON), so zn cannot tell whether it turns off its hooks.');
      continue;
    }
    if (!data || typeof data !== 'object') continue;
    const hc = data.hooksConfig && typeof data.hooksConfig === 'object' ? data.hooksConfig : {};
    const hk = data.hooks && typeof data.hooks === 'object' && !Array.isArray(data.hooks) ? data.hooks : {};
    const tl = data.tools && typeof data.tools === 'object' ? data.tools : {};
    if (hc.enabled === false || tl.enableHooks === false || hk.enabled === false) {
      warnings.push(label + ' (' + file + ') turn all hooks off (hooksConfig.enabled is false), so zn\'s hook does not run. Set it to true to turn hooks on.');
      continue;
    }
    const lists = [hc.disabled, hk.disabled].filter(Array.isArray);
    if (lists.some((l) => l.some(named))) {
      warnings.push(label + ' (' + file + ') list zn\'s hook in hooksConfig.disabled (for example after `/hooks disable`), so it does not run. Remove it from that list, or run `/hooks enable zn-gate` in Gemini CLI.');
    }
  }
  return warnings;
}

/* ------------------------- zn installed by the organization ------------------------- */

/*
 * Whether zn's hooks are in the agent's managed configuration (what an administrator deploys with MDM or
 * configuration management; `zn team managed-config` prints it). Read-only. Verified 2026-10-19 against:
 *  https://code.claude.com/docs/en/settings  (managed-settings.json, managed-settings.d/*.json)
 *  https://cursor.com/docs/hooks             (enterprise hooks.json)
 *  https://learn.chatgpt.com/docs/enterprise/managed-configuration (requirements.toml: [[hooks.<Event>]])
 * Hooks of the managed layer and of the user both run, so a user-level setup next to it runs twice.
 * Policy sent through MDM profiles, the Windows registry or the agent's cloud is not seen here.
 */

/* [{event, matcher, command}] for every hook command in a hooks tree that is zn's own for this agent. */
function ourHookEntries(hooks, agentId) {
  const { isOurs } = require('./config-file');
  const out = [];
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) return out;
  for (const [event, list] of Object.entries(hooks)) {
    for (const g of Array.isArray(list) ? list : []) {
      if (!g || typeof g !== 'object') continue;
      const cands = [g];
      for (const h of Array.isArray(g.hooks) ? g.hooks : []) cands.push(h);
      for (const h of cands) {
        if (!h || typeof h !== 'object') continue;
        const command = [h.command, h.command_windows, h.commandWindows].find((c) => isOurs(c, agentId));
        if (command) out.push({ event, matcher: g.matcher, command });
      }
    }
  }
  return out;
}

/**
 * managedInstall(agentId, opts) -> {files: [path], entries: [{event, matcher, command}]} | null
 * null when no managed file holds a zn hook. agentId: 'claude-code', 'codex' or 'cursor'.
 * opts: the same injectable paths as the policy checks above (managedDir; requirementsFile; hooksFile;
 * platform, env), so tests never read the real system folders.
 */
function managedInstall(agentId, opts = {}) {
  const platform = opts.platform || process.platform;
  const env = opts.env || process.env;
  const found = [];
  if (agentId === 'claude-code') {
    for (const s of managedSources(opts.managedDir || managedDir(platform))) {
      if (s.data) found.push({ file: s.file, entries: ourHookEntries(s.data.hooks, agentId) });
    }
  } else if (agentId === 'codex') {
    const r = readToml(opts.requirementsFile || codexRequirementsFile(platform, env));
    if (r && r.data) found.push({ file: r.file, entries: ourHookEntries(r.data.hooks, agentId) });
  } else if (agentId === 'cursor') {
    const r = readSource(opts.hooksFile || cursorEnterpriseFile(platform, env));
    if (r && r.data) found.push({ file: r.file, entries: ourHookEntries(r.data.hooks, agentId) });
  }
  const withZn = found.filter((f) => f.entries.length);
  if (!withZn.length) return null;
  return { files: withZn.map((f) => f.file), entries: withZn.flatMap((f) => f.entries) };
}

module.exports = { claudeCodePolicyWarnings, managedDir, codexPolicyWarnings, cursorPolicyWarnings, geminiPolicyWarnings, managedInstall, _internal: { codexRequirementsFile, codexManagedConfigFile, cursorEnterpriseFile, ourHookEntries } };
