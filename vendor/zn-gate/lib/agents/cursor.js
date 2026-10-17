'use strict';

/**
 * Cursor (IDE agent) adapter.
 *
 * Hook format (cursor.com/docs/agent/hooks, read 2026-10-11):
 *
 *  hooks.json in ~/.cursor/ (user) or <project>/.cursor/ (project):
 *    { "version": 1, "hooks": { "<event>": [ { "command": "...", "timeout": <s>, "matcher": "<regex>" } ] } }
 *  Every event's stdin has conversation_id, generation_id, hook_event_name
 *  and workspace_roots, plus:
 *    beforeReadFile        file_path, content     -> {permission: allow|deny, user_message}
 *    beforeShellExecution  command, cwd           -> {permission: allow|deny|ask, user_message, agent_message}
 *    beforeSubmitPrompt    prompt                 -> {continue: bool, user_message}
 *    beforeMCPExecution    tool_name, tool_input, mcp_server_name, command|url
 *                                                 -> {permission: allow|deny, user_message, agent_message}
 *    postToolUse           tool_name, tool_input, tool_output (JSON string)
 *                                                 -> {updated_mcp_tool_output} (MCP tools only)
 *  No output (exit 0, empty stdout) counts as a hook failure that fails
 *  open: Cursor carries on with its own settings. That is how this adapter
 *  says "no opinion" for shell commands, so it never auto-approves.
 *
 * What Cursor allows, and so what zn does there (docs/compat.md):
 *  - Reads of credential files, .env with values and ~/.zn are denied
 *    (beforeReadFile cannot redact, only allow or deny).
 *  - Shell commands that read those files or manage the vault are denied.
 *    A command with __ZN_<NAME>__ markers is denied with the exact
 *    `zn run -- ...` command to use; once wrapped, Cursor asks the user.
 *    (preToolUse could rewrite it, but only together with "allow", and
 *    Cursor does not enforce "ask" there.)
 *  - Prompts with a secret are blocked.
 *  - MCP tool output is tokenized. Output of built-in tools (shell, file
 *    reads) cannot be rewritten in Cursor: a value printed by a command
 *    reaches the model. Keep secrets in the vault and .env files shadowed.
 *  - The Cursor CLI (cursor-agent) is not covered: its hook support is not
 *    documented and reported incomplete.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const cfg = require('./config-file');
const { whichSync } = require('../broker/markers');

const id = 'cursor';
const HOOK_TIMEOUT_S = 30;
const EVENTS = ['beforeMCPExecution', 'beforeReadFile', 'beforeShellExecution', 'beforeSubmitPrompt', 'postToolUse', 'preToolUse'];
const BUILTIN = { Shell: 'bash', Read: 'read', Write: 'write', Edit: 'edit', Grep: 'grep', Glob: 'glob', WebFetch: 'webfetch' };
// preToolUse covers the built-in tools that can name a file, so the same path checks apply.
const PRE_TOOL_MATCHER = 'Grep|Write|Delete';
// Events whose hook must block when it fails (crash, timeout, no output).
const FAIL_CLOSED = new Set(['beforeReadFile', 'beforeSubmitPrompt']);

function parseMaybeJson(s) {
  if (typeof s !== 'string') return s;
  try { return JSON.parse(s); } catch (_) { return s; }
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const name = raw.hook_event_name;
  const cwd = raw.cwd || (Array.isArray(raw.workspace_roots) && raw.workspace_roots[0]) || process.cwd();
  const base = { cwd, sessionId: raw.conversation_id || null, raw, hookEvent: name };
  if (name === 'beforeReadFile') return { ...base, event: 'pre_tool', tool: 'read', toolName: 'Read', input: { path: raw.file_path, texts: [] } };
  if (name === 'beforeShellExecution') return { ...base, event: 'pre_tool', tool: 'bash', toolName: 'Shell', input: { command: String(raw.command || ''), texts: [] } };
  if (name === 'beforeSubmitPrompt') return { ...base, event: 'user_prompt', tool: null, input: { prompt: typeof raw.prompt === 'string' ? raw.prompt : '' } };
  if (name === 'beforeMCPExecution') {
    return {
      ...base,
      event: 'pre_tool',
      tool: 'mcp',
      toolName: String(raw.tool_name || ''),
      mcp: { server: raw.mcp_server_name || null, tool: raw.tool_name },
      input: { args: parseMaybeJson(raw.tool_input) },
    };
  }
  if (name === 'preToolUse') {
    // The input keys of Grep, Write and Delete are not documented: the first
    // string under a known name is the path. Without one, respond() fails closed for writes.
    const toolName = String(raw.tool_name || '');
    const ti = raw.tool_input && typeof raw.tool_input === 'object' ? raw.tool_input : {};
    const pick = (...keys) => keys.map((k) => ti[k]).find((v) => typeof v === 'string' && v) || null;
    if (toolName === 'Grep') return { ...base, event: 'pre_tool', tool: 'grep', toolName, input: { path: pick('path', 'target_directory') || undefined, texts: [] } };
    if (toolName === 'Write' || toolName === 'Delete') {
      return { ...base, event: 'pre_tool', tool: 'write', toolName, input: { path: pick('file_path', 'path', 'target_file') || undefined, texts: [] } };
    }
    return { ...base, event: null };
  }
  if (name === 'postToolUse') {
    const toolName = String(raw.tool_name || '');
    const isMcp = /^MCP:/i.test(toolName) || !Object.prototype.hasOwnProperty.call(BUILTIN, toolName);
    return {
      ...base,
      event: 'post_tool',
      tool: isMcp ? 'mcp' : BUILTIN[toolName],
      toolName,
      mcp: isMcp ? { server: null, tool: toolName.replace(/^MCP:/i, '') } : null,
      input: { texts: [] },
      // Only MCP output can be rewritten in Cursor; built-in output is left alone.
      output: isMcp ? parseMaybeJson(raw.tool_output) : undefined,
    };
  }
  return { ...base, event: null };
}

function respond(d) {
  const ev = d && d.event;
  if (!ev || !ev.event) return null;
  const h = ev.hookEvent;
  if (h === 'preToolUse') {
    if (d.decision === 'deny') return { permission: 'deny', user_message: d.message || 'Blocked by zn', agent_message: d.message || 'Blocked by zn' };
    if (ev.tool === 'write' && !ev.input.path) {
      const msg = 'zn: could not read the file this call writes, so zn cannot check it. Name the file explicitly.';
      return { permission: 'deny', user_message: msg, agent_message: msg };
    }
    // No opinion, not "allow": an allow could skip Cursor's own confirmations.
    return null;
  }
  if (h === 'beforeReadFile') {
    if (d.decision === 'deny') return { permission: 'deny', user_message: d.message || 'Blocked by zn' };
    return { permission: 'allow' };
  }
  if (h === 'beforeShellExecution') {
    if (d.decision === 'deny') return { permission: 'deny', user_message: d.message || 'Blocked by zn', agent_message: d.message || 'Blocked by zn' };
    if (d.updatedInput && d.kind === 'wrap') {
      const msg = 'zn: this command uses a stored secret. Run it through zn instead, exactly like this: zn run -- ' + ev.input.command +
        '  (zn puts the value only into that process, if the user allowed this command for the secret).';
      return { permission: 'deny', user_message: msg, agent_message: msg };
    }
    if (d.decision === 'ask' && !d.updatedInput) return { permission: 'ask', user_message: d.message || 'zn asks for confirmation' };
    return null; // no opinion: Cursor's own approval settings apply
  }
  if (h === 'beforeSubmitPrompt') {
    if (d.decision === 'deny') return { continue: false, user_message: d.message || 'Blocked by zn' };
    return { continue: true };
  }
  if (h === 'beforeMCPExecution') {
    if (d.decision === 'deny') return { permission: 'deny', user_message: d.message || 'Blocked by zn', agent_message: d.message || 'Blocked by zn' };
    return null; // no opinion: Cursor's own MCP approval applies
  }
  if (h === 'postToolUse') {
    if (ev.tool === 'mcp' && d.updatedOutput !== undefined) {
      const out = { updated_mcp_tool_output: typeof d.updatedOutput === 'string' ? { text: d.updatedOutput } : d.updatedOutput };
      if (d.message) out.additional_context = d.message;
      return out;
    }
    return null;
  }
  return null;
}

/* ------------------------ install / uninstall ---------------------- */

function hooksFile(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.cursor', 'hooks.json');
  return path.join(opts.home || os.homedir(), '.cursor', 'hooks.json');
}

function strip(list) {
  return Array.isArray(list) ? list.filter((h) => !(h && cfg.isOurs(h.command, id))) : [];
}

function install(opts = {}) {
  const file = hooksFile(opts);
  const data = cfg.readJson(file);
  const report = { settings: file, backup: cfg.backup(file), warnings: [] };
  data.version = data.version || 1;
  data.hooks = cfg.hooksOf(data, file);
  // On Windows Cursor wraps hook commands in PowerShell, which cannot run a
  // quoted path as a command: the powershell.exe form runs there.
  const command = !opts.command && (opts.platform || process.platform) === 'win32'
    ? cfg.hookCommandWindows(id, opts)
    : cfg.hookCommand(id, opts);
  for (const event of EVENTS) {
    data.hooks[event] = strip(data.hooks[event]);
    const entry = { command, timeout: HOOK_TIMEOUT_S };
    if (event === 'preToolUse') entry.matcher = PRE_TOOL_MATCHER;
    if (FAIL_CLOSED.has(event)) entry.failClosed = true;
    data.hooks[event].push(entry);
  }
  cfg.writeJson(file, data);
  report.warnings.push('Cursor cannot rewrite the output of shell commands or file reads: zn blocks reads of secret files and redacts MCP output only (see docs/compat.md).');
  if (opts.mcp !== false) {
    const cli = path.resolve(__dirname, '..', '..', 'bin', 'cli.js').replace(/\\/g, '/');
    report.warnings.push('optional: to let Cursor use the secrets kept in zn\'s vault, add the "secrets" MCP server to ~/.cursor/mcp.json under "mcpServers": "secrets": ' +
      JSON.stringify({ command: (opts.nodePath || process.execPath).replace(/\\/g, '/'), args: [cli, 'secrets-mcp', '--agent', 'cursor'] }));
  }
  return report;
}

function uninstall(opts = {}) {
  const file = hooksFile(opts);
  const report = { settings: file, backup: null, removed: 0, warnings: [] };
  if (!fs.existsSync(file)) return report;
  const data = cfg.readJson(file);
  if (!data.hooks || typeof data.hooks !== 'object') return report;
  const before = JSON.stringify(data.hooks);
  for (const event of Object.keys(data.hooks)) {
    const kept = strip(data.hooks[event]);
    if (kept.length) data.hooks[event] = kept; else delete data.hooks[event];
  }
  if (JSON.stringify(data.hooks) !== before) {
    report.backup = cfg.backup(file);
    report.removed = 1;
    cfg.writeJson(file, data);
  }
  return report;
}

function detect(opts = {}) {
  if (whichSync('cursor', (opts.env || process.env).PATH || '')) return true;
  return fs.existsSync(path.join(opts.home || os.homedir(), '.cursor'));
}

module.exports = {
  id,
  detect,
  install,
  uninstall,
  normalize,
  respond,
  capabilities: { ask: 'shell', rewriteInput: false, rewriteOutput: 'mcp' },
  EVENTS,
  hooksFile,
};
