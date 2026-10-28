'use strict';

/**
 * Claude Code adapter (reference implementation for the other agents).
 *
 * Hook format verified against https://code.claude.com/docs/en/hooks
 * (read 2026-10-11):
 *
 *  settings.json:
 *    { "hooks": { "<Event>": [ { "matcher": "<regex on tool_name>",
 *                                "hooks": [ { "type": "command", "command": "...", "timeout": <s> } ] } ] } }
 *    User scope: ~/.claude/settings.json ($CLAUDE_CONFIG_DIR when set);
 *    project scope: <project>/.claude/settings.json.
 *
 *  stdin (all events): session_id, transcript_path, cwd, permission_mode,
 *    hook_event_name; PreToolUse/PostToolUse add tool_name, tool_input,
 *    tool_use_id; PostToolUse adds tool_response; UserPromptSubmit adds prompt.
 *    MCP tools are named mcp__<server>__<tool>. tool_input.file_path is absolute.
 *
 *  PreToolUse output: hookSpecificOutput.{hookEventName, permissionDecision
 *    (allow|deny|ask|defer), permissionDecisionReason, updatedInput,
 *    additionalContext}. additionalContext goes to the model; we use it to
 *    say that a secret was kept as a marker (d.context).
 *    "updatedInput ... Replaces the entire input object, so include unchanged
 *    fields alongside modified ones"; combined with "allow" it auto-approves,
 *    with "ask" it shows the modified input to the user. We always use "ask"
 *    when we rewrite, so the user's own permission rules are never bypassed.
 *
 *  PostToolUse output: hookSpecificOutput.{hookEventName, updatedToolOutput,
 *    additionalContext}. "The value must match the tool's output shape"; a
 *    mismatching value is ignored for built-in tools, MCP output is not
 *    validated. We rewrite string leaves only, so the shape is preserved.
 *    Top-level decision:"block" does NOT hide the original output.
 *
 *  UserPromptSubmit output: top-level {decision: "block", reason} stops the
 *    prompt before it reaches Claude; hookSpecificOutput.suppressOriginalPrompt
 *    keeps the text out of the block message (it can still be in the local
 *    transcript and prompt history, which stay on this machine).
 *
 *  UserPromptExpansion (read 2026-10-17): fires when a typed skill or command
 *    expands into a prompt; input adds expansion_type, command_name,
 *    command_args, command_source and prompt (the expanded text). It can block
 *    ({decision: "block", reason}) but cannot rewrite the text. UserPromptSubmit
 *    sees only what was typed, so this event is where the expansion is checked.
 *
 *  Exit code 0 with JSON on stdout; any other non-2 code is a non-blocking
 *  error (the action proceeds), which is our fail-open behaviour.
 *
 *  A hook that cannot start (read 2026-10-20): "Non-blocking error: your hook
 *  exits with any other code, or fails in some other way, such as not
 *  starting or printing invalid JSON. The action goes ahead, except for hooks
 *  whose failure blocks the action, for example a hook with `onFailure` set
 *  to "block"." and "In shell form, when the script path doesn't exist or
 *  isn't executable, the shell exits with a code like 127 ... a hook that
 *  can't start is a non-blocking error too." So a user install writes a
 *  launcher script (lib/agents/launcher.js) as the hook command: if the
 *  Node.js it was installed with is gone it exits 2 with the reason on stderr
 *  (PreToolUse, UserPromptSubmit, UserPromptExpansion) or only warns
 *  (PostToolUse). PreToolUse also carries onFailure "block" (Claude Code
 *  2.1.295 and later; earlier versions ignore it).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
// Loaded on first use: the hook does not run `claude` and child_process costs a few milliseconds to load.
let spawnSyncLazy = null;
function spawnSync(...args) {
  if (!spawnSyncLazy) spawnSyncLazy = require('child_process').spawnSync;
  return spawnSyncLazy(...args);
}
const { writeFileAtomic } = require('../broker/files');
const { whichSync } = require('../broker/markers');
const { shQuote, portablePath } = require('../shell-quote');
const { claudeCodePolicyWarnings } = require('./managed-policy');
const cfg = require('./config-file');
const { hooksOf } = cfg;
const launcher = require('./launcher');

const id = 'claude-code';

// A regex (it contains mcp__.*), anchored so it names exactly these tools. PowerShell and Monitor run
// commands like Bash; LSP reads files; the MCP tools are checked for secrets and personal data before they run.
const PRE_MATCHER = '^(Bash|PowerShell|Monitor|Read|Grep|LSP|Edit|MultiEdit|Write|NotebookEdit|WebFetch)$|^mcp__.*';
// A regex (it contains mcp__.*), anchored so it names exactly these tools.
const POST_MATCHER = '^(Bash|PowerShell|Monitor|Read|Grep|LSP|WebFetch|ReadMcpResourceTool)$|^mcp__.*';
const HOOK_TIMEOUT_S = 15;
// Older versions wrote the paths in double quotes; both forms are ours.
// zn's launcher script (lib/agents/launcher.js) is ours too: '<dir>/zn-hook-claude-code.sh' <Event>
const OUR_COMMAND_RE = /(\bhook claude-code|hooks[\\/]runner\.js["']? claude-code|zn-hook-claude-code\.sh["']? [A-Za-z]+)\s*$/;
const MCP_SERVER_NAME = 'secrets';

const TOOL_MAP = {
  Bash: 'bash',
  PowerShell: 'powershell',
  Monitor: 'monitor',
  LSP: 'lsp',
  ReadMcpResourceTool: 'mcpresource',
  Read: 'read',
  Write: 'write',
  Edit: 'edit',
  MultiEdit: 'multiedit',
  NotebookEdit: 'notebookedit',
  Grep: 'grep',
  Glob: 'glob',
  WebFetch: 'webfetch',
  WebSearch: 'websearch',
};

/* ----------------------------- events ----------------------------- */

function textsOf(tool, input) {
  const texts = [];
  const add = (key, v) => { if (typeof v === 'string') texts.push({ key, value: v }); };
  if (tool === 'write') add(['content'], input.content);
  if (tool === 'edit') { add(['old_string'], input.old_string); add(['new_string'], input.new_string); }
  if (tool === 'notebookedit') add(['new_source'], input.new_source);
  if (tool === 'multiedit' && Array.isArray(input.edits)) {
    input.edits.forEach((e, i) => {
      if (e && typeof e === 'object') { add(['edits', i, 'old_string'], e.old_string); add(['edits', i, 'new_string'], e.new_string); }
    });
  }
  return texts;
}

// `ours` is set only for a call to zn's own server, verified from the MCP configuration (znMcpServerKind).
function mcpInfo(server, tool, event, cwd) {
  const info = { server, tool };
  const ours = event === 'pre_tool' ? znMcpServerKind(server, cwd) : null;
  if (ours) info.ours = ours;
  return info;
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const name = raw.hook_event_name;
  const event = name === 'PreToolUse' ? 'pre_tool'
    : name === 'PostToolUse' ? 'post_tool'
      : name === 'UserPromptSubmit' ? 'user_prompt'
        : name === 'UserPromptExpansion' ? 'prompt_expansion' : null;
  const base = { event, cwd: raw.cwd || process.cwd(), sessionId: raw.session_id || null, raw };
  if (event === 'user_prompt') return { ...base, tool: null, input: { prompt: typeof raw.prompt === 'string' ? raw.prompt : '' }, output: undefined };
  if (event === 'prompt_expansion') return { ...base, tool: null, input: { prompt: typeof raw.prompt === 'string' ? raw.prompt : '' }, output: undefined };
  if (!event) return base;
  const toolName = String(raw.tool_name || '');
  const mcp = /^mcp__(.+?)__(.+)$/.exec(toolName);
  const tool = mcp ? 'mcp' : (TOOL_MAP[toolName] || toolName.toLowerCase());
  const ti = raw.tool_input && typeof raw.tool_input === 'object' ? raw.tool_input : {};
  const input = {
    command: typeof ti.command === 'string' ? ti.command : undefined,
    path: ti.file_path || ti.notebook_path || ti.filePath || ti.path || undefined,
    url: typeof ti.url === 'string' ? ti.url : undefined,
    texts: textsOf(tool, ti),
  };
  // For an MCP tool, tool_input is the call's arguments; runner.js checks them (as for Codex).
  if (mcp) input.args = ti;
  return {
    ...base,
    tool,
    toolName,
    mcp: mcp ? mcpInfo(mcp[1], mcp[2], event, base.cwd) : null,
    input,
    output: event === 'post_tool' ? raw.tool_response : undefined,
  };
}

function setPath(obj, key, value) {
  let cur = obj;
  for (let i = 0; i < key.length - 1; i++) cur = cur[key[i]];
  cur[key[key.length - 1]] = value;
}

function buildUpdatedInput(ev, upd) {
  const input = JSON.parse(JSON.stringify((ev.raw && ev.raw.tool_input) || {}));
  if (typeof upd.command === 'string') input.command = upd.command;
  for (const t of upd.texts || []) setPath(input, t.key, t.value);
  return input;
}

/**
 * Internal decision -> Claude Code hook JSON (or null for "no opinion").
 * d = {decision: 'allow'|'deny'|'ask', updatedInput?, updatedOutput?, message?, event}
 */
function respond(d) {
  const ev = d && d.event;
  if (!ev || !ev.event) return null;
  const out = respondInner(d, ev);
  // systemMessage: a notice shown to the user (not to the model). It can stand alone, on an allow that has nothing else to say.
  if (out && d.userMessage) out.systemMessage = d.userMessage;
  else if (!out && d.userMessage && d.decision === 'allow') return { systemMessage: d.userMessage };
  return out;
}

function respondInner(d, ev) {
  if (ev.event === 'pre_tool') {
    if (d.decision === 'deny') {
      return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: d.message || 'Blocked by zn' } };
    }
    if (d.updatedInput) {
      const out = {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: d.decision === 'allow' ? 'allow' : 'ask',
          permissionDecisionReason: d.message || 'Modified by zn',
          updatedInput: buildUpdatedInput(ev, d.updatedInput),
        },
      };
      if (d.context) out.hookSpecificOutput.additionalContext = d.context;
      return out;
    }
    if (d.decision === 'ask') {
      const out = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: d.message || 'zn asks for confirmation' } };
      if (d.context) out.hookSpecificOutput.additionalContext = d.context;
      return out;
    }
    return null; // never emit a bare "allow": it would bypass the user's permission rules
  }
  if (ev.event === 'post_tool') {
    if (d.updatedOutput !== undefined) {
      const out = { hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: d.updatedOutput } };
      if (d.message) out.hookSpecificOutput.additionalContext = d.message;
      return out;
    }
    if (d.decision === 'deny') return { decision: 'block', reason: d.message || 'Blocked by zn' };
    // A note for the agent with the output unchanged (for example, text in it that reads like instructions).
    if (d.message) return { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: d.message } };
    return null;
  }
  if (ev.event === 'user_prompt') {
    if (d.decision === 'deny') {
      return {
        decision: 'block',
        reason: d.message || 'Blocked by zn',
        hookSpecificOutput: { hookEventName: 'UserPromptSubmit', suppressOriginalPrompt: true },
      };
    }
    return null;
  }
  if (ev.event === 'prompt_expansion') {
    return d.decision === 'deny' ? { decision: 'block', reason: d.message || 'Blocked by zn' } : null;
  }
  return null;
}

/* ------------------------ install / uninstall ---------------------- */

function configDir(opts = {}) {
  const env = opts.env || process.env;
  if (env.CLAUDE_CONFIG_DIR) return path.resolve(env.CLAUDE_CONFIG_DIR);
  return path.join(opts.home || os.homedir(), '.claude');
}

function settingsFile(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.claude', 'settings.json');
  return path.join(configDir(opts), 'settings.json');
}

// Claude Code runs a hook command with `sh -c` (macOS, Linux) or Git Bash
// (Windows): each path is one single-quoted sh word.
function quoteArg(s, platform) {
  return shQuote(portablePath(s, platform));
}

function cliPath() {
  return path.resolve(__dirname, '..', '..', 'bin', 'cli.js');
}

function runnerPath() {
  return path.resolve(__dirname, '..', 'hooks', 'runner.js');
}

// The hook calls lib/hooks/runner.js directly (same as `zn hook claude-code`)
// so each tool call does not pay for loading the whole CLI.
function hookCommand(opts = {}) {
  if (opts.command) return opts.command;
  // A project install is a shared file: it names zn on the PATH, never the paths of the machine that installed it.
  if ((opts.scope || 'user') === 'project') return 'zn hook claude-code';
  return quoteArg(opts.nodePath || process.execPath, opts.platform) + ' ' + quoteArg(opts.runnerPath || runnerPath(), opts.platform) + ' claude-code';
}

function readJson(file) {
  let data;
  try {
    const text = fs.readFileSync(file, 'utf8');
    data = text.replace(/^\uFEFF/, '').trim() ? cfg.parseJson(text) : {};
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw new Error('cannot parse ' + file + ': ' + err.message);
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error(file + ' must hold a JSON object, not ' + (data === null ? 'null' : Array.isArray(data) ? 'an array' : typeof data) + ' (left unchanged)');
  }
  return data;
}

/* A field that must hold a JSON object: missing or null is empty; an array or a scalar is refused, never overwritten. */
function objectField(data, key, file) {
  const v = data[key];
  if (v === undefined || v === null) return {};
  if (typeof v !== 'object' || Array.isArray(v)) {
    throw new Error('"' + key + '" in ' + file + ' must be an object, not ' + (Array.isArray(v) ? 'an array' : typeof v) + ' (left unchanged)');
  }
  return v;
}

/* Uninstall checks the project .mcp.json before anything is changed, so a refusal leaves both files as they were. */
function assertMcpFile(opts = {}) {
  if (opts.mcp === false || (opts.scope || 'user') !== 'project') return;
  const file = path.join(path.resolve(opts.projectDir || process.cwd()), '.mcp.json');
  if (fs.existsSync(file)) objectField(readJson(file), 'mcpServers', file);
}

function backup(file) {
  if (!fs.existsSync(file)) return null;
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const dest = file + '.bak-zn-' + stamp;
  fs.copyFileSync(file, dest);
  return dest;
}

function stripOurs(groups) {
  if (!Array.isArray(groups)) return [];
  const out = [];
  for (const g of groups) {
    if (!g || !Array.isArray(g.hooks)) { out.push(g); continue; }
    const hooks = g.hooks.filter((h) => !(h && typeof h.command === 'string' && (OUR_COMMAND_RE.test(h.command) || launcher.isProjectGuard(h.command, id))));
    if (hooks.length) out.push({ ...g, hooks });
  }
  return out;
}

// command: one command for every event, or a function of the event name (the launcher needs it).
function ourHooks(command) {
  const h = (event) => ({ type: 'command', command: typeof command === 'function' ? command(event) : command, timeout: HOOK_TIMEOUT_S });
  return {
    // A hook that cannot start or times out blocks the call (Claude Code 2.1.295 and later; earlier
    // versions ignore the field, and the launcher covers them).
    PreToolUse: { matcher: PRE_MATCHER, hooks: [{ ...h('PreToolUse'), onFailure: 'block' }] },
    PostToolUse: { matcher: POST_MATCHER, hooks: [h('PostToolUse')] },
    // A prompt hook that cannot start or times out blocks the prompt
    // (Claude Code 2.1.295 and later; earlier versions ignore the field).
    UserPromptSubmit: { hooks: [{ ...h('UserPromptSubmit'), onFailure: 'block' }] },
    // A typed skill or command expands after UserPromptSubmit; this checks the expanded text.
    UserPromptExpansion: { hooks: [{ ...h('UserPromptExpansion'), onFailure: 'block' }] },
  };
}

/**
 * The hook command for each event. A user install goes through zn's launcher so that a Node.js that has gone
 * away blocks instead of letting Claude Code run the call unchecked (exit 127 is a non-blocking error);
 * a project install (the file is shared, an absolute path is not) runs `zn` from the PATH inside a start guard that blocks the same
 * way; a command given by the caller keeps the plain command. Claude Code runs hooks with sh (Git Bash on Windows), so the same script serves Windows.
 */
function commandFor(opts = {}) {
  if (opts.command) return hookCommand(opts);
  // A project install names `zn` on the PATH inside zn's own start guard (launcher.projectShCommand): a missing zn or Node.js blocks.
  if ((opts.scope || 'user') === 'project') return (event) => launcher.projectShCommand(id, event);
  const node = opts.nodePath || process.execPath;
  const runner = opts.runnerPath || runnerPath();
  const file = launcher.writeLauncher(id, node, runner, { ...opts, deadlineS: launcher.launcherDeadlineS(HOOK_TIMEOUT_S), deadlineSoft: true });
  return (event) => launcher.launcherCommand(file, event, opts.platform);
}

function mcpServerConfig(opts = {}) {
  return { command: opts.nodePath || process.execPath, args: [opts.cliPath || cliPath(), 'secrets-mcp', '--agent', 'claude-code'] };
}

const PROJECT_MCP_NOTE = 'a project install adds no MCP server: to use zn\'s secrets tools in Claude Code, run `zn hooks install claude-code` (your user settings)';

/* A project install registers no MCP server. The shared .mcp.json could only name `zn`, and Claude Code looks that
 * name up on the PATH it was started with, where a folder of the project can come first. The server an earlier
 * zn-gate wrote there (the bare `zn secrets-mcp`) is removed, with a backup. */
function removeProjectMcp(opts, report) {
  const file = path.join(path.resolve(opts.projectDir || process.cwd()), '.mcp.json');
  if (fs.existsSync(file)) {
    let data;
    let servers;
    try {
      data = readJson(file);
      servers = objectField(data, 'mcpServers', file);
    } catch (err) {
      report.warnings.push('could not read ' + file + ' (' + err.message + '), so it was left as it is; ' + PROJECT_MCP_NOTE);
      return;
    }
    if (isBareZnSecrets(servers[MCP_SERVER_NAME])) {
      report.mcpBackup = backup(file);
      delete servers[MCP_SERVER_NAME];
      writeFileAtomic(file, cfg.stringifyJson(data), 0o644);
      report.warnings.push('removed the MCP server "' + MCP_SERVER_NAME + '" that an earlier zn-gate wrote to ' + file + ' (it started `zn` by name); ' + PROJECT_MCP_NOTE);
      return;
    }
  }
  report.warnings.push(PROJECT_MCP_NOTE);
}

/* The claude CLI to run for `claude mcp`: on the PATH entries outside the project, and not a link into the project. */
function findClaude(env) {
  const exe = require('../exe');
  const found = whichSync('claude', exe.programEnv(env).PATH);
  return found && !exe.programInProject(found, env, process.cwd()) ? found : null;
}

function installMcp(opts, report) {
  if ((opts.scope || 'user') === 'project') return removeProjectMcp(opts, report);
  const conf = mcpServerConfig(opts);
  // Absolute PATH entries outside the project only (install often runs in a project folder), and never a claude whose real
  // file is in the project. A claude.cmd (npm on Windows) is still found here, for the batch-file note below.
  const claude = opts.claudeBin !== undefined ? opts.claudeBin : findClaude(opts.env || process.env);
  // No JSON: this form works the same in cmd.exe, PowerShell and POSIX shells.
  const manual = 'claude mcp add --scope user ' + MCP_SERVER_NAME + ' -- ' + [conf.command, ...conf.args].map((a) => '"' + a + '"').join(' ');
  if (!claude) {
    report.warnings.push('`claude` CLI not found: register the MCP server yourself with: ' + manual);
    return;
  }
  // A batch-file `claude` (an npm install on Windows) only runs through
  // cmd.exe, which re-parses the command line: the JSON (quotes, paths with
  // spaces or & ^ %) would not reach it intact. Never start it that way.
  if (/\.(?:cmd|bat)$/i.test(claude)) {
    report.warnings.push('`claude` is a batch file (' + path.basename(claude) + '), which zn does not run through cmd.exe: register the MCP server yourself with: ' + manual);
    return;
  }
  // Only absolute PATH entries outside the project: a `claude` script that starts with `#!/usr/bin/env node`
  // looks node up there.
  const r = spawnSync(claude, ['mcp', 'add-json', '--scope', 'user', MCP_SERVER_NAME, JSON.stringify({ type: 'stdio', ...conf })],
    { encoding: 'utf8', windowsHide: true, env: require('../exe').programEnv(opts.env || process.env) });
  if (r.status === 0) report.mcp = 'claude mcp (user scope)';
  else report.warnings.push('`claude mcp add-json` failed (' + String(r.stderr || r.stdout || r.error || '').trim().slice(0, 300) + '): register the MCP server yourself with: ' + manual);
}

/* A project install names `zn`, so it only works where zn is on the PATH. opts.znBin overrides the lookup (tests). */
function znOnPath(opts = {}) {
  if (opts.znBin !== undefined) return !!opts.znBin;
  const envPath = (opts.env || process.env).PATH || '';
  if (whichSync('zn', envPath)) return true;
  return process.platform === 'win32' && !!(whichSync('zn.cmd', envPath) || whichSync('zn.exe', envPath));
}

/**
 * Write the hook configuration (and register the "secrets" MCP server).
 * opts: {scope: 'user'|'project', projectDir, home, env, nodePath, cliPath, command, mcp: false, claudeBin, znBin}
 */
function install(opts = {}) {
  const file = settingsFile(opts);
  const data = readJson(file);
  const report = { settings: file, backup: backup(file), warnings: [] };
  data.hooks = hooksOf(data, file);
  const ours = ourHooks(commandFor(opts));
  for (const [event, group] of Object.entries(ours)) {
    data.hooks[event] = stripOurs(data.hooks[event]);
    data.hooks[event].push(group);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  writeFileAtomic(file, cfg.stringifyJson(data), 0o644);
  if (opts.mcp !== false) installMcp(opts, report);
  if (!opts.command && (opts.scope || 'user') === 'project' && !znOnPath(opts)) {
    report.warnings.push('`zn` is not on your PATH, and this project install runs `zn hook claude-code`' +
      ': until zn-gate is installed globally (npm i -g zn-gate, or pip install zn-gate), the hooks fail here and Claude Code may block every tool call or skip the secret checks. Everyone who uses this project needs zn on their PATH.');
  }
  // Organization settings can turn these hooks or the MCP server off with no
  // sign in Claude Code; say it here.
  // Advisory only: a failure here never fails an install already written.
  try {
    const users = [...new Set([file, path.join(configDir(opts), 'settings.json')])];
    const conf = mcpServerConfig(opts);
    report.warnings.push(...claudeCodePolicyWarnings({
      managedDir: opts.managedDir, userSettings: users, mcp: opts.mcp !== false && (opts.scope || 'user') !== 'project', mcpCommand: [conf.command, ...conf.args],
    }));
  } catch (_) { /* no policy note */ }
  return report;
}

function uninstall(opts = {}) {
  const file = settingsFile(opts);
  const report = { settings: file, backup: null, removed: 0, warnings: [] };
  assertMcpFile(opts);
  if (fs.existsSync(file)) {
    const data = readJson(file);
    const hooks = hooksOf(data, file);
    const before = JSON.stringify(hooks);
    for (const event of Object.keys(hooks)) {
      const kept = stripOurs(hooks[event]);
      if (kept.length) hooks[event] = kept; else delete hooks[event];
    }
    if (Object.keys(hooks).length === 0) delete data.hooks;
    if (JSON.stringify(hooks) !== before) {
      report.backup = backup(file);
      report.removed = 1;
      writeFileAtomic(file, cfg.stringifyJson(data), 0o644);
      // The launcher (see commandFor) is shared by every Claude Code profile of this machine (every CLAUDE_CONFIG_DIR),
      // so uninstalling one profile leaves it in place: deleting it would make the other profiles' hooks exit 127,
      // which Claude Code runs through as a non-blocking error. Only the machine-wide uninstall removes it.
      if ((opts.scope || 'user') !== 'project' && opts.removeLauncher === true) {
        try { fs.unlinkSync(launcher.launcherFile(id, opts)); } catch (_) { /* none */ }
      }
    }
  }
  if (opts.mcp !== false) {
    if ((opts.scope || 'user') === 'project') {
      const mcpFile = path.join(path.resolve(opts.projectDir || process.cwd()), '.mcp.json');
      if (fs.existsSync(mcpFile)) {
        const data = readJson(mcpFile);
        const s = objectField(data, 'mcpServers', mcpFile)[MCP_SERVER_NAME];
        if (s && isZnSecretsServer(s)) {
          backup(mcpFile);
          delete data.mcpServers[MCP_SERVER_NAME];
          writeFileAtomic(mcpFile, cfg.stringifyJson(data), 0o644);
        }
      }
    } else {
      // Only zn's own server: a user MCP server that happens to be called "secrets" is left alone.
      const ours = userMcpServerIsOurs(opts);
      // Absolute PATH entries only, as for install: a relative entry points into the folder uninstall runs in.
      const claude = ours !== true ? null : opts.claudeBin !== undefined ? opts.claudeBin
        : findClaude(opts.env || process.env);
      if (ours === false) {
        report.warnings.push('left the MCP server named "' + MCP_SERVER_NAME + '" in place: it is not zn\'s');
      } else if (ours === null) {
        report.warnings.push('could not read your Claude Code MCP settings, so the MCP server named "' + MCP_SERVER_NAME + '" was left in place; if it is zn\'s, remove it with: claude mcp remove --scope user ' + MCP_SERVER_NAME);
      } else if (claude && /\.(?:cmd|bat)$/i.test(claude)) {
        report.warnings.push('`claude` is a batch file (' + path.basename(claude) + '), which zn does not run through cmd.exe: remove the MCP server yourself with: claude mcp remove --scope user ' + MCP_SERVER_NAME);
      } else if (claude) {
        spawnSync(claude, ['mcp', 'remove', '--scope', 'user', MCP_SERVER_NAME],
          { encoding: 'utf8', windowsHide: true, env: require('../exe').programEnv(opts.env || process.env) });
      } else if (ours === true) {
        report.warnings.push('`claude` is not on your PATH: remove zn\'s MCP server yourself with: claude mcp remove --scope user ' + MCP_SERVER_NAME);
      }
    }
  }
  return report;
}

/* zn's own "secrets" server: `secrets-mcp` as an argument of zn-gate's bin/cli.js, of `zn`/`zn-gate`, or of `npx zn-gate`.
 * A server that only mentions the word (another package, a note in env) is someone else's. */
function isZnSecretsServer(s) {
  if (!s || typeof s !== 'object') return false;
  const args = Array.isArray(s.args) ? s.args.map(String) : [];
  const i = args.indexOf('secrets-mcp');
  if (i < 0) return false;
  const prev = i > 0 ? args[i - 1].replace(/\\/g, '/') : '';
  const cmd = path.basename(String(s.command || '').replace(/\\/g, '/')).replace(/\.(?:cmd|exe|ps1)$/i, '').toLowerCase();
  if (/(?:^|\/)zn-gate\/bin\/cli\.js$/i.test(prev)) return true;
  if (i === 0 && (cmd === 'zn' || cmd === 'zn-gate')) return true;
  return /^zn-gate(?:@[^\s]+)?$/i.test(prev) && (cmd === 'npx' || cmd === 'npm');
}

/* The user-scope MCP servers live in .claude.json (in CLAUDE_CONFIG_DIR when set): true when the "secrets"
 * server there is zn's, false when it is someone else's, undefined when there is none, null when unreadable. */
function userMcpServerIsOurs(opts = {}) {
  const env = opts.env || process.env;
  const file = env.CLAUDE_CONFIG_DIR ? path.join(configDir(opts), '.claude.json') : path.join(opts.home || os.homedir(), '.claude.json');
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  } catch (err) {
    return err.code === 'ENOENT' ? undefined : null;
  }
  const s = data && data.mcpServers && data.mcpServers[MCP_SERVER_NAME];
  if (!s) return undefined;
  return isZnSecretsServer(s);
}

/* ---- Is an MCP tool call going to one of zn's own servers? ----
 * The PreToolUse event names only the tool (mcp__<server>__<tool>), not the server's command, so the
 * adapter checks the MCP configuration Claude Code itself reads. A name alone is never enough: a project
 * can define any server name in its own .mcp.json. The answer is 'secrets' (the vault server) or null.
 * It is not null only when:
 *  - the user-scope server named "secrets" is the one `zn hooks install claude-code` writes: this Node.js and
 *    this zn-gate's bin/cli.js, both by absolute path and the same files once links are resolved (a `zn` or
 *    `npx` found on the PATH could be a program of the project), and
 *  - no .mcp.json and no local-scope entry of ~/.claude.json defines a server with that name at all, from
 *    the working folder upwards and from the project folder Claude Code names (CLAUDE_PROJECT_DIR) upwards
 *    (a CLAUDE_PROJECT_DIR that is not an absolute path gives null), and
 *  - the entry sets nothing that changes what that Node.js loads (NODE_OPTIONS, NODE_PATH, a folder to run in
 *    inside the project).
 * The zn-gate plugin registers no MCP server since 1.14.0, so a plugin server name (plugin_zn-gate_secrets,
 * plugin_zn-gate_zn-gate) is never zn's: an older plugin started its servers with `node` from the PATH.
 * Anything unreadable gives null, so the call is checked as for any other server. */

function readJsonFile(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  } catch (err) {
    return err.code === 'ENOENT' ? undefined : null;
  }
}

/* The server a project install of an earlier zn-gate wrote to .mcp.json (only removed now, never trusted). */
function isBareZnSecrets(s) {
  if (!s || typeof s !== 'object' || s.url) return false;
  const args = Array.isArray(s.args) ? s.args.map(String) : [];
  return (s.command === 'zn' || s.command === 'zn-gate') && args[0] === 'secrets-mcp';
}

function znMcpServerKind(server, cwd, opts = {}) {
  if (server !== MCP_SERVER_NAME) return null;
  const env = opts.env || process.env;
  const file = env.CLAUDE_CONFIG_DIR ? path.join(configDir(opts), '.claude.json') : path.join(opts.home || os.homedir(), '.claude.json');
  const data = readJsonFile(file);
  if (data === null) return null;
  const userServers = data && typeof data.mcpServers === 'object' && data.mcpServers ? data.mcpServers : {};
  const localProjects = data && typeof data.projects === 'object' && data.projects ? data.projects : {};
  // Folder names are compared without case on Windows (a drive letter or a folder typed in another case).
  const win = (opts.platform || process.platform) === 'win32';
  const key = (p) => (win ? path.resolve(p).toLowerCase() : path.resolve(p));
  // A hook can run in a folder outside the project (one added with --add-dir): look up from both. A project
  // folder that cannot be placed leaves the servers Claude Code loads unknown.
  const starts = [path.resolve(cwd || process.cwd())];
  const projectDir = env.CLAUDE_PROJECT_DIR;
  if (projectDir !== undefined && projectDir !== '') {
    if (!path.isAbsolute(String(projectDir))) return null;
    starts.push(String(projectDir));
  }
  const seen = new Set();
  const overrides = [];
  for (const start of starts) {
    let dir = path.resolve(start);
    for (;;) {
      if (!seen.has(key(dir))) {
        seen.add(key(dir));
        const proj = readJsonFile(path.join(dir, '.mcp.json'));
        if (proj === null) return null;
        if (proj && proj.mcpServers && proj.mcpServers[server]) overrides.push(proj.mcpServers[server]);
        for (const k of Object.keys(localProjects)) {
          const p = localProjects[k];
          if (key(k) === key(dir) && p && p.mcpServers && p.mcpServers[server]) overrides.push(p.mcpServers[server]);
        }
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  if (overrides.length) return null;
  return isInstalledSecretsServer(userServers[server], { ...opts, env, cwd: path.resolve(cwd || process.cwd()) }) ? 'secrets' : null;
}

function realOf(p) {
  try {
    const r = fs.realpathSync.native(p);
    return process.platform === 'win32' ? r.toLowerCase() : r;
  } catch (_) {
    return null;
  }
}

/* The user-scope server `zn hooks install claude-code` registers: a Node.js and a zn-gate bin/cli.js, both by
 * absolute path, neither inside the project (the folder the hook runs in, its git work tree, CLAUDE_PROJECT_DIR).
 * Any zn-gate copy counts, not only the one running this hook: the plugin loads zn-gate from its own vendor folder
 * while the server was registered from the npm package. */
function isInstalledSecretsServer(s, opts = {}) {
  if (!s || typeof s !== 'object' || s.url || typeof s.command !== 'string') return false;
  const args = Array.isArray(s.args) ? s.args.map(String) : [];
  if (args[1] !== 'secrets-mcp' || !path.isAbsolute(s.command) || !path.isAbsolute(args[0] || '')) return false;
  const node = realOf(s.command);
  const cli = realOf(args[0]);
  if (!node || !cli) return false;
  const win = process.platform === 'win32';
  if (!(win ? /^node\.exe$/ : /^node$/).test(path.basename(node))) return false;
  if (!cli.split(path.sep).join('/').endsWith('/zn-gate/bin/cli.js')) return false;
  const places = require('../exe').projectPlaces(opts.cwd || process.cwd(), opts.env || process.env, win);
  const inside = (p, d) => { const rel = path.relative(d, p); return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel)); };
  if (places.some((d) => inside(node, d) || inside(cli, d))) return false;
  // Nothing in the entry may change what that Node.js loads: no NODE_OPTIONS or NODE_PATH, and no folder to run in
  // that is inside the project.
  const env = s.env && typeof s.env === 'object' ? Object.keys(s.env) : [];
  if (env.some((k) => /^NODE_(?:OPTIONS|PATH)$/i.test(k))) return false;
  if (s.cwd !== undefined) {
    if (typeof s.cwd !== 'string' || !path.isAbsolute(s.cwd)) return false;
    const where = realOf(s.cwd) || (win ? path.resolve(s.cwd).toLowerCase() : path.resolve(s.cwd));
    if (places.some((d) => inside(where, d))) return false;
  }
  return true;
}

function detect(opts = {}) {
  if (whichSync('claude', (opts.env || process.env).PATH || '')) return true;
  return fs.existsSync(configDir(opts));
}

module.exports = {
  id,
  HOOK_TIMEOUT_S,
  isZnSecretsServer,
  znMcpServerKind,
  detect,
  install,
  uninstall,
  normalize,
  respond,
  // exported for tests and for the other adapters to reuse
  PRE_MATCHER,
  POST_MATCHER,
  settingsFile,
  configDir,
  hookCommand,
  ourHooks,
};
