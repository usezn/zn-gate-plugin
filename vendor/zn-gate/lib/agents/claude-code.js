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
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { writeFileAtomic } = require('../broker/files');
const { whichSync } = require('../broker/markers');
const { shQuote, portablePath } = require('../shell-quote');
const { claudeCodePolicyWarnings } = require('./managed-policy');

const id = 'claude-code';

// Exact names (a matcher of letters and | is an exact list). PowerShell and
// Monitor run commands like Bash; LSP reads files.
const PRE_MATCHER = 'Bash|PowerShell|Monitor|Read|Grep|LSP|Edit|MultiEdit|Write|NotebookEdit|WebFetch';
// A regex (it contains mcp__.*), anchored so it names exactly these tools.
const POST_MATCHER = '^(Bash|PowerShell|Monitor|Read|Grep|LSP|WebFetch|ReadMcpResourceTool)$|^mcp__.*';
const HOOK_TIMEOUT_S = 15;
// Older versions wrote the paths in double quotes; both forms are ours.
const OUR_COMMAND_RE = /(\bhook claude-code|hooks[\\/]runner\.js["']? claude-code)\s*$/;
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
  return {
    ...base,
    tool,
    toolName,
    mcp: mcp ? { server: mcp[1], tool: mcp[2] } : null,
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
  // systemMessage: a notice shown to the user (not to the model).
  if (out && d.userMessage) out.systemMessage = d.userMessage;
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
  return quoteArg(opts.nodePath || process.execPath, opts.platform) + ' ' + quoteArg(opts.runnerPath || runnerPath(), opts.platform) + ' claude-code';
}

function readJson(file) {
  try {
    const text = fs.readFileSync(file, 'utf8');
    return text.trim() ? JSON.parse(text) : {};
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw new Error('cannot parse ' + file + ': ' + err.message);
  }
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
    const hooks = g.hooks.filter((h) => !(h && typeof h.command === 'string' && OUR_COMMAND_RE.test(h.command)));
    if (hooks.length) out.push({ ...g, hooks });
  }
  return out;
}

function ourHooks(command) {
  const h = { type: 'command', command, timeout: HOOK_TIMEOUT_S };
  return {
    PreToolUse: { matcher: PRE_MATCHER, hooks: [h] },
    PostToolUse: { matcher: POST_MATCHER, hooks: [h] },
    // A prompt hook that cannot start or times out blocks the prompt
    // (Claude Code 2.1.295 and later; earlier versions ignore the field).
    UserPromptSubmit: { hooks: [{ ...h, onFailure: 'block' }] },
    // A typed skill or command expands after UserPromptSubmit; this checks the expanded text.
    UserPromptExpansion: { hooks: [{ ...h, onFailure: 'block' }] },
  };
}

function mcpServerConfig(opts = {}) {
  return { command: opts.nodePath || process.execPath, args: [opts.cliPath || cliPath(), 'secrets-mcp', '--agent', 'claude-code'] };
}

function installMcp(opts, report) {
  const conf = mcpServerConfig(opts);
  if ((opts.scope || 'user') === 'project') {
    const file = path.join(path.resolve(opts.projectDir || process.cwd()), '.mcp.json');
    const data = readJson(file);
    data.mcpServers = data.mcpServers || {};
    const existing = data.mcpServers[MCP_SERVER_NAME];
    if (existing && !isZnSecretsServer(existing)) {
      report.warnings.push('an MCP server named "' + MCP_SERVER_NAME + '" already exists in ' + file + '; left unchanged');
      return;
    }
    report.mcpBackup = backup(file);
    data.mcpServers[MCP_SERVER_NAME] = conf;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    writeFileAtomic(file, JSON.stringify(data, null, 2) + '\n', 0o644);
    report.mcp = file;
    return;
  }
  const claude = opts.claudeBin !== undefined ? opts.claudeBin : whichSync('claude', process.env.PATH || '');
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
  const r = spawnSync(claude, ['mcp', 'add-json', '--scope', 'user', MCP_SERVER_NAME, JSON.stringify({ type: 'stdio', ...conf })],
    { encoding: 'utf8', windowsHide: true });
  if (r.status === 0) report.mcp = 'claude mcp (user scope)';
  else report.warnings.push('`claude mcp add-json` failed (' + String(r.stderr || r.stdout || r.error || '').trim().slice(0, 300) + '): register the MCP server yourself with: ' + manual);
}

/**
 * Write the hook configuration (and register the "secrets" MCP server).
 * opts: {scope: 'user'|'project', projectDir, home, env, nodePath, cliPath, command, mcp: false, claudeBin}
 */
function install(opts = {}) {
  const file = settingsFile(opts);
  const data = readJson(file);
  const report = { settings: file, backup: backup(file), warnings: [] };
  data.hooks = data.hooks && typeof data.hooks === 'object' ? data.hooks : {};
  const ours = ourHooks(hookCommand(opts));
  for (const [event, group] of Object.entries(ours)) {
    data.hooks[event] = stripOurs(data.hooks[event]);
    data.hooks[event].push(group);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  writeFileAtomic(file, JSON.stringify(data, null, 2) + '\n', 0o644);
  if (opts.mcp !== false) installMcp(opts, report);
  // Organization settings can turn these hooks or the MCP server off with no
  // sign in Claude Code; say it here.
  // Advisory only: a failure here never fails an install already written.
  try {
    const users = [...new Set([file, path.join(configDir(opts), 'settings.json')])];
    const conf = mcpServerConfig(opts);
    report.warnings.push(...claudeCodePolicyWarnings({
      managedDir: opts.managedDir, userSettings: users, mcp: opts.mcp !== false, mcpCommand: [conf.command, ...conf.args],
    }));
  } catch (_) { /* no policy note */ }
  return report;
}

function uninstall(opts = {}) {
  const file = settingsFile(opts);
  const report = { settings: file, backup: null, removed: 0, warnings: [] };
  if (fs.existsSync(file)) {
    const data = readJson(file);
    if (data.hooks && typeof data.hooks === 'object') {
      const before = JSON.stringify(data.hooks);
      for (const event of Object.keys(data.hooks)) {
        const kept = stripOurs(data.hooks[event]);
        if (kept.length) data.hooks[event] = kept; else delete data.hooks[event];
      }
      if (Object.keys(data.hooks).length === 0) delete data.hooks;
      if (JSON.stringify(data.hooks || {}) !== before) {
        report.backup = backup(file);
        report.removed = 1;
        writeFileAtomic(file, JSON.stringify(data, null, 2) + '\n', 0o644);
      }
    }
  }
  if (opts.mcp !== false) {
    if ((opts.scope || 'user') === 'project') {
      const mcpFile = path.join(path.resolve(opts.projectDir || process.cwd()), '.mcp.json');
      if (fs.existsSync(mcpFile)) {
        const data = readJson(mcpFile);
        const s = data.mcpServers && data.mcpServers[MCP_SERVER_NAME];
        if (s && isZnSecretsServer(s)) {
          backup(mcpFile);
          delete data.mcpServers[MCP_SERVER_NAME];
          writeFileAtomic(mcpFile, JSON.stringify(data, null, 2) + '\n', 0o644);
        }
      }
    } else {
      // Only zn's own server: a user MCP server that happens to be called "secrets" is left alone.
      const ours = userMcpServerIsOurs(opts);
      const claude = ours !== true ? null : opts.claudeBin !== undefined ? opts.claudeBin : whichSync('claude', process.env.PATH || '');
      if (ours === false) {
        report.warnings.push('left the MCP server named "' + MCP_SERVER_NAME + '" in place: it is not zn\'s');
      } else if (ours === null) {
        report.warnings.push('could not read your Claude Code MCP settings, so the MCP server named "' + MCP_SERVER_NAME + '" was left in place; if it is zn\'s, remove it with: claude mcp remove --scope user ' + MCP_SERVER_NAME);
      } else if (claude && /\.(?:cmd|bat)$/i.test(claude)) {
        report.warnings.push('`claude` is a batch file (' + path.basename(claude) + '), which zn does not run through cmd.exe: remove the MCP server yourself with: claude mcp remove --scope user ' + MCP_SERVER_NAME);
      } else if (claude) {
        spawnSync(claude, ['mcp', 'remove', '--scope', 'user', MCP_SERVER_NAME], { encoding: 'utf8', windowsHide: true });
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

function detect(opts = {}) {
  if (whichSync('claude', (opts.env || process.env).PATH || '')) return true;
  return fs.existsSync(configDir(opts));
}

module.exports = {
  id,
  isZnSecretsServer,
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
};
