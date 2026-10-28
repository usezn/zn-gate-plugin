'use strict';

/**
 * OpenAI Codex CLI adapter.
 *
 * Hook format (learn.chatgpt.com/docs/hooks, checked 2026-10-18; the old
 * developers.openai.com/codex/hooks URL redirects there):
 *
 *  hooks.json in ~/.codex/ ($CODEX_HOME) or <repo>/.codex/:
 *    { "hooks": { "<Event>": [ { "matcher": "<regex on tool_name>",
 *                                "hooks": [ { "type": "command", "command": "...", "timeout": <s> } ] } ] } }
 *  Non-managed hooks run only after the user trusts them in Codex (/hooks);
 *  a changed hook needs trusting again. Project hooks also need the
 *  project's .codex/ layer to be trusted.
 *
 *  stdin: session_id, transcript_path, cwd, hook_event_name, model; tool
 *    events add tool_name ("Bash", "apply_patch", "mcp__<server>__<tool>"),
 *    tool_use_id and tool_input. Bash and apply_patch use tool_input.command;
 *    for an MCP tool, tool_input is the call's arguments. PreToolUse runs for
 *    Bash, apply_patch and MCP tools (PRE_MATCHER).
 *
 *  PreToolUse: hookSpecificOutput.permissionDecision "deny" (+ reason).
 *    updatedInput is accepted only with "allow", and "ask" is not supported
 *    (the hook is marked failed and the call runs).
 *  PostToolUse: no field rewrites the output; {decision: "block", reason}
 *    replaces the tool result with the reason. With zn's opt-in
 *    replaceToolOutputOnSecret setting, a real secret also adds continue: false
 *    and stopReason. Codex then replaces the result with the stop text and
 *    continues the turn; it does not end it. Run on a live Codex CLI 0.163.0
 *    (2026-10-19, bench/e2e/codex/scenarios/replace): the model received the
 *    tokenized copy of the output, not the stop text, and the turn went on.
 *  UserPromptSubmit: {decision: "block", reason}.
 *  SessionStart (matcher on source: startup, resume, clear, compact, fork) and
 *    SubagentStart (stdin adds agent_id, agent_type, turn_id): both read
 *    hookSpecificOutput.additionalContext, which Codex adds to the model's
 *    context (github.com/openai/codex, codex-rs/hooks/schema/generated/
 *    session-start.command.output.schema.json and subagent-start...). zn sends
 *    a short reminder there; it never blocks (SubagentStart ignores continue).
 *  PermissionRequest (runs only when Codex is about to ask the user: Bash,
 *    apply_patch, MCP tools): hookSpecificOutput.decision {behavior: "deny",
 *    message}. zn answers only "deny", and only for a call its PreToolUse
 *    check denies. "allow" is never sent (it would skip the approval prompt),
 *    nor updatedInput, updatedPermissions or interrupt (they fail closed).
 *    Anything else: no output, and the approval prompt stays.
 *  Stop (no matcher; runs after each final answer): stdin has
 *    last_assistant_message and stop_hook_active. zn warns with systemMessage,
 *    which Codex shows to you and the model does not see. With
 *    "hooks": {"stopReview": "block"} in ~/.zn/config.json, zn returns
 *    {decision: "block", reason}: Codex then continues with the reason as a
 *    new prompt. zn never blocks when stop_hook_active is true.
 *    An unseen placeholder is looked for in the session log (transcript_path).
 *    Codex 0.163.0 writes each final answer there three times (event message,
 *    response item, task-complete record), so zn counts the copies of the
 *    answer it finds and leaves them all out, not just one (runner.js,
 *    unseenMarkers). If the log escapes the answer differently from JSON, one
 *    copy is assumed and a placeholder only the answer contains can go unflagged.
 *  Exit 0 with no output: no opinion; Codex's own approval policy applies.
 *
 * What that means here (docs/compat.md):
 *  - Reads of credential files, .env with values and ~/.zn are denied.
 *  - A command with __ZN_<NAME>__ markers in its arguments is denied with
 *    the way to pass the secret as an environment variable instead
 *    (`zn run --secrets NAME -- ...`); a rewrite would need "allow", which
 *    skips the user's approval policy. Once the agent runs it through zn
 *    run, the hook stays silent and Codex's approval policy plus zn run's
 *    own checks apply.
 *  - Detected tokens are never restored into commands (that would also need
 *    "allow"); they stay as tokens.
 *  - Output with secrets is replaced, through "block", by its tokenized
 *    text. The model sees the text with __ZN_ tokens, not the structured
 *    result (lossy, but no value gets through).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const cfg = require('./config-file');
const { askAsDeny, isPlainAsk } = require('./ask-deny');
const { whichSync } = require('../broker/markers');
const launcher = require('./launcher');

const id = 'codex';
// MCP calls are checked before they run: their arguments go through the same
// scan as other agents' MCP calls (see runner.js, decideMcp).
const PRE_MATCHER = '^(Bash|apply_patch|mcp__.+)$';
// Every tool: output of tools zn does not know is tokenized like MCP output.
const POST_MATCHER = '.*';
const HOOK_TIMEOUT_S = 30;
const HOOK_STATUS = 'zn: checking for secrets';

// Patches longer than this are refused before parsing, like shell commands over
// 100 KB: checking them could take longer than the agent waits for the hook.
const PATCH_SCAN_CAP = 100 * 1024; // characters
const PATCH_MARKERS = ['*** Add File: ', '*** Update File: ', '*** Delete File: ', '*** Move to: '];

// How the agents read a patch: Codex and OpenCode split it at '\n' and drop a
// trailing '\r'. Codex then trims the line with Rust's trim() (Unicode
// White_Space, which includes U+0085 but not U+FEFF) and keeps the rest of the
// line after the marker as the file name; OpenCode trims with JavaScript's
// trim() and trims the name too. zn checks every form either agent could use.
const RUST_SPACE = '\\t-\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000';
const RUST_EDGE = new RegExp('^[' + RUST_SPACE + ']+|[' + RUST_SPACE + ']+$', 'g');
const ANY_EDGE = /^[\s\u0085]+|[\s\u0085]+$/g;
// A name with a control or line-separator character is not checked: the patch is refused.
const ODD_NAME = /[\u0000-\u001f\u007f\u0085\u2028\u2029]/;
// A line that looks like a file marker without being one the agents read, or a
// marker that sends the patch to another environment: the patch is refused.
const MARKER_LIKE = /^\*{3}\s*(?:(?:add|update|delete|rename)\s*file|move\s*to|environment\s*id)\s*:/i;

/*
 * apply_patch: every name the patch could touch, one line at a time (linear
 * time), and whether a line or a name cannot be read safely (the patch is then
 * refused rather than let through).
 */
function patchScan(patch) {
  const files = new Set();
  let suspicious = false;
  for (let line of String(patch || '').split('\n')) {
    // Every marker, and every marker-like line, has "***": other lines are skipped cheaply.
    if (!line.includes('***')) continue;
    if (line.endsWith('\r')) line = line.slice(0, -1);
    const forms = new Set([line.replace(RUST_EDGE, ''), line.trim(), line.replace(ANY_EDGE, '')]);
    let marked = false;
    for (const t of forms) {
      const marker = PATCH_MARKERS.find((k) => t.startsWith(k));
      if (!marker) continue;
      marked = true;
      const rest = t.slice(marker.length);
      const names = new Set([rest, rest.trim(), rest.replace(ANY_EDGE, '')].filter(Boolean));
      if (names.size === 0) suspicious = true;
      for (const name of names) {
        if (ODD_NAME.test(name)) suspicious = true;
        files.add(name);
      }
    }
    if (!marked && [...forms].some((t) => MARKER_LIKE.test(t))) suspicious = true;
  }
  return { files: [...files], suspicious };
}

function patchFiles(patch) {
  return patchScan(patch).files;
}

// The tools of zn's own "secrets" MCP server (lib/broker/mcp.js). Only these
// names can get the placeholder exception, so a third-party server called
// "secrets__<something>" cannot take it.
const OWN_SECRETS_TOOL = /^mcp__secrets__(secrets_list|secrets_http_request|secrets_render_file|secrets_request)$/;

/*
 * The command of a [mcp_servers.secrets] table in one config.toml. found is
 * false when there is no such table; command is null when the table is there
 * but cannot be read (or the file cannot be parsed), which fails closed.
 */
function configSecretsCommand(file) {
  if (!fs.existsSync(file)) return { found: false, command: null };
  try {
    const data = require('../audit/parse').parseToml(fs.readFileSync(file, 'utf8')).data;
    const s = data && data.mcp_servers && data.mcp_servers.secrets;
    if (s === undefined) return { found: false, command: null };
    if (!s || typeof s.command !== 'string' || !Array.isArray(s.args)) return { found: true, command: null };
    const command = [s.command, ...s.args.map(String)]
      .map((w) => (/^[\w./:\\-]+$/.test(w) ? w : '"' + w.replace(/["\\]/g, '') + '"'))
      .join(' ');
    return { found: true, command };
  } catch (_) {
    return { found: true, command: null };
  }
}

// Every .codex/config.toml from cwd up to the project root (the first folder
// with a .git entry), or up to the file system root when there is none.
function projectConfigFiles(cwd) {
  const out = [];
  let dir = path.resolve(cwd || process.cwd());
  for (;;) {
    out.push(path.join(dir, '.codex', 'config.toml'));
    if (fs.existsSync(path.join(dir, '.git'))) break;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return out;
}

/*
 * The command that starts zn's own "secrets" MCP server, as the user's
 * config.toml has it (`zn hooks install` writes it there). Codex's hook input
 * does not name the command of an MCP server, so runner.js can only tell zn's
 * server apart when this is passed as raw.command. A project's own
 * .codex/config.toml that defines "secrets" must name the same command, or
 * there is no exception (fails closed). Null when the exception is not granted.
 * Command-line overrides (-c) and profiles are not visible to the hook.
 */
function secretsServerCommand(env, cwd) {
  const user = configSecretsCommand(path.join(codexHome({ env }), 'config.toml'));
  if (!user.found || !user.command) return null;
  for (const file of projectConfigFiles(cwd)) {
    const project = configSecretsCommand(file);
    if (project.found && project.command !== user.command) return null;
    if (project.found && !project.command) return null;
  }
  return user.command;
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const name = raw.hook_event_name;
  const event = name === 'PreToolUse' || name === 'PermissionRequest' ? 'pre_tool' : name === 'PostToolUse' ? 'post_tool' : name === 'UserPromptSubmit' ? 'user_prompt' : name === 'Stop' ? 'stop' : name === 'SessionStart' || name === 'SubagentStart' ? 'session_start' : null;
  // PermissionRequest is checked by the same policy as PreToolUse; respond() answers it with deny only.
  const base = { event, permissionRequest: name === 'PermissionRequest', cwd: raw.cwd || process.cwd(), sessionId: raw.session_id || null, raw };
  if (event === 'session_start') return { ...base, tool: null, hookEventName: name, input: {} };
  if (event === 'user_prompt') return { ...base, tool: null, input: { prompt: typeof raw.prompt === 'string' ? raw.prompt : '' } };
  if (event === 'stop') {
    return {
      ...base,
      tool: null,
      input: {
        message: typeof raw.last_assistant_message === 'string' ? raw.last_assistant_message : '',
        stopHookActive: raw.stop_hook_active === true,
        transcriptPath: typeof raw.transcript_path === 'string' ? raw.transcript_path : null,
      },
    };
  }
  if (!event) return base;
  const toolName = String(raw.tool_name || '');
  const mcp = /^mcp__(.+?)__(.+)$/.exec(toolName);
  const ti = raw.tool_input && typeof raw.tool_input === 'object' ? raw.tool_input : {};
  // Unknown tools are treated like MCP output: their text is tokenized.
  let tool = mcp ? 'mcp' : toolName === 'Bash' ? 'bash' : toolName === 'apply_patch' ? 'write' : 'mcp';
  const input = { command: typeof ti.command === 'string' ? ti.command : undefined, texts: [] };
  let evRaw = raw;
  if (mcp) {
    // For MCP, tool_input is the call's arguments; runner.js checks them.
    input.args = raw.tool_input === undefined || raw.tool_input === null ? {} : raw.tool_input;
    const command = mcp[1] === 'secrets' && OWN_SECRETS_TOOL.test(toolName) ? secretsServerCommand(process.env, base.cwd) : null;
    if (command) evRaw = { ...raw, command };
  }
  if (toolName === 'apply_patch') {
    // Every file the patch touches is checked by the policy; a patch whose
    // file names cannot be read is refused rather than let through.
    const tooLong = String(ti.command || '').length > PATCH_SCAN_CAP;
    const scan = tooLong ? { files: [], suspicious: false } : patchScan(ti.command);
    const files = scan.files;
    const home = os.homedir();
    const zn = files.find((f) => path.resolve(base.cwd, f).replace(/\\/g, '/').startsWith(path.join(home, '.zn').replace(/\\/g, '/')));
    input.paths = files;
    input.path = zn || files[0];
    input.tooLong = tooLong;
    input.unparsed = !tooLong && (files.length === 0 || scan.suspicious);
    input.texts = [{ key: ['command'], value: String(ti.command || '') }];
    input.command = undefined;
    tool = 'write';
  }
  return { ...base, raw: evRaw, tool, toolName, mcp: mcp ? { server: mcp[1], tool: mcp[2] } : null, input, output: event === 'post_tool' ? raw.tool_response : undefined };
}

function outputText(v) {
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object' && (typeof v.stdout === 'string' || typeof v.stderr === 'string')) {
    return [v.stdout, v.stderr].filter((x) => typeof x === 'string' && x).join('\n');
  }
  return JSON.stringify(v, null, 2);
}

function respond(d) {
  const ev = d && d.event;
  if (!ev || !ev.event) return null;
  if (ev.event === 'pre_tool') {
    const deny = (reason) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } });
    let out = null;
    if (d.decision === 'deny') out = deny(d.message || 'Blocked by zn');
    else if (d.updatedInput && d.kind === 'wrap' && typeof ev.input.command === 'string') {
      out = deny('zn: this command uses a stored secret. Run it through zn instead, exactly like this: zn run -- ' + ev.input.command +
        '  (zn puts the value only into that process, if the user allowed this command for the secret).');
    }
    else if (isPlainAsk(d)) out = deny(askAsDeny('Codex CLI', d));
    // Restoring detected tokens would need "allow" (skips the user's approval
    // policy) or "ask" (unsupported): stay silent. A question zn wanted to
    // ask is a deny, because Codex hooks cannot ask.
    if (!ev.permissionRequest) return out;
    // PermissionRequest: the same deny and reason, in its own shape. Never "allow".
    return out && { hookSpecificOutput: { hookEventName: 'PermissionRequest', decision: { behavior: 'deny', message: out.hookSpecificOutput.permissionDecisionReason } } };
  }
  if (ev.event === 'post_tool') {
    if (d.updatedOutput !== undefined) {
      const out = {
        decision: 'block',
        reason: outputText(d.updatedOutput) + (d.message ? '\n\n[' + d.message + ']' : ''),
      };
      // Opt-in (hooks.replaceToolOutputOnSecret, see runner.js): also return continue: false
      // with stopReason. Codex then replaces the result with the stop text and carries on.
      if (d.stopReason) {
        out.continue = false;
        out.stopReason = d.stopReason;
      }
      return out;
    }
    if (d.decision === 'deny') return { decision: 'block', reason: d.message || 'zn: output withheld' };
    return null;
  }
  if (ev.event === 'session_start') {
    // Context only. Both events take the same field; the event name must match.
    return d.context ? { hookSpecificOutput: { hookEventName: ev.hookEventName, additionalContext: d.context } } : null;
  }
  if (ev.event === 'user_prompt' && d.decision === 'deny') return { decision: 'block', reason: d.message || 'Blocked by zn' };
  if (ev.event === 'stop') {
    // Only "block" is a decision; a warning is shown to the user as systemMessage.
    if (d.decision === 'deny') return { decision: 'block', reason: d.message || 'zn: rewrite the last answer without the secret value' };
    return d.notice ? { systemMessage: d.notice } : null;
  }
  return null;
}

/* ------------------------ install / uninstall ---------------------- */

function codexHome(opts = {}) {
  const env = opts.env || process.env;
  return env.CODEX_HOME ? path.resolve(env.CODEX_HOME) : path.join(opts.home || os.homedir(), '.codex');
}

function hooksFile(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.codex', 'hooks.json');
  return path.join(codexHome(opts), 'hooks.json');
}

function strip(groups) {
  if (!Array.isArray(groups)) return [];
  const out = [];
  for (const g of groups) {
    if (!g || !Array.isArray(g.hooks)) { out.push(g); continue; }
    const hooks = g.hooks.filter((h) => !(h && cfg.isOurs(h.command, id)));
    if (hooks.length) out.push({ ...g, hooks });
  }
  return out;
}

function mcpSnippet(opts = {}) {
  const cli = path.resolve(__dirname, '..', '..', 'bin', 'cli.js').replace(/\\/g, '/');
  return '[mcp_servers.secrets]\ncommand = ' + JSON.stringify((opts.nodePath || process.execPath).replace(/\\/g, '/')) +
    '\nargs = [' + JSON.stringify(cli) + ', "secrets-mcp", "--agent", "codex"]';
}

/* The hook groups zn writes, by event, for one handler (also used to print a managed requirements.toml). */
function hookGroups(handler) {
  // One handler for every event, or a function of the event name (the launcher needs to know it).
  const h = (event) => (typeof handler === 'function' ? handler(event) : handler);
  return {
    PreToolUse: { matcher: PRE_MATCHER, hooks: [h('PreToolUse')] },
    // Same matcher as PreToolUse: the approval prompt is asked only for calls zn's PreToolUse check let through.
    PermissionRequest: { matcher: PRE_MATCHER, hooks: [h('PermissionRequest')] },
    PostToolUse: { matcher: POST_MATCHER, hooks: [h('PostToolUse')] },
    UserPromptSubmit: { hooks: [h('UserPromptSubmit')] },
    // A short reminder for the model, at the start of a session and of a subagent. No matcher: every source.
    SessionStart: { hooks: [h('SessionStart')] },
    SubagentStart: { hooks: [h('SubagentStart')] },
    // Stop ignores matchers in Codex; the group has none.
    Stop: { hooks: [h('Stop')] },
  };
}

/**
 * The hook handler for each event. A user install goes through zn's launcher
 * (lib/agents/launcher.js) so that a Node.js that has gone away blocks instead
 * of letting Codex run the call unchecked; a project install runs `zn` from the
 * PATH inside a start guard that blocks the same way; a command given by the
 * caller keeps the plain command.
 */
function handlerFor(opts = {}) {
  const base = { type: 'command', timeout: HOOK_TIMEOUT_S, statusMessage: HOOK_STATUS };
  const plain = () => ({ ...base, command: cfg.hookCommand(id, opts), commandWindows: cfg.hookCommandWindows(id, opts) });
  if (opts.command) return plain;
  // A project install runs `zn` from the PATH inside zn's start guard (launcher.projectShCommand): a missing zn or Node.js blocks.
  if ((opts.scope || 'user') === 'project') {
    return (event) => ({ ...plain(), command: launcher.projectShCommand(id, event), commandWindows: launcher.windowsScriptCommand(launcher.projectWindowsScript(id, event), { cmd: true }) });
  }
  const platform = opts.platform || process.platform;
  const node = opts.nodePath || process.execPath;
  const runner = opts.runnerPath || cfg.runnerPath();
  const file = platform === 'win32' ? null : launcher.writeLauncher(id, node, runner, { ...opts, deadlineS: launcher.launcherDeadlineS(HOOK_TIMEOUT_S), deadlineSoft: true });
  return (event) => {
    const h = plain();
    if (file) h.command = launcher.launcherCommand(file, event, platform);
    const script = launcher.windowsScript(id, event, node, runner);
    if (script) h.commandWindows = launcher.windowsScriptCommand(script);
    return h;
  };
}

function install(opts = {}) {
  const file = hooksFile(opts);
  const data = cfg.readJson(file);
  const report = { settings: file, backup: cfg.backup(file), warnings: [] };
  data.hooks = cfg.hooksOf(data, file);
  const ours = hookGroups(handlerFor(opts));
  for (const [event, group] of Object.entries(ours)) {
    data.hooks[event] = strip(data.hooks[event]);
    data.hooks[event].push(group);
  }
  cfg.writeJson(file, data);
  report.warnings.push('Codex runs new or changed hooks only after you trust them: open Codex and review them with /hooks.');
  if (opts.mcp !== false) {
    report.warnings.push('optional: to let Codex use the secrets kept in zn\'s vault, add the "secrets" MCP server by putting this in ' + path.join(codexHome(opts), 'config.toml') + ':\n' + mcpSnippet(opts));
  }
  // Organization requirements or the user's config.toml can turn these hooks off with no sign in Codex; say it here.
  // Advisory only: a failure here never fails an install already written.
  try {
    report.warnings.push(...require('./managed-policy').codexPolicyWarnings({
      env: opts.env, codexHome: codexHome(opts), requirementsFile: opts.codexRequirementsFile, managedConfigFile: opts.codexManagedConfigFile,
    }));
  } catch (_) { /* no policy note */ }
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
    if (Object.keys(data.hooks).length === 0) delete data.hooks;
    cfg.writeJson(file, data);
    // The launcher (see handlerFor) is shared by every config of this machine: one uninstall leaves it in place,
    // only the machine-wide uninstall (opts.removeLauncher) deletes it.
    if ((opts.scope || 'user') !== 'project' && opts.removeLauncher === true) {
      try { fs.unlinkSync(launcher.launcherFile(id, opts)); } catch (_) { /* none */ }
    }
  }
  return report;
}

function detect(opts = {}) {
  if (whichSync('codex', (opts.env || process.env).PATH || '')) return true;
  return fs.existsSync(codexHome(opts));
}

module.exports = {
  id,
  detect,
  install,
  uninstall,
  normalize,
  respond,
  capabilities: { ask: false, rewriteInput: false, rewriteOutput: 'block' },
  PRE_MATCHER,
  POST_MATCHER,
  HOOK_TIMEOUT_S,
  HOOK_STATUS,
  hookGroups,
  hooksFile,
  patchFiles,
  patchScan,
  PATCH_SCAN_CAP,
};
