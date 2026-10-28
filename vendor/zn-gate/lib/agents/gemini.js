'use strict';

/**
 * Gemini CLI adapter. Experimental.
 *
 * Hook contract (read 2026-10-19):
 *  - https://geminicli.com/docs/hooks/            events, exit codes, settings layout, matchers, trust
 *  - https://geminicli.com/docs/hooks/reference/  stdin and stdout fields per event
 *  - https://geminicli.com/docs/reference/tools/  built-in tool names and their argument names
 *  - https://geminicli.com/docs/cli/settings/     hooksConfig.enabled, user and workspace settings paths
 *  (hooksConfig.disabled and GOOGLE_GEMINI_BASE_URL are in the source of google-gemini/gemini-cli, not in the docs)
 *
 *  settings.json:
 *    { "hooks": { "BeforeTool": [ { "matcher": "<regex on the tool name>",
 *                                   "hooks": [ { "name": "...", "type": "command", "command": "...",
 *                                                "timeout": <milliseconds, default 60000> } ] } ] } }
 *    User: ~/.gemini/settings.json. Project: <project>/.gemini/settings.json. System: /etc/gemini-cli/settings.json
 *    (the docs list project, user, system in that order of precedence, then extensions).
 *
 *  stdin (all events): session_id, transcript_path, cwd, hook_event_name, timestamp.
 *    BeforeTool adds tool_name, tool_input, mcp_context (optional) and original_request_name.
 *    MCP tools are named mcp_<server>_<tool>.
 *
 *  BeforeTool output (exit 0): {decision: "deny" | "block", reason} blocks the tool and the reason goes to the
 *    agent as a tool error. hookSpecificOutput.tool_input is merged over the model's arguments (zn does not use it).
 *    The documented decisions are deny and block only: there is no "ask" and no "allow", so zn blocks or says
 *    nothing. No output at all (exit 0, empty stdout) means no opinion, and Gemini CLI's own approval applies.
 *  Docs (read 2026-10-20): exit 2 is "Critical Block. The target action (tool, turn, or stop) is aborted"; "Other:
 *    Non-fatal failure. A warning is shown, but the interaction proceeds"; the page does not say what a hook that
 *    cannot start does, so it is treated as the other case. zn's launcher script (lib/agents/launcher.js) exits 2.
 *  Exit 2 blocks the tool and stderr is the reason. Any other exit code is a warning and the tool RUNS:
 *    a hook that crashes, times out or cannot start does not block anything. Output that is not JSON is read
 *    as a system message and counts as allow.
 *
 * Tool names and arguments (reference/tools): run_shell_command {command, dir_path}, read_file {file_path},
 * read_many_files {include, exclude}, write_file {file_path, content}, replace {file_path, old_string, new_string},
 * grep_search {pattern, dir_path, include_pattern, no_ignore} (alias search_file_content), glob and list_directory
 * {dir_path}, web_fetch {prompt}.
 *
 * Not used: AfterTool (its decision can replace a tool result, but the shape of tool_response is not documented
 * well enough to rewrite it safely), SessionStart and the rest. zn registers BeforeTool only.
 */

const fs = require('fs');
const { askAsDeny, isPlainAsk } = require('./ask-deny');
const { fileURLToPath } = require('url');
const os = require('os');
const path = require('path');
const cfg = require('./config-file');
const launcher = require('./launcher');
const { whichSync } = require('../broker/markers');

const id = 'gemini';
const HOOK_NAME = 'zn-gate';
const HOOK_TIMEOUT_MS = 15000;
const MATCHER = '*';

const SHELL_TOOLS = new Set(['run_shell_command']);
// Tools that only show names or ask the user something: no opinion.
const NAMES_ONLY_TOOLS = new Set(['glob', 'list_directory']);
const READ_TOOLS = new Set(['read_file']);
const WRITE_TOOLS = new Set(['write_file', 'replace']);
const GREP_TOOLS = new Set(['grep_search', 'search_file_content']);
const COMMAND_KEYS = ['command', 'Command', 'cmd'];
const PATH_KEY_RE = /path|file|target|uri|dir|source|destination|include/i;
const NOT_PATH_KEY_RE = /content|text|instruction|description|query|pattern|code|summary|title|exclude|prompt|string/i;
const MAX_PATH_LEN = 4096;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

function firstString(obj, keys) {
  for (const k of keys) if (typeof obj[k] === 'string' && obj[k]) return obj[k];
  return undefined;
}

/**
 * Every string argument whose key looks like a file or folder (content-like keys are skipped), three levels deep.
 * A file: address that cannot be turned into a path sets `bad`, so the call is refused instead of passed.
 */
function pathsOf(args) {
  const out = [];
  let bad = false;
  const add = (v) => {
    if (typeof v !== 'string' || !v) return;
    if (/^file:/i.test(v)) {
      try { out.push(fileURLToPath(v)); } catch (_) { bad = true; }
      return;
    }
    if (v.length > MAX_PATH_LEN || /[\r\n]/.test(v)) return;
    out.push(v);
  };
  const keyOk = (k) => PATH_KEY_RE.test(k) && !NOT_PATH_KEY_RE.test(k);
  const walk = (obj, depth) => {
    for (const [k, v] of Object.entries(obj)) {
      if (keyOk(k)) {
        if (Array.isArray(v)) v.forEach(add); else add(v);
      }
      if (depth < 3) {
        if (isObj(v)) walk(v, depth + 1);
        else if (Array.isArray(v)) v.forEach((x) => { if (isObj(x)) walk(x, depth + 1); });
      }
    }
  };
  walk(args, 0);
  return { paths: out, bad };
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const base = { cwd: typeof raw.cwd === 'string' && raw.cwd ? raw.cwd : process.cwd(), sessionId: raw.session_id || null, raw };
  // zn registers BeforeTool only, so a payload that names no event is a malformed BeforeTool, not another event.
  const named = raw.hook_event_name;
  if (named !== undefined && named !== null && named !== '' && named !== 'BeforeTool') return { ...base, event: null };
  const toolName = typeof raw.tool_name === 'string' ? raw.tool_name : '';
  const args = isObj(raw.tool_input) ? raw.tool_input : {};
  const cwd = typeof args.dir_path === 'string' && args.dir_path && !/[\r\n]/.test(args.dir_path) && SHELL_TOOLS.has(toolName)
    ? path.resolve(base.cwd, args.dir_path) : base.cwd;
  const ev = { ...base, cwd, event: 'pre_tool', toolName, rawArgs: args };
  const unreadable = (what) => ({ ...ev, tool: 'unreadable', input: { texts: [] }, unreadable: 'zn: could not read ' + what + ' of this call, so zn cannot check it.' });

  if (!toolName) return unreadable('the tool name');

  const mcp = /^mcp_(.+?)_(.+)$/i.exec(toolName);
  if (mcp) {
    const mc = isObj(raw.mcp_context) ? raw.mcp_context : {};
    const server = typeof mc.server_name === 'string' && mc.server_name ? mc.server_name : mcp[1];
    const tool = typeof mc.tool_name === 'string' && mc.tool_name ? mc.tool_name : mcp[2];
    const mp = pathsOf(args);
    const e = { ...ev, tool: 'mcp', mcp: { server, tool }, input: { args, paths: mp.paths, texts: [] } };
    if (mp.bad) e.unreadable = 'zn: could not read a file address in this call, so zn cannot check it.';
    return e;
  }
  if (SHELL_TOOLS.has(toolName)) {
    const cmd = firstString(args, COMMAND_KEYS);
    if (cmd === undefined) return unreadable('the command');
    return { ...ev, tool: 'bash', input: { command: cmd, texts: [] } };
  }
  const { paths, bad } = pathsOf(args);
  const input = { path: paths[0], paths, texts: [] };
  if (toolName === 'web_fetch') {
    // The prompt holds the addresses to fetch (and any text around them).
    return { ...ev, tool: 'webfetch', input: { url: typeof args.prompt === 'string' ? args.prompt : '', texts: [] } };
  }
  if (GREP_TOOLS.has(toolName)) {
    const dir = typeof args.dir_path === 'string' && args.dir_path ? args.dir_path : '';
    const e = { ...ev, tool: 'grep', input: { ...input, scanDir: dir ? path.resolve(base.cwd, dir) : base.cwd } };
    if (bad) e.unreadable = 'zn: could not read a file address in this call, so zn cannot check it.';
    return e;
  }
  const kind = READ_TOOLS.has(toolName) || toolName === 'read_many_files' ? 'read' : WRITE_TOOLS.has(toolName) ? 'write' : null;
  if (kind) {
    const e = { ...ev, tool: kind, input };
    if (bad) e.unreadable = 'zn: could not read a file address in this call, so zn cannot check it.';
    else if (!paths.length) e.unreadable = 'zn: could not read the file this call uses, so zn cannot check it. Name the file explicitly.';
    return e;
  }
  // Any other tool that names a file (a future tool, an extension) gets the read and write checks on every path.
  if (!NAMES_ONLY_TOOLS.has(toolName) && (paths.length || bad)) {
    const e = { ...ev, tool: 'fileaccess', input };
    if (bad) e.unreadable = 'zn: could not read a file address in this call, so zn cannot check it.';
    return e;
  }
  return { ...ev, tool: toolName.toLowerCase(), input: { texts: [] } };
}

function deny(reason) {
  return { decision: 'deny', reason: reason || 'Blocked by zn' };
}

/**
 * Internal decision -> Gemini CLI hook JSON, or null for "no opinion" (zn never says allow).
 * The documented BeforeTool decisions are deny and block. A command that needs a secret is blocked with the exact
 * zn run command to use instead. Anything zn would ask about is blocked too, with the way to approve it (Gemini CLI
 * hooks cannot ask, and a silent pass would let the call run). A rewrite proposal (updatedInput) stays silent.
 */
function respond(d) {
  const ev = d && d.event;
  if (!ev || ev.event !== 'pre_tool') return null;
  if (d.decision === 'deny') return deny(d.message);
  if (ev.unreadable) return deny(ev.unreadable);
  if (d.updatedInput && d.kind === 'wrap') {
    return deny('zn: this command uses a stored secret. Run it through zn instead, exactly like this: zn run -- ' + ev.input.command +
      '  (zn puts the value only into that process, if the user allowed this command for the secret).');
  }
  // Gemini CLI hooks cannot ask: a question zn wanted to ask is a deny, not a silent pass.
  if (isPlainAsk(d)) {
    return deny(askAsDeny('Gemini CLI', d) + (ev.tool === 'grep' ? ' For a search, naming a narrower path avoids the question.' : ''));
  }
  return null;
}

/* ------------------------ install / uninstall ---------------------- */

function settingsFile(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.gemini', 'settings.json');
  return path.join(opts.home || os.homedir(), '.gemini', 'settings.json');
}

/** The path of the system settings file the docs name (Linux and macOS). */
function systemSettingsFile() {
  return '/etc/gemini-cli/settings.json';
}

/** Removes zn's handlers from a list of hook groups; returns the groups that remain. */
function stripOurs(groups) {
  if (!Array.isArray(groups)) return groups;
  const kept = [];
  for (const g of groups) {
    if (isObj(g) && Array.isArray(g.hooks)) {
      const hs = g.hooks.filter((h) => !(isObj(h) && cfg.isOurs(h.command, id)));
      if (hs.length) kept.push(hs.length === g.hooks.length ? g : { ...g, hooks: hs });
    } else if (!(isObj(g) && cfg.isOurs(g.command, id))) {
      kept.push(g);
    }
  }
  return kept;
}

/**
 * The hook command. Gemini CLI fails open when a hook cannot start (only exit code 2 blocks), so a user install
 * goes through zn's launcher (lib/agents/launcher.js): a Node.js that has gone away blocks the tool (exit 2)
 * instead of letting it run. A project install runs `zn` from the PATH inside a start guard that blocks the same way; a command given by the caller keeps the plain command.
 */
function commandFor(opts = {}) {
  const platform = opts.platform || process.platform;
  const scope = opts.scope || 'user';
  if (opts.command) return cfg.hookCommand(id, opts);
  // A project install runs `zn` from the PATH inside zn's start guard (launcher.projectShCommand / projectWindowsScript): a missing zn or Node.js blocks.
  if (scope === 'project') return platform === 'win32' ? launcher.windowsScriptCommand(launcher.projectWindowsScript(id, 'BeforeTool')) : launcher.projectShCommand(id, 'BeforeTool');
  const node = opts.nodePath || process.execPath;
  const runner = opts.runnerPath || cfg.runnerPath();
  if (platform === 'win32') {
    const script = launcher.windowsScript(id, 'BeforeTool', node, runner);
    return script ? launcher.windowsScriptCommand(script) : cfg.hookCommandWindows(id, opts);
  }
  return launcher.launcherCommand(launcher.writeLauncher(id, node, runner, { ...opts, deadlineS: launcher.launcherDeadlineS(HOOK_TIMEOUT_MS / 1000), deadlineSoft: true }), 'BeforeTool', platform);
}

function install(opts = {}) {
  const scope = opts.scope || 'user';
  const file = settingsFile(opts);
  const data = cfg.readJson(file);
  const hooks = cfg.hooksOf(data, file);
  if (hooks.BeforeTool !== undefined && !Array.isArray(hooks.BeforeTool)) {
    throw new Error('"hooks.BeforeTool" in ' + file + ' must be a list (left unchanged)');
  }
  const report = { settings: file, backup: cfg.backup(file), warnings: [] };
  if (report.backup && scope === 'project') report.warnings.push('The backup ' + report.backup + ' sits inside the project: do not commit it.');
  const command = commandFor(opts);
  const groups = stripOurs(hooks.BeforeTool || []);
  groups.push({ matcher: MATCHER, hooks: [{ name: HOOK_NAME, type: 'command', command, timeout: HOOK_TIMEOUT_MS }] });
  hooks.BeforeTool = groups;
  data.hooks = hooks;
  cfg.writeJson(file, data);
  report.warnings.push('Gemini CLI support is experimental. zn checks tool calls before they run (BeforeTool): it blocks reads and writes of secret files and shell commands that handle secrets.');
  report.warnings.push('Gemini CLI treats a hook that crashes or times out as a warning and runs the tool anyway (only exit code 2 blocks). If the Node.js zn was installed with goes away, zn\'s launcher script blocks the tool instead; run `zn-gate check` to see that the hook works.');
  report.warnings.push('Gemini CLI hooks cannot ask the user and zn does not use AfterTool, so what a tool returns is not hidden: a value printed by a command or a file the agent may read reaches the model. Keep secrets in the vault.');
  if (scope === 'project') {
    report.warnings.push('Gemini CLI treats a project hook as untrusted until the user approves it, and runs `zn` from your PATH (zn hook gemini): every teammate who opens this project needs zn-gate installed.');
  }
  report.warnings.push('The settings `hooksConfig.enabled: false`, a name in `hooksConfig.disabled`, or `/hooks disable` turn the hook off; `zn-gate check` reports them.');
  return report;
}

function uninstall(opts = {}) {
  const file = settingsFile(opts);
  const report = { settings: file, backup: null, removed: 0, warnings: [] };
  if (!fs.existsSync(file)) return report;
  const data = cfg.readJson(file);
  const hooks = cfg.hooksOf(data, file);
  const before = JSON.stringify(hooks);
  for (const event of Object.keys(hooks)) {
    const kept = stripOurs(hooks[event]);
    if (Array.isArray(kept) && kept.length === 0) delete hooks[event]; else hooks[event] = kept;
  }
  if (JSON.stringify(hooks) === before) return report;
  if (Object.keys(hooks).length === 0) delete data.hooks; else data.hooks = hooks;
  report.backup = cfg.backup(file);
  report.removed = 1;
  cfg.writeJson(file, data);
  // The launcher (see commandFor) is shared by every config of this machine: one uninstall leaves it in place,
  // only the machine-wide uninstall (opts.removeLauncher) deletes it.
  if ((opts.scope || 'user') !== 'project' && opts.removeLauncher === true) {
    try { fs.unlinkSync(launcher.launcherFile(id, opts)); } catch (_) { /* none */ }
  }
  return report;
}

function detect(opts = {}) {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  if (whichSync('gemini', env.PATH || '')) return true;
  return ['settings.json', 'oauth_creds.json', 'GEMINI.md', 'tmp'].some((f) => fs.existsSync(path.join(home, '.gemini', f)));
}

module.exports = {
  id,
  detect,
  install,
  uninstall,
  normalize,
  respond,
  capabilities: { ask: 'none', rewriteInput: false, rewriteOutput: false },
  HOOK_NAME,
  HOOK_TIMEOUT_MS,
  settingsFile,
  hooksFile: settingsFile,
  systemSettingsFile,
  pathsOf,
};
