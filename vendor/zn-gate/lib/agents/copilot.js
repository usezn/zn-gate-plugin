'use strict';

/**
 * GitHub Copilot CLI adapter. Experimental.
 *
 * Hook format (docs read 2026-10-19):
 *  - https://docs.github.com/en/copilot/reference/hooks-reference
 *  - https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models (custom model endpoint)
 *
 *  Files: Copilot CLI loads every *.json in <project>/.github/hooks/ and in ~/.copilot/hooks/ ($COPILOT_HOME/hooks/
 *  when COPILOT_HOME is set), after the machine policy files (/etc/github-copilot/policy.d/*.json, which no user
 *  setting can switch off). zn writes its own file, zn-gate.json, in one of those folders and only edits what it
 *  wrote there:
 *    { "version": 1, "hooks": { "preToolUse": [ { "type": "command", "bash": "...", "powershell": "...", "timeoutSec": 15 } ] } }
 *
 *  stdin has two spellings, chosen by the casing of the event name in the hooks file: camelCase (preToolUse:
 *  sessionId, timestamp, cwd, toolName, toolArgs; postToolUse adds toolResult {resultType, textResultForLlm}) and
 *  the VS Code compatible one (PreToolUse: hook_event_name, session_id, tool_name, tool_input, tool_result). The
 *  camelCase payload does not name its event, so zn tells them apart by their fields. zn installs the camelCase keys.
 *  stdout of preToolUse: {permissionDecision: allow | deny | ask, permissionDecisionReason (required for deny)}.
 *  Empty output means "no opinion" (default behaviour), so zn never prints "allow".
 *  stdout of postToolUse: {modifiedResult: {resultType: "success", textResultForLlm}, additionalContext}.
 *  Exit codes: 0 = parse stdout; 2 = deny for preToolUse (a warning for the other events); any other non-zero =
 *  fail-closed for preToolUse and fail-open for the others. A TIMEOUT (default 30 s) always fails OPEN.
 *
 *  Events: preToolUse is checked and can deny (zn also asks for confirmation when it needs one; Copilot turns
 *  "ask" into a deny in the cloud agent and in autopilot). postToolUse replaces secret values in the result of
 *  read-type and shell tools. userPromptSubmitted cannot block or rewrite for command hooks (modifiedPrompt is
 *  honoured only by SDK hooks) and sessionStart can only add context, so zn does not install them; if one arrives
 *  anyway it gets no opinion.
 *
 * Runtime tool names: bash, powershell (CLI only), view, create, edit, grep, glob, web_fetch, task, ask_user. The
 * argument names are not documented on that page, so this adapter finds the command and the files by likely key
 * names (like the Antigravity adapter) and refuses a known tool whose arguments it cannot read. How an MCP tool is
 * named is not documented: a tool zn cannot classify gets the path checks if it names a file and no opinion
 * otherwise.
 *
 * Checked against a real Copilot CLI 1.0.98 (bench/e2e/harness/run_copilot.sh, scripted provider): tool names bash, view,
 * create with the arguments command, path, file_text; a deny is shown to the model as "Denied by preToolUse hook: <reason>";
 * postToolUse modifiedResult reaches the model; no secret value reached the provider. Copilot's own events.jsonl keeps the original output.
 *
 * Switching hooks off: "disableAllHooks": true at the top of a hooks file skips that file; in a repository's
 * .github/copilot/settings(.local).json it skips every hook except the policy ones. `zn-gate check` reports both.
 */

const fs = require('fs');
const { fileURLToPath } = require('url');
const os = require('os');
const path = require('path');
const cfg = require('./config-file');
const launcher = require('./launcher');

const id = 'copilot';
const FILE_NAME = 'zn-gate.json';
const HOOK_TIMEOUT_S = 15;
const INSTALL_EVENTS = ['preToolUse', 'postToolUse'];

// The VS Code compatible spelling may carry Claude-style tool names.
const CLAUDE_NAMES = { Bash: 'bash', Read: 'view', Write: 'create', Edit: 'edit', MultiEdit: 'edit', Grep: 'grep', Glob: 'glob', WebFetch: 'web_fetch' };
const SHELL_TOOLS = new Set(['bash', 'powershell']);
const WRITE_TOOLS = new Set(['create', 'edit']);
const KNOWN_TOOLS = new Set(['bash', 'powershell', 'view', 'create', 'edit', 'grep', 'glob', 'web_fetch']);
const COMMAND_KEYS = ['command', 'cmd', 'Command', 'script'];
const PATH_KEY_RE = /path|file|target|uri|dir|source|destination/i;
const NOT_PATH_KEY_RE = /content|text|instruction|description|query|pattern|code|chunk|summary|title|str$/i;
const MAX_PATH_LEN = 4096;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

function firstString(obj, keys) {
  for (const k of keys) if (typeof obj[k] === 'string' && obj[k]) return obj[k];
  return undefined;
}

/** Every string argument whose key looks like a file or folder (content-like keys skipped), three levels deep. */
function pathsOf(args) {
  const out = [];
  let bad = false;
  const add = (k, v) => {
    if (typeof v !== 'string' || !v) return;
    if (/^file:/i.test(v)) {
      try { out.push(fileURLToPath(v)); } catch (_) { bad = true; }
      return;
    }
    if (/url/i.test(k) && !PATH_KEY_RE.test(k)) return;
    if (v.length > MAX_PATH_LEN || /[\r\n]/.test(v)) return;
    out.push(v);
  };
  const keyOk = (k) => (PATH_KEY_RE.test(k) || /url/i.test(k)) && !NOT_PATH_KEY_RE.test(k);
  const walk = (obj, depth) => {
    for (const [k, v] of Object.entries(obj)) {
      if (keyOk(k)) {
        if (Array.isArray(v)) v.forEach((x) => add(k, x)); else add(k, v);
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

/** The event of a payload: the casing of the hooks file picks the spelling, and the camelCase one has no event name. */
function eventName(raw) {
  const named = raw.hook_event_name || raw.hookEventName;
  if (typeof named === 'string' && named) return named.charAt(0).toLowerCase() + named.slice(1);
  const has = (k) => raw[k] !== undefined && raw[k] !== null;
  if (has('toolResult') || has('tool_result')) return 'postToolUse';
  if (has('toolName') || has('tool_name') || has('toolArgs') || has('tool_input')) return has('error') ? 'postToolUseFailure' : 'preToolUse';
  if (typeof raw.prompt === 'string') return 'userPromptSubmitted';
  if (has('source')) return 'sessionStart';
  return null;
}

/** toolArgs / tool_input as an object. A JSON string is parsed too. null = could not be read. */
function argsOf(raw) {
  let a = raw.toolArgs !== undefined ? raw.toolArgs : raw.tool_input;
  if (a === undefined || a === null) return {};
  if (typeof a === 'string') {
    try { a = JSON.parse(a); } catch (_) { return null; }
  }
  return isObj(a) ? a : null;
}

function resultText(raw) {
  const r = raw.toolResult !== undefined ? raw.toolResult : raw.tool_result;
  if (!isObj(r)) return undefined;
  const type = r.resultType !== undefined ? r.resultType : r.result_type;
  const text = r.textResultForLlm !== undefined ? r.textResultForLlm : r.text_result_for_llm;
  // Only a successful result is rewritten: modifiedResult must say "success", so it cannot stand in for a failure.
  return type === 'success' && typeof text === 'string' ? text : undefined;
}

function normalize(raw) {
  if (!isObj(raw)) return null;
  const cwd = typeof raw.cwd === 'string' && raw.cwd ? raw.cwd : process.cwd();
  const base = { cwd, sessionId: raw.sessionId || raw.session_id || null, raw };
  const name = eventName(raw);
  if (name !== 'preToolUse' && name !== 'postToolUse') return { ...base, event: null };
  const rawName = String(raw.toolName !== undefined ? raw.toolName : raw.tool_name || '');
  const toolName = CLAUDE_NAMES[rawName] || rawName.toLowerCase();
  const args = argsOf(raw);
  const event = name === 'preToolUse' ? 'pre_tool' : 'post_tool';
  const ev = { ...base, event, toolName, rawArgs: args || {} };
  if (event === 'pre_tool' && !rawName) return { ...ev, tool: 'unreadable', input: { texts: [] }, unreadable: 'zn: could not read the tool name of this call, so zn cannot check it.' };
  if (event === 'post_tool') ev.output = resultText(raw);
  const unreadable = (what) => 'zn: could not read the ' + what + ' of this call, so zn cannot check it.';

  const known = KNOWN_TOOLS.has(toolName);
  if (args === null) {
    return { ...ev, tool: toolName || 'unknown', input: { texts: [] }, ...(known ? { unreadable: unreadable('arguments') } : {}) };
  }
  const cmd = firstString(args, COMMAND_KEYS);
  if (SHELL_TOOLS.has(toolName) || (!known && cmd !== undefined)) {
    const e = { ...ev, tool: toolName === 'powershell' ? 'powershell' : 'bash', input: { command: cmd || '', texts: [] } };
    if (cmd === undefined) e.unreadable = unreadable('command');
    return e;
  }
  const { paths, bad } = pathsOf(args);
  const input = { path: paths[0], paths, texts: [] };
  const kind = toolName === 'view' ? 'read' : toolName === 'grep' ? 'grep' : WRITE_TOOLS.has(toolName) ? 'write' : null;
  if (kind) {
    const searchDir = kind === 'grep' ? (paths[0] ? path.resolve(cwd, paths[0]) : cwd) : null;
    const e = { ...ev, tool: kind, input: searchDir ? { ...input, scanDir: searchDir } : input };
    if (bad) e.unreadable = unreadable('file address');
    else if (kind !== 'grep' && !paths.length) e.unreadable = unreadable('file');
    return e;
  }
  if (toolName === 'web_fetch') {
    const url = firstString(args, ['url', 'uri', 'URL']);
    return { ...ev, tool: 'webfetch', input: { url: url || '', texts: [] } };
  }
  // glob lists names only. Any other tool that names a file (a plugin, an MCP server, a future tool) gets the read
  // and write checks on every path in it; tools with no path get no opinion.
  if (toolName !== 'glob' && (paths.length || bad)) {
    const e = { ...ev, tool: 'fileaccess', input };
    if (bad) e.unreadable = unreadable('file address');
    return e;
  }
  return { ...ev, tool: toolName || 'unknown', input: { texts: [] } };
}

function respond(d) {
  const ev = d && d.event;
  if (!ev || !ev.event) return null; // no opinion: empty output
  if (ev.event === 'post_tool') {
    if (typeof d.updatedOutput !== 'string') return null;
    const o = { modifiedResult: { resultType: 'success', textResultForLlm: d.updatedOutput } };
    if (d.message) o.additionalContext = d.message;
    return o;
  }
  const deny = (reason) => ({ permissionDecision: 'deny', permissionDecisionReason: reason });
  if (d.decision === 'deny') return deny(d.message || 'Blocked by zn');
  if (ev.unreadable) return deny(ev.unreadable);
  if (d.updatedInput && d.kind === 'wrap') {
    return deny('zn: this command uses a stored secret. Run it through zn instead, exactly like this: zn run -- ' + ev.input.command +
      '  (zn puts the value only into that process, if the user allowed this command for the secret).');
  }
  // A rewritten command is not applied (the argument names are not documented): the user is asked about the
  // original instead. Copilot turns "ask" into a deny where nobody can answer (cloud agent, autopilot).
  if (d.decision === 'ask' || d.updatedInput) return { permissionDecision: 'ask', permissionDecisionReason: d.message || 'zn asks for confirmation' };
  return null; // never "allow": zn has no opinion and Copilot's own permission rules decide
}

/* ------------------------ install / uninstall ---------------------- */

/** Copilot's user folder: $COPILOT_HOME, else ~/.copilot. */
function copilotHome(opts = {}) {
  const env = opts.env || process.env;
  return env.COPILOT_HOME || path.join(opts.home || os.homedir(), '.copilot');
}

function hooksFile(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.github', 'hooks', FILE_NAME);
  return path.join(copilotHome(opts), 'hooks', FILE_NAME);
}

const handlerIsOurs = (h) => isObj(h) && ['bash', 'powershell', 'command'].some((k) => cfg.isOurs(h[k], id));

/** Removes zn's handlers from a hooks file's data; true when something was removed. */
function stripOurs(data) {
  if (!isObj(data.hooks)) return false;
  let changed = false;
  for (const event of Object.keys(data.hooks)) {
    const list = data.hooks[event];
    if (!Array.isArray(list)) continue;
    const kept = list.filter((h) => !handlerIsOurs(h));
    if (kept.length !== list.length) changed = true;
    if (kept.length) data.hooks[event] = kept; else delete data.hooks[event];
  }
  return changed;
}

function install(opts = {}) {
  const file = hooksFile(opts);
  const project = (opts.scope || 'user') === 'project';
  const data = cfg.readJson(file);
  if (data.version !== undefined && data.version !== 1) throw new Error(file + ' has "version": ' + JSON.stringify(data.version) + ', not 1 (left unchanged)');
  cfg.hooksOf(data, file);
  const report = { settings: file, backup: cfg.backup(file), warnings: [] };
  if (report.backup && project) report.warnings.push('The backup ' + report.backup + ' sits inside the project: do not commit it.');
  stripOurs(data);
  const platform = opts.platform || process.platform;
  // A project install runs `zn` from the PATH inside zn's start guard (launcher.projectShCommand / projectWindowsScript): a missing zn or Node.js denies the call.
  const guarded = project && !opts.command;
  const bash = cfg.hookCommand(id, opts);
  const handlerFor = (event) => {
    if (guarded) return { type: 'command', bash: launcher.projectShCommand(id, event), powershell: launcher.windowsScriptCommand(launcher.projectWindowsScript(id, event)), timeoutSec: HOOK_TIMEOUT_S };
    const h = { type: 'command', bash, timeoutSec: HOOK_TIMEOUT_S };
    if (opts.command) h.powershell = opts.command;
    else if (project) h.powershell = bash;
    else if (platform === 'win32') h.powershell = cfg.hookCommandWindows(id, opts);
    return h;
  };
  data.version = 1;
  if (!isObj(data.hooks)) data.hooks = {};
  // "disableAllHooks" in a file zn wrote would switch its own hook off: an install turns it back on.
  if (data.disableAllHooks === true) {
    delete data.disableAllHooks;
    report.warnings.push('"disableAllHooks" was true in this file and was removed: it switched every hook of the file off.');
  }
  for (const event of INSTALL_EVENTS) {
    const list = Array.isArray(data.hooks[event]) ? data.hooks[event] : [];
    data.hooks[event] = [...list, handlerFor(event)];
  }
  cfg.writeJson(file, data);
  report.warnings.push('GitHub Copilot CLI support is experimental. zn checks tool calls before they run (preToolUse): it blocks reads and writes of secret files and shell commands that handle secrets, and it replaces secret values in the results of read-type and shell tools (postToolUse).');
  report.warnings.push('Copilot keeps its own session log (events.jsonl) with the original tool output on this machine: zn replaces secret values in what goes to the model, not in that local log.');
  report.warnings.push('Copilot does not let a command hook block a typed prompt, so a secret pasted into a prompt is not stopped.');
  report.warnings.push('Copilot lets a call through when a hook times out (30 s by default; zn asks for ' + HOOK_TIMEOUT_S + ' s), and its machine policy files (/etc/github-copilot/policy.d, or the Windows policy folder) are loaded in addition to this one.');
  if (project && !opts.command) report.warnings.push('The project hook runs `zn` from your PATH (zn hook copilot): every teammate who opens this project in Copilot CLI needs zn-gate installed, otherwise the hook cannot start. Copilot also asks each person to trust the folder before it runs repository hooks.');
  return report;
}

function uninstall(opts = {}) {
  const file = hooksFile(opts);
  const report = { settings: file, backup: null, removed: 0, warnings: [] };
  if (!fs.existsSync(file)) return report;
  const data = cfg.readJson(file);
  const before = JSON.stringify(data);
  if (!stripOurs(data) || JSON.stringify(data) === before) return report;
  report.backup = cfg.backup(file);
  report.removed = 1;
  const hooksLeft = isObj(data.hooks) ? Object.keys(data.hooks).length : 0;
  const others = Object.keys(data).filter((k) => k !== 'version' && k !== 'hooks' && k !== 'disableAllHooks');
  if (!hooksLeft && !others.length) {
    fs.unlinkSync(file);
  } else {
    if (!hooksLeft) delete data.hooks;
    cfg.writeJson(file, data);
  }
  return report;
}

function detect(opts = {}) {
  return fs.existsSync(copilotHome(opts));
}

module.exports = {
  id,
  HOOK_TIMEOUT_S,
  detect,
  install,
  uninstall,
  normalize,
  respond,
  capabilities: { ask: 'interactive', rewriteInput: false, rewriteOutput: true },
  hooksFile,
  copilotHome,
};
