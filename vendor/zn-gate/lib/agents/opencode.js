'use strict';

/**
 * OpenCode adapter: a plugin that calls the zn hook runner.
 *
 * Plugin API (opencode.ai/docs/plugins and the OpenCode source at v1.18.25,
 * read 2026-10-11):
 *  - Plugins load from ~/.config/opencode/plugins/ (user) and
 *    <project>/.opencode/plugins/ (project); `plugin/` also works.
 *  - "tool.execute.before"(input {tool, sessionID, callID}, output {args}):
 *    mutating output.args in place changes the call; throwing blocks it.
 *    OpenCode's own permission rules still apply afterwards, so a rewrite
 *    never approves anything by itself.
 *  - "tool.execute.after"(input {tool, sessionID, callID, args},
 *    output {title, output, metadata}): mutating output.output in place
 *    changes what the model sees. MCP tools hand over the raw MCP result
 *    (content[].text), which is rewritten in place too, and so is
 *    output.metadata (the TUI's preview of the output, kept in OpenCode's
 *    local database). Metadata that OpenCode writes while a command is still
 *    running is stored before the hook runs and is out of its reach.
 *  - "chat.message"(input, output {message, parts}): runs before the user's
 *    message is stored and sent; throwing stops it.
 *  - Tool ids and arguments: bash {command}, read {filePath},
 *    write {filePath, content}, edit {filePath, oldString, newString},
 *    grep {pattern, path}, webfetch {url}, apply_patch {patchText}, lsp;
 *    MCP tools are <server>_<tool>.
 *
 * The plugin (written by `zn hooks install opencode`) sends each event to
 * `node lib/hooks/runner.js opencode` on stdin and applies the answer:
 *   {action: "deny", message}            throw (the call or the message is blocked)
 *   {action: "args", args, message}      set those args in place
 *   {action: "output", output, content}  set the tool output in place
 *   {action: "none"}
 * A runner that fails or answers garbage fails closed in the plugin.
 *
 * Do not rely on OpenCode's shell.env to pass secrets (issue #41117): zn
 * rewrites the command itself.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { whichSync } = require('../broker/markers');
const { askAsDeny, isPlainAsk } = require('./ask-deny');
const { writeFileAtomic } = require('../broker/files');
const cfg = require('./config-file');
const { patchScan, PATCH_SCAN_CAP } = require('./codex');

const id = 'opencode';
const PLUGIN_FILE = 'zn-gate.js';
const PLUGIN_MARK = '// zn-gate plugin for OpenCode';
const BUILTIN = new Set(['bash', 'read', 'write', 'edit', 'grep', 'glob', 'webfetch', 'websearch', 'apply_patch', 'task', 'todowrite', 'todoread', 'todo', 'skill', 'question', 'plan', 'list', 'patch', 'multiedit', 'lsp']);

const TOKENIZED_OUTPUT = new Set(['task', 'websearch', 'glob', 'list', 'skill', 'codesearch']);

function textsOf(tool, args) {
  const texts = [];
  const add = (key, v) => { if (typeof v === 'string') texts.push({ key: [key], value: v }); };
  if (tool === 'write') add('content', args.content);
  if (tool === 'edit') { add('oldString', args.oldString); add('newString', args.newString); }
  if (tool === 'apply_patch') add('patchText', args.patchText);
  return texts;
}

// The plugin sends the base name of $SHELL (never a path; empty when unset) and process.platform.
// powershell.exe, pwsh and pwsh-preview all count as PowerShell.
function shellBase(name) {
  if (typeof name !== 'string') return '';
  return name.replace(/\\/g, '/').split('/').pop().toLowerCase().replace(/\.exe$/, '');
}
function isPowerShellName(name) {
  const base = shellBase(name);
  return base === 'powershell' || /^pwsh(-preview)?$/.test(base);
}
const BASH_LIKE = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh']);
// Mirrors OpenCode's own choice (packages/core/src/shell/select.ts): on Windows it uses $SHELL
// when that names a usable shell and otherwise picks pwsh, then powershell, then Git Bash, then
// cmd.exe. So on Windows an unset or non-bash $SHELL means PowerShell; elsewhere only an
// explicit PowerShell name does. Measured with OpenCode 1.19.3 on Windows Server 2022.
function usesPowerShell(shell, platform) {
  if (isPowerShellName(shell)) return true;
  if (platform !== 'win32') return false;
  return !BASH_LIKE.has(shellBase(shell));
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const args = raw.args && typeof raw.args === 'object' ? raw.args : {};
  const root = raw.cwd || process.cwd();
  // A command or file tool that names its own working directory is checked from there.
  const cwd = typeof args.workdir === 'string' && args.workdir ? path.resolve(root, args.workdir) : root;
  const base = { cwd, sessionId: raw.sessionID || null, raw };
  if (raw.hook === 'chat.message') return { ...base, event: 'user_prompt', tool: null, input: { prompt: typeof raw.prompt === 'string' ? raw.prompt : '' } };
  const t = String(raw.tool || '');
  let tool;
  if (t === 'read_mcp_resource') tool = 'mcpresource';
  else if (t === 'apply_patch' || t === 'patch') tool = 'write';
  // These return text the model reads, so their output is tokenized like MCP output.
  else if (TOKENIZED_OUTPUT.has(t)) tool = 'mcp';
  else if (BUILTIN.has(t)) tool = t;
  else tool = 'mcp';
  // OpenCode's bash tool runs in the user's shell. When the plugin saw that it is PowerShell,
  // the command is checked and wrapped as PowerShell, not as POSIX sh.
  if (tool === 'bash' && usesPowerShell(raw.shell, raw.platform)) tool = 'powershell';
  const input = {
    command: typeof args.command === 'string' ? args.command : undefined,
    path: args.filePath || args.path || undefined,
    url: typeof args.url === 'string' ? args.url : undefined,
    texts: textsOf(t === 'patch' ? 'apply_patch' : t, args),
  };
  if (t === 'apply_patch' || t === 'patch') {
    // Every file the patch touches is checked, as in the Codex adapter.
    const tooLong = String(args.patchText || '').length > PATCH_SCAN_CAP;
    const scan = tooLong ? { files: [], suspicious: false } : patchScan(args.patchText);
    const files = scan.files;
    input.paths = files;
    input.path = files[0];
    input.tooLong = tooLong;
    input.unparsed = !tooLong && (files.length === 0 || scan.suspicious);
  }
  if (raw.hook === 'tool.execute.before') return { ...base, event: 'pre_tool', tool, toolName: t, input };
  if (raw.hook === 'tool.execute.after') {
    const output = {};
    if (typeof raw.output === 'string') output.output = raw.output;
    if (Array.isArray(raw.content)) output.content = raw.content;
    // metadata holds the TUI's copy of the output (previews, display text),
    // which OpenCode stores in its local database.
    if (raw.metadata && typeof raw.metadata === 'object') output.metadata = raw.metadata;
    // The runner only scrubs tools it knows; everything else counts as MCP.
    return { ...base, event: 'post_tool', tool: tool === 'write' || tool === 'edit' ? 'read' : tool, toolName: t, input, output };
  }
  return { ...base, event: null };
}

function respond(d) {
  const ev = d && d.event;
  if (!ev || !ev.event) return { action: 'none' };
  if (d.decision === 'deny' && ev.event !== 'post_tool') return { action: 'deny', message: d.message || 'Blocked by zn' };
  // OpenCode's plugin API has no question: one that zn wanted to ask is a deny.
  if (ev.event === 'pre_tool' && isPlainAsk(d)) return { action: 'deny', message: askAsDeny('OpenCode', d) };
  // Only rewrites that add no secret value (wrapping in `zn run`) are
  // applied. Restoring detected values into the arguments is not: OpenCode
  // keeps the mutated arguments in the session, where the model could read
  // them back. Those tokens stay as they are.
  if (ev.event === 'pre_tool' && d.updatedInput && d.kind === 'wrap') {
    const args = {};
    if (typeof d.updatedInput.command === 'string') args.command = d.updatedInput.command;
    for (const t of d.updatedInput.texts || []) args[t.key[0]] = t.value;
    return { action: 'args', args, message: d.message };
  }
  if (ev.event === 'post_tool' && d.updatedOutput !== undefined) {
    return { action: 'output', output: d.updatedOutput.output, content: d.updatedOutput.content, metadata: d.updatedOutput.metadata, message: d.message };
  }
  return { action: 'none' };
}

/* ------------------------------ plugin ------------------------------ */

// Seconds the plugin waits for the runner before it gives up (and the post-tool check stops before that).
const HOOK_TIMEOUT_S = 20;

function pluginSource(opts = {}) {
  // A project plugin is shared through the repository: it calls `zn` on PATH
  // instead of naming this user's node and runner.
  const project = (opts.scope || 'user') === 'project';
  const node = JSON.stringify((opts.nodePath || process.execPath).replace(/\\/g, '/'));
  const runner = JSON.stringify((opts.runnerPath || cfg.runnerPath()).replace(/\\/g, '/'));
  const launch = project ? 'const NODE = "zn";\nconst RUNNER = null;' : `const NODE = ${node};\nconst RUNNER = ${runner};`;
  const argv = project ? '["hook", "opencode"]' : '[RUNNER, "opencode"]';
  // On Windows `zn` is zn.cmd, which spawn runs only through a shell. The
  // arguments are fixed strings, so the shell adds no input of its own; and
  // neither `zn` nor the `node` it starts may come from the folder OpenCode
  // runs in (the project, where an agent can write a zn or node of its own):
  // the PATH keeps only its absolute entries, and cmd.exe does not look in the
  // current directory first.
  const shell = project ? 'process.platform === "win32"' : 'false';
  const env = project ? 'projectEnv()' : 'process.env';
  const projectEnvSource = project ? `
// The environment of \`zn\`: the PATH without its relative or empty entries, and
// on Windows no search of the current directory by cmd.exe.
function projectEnv() {
  const win = process.platform === "win32";
  const env = {};
  let pathValue = "";
  for (const [k, v] of Object.entries(process.env)) {
    if (k.toUpperCase() === "PATH") pathValue = String(v || "");
    else env[k] = v;
  }
  const keep = (d) => (win ? /^(?:[A-Za-z]:[\\\\/]|\\\\\\\\)/.test(d) : d.startsWith("/"));
  env.PATH = pathValue.split(win ? ";" : ":").filter(keep).join(win ? ";" : ":");
  if (win) env.NoDefaultCurrentDirectoryInExePath = "1";
  return env;
}
` : '';
  return `${PLUGIN_MARK} (written by \`zn hooks install opencode\`; remove with \`zn hooks uninstall opencode\`).
// Sends tool calls, tool results and chat messages to the local zn hook runner,
// which blocks reads of secret files, puts commands that use stored secrets
// through \`zn run\`, and replaces secret values in tool output with __ZN_ tokens.
import { spawn } from "node:child_process";

${launch}
${projectEnvSource}const TIMEOUT_MS = ${HOOK_TIMEOUT_S * 1000};
// The only answers the plugin acts on. Any other answer is an error, which
// blocks the call (before), withholds the output (after) or stops the message.
const ACTIONS = ["none", "deny", "error", "args", "output"];
// OpenCode runs its bash tool in $SHELL, or in PowerShell on Windows when it is unset. The
// runner needs only the program's name (not its path) and the platform to tell them apart.
const SHELL = String(process.env.SHELL || "").replace(/\\\\/g, "/").split("/").pop();

// Copy scrubbed string leaves from src into target, in place.
function applyStrings(target, src) {
  if (!target || !src || typeof target !== "object" || typeof src !== "object") return;
  for (const k of Object.keys(src)) {
    if (typeof src[k] === "string" && typeof target[k] === "string") target[k] = src[k];
    else if (src[k] && typeof src[k] === "object") applyStrings(target[k], src[k]);
  }
}

function runHook(event) {
  return new Promise((resolve) => {
    let out = "";
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let child;
    try {
      child = spawn(NODE, ${argv}, { stdio: ["pipe", "pipe", "ignore"], windowsHide: true, shell: ${shell}, env: ${env} });
    } catch (err) {
      finish({ action: "error", message: String(err && err.message || err) });
      return;
    }
    const timer = setTimeout(() => { try { child.kill(); } catch (_) {} finish({ action: "error", message: "timeout" }); }, TIMEOUT_MS);
    child.stdout.on("data", (c) => { out += c; });
    child.on("error", (err) => { clearTimeout(timer); finish({ action: "error", message: String(err && err.message || err) }); });
    child.on("close", () => {
      clearTimeout(timer);
      let answer = null;
      try { answer = JSON.parse(out); } catch (_) { answer = null; }
      if (!answer || typeof answer !== "object" || !ACTIONS.includes(answer.action)) {
        finish({ action: "error", message: "no answer from the zn hook" });
      } else {
        finish(answer);
      }
    });
    // A hook that ends without reading its input (EPIPE) is answered by close above; it must not crash OpenCode.
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(event));
  });
}

export const ZnGate = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    const r = await runHook({ hook: "tool.execute.before", tool: input.tool, sessionID: input.sessionID, cwd: directory, args: output.args, shell: SHELL, platform: process.platform });
    if (r.action === "deny") throw new Error(r.message);
    if (r.action === "error") throw new Error("zn: the secret scrubber is not working (" + r.message + "); call blocked");
    if (r.action === "args" && r.args) for (const [k, v] of Object.entries(r.args)) output.args[k] = v;
  },
  "tool.execute.after": async (input, output) => {
    const content = Array.isArray(output.content) ? output.content : null;
    const r = await runHook({
      hook: "tool.execute.after", tool: input.tool, sessionID: input.sessionID, cwd: directory, args: input.args, shell: SHELL, platform: process.platform,
      output: typeof output.output === "string" ? output.output : undefined,
      metadata: output.metadata && typeof output.metadata === "object" ? output.metadata : undefined,
      content: content ? content.map((c) => (c && typeof c.text === "string" ? { type: c.type, text: c.text } : { type: c && c.type })) : undefined,
    });
    if (r.action === "error") {
      if (typeof output.output === "string") output.output = "[zn: output withheld: the secret scrubber is not working]";
      if (output.metadata && typeof output.metadata === "object") output.metadata = {};
      if (content) for (const c of content) if (c && typeof c.text === "string") c.text = "[zn: output withheld]";
      return;
    }
    if (r.action !== "output") return;
    if (typeof r.output === "string" && typeof output.output === "string") output.output = r.output;
    if (r.metadata) applyStrings(output.metadata, r.metadata);
    if (content && Array.isArray(r.content)) r.content.forEach((c, i) => { if (c && typeof c.text === "string" && content[i]) content[i].text = c.text; });
  },
  "chat.message": async (input, output) => {
    const parts = Array.isArray(output.parts) ? output.parts : [];
    const prompt = parts.filter((p) => p && p.type === "text" && typeof p.text === "string").map((p) => p.text).join("\\n");
    if (!prompt) return;
    const r = await runHook({ hook: "chat.message", sessionID: input.sessionID, cwd: directory, prompt });
    if (r.action === "deny") throw new Error(r.message);
    if (r.action === "error") throw new Error("zn: the secret scrubber is not working (" + r.message + "); message not sent");
  },
});
`;
}

/* ------------------------ install / uninstall ---------------------- */

function configDir(opts = {}) {
  const env = opts.env || process.env;
  return path.join(env.XDG_CONFIG_HOME ? path.resolve(env.XDG_CONFIG_HOME) : path.join(opts.home || os.homedir(), '.config'), 'opencode');
}

function pluginPath(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.opencode', 'plugins', PLUGIN_FILE);
  return path.join(configDir(opts), 'plugins', PLUGIN_FILE);
}

function install(opts = {}) {
  const file = pluginPath(opts);
  const report = { settings: file, backup: null, warnings: [] };
  if (fs.existsSync(file) && !fs.readFileSync(file, 'utf8').startsWith(PLUGIN_MARK)) {
    throw new Error(file + ' exists and was not written by zn; left unchanged');
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  writeFileAtomic(file, pluginSource(opts), 0o644);
  if (opts.mcp !== false) {
    // A project's opencode.json is shared: the hint names zn on the PATH, never the paths of this machine.
    const project = (opts.scope || 'user') === 'project';
    const cli = path.resolve(__dirname, '..', '..', 'bin', 'cli.js').replace(/\\/g, '/');
    const command = project
      ? ['zn', 'secrets-mcp', '--agent', 'opencode']
      : [(opts.nodePath || process.execPath).replace(/\\/g, '/'), cli, 'secrets-mcp', '--agent', 'opencode'];
    report.warnings.push('optional: to let OpenCode use the secrets kept in zn\'s vault, add the "secrets" MCP server to ' +
      (project ? 'opencode.json in this project' : 'opencode.json') + ' under "mcp": "secrets": ' + JSON.stringify({ type: 'local', command }) +
      (project ? ' (everyone who uses the project needs zn on their PATH)' : ''));
  }
  return report;
}

function uninstall(opts = {}) {
  const file = pluginPath(opts);
  const report = { settings: file, backup: null, removed: 0, warnings: [] };
  if (fs.existsSync(file) && fs.readFileSync(file, 'utf8').startsWith(PLUGIN_MARK)) {
    fs.unlinkSync(file);
    report.removed = 1;
  }
  return report;
}

function detect(opts = {}) {
  if (whichSync('opencode', (opts.env || process.env).PATH || '')) return true;
  return fs.existsSync(configDir(opts));
}

module.exports = {
  id,
  HOOK_TIMEOUT_S,
  detect,
  install,
  uninstall,
  normalize,
  isPowerShellName,
  usesPowerShell,
  respond,
  capabilities: { ask: false, rewriteInput: true, rewriteOutput: 'all' },
  pluginSource,
  pluginPath,
};
