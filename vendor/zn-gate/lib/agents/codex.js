'use strict';

/**
 * OpenAI Codex CLI adapter.
 *
 * Hook format (learn.chatgpt.com/docs/hooks, read 2026-10-11; the old
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
 *    tool_use_id and tool_input. Bash and apply_patch use tool_input.command.
 *
 *  PreToolUse: hookSpecificOutput.permissionDecision "deny" (+ reason).
 *    updatedInput is accepted only with "allow", and "ask" is not supported
 *    (the hook is marked failed and the call runs).
 *  PostToolUse: no field rewrites the output; {decision: "block", reason}
 *    replaces the tool result with the reason.
 *  UserPromptSubmit: {decision: "block", reason}.
 *  Exit 0 with no output: no opinion; Codex's own approval policy applies.
 *
 * What that means here (docs/compat.md):
 *  - Reads of credential files, .env with values and ~/.zn are denied.
 *  - A command with __ZN_<NAME>__ markers is denied with the exact
 *    `zn run -- ...` command to use instead, because rewriting it would
 *    need "allow", which skips the user's approval policy. Once the agent
 *    runs it through zn run, the hook stays silent and Codex's approval
 *    policy plus zn run's own checks apply.
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
const { whichSync } = require('../broker/markers');

const id = 'codex';
const PRE_MATCHER = '^(Bash|apply_patch)$';
// Every tool: output of tools zn does not know is tokenized like MCP output.
const POST_MATCHER = '.*';
const HOOK_TIMEOUT_S = 30;

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

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const name = raw.hook_event_name;
  const event = name === 'PreToolUse' ? 'pre_tool' : name === 'PostToolUse' ? 'post_tool' : name === 'UserPromptSubmit' ? 'user_prompt' : null;
  const base = { event, cwd: raw.cwd || process.cwd(), sessionId: raw.session_id || null, raw };
  if (event === 'user_prompt') return { ...base, tool: null, input: { prompt: typeof raw.prompt === 'string' ? raw.prompt : '' } };
  if (!event) return base;
  const toolName = String(raw.tool_name || '');
  const mcp = /^mcp__(.+?)__(.+)$/.exec(toolName);
  const ti = raw.tool_input && typeof raw.tool_input === 'object' ? raw.tool_input : {};
  // Unknown tools are treated like MCP output: their text is tokenized.
  let tool = mcp ? 'mcp' : toolName === 'Bash' ? 'bash' : toolName === 'apply_patch' ? 'write' : 'mcp';
  const input = { command: typeof ti.command === 'string' ? ti.command : undefined, texts: [] };
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
  return { ...base, tool, toolName, mcp: mcp ? { server: mcp[1], tool: mcp[2] } : null, input, output: event === 'post_tool' ? raw.tool_response : undefined };
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
    if (d.decision === 'deny') return deny(d.message || 'Blocked by zn');
    if (d.updatedInput && d.kind === 'wrap' && typeof ev.input.command === 'string') {
      return deny('zn: this command uses a stored secret. Run it through zn instead, exactly like this: zn run -- ' + ev.input.command +
        '  (zn puts the value only into that process, if the user allowed this command for the secret).');
    }
    // Restoring detected tokens or asking would need "allow" (skips the
    // user's approval policy) or "ask" (unsupported): stay silent.
    return null;
  }
  if (ev.event === 'post_tool') {
    if (d.updatedOutput !== undefined) {
      return {
        decision: 'block',
        reason: outputText(d.updatedOutput) + (d.message ? '\n\n[' + d.message + ']' : ''),
      };
    }
    if (d.decision === 'deny') return { decision: 'block', reason: d.message || 'zn: output withheld' };
    return null;
  }
  if (ev.event === 'user_prompt' && d.decision === 'deny') return { decision: 'block', reason: d.message || 'Blocked by zn' };
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

function install(opts = {}) {
  const file = hooksFile(opts);
  const data = cfg.readJson(file);
  const report = { settings: file, backup: cfg.backup(file), warnings: [] };
  data.hooks = cfg.hooksOf(data, file);
  const h = {
    type: 'command',
    command: cfg.hookCommand(id, opts),
    commandWindows: cfg.hookCommandWindows(id, opts),
    timeout: HOOK_TIMEOUT_S,
    statusMessage: 'zn: checking for secrets',
  };
  const ours = {
    PreToolUse: { matcher: PRE_MATCHER, hooks: [h] },
    PostToolUse: { matcher: POST_MATCHER, hooks: [h] },
    UserPromptSubmit: { hooks: [h] },
  };
  for (const [event, group] of Object.entries(ours)) {
    data.hooks[event] = strip(data.hooks[event]);
    data.hooks[event].push(group);
  }
  cfg.writeJson(file, data);
  report.warnings.push('Codex runs new or changed hooks only after you trust them: open Codex and review them with /hooks.');
  if (opts.mcp !== false) {
    report.warnings.push('to add the "secrets" MCP server, put this in ' + path.join(codexHome(opts), 'config.toml') + ':\n' + mcpSnippet(opts));
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
    if (Object.keys(data.hooks).length === 0) delete data.hooks;
    cfg.writeJson(file, data);
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
  hooksFile,
  patchFiles,
  patchScan,
  PATCH_SCAN_CAP,
};
