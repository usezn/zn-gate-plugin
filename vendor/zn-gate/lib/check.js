'use strict';

/**
 * zn-gate check: shows, safely, that the zn hooks installed for each agent
 * stop a secret from being read and still let ordinary files through.
 *
 * It makes a temporary folder with a .env file that holds an obviously fake
 * key and a README.txt, and for each agent:
 *   - finds zn's user-level setup: the hook for the agent's read event, with
 *     a matcher that covers the read, or, for Claude Code, the zn-gate plugin
 *     listed in installed_plugins.json, not turned off, in the folder where
 *     Claude Code installs plugins, with a manifest that holds the exact
 *     PreToolUse hook the plugin ships, covering the read (nothing of the
 *     plugin runs before that is known);
 *   - asks zn what it decides for a read of .env (must block) and of
 *     README.txt (must be allowed);
 *   - runs the installed hook the same way the agent does, with the same two
 *     requests, so a hook that cannot start, or that blocks everything because
 *     part of zn is missing, is reported instead of passing.
 * An installed command is run only when it has the exact shape zn writes,
 * with Node.js and a real zn-gate runner, as node + runner without a shell,
 * in the temporary folder. A plugin's PreToolUse hook is run as the agent
 * runs that exact command. A zn-gate plugin for Cursor is only reported. Nothing leaves the machine, no agent is started,
 * no setting changes, and the folder is deleted at the end. Project-level
 * setups are reported but not run.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { nodeAdvice } = require('./node-support');

const FAKE_LINE = 'ZN_CHECK_EXAMPLE_KEY=zn-check-fake-value-not-a-real-key\n';
const HOOK_TIMEOUT_MS = 15000;
const PLUGIN_ID = 'zn-gate@usezn';
// The PreToolUse hooks the zn-gate plugins ship (plugins/zn-gate/hooks/hooks.json, plugins/zcode/hooks/hooks.json).
// A plugin counts only when its manifest holds this exact hook, and zn-gate check runs that command as the agent does.
const CLAUDE_PRE_COMMAND = '/bin/sh "${CLAUDE_PLUGIN_ROOT}/scripts/zn-node.sh" PreToolUse hook claude-code';
// The plugin's SessionStart command: run only to show the launcher's own message (for example a Node.js it refuses).
const CLAUDE_CHECK_COMMAND = '/bin/sh "${CLAUDE_PLUGIN_ROOT}/scripts/zn-node.sh" SessionStart check claude-code';
const ZCODE_PRE_WORDS = ['/bin/sh', '${ZCODE_PLUGIN_ROOT}/scripts/zn-hook.sh', 'PreToolUse'];

/* The zn-gate Claude Code plugin needs Node.js 20.19 or later; zn-gate itself runs on 18 and later.
   This is the one place that says which version; the messages below and in init are built from it. */
const PLUGIN_NODE_MIN = '20.19';
function pluginNodeOk(version) {
  const [major, minor] = String(version || process.versions.node).split('.').map((x) => parseInt(x, 10) || 0);
  // The plugin loads zn-gate through a loader constant that arrives in Node.js 20.12 and 21.7, and its locked
  // dependencies (@noble/*) declare Node.js 20.19 or later, so the floor on the 20 line is 20.19.
  return major > 21 || (major === 21 && minor >= 7) || (major === 20 && minor >= 19);
}
function pluginNodeMessage(version) {
  return 'the zn-gate plugin needs Node.js ' + PLUGIN_NODE_MIN + ' or later (you have ' + String(version || process.versions.node) + ')';
}

/* The plugin's hooks run `node` as Claude Code finds it on its PATH, which is not always the Node.js that runs
   zn-gate (npx, nvm, several installs). This finds that `node` and asks it for its version. Never throws:
   null means it could not be found or run. Same binary as this process: no need to start it.
   Only a node the plugin's hooks would start counts, with the rule of the plugin's zn-node.sh, applied before anything
   runs: an absolute PATH entry whose real path is in the folder check runs in (`cwd`), its project (the git work tree
   around it) or a node_modules folder is skipped, and so is a node that links into one. A project bin/ on the PATH
   (direnv) is never started by check; with no other node the version is unknown. */
function resolveHookNode(env, cwd) {
  try {
    const isWin = process.platform === 'win32';
    const norm = (f) => { let r = path.resolve(f); try { r = fs.realpathSync(r); } catch (err) { /* keep it */ } return isWin ? r.toLowerCase() : r; };
    // The shared rule (exe.findProgram): never a node in the project, its git work tree or node_modules, nor one that
    // links there; the home folder is never the project, so a Node.js from nvm or volta counts.
    const file = require('./exe').findProgram('node', env || process.env, cwd || process.cwd(), { strict: true });
    if (!file) return null;
    if (norm(file) === norm(process.execPath)) return { version: process.versions.node, path: file };
    const r = spawnSync(file, ['--version'], { encoding: 'utf8', timeout: 3000, windowsHide: true, shell: false });
    const m = /^v(\d+\.\d+\.\d+)/.exec(String(r.stdout || '').trim());
    return r.status === 0 && m ? { version: m[1], path: file } : null;
  } catch (err) {
    return null;
  }
}

/* What the plugin's hooks will run on: {ok, unknown, version, why}. opts: nodeVersion (this zn-gate's, injected in
   tests), hookNode (injected: a {version, path}, null for "unknown", or a function(env) returning one). Given only
   nodeVersion, the hooks are taken to run on that same Node.js. */
function pluginNodeStatus(opts = {}) {
  const zn = opts.nodeVersion || process.versions.node;
  let hook = opts.hookNode;
  if (typeof hook === 'function') hook = hook(opts.env || process.env);
  else if (hook === undefined) hook = opts.nodeVersion ? { version: opts.nodeVersion, path: null } : resolveHookNode(opts.env, opts.cwd);
  if (!hook || !hook.version) {
    return { ok: false, unknown: true, version: null, zn, why: 'zn-gate could not find or run the `node` that Claude Code will start the hooks of the plugin with (the first one on your PATH)' };
  }
  const same = !hook.path || hook.version === zn;
  const why = same ? 'you have ' + hook.version
    : 'Claude Code will run the hooks of the plugin with Node.js ' + hook.version + (hook.path ? ' (from ' + hook.path + ')' : '') + '; zn-gate itself runs on Node.js ' + zn;
  return { ok: pluginNodeOk(hook.version), unknown: false, version: hook.version, zn, why };
}
function pluginNodeProblem(st) {
  return st.unknown ? 'the zn-gate plugin could not be checked: ' + st.why
    : 'the zn-gate plugin needs Node.js ' + PLUGIN_NODE_MIN + ' or later (' + st.why + ')';
}

const AGENTS = [
  {
    id: 'claude-code', name: 'Claude Code', event: 'PreToolUse', tool: 'Read',
    fix: 'install the zn-gate plugin: `claude plugin marketplace add usezn/zn`, then `claude plugin install zn-gate@usezn`',
    file: (a, o) => a.settingsFile(o), project: (dir) => path.join(dir, '.claude', 'settings.json'),
    request: (dir, file) => ({ hook_event_name: 'PreToolUse', session_id: 'zn-check', cwd: dir, tool_name: 'Read', tool_input: { file_path: file } }),
  },
  {
    id: 'codex', name: 'Codex CLI', event: 'PreToolUse', tool: 'Bash',
    fix: 'run `zn hooks install codex` in your own terminal',
    file: (a, o) => a.hooksFile(o), project: (dir) => path.join(dir, '.codex', 'hooks.json'),
    request: (dir, file) => ({ hook_event_name: 'PreToolUse', session_id: 'zn-check', cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat ' + path.basename(file) } }),
  },
  {
    id: 'cursor', name: 'Cursor', event: 'beforeReadFile', tool: null,
    fix: 'run `zn hooks install cursor` in your own terminal',
    file: (a, o) => a.hooksFile(o), project: (dir) => path.join(dir, '.cursor', 'hooks.json'),
    request: (dir, file) => ({ hook_event_name: 'beforeReadFile', cwd: dir, file_path: file, content: 'x', workspace_roots: [dir] }),
  },
  {
    id: 'opencode', name: 'OpenCode', event: null, tool: null,
    fix: 'run `zn hooks install opencode` in your own terminal',
    file: (a, o) => a.pluginPath(o), project: (dir) => path.join(dir, '.opencode', 'plugins', 'zn-gate.js'),
    request: (dir, file) => ({ hook: 'tool.execute.before', tool: 'read', cwd: dir, args: { filePath: file } }),
  },
  {
    id: 'antigravity', name: 'Antigravity', event: 'PreToolUse', tool: 'view_file',
    fix: 'run `zn hooks install antigravity` in your own terminal',
    file: (a, o) => a.hooksFile(o), project: (dir) => path.join(dir, '.agents', 'hooks.json'),
    request: (dir, file) => ({ conversationId: 'zn-check', workspacePaths: [dir], toolCall: { name: 'view_file', args: { AbsolutePath: file } }, stepIdx: 0 }),
  },
  {
    id: 'copilot', name: 'Copilot CLI (experimental)', event: 'preToolUse', tool: 'view',
    fix: 'run `zn hooks install copilot` in your own terminal',
    file: (a, o) => a.hooksFile(o), project: (dir) => path.join(dir, '.github', 'hooks', 'zn-gate.json'),
    request: (dir, file) => ({ sessionId: 'zn-check', timestamp: 0, cwd: dir, toolName: 'view', toolArgs: { path: file } }),
  },
  {
    id: 'gemini', name: 'Gemini CLI', event: 'BeforeTool', tool: 'read_file',
    fix: 'run `zn hooks install gemini` in your own terminal',
    file: (a, o) => a.settingsFile(o), project: (dir) => path.join(dir, '.gemini', 'settings.json'),
    request: (dir, file) => ({ hook_event_name: 'BeforeTool', session_id: 'zn-check', cwd: dir, tool_name: 'read_file', tool_input: { file_path: file } }),
  },
  {
    // ZCode only runs the hooks of the user's config.json; the project path is where a project install would have been.
    id: 'zcode', name: 'ZCode', event: 'PreToolUse', tool: 'Read',
    fix: 'run `zn hooks install zcode` in your own terminal',
    file: (a, o) => a.configFile(o), project: (dir) => path.join(dir, '.zcode', 'config.json'),
    request: (dir, file) => ({ hook_event_name: 'PreToolUse', session_id: 'zn-check', cwd: dir, tool_name: 'Read', tool_input: { file_path: file } }),
  },
];

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  } catch (err) {
    return null;
  }
}

/* [{event, matcher, command}] from a hooks file: Claude Code and Codex use groups with a matcher, Cursor plain entries. */
function hookEntries(tree, agentId, opts = {}) {
  const out = [];
  // Claude Code, Codex and Cursor keep events under "hooks". Antigravity keeps named hooks at the top level
  // (and only there), each with its own "enabled" flag ("Set to false to disable the hook without removing it").
  // A hook that is turned off runs nothing: its entries are left out, or with `withDisabled` kept and flagged.
  const sets = [];
  if (agentId === 'antigravity') {
    for (const [name, v] of Object.entries(tree && typeof tree === 'object' ? tree : {})) {
      if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
      if (v.enabled !== false) sets.push({ hooks: v, name, disabled: false });
      else if (opts.withDisabled) sets.push({ hooks: v, name, disabled: true });
    }
  } else if (agentId === 'zcode') {
    // ZCode keeps events under hooks.events, and a hook is a "process" (program + args) or a "command" (shell string).
    sets.push({ hooks: tree && tree.hooks && typeof tree.hooks.events === 'object' ? tree.hooks.events : {}, disabled: false });
  } else {
    sets.push({ hooks: tree && typeof tree.hooks === 'object' ? tree.hooks : {}, disabled: false });
  }
  for (const { hooks, name, disabled } of sets) {
    for (const [event, list] of Object.entries(hooks || {})) {
      if (event === 'enabled') continue;
      for (const g of Array.isArray(list) ? list : []) {
        if (!g || typeof g !== 'object') continue;
        const extra = agentId === 'antigravity' ? { name, disabled } : {};
        if (typeof g.command === 'string') out.push({ event, matcher: g.matcher, command: g.command, onFailure: g.onFailure, async: g.async, ...extra });
        // GitHub Copilot CLI keeps the shell command in "bash" (and "powershell"), next to an optional matcher.
        // On Windows Copilot CLI runs "powershell" instead, so that is the command to read there.
        const copilotCmd = agentId !== 'copilot' ? null : process.platform === 'win32' && typeof g.powershell === 'string' ? g.powershell : g.bash;
        if (typeof copilotCmd === 'string') out.push({ event, matcher: g.matcher, command: copilotCmd });
        for (const h of Array.isArray(g.hooks) ? g.hooks : []) {
          // Codex on Windows runs commandWindows (command_windows in TOML), not command.
          const win = agentId === 'codex' && process.platform === 'win32' && h ? (typeof h.commandWindows === 'string' ? h.commandWindows : h.command_windows) : null;
          const text = agentId === 'zcode' ? require('./agents/zcode').commandText(h) : typeof win === 'string' ? win : h && typeof h.command === 'string' ? h.command : '';
          if (text) out.push({ event, matcher: g.matcher, command: text, onFailure: h.onFailure, async: h.async, ...extra });
        }
      }
    }
  }
  return out;
}

function matcherCovers(matcher, tool) {
  if (!tool || matcher === undefined || matcher === null || matcher === '' || matcher === '*') return true;
  try {
    return new RegExp('^(?:' + matcher + ')$').test(tool);
  } catch (err) {
    return String(matcher).split('|').includes(tool);
  }
}

/* Enabled Antigravity hooks other than zn's that handle PreToolUse, in the given hooks files: [{name, file}]. Never throws. */
function antigravityOtherHooks(files) {
  const out = [];
  const seen = new Set();
  for (const file of files) {
    const key = path.resolve(file);
    if (seen.has(key)) continue;
    seen.add(key);
    // A project folder can be anyone's repository: read only a regular file, and only so much of it.
    const text = require('./audit')._internal.readBounded(file, 256 * 1024, file === files[0]).text;
    let tree = null;
    try { tree = text ? JSON.parse(text.replace(/^\uFEFF/, '')) : null; } catch (_) { tree = null; }
    const byName = new Map();
    for (const e of hookEntries(tree, 'antigravity')) {
      if (e.event !== 'PreToolUse' || parseCommand(e.command, 'antigravity')) continue;
      if (!byName.has(e.name)) byName.set(e.name, { name: e.name, file });
    }
    out.push(...byName.values());
  }
  return out;
}

/* A zn hook command: {node, runner} (run directly), {onPath} (`zn hook <agent>`) or null. */
function parseCommand(command, agentId) {
  const { _internal: audit } = require('./audit');
  const launcher = require('./agents/launcher');
  const c = require('./shell-quote').readableWindowsCommand(String(command).trim());
  // zn's launcher script (lib/agents/launcher.js): '<dir>/zn-hook-<agent>.sh' <Event>. It names the Node.js and
  // runner it was installed with in ZN_NODE=... and ZN_RUNNER=... lines.
  // Antigravity runs the command split on spaces with no shell, so zn writes the path unquoted there (an older
  // zn-gate wrote it quoted, which that agent cannot start: `quoted` makes check ask for a reinstall).
  const lm = new RegExp(agentId === 'antigravity' ? "^('?)(" + audit.SAFE_ABS + '/zn-hook-' + agentId + "\\.sh)\\1 ([A-Za-z]+)$" : "^()'(" + audit.SAFE_ABS + '/zn-hook-' + agentId + "\\.sh)' ([A-Za-z]+)$").exec(c);
  if (lm) {
    const quoted = lm[1] === "'" || agentId !== 'antigravity';
    lm.splice(1, 1);
    lm.quoted = quoted;
    lm.raw = c;
    let text = '';
    const extra = agentId === 'antigravity' ? { quoted: lm.quoted, raw: lm.raw } : {};
    try { text = fs.readFileSync(lm[1], 'utf8'); } catch (err) { return { launcher: lm[1], event: lm[2], unreadable: true, ...extra }; }
    const n = new RegExp("^ZN_NODE='(" + audit.SAFE_ABS + ")'$", 'm').exec(text);
    const r = new RegExp("^ZN_RUNNER='(" + audit.SAFE_ABS + ")'$", 'm').exec(text);
    if (!n || !r) return { launcher: lm[1], event: lm[2], unreadable: true, ...extra };
    return { launcher: lm[1], event: lm[2], node: n[1], runner: r[1], ...extra };
  }
  // On Windows, Cursor and Gemini CLI run the same three steps as an encoded PowerShell script (launcher.windowsScript).
  const ws = require('./shell-quote').windowsCommandScript(c);
  if (ws) {
    // Both the current script and the one written by earlier versions (no progress line, unconditional exit).
    // the current script (no cmdlet: zf and [System.IO.File]::Exists) is read as the older Test-Path form below
    // The ack file of the current script (zk, zx, zd) is read as the plain exit of the older one.
    const wsOld = ws.replace(/\$za = \$null;.*?(?=function zf\()/s, '')
      .replace(/if \(\(\$LASTEXITCODE -eq 0 -and \(zk\)\) -or \$LASTEXITCODE -eq 2\) \{ zx (0|\$LASTEXITCODE) \}/g, 'if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2) { exit $1 }')
      .replace(/if \(\(\$rc -eq 0 -and \(zk\)\) -or \$rc -eq 2\) \{ zx (0|\$rc) \}/g, 'if ($rc -eq 0 -or $rc -eq 2) { exit $1 }')
      .replace(/zd; /g, '')
      .replace(/(?:\$env:NoDefaultCurrentDirectoryInExePath = '1'; \$env:PATH = [^\n]*?-join ';'; )?function zf\(\$x\) \{[^\n]*?return \$null \}; /, '')
      // ZCode's launcher runs the hook as a child with a deadline (zr, launcher.windowsScript with deadlineS): read it as the plain `& node runner agent; if (...) { exit ... }` step.
      .replace(/function zr\(\$f, \$a\) \{[^\n]*?return \$rc \}; /, '')
      .replace(/\$rc = zr '"([^'"]+)"' '"([^'"]+)" ([a-z-]+)'; if \(\$rc -eq 0 -or \$rc -eq 2\) \{ exit \$rc \}/, (m0, n, r, a) => "& '" + n + "' '" + r + "' " + a + '; if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2) { exit $LASTEXITCODE }')
      .replace(/\[System\.IO\.File\]::Exists\('([^']+)'\)/g, "(Test-Path -LiteralPath '$1')");
    const wm = /^(?:\$ProgressPreference='SilentlyContinue'; \$zt=0; )?if \(\(Test-Path -LiteralPath '([^']+)'\) -and \(Test-Path -LiteralPath '([^']+)'\)\) \{ (?:\$zt=1; )?& '[^']+' '[^']+' ([a-z-]+); (?:if \(\$LASTEXITCODE -eq 0 -or \$LASTEXITCODE -eq 2\) \{ exit (?:\$LASTEXITCODE|0) \}|exit \$LASTEXITCODE) \}; .* # zn hook ([a-z-]+)$/s.exec(wsOld);
    // winScript is the PowerShell text itself: c may be its readable -Command form, which is not base64.
    if (wm && wm[3] === agentId && wm[4] === agentId) return { winScript: ws, node: wm[1], runner: wm[2] };
  }
  // The project hook (shared file): `zn` on the PATH inside zn's own guard (launcher.projectShCommand / projectWindowsScript).
  // Only the exact guard this version writes counts as guarded; a guard-looking command that differs is reported as modified.
  if (launcher.isProjectGuardExact(c, agentId) || (ws && launcher.isProjectWindowsScriptExact(ws, agentId))) return { onPath: true, guarded: true };
  if (launcher.isProjectGuard(c, agentId) || (ws && launcher.isProjectWindowsScript(ws, agentId))) return { onPath: true, guarded: true, modified: true };
  if (!c.endsWith(' ' + agentId) && !c.endsWith(' ' + agentId + '"')) return null;
  if (audit.OUR_HOOKS[0].test(c)) return { onPath: true };
  const quoted = new RegExp("^'(" + audit.SAFE_ABS + ")' '(" + audit.SAFE_ABS + "/zn-gate/lib/hooks/runner\\.js)' " + agentId + '$');
  for (const re of [audit.OUR_HOOKS[1], audit.OUR_HOOKS[2], quoted]) {
    const m = re.exec(c);
    if (!m) continue;
    let node = null;
    let runner = null;
    try {
      node = fs.realpathSync(m[1]);
      runner = fs.realpathSync(m[2]);
    } catch (err) {
      return { node: m[1], runner: m[2], missing: true };
    }
    if (!/^node(?:js)?(?:\.exe)?$/i.test(path.basename(node)) || !audit.znGateFile(runner, 'lib/hooks/runner.js')) return null;
    return { node, runner };
  }
  return null;
}

/*
 * The Git Bash that Claude Code runs hooks with on Windows: CLAUDE_CODE_GIT_BASH_PATH when it names a file (the setting
 * Claude Code documents), else bin\bash.exe of the Git for Windows whose git is on an absolute PATH entry (a default
 * install puts only Git\cmd on the PATH), else bash or sh from the absolute PATH entries. Null when there is none.
 */
function gitBash(env) {
  const exe = require('./exe');
  const given = (env || {}).CLAUDE_CODE_GIT_BASH_PATH;
  if (typeof given === 'string' && path.isAbsolute(given)) {
    try { if (fs.statSync(given).isFile()) return given; } catch (err) { /* not there */ }
  }
  const git = exe.findProgram('git', env);
  if (git) {
    const bash = path.resolve(path.dirname(git), '..', 'bin', process.platform === 'win32' ? 'bash.exe' : 'bash');
    try { if (fs.statSync(bash).isFile()) return bash; } catch (err) { /* not a Git for Windows layout */ }
  }
  return exe.findProgram('bash', env) || exe.findProgram('sh', env);
}

function decisionOf(stdout, status) {
  if (status === 2) return 'deny';
  const o = String(stdout || '');
  if (/"permissionDecision"\s*:\s*"deny"|"decision"\s*:\s*"(?:deny|block)"|"permission"\s*:\s*"deny"|"continue"\s*:\s*false/.test(o)) return 'deny';
  return 'allow';
}

function spawnHook(file, args, input, env, cwd, timeout = HOOK_TIMEOUT_MS) {
  const r = spawnSync(file, args, {
    input: JSON.stringify(input), encoding: 'utf8', timeout, cwd,
    env: { ...process.env, ZN_STATS: 'off', ...env }, windowsHide: true,
  });
  // A hook that answers and exits before reading all its input makes the write fail with EPIPE although it ran: its status and output are the answer.
  const ranAndExited = r.error && r.error.code === 'EPIPE' && typeof r.status === 'number';
  if (r.error && !ranAndExited) return { ran: false, why: r.error.code || r.error.message };
  return { ran: true, decision: decisionOf(r.stdout, r.status), stdout: r.stdout, status: r.status };
}

/* Folders of the zn-gate Claude Code plugin listed in installed_plugins.json. */
function claudePlugin(home, env) {
  const cc = require('./agents').getAdapter('claude-code');
  const dir = cc.configDir({ home, env });
  const listed = readJson(path.join(dir, 'plugins', 'installed_plugins.json'));
  const entries = listed && listed.plugins && listed.plugins[PLUGIN_ID];
  const roots = (Array.isArray(entries) ? entries : entries ? [entries] : [])
    .map((e) => e && e.installPath).filter((p) => typeof p === 'string' && fs.existsSync(path.join(p, 'scripts', 'zn-launch.js')));
  const settings = readJson(cc.settingsFile({ home, env })) || {};
  const off = settings.enabledPlugins && settings.enabledPlugins[PLUGIN_ID] === false;
  return { root: roots[0] || null, off };
}

/* What each hook of a plugin's manifest (hooks/hooks.json under `root`) starts, as the host starts it: ZCode runs a
   "process" hook's command directly with its args, and Claude Code runs a "command" hook through a shell. Only the form
   zn's plugins use counts as safe: a system shell by its full path (SYSTEM_SHELLS), with no option, no NAME=value in
   front, no pattern the shell expands and nothing else on the shell line, whose first operand is a script inside the
   plugin folder (`${<rootVar>}/...`) that really is a file there (its real path, links resolved, is inside the real
   path of the plugin folder).
   Anything else may look a program up by name or read a script from the folder the agent runs in, the project, before
   zn's own code can clean the PATH, so a relative or empty PATH entry or a planted file could skip zn. On Windows,
   Claude Code runs a command hook with bash only when the hook says "shell": "bash"; otherwise /bin/sh is no full path.
   Returns {hooks: [{event, file, args, byName, ...}], bare: <first hook with byName set> | null}, or null when the
   manifest cannot be read. byName says what makes the hook unsafe. `command`, `words` (before the plugin root is filled
   in), `shell`, `onFailure` and `timeout` are kept as written, for the exact-hook rules below. */
function pluginManifest(root, rootVar, platform = process.platform) {
  const data = readJson(path.join(root, 'hooks', 'hooks.json'));
  if (!data || typeof data.hooks !== 'object' || data.hooks === null) return null;
  const fill = (v) => String(v).split('${' + rootVar + '}').join(root);
  const hooks = [];
  for (const [event, groups] of Object.entries(data.hooks)) {
    for (const g of Array.isArray(groups) ? groups : []) {
      for (const h of (g && Array.isArray(g.hooks)) ? g.hooks : []) {
        if (!h || typeof h.command !== 'string') continue;
        let words;
        let byName = null;
        if (h.type === 'process') {
          words = [h.command, ...(Array.isArray(h.args) ? h.args.map(String) : [])];
        } else {
          byName = shellLineProblem(h.command);
          words = shellWords(h.command);
        }
        if (!words.length) continue;
        if (!byName) byName = unsafeStart(words, rootVar, h.type !== 'process');
        if (!byName) byName = scriptOutside(root, fill(words[1]));
        if (!byName && h.type !== 'process' && platform === 'win32' && h.shell !== 'bash') {
          byName = 'the default Windows shell of Claude Code (no "shell": "bash"), where /bin/sh is not a full path';
        }
        // What decides whether the host runs the hook at all, and waits for its answer, for the PreToolUse check below.
        const off = h.enabled === false || h.disabled === true || g.enabled === false || g.disabled === true;
        hooks.push({ event, file: fill(words[0]), args: words.slice(1).map(fill), byName, type: h.type, matcher: g.matcher, async: h.async === true || h.async === 'true' || Boolean(h.asyncRewake), off,
          command: h.command, words, shell: h.shell, onFailure: h.onFailure, timeout: h.timeout });
      }
    }
  }
  return { hooks, bare: hooks.find((h) => h.byName) || null };
}

/* Real path of `p`, or null when it is not there. */
function realOrNull(p) {
  try { return fs.realpathSync(p); } catch (_) { return null; }
}

/* Whether `p` is `dir` itself (when `orSame`) or a path inside it. */
function isInside(p, dir, orSame) {
  const fold = (s) => (process.platform === 'win32' ? s.toLowerCase() : s);
  const rel = path.relative(fold(dir), fold(p));
  if (rel === '') return Boolean(orSame);
  return rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel);
}

/* The folder of the repository `cwd` is in (the nearest one above it with .git), else `cwd` itself. */
function projectRootOf(cwd) {
  let cur = path.resolve(cwd);
  for (;;) {
    if (fs.existsSync(path.join(cur, '.git'))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) return path.resolve(cwd);
    cur = parent;
  }
}

/* Why the plugin folder `root` from installed_plugins.json is not one zn-gate check may start code from, or ''.
   installed_plugins.json is a plain file that can name any folder, so its launcher is run only when the real path of
   the folder is inside a folder where Claude Code itself installs plugins (plugins under its configuration folder, or
   CLAUDE_CODE_PLUGIN_CACHE_DIR when set), is not inside the project check runs in (a repository could hold a plugin
   folder of its own), and its launcher really is a file inside it. The home folder, or a folder above it, is not
   taken as a project (the configuration folder is inside it), nor is the configuration folder or one inside it. */
function claudePluginRootProblem(root, ctx) {
  const cc = require('./agents').getAdapter('claude-code');
  const env = ctx.env || {};
  const config = cc.configDir({ home: ctx.home, env });
  const places = [path.join(config, 'plugins')];
  if (typeof env.CLAUDE_CODE_PLUGIN_CACHE_DIR === 'string' && path.isAbsolute(env.CLAUDE_CODE_PLUGIN_CACHE_DIR)) places.push(env.CLAUDE_CODE_PLUGIN_CACHE_DIR);
  const real = realOrNull(root);
  if (!real) return 'the zn-gate plugin folder listed in installed_plugins.json (' + root + ') is missing';
  if (!places.map(realOrNull).some((p) => p && isInside(real, p, false))) {
    return 'the zn-gate plugin listed in installed_plugins.json is in ' + root + ', which is not inside the folder where Claude Code installs plugins (' + places.join(' or ') + '), so zn-gate check does not run it';
  }
  const home = realOrNull(ctx.home) || path.resolve(ctx.home);
  const realConfig = realOrNull(config);
  for (const dir of new Set([ctx.cwd, projectRootOf(ctx.cwd)])) {
    const proj = realOrNull(dir);
    // Run from the configuration folder itself (some keep it in git), that folder is not a project either.
    if (!proj || isInside(home, proj, true) || (realConfig && isInside(proj, realConfig, true))) continue;
    if (isInside(real, proj, true)) return 'the zn-gate plugin listed in installed_plugins.json is in ' + root + ', inside this project (' + dir + '), so zn-gate check does not run it';
  }
  if (scriptOutside(real, path.join(real, 'scripts', 'zn-launch.js'))) return 'the launcher of the zn-gate plugin (' + path.join(root, 'scripts', 'zn-launch.js') + ') is not a file inside the plugin folder';
  return '';
}

const NO_ON_FAILURE = 'does not have "onFailure": "block"';

/* The PreToolUse hook of the plugin's manifest that checks a call of `tool` before Claude Code runs it: {hook} when
   there is one, else {problem}. Only the hook the plugin ships counts: a "command" hook whose command is exactly
   CLAUDE_PRE_COMMAND, with "shell": "bash" and "onFailure": "block" (a hook that cannot run then blocks the call),
   not turned off, not run in the background (Claude Code does not wait for the answer of an async hook, so it cannot
   block), with a matcher that covers `tool`. Any other command, even one that runs another script of the plugin,
   may answer nothing, and Claude Code would then run the call unchecked. */
function claudePreHook(manifest, file, tool) {
  const pre = manifest.hooks.filter((h) => h.event === 'PreToolUse');
  const why = (h) => (h.byName ? null : h.type !== 'command' ? 'is not a "command" hook' : h.off ? 'is turned off'
    : h.async ? 'runs in the background (async), where Claude Code does not wait for its answer'
      : !matcherCovers(h.matcher, tool) ? 'has a matcher that does not cover ' + tool
        : h.command !== CLAUDE_PRE_COMMAND ? 'runs `' + oneLine(h.command, 200) + '`, which is not the hook the zn-gate plugin ships (`' + CLAUDE_PRE_COMMAND + '`)'
          : h.shell !== 'bash' ? 'does not ask for bash ("shell": "bash"), unlike the hook the zn-gate plugin ships'
            : h.onFailure !== 'block' ? NO_ON_FAILURE : null);
  const hook = pre.find((h) => !h.byName && !why(h));
  if (hook) return { hook, problem: '' };
  const first = pre.map(why).find(Boolean);
  if (!first) return { hook: null, problem: 'the zn-gate plugin has no PreToolUse hook in ' + file + ', so Claude Code runs no zn check before tool calls' };
  return { hook: null, problem: 'the PreToolUse hook of the zn-gate plugin in ' + file + ' ' + first +
    (first === NO_ON_FAILURE ? ', so Claude Code runs a call unchecked when the hook cannot run' : ', so Claude Code runs no zn check before tool calls') };
}

/* Why no hook of the plugin's manifest checks a call of `tool` before Claude Code runs it, or '' (claudePreHook). */
function claudePreToolProblem(manifest, file, tool) {
  return claudePreHook(manifest, file, tool).problem;
}

/* How Claude Code starts one of the plugin's published hook commands (`command`, CLAUDE_PRE_COMMAND or
   CLAUDE_CHECK_COMMAND), for the plugin folder `root` that was checked: bash runs the line, which starts /bin/sh on the
   plugin's scripts/zn-node.sh with the rest of the line as its arguments. Elsewhere than Windows that is /bin/sh itself,
   started here by that full path with the same arguments (no bash is looked up); on Windows it is Git Bash given the
   line, as Claude Code does ("shell": "bash"). CLAUDE_PLUGIN_ROOT is the plugin folder, CLAUDE_PROJECT_DIR the project
   check runs in, its repository root when there is one (zn-node.sh skips PATH entries in it, so a project bin/ on the
   PATH is skipped also when check runs from a subfolder), and PATH the one check was given. The timeout is the hook's
   (`timeoutS`, at most 15 seconds). Null when there is no Git Bash on Windows. */
function claudePluginRun(command, root, ctx, timeoutS, platform = process.platform) {
  const env = { CLAUDE_PLUGIN_ROOT: root, CLAUDE_PROJECT_DIR: projectRootOf(ctx.cwd) };
  if (ctx.env && typeof ctx.env.PATH === 'string') env.PATH = ctx.env.PATH;
  const timeout = typeof timeoutS === 'number' && timeoutS > 0 ? Math.min(HOOK_TIMEOUT_MS, timeoutS * 1000) : HOOK_TIMEOUT_MS;
  if (platform === 'win32') {
    const bash = gitBash(ctx.env || process.env);
    return bash ? { file: bash, args: ['-c', command], env, timeout } : null;
  }
  const words = shellWords(command).map((w) => w.split('${CLAUDE_PLUGIN_ROOT}').join(root));
  return { file: words[0], args: words.slice(1), env, timeout };
}

/* The folder of a zn-gate plugin for Cursor, or null. Cursor documents ~/.cursor/plugins/local/<plugin> for plugins
   added by hand and does not say where it keeps the ones it installs, so every folder under ~/.cursor/plugins (a few
   levels deep, links not followed) is looked at. A folder counts when its .cursor-plugin/plugin.json is named
   "zn-gate" and points to usezn's repository. Only that file is read (a regular file, with a size limit); nothing of
   the plugin is run. */
function cursorZnPlugin(home) {
  const audit = require('./audit');
  const queue = [[path.join(home, '.cursor', 'plugins'), 0]];
  let seen = 0;
  while (queue.length && seen < 2000) {
    const [dir, depth] = queue.shift();
    seen++;
    const text = audit._internal.readBounded(path.join(dir, '.cursor-plugin', 'plugin.json'), 64 * 1024, false).text;
    let m = null;
    try { m = text ? JSON.parse(text.replace(/^\uFEFF/, '')) : null; } catch (_) { m = null; }
    const ours = (u) => typeof u === 'string' && /^https:\/\/github\.com\/usezn\/zn(?:[/#?]|$)/.test(u);
    if (m && m.name === 'zn-gate' && (ours(m.repository) || ours(m.homepage))) return dir;
    if (depth >= 5) continue;
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of ents) if (e.isDirectory() && e.name !== 'node_modules' && e.name !== '.git') queue.push([path.join(dir, e.name), depth + 1]);
  }
  return null;
}

const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
// The only programs a plugin hook may start: the system shells by their usual full paths (not any file of that name).
const SYSTEM_SHELLS = new Set(['/bin/sh', '/usr/bin/sh', '/bin/bash', '/usr/bin/bash', '/bin/dash', '/usr/bin/dash']);

/* Why the script a safe-looking hook runs is not a file inside the plugin folder (a link out of it, a folder, missing),
   or null. Both paths are resolved with their links, so a link inside the plugin to a file elsewhere does not pass. */
function scriptOutside(root, script) {
  try {
    const realRoot = fs.realpathSync(root);
    const real = fs.realpathSync(script);
    if (real.startsWith(realRoot + path.sep) && fs.statSync(real).isFile()) return null;
    return 'a script that is not a file inside the plugin folder (' + script + ' is ' + real + ')';
  } catch (_) {
    return 'a script that is not in the plugin folder (' + script + ' is missing)';
  }
}

/* Why the words of a hook (before the plugin root is filled in) are not the safe form, or null when they are. The
   specific reasons (a name, env, a shell given -c) come first because they tell the user what is wrong. */
function unsafeStart(words, rootVar, shell) {
  const [prog, first] = words;
  if (shell && ASSIGN.test(prog)) return 'a NAME=value in front of the program (' + prog.split('=')[0] + '), which can make the shell read other code';
  if (!prog.startsWith('/') || /[$`~]/.test(prog)) return '`' + prog + '` by name';
  const glob = words.find((w) => /[*?[]/.test(w));
  if (glob !== undefined) return 'a pattern the shell or the host expands (`' + glob + '`), so what runs is not what the manifest names';
  const name = prog.slice(prog.lastIndexOf('/') + 1);
  if (name === 'env') return '`env`, which looks the program it starts up by name';
  // Code given inline (sh -c, bash -o pipefail -c, node -e, python3 -c): a new command line or program, not a script.
  const inline = words.slice(1).find((w) => /^[-+][A-Za-z]*c[A-Za-z]*$/.test(w) || (/^(node|perl|ruby)/.test(name) && /^-[A-Za-z]*e$/.test(w)));
  if (inline) return 'code given inline (`' + name + ' ' + inline + '`), which looks its programs up by name';
  const prefix = '${' + rootVar + '}/';
  const script = typeof first === 'string' && first.startsWith(prefix) && !/[$`]/.test(first.slice(prefix.length)) &&
    !first.slice(prefix.length).split('/').some((seg) => seg === '..' || seg === '.' || seg === '');
  if (!SYSTEM_SHELLS.has(prog) || !script) {
    return '`' + words.slice(0, 2).join(' ') + '`, which is not a system shell running a script inside the plugin folder';
  }
  return null;
}

/* Why a shell command line is not a plain list of words that zn-gate check reads exactly as the shell does, or null.
   A backslash, a single quote or a control character (the shell and shellWords could split or unescape it
   differently, e.g. "\/bin/sh" or "\${ROOT}"), an unquoted ; & | < > or newline, a command substitution ($( or a
   backquote, also inside double quotes), or a quote that is never closed. */
function shellLineProblem(line) {
  if (/[\\'\x00-\x1f\x7f]/.test(line)) {
    return 'a shell command line with a backslash, a single quote or a control character, which zn-gate check does not read the way the shell does';
  }
  let q = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '`' || (c === '$' && line[i + 1] === '(')) return 'a shell command line (with a command substitution), which looks its programs up by name';
    if (q === '"') { if (c === '"') q = ''; continue; }
    if (c === '"') { q = c; continue; }
    if (';&|<>'.includes(c)) return 'a shell command line (with ; & | < >), which looks its programs up by name';
  }
  return q ? 'a shell command line with a quote that is never closed, so the hook does not start' : null;
}

/* The words of a simple shell command line: spaces split them, and single or double quotes keep a word together. */
function shellWords(line) {
  const out = [];
  const re = /\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^\s"']+))/gy;
  let m;
  let cur = null;
  let last = 0;
  while ((m = re.exec(line)) !== null && m[0].length) {
    const glued = cur !== null && m.index === last && !/^\s/.test(m[0]);
    const part = m[1] !== undefined ? m[1].replace(/\\(.)/g, '$1') : m[2] !== undefined ? m[2] : m[3];
    if (glued) cur += part; else { if (cur !== null) out.push(cur); cur = part; }
    last = re.lastIndex;
  }
  if (cur !== null) out.push(cur);
  return out;
}

/* The problem of a manifest hook that starts its program by name. */
function bareProgramProblem(hook) {
  if (/does not start$/.test(hook.byName)) return 'the zn-gate plugin starts its ' + hook.event + ' hook with ' + hook.byName;
  return 'the zn-gate plugin starts its ' + hook.event + ' hook with ' + hook.byName +
    ', so a program or script in a relative or empty PATH entry, or in the folder the agent runs in, could run in its place and skip zn';
}

/* zn's hooks in the agent's managed configuration: {files, entries} | null. Never throws. */
function managedFor(agentId, ctx) {
  try {
    const opts = agentId === 'claude-code' ? ctx.claudePolicy : agentId === 'codex' ? ctx.codexPolicy : agentId === 'cursor' ? ctx.cursorPolicy : null;
    if (opts === null) return null;
    return require('./agents/managed-policy').managedInstall(agentId, { ...(opts || {}), env: ctx.env });
  } catch (_) {
    return null;
  }
}

/* Hook policy warnings for Claude Code (managed settings, disableAllHooks), as `zn-gate status` shows. */
function claudePolicy(home, env, opts) {
  try {
    const cc = require('./agents').getAdapter('claude-code');
    const w = require('./agents/managed-policy').claudeCodePolicyWarnings({ ...(opts || {}), userSettings: [cc.settingsFile({ home, env })], mcp: false });
    return w.filter((x) => /hooks/i.test(x));
  } catch (err) {
    return [];
  }
}

/* Codex hooks with `async` set (true, or the string "true" from TOML) run in the background: they cannot block or change anything. */
function isBackground(e) {
  return e.async === true || e.async === 'true';
}

/* The first file that sets one of zn's Codex hooks to run in the background: the Codex home's hooks.json and config.toml. */
function codexBackgroundFile(codexHome, hooksFile) {
  const trees = [[hooksFile, readJson(hooksFile)]];
  try {
    trees.push([path.join(codexHome, 'config.toml'), require('./audit/parse').parseToml(fs.readFileSync(path.join(codexHome, 'config.toml'), 'utf8')).data]);
  } catch (_) { /* no config.toml, or one zn cannot read: nothing to say here */ }
  for (const [file, tree] of trees) {
    const hit = hookEntries(tree, 'codex').find((e) => isBackground(e) && parseCommand(e.command, 'codex'));
    if (hit) return { file, event: hit.event };
  }
  return null;
}

/* Codex keeps a per-hook switch in config.toml: [hooks.state."<hooks file>:<event>:<group>:<hook>"] enabled = false.
   The key is the file that declares the hook, the event in snake case, and the 0-based position of the group and of the hook in it. */
function samePath(a, b) {
  const x = path.resolve(String(a));
  const y = path.resolve(String(b));
  return process.platform === 'win32' ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/* The first of zn's Codex hooks (in the files given) that the user's config.toml switches off with hooks.state; null if none. */
function codexHookSwitchedOff(codexHome, files) {
  let state;
  try {
    const data = require('./audit/parse').parseToml(fs.readFileSync(path.join(codexHome, 'config.toml'), 'utf8')).data;
    state = data && data.hooks && data.hooks.state;
  } catch (_) { return null; /* no config.toml, or one zn cannot read: nothing to say here */ }
  if (!state || typeof state !== 'object') return null;
  const { isOurs } = require('./agents/config-file');
  for (const [key, st] of Object.entries(state)) {
    if (!st || typeof st !== 'object' || (st.enabled !== false && st.enabled !== 'false')) continue;
    const m = /^(.*):([a-z_]+):(\d+):(\d+)$/.exec(key.trim());
    if (!m) continue;
    const src = files.find((f) => samePath(f, m[1]));
    if (!src) continue;
    const tree = src.endsWith('.toml') ? (() => { try { return require('./audit/parse').parseToml(fs.readFileSync(src, 'utf8')).data; } catch (_) { return null; } })() : readJson(src);
    const hooks = tree && typeof tree.hooks === 'object' && tree.hooks ? tree.hooks : {};
    const event = Object.keys(hooks).find((e) => e.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase() === m[2]);
    const group = event && Array.isArray(hooks[event]) ? hooks[event][Number(m[3])] : null;
    const hook = group && Array.isArray(group.hooks) ? group.hooks[Number(m[4])] : null;
    if (hook && isOurs(hook.command, 'codex')) return { file: path.join(codexHome, 'config.toml'), event };
  }
  return null;
}

function oneLine(s, n) {
  return String(s || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
}

/* A sentence without its final full stop, to quote it inside another one. */
function bare(s) {
  return String(s || '').replace(/[\s.]+$/, '');
}

const RULES_FIX = 'install zn-gate again: run `npm install -g zn-gate` in your own terminal, then run `zn-gate check` again';
const PLUGIN_REINSTALL = 'install the plugin again: run `claude plugin uninstall zn-gate@usezn`, then `claude plugin install zn-gate@usezn`, in your own terminal, then run `zn-gate check` again';
const REINSTALL = (id) => 'install zn-gate again for the Node.js you use now: run `npm install -g zn-gate`, then `zn hooks install ' + id + '`, in your own terminal';

/* Absolute path of `name`, searched only in absolute PATH entries; null when there is none. */
function onAbsPath(name, env) {
  const absPath = require('./exe').absolutePath((env || process.env).PATH || '', process.platform, { env: env || process.env });
  const found = require('./exe').whichSync(process.platform === 'win32' ? name + (name === 'zn' ? '.cmd' : '.exe') : name, absPath);
  return found ? path.resolve(found) : null;
}

/* Absolute path of the `zn` command, searched only in absolute PATH entries; null when there is none. */
function znOnPath(env) {
  // Only absolute PATH entries: a relative one (node_modules/.bin, .) depends on the folder check runs from.
  const absPath = require('./exe').absolutePath((env || process.env).PATH || '', process.platform, { env: env || process.env });
  const found = require('./exe').whichSync(process.platform === 'win32' ? 'zn.cmd' : 'zn', absPath);
  return found ? path.resolve(found) : null;
}

/*
 * zn's own hooks in the user's hooks file (`zn hooks install <agent>`), not run yet:
 * {installed, problem, fix, live, notes}. `live` is {file, args, env} when the read hook can be run as the agent runs it.
 */
function cliHooks(spec, ctx, userFile, given) {
  const out = { installed: false, problem: '', fix: '', live: null, notes: [] };
  // `given`: hook entries already read from the managed configuration instead of the user's hooks file.
  const all = (given || hookEntries(readJson(userFile), spec.id, { withDisabled: true })).filter((e) => parseCommand(e.command, spec.id));
  const entries = all.filter((e) => !e.disabled);
  out.installed = all.length > 0;
  if (!out.installed) return out;
  if (!entries.length) {
    // Antigravity skips a named hook with "enabled": false and says nothing, so zn's hook protects nothing.
    out.problem = 'zn\'s hook is turned off in ' + userFile + ' ("enabled": false on the hook ' + JSON.stringify(all[0].name) + '), so Antigravity skips it and zn does not protect Antigravity';
    out.fix = 'run `zn hooks install antigravity` in your own terminal (it turns the hook back on), or set "enabled" to true on that hook, then run `zn-gate check` again';
    return out;
  }
  // Set up with `zn hooks install`, so that is also how to repair it (not the plugin: both would run).
  out.fix = 'run `zn hooks install ' + spec.id + '` in your own terminal';
  const read = entries.find((e) => e.event === spec.event && matcherCovers(e.matcher, spec.tool));
  if (!read) {
    out.problem = 'zn\'s hooks are there, but not the one that checks reading files (' + spec.event + ')';
    return out;
  }
  const cmd = parseCommand(read.command, spec.id);
  // zn-gate 1.13 and earlier started powershell.exe by name: cmd.exe (Codex) and the process start of several agents look in
  // the current folder first, so a powershell.exe in the project could run instead. Only a reinstall writes the full path.
  if (/^powershell\.exe /i.test(String(read.command).trim())) {
    out.problem = 'its hook command starts powershell.exe by name (written by an older zn-gate), so a powershell.exe in the project folder could run in its place';
    out.fix = REINSTALL(spec.id);
    return out;
  }
  if (spec.id === 'antigravity' && process.platform !== 'win32') {
    // Antigravity splits the command on spaces and runs it with no shell: any quote stays in a name, and a path with a
    // space is cut in two. Run the same split instead of trusting how zn would read the command.
    const first = String(read.command).trim().split(' ')[0];
    const abs = path.isAbsolute(first) && !(() => { try { return fs.statSync(first).isFile(); } catch (err) { return false; } })();
    if (/['"]/.test(read.command) || abs) {
      out.problem = 'its hook cannot start: Antigravity runs the command without a shell, split on spaces, so this one (' + String(read.command).trim() + ') is cut in the wrong place and never runs';
      out.fix = 'if the path of your home folder has a space, choose a folder with no spaces and run `ZN_HOOK_DIR=<that folder> zn hooks install antigravity` in your own terminal; otherwise ' + REINSTALL(spec.id);
      return out;
    }
  }
  if (cmd.launcher || cmd.winScript) {
    // The launcher runs the Node.js it was installed with, else `zn` from the PATH, else it blocks (see launcher.js).
    const isFile = (f) => { try { return fs.statSync(f).isFile(); } catch (err) { return false; } };
    const recorded = !cmd.unreadable && isFile(cmd.node) && isFile(cmd.runner);
    const viaPath = !recorded && !cmd.unreadable && Boolean(znOnPath(ctx.env) && onAbsPath('node', ctx.env));
    if (spec.id === 'antigravity' && cmd.quoted && !cmd.winScript) {
      // Antigravity splits the command on spaces and runs it with no shell: the quotes stay in the file name (ENOENT).
      out.problem = 'its hook cannot start: Antigravity runs the command without a shell, so the quotes around the launcher path (' + cmd.launcher + ') become part of the file name and the hook never runs';
      out.fix = REINSTALL(spec.id);
    } else if (cmd.unreadable) {
      out.problem = 'its hook cannot start: its launcher script (' + cmd.launcher + ') is missing or was changed';
      out.fix = REINSTALL(spec.id);
    } else if (!recorded && !viaPath) {
      out.problem = 'its hook cannot start: its ' + (isFile(cmd.node) ? 'zn-gate files (' + cmd.runner + ')' : 'Node.js (' + cmd.node + ')') + ' is no longer there, so zn now blocks the tool calls and prompts instead of checking them';
      out.fix = REINSTALL(spec.id);
    } else {
      if (viaPath) out.notes.push('the Node.js zn was installed with is gone; the hook now runs `zn` from your PATH. Run `zn hooks install ' + spec.id + '` to set it up again');
      // Run it with the PATH check was given, which is what decides whether `zn` and `node` are found.
      // Windows cannot run a .sh file directly; Claude Code runs it with sh (Git Bash) there.
      // The system PowerShell by its path: check may run in a project folder, which could hold a powershell.exe of its own.
      const exe = require('./exe');
      const run = cmd.winScript ? { file: exe.systemPowerShell(), args: ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(cmd.winScript, 'utf16le').toString('base64')] }
        : spec.id === 'antigravity' && process.platform !== 'win32' ? { file: exe.findProgram(cmd.raw.split(' ')[0], ctx.env || process.env), args: cmd.raw.split(' ').slice(1) } // as Antigravity runs it: split on spaces, no shell
          : process.platform === 'win32' ? { file: gitBash(ctx.env || process.env), args: [cmd.launcher, cmd.event] } : { file: cmd.launcher, args: [cmd.event] };
      // The system PowerShell, and sh (Git Bash) from the absolute PATH entries only; without one the live test is skipped.
      if (run.file) out.live = { ...run, env: ctx.env && ctx.env.PATH ? { PATH: ctx.env.PATH } : {} };
      else out.notes.push('the program that runs the hook was not found, so the hook was not run here; zn\'s rules were checked directly');
    }
  } else if (cmd.missing) {
    out.problem = 'its hook cannot start: ' + (fs.existsSync(cmd.node) ? 'its zn-gate files (' + cmd.runner + ')' : 'its Node.js (' + cmd.node + ')') + ' is no longer there';
    // Usually a Node.js version removed with nvm (or similar), which takes its global zn-gate with it.
    out.fix = REINSTALL(spec.id);
  } else if (cmd.onPath) {
    const zn = znOnPath(ctx.env);
    if (!zn) { out.problem = 'its hook runs `zn`, and there is no `zn` on your PATH'; out.fix = REINSTALL(spec.id); }
    else if (process.platform !== 'win32') out.live = { file: zn, args: ['hook', spec.id], env: {} };
    else out.notes.push('the installed hook runs `zn` from your PATH; zn\'s rules were checked directly');
  } else {
    out.live = { file: cmd.node, args: [cmd.runner, spec.id], env: {} };
  }
  return out;
}

/*
 * Whether this folder's hooks file holds zn's hook as a bare `zn hook <agent>` (written by zn-gate before 1.14, or by hand):
 * when `zn` or Node.js cannot start, the agent runs the call unchecked. The guarded form that `zn hooks install <agent> --project`
 * writes now is not bare. `text` is the project file, read with a size limit.
 */
function bareProjectHook(spec, text) {
  if (!text || spec.id === 'opencode' || spec.id === 'zcode') return false;
  try {
    const tree = JSON.parse(String(text).replace(/^\uFEFF/, ''));
    return hookEntries(tree, spec.id).some((e) => { const c = parseCommand(e.command, spec.id); return Boolean(c && c.onPath && !c.guarded); });
  } catch (_) { return false; }
}

/* Whether this folder's hooks file holds a hook of zn's: its text names zn, or one of its commands is zn's (on Windows the
 * project guard is an encoded PowerShell command, so the file holds no plain "zn"). */
function projectHookOurs(spec, text) {
  if (!text) return false;
  if (/zn|runner\.js/.test(text)) return true;
  if (spec.id === 'opencode' || spec.id === 'zcode') return false;
  try {
    const tree = JSON.parse(String(text).replace(/^\uFEFF/, ''));
    return hookEntries(tree, spec.id).some((e) => Boolean(parseCommand(e.command, spec.id)));
  } catch (_) { return false; }
}

/* Whether this folder's hooks file holds a guard that looks like zn's but is not exactly one this version writes. */
function modifiedProjectGuard(spec, text) {
  if (!text || spec.id === 'opencode' || spec.id === 'zcode') return false;
  try {
    const tree = JSON.parse(String(text).replace(/^\uFEFF/, ''));
    return hookEntries(tree, spec.id).some((e) => { const c = parseCommand(e.command, spec.id); return Boolean(c && c.modified); });
  } catch (_) { return false; }
}

/* Runs an installed hook with the two requests: '' when it blocks .env and allows the ordinary file, else the problem. */
function runLive(spec, ctx, live) {
  const a = spawnHook(live.file, live.args, spec.request(ctx.dir, ctx.envFile), live.env, ctx.dir, live.timeout);
  const b = a.ran ? spawnHook(live.file, live.args, spec.request(ctx.dir, ctx.readme), live.env, ctx.dir, live.timeout) : a;
  if (!a.ran) return 'its hook cannot start (' + a.why + ')';
  if (a.decision !== 'deny') return 'the installed hook did not block the read of .env';
  if (b.decision === 'deny') return 'the installed hook blocks everything, ordinary files too, so part of zn is missing or broken';
  return '';
}

/* Whether a documented Copilot CLI setting turns zn's hooks off: {problem, fix, notes}. */
function copilotSwitchedOff(userFile, ctx, adapter) {
  const out = { problem: '', fix: '', notes: [] };
  const mine = readJson(userFile);
  if (mine && mine.disableAllHooks === true) {
    out.problem = 'zn\'s hooks file has "disableAllHooks" turned on, so Copilot skips it';
    out.fix = 'run `zn hooks install copilot` in your own terminal (it turns the hooks back on)';
    return out;
  }
  for (const name of ['settings.json', 'settings.local.json']) {
    const f = path.join(ctx.cwd, '.github', 'copilot', name);
    const s = require('./audit')._internal.readBounded(f, 256 * 1024, false).text;
    let j = null;
    try { j = s ? JSON.parse(s.replace(/^\uFEFF/, '')) : null; } catch (_) { j = null; }
    if (j && j.disableAllHooks === true) {
      out.problem = 'the Copilot settings of this folder (' + f + ') have "disableAllHooks" turned on, so Copilot runs no hook of yours here (only machine policy hooks)';
      out.fix = 'remove "disableAllHooks" from that file, then run `zn-gate check` again';
      return out;
    }
  }
  const user = readJson(path.join(adapter.copilotHome({ home: ctx.home, env: ctx.env }), 'settings.json'));
  if (user && user.disableAllHooks === true) out.notes.push('your Copilot user settings have "disableAllHooks" turned on; the docs do not say whether that skips hook files, so check that zn still runs');
  out.notes.push('Copilot also loads machine policy hooks (/etc/github-copilot/policy.d) and skips a hook that takes longer than its timeout; zn cannot see either from here');
  return out;
}

async function checkAgent(spec, ctx) {
  const { getAdapter } = require('./agents');
  const runner = require('./hooks/runner');
  const adapter = getAdapter(spec.id);
  const res = { id: spec.id, name: spec.name, fix: spec.fix, state: 'not-set-up', problem: '', message: '', notes: [] };
  const userFile = spec.file(adapter, { home: ctx.home, env: ctx.env });

  // zn's own decision for the two requests (no hook involved). Without live checks only the setup is read.
  let rulesOk = true;
  if (ctx.live) {
    const secret = await runner.handle(adapter, spec.request(ctx.dir, ctx.envFile), { home: ctx.home });
    const control = await runner.handle(adapter, spec.request(ctx.dir, ctx.readme), { home: ctx.home });
    res.message = oneLine(secret.decision && secret.decision.message, 300);
    rulesOk = secret.decision && secret.decision.decision === 'deny' && !(control.decision && control.decision.decision === 'deny');
  }

  // What is installed for this user.
  let live = null;      // {file, args, env} to run, or {why} when it cannot start
  let installed = false;
  // zn-gate no longer supports its Cursor plugin: its hooks start `node` by name, so an absolute PATH entry that points
  // into a project (its node_modules/.bin, a folder added by direnv) can run a program of that project instead of zn.
  const cursorPlugin = spec.id === 'cursor' ? cursorZnPlugin(ctx.home) : null;
  const CURSOR_PLUGIN = cursorPlugin ? 'the zn-gate plugin for Cursor is installed (' + cursorPlugin + '), and zn-gate no longer supports it: its hooks start `node` by name, so a PATH entry that points into a project can run a program of that project in place of zn' : '';
  const CURSOR_REMOVE = 'remove the zn-gate plugin in Cursor (Customize, in the sidebar)';
  if (spec.id === 'claude-code') {
    const plugin = claudePlugin(ctx.home, ctx.env);
    const hasCliHooks = hookEntries(readJson(userFile), spec.id).some((e) => parseCommand(e.command, spec.id));
    // A plugin that is turned off runs nothing: with zn's own hooks next to it, those hooks are what protects
    // the agent, so they are checked as such (below) and never offered for removal.
    if (plugin.root && plugin.off && hasCliHooks) res.notes.push('the zn-gate plugin is also installed, but turned off');
    if (plugin.root && !(plugin.off && hasCliHooks)) {
      installed = true;
      res.where = 'the zn-gate plugin';
      res.via = 'plugin';
      // zn's own hooks left next to the plugin both run, and a broken prompt hook among them blocks every prompt.
      // Which set to drop depends on whether the plugin works, so the plugin is checked first (below).
      if (hasCliHooks) res.via = 'both';
      if (plugin.off) {
        res.pluginOff = true;
        res.problem = 'the zn-gate plugin is turned off in your Claude Code settings';
        res.fix = 'turn it on: run `claude plugin enable zn-gate@usezn` in your own terminal';
      }
      const nodeSt = plugin.off ? null : (ctx.pluginNode || (ctx.pluginNode = pluginNodeStatus(ctx)));
      if (nodeSt && !nodeSt.ok) {
        res.problem = pluginNodeProblem(nodeSt);
        res.fix = (nodeSt.unknown ? 'make sure `node --version` works in a new terminal and shows ' + PLUGIN_NODE_MIN + ' or later' : 'update Node.js to ' + PLUGIN_NODE_MIN + ' or later (the current LTS from nodejs.org), and make it the first `node` on your PATH') + ', or use zn\'s hooks instead: run `npm install -g zn-gate`, then `zn hooks install claude-code`, and after that turn the plugin off with `claude plugin disable zn-gate@usezn`, all in your own terminal';
        res.pluginFault = true;
        res.pluginNode = true;
      }
      // Nothing of the plugin runs until its folder and its manifest pass: the folder is one Claude Code installs
      // plugins into (not the project), and the manifest has a PreToolUse hook that Claude Code runs and waits for.
      const manifestFile = path.join(plugin.root, 'hooks', 'hooks.json');
      let distrust = '';
      let manifest = null;
      let preHook = null;
      if (!plugin.off) {
        distrust = claudePluginRootProblem(plugin.root, ctx);
        if (!distrust) manifest = pluginManifest(plugin.root, 'CLAUDE_PLUGIN_ROOT');
        if (!distrust && !manifest) distrust = 'the zn-gate plugin has no hook manifest zn-gate check can read (' + manifestFile + '), so nothing shows that Claude Code runs a zn check before tool calls';
        if (distrust) {
          res.problem = distrust;
          res.fix = PLUGIN_REINSTALL;
          res.pluginFault = true;
        } else if (manifest.bare) {
          res.problem = bareProgramProblem(manifest.bare);
          res.fix = 'update the plugin: run `claude plugin update zn-gate@usezn` in your own terminal; if `zn-gate check` still reports this, use zn\'s hooks instead: run `npm install -g zn-gate`, then `zn hooks install claude-code`, then `claude plugin disable zn-gate@usezn`, all in your own terminal, then run `zn-gate check` again';
          res.pluginFault = true;
          distrust = res.problem;
        } else {
          const pre = claudePreHook(manifest, manifestFile, spec.tool);
          distrust = pre.problem;
          if (distrust) { res.problem = distrust; res.fix = PLUGIN_REINSTALL; res.pluginFault = true; } else preHook = pre.hook;
        }
      }
      if (!plugin.off && !distrust) {
        // The live test runs the PreToolUse command of the manifest, the one checked above, as Claude Code runs it
        // (never zn-launch.js directly): if that command does not refuse the read of .env, the plugin protects nothing.
        const realRoot = realOrNull(plugin.root) || plugin.root;
        const run = claudePluginRun(CLAUDE_PRE_COMMAND, realRoot, ctx, preHook.timeout);
        if (!run) {
          res.problem = 'Git Bash was not found, and Claude Code runs the hooks of the zn-gate plugin with it on Windows ("shell": "bash"), so the hook cannot start';
          res.fix = 'install Git for Windows (or set CLAUDE_CODE_GIT_BASH_PATH to its bash.exe), or use zn\'s hooks instead: run `npm install -g zn-gate`, then `zn hooks install claude-code`, then `claude plugin disable zn-gate@usezn`, all in your own terminal, then run `zn-gate check` again';
          res.pluginFault = true;
        } else {
          // The plugin's SessionStart command, the same script with "check": only for the launcher's own message about
          // the plugin itself (for example a Node.js it does not support). It never makes the plugin count as protected.
          const checkRun = claudePluginRun(CLAUDE_CHECK_COMMAND, realRoot, ctx, 15);
          const pre = ctx.live ? spawnHook(checkRun.file, checkRun.args, {}, checkRun.env, ctx.dir, checkRun.timeout) : { ran: false };
          const sys = pre.ran && /"systemMessage"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(pre.stdout || '');
          if (!res.problem && sys) { res.problem = bare(oneLine(JSON.parse('"' + sys[1] + '"'), 300)); res.pluginFault = true; }
          live = { ...run, plugin: true };
        }
      }
    }
  }
  if (spec.id === 'zcode') {
    // The zn-gate plugin: ZCode runs a plugin's hooks whatever hooks.enabled says, so it protects on its own.
    const plugin = adapter.pluginState({ home: ctx.home });
    if (plugin.root) {
      const conf = readJson(userFile) || {};
      const userHooks = hookEntries(conf, spec.id).some((e) => parseCommand(e.command, spec.id));
      const userHooksOn = userHooks && conf.hooks && conf.hooks.enabled === true;
      if (plugin.enabled) {
        installed = true;
        res.where = 'the zn-gate plugin';
        res.via = 'plugin';
        if (userHooksOn) {
          res.notes.push('zn is also set up with `zn hooks install zcode`, so every call is checked twice (ZCode does not remove duplicate hooks); keep one: run `zn hooks uninstall zcode` in your own terminal to keep the plugin, or turn the plugin off in ZCode (Settings, Plugins) to keep the hooks');
        }
        // The hook runs exactly as ZCode starts it: the program named in the plugin's hooks.json, never one looked up here.
        // Only the PreToolUse hook the plugin ships counts: a "process" hook that runs exactly /bin/sh with
        // ${ZCODE_PLUGIN_ROOT}/scripts/zn-hook.sh PreToolUse, turned on, for every tool it is asked about.
        const manifest = pluginManifest(plugin.root, 'ZCODE_PLUGIN_ROOT');
        const pres = manifest ? manifest.hooks.filter((h) => h.event === 'PreToolUse') : [];
        const pre = pres.find((h) => !h.byName && h.type === 'process' && !h.off && !h.async && matcherCovers(h.matcher, spec.tool) &&
          h.words.length === ZCODE_PRE_WORDS.length && h.words.every((w, i) => w === ZCODE_PRE_WORDS[i]));
        const REINSTALL = 'install the zn-gate plugin again in ZCode (Settings, Plugins), then run `zn-gate check` again';
        const zfile = path.join(plugin.root, 'hooks', 'hooks.json');
        if (!pres.length) {
          res.problem = 'the zn-gate plugin has no PreToolUse hook in ' + zfile + ', so ZCode runs no zn check before tool calls';
          res.fix = REINSTALL;
        } else if (manifest.bare) {
          res.problem = bareProgramProblem(manifest.bare);
          res.fix = 'update the plugin: ' + REINSTALL;
        } else if (!pre) {
          res.problem = 'the PreToolUse hook of the zn-gate plugin in ' + zfile + ' is not the hook the plugin ships (`' + ZCODE_PRE_WORDS.join(' ') + '`, turned on, for every tool), so ZCode runs no zn check before tool calls';
          res.fix = REINSTALL;
        } else if (!fs.existsSync(pre.file)) {
          res.problem = 'the zn-gate plugin starts its hook with ' + pre.file + ', which is not on this computer, so the hook cannot start';
          res.fix = 'the ZCode plugin needs a system with ' + pre.file + ' (Linux); elsewhere use `zn hooks install zcode` in your own terminal, then run `zn-gate check` again';
        } else {
          live = { file: pre.file, args: pre.args, env: ctx.env && ctx.env.PATH ? { PATH: ctx.env.PATH } : {}, plugin: true };
        }
      } else if (!userHooksOn) {
        // Turned off, and nothing else of zn's runs: ZCode is not protected.
        installed = true;
        res.where = 'the zn-gate plugin';
        res.via = 'plugin';
        res.problem = plugin.pluginsOff ? 'plugins are turned off in ZCode ("plugins.enabled" is false in ' + userFile + '), so the zn-gate plugin does not run and no other zn hook protects ZCode'
          : userHooks ? 'the zn-gate plugin is turned off in ZCode, and "hooks.enabled" is ' + (conf.hooks && conf.hooks.enabled === false ? 'false' : 'not true') + ' in ' + userFile + ', so ZCode runs none of the hooks of `zn hooks install zcode` either and nothing of zn protects ZCode'
          : 'the zn-gate plugin is turned off in ZCode, and the hooks of `zn hooks install zcode` are not installed, so nothing of zn protects ZCode';
        res.fix = 'turn the plugin on in ZCode (Settings, Plugins), or run `zn hooks install zcode` in your own terminal, then run `zn-gate check` again';
        res.pluginOff = true;
      } else {
        res.notes.push('the zn-gate plugin is installed but turned off; the hooks of `zn hooks install zcode` are what protect ZCode');
      }
    }
  }
  if (!installed && spec.id === 'opencode') {
    let src = '';
    try { src = fs.readFileSync(userFile, 'utf8'); } catch (err) { src = ''; }
    installed = /\/zn-gate\/lib\/hooks\/runner\.js"|"hook", "opencode"/.test(src);
    res.where = userFile;
  } else if (!installed) {
    const h = cliHooks(spec, ctx, userFile);
    installed = h.installed;
    res.where = userFile;
    if (installed) { res.fix = h.fix; res.via = 'hooks'; res.problem = h.problem; live = h.live; res.notes.push(...h.notes); }
  }
  // zn installed by the organization (managed settings, enterprise hooks.json, requirements.toml). Read-only.
  const managed = managedFor(spec.id, ctx);
  if (managed) {
    res.managed = managed.files[0];
    const mgWhere = managed.files.join(', ');
    if (!installed) {
      const h = cliHooks(spec, ctx, null, managed.entries);
      installed = true;
      res.where = managed.files[0];
      res.via = 'managed';
      res.problem = h.problem;
      live = h.live;
      res.notes.push(...h.notes);
      // Only an administrator can repair the managed files.
      res.fix = 'ask your administrator to repair the managed configuration (' + mgWhere + ')';
    } else {
      res.notes.push('zn is also set up in ' + res.where + ', next to the managed configuration, so its hooks run twice; to keep only the managed one, ' + (res.via === 'plugin' || res.via === 'both' ? 'turn the plugin off: `claude plugin disable zn-gate@usezn`' : 'run `zn hooks uninstall ' + spec.id + '`') + ' in your own terminal');
    }
    res.notes.unshift('zn is installed through your organization\'s managed configuration (' + mgWhere + ')');
  }
  if (spec.id === 'claude-code' && installed && res.where === userFile) {
    // Without onFailure "block", a prompt hook that cannot run lets every prompt through (Claude Code 2.1.295 and later read it).
    const prompt = hookEntries(readJson(userFile), spec.id).find((e) => e.event === 'UserPromptSubmit' && parseCommand(e.command, spec.id));
    if (prompt && prompt.onFailure !== 'block') res.notes.push('its prompt hook lets prompts through when it cannot run; run `zn hooks install claude-code` again to have them blocked instead');
    // Hooks written by an older zn-gate have no hook for typed skills and commands. The Claude Code version is not
    // known here, so the note is harmless on a version without that event.
    const hasExpansion = hookEntries(readJson(userFile), spec.id).some((e) => e.event === 'UserPromptExpansion' && parseCommand(e.command, spec.id));
    if (!hasExpansion) res.notes.push('its hooks lack the newer prompt-expansion check (for typed skills and commands); run `zn hooks install claude-code` again to add it');
  }
  if (spec.id === 'claude-code' && installed && (!res.problem || res.pluginFault)) {
    const p = claudePolicy(ctx.home, ctx.env, ctx.claudePolicy);
    // A Claude Code setting stops every hook, the plugin's and zn's own alike: that setting is the fix, not either set.
    if (p.length) {
      res.problem = bare(oneLine(p[0], 300));
      res.fix = 'change that Claude Code setting as it says, then run `zn-gate check` again';
      res.pluginFault = false;
    }
  }
  if (spec.id === 'codex' && installed && !res.problem) {
    // Codex requirements, its managed configuration or the user's config.toml can turn every hook off.
    let p = [];
    // The user's hooks.json sits in the Codex home folder, next to its config.toml.
    const codexHome = path.dirname(adapter.hooksFile({ home: ctx.home, env: ctx.env }));
    try { p = require('./agents/managed-policy').codexPolicyWarnings({ ...(ctx.codexPolicy || {}), env: ctx.env, codexHome }); } catch (_) { p = []; }
    // A file zn could not read is a note: zn does not know that it turns the hooks off.
    for (const w of p.filter((x) => /^could not read/.test(x))) res.notes.push(oneLine(w, 300));
    p = p.filter((x) => !/^could not read/.test(x));
    if (p.length) {
      res.problem = bare(oneLine(p[0], 300));
      res.fix = 'change that Codex setting as it says, then run `zn-gate check` again';
    }
  }
  if (spec.id === 'codex' && installed && !res.problem && res.where === userFile) {
    // A hook Codex runs in the background cannot block a call or change a result, so it protects nothing.
    const bg = codexBackgroundFile(path.dirname(userFile), userFile);
    if (bg) {
      res.problem = 'zn\'s ' + bg.event + ' hook runs in the background (async) in ' + bg.file + ', and a background hook cannot block anything, so zn does not protect Codex';
      res.fix = 'remove `async` from zn\'s hooks in that file, or run `zn hooks install codex` again, then run `zn-gate check` again';
    }
  }
  if (spec.id === 'codex' && installed && !res.problem && res.where === userFile) {
    // [hooks.state] in the user's config.toml can switch one hook off: Codex then skips it without a word.
    const off = codexHookSwitchedOff(path.dirname(userFile), [userFile, path.join(path.dirname(userFile), 'config.toml')]);
    if (off) {
      res.problem = 'zn\'s ' + off.event + ' hook is switched off in ' + off.file + ' ([hooks.state] enabled = false), so Codex skips it and zn does not protect Codex';
      res.fix = 'delete that [hooks.state] entry, or turn zn\'s hook back on in `/hooks` in Codex, then run `zn-gate check` again';
    }
  }
  if (spec.id === 'cursor' && installed) {
    // Cursor's enterprise hooks.json (read-only): zn's hook there without failClosed, or enterprise hooks without zn's.
    try { res.notes.push(...require('./agents/managed-policy').cursorPolicyWarnings({ ...(ctx.cursorPolicy || {}), env: ctx.env }).map((w) => oneLine(w, 400))); } catch (_) { /* never fails the check */ }
  }
  if (spec.id === 'gemini' && installed && !res.problem) {
    // hooksConfig.enabled false, or zn's hook named in hooksConfig.disabled, in the user, project or system settings.
    let p = [];
    try {
      p = require('./agents/managed-policy').geminiPolicyWarnings({
        files: [
          { file: userFile, label: 'your Gemini CLI settings' },
          { file: spec.project(ctx.cwd), label: 'this folder\'s Gemini CLI settings' },
          { file: ctx.geminiSystemFile || adapter.systemSettingsFile(), label: 'the system Gemini CLI settings' },
        ],
      });
    } catch (_) { p = []; }
    for (const w of p.filter((x) => /^could not read/.test(x))) res.notes.push(oneLine(w, 300));
    p = p.filter((x) => !/^could not read/.test(x));
    if (p.length) {
      res.problem = bare(oneLine(p[0], 300));
      res.fix = 'change that Gemini CLI setting as it says, then run `zn-gate check` again';
    }
  }
  if (spec.id === 'zcode' && installed && !res.problem && res.via !== 'plugin') {
    // ZCode runs no hook unless hooks.enabled is true, and skips an entry that has "enabled": false.
    let w = { problems: [], notes: [], fix: '' };
    try { w = adapter.configWarnings({ file: userFile }); } catch (_) { /* nothing to add */ }
    res.notes.push(...w.notes.map((x) => oneLine(x, 300)));
    if (w.problems.length) {
      res.problem = bare(oneLine(w.problems[0], 300));
      res.fix = w.fix;
    }
  }
  if (spec.id === 'codex' && installed && !res.problem) {
    // Codex runs every PreToolUse hook at the same time, each with the original call: another tool's hook can
    // change a call after zn checked it, or answer an approval prompt. zn cannot see what that hook does.
    let other = null;
    try { other = require('./codex-other-hooks').findOtherHooks(path.dirname(userFile), ctx.cwd); } catch (_) { other = null; }
    if (other) {
      res.problem = 'another hook runs before Codex calls (' + other.event + ' in ' + other.file + '); it can change a call after zn has checked it, so zn cannot fully protect Codex';
      res.fix = 'review that hook and remove it if you do not need it, or have your administrator manage hooks with `allow_managed_hooks_only`, then run `zn-gate check` again';
    }
  }
  if (spec.id === 'copilot' && installed && !res.problem) {
    // Copilot skips a hooks file with "disableAllHooks": true, and every non-policy hook when a repository's settings say so.
    const off = copilotSwitchedOff(userFile, ctx, adapter);
    if (off.problem) { res.problem = off.problem; res.fix = off.fix; }
    res.notes.push(...off.notes);
  }
  if (spec.id === 'antigravity' && installed && res.where === userFile) {
    // Antigravity says what "allow" means ("delegating to the next hook or default policy") but not in which order hooks
    // run or which answer wins, so another enabled PreToolUse hook is something zn cannot see through.
    const others = antigravityOtherHooks([userFile, spec.project(ctx.cwd)]);
    if (others.length) {
      const first = others[0];
      res.notes.push('another Antigravity hook also runs before tool calls (' + JSON.stringify(first.name) + ' in ' + first.file + (others.length > 1 ? ', and ' + (others.length - 1) + ' more' : '') + '). Antigravity does not document in which order hooks run or which answer wins, so zn cannot tell whether its deny holds against it; review that hook, or turn it off with "enabled": false');
    }
  }
  if (spec.id === 'opencode' && installed) res.notes.push('zn\'s rules were checked; its plugin runs inside OpenCode, so it was not started here');

  // The project file can be anyone's repository: read only a regular file, and only so much of it.
  const projFile = spec.project(ctx.cwd);
  const projText = path.resolve(projFile) !== path.resolve(userFile) ? require('./audit')._internal.readBounded(projFile, 256 * 1024, false).text : null;
  const projBare = bareProjectHook(spec, projText);
  const BARE_FIX = 'run `zn hooks install ' + spec.id + ' --project` again in that project (it writes the guarded command)';
  const projModified = !projBare && modifiedProjectGuard(spec, projText);
  const MOD_MSG = 'the zn hook in ' + projFile + ' was modified (it is not the guard zn writes); run `zn hooks install ' + spec.id + ' --project` again in that project';
  if (installed && projModified) res.notes.push(MOD_MSG);
  if (installed && projBare) res.notes.push('the hook in ' + projFile + ' is a bare `zn hook ' + spec.id + '`: where zn or Node.js cannot start, ' + spec.name + ' runs the call unchecked there; ' + BARE_FIX);

  if (cursorPlugin && !installed) {
    // The plugin alone: Cursor is not protected, and nothing of the plugin is run here.
    installed = true;
    live = null;
    res.where = cursorPlugin;
    res.via = 'plugin';
    res.problem = CURSOR_PLUGIN;
    res.fix = 'run ' + (znOnPath(ctx.env) ? '' : '`npm install -g zn-gate`, then ') + '`zn hooks install cursor` in your own terminal, then ' + CURSOR_REMOVE + ', then run `zn-gate check` again';
  }

  if (!installed) {
    // Whether the agent is on this machine at all, so the report offers no setup for an agent that is not there.
    try { res.found = Boolean(adapter.detect({ home: ctx.home, env: ctx.env })); } catch (err) { res.found = true; }
    // `zn hooks install` needs zn-gate installed for the user: run from npx alone, there is no `zn` command yet.
    if (spec.id !== 'claude-code' && !znOnPath(ctx.env)) res.fix = 'run `npm install -g zn-gate`, then `zn hooks install ' + spec.id + '`, in your own terminal';
    const proj = projFile;
    const text = projText;
    if (projectHookOurs(spec, text)) {
      res.state = 'project-only';
      res.where = proj;
      if (projBare) {
        // A bare `zn hook` fails open when zn or Node.js is gone: the project is not protected.
        res.state = 'not-protected';
        res.problem = 'the hook in ' + proj + ' is a bare `zn hook ' + spec.id + '`, so where zn or Node.js cannot start, ' + spec.name + ' runs the call unchecked';
        res.fix = BARE_FIX;
      } else if (projModified) {
        res.state = 'not-protected';
        res.problem = MOD_MSG;
        res.fix = BARE_FIX;
      }
    }
    return res;
  }
  if (!res.problem && !rulesOk) {
    // These are the rules of the copy that runs this command (with npx, its cached copy), not necessarily the
    // installed one; reinstalling zn-gate globally is still the repair that fits most cases.
    // zn's own rules, the ones this command runs, let the read through: the zn-gate install is what needs repair,
    // whatever runs the hooks (installing the plugin again or reinstalling the hooks would not change it).
    res.problem = 'zn did not block the read of .env';
    res.fix = RULES_FIX;
    res.rulesFault = true;
  }
  if (!res.problem && live && ctx.live) {
    res.problem = runLive(spec, ctx, live);
    if (res.problem && live.plugin) res.pluginFault = true;
    else if (!res.problem) res.verified = true;
  }
  if (cursorPlugin && res.via !== 'plugin') {
    // zn's own Cursor hooks next to the plugin: the plugin's hooks still run, so Cursor is not protected until it is
    // removed. As with the Claude Code plugin, the hooks are repaired first when they do not work either.
    res.cursorPlugin = cursorPlugin;
    res.verified = false;
    if (!res.problem) {
      res.problem = CURSOR_PLUGIN + ', while the zn hooks next to it (' + res.where + ') work';
      res.fix = CURSOR_REMOVE + ', then run `zn-gate check` again';
    } else {
      res.problem = CURSOR_PLUGIN + ', and the zn hooks next to it do not work either (' + bare(res.problem) + ')';
      res.fix = 'first repair the hooks: ' + res.fix + '; after that, ' + CURSOR_REMOVE + ', then run `zn-gate check` again';
    }
  }
  if (res.via === 'both') {
    if (res.pluginFault) {
      // The plugin does not work here. Which way out keeps the agent protected depends on zn's own hooks next to
      // it, so they are checked now, also run as Claude Code runs them, before anything is said about them.
      res.pluginBroken = true;
      if (!rulesOk) {
        // zn's own rules let the read through, so neither set can work until zn-gate is repaired.
        res.problem = 'zn did not block the read of .env';
        res.fix = RULES_FIX;
        res.rulesFault = true;
        res.state = 'not-protected';
        return res;
      }
      const why = bare(res.problem);
      const h = cliHooks(spec, ctx, userFile);
      let hooksProblem = h.problem;
      if (!hooksProblem && !rulesOk) hooksProblem = 'zn did not block the read of .env';
      if (!hooksProblem && h.live) hooksProblem = runLive(spec, ctx, h.live);
      res.hooksBroken = Boolean(hooksProblem);
      if (!res.hooksBroken) {
        res.problem = 'the zn-gate plugin does not work here (' + why + '), while the hooks of `zn hooks install claude-code` next to it do';
        res.fix = 'turn the plugin off, which keeps those hooks: run `claude plugin disable zn-gate@usezn` in your own terminal, then run `zn-gate check` again';
      } else {
        // Repair the hooks first, and only then turn the plugin off: at no point does the agent have less than before.
        res.problem = 'the zn-gate plugin does not work here (' + why + '), and the hooks of `zn hooks install claude-code` next to it do not work either (' + bare(hooksProblem) + ')';
        res.fix = 'first repair the hooks: run `npm install -g zn-gate`, then `zn hooks install claude-code`; after that, turn the plugin off with `claude plugin disable zn-gate@usezn`; all in your own terminal, then run `zn-gate check` again';
      }
    } else if (!res.problem) {
      res.duplicate = true;
      res.verified = false;
      res.problem = 'the zn-gate plugin and the hooks of `zn hooks install claude-code` are both set up, so both run, and a broken one can block every prompt';
      res.fix = 'remove the second set: run `zn hooks uninstall claude-code` in your own terminal';
    }
  }
  res.state = res.problem ? 'not-protected' : 'protected';
  return res;
}

/* Warnings about the Node.js that runs zn-gate and the one the plugin's hooks will run on (end-of-life, or below the
   patched release of its line). They never change what is protected or the exit code. */
function nodeWarnings(opts, env) {
  const out = [];
  try {
    const zn = opts.nodeVersion || process.versions.node;
    const a = nodeAdvice(zn);
    if (a) out.push(a.message);
    let hook = opts.hookNode;
    if (typeof hook === 'function') hook = hook(env);
    else if (hook === undefined) hook = opts.nodeVersion ? null : resolveHookNode(env, opts.cwd);
    if (hook && hook.version && hook.version !== zn) {
      const h = nodeAdvice(hook.version);
      if (h) out.push('The hooks will run on Node.js ' + hook.version + (hook.path ? ' (from ' + hook.path + ')' : '') + '. ' + h.message);
    }
  } catch (err) { /* a warning never fails the check */ }
  return out;
}

/**
 * check({home, env, cwd, live}) -> {results, removed, warnings}. Never throws for one agent.
 * With live: false only the setup is read: no test folder, no rules run, no hook started
 * (each result then has checked: false, and "protected" means set up with no problem found).
 */
async function check(opts = {}) {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const cwd = opts.cwd || process.cwd();
  if (opts.live === false) {
    const ctx = { home, env, cwd, live: false, dir: cwd, codexPolicy: opts.codexPolicy, claudePolicy: opts.claudePolicy, cursorPolicy: opts.cursorPolicy, geminiSystemFile: opts.geminiSystemFile, nodeVersion: opts.nodeVersion, hookNode: opts.hookNode, pluginNode: opts.pluginNode };
    const results = [];
    for (const spec of AGENTS) {
      try {
        results.push({ ...(await checkAgent(spec, ctx)), checked: false });
      } catch (err) {
        results.push({ id: spec.id, name: spec.name, fix: spec.fix, state: 'not-protected', problem: 'zn could not read its setup: ' + oneLine(err && err.message, 200), notes: [], checked: false });
      }
    }
    return { results, removed: true, warnings: nodeWarnings(opts, env) };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-check-'));
  const ctx = { home, env, cwd, live: true, dir, envFile: path.join(dir, '.env'), readme: path.join(dir, 'README.txt'), codexPolicy: opts.codexPolicy, claudePolicy: opts.claudePolicy, cursorPolicy: opts.cursorPolicy, geminiSystemFile: opts.geminiSystemFile, nodeVersion: opts.nodeVersion, hookNode: opts.hookNode, pluginNode: opts.pluginNode };
  const results = [];
  try {
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
    fs.writeFileSync(ctx.envFile, FAKE_LINE, { mode: 0o600 });
    fs.writeFileSync(ctx.readme, 'An ordinary file that zn lets your agent read.\n');
    for (const spec of AGENTS) {
      try {
        results.push(await checkAgent(spec, ctx));
      } catch (err) {
        results.push({ id: spec.id, name: spec.name, fix: spec.fix, state: 'not-protected', problem: 'zn could not check it: ' + oneLine(err && err.message, 200), notes: [] });
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return { results, removed: !fs.existsSync(dir), warnings: nodeWarnings(opts, env) };
}

/** Plain-language report; returns the exit code (0 when every agent set up is protected). */
function report({ results, removed, warnings }, write) {
  const w = write || ((s) => process.stdout.write(s));
  w('\nzn-gate check: does zn stop your coding agent from reading a secret?\n\n');
  w('zn made a test folder with a fake key in a .env file and an ordinary file next to it, then asked\n');
  w('each agent\'s zn hook whether the agent may read them. This is what happened:\n\n');
  let setUp = 0;
  let bad = 0;
  const missing = [];
  for (const r of results) {
    if (r.state === 'not-set-up' && r.found === false) {
      w(`  -  ${r.name.padEnd(12)} not found on this machine\n`);
      continue;
    }
    if (r.state === 'not-set-up') {
      missing.push(r.name);
      w(`  -  ${r.name.padEnd(12)} zn is not set up for this agent. To protect it, ${r.fix}.\n`);
      continue;
    }
    if (r.state === 'project-only') {
      w(`  -  ${r.name.padEnd(12)} zn is set up only for one project (${r.where}). This check covers the setup for your user; to protect every project, ${r.fix}.\n`);
      continue;
    }
    setUp++;
    if (r.state === 'not-protected') {
      bad++;
      w(`  X  ${r.name.padEnd(12)} NOT protected: ${r.problem}.\n`);
      w(`     To fix it, ${r.fix}.\n`);
      continue;
    }
    w(`  OK ${r.name.padEnd(12)} blocked the .env file and allowed the ordinary file. Your agent would be told:\n`);
    w(`     "${r.message}"\n`);
    for (const n of r.notes) w(`     (${n})\n`);
  }
  w('\n');
  const init = 'run `npx -y zn-gate init` in your own terminal: it shows each step and asks before it runs one.\n';
  // Nothing to set up only when every agent is missing from the machine (a project-only setup counts as found).
  if (!setUp && !results.some((r) => r.found !== false || r.state !== 'not-set-up')) {
    w('No supported coding agent was found on this machine (Claude Code, Codex CLI, Cursor, OpenCode, Antigravity, ZCode desktop app), so there is nothing to check.\n');
    w('Install one, then run `npx -y zn-gate init`. Other editors: https://usezn.com/docs/install\n\n');
  } else if (!setUp) {
    w('zn is not set up for your agents yet, so nothing protects your secrets. To set it up, ' + init);
    w('More: https://usezn.com/docs/install\n\n');
  } else if (!bad) {
    w('Your agent cannot read secret files such as .env through these tools. Nothing was sent anywhere.\n');
    if (missing.length) w('Not set up yet: ' + missing.join(', ') + '. To add ' + (missing.length > 1 ? 'them' : 'it') + ', ' + init);
    w('If your agent needs a value from .env, keep it in zn\'s vault instead: `zn env shadow .env`.\n');
    w('More: https://usezn.com/docs/check\n\n');
  } else {
    w('Some agents are not protected (see above). More: https://usezn.com/docs/check\n\n');
  }
  for (const n of warnings || []) w('Warning: ' + n + '\n');
  if (warnings && warnings.length) w('\n');
  w(removed ? 'The test folder was deleted.\n' : 'The test folder could not be deleted; it holds only the fake key.\n');
  return setUp && !bad ? 0 : 1;
}

module.exports = { check, report, FAKE_LINE, AGENTS, _internal: { pluginManifest, spawnHook, gitBash, PLUGIN_NODE_MIN, pluginNodeOk, pluginNodeMessage, pluginNodeStatus, pluginNodeProblem, resolveHookNode, hookEntries, matcherCovers, parseCommand, decisionOf, claudePlugin, claudePluginRootProblem, claudePreToolProblem, claudePreHook, claudePluginRun, cursorZnPlugin, CLAUDE_PRE_COMMAND, CLAUDE_CHECK_COMMAND, ZCODE_PRE_WORDS } };
