'use strict';

/**
 * zn-gate check: shows, safely, that the zn hooks installed for each agent
 * stop a secret from being read and still let ordinary files through.
 *
 * It makes a temporary folder with a .env file that holds an obviously fake
 * key and a README.txt, and for each agent:
 *   - finds zn's user-level setup: the hook for the agent's read event, with
 *     a matcher that covers the read, or, for Claude Code, the zn-gate plugin
 *     listed in installed_plugins.json and not turned off;
 *   - asks zn what it decides for a read of .env (must block) and of
 *     README.txt (must be allowed);
 *   - runs the installed hook the same way the agent does, with the same two
 *     requests, so a hook that cannot start, or that blocks everything because
 *     part of zn is missing, is reported instead of passing.
 * An installed command is run only when it has the exact shape zn writes,
 * with Node.js and a real zn-gate runner, as node + runner without a shell,
 * in the temporary folder. Nothing leaves the machine, no agent is started,
 * no setting changes, and the folder is deleted at the end. Project-level
 * setups are reported but not run.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const FAKE_LINE = 'ZN_CHECK_EXAMPLE_KEY=zn-check-fake-value-not-a-real-key\n';
const HOOK_TIMEOUT_MS = 15000;
const PLUGIN_ID = 'zn-gate@usezn';

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
];

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return null;
  }
}

/* [{event, matcher, command}] from a hooks file: Claude Code and Codex use groups with a matcher, Cursor plain entries. */
function hookEntries(tree) {
  const out = [];
  const hooks = tree && typeof tree.hooks === 'object' ? tree.hooks : {};
  for (const [event, list] of Object.entries(hooks)) {
    for (const g of Array.isArray(list) ? list : []) {
      if (!g || typeof g !== 'object') continue;
      if (typeof g.command === 'string') out.push({ event, matcher: g.matcher, command: g.command, onFailure: g.onFailure });
      for (const h of Array.isArray(g.hooks) ? g.hooks : []) {
        if (h && typeof h.command === 'string') out.push({ event, matcher: g.matcher, command: h.command, onFailure: h.onFailure });
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

/* A zn hook command: {node, runner} (run directly), {onPath} (`zn hook <agent>`) or null. */
function parseCommand(command, agentId) {
  const { _internal: audit } = require('./audit');
  const c = String(command).trim();
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

function decisionOf(stdout, status) {
  if (status === 2) return 'deny';
  const o = String(stdout || '');
  if (/"permissionDecision"\s*:\s*"deny"|"decision"\s*:\s*"(?:deny|block)"|"permission"\s*:\s*"deny"|"continue"\s*:\s*false/.test(o)) return 'deny';
  return 'allow';
}

function spawnHook(file, args, input, env, cwd) {
  const r = spawnSync(file, args, {
    input: JSON.stringify(input), encoding: 'utf8', timeout: HOOK_TIMEOUT_MS, cwd,
    env: { ...process.env, ZN_STATS: 'off', ...env }, windowsHide: true,
  });
  if (r.error) return { ran: false, why: r.error.code || r.error.message };
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

/* Hook policy warnings for Claude Code (managed settings, disableAllHooks), as `zn-gate status` shows. */
function claudePolicy(home, env) {
  try {
    const cc = require('./agents').getAdapter('claude-code');
    const w = require('./agents/managed-policy').claudeCodePolicyWarnings({ userSettings: [cc.settingsFile({ home, env })], mcp: false });
    return w.filter((x) => /hooks/i.test(x));
  } catch (err) {
    return [];
  }
}

function oneLine(s, n) {
  return String(s || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
}

async function checkAgent(spec, ctx) {
  const { getAdapter } = require('./agents');
  const runner = require('./hooks/runner');
  const adapter = getAdapter(spec.id);
  const res = { id: spec.id, name: spec.name, fix: spec.fix, state: 'not-set-up', problem: '', message: '', notes: [] };
  const userFile = spec.file(adapter, { home: ctx.home, env: ctx.env });

  // zn's own decision for the two requests (no hook involved).
  const secret = await runner.handle(adapter, spec.request(ctx.dir, ctx.envFile), { home: ctx.home });
  const control = await runner.handle(adapter, spec.request(ctx.dir, ctx.readme), { home: ctx.home });
  res.message = oneLine(secret.decision && secret.decision.message, 300);
  const rulesOk = secret.decision && secret.decision.decision === 'deny' && !(control.decision && control.decision.decision === 'deny');

  // What is installed for this user.
  let live = null;      // {file, args, env} to run, or {why} when it cannot start
  let installed = false;
  if (spec.id === 'claude-code') {
    const plugin = claudePlugin(ctx.home, ctx.env);
    const cliHooks = hookEntries(readJson(userFile)).some((e) => parseCommand(e.command, spec.id));
    // A plugin that is turned off runs nothing: with zn's own hooks next to it, those hooks are what protects
    // the agent, so they are checked as such (below) and never offered for removal.
    if (plugin.root && plugin.off && cliHooks) res.notes.push('the zn-gate plugin is also installed, but turned off');
    if (plugin.root && !(plugin.off && cliHooks)) {
      installed = true;
      res.where = 'the zn-gate plugin';
      res.via = 'plugin';
      // zn's own hooks left next to the plugin both run, and a broken prompt hook among them blocks every prompt.
      if (cliHooks) {
        res.via = 'both';
        res.problem = 'the zn-gate plugin and the hooks of `zn hooks install claude-code` are both set up, so both run, and a broken one can block every prompt';
        res.fix = 'remove the second set: run `zn hooks uninstall claude-code` in your own terminal';
      }
      if (plugin.off) {
        res.pluginOff = true;
        res.problem = 'the zn-gate plugin is turned off in your Claude Code settings';
        res.fix = 'turn it on: run `claude plugin enable zn-gate@usezn` in your own terminal';
      }
      const pre = spawnHook(process.execPath, [path.join(plugin.root, 'scripts', 'zn-launch.js'), 'check', 'claude-code'], {}, { CLAUDE_PLUGIN_ROOT: plugin.root }, ctx.dir);
      const sys = pre.ran && /"systemMessage"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(pre.stdout || '');
      if (!res.problem && sys) res.problem = oneLine(JSON.parse('"' + sys[1] + '"'), 300);
      live = { file: process.execPath, args: [path.join(plugin.root, 'scripts', 'zn-launch.js'), 'hook', 'claude-code'], env: { CLAUDE_PLUGIN_ROOT: plugin.root } };
    }
  }
  if (!installed && spec.id === 'opencode') {
    let src = '';
    try { src = fs.readFileSync(userFile, 'utf8'); } catch (err) { src = ''; }
    installed = /\/zn-gate\/lib\/hooks\/runner\.js"|"hook", "opencode"/.test(src);
    res.where = userFile;
  } else if (!installed) {
    const entries = hookEntries(readJson(userFile)).filter((e) => parseCommand(e.command, spec.id));
    installed = entries.length > 0;
    res.where = userFile;
    // Set up with `zn hooks install`, so that is also how to repair it (not the plugin: both would run).
    if (installed) { res.fix = 'run `zn hooks install ' + spec.id + '` in your own terminal'; res.via = 'hooks'; }
    const read = entries.find((e) => e.event === spec.event && matcherCovers(e.matcher, spec.tool));
    if (installed && !read) {
      res.problem = 'zn\'s hooks are there, but not the one that checks reading files (' + spec.event + ')';
    } else if (read) {
      const cmd = parseCommand(read.command, spec.id);
      if (cmd.missing) {
        res.problem = 'its hook cannot start: ' + (fs.existsSync(cmd.node) ? 'its zn-gate files (' + cmd.runner + ')' : 'its Node.js (' + cmd.node + ')') + ' is no longer there';
        // Usually a Node.js version removed with nvm (or similar), which takes its global zn-gate with it.
        res.fix = 'install zn-gate again for the Node.js you use now: run `npm install -g zn-gate`, then `zn hooks install ' + spec.id + '`, in your own terminal';
      } else if (cmd.onPath) {
        // Only absolute PATH entries: a relative one (node_modules/.bin, .) depends on the folder check runs from.
        const absPath = String((ctx.env || process.env).PATH || '').split(path.delimiter).filter((d) => d && path.isAbsolute(d)).join(path.delimiter);
        const found = require('./exe').whichSync(process.platform === 'win32' ? 'zn.cmd' : 'zn', absPath);
        const zn = found ? path.resolve(found) : null;
        if (!zn) { res.problem = 'its hook runs `zn`, and there is no `zn` on your PATH'; res.fix = 'install zn-gate again for the Node.js you use now: run `npm install -g zn-gate`, then `zn hooks install ' + spec.id + '`, in your own terminal'; }
        else if (process.platform !== 'win32') live = { file: zn, args: ['hook', spec.id], env: {} };
        else res.notes.push('the installed hook runs `zn` from your PATH; zn\'s rules were checked directly');
      } else {
        live = { file: cmd.node, args: [cmd.runner, spec.id], env: {} };
      }
    }
  }
  if (spec.id === 'claude-code' && installed && res.where === userFile) {
    // Without onFailure "block", a prompt hook that cannot run lets every prompt through (Claude Code 2.1.295 and later read it).
    const prompt = hookEntries(readJson(userFile)).find((e) => e.event === 'UserPromptSubmit' && parseCommand(e.command, spec.id));
    if (prompt && prompt.onFailure !== 'block') res.notes.push('its prompt hook lets prompts through when it cannot run; run `zn hooks install claude-code` again to have them blocked instead');
  }
  if (spec.id === 'claude-code' && installed && !res.problem) {
    const p = claudePolicy(ctx.home, ctx.env);
    if (p.length) res.problem = oneLine(p[0], 300);
  }
  if (spec.id === 'opencode' && installed) res.notes.push('zn\'s rules were checked; its plugin runs inside OpenCode, so it was not started here');

  if (!installed) {
    const proj = spec.project(ctx.cwd);
    // The project folder can be anyone's repository: read only a regular file, and only so much of it.
    const text = path.resolve(proj) !== path.resolve(userFile) ? require('./audit')._internal.readBounded(proj, 256 * 1024, false).text : null;
    if (text && /zn|runner\.js/.test(text)) {
      res.state = 'project-only';
      res.where = proj;
    }
    return res;
  }
  if (!res.problem && !rulesOk) res.problem = 'zn did not block the read of .env';
  if (!res.problem && live) {
    const a = spawnHook(live.file, live.args, spec.request(ctx.dir, ctx.envFile), live.env, ctx.dir);
    const b = a.ran ? spawnHook(live.file, live.args, spec.request(ctx.dir, ctx.readme), live.env, ctx.dir) : a;
    if (!a.ran) res.problem = 'its hook cannot start (' + a.why + ')';
    else if (a.decision !== 'deny') res.problem = 'the installed hook did not block the read of .env';
    else if (b.decision === 'deny') res.problem = 'the installed hook blocks everything, ordinary files too, so part of zn is missing or broken';
    else res.verified = true;
  }
  res.state = res.problem ? 'not-protected' : 'protected';
  return res;
}

/**
 * check({home, env, cwd}) -> {results, removed}. Never throws for one agent.
 */
async function check(opts = {}) {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-check-'));
  const ctx = { home, env, cwd: opts.cwd || process.cwd(), dir, envFile: path.join(dir, '.env'), readme: path.join(dir, 'README.txt') };
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
  return { results, removed: !fs.existsSync(dir) };
}

/** Plain-language report; returns the exit code (0 when every agent set up is protected). */
function report({ results, removed }, write) {
  const w = write || ((s) => process.stdout.write(s));
  w('\nzn-gate check: does zn stop your coding agent from reading a secret?\n\n');
  w('zn made a test folder with a .env file that holds a fake key, and asked each agent\'s zn hook\n');
  w('to let the agent read it, and an ordinary file next to it. This is what happened:\n\n');
  let setUp = 0;
  let bad = 0;
  for (const r of results) {
    if (r.state === 'not-set-up') {
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
  if (!setUp) {
    w('zn is not set up for any agent yet, so nothing protects your secrets. Install it for your agent:\n');
    w('https://usezn.com/docs/install\n\n');
  } else if (!bad) {
    w('Your agent cannot read secret files such as .env through these tools. Nothing was sent anywhere.\n');
    w('If your agent needs a value from .env, keep it in zn\'s vault instead: `zn env shadow .env`.\n');
    w('More: https://usezn.com/docs/check\n\n');
  } else {
    w('Some agents are not protected (see above). More: https://usezn.com/docs/check\n\n');
  }
  w(removed ? 'The test folder was deleted.\n' : 'The test folder could not be deleted; it holds only the fake key.\n');
  return setUp && !bad ? 0 : 1;
}

module.exports = { check, report, FAKE_LINE, AGENTS, _internal: { hookEntries, matcherCovers, parseCommand, decisionOf, claudePlugin } };
