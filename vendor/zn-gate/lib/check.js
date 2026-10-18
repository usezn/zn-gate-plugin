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

/* A sentence without its final full stop, to quote it inside another one. */
function bare(s) {
  return String(s || '').replace(/[\s.]+$/, '');
}

const RULES_FIX = 'install zn-gate again: run `npm install -g zn-gate` in your own terminal, then run `zn-gate check` again';
const REINSTALL = (id) => 'install zn-gate again for the Node.js you use now: run `npm install -g zn-gate`, then `zn hooks install ' + id + '`, in your own terminal';

/* Absolute path of the `zn` command, searched only in absolute PATH entries; null when there is none. */
function znOnPath(env) {
  // Only absolute PATH entries: a relative one (node_modules/.bin, .) depends on the folder check runs from.
  const absPath = String((env || process.env).PATH || '').split(path.delimiter).filter((d) => d && path.isAbsolute(d)).join(path.delimiter);
  const found = require('./exe').whichSync(process.platform === 'win32' ? 'zn.cmd' : 'zn', absPath);
  return found ? path.resolve(found) : null;
}

/*
 * zn's own hooks in the user's hooks file (`zn hooks install <agent>`), not run yet:
 * {installed, problem, fix, live, notes}. `live` is {file, args, env} when the read hook can be run as the agent runs it.
 */
function cliHooks(spec, ctx, userFile) {
  const out = { installed: false, problem: '', fix: '', live: null, notes: [] };
  const entries = hookEntries(readJson(userFile)).filter((e) => parseCommand(e.command, spec.id));
  out.installed = entries.length > 0;
  if (!out.installed) return out;
  // Set up with `zn hooks install`, so that is also how to repair it (not the plugin: both would run).
  out.fix = 'run `zn hooks install ' + spec.id + '` in your own terminal';
  const read = entries.find((e) => e.event === spec.event && matcherCovers(e.matcher, spec.tool));
  if (!read) {
    out.problem = 'zn\'s hooks are there, but not the one that checks reading files (' + spec.event + ')';
    return out;
  }
  const cmd = parseCommand(read.command, spec.id);
  if (cmd.missing) {
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

/* Runs an installed hook with the two requests: '' when it blocks .env and allows the ordinary file, else the problem. */
function runLive(spec, ctx, live) {
  const a = spawnHook(live.file, live.args, spec.request(ctx.dir, ctx.envFile), live.env, ctx.dir);
  const b = a.ran ? spawnHook(live.file, live.args, spec.request(ctx.dir, ctx.readme), live.env, ctx.dir) : a;
  if (!a.ran) return 'its hook cannot start (' + a.why + ')';
  if (a.decision !== 'deny') return 'the installed hook did not block the read of .env';
  if (b.decision === 'deny') return 'the installed hook blocks everything, ordinary files too, so part of zn is missing or broken';
  return '';
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
  if (spec.id === 'claude-code') {
    const plugin = claudePlugin(ctx.home, ctx.env);
    const hasCliHooks = hookEntries(readJson(userFile)).some((e) => parseCommand(e.command, spec.id));
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
      const pre = ctx.live ? spawnHook(process.execPath, [path.join(plugin.root, 'scripts', 'zn-launch.js'), 'check', 'claude-code'], {}, { CLAUDE_PLUGIN_ROOT: plugin.root }, ctx.dir) : { ran: false };
      const sys = pre.ran && /"systemMessage"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(pre.stdout || '');
      // The launcher's own check message is about the plugin itself (for example a Node.js it does not support).
      if (!res.problem && sys) { res.problem = bare(oneLine(JSON.parse('"' + sys[1] + '"'), 300)); res.pluginFault = true; }
      live = { file: process.execPath, args: [path.join(plugin.root, 'scripts', 'zn-launch.js'), 'hook', 'claude-code'], env: { CLAUDE_PLUGIN_ROOT: plugin.root }, plugin: true };
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
  if (spec.id === 'claude-code' && installed && res.where === userFile) {
    // Without onFailure "block", a prompt hook that cannot run lets every prompt through (Claude Code 2.1.295 and later read it).
    const prompt = hookEntries(readJson(userFile)).find((e) => e.event === 'UserPromptSubmit' && parseCommand(e.command, spec.id));
    if (prompt && prompt.onFailure !== 'block') res.notes.push('its prompt hook lets prompts through when it cannot run; run `zn hooks install claude-code` again to have them blocked instead');
  }
  if (spec.id === 'claude-code' && installed && (!res.problem || res.pluginFault)) {
    const p = claudePolicy(ctx.home, ctx.env);
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
  if (spec.id === 'opencode' && installed) res.notes.push('zn\'s rules were checked; its plugin runs inside OpenCode, so it was not started here');

  if (!installed) {
    // Whether the agent is on this machine at all, so the report offers no setup for an agent that is not there.
    try { res.found = Boolean(adapter.detect({ home: ctx.home, env: ctx.env })); } catch (err) { res.found = true; }
    // `zn hooks install` needs zn-gate installed for the user: run from npx alone, there is no `zn` command yet.
    if (spec.id !== 'claude-code' && !znOnPath(ctx.env)) res.fix = 'run `npm install -g zn-gate`, then `zn hooks install ' + spec.id + '`, in your own terminal';
    const proj = spec.project(ctx.cwd);
    // The project folder can be anyone's repository: read only a regular file, and only so much of it.
    const text = path.resolve(proj) !== path.resolve(userFile) ? require('./audit')._internal.readBounded(proj, 256 * 1024, false).text : null;
    if (text && /zn|runner\.js/.test(text)) {
      res.state = 'project-only';
      res.where = proj;
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

/**
 * check({home, env, cwd, live}) -> {results, removed}. Never throws for one agent.
 * With live: false only the setup is read: no test folder, no rules run, no hook started
 * (each result then has checked: false, and "protected" means set up with no problem found).
 */
async function check(opts = {}) {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const cwd = opts.cwd || process.cwd();
  if (opts.live === false) {
    const ctx = { home, env, cwd, live: false, dir: cwd, codexPolicy: opts.codexPolicy };
    const results = [];
    for (const spec of AGENTS) {
      try {
        results.push({ ...(await checkAgent(spec, ctx)), checked: false });
      } catch (err) {
        results.push({ id: spec.id, name: spec.name, fix: spec.fix, state: 'not-protected', problem: 'zn could not read its setup: ' + oneLine(err && err.message, 200), notes: [], checked: false });
      }
    }
    return { results, removed: true };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-check-'));
  const ctx = { home, env, cwd, live: true, dir, envFile: path.join(dir, '.env'), readme: path.join(dir, 'README.txt'), codexPolicy: opts.codexPolicy };
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
    w('No supported coding agent was found on this machine (Claude Code, Codex CLI, Cursor, OpenCode), so there is nothing to check.\n');
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
  w(removed ? 'The test folder was deleted.\n' : 'The test folder could not be deleted; it holds only the fake key.\n');
  return setUp && !bad ? 0 : 1;
}

module.exports = { check, report, FAKE_LINE, AGENTS, _internal: { hookEntries, matcherCovers, parseCommand, decisionOf, claudePlugin } };
