'use strict';

/**
 * zn-gate init: the guided setup. It finds the coding agents on this machine,
 * checks which ones zn already protects (lib/check.js), and for each one that
 * is not protected shows the one route that protects it:
 *   - Claude Code: the zn-gate plugin (two `claude plugin` commands, or the
 *     same two `/plugin` commands typed in Claude Code when there is no
 *     `claude` command);
 *   - Codex CLI, Cursor, OpenCode: `zn hooks install <agent>`, from a global
 *     install of zn-gate (hooks never point into the npx cache or another
 *     temporary copy, which can be deleted).
 * In your own terminal it offers to run each step, one confirmation each.
 * Without a terminal, or when an AI agent runs it, it only prints the steps,
 * and the agent hooks deny `zn-gate init` to agents (lib/hooks/policy.js), as
 * they deny `zn hooks install`. It ends with `zn-gate check`.
 *
 * Programs are run by absolute path, found only in absolute PATH entries, so
 * a program planted in the current folder (a cloned repository) never runs.
 *
 * The previous behaviour of `init` (wrapping the MCP servers you already use
 * with the zn-gate proxy) is `zn-gate init --wrap-mcp`.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PKG_ROOT = path.join(__dirname, '..');
const VERSION = require('../package.json').version;
const isWin = process.platform === 'win32';

/* zn-gate runs from a temporary copy (npx, pnpm dlx, yarn dlx, bunx) rather than an install that stays. */
function fromTemporaryCopy(dir = __dirname) {
  return /[\\/](?:_npx|dlx(?:-[^\\/]*)?|xfs-[^\\/]*|\.bun[\\/]install[\\/]cache|bunx-[^\\/]*)[\\/]/.test(dir);
}

/* Absolute path of a program, searched only in absolute PATH entries; null when not found. */
function findProgram(name, env) {
  const exe = require('./exe');
  const absPath = String((env || process.env).PATH || '').split(path.delimiter).filter((d) => d && path.isAbsolute(d)).join(path.delimiter);
  const found = exe.whichSync(isWin ? name + '.cmd' : name, absPath) || (isWin ? exe.whichSync(name + '.exe', absPath) : null);
  return found ? path.resolve(found) : null;
}

function samePath(a, b) {
  const norm = (p) => { let r = path.resolve(p); try { r = fs.realpathSync(r); } catch (err) { /* keep it */ } return isWin ? r.toLowerCase() : r; };
  return norm(a) === norm(b);
}

function cmp(a, b) {
  const pa = String(a).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  // 1.9.0-rc.1 comes before 1.9.0.
  const preA = /-/.test(String(a));
  const preB = /-/.test(String(b));
  return preA === preB ? 0 : (preA ? -1 : 1);
}

/* Run a program found by findProgram, with fixed arguments. */
function spawnProgram(file, args, env, extra = {}) {
  const childEnv = { ...env };
  if (isWin) childEnv.NoDefaultCurrentDirectoryInExePath = '1';
  // A .cmd file (npm, claude, zn on Windows) only starts through cmd.exe; its path is absolute and quoted.
  if (isWin && /\.cmd$/i.test(file)) {
    return spawnSync('"' + file + '"', args, { ...extra, env: childEnv, shell: true, windowsHide: true });
  }
  return spawnSync(file, args, { ...extra, env: childEnv, windowsHide: true });
}

/* {npm, prefix, pkgDir, version, zn} of the global npm install of zn-gate, or {} when npm is not found. */
function globalInstall(env) {
  const npm = findProgram('npm', env);
  if (!npm) return {};
  const r = spawnProgram(npm, ['prefix', '-g'], env, { encoding: 'utf8', timeout: 30000 });
  const prefix = r.status === 0 ? String(r.stdout || '').trim() : '';
  if (!prefix || !path.isAbsolute(prefix)) return { npm };
  const pkgDir = isWin ? path.join(prefix, 'node_modules', 'zn-gate') : path.join(prefix, 'lib', 'node_modules', 'zn-gate');
  let version = null;
  try { version = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version || null; } catch (err) { version = null; }
  const zn = isWin ? path.join(prefix, 'zn.cmd') : path.join(prefix, 'bin', 'zn');
  return { npm, prefix, pkgDir, version, zn };
}

/* The plan: {items: [{id, name, found, state, problem, steps}], setup: [step]} ; a step is {label, run: [file, args] | null, manual}. */
async function plan(opts = {}) {
  const { getAdapter } = require('./agents');
  const { check, _internal: { pluginNodeOk } } = require('./check');
  const env = opts.env || process.env;
  const home = opts.home;
  const nodeVersion = opts.nodeVersion || process.versions.node;
  const res = await check({ home, env, cwd: opts.cwd, nodeVersion });
  let temporary = opts.temporary !== undefined ? opts.temporary : fromTemporaryCopy();
  const glob = opts.global || globalInstall(env);
  if (opts.temporary === undefined && !temporary && glob.pkgDir && !samePath(PKG_ROOT, glob.pkgDir)) temporary = true;
  // Without npm, an install inside node_modules (a project dependency) is not used for hooks either.
  if (opts.temporary === undefined && !temporary && !glob.pkgDir && /[\\/]node_modules[\\/]/.test(PKG_ROOT + path.sep)) temporary = true;
  const items = [];
  let needsZn = false;
  for (const r of res.results) {
    const found = r.state !== 'not-set-up' || getAdapter(r.id).detect({ home, env });
    const item = { id: r.id, name: r.name, found, state: r.state, problem: r.problem || '', steps: [] };
    if (found && r.state !== 'protected') {
      // Claude Code set up with zn's own hooks is repaired with them, and with the plugin as well it drops them:
      // installing the plugin on top would run both sets.
      // A broken plugin next to zn's own hooks that do not work either: the hooks are repaired first (below).
      let hooksVerb = r.id !== 'claude-code' ? 'install' : r.via === 'hooks' ? 'install'
        : r.via === 'both' && r.duplicate ? 'uninstall' : r.via === 'both' && r.pluginBroken && r.hooksBroken ? 'install' : null;
      // The plugin needs Node.js 20.12 or later: with an older one it is not installed, and zn's own hooks are set up instead.
      // A plugin that is already installed does not work there either: once the hooks are seen to work, it is turned off.
      let dropPlugin = false;
      if (r.id === 'claude-code' && !pluginNodeOk(nodeVersion) && !hooksVerb && !r.rulesFault && (r.via === 'plugin' || r.state === 'not-set-up')) {
        hooksVerb = 'install';
        dropPlugin = r.via === 'plugin' && !r.pluginOff;
        item.note = dropPlugin
          ? 'Claude Code plugin will be turned off: it needs Node.js 20.12 or later (you have ' + nodeVersion + '); zn\'s hooks will be used instead. Update Node.js to use the plugin.'
          : 'Claude Code plugin skipped: it needs Node.js 20.12 or later (you have ' + nodeVersion + '). zn\'s hooks are set up instead; update Node.js to use the plugin.';
      }
      const disablePlugin = () => {
        const claude = opts.claude !== undefined ? opts.claude : findProgram('claude', env);
        if (claude) return { label: 'turn off the zn-gate plugin (zn\'s own hooks stay)', run: [claude, ['plugin', 'disable', 'zn-gate@usezn']], manual: 'claude plugin disable zn-gate@usezn' };
        return { label: 'do this yourself', run: null, manual: 'in Claude Code, type /plugin disable zn-gate@usezn' };
      };
      if (r.rulesFault) {
        // zn's own rules let the test .env through: zn-gate itself needs repair, whatever runs the hooks.
        item.steps.push({ label: 'first do this yourself', run: null, manual: r.fix });
      } else if (!hooksVerb && r.pluginBroken) {
        // The plugin does not work next to zn's own hooks, which check found working: turn the plugin off and keep the hooks.
        item.steps.push(disablePlugin());
      } else if (!hooksVerb && r.via === 'both') {
        // Something other than the plugin (a Claude Code setting that stops all hooks, zn's rules): neither set is touched.
        item.steps.push({ label: 'first do this yourself', run: null, manual: r.fix });
      } else if (!hooksVerb && r.pluginOff) {
        // Installed but turned off: installing it again would not turn it on.
        const claude = opts.claude !== undefined ? opts.claude : findProgram('claude', env);
        if (claude) item.steps.push({ label: 'turn on the zn-gate plugin', run: [claude, ['plugin', 'enable', 'zn-gate@usezn']], manual: 'claude plugin enable zn-gate@usezn' });
        else item.steps.push({ label: 'do this yourself', run: null, manual: 'in Claude Code, type /plugin enable zn-gate@usezn' });
      } else if (!hooksVerb) {
        const claude = opts.claude !== undefined ? opts.claude : findProgram('claude', env);
        if (claude) {
          item.steps.push({ label: 'add the usezn plugin marketplace', run: [claude, ['plugin', 'marketplace', 'add', 'usezn/zn']], manual: 'claude plugin marketplace add usezn/zn' });
          item.steps.push({ label: 'install the zn-gate plugin', run: [claude, ['plugin', 'install', 'zn-gate@usezn']], manual: 'claude plugin install zn-gate@usezn' });
        } else {
          item.steps.push({ label: 'do this yourself', run: null, manual: 'in Claude Code, type /plugin marketplace add usezn/zn and then /plugin install zn-gate@usezn' });
        }
      } else {
        needsZn = true;
        // This install's own CLI, or, from a temporary copy, the global one (by absolute path).
        const zn = temporary ? (glob.zn || null) : process.execPath;
        const args = temporary ? ['hooks', hooksVerb, r.id] : [path.join(PKG_ROOT, 'bin', 'cli.js'), 'hooks', hooksVerb, r.id];
        const label = hooksVerb === 'uninstall' ? 'remove zn\'s own hooks for ' + r.name + ' (the zn-gate plugin stays)' : 'install zn\'s hooks for ' + r.name;
        item.steps.push({ label, run: zn ? [zn, args] : null, manual: 'zn hooks ' + hooksVerb + ' ' + r.id, needsGlobal: temporary });
        // Only after the hooks are repaired and seen to work: the steps stop at the first one that is skipped or fails,
        // so the plugin is never turned off while the hooks still do not work.
        if (r.pluginBroken || dropPlugin) {
          item.steps.push({ label: 'check that zn\'s hooks for ' + r.name + ' work now', manual: 'zn-gate check (go on only if it says the hooks work)', verify: () => hooksWorkNextToPlugin({ ...opts, nodeVersion }, r.id) });
          const off = disablePlugin();
          if (dropPlugin) off.done = 'Claude Code plugin turned off; zn\'s hooks protect Claude Code. Update Node.js to use the plugin.';
          item.steps.push(off);
        }
      }
    }
    items.push(item);
  }
  const setup = [];
  if (needsZn && temporary) {
    if (glob.version && cmp(glob.version, VERSION) >= 0) {
      // A global install that is the same or newer is used as it is: never downgrade it.
    } else if (glob.npm) {
      setup.push({ label: 'install zn-gate ' + VERSION + ' for your user' + (glob.version ? ' (you have ' + glob.version + ')' : ''), run: [glob.npm, ['install', '-g', 'zn-gate@' + VERSION]], manual: 'npm install -g zn-gate@' + VERSION });
    } else {
      setup.push({ label: 'install zn-gate for your user', run: null, manual: 'npm install -g zn-gate' });
    }
  }
  return { items, setup, temporary };
}

/* After the hooks are repaired next to a broken plugin: '' when check now finds those hooks working, else why not. */
async function hooksWorkNextToPlugin(opts, id) {
  const { check } = require('./check');
  const r = (await check({ home: opts.home, env: opts.env || process.env, cwd: opts.cwd, nodeVersion: opts.nodeVersion })).results.find((x) => x.id === id);
  if (!r) return 'zn-gate check did not report it';
  if (r.state === 'protected' || (r.pluginBroken && !r.hooksBroken)) return '';
  return r.problem || 'zn-gate check did not find them working';
}

/* Run one step in the user's terminal (inherits stdio). Absolute program path and fixed arguments only. */
function runStep(step, env) {
  const [file, args] = step.run;
  const r = spawnProgram(file, args, env, { stdio: 'inherit' });
  return !r.error && r.status === 0;
}

/**
 * guide({home, env, cwd, stdin, write, confirm, run}) -> exit code.
 * `confirm(question)` resolves true/false; it is asked only when a person runs init in a terminal.
 */
async function guide(opts = {}) {
  const env = opts.env || process.env;
  const w = opts.write || ((s) => process.stdout.write(s));
  const tty = require('./broker/tty');
  const stdin = opts.stdin || process.stdin;
  const agent = tty.agentDetected(env, opts);
  const interactive = Boolean(stdin.isTTY) && !agent;
  const { items, setup } = await plan(opts);

  w('\nzn-gate init: set up zn for the coding agents on this machine\n\n');
  const todo = items.filter((i) => i.steps.length);
  for (const i of items) {
    if (!i.found) w(`  -  ${i.name.padEnd(12)} not found on this machine\n`);
    else if (i.state === 'protected') w(`  OK ${i.name.padEnd(12)} already protected by zn\n`);
    else w(`  >  ${i.name.padEnd(12)} ${i.state === 'not-protected' ? 'not protected: ' + i.problem : 'not set up yet'}\n`);
  }
  for (const i of items) if (i.note && i.steps.length) w(`${i.note}\n`);
  w('\n');
  const tail = () => w('(To wrap the MCP servers in your agent configs, which `zn-gate init` used to do: `zn-gate init --wrap-mcp`.)\n');
  if (!items.some((i) => i.found)) {
    w('No supported coding agent was found (Claude Code, Codex CLI, Cursor, OpenCode). Nothing was changed.\n');
    w('Install one, then run `npx -y zn-gate init` again. Other editors: https://usezn.com/docs/install\n');
    tail();
    return 1;
  }
  if (!todo.length) {
    w('Every agent found is already protected. To see it block a test secret: `zn-gate check`\n');
    return 0;
  }
  const allSteps = [...setup, ...todo.flatMap((i) => i.steps)];
  if (!interactive) {
    w((agent
      ? 'An AI agent is running this, so zn only prints the steps: installing hooks is your decision.'
      : 'This is not an interactive terminal, so zn only prints the steps.') + ' Nothing was changed.\n');
    w('Run them in your own terminal:\n\n');
    for (const s of allSteps) w(`  ${s.manual}\n`);
    w('\nThen check that it works: `npx -y zn-gate check`\n');
    tail();
    return 1;
  }
  const ask = opts.confirm || ((q) => tty.confirm(q, { stdin, stderr: process.stderr }));
  const run = opts.run || runStep;
  let skipped = 0;
  let globalReady = !setup.length;
  for (const s of setup) {
    if (!s.run) { w(`First, ${s.label}: ${s.manual}\n`); skipped++; break; }
    if (!(await ask(`${s.label}: run \`${s.manual}\`?`))) { w(`  skipped. You can run it later: ${s.manual}\n`); skipped++; break; }
    if (!run(s, env)) { w(`  that did not finish. Run it yourself: ${s.manual}\n`); skipped++; break; }
    globalReady = true;
  }
  let glob = null;
  for (const i of todo) {
    w(`${i.name}:\n`);
    for (const s of i.steps) {
      let step = s;
      if (s.needsGlobal) {
        if (!globalReady) { w(`  needs zn-gate installed for your user first. Later: ${s.manual}\n`); skipped++; break; }
        if (!s.run) {
          glob = glob || globalInstall(env);
          step = glob.zn && fs.existsSync(glob.zn) ? { ...s, run: [glob.zn, ['hooks', 'install', i.id]] } : s;
        }
      }
      if (s.verify) {
        const why = await s.verify();
        if (why) { w(`  ${s.label}: not yet (${why}). The zn-gate plugin was left on.\n`); skipped++; break; }
        w(`  ${s.label}: yes\n`);
        continue;
      }
      if (!step.run) { w(`  ${s.label}: ${s.manual}\n`); skipped++; break; }
      if (!(await ask(`  ${s.label}: run \`${s.manual}\`?`))) { w(`  skipped. You can run it later: ${s.manual}\n`); skipped++; break; }
      if (!run(step, env)) { w(`  that did not finish. Run it yourself: ${s.manual}\n`); skipped++; break; }
      if (step.done) w(`  ${step.done}\n`);
    }
  }
  w('\n');
  const { check, report } = require('./check');
  const code = report(await check({ home: opts.home, env, cwd: opts.cwd, nodeVersion: opts.nodeVersion }), w);
  return skipped ? 1 : code;
}

module.exports = { guide, plan, fromTemporaryCopy, _internal: { findProgram, globalInstall, cmp, runStep, spawnProgram } };
