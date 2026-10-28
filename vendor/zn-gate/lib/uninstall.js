'use strict';

/**
 * zn-gate uninstall: take zn-gate out of this computer in one step.
 *
 * It finds what is set up with the same code that `zn-gate check`, `zn hooks`
 * and `zn-gate init` use, prints the plan, and (only for a person in a
 * terminal, exactly like `zn hooks install`) removes it:
 *   - the zn-gate plugin of Claude Code;
 *   - zn's hooks of every agent, for your user and for the current project;
 *   - MCP servers wrapped by `zn-gate init --wrap-mcp` (the saved copy is put back);
 *   - the vault, only after a second, separate confirmation (default no).
 * .env files that `zn env shadow` filled with markers are never edited: the
 * values live in the vault, and `zn env unshadow` is what puts them back.
 * It ends with `zn-gate check`.
 *
 * `--dry-run` prints the plan and changes nothing.
 */

const fs = require('fs');
const path = require('path');

const USAGE = 'usage: zn-gate uninstall [--dry-run]';
const PLUGIN_ID = 'zn-gate@usezn';

function out(io, line) { io.stdout.write(line + '\n'); }

/* Where zn's hooks sit in one agent's project folder, or null. Reuses the detection of zn-gate check. */
function projectHooks(spec, cwd, userFile) {
  const chk = require('./check')._internal;
  const file = spec.project(cwd);
  if (path.resolve(file) === path.resolve(userFile)) return null;
  let text = '';
  try { if (fs.lstatSync(file).isFile()) text = fs.readFileSync(file, 'utf8'); } catch (_) { return null; }
  if (spec.id === 'opencode') return /\/zn-gate\/lib\/hooks\/runner\.js"|"hook", "opencode"/.test(text) ? file : null;
  let tree = null;
  try { tree = JSON.parse(text.replace(/^\uFEFF/, '')); } catch (_) { return null; }
  return chk.hookEntries(tree, spec.id).some((e) => chk.parseCommand(e.command, spec.id)) ? file : null;
}

/* .env style files of the project folder that hold zn markers (names only). */
function shadowedFiles(cwd) {
  const found = [];
  let names = [];
  try { names = fs.readdirSync(cwd); } catch (_) { return found; }
  for (const n of names) {
    if (!/^\.env(\..+)?$/.test(n)) continue;
    const f = path.join(cwd, n);
    try {
      if (!fs.lstatSync(f).isFile() || fs.statSync(f).size > 1024 * 1024) continue;
      if (/__ZN_[A-Z0-9_]+__/.test(fs.readFileSync(f, 'utf8'))) found.push(f);
    } catch (_) { /* unreadable: skip */ }
  }
  return found;
}

/* MCP configs with servers wrapped by `zn-gate init --wrap-mcp`, and the saved copy to put back. */
function wrappedConfigs(envList) {
  const init = require('./init');
  const list = [];
  for (const e of init.scanEnvironments(envList || null)) {
    if (!e.exists) continue;
    // zn's own "secrets" server also names zn-gate; only a server wrapped with `shield` counts.
    const wrapped = e.servers.filter((s) => s.shielded && !s.error && /\bshield\b/.test([s.command || '', ...(s.args || [])].join(' ')));
    if (!wrapped.length) continue;
    // Same pick and same safety checks as the restore itself (init.latestBackup / resolveConfig):
    // the file named in the plan is the file that is put back; an unsafe config is not offered.
    const unsafe = init.resolveConfig(e.filePath, e.scope).reason || null;
    const backup = unsafe ? null : init.latestBackup(e.filePath, e.scope);
    list.push({ env: e, name: e.name, file: e.filePath, servers: wrapped.length, backup, unsafe });
  }
  return list;
}

/**
 * What is set up: {agents, wrapped, shadowed, vault}. Read only.
 * opts: home, env, cwd, envList (tests).
 */
async function plan(opts = {}) {
  const home = opts.home || require('os').homedir();
  const env = opts.env || process.env;
  const cwd = opts.cwd || process.cwd();
  const zc = require('./check');
  const { getAdapter } = require('./agents');
  // Setup only: nothing is run, and the Node.js version the plugin needs is not asked here.
  const res = await zc.check({ home, env, cwd, live: false, pluginNode: { ok: true, unknown: false } });
  const agents = [];
  for (const r of res.results) {
    const spec = zc.AGENTS.find((a) => a.id === r.id);
    const userFile = spec.file(getAdapter(r.id), { home, env });
    const a = { id: r.id, name: r.name, userHooks: null, projectHooks: null, plugin: null };
    if (r.via === 'hooks' || r.via === 'both') a.userHooks = userFile;
    if (r.id === 'claude-code') {
      const p = zc._internal.claudePlugin(home, env);
      if (p.root) a.plugin = p.root;
    }
    a.projectHooks = projectHooks(spec, cwd, userFile);
    if (a.userHooks || a.projectHooks || a.plugin) agents.push(a);
  }
  const vaultOpts = env.ZN_HOME ? { home: env.ZN_HOME } : (opts.home ? { home: path.join(home, '.zn') } : {});
  const store = require('./vault/store');
  const purge = require('./vault/purge');
  const found = purge.targets(vaultOpts);
  return {
    agents,
    wrapped: wrappedConfigs(opts.envList),
    shadowed: shadowedFiles(cwd),
    vault: { exists: found.files.length > 0, home: store.paths(vaultOpts).home, lines: purge.describe(found, vaultOpts) },
    vaultOpts,
  };
}

function isEmpty(p) {
  return !p.agents.length && !p.wrapped.length && !p.vault.exists && !p.shadowed.length;
}

function printPlan(p, io) {
  out(io, '');
  out(io, 'zn-gate uninstall: what zn-gate set up on this computer');
  out(io, '');
  if (isEmpty(p)) {
    out(io, 'Nothing from zn-gate was found for your user or this folder.');
    return;
  }
  if (p.agents.length || p.wrapped.length) out(io, 'Will be removed:');
  for (const a of p.agents) {
    out(io, '  ' + a.name);
    if (a.plugin) out(io, '    - the zn-gate plugin (' + a.plugin + ')');
    if (a.userHooks) out(io, '    - zn\'s hooks for your user (and its "secrets" MCP server, if listed): ' + a.userHooks);
    if (a.projectHooks) out(io, '    - zn\'s hooks for this project: ' + a.projectHooks);
  }
  if (p.wrapped.length) {
    out(io, '  MCP servers wrapped by zn-gate init --wrap-mcp');
    for (const w of p.wrapped) {
      out(io, '    - ' + w.name + ' (' + w.servers + ' wrapped): ' + (w.backup
        ? w.file + ' goes back to the copy saved before wrapping (' + w.backup + '); changes made to that file since are lost'
        : w.file + (w.unsafe ? ' cannot be restored safely (' + w.unsafe + '), so it is left as it is' : ' has no saved copy, so it is left as it is') + ': remove the "zn-gate shield" wrapping by hand'));
    }
  }
  if (p.vault.exists) {
    out(io, 'Asked separately at the end (default no):');
    out(io, '  The vault in ' + p.vault.home + ': your stored secrets. Deleting it cannot be undone.');
    out(io, '  If you say yes, all of this is deleted:');
    for (const l of p.vault.lines) out(io, '    - ' + l);
  }
  if (p.shadowed.length) {
    out(io, 'Left alone:');
    for (const f of p.shadowed) out(io, '  - ' + f + ' holds zn markers instead of values. The values are in the vault; run `zn env unshadow` first if you want them back in the file.');
  }
}

function pluginStep(io) {
  const ig = require('./init-guide')._internal;
  const claude = io.claude !== undefined ? io.claude : ig.findProgram('claude', io.env);
  return claude
    ? { run: [claude, ['plugin', 'uninstall', PLUGIN_ID]], manual: 'claude plugin uninstall ' + PLUGIN_ID, exec: ig.runStep }
    : { run: null, manual: 'in Claude Code, type /plugin uninstall ' + PLUGIN_ID, exec: ig.runStep };
}

async function removeVault(p, io) {
  const daemon = require('./vault/daemon');
  const policy = require('./team/policy');
  const o = p.vaultOpts;
  const f = policy.paths(o);
  if ([f.teamFile, f.policyFile].some((x) => fs.existsSync(x))) {
    out(io, 'The vault was kept: this computer belongs to a zn Team organization and its controls are kept inside the vault. Ask your administrator.');
    return 'failed';
  }
  if (await daemon.isRunning(o)) {
    out(io, 'The vault was kept: it is unlocked. Run `zn lock`, then `zn-gate uninstall` again.');
    return 'failed';
  }
  // Files first, the key last: if a file cannot be removed, the key stays and what is left still opens.
  // Every backup, token map and session file goes too, and a second look checks that none is left.
  const purge = require('./vault/purge');
  const r = await purge.removeAll(o);
  if (r.left.length) {
    out(io, 'The vault was not fully deleted. These files could not be removed:');
    for (const f of r.left) out(io, '  - ' + f);
    out(io, 'The vault key in your system keychain was kept, so what is left of the vault can still be opened. Delete those files by hand (or fix their permissions) and run `zn-gate uninstall` again.');
    return 'failed';
  }
  const problem = purge.keyProblem(r);
  if (problem) {
    out(io, 'The vault files are gone, but ' + problem.charAt(0).toLowerCase() + problem.slice(1));
    return 'failed';
  }
  out(io, 'Vault deleted.');
  const note = purge.keyNote(r);
  if (note) out(io, note);
  return true;
}

/**
 * Returns the exit code. io: stdin, stdout, stderr, env, cwd, home, confirm(question), human,
 * claude (path or null), run(step, env), envList (tests).
 */
async function run(args, io) {
  let dryRun = false;
  const deps = require('./deps');
  for (const a of args) {
    if (a === '--dry-run') dryRun = true;
    else throw deps.znError('ZN_USAGE', (a.startsWith('-') ? 'unknown option ' + a.slice(0, 40).replace(/[^\x20-\x7e]/g, '?') : 'unexpected argument') + '. ' + USAGE);
  }
  process.env.ZN_STATS = 'off';
  const p = await plan({ home: io.home, env: io.env, cwd: io.cwd, envList: io.envList });
  printPlan(p, io);
  if (isEmpty(p)) return 0;
  if (dryRun) { out(io, ''); out(io, 'This was a dry run: nothing was changed.'); return 0; }
  out(io, '');
  // Same rule as `zn hooks install`: a person at a terminal, never an agent or a script.
  const tty = require('./broker/tty');
  if (!io.human) tty.requireHuman('zn-gate uninstall', io);
  let failed = 0;
  const ask = io.confirm || ((q) => tty.confirm(q, { stdin: io.stdin, stderr: io.stderr }));
  if (p.agents.length || p.wrapped.length) {
    if (!(await ask('Remove what is listed above?'))) { out(io, 'Nothing was changed.'); return 1; }
    // Wrapped MCP first: putting a saved copy back must not undo the hook removal that follows.
    const withBackup = p.wrapped.filter((w) => w.backup);
    if (withBackup.length) {
      const r = require('./init').configureEnvironments({ revert: true, envList: withBackup.map((w) => w.env) });
      for (const act of r.actions) {
        out(io, '  ' + act.env + ': ' + (act.status === 'reverted' ? 'put back from ' + act.from : act.status));
        if (act.status !== 'reverted') failed++;
      }
    }
    const { getAdapter } = require('./agents');
    for (const a of p.agents) {
      const adapter = getAdapter(a.id);
      for (const scope of ['user', 'project']) {
        if (!(scope === 'user' ? a.userHooks : a.projectHooks)) continue;
        try {
          const rep = adapter.uninstall({ scope, projectDir: io.cwd, home: io.home, env: io.env, mcp: true, removeLauncher: true });
          out(io, '  ' + a.name + ': removed zn\'s hooks (' + scope + ') in ' + rep.settings + (rep.backup ? ' (copy saved: ' + rep.backup + ')' : ''));
        } catch (err) {
          out(io, '  ' + a.name + ': could not remove the ' + scope + ' hooks: ' + (err && err.message ? err.message : err));
          failed++;
        }
      }
      if (a.plugin) {
        const s = pluginStep(io);
        if (!s.run) { out(io, '  ' + a.name + ': do this yourself: ' + s.manual); failed++; }
        else if ((io.run || s.exec)(s, io.env)) out(io, '  ' + a.name + ': plugin removed');
        else { out(io, '  ' + a.name + ': the plugin was not removed. Run it yourself: ' + s.manual); failed++; }
      }
    }
    // Look again: a config wrapped twice, or one with no saved copy, is still wrapped.
    const still = wrappedConfigs(io.envList);
    if (still.length) {
      out(io, '');
      out(io, 'Still wrapped by zn-gate shield (do this yourself):');
      for (const w of still) out(io, '  - ' + w.name + ' (' + w.servers + ' server' + (w.servers === 1 ? '' : 's') + ') in ' + w.file + ': open the file and put the original command of each server back in place of the zn-gate shield wrapper.');
      failed++;
    }
  }
  if (p.vault.exists) {
    out(io, '');
    out(io, 'Your vault still holds your secrets (' + p.vault.home + ').' + (p.shadowed.length ? ' The .env files with markers need it.' : ''));
    out(io, 'If you answer yes, all of this is deleted for good:');
    for (const l of p.vault.lines) out(io, '  - ' + l);
    if (await ask('Delete the vault too? Every secret in it is lost for good.')) { if ((await removeVault(p, io)) === 'failed') failed++; }
    else out(io, 'The vault was kept.');
  }
  out(io, '');
  const zc = require('./check');
  zc.report(await zc.check({ home: io.home, env: io.env, cwd: io.cwd }), (s) => io.stdout.write(s));
  out(io, '');
  if (failed) out(io, 'Not everything was removed: ' + failed + (failed === 1 ? ' step' : ' steps') + ' did not finish (see above). Exit code 1.');
  out(io, 'Last step, to remove the program itself: npm uninstall -g zn-gate');
  return failed ? 1 : 0;
}

module.exports = { run, plan, printPlan, USAGE };
