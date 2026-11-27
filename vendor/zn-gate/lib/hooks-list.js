'use strict';

/**
 * zn-gate check --hooks: lists every zn hook that is installed for an agent, and says for each one whether it is
 * OK, STALE (works, but was written by an older zn-gate or points at an older one) or BROKEN (cannot run, is
 * turned off, is written twice, or is not a hook zn can read), with the command that fixes it.
 *
 * Read only: it reads the agents' configuration files and the launcher files, runs no hook and writes nothing.
 * It reuses the readers of check.js, so what counts as installed is the same in both.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_BYTES = 1024 * 1024;

function readText(file) {
  let st;
  try { st = fs.statSync(file); } catch (err) { return null; }
  if (!st.isFile()) return null;
  if (st.size > MAX_BYTES) return { tooBig: true, text: '' };
  try { return { text: fs.readFileSync(file, 'utf8').replace(/^﻿/, '') }; } catch (err) { return { unreadable: true, text: '' }; }
}

function shorten(command, max = 110) {
  const c = String(command).replace(/\s+/g, ' ').trim();
  if (/-EncodedCommand|^powershell(\.exe)? /i.test(c) || c.length > 400) return 'zn PowerShell hook script';
  return c.length > max ? c.slice(0, max - 3) + '...' : c;
}

/** Whether the launcher text is the one this zn-gate would write for the same Node.js and runner. */
function launcherIsCurrent(agentId, cmd) {
  try {
    const launcher = require('./agents/launcher');
    const text = fs.readFileSync(cmd.launcher, 'utf8');
    if (typeof cmd.sha !== 'string' || cmd.files === null || cmd.files === undefined) return false;
    const kept = require('./agents/refresh')._launcherOptions(text);
    const next = launcher.unixScript(agentId, cmd.node, cmd.runner, { ...kept, runnerDigest: cmd.sha, manifest: cmd.files === '-' ? '' : cmd.files, platform: process.platform });
    return next === text;
  } catch (err) {
    return true; // not comparable: never report what could not be read as stale
  }
}

function fixFor(id, scope) {
  return 'zn hooks install ' + id + (scope === 'project' ? ' --project' : '');
}

/** Rows for one JSON hooks file: [{event, matcher, command, status, reason}]. */
function jsonFileRows(spec, ctx, file, scope, text) {
  const { hookEntries, parseCommand } = require('./check')._internal;
  const cfg = require('./agents/config-file');
  const rows = [];
  let tree;
  try { tree = JSON.parse(text); } catch (err) { tree = undefined; }
  if (tree === undefined || tree === null || typeof tree !== 'object') {
    return [{ event: '-', command: '', status: 'BROKEN', reason: 'the file is not valid JSON, so ' + spec.name + ' cannot read its hooks and zn cannot add its own', scope }];
  }
  const ours = [];
  for (const e of hookEntries(tree, spec.id, { withDisabled: true })) {
    const parsed = parseCommand(e.command, spec.id);
    if (parsed) ours.push({ e, parsed });
    else if (cfg.isOurs(e.command, spec.id)) rows.push({ event: e.event, matcher: e.matcher, command: e.command, status: 'BROKEN', reason: 'it looks like a zn hook but not the exact form zn writes, so zn cannot check it', scope });
  }
  const byEvent = new Map();
  for (const o of ours) byEvent.set(o.e.event, (byEvent.get(o.e.event) || 0) + 1);
  for (const { e, parsed } of ours) {
    const row = { event: e.event, matcher: e.matcher, command: e.command, status: 'OK', reason: '', scope };
    if (byEvent.get(e.event) > 1) {
      row.status = 'BROKEN';
      row.reason = 'zn\'s hook is written ' + byEvent.get(e.event) + ' times for this event, so every call is checked more than once';
    } else {
      const h = ctx.cliHooks({ ...spec, event: e.event, tool: null }, ctx, file, [e]);
      if (h.problem) {
        row.status = /starts powershell\.exe by name/i.test(h.problem) ? 'STALE' : 'BROKEN';
        row.reason = h.problem;
      } else if (parsed.modified) {
        row.status = 'STALE';
        row.reason = 'its start guard is not the one this zn-gate writes';
      } else if (h.notes.length) {
        row.status = 'STALE';
        row.reason = h.notes[0];
      } else if (parsed.launcher && !parsed.unreadable && !launcherIsCurrent(spec.id, parsed)) {
        row.status = 'STALE';
        row.reason = 'its launcher script was written by an older zn-gate';
      }
    }
    rows.push(row);
  }
  return rows;
}

function opencodeRows(file, scope, text) {
  if (!/zn hooks install opencode|zn-gate\/lib\/hooks\/runner\.js|"hook", "opencode"/.test(text)) return [];
  const row = { event: 'tool.execute.before', command: 'plugin ' + file, status: 'OK', reason: '', scope };
  const grab = (name) => {
    const m = new RegExp('^const ' + name + ' = ("[^"\\n]*")', 'm').exec(text);
    try { return m ? JSON.parse(m[1]) : null; } catch (err) { return null; }
  };
  if (scope === 'user') {
    const node = grab('NODE');
    const runner = grab('RUNNER');
    const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch (err) { return false; } };
    if (!node || !runner) { row.status = 'BROKEN'; row.reason = 'the plugin does not name the Node.js and zn-gate files it runs'; }
    else if (!isFile(node)) { row.status = 'BROKEN'; row.reason = 'its Node.js (' + node + ') is no longer there'; }
    else if (!isFile(runner)) { row.status = 'BROKEN'; row.reason = 'its zn-gate files (' + runner + ') are no longer there'; }
  }
  return [row];
}

/**
 * listHooks({home, env, cwd}) -> {agents: [{id, name, files: [{file, scope, rows}]}], counts: {ok, stale, broken}}.
 * Never throws for one agent. Only agents with a hooks file that holds zn hooks (or a file zn cannot read) appear.
 */
function listHooks(opts = {}) {
  const check = require('./check');
  const { getAdapter } = require('./agents');
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const cwd = opts.cwd || process.cwd();
  const ctx = { home, env, cwd, live: false, dir: cwd, cliHooks: check._internal.cliHooks };
  const agents = [];
  const counts = { ok: 0, stale: 0, broken: 0 };
  for (const spec of check.AGENTS) {
    const entry = { id: spec.id, name: spec.name, files: [] };
    try {
      const adapter = getAdapter(spec.id);
      const seen = new Set();
      for (const [file, scope] of [[spec.file(adapter, { home, env }), 'user'], [spec.project(cwd), 'project']]) {
        const key = path.resolve(file);
        if (seen.has(key)) continue;
        seen.add(key);
        const read = readText(file);
        if (!read) continue;
        let rows;
        if (read.tooBig || read.unreadable) rows = [{ event: '-', command: '', status: 'BROKEN', reason: 'the file cannot be read (too large or no access)', scope }];
        else if (spec.id === 'opencode') rows = opencodeRows(file, scope, read.text);
        else rows = jsonFileRows(spec, ctx, file, scope, read.text);
        if (!rows.length) continue;
        for (const r of rows) {
          r.fix = fixFor(spec.id, scope);
          counts[r.status.toLowerCase()]++;
        }
        entry.files.push({ file, scope, rows });
      }
    } catch (err) {
      entry.files.push({ file: '-', scope: 'user', rows: [{ event: '-', command: '', status: 'BROKEN', reason: 'zn could not read its setup: ' + String(err && err.message).slice(0, 160), fix: fixFor(spec.id, 'user') }] });
      counts.broken++;
    }
    if (entry.files.length) agents.push(entry);
  }
  return { agents, counts };
}

/** Plain-language report; returns the exit code (0 when every hook is OK or none is installed). */
function report({ agents, counts }, write) {
  const { winCommandText } = require('./zn-command');
  const out = write || ((s) => process.stdout.write(s));
  const w = (s) => out(winCommandText(s));
  w('\nzn hooks installed on this machine (nothing was run or changed):\n');
  if (!agents.length) {
    w('\n  None found. To set zn up, run `npx -y zn-gate init` in your own terminal.\n\n');
    return 0;
  }
  for (const a of agents) {
    for (const f of a.files) {
      w('\n' + a.name + ' (' + f.scope + '): ' + f.file + '\n');
      const why = new Map();
      for (const r of f.rows) {
        const what = (r.event + (r.matcher ? ' [' + r.matcher + ']' : '')).trim();
        w('  ' + r.status.padEnd(6) + ' ' + what + (r.command ? '  ' + shorten(r.command) : '') + '\n');
        if (r.status !== 'OK' && !why.has(r.status + r.reason)) why.set(r.status + r.reason, r);
      }
      // One explanation per distinct problem, not one per event.
      for (const r of why.values()) {
        w('  ' + r.status + ': ' + r.reason + '.\n');
        w('    Fix: run `' + r.fix + '` in your own terminal.\n');
      }
    }
  }
  w('\n' + counts.ok + ' OK, ' + counts.stale + ' stale, ' + counts.broken + ' broken.\n');
  if (counts.stale || counts.broken) w('To remove the hooks of an agent instead, run `zn hooks uninstall <agent>`.\n');
  w('\n');
  return counts.stale || counts.broken ? 1 : 0;
}

/**
 * Warning for `zn-gate status`: one block naming every agent whose installed hook was written by an older
 * zn-gate (STALE), with the one command that refreshes it. Empty string when nothing is stale. Read only.
 * Broken hooks are left to `zn-gate check --hooks`.
 */
function staleWarning(opts = {}) {
  const res = opts.result || listHooks(opts);
  const todo = [];
  for (const a of res.agents) {
    for (const f of a.files) {
      const stale = f.rows.filter((r) => r.status === 'STALE');
      if (stale.length) todo.push({ name: a.name, scope: f.scope, fix: stale[0].fix });
    }
  }
  if (!todo.length) return '';
  let out = '  Hooks           : ' + (todo.length === 1 ? 'a hook was' : todo.length + ' hooks were') + ' installed by an older zn-gate and should be refreshed:\n';
  for (const t of todo) out += '    ' + t.name + ' (' + t.scope + '): run `' + t.fix + '`\n';
  return out + '\n';
}

/**
 * One line for the end of a plain `zn-gate check`: how many installed hooks are OK, stale or broken, from the same
 * listHooks result as `check --hooks`. Returns '' when no agent hook is installed.
 */
function summaryLine({ agents, counts }) {
  if (!agents.length) return '';
  return 'Hooks: ' + counts.ok + ' OK, ' + counts.stale + ' stale, ' + counts.broken + ' broken. Run zn-gate check --hooks for details.';
}

module.exports = { listHooks, report, staleWarning, summaryLine };
