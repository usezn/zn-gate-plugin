'use strict';
/**
 * zn audit [path] [--format text|json|sarif] [--output <file>]
 *          [--fail-on low|medium|high|critical|none]
 *          [--agents claude,codex,cursor,opencode,amazonq,copilot,gemini,all] [--include-home]
 *
 * Exit codes: 0 nothing at or above --fail-on, 1 findings at or above it,
 * 2 usage or runtime error.
 */

const fs = require('fs');
const path = require('path');
const { audit, AGENTS } = require('./index');
const report = require('./report');

const USAGE = 'usage: zn audit [path] [--format text|json|sarif] [--output <file>] [--fail-on low|medium|high|critical|none] [--agents claude,codex,cursor,opencode,amazonq,copilot,gemini,all] [--include-home]';
const FORMATS = ['text', 'json', 'sarif'];
const FAIL_ON = ['low', 'medium', 'high', 'critical', 'none'];

class UsageError extends Error {}

// `zn audit` showed the secret-use log in 1.5.
const LOG_MOVED = '`zn audit` reviews agent configs; the secret-use log is `zn vault log` (alias `zn secret log`)';

function parseArgs(args) {
  const opts = { path: null, format: 'text', output: null, failOn: 'high', agents: ['all'], includeHome: false, help: false };
  const takesValue = { '--format': 'format', '--output': 'output', '-o': 'output', '--fail-on': 'failOn', '--agents': 'agents' };
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === '-h' || a === '--help') { opts.help = true; continue; }
    if (a === '--since' || a.startsWith('--since=')) throw new UsageError(LOG_MOVED);
    if (a === '--include-home') { opts.includeHome = true; continue; }
    const eq = a.indexOf('=');
    const name = a.startsWith('--') && eq > 0 ? a.slice(0, eq) : a;
    if (takesValue[name]) {
      let v;
      if (name !== a) v = a.slice(eq + 1);
      else {
        v = args[i + 1];
        i++;
        if (v === undefined || String(v).startsWith('--')) throw new UsageError(name + ' needs a value');
      }
      opts[takesValue[name]] = String(v);
      continue;
    }
    if (a.startsWith('-') && a !== '-') throw new UsageError('unknown option ' + a);
    if (opts.path !== null) throw new UsageError('only one path can be audited at a time');
    opts.path = a;
  }
  opts.format = opts.format.toLowerCase();
  if (!FORMATS.includes(opts.format)) throw new UsageError('--format must be one of ' + FORMATS.join(', '));
  opts.failOn = opts.failOn.toLowerCase();
  if (!FAIL_ON.includes(opts.failOn)) throw new UsageError('--fail-on must be one of ' + FAIL_ON.join(', '));
  if (typeof opts.agents === 'string') opts.agents = opts.agents.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (!opts.agents.length) throw new UsageError('--agents needs at least one agent');
  for (const a of opts.agents) {
    if (a !== 'all' && !AGENTS.includes(a)) throw new UsageError('unknown agent ' + JSON.stringify(a) + ' (known: ' + AGENTS.join(', ') + ', all)');
  }
  return opts;
}

async function main(args, ioIn) {
  const io = Object.assign({ stdout: process.stdout, stderr: process.stderr, cwd: process.cwd(), env: process.env, home: undefined }, ioIn || {});
  let opts;
  try {
    opts = parseArgs(args || []);
  } catch (err) {
    io.stderr.write('zn audit: ' + err.message + '\n' + USAGE + '\n');
    return 2;
  }
  if (opts.help) {
    io.stdout.write(USAGE + '\n\nReviews the agent configuration in a repository (hooks, MCP servers, endpoints,\npermissions, instructions) without running anything. Docs: docs/audit.md\n');
    return 0;
  }
  try {
    const root = path.resolve(io.cwd, opts.path || '.');
    let st;
    try { st = fs.statSync(root); } catch (_) {
      throw new Error(opts.path === 'log' ? LOG_MOVED : 'path not found: ' + (opts.path || '.'));
    }
    if (!st.isDirectory()) throw new Error('not a directory: ' + (opts.path || '.'));
    const result = audit({ root, agents: opts.agents, includeHome: opts.includeHome, home: io.home, env: io.env });
    const toolVersion = require('../../package.json').version;
    const meta = {
      toolVersion,
      failOn: opts.failOn,
      displayRoot: opts.path || '.',
      color: !opts.output && opts.format === 'text' && io.stdout.isTTY === true && !io.env.NO_COLOR,
    };
    const text = opts.format === 'json' ? report.toJson(result, meta) : opts.format === 'sarif' ? report.toSarif(result, meta) : report.toText(result, meta);
    if (opts.output) {
      fs.writeFileSync(path.resolve(io.cwd, opts.output), text, 'utf8');
      const s = report.summarize(result, opts.failOn);
      io.stderr.write('zn audit: ' + s.findings + ' finding' + (s.findings === 1 ? '' : 's') + ' written to ' + opts.output + '\n');
    } else {
      io.stdout.write(text);
    }
    return report.summarize(result, opts.failOn).failed ? 1 : 0;
  } catch (err) {
    io.stderr.write('zn audit: ' + err.message + '\n');
    return 2;
  }
}

module.exports = { main, parseArgs, USAGE };
