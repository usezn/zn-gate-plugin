'use strict';

/**
 * zn run [--secrets A,B] -- <command> [args...]
 *
 * Env mode of the secrets broker (the MVP has no egress proxy):
 *   - --secrets NAME sets env NAME=value in the child, and named markers
 *     (__ZN_<NAME>__) in the environment zn run inherits are replaced by the
 *     real values. Nothing else is changed: values only ever exist inside the
 *     child's environment.
 *   - A marker in the command's arguments is refused, never filled in: an
 *     argument is visible to every process of the same user (ps,
 *     /proc/<pid>/cmdline) and to command-line loggers. The environment is the
 *     only channel zn run uses. Processes of the same user can read it too
 *     (/proc/<pid>/environ), but it is not listed by ps or logged with the
 *     command line.
 *   - Only for secrets in mode "env" whose allowCommands matches the command.
 *   - The first use of each (secret, command) pair needs your confirmation
 *     on the vault's own channel (dialog or `zn unlock --foreground`).
 *   - The command name is resolved once, to the real path of one file. That
 *     file is opened, its descriptor fingerprinted and checked against the
 *     approval, checked again right before start, and then started by that
 *     path (on Linux, a native program is started through the descriptor
 *     itself), never by looking the name up on PATH again.
 *   - The child's stdout/stderr are masked: the value and its base64, hex
 *     and url-encoded forms are printed as the marker.
 *   - Fail-closed: any policy or vault error stops before the child starts.
 *
 * Commands that only need a secret for an HTTP call should use the
 * secrets_http_request MCP tool instead: there the request is made by zn
 * and only goes to the secret's allowHosts.
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const markers = require('./markers');
const { warnNotice, WARN_REASON } = require('../team/effective');
const exe = require('../exe');
const { createMasker } = require('./mask');
const { approvalStore } = require('./approvals');
const { znError, loadVault, findProjectRoot } = require('../deps');
const { humanError } = require('../errors');
const { znCommand } = require('../zn-command');

const USAGE = 'usage: zn run [--secrets NAME[,NAME...]] [--agent ID] -- <command> [args...]';

// Settings that make the approved program, or the interpreter it starts (an
// npm CLI is a shim that runs node), load code or files of the caller's
// choosing: dynamic loader and glibc settings (LD_PRELOAD,
// DYLD_INSERT_LIBRARIES, GCONV_PATH ...) and interpreter start-up options
// (NODE_OPTIONS=--require, PYTHONPATH, PERL5OPT, JAVA_TOOL_OPTIONS, BASH_ENV ...).
const LOADER_VAR = new RegExp('^(LD_|DYLD_)|^(GCONV_PATH|GLIBC_TUNABLES|LOCPATH|NLSPATH|HOSTALIASES|RES_OPTIONS|' +
  'NODE_OPTIONS|NODE_PATH|NODE_REPL_EXTERNAL_MODULE|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONINSPECT|PERL5OPT|PERL5LIB|PERLLIB|' +
  'RUBYOPT|RUBYLIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|BASH_ENV|ENV)$', 'i');

function splitList(v) {
  return String(v || '').split(',').map((s) => s.trim()).filter(Boolean);
}

function parseRunArgs(args) {
  const secrets = [];
  let agent = null;
  let i = 0;
  let sawDashDash = false;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { i++; sawDashDash = true; break; }
    if (a === '--secrets' || a === '-s') {
      const v = args[++i];
      if (!v) throw znError('ZN_USAGE', USAGE);
      secrets.push(...splitList(v));
    } else if (a.startsWith('--secrets=')) {
      secrets.push(...splitList(a.slice('--secrets='.length)));
    } else if (a === '--agent') {
      // Set by agent hooks (for the audit log); not a security control.
      agent = String(args[++i] || '');
      if (!/^[a-z0-9-]{1,32}$/.test(agent)) throw znError('ZN_USAGE', 'invalid --agent');
    } else {
      throw znError('ZN_USAGE', 'unexpected argument before --: ' + a + '\n' + USAGE);
    }
  }
  const command = sawDashDash ? args.slice(i) : [];
  if (command.length === 0) throw znError('ZN_USAGE', USAGE);
  for (const name of secrets) {
    const bad = markers.validateSecretName(name);
    if (bad) throw znError('ZN_USAGE', 'invalid secret name ' + JSON.stringify(name) + ': ' + bad);
  }
  const out = { secrets: [...new Set(secrets)], command };
  if (agent) out.agent = agent;
  return out;
}

/** Named secrets the command needs: the ones named with --secrets. */
function requiredSecrets(parsed) {
  return [...new Set(parsed.secrets)];
}

/** Names of the secret markers written in the command's arguments (never allowed). */
function argvMarkers(parsed) {
  const names = new Set();
  for (const a of parsed.command) for (const m of markers.findNamedMarkers(a)) names.add(m.name);
  return [...names];
}

/**
 * Refuses a command that carries a secret marker in its arguments. The value
 * would end up in the process list and in command-line logs, so zn run does
 * not fill it in; the secret goes in the environment instead.
 */
function assertNoArgvMarkers(parsed) {
  const found = argvMarkers(parsed);
  if (found.length === 0) return;
  const first = found[0];
  throw znError('ZN_POLICY_DENIED', 'a secret marker in the command arguments (' + found.map((n) => markers.markerFor(n)).join(', ') + ') is not filled in: ' +
    'an argument is visible to other processes (ps) and to command-line logs, so zn run never puts a value there. ' +
    'Next step: give the program the secret as an environment variable instead: ' + znCommand('run --secrets ' + first + ' -- <command>') +
    ', and have the program read $' + first + ' (many tools read a fixed variable, such as PGPASSWORD for psql: store the secret under that name). ' +
    'For HTTP APIs use the secrets_http_request tool of the zn "secrets" MCP server.');
}

/**
 * Named markers that only appear in inherited environment values (for
 * example a shadowed .env loaded by direnv). They are optional: injected when
 * the secret already allows and approved this command, left as markers
 * otherwise, so unrelated commands keep working.
 */
function optionalSecrets(parsed, env) {
  const required = new Set(requiredSecrets(parsed));
  const names = new Set();
  for (const v of Object.values(env || {})) {
    for (const m of markers.findNamedMarkers(v)) if (!required.has(m.name)) names.add(m.name);
  }
  return [...names];
}

function referencedSecrets(parsed, env) {
  return [...requiredSecrets(parsed), ...optionalSecrets(parsed, env)];
}

/*
 * cmd.exe for batch files, chosen by zn. Never ComSpec, SystemRoot, PATH or
 * the current directory, which the caller of zn run (an agent) controls:
 * with `shell: true` Node starts whatever ComSpec names, and that program
 * would receive the secret values. The path comes from the kernel's
 * \SystemRoot link, which no environment variable or drive mapping of the
 * caller changes; it is resolved twice so a drive letter remapped in this
 * logon session is refused too. Returns the path or null.
 */
function systemCmdExe() {
  if (process.platform !== 'win32') return null;
  let cmd;
  try { cmd = fs.realpathSync.native('\\\\?\\GLOBALROOT\\SystemRoot\\System32\\cmd.exe'); } catch (_) { return null; }
  if (!/^[A-Za-z]:\\[^%!"]+\\System32\\cmd\.exe$/i.test(cmd)) return null;
  try { if (fs.realpathSync.native(cmd).toLowerCase() !== cmd.toLowerCase()) return null; } catch (_) { return null; }
  return cmd;
}

function cmdQuote(arg) {
  return '"' + String(arg).replace(/"/g, '""') + '"';
}

/*
 * How to start a batch file: {file, args} for spawn with
 * windowsVerbatimArguments, or throws ZN_POLICY_DENIED. cmd.exe re-parses
 * its command line and expands %VAR% (and !VAR!) even inside quotes, so
 * arguments that zn changed (secret values) or that hold metacharacters are
 * refused, and so is a program path with expansion characters.
 * original: the arguments as the caller wrote them.
 */
function batchInvocation(resolved, args, original) {
  const touched = args.some((a, i) => a !== original[i]);
  if (touched || args.some((a) => /[&|<>^%!"\r\n]/.test(a)) || /[%!"\r\n]/.test(resolved)) {
    throw znError('ZN_POLICY_DENIED', path.basename(resolved) +
      ' is a batch file: zn run will not pass secret values or shell metacharacters through cmd.exe. ' +
      'Use --secrets NAME to pass the value as an environment variable instead.');
  }
  const cmdExe = systemCmdExe();
  if (!cmdExe) {
    throw znError('ZN_POLICY_DENIED', path.basename(resolved) +
      ' is a batch file and zn could not find the system cmd.exe; it was not started. Next step: run a program file (.exe) instead of the batch file.');
  }
  // /d: no AutoRun commands; /v:off: no !VAR! expansion; /s /c "...": cmd.exe
  // runs the line between the outer quotes as is.
  const line = [resolved, ...args].map(cmdQuote).join(' ');
  return { file: cmdExe, args: ['/d', '/v:off', '/s', '/c', '"' + line + '"'] };
}

/**
 * Decide and resolve. Returns {argv, env, secrets: [{name, mode, command, value}]}
 * or throws ZN_POLICY_DENIED / ZN_NOT_FOUND / ZN_LOCKED.
 */
async function prepare(parsed, opts) {
  const env = opts.env || process.env;
  const cwd = opts.cwd || process.cwd();
  const project = opts.project || findProjectRoot(cwd);
  const vault = opts.vault;
  const agent = opts.agent || parsed.agent || env.ZN_AGENT || null;
  const argv0 = parsed.command[0];
  const exeName = markers.normalizeExe(argv0);
  assertNoArgvMarkers(parsed);
  const names = requiredSecrets(parsed);
  const optional = optionalSecrets(parsed, env);
  if (names.length === 0 && optional.length === 0) {
    return { argv: parsed.command, env: { ...env }, secrets: [], project, resolved: null };
  }

  const audit = async (ev) => {
    try { await vault.audit(ev); } catch (_) { /* audit must never unblock or crash a decision */ }
  };
  const deny = async (name, mode, reason, code = 'ZN_POLICY_DENIED') => {
    await audit({ secret: name, mode, agent, tool: 'zn run', argv0: exeName, host: null, decision: 'deny', reason });
    throw znError(code, reason);
  };

  // Local settings with the organization policy applied (zn Team): every
  // matching rule restricts. The agent id of zn run (--agent, ZN_AGENT) is
  // self-reported, so nothing new is offered for it.
  const list = await vault.listSecrets({ effective: true, agent, agentTrusted: false });
  const meta = new Map((list || []).map((s) => [s.name, s]));
  const approvals = opts.approvals || approvalStore({ vault, znHome: opts.znHome });
  const found = exe.resolveExecutable(argv0, env);
  const planted = markers.checkResolvedExecutable(found ? found.path : null, project, found ? found.real : undefined);
  // Open the file now: approvals are checked against this descriptor's
  // fingerprint, and the same descriptor is checked again before start.
  let opened = null;
  if (found && !planted) {
    try { opened = exe.openExecutable(found.real); } catch (_) { opened = null; }
  }
  const risk = opened && found ? exe.scriptRisk(opened, found.real) : null;
  const ctx = { project, executable: opened ? { real: found.real, fp: opened.fp } : null };
  const close = () => { if (opened) { try { fs.closeSync(opened.fd); } catch (_) { /* closed */ } opened = null; } };
  try {
    const prep = await decide();
    if (prep.secrets.length === 0) close();
    else prep.exe = { real: found.real, fp: ctx.executable.fp, opened };
    return prep;
  } catch (err) {
    close();
    throw err;
  }

  async function decide() {
  const chosen = [];

  for (const name of names) {
    const m = meta.get(name);
    if (!m) {
      await deny(name, null, 'secret ' + name + ' is not in the vault. Add it from your own terminal: zn secret set ' + name, 'ZN_NOT_FOUND');
    }
    if (m.deny) await deny(name, m.mode, 'secret ' + name + ' is blocked for this agent by your organization policy. Next step: do not use this secret here. If the task needs it, review the organization policy, or, if you are an agent, ask the user.', 'ZN_POLICY_DENIED');
    if (m.mode !== 'env') {
      await deny(name, m.mode, 'secret ' + name + ' is in ' + (m.mode || 'proxy') + ' mode, so zn run never puts it in a process. ' +
        'For HTTP APIs use the secrets_http_request tool of the zn "secrets" MCP server.');
    }
    const entry = markers.matchAllowCommands(m.allowCommands, parsed.command);
    if (!entry) {
      await deny(name, m.mode, '`' + exeName + '` is not allowed to use ' + name + ' yet. ' +
        'The user can allow it from their own terminal: zn secret allow ' + name + ' --command ' + exeName + ' ' +
        '(for HTTP APIs, the secrets_http_request tool of the zn "secrets" MCP server needs no command allowed).');
    }
    if (planted) await deny(name, m.mode, '`' + argv0 + '` ' + planted + '; zn run will not give it ' + name);
    if (!opened) await deny(name, m.mode, '`' + argv0 + '` could not be opened for checking; zn run will not give it ' + name);
    if (risk && risk.deny) await deny(name, m.mode, scriptDenial(risk.deny, argv0, name));
    chosen.push({ name, mode: m.mode, command: entry });
  }

  const skipped = [];
  for (const name of optional) {
    const m = meta.get(name);
    const entry = m && !m.deny && m.mode === 'env' && !planted && opened && !(risk && risk.deny) ? markers.matchAllowCommands(m.allowCommands, parsed.command) : null;
    if (entry && await approvals.isApproved(name, entry, ctx)) chosen.push({ name, mode: m.mode, command: entry });
    else skipped.push(name);
  }
  if (skipped.length && opts.stderr !== false) {
    (opts.stderr || process.stderr).write('zn run: left as markers in the environment (not allowed or not yet approved for `' + exeName + '`): ' + skipped.join(', ') + '\n');
  }

  // First use of a (secret, command) pair: the vault daemon asks the user on
  // its own channel (the terminal of `zn unlock --foreground` or an OS
  // dialog), never on this process's terminal, which an agent may control.
  for (const c of chosen) {
    if (await approvals.isApproved(c.name, c.command, ctx)) continue;
    if (opts.stderr !== false) {
      (opts.stderr || process.stderr).write('zn run: first use of ' + c.name + ' with `' + c.command + '`: confirm it in the zn vault prompt (dialog or the `zn unlock --foreground` terminal)\n');
    }
    try {
      await approvals.recordApproval(c.name, c.command, ctx);
    } catch (err) {
      const why = err && err.code === 'ZN_POLICY_DENIED' ? err.message : (err && err.message) || 'not approved';
      await deny(c.name, c.mode, 'first use of ' + c.name + ' with `' + c.command + '` was not approved (' + why + '). Nothing was run or sent. Do not retry the same request; finish the task another way.');
    }
  }

  const values = new Map();
  for (const c of chosen) {
    const v = await vault.resolve(project, markers.markerFor(c.name), { purpose: 'run', agent, tool: 'zn run', argv: parsed.command, exe: ctx.executable });
    if (v == null) await deny(c.name, c.mode, 'secret ' + c.name + ' has no value in the vault. Next step: save its value with zn secret set ' + c.name + ' in your own terminal, or, if you are an agent, ask the user to do it.', 'ZN_NOT_FOUND');
    values.set(c.name, String(v));
  }

  const childEnv = {};
  for (const [k, v] of Object.entries(env)) childEnv[k] = markers.substitute(v, values);
  for (const name of parsed.secrets) childEnv[name] = values.get(name);
  if (values.size > 0) {
    // The loader reads these before the program runs, so they would load code
    // of the caller's choosing into the approved program. Only dropped when
    // secret values are handed over, and said once.
    const loader = Object.keys(childEnv).filter((k) => LOADER_VAR.test(k));
    for (const k of loader) delete childEnv[k];
    if (loader.length && opts.stderr !== false) {
      (opts.stderr || process.stderr).write('zn run: removed ' + loader.join(', ') + ' from the environment (loader and interpreter start-up variables; they are not passed when secret values are injected)\n');
    }
    // Windows: a program the approved one starts by name (an npm shim runs
    // `node`) must not come from the current directory, where an agent can
    // write files.
    if (process.platform === 'win32') {
      for (const k of Object.keys(childEnv)) if (k.toLowerCase() === 'nodefaultcurrentdirectoryinexepath') delete childEnv[k];
      childEnv.NoDefaultCurrentDirectoryInExePath = '1';
    }
  }
  // Arguments go through exactly as written: assertNoArgvMarkers refused any marker in them.
  const argv = parsed.command.slice();

  const ownScript = risk && !risk.deny && risk.warn ? risk.warn : null;
  if (ownScript && chosen.length && opts.stderr !== false) {
    (opts.stderr || process.stderr).write('zn run: warning: `' + exeName + '` is a script you can rewrite (' + ownScript + '); another program running as you could swap it while it starts and read the secret. ' +
      'Keep it where only you can write, or run it through its interpreter.\n');
  }
  for (const c of chosen) {
    // A `warn` rule of the organization policy: allowed, recorded as "warn", and said.
    const m = meta.get(c.name);
    if (m && m.warn === true) {
      await audit({ secret: c.name, mode: c.mode, agent, tool: 'zn run', argv0: exeName, host: null, decision: 'warn', reason: WARN_REASON });
      if (opts.stderr !== false) (opts.stderr || process.stderr).write(warnNotice(c.name, m.warnReason) + '\n');
    } else {
      await audit({ secret: c.name, mode: c.mode, agent, tool: 'zn run', argv0: exeName, host: null, decision: 'allow', reason: 'allowCommands: ' + c.command + (ownScript ? '; script writable by the current user: ' + ownScript : '') });
    }
  }
  return { argv, env: childEnv, secrets: chosen.map((c) => ({ ...c, value: values.get(c.name) })), project, resolved: found ? found.real : null };
  }
}

/*
 * A `#!` script (on Windows, a .cmd or .bat file) is opened again by its
 * interpreter after the last check. When group or others (on Windows, another
 * principal) can rewrite it or a folder above it, or another account owns it,
 * it could be swapped in that window and would receive the secret: refuse.
 * A script only the current user can write is allowed with a warning.
 */
function scriptDenial(loose, argv0, name) {
  return '`' + argv0 + '` is a script that others can rewrite (' + loose + '), and its interpreter opens it again after zn has checked it, ' +
    'so zn run will not give it ' + name + '. Next step: move the script where only you can write (not group or others) and that you own, ' +
    'or run it through its interpreter, for example: zn run -- bash ./script.sh, after allowing that command.';
}

function closeExe(prep) {
  if (prep && prep.exe && prep.exe.opened) {
    try { fs.closeSync(prep.exe.opened.fd); } catch (_) { /* closed */ }
    prep.exe.opened = null;
  }
}

function spawnMasked(prep, opts) {
  try {
    return spawnChecked(prep, opts);
  } finally {
    // spawn() returns once the child has started the program, so the
    // descriptor is no longer needed (it is close-on-exec in the child).
    closeExe(prep);
  }
}

function spawnChecked(prep, opts) {
  const stdout = opts.stdout || process.stdout;
  const stderr = opts.stderr || process.stderr;
  const masker = createMasker(prep.secrets);
  let file = prep.argv[0];
  let args = prep.argv.slice(1);
  let verbatim = false;
  let argv0;
  if (prep.secrets.length) {
    // Values are about to be handed over: start exactly the file that was
    // checked, after checking it once more.
    if (!prep.exe || !prep.exe.opened) return Promise.reject(znError('ZN_POLICY_DENIED', 'the program was not checked; nothing was started. Next step: run the command again.'));
    const why = exe.verifyOpen(prep.exe.opened, prep.exe.real, prep.exe.fp);
    if (why) {
      return Promise.reject(znError('ZN_POLICY_DENIED', '`' + prep.argv[0] + '`: ' + why + ' (' + prep.exe.real + '); it was not started. ' +
        'Run the command again; if this keeps happening, something is replacing the program.'));
    }
    const again = exe.scriptRisk(prep.exe.opened, prep.exe.real);
    if (again && again.deny) {
      return Promise.reject(znError('ZN_POLICY_DENIED', '`' + prep.argv[0] + '` is a script that others can rewrite (' + again.deny + '); it was not started. ' +
        'Put the script where only you can write, or run it through its interpreter.'));
    }
    file = exe.execPath(prep.exe.opened, prep.exe.real);
    // The program still sees the name it was called by (multi-call binaries need it).
    if (process.platform !== 'win32') argv0 = prep.argv[0];
  }
  if (process.platform === 'win32' && prep.resolved && /\.(cmd|bat)$/i.test(prep.resolved)) {
    let b;
    try { b = batchInvocation(prep.resolved, args, opts.originalArgs.slice(1)); } catch (err) { return Promise.reject(err); }
    file = b.file;
    args = b.args;
    verbatim = true;
  }
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(file, args, {
        argv0,
        env: prep.env,
        cwd: opts.cwd || process.cwd(),
        stdio: ['inherit', 'pipe', 'pipe'],
        shell: false,
        windowsVerbatimArguments: verbatim,
        windowsHide: true,
      });
    } catch (err) {
      reject(err);
      return;
    }
    const so = masker.stream();
    const se = masker.stream();
    child.stdout.on('data', (d) => stdout.write(so.write(d)));
    child.stderr.on('data', (d) => stderr.write(se.write(d)));
    const onInt = () => { try { child.kill('SIGINT'); } catch (_) { /* gone */ } };
    const onTerm = () => { try { child.kill('SIGTERM'); } catch (_) { /* gone */ } };
    process.on('SIGINT', onInt);
    process.on('SIGTERM', onTerm);
    const cleanup = () => {
      process.removeListener('SIGINT', onInt);
      process.removeListener('SIGTERM', onTerm);
    };
    child.on('error', (err) => {
      cleanup();
      reject(err.code === 'ENOENT' ? znError('ZN_NOT_FOUND', '`' + prep.argv[0] + '` is not installed, or it is not on your PATH. Next step: check that the program is installed and on your PATH.') : err);
    });
    child.on('close', (code, signal) => {
      cleanup();
      stdout.write(so.end());
      stderr.write(se.end());
      resolve(code == null ? (signal === 'SIGINT' ? 130 : 143) : code);
    });
  });
}

/**
 * Programmatic entry. Resolves to the exit code.
 * opts: {vault, env, cwd, stdin, stdout, stderr, confirm, approvals, znHome, agent, project}
 */
async function runBroker(args, opts = {}) {
  const stderr = opts.stderr || process.stderr;
  try {
    const parsed = parseRunArgs(args);
    assertNoArgvMarkers(parsed);
    const env = opts.env || process.env;
    let vault = opts.vault;
    let prep;
    if (requiredSecrets(parsed).length > 0) {
      vault = vault || await loadVault();
      prep = await prepare(parsed, { ...opts, env, vault });
    } else if (optionalSecrets(parsed, env).length > 0) {
      try {
        vault = vault || await loadVault();
        prep = await prepare(parsed, { ...opts, env, vault });
      } catch (err) {
        if (err.code !== 'ZN_LOCKED') throw err;
        stderr.write('zn run: your secret vault is locked, so secrets were not filled in. Unlock it in your terminal with: ' + znCommand('unlock') + '\n');
        prep = { argv: parsed.command, env: { ...env }, secrets: [], resolved: null };
      }
    } else {
      prep = { argv: parsed.command, env: { ...env }, secrets: [], resolved: null };
    }
    return await spawnMasked(prep, { ...opts, originalArgs: parsed.command });
  } catch (err) {
    stderr.write('zn run: ' + humanError(err) + '\n');
    if (err.code === 'ZN_USAGE') return 64;
    if (err.code === 'ZN_POLICY_DENIED') return 77;
    if (err.code === 'ZN_NOT_FOUND') return 127;
    return 1;
  }
}

async function main(args) {
  process.exitCode = await runBroker(args);
}

module.exports = { systemCmdExe, batchInvocation, parseRunArgs, requiredSecrets, argvMarkers, optionalSecrets, referencedSecrets, prepare, runBroker, main, USAGE };

// Direct entry (`node lib/broker/run.js -- <command>`), used by hook rewrites.
if (require.main === module) main(process.argv.slice(2));
