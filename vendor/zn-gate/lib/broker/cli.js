'use strict';

/**
 * `zn secret ...` (including `zn secret log`), `zn vault log`, `zn env ...`
 * and `zn hooks ...`.
 *
 * Every command that adds, changes, reveals or removes a value is for the
 * person at the keyboard: it needs an interactive terminal, refuses to run
 * inside an agent's shell, and never accepts a value as an argument.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const markers = require('./markers');
const dotenv = require('./dotenv');
const tty = require('./tty');
const { approvalStore } = require('./approvals');
const { writeFileAtomic } = require('./files');
const deps = require('../deps');
const exe = require('../exe');
const { humanError } = require('../errors');
const { validateSecretValue } = require('../scrub/exact');
const { znCommand } = require('../zn-command');

const MODES = new Set(['proxy', 'env', 'file']);
const PLACEMENTS = new Set(['header', 'query', 'body']);

function checkPlacements(list) {
  for (const p of list || []) {
    if (!PLACEMENTS.has(p)) throw deps.znError('ZN_USAGE', '--in must be header, query (the URL) or body');
  }
}

function parseFlags(args, spec = {}) {
  const multi = new Set(spec.multi || []);
  const bool = new Set(spec.bool || []);
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const key = (eq === -1 ? a.slice(2) : a.slice(2, eq));
      if (bool.has(key)) { flags[key] = true; continue; }
      const v = eq === -1 ? args[++i] : a.slice(eq + 1);
      if (v === undefined) throw deps.znError('ZN_USAGE', '--' + key + ' needs a value');
      if (multi.has(key)) flags[key] = [...(flags[key] || []), ...String(v).split(',').map((s) => s.trim()).filter(Boolean)];
      else flags[key] = v;
    } else {
      positional.push(a);
    }
  }
  return { flags, positional };
}

function makeIo(io = {}) {
  return {
    stdin: io.stdin || process.stdin,
    stdout: io.stdout || process.stdout,
    stderr: io.stderr || process.stderr,
    env: io.env || process.env,
    cwd: io.cwd || process.cwd(),
    home: io.home || os.homedir(),
    vault: io.vault,
    readSecret: io.readSecret,
    confirm: io.confirm,
    human: io.human, // tests: skip the terminal check
    ancestry: io.ancestry, claude: io.claude, run: io.run, envList: io.envList, // tests (zn-gate uninstall)
  };
}

function needHuman(io, what) {
  if (io.human) return;
  tty.requireHuman(what, io);
}

async function vaultOf(io) {
  if (!io.vault) io.vault = await deps.loadVault();
  return io.vault;
}

function out(io, line) {
  io.stdout.write(line + '\n');
}

function metaFromFlags(flags, defaults = {}) {
  const mode = flags.mode || defaults.mode || (flags.command ? 'env' : flags.host ? 'proxy' : 'proxy');
  if (!MODES.has(mode)) throw deps.znError('ZN_USAGE', '--mode must be proxy, env or file');
  checkPlacements(flags.in);
  return {
    allowIn: [...new Set(['header', ...(flags.in || [])])],
    mode,
    allowHosts: flags.host || defaults.allowHosts || [],
    allowCommands: flags.command || defaults.allowCommands || [],
    source: defaults.source || 'local',
    type: flags.type || defaults.type || undefined,
  };
}

/* Warnings shown when a command is allowed for a secret: interpreters run
 * any code, and a program the user can overwrite can be swapped later. */
function commandWarnings(io, name, command) {
  const head = String(command).trim().split(/\s+/)[0];
  const found = exe.hasPathSeparator(head) ? null : exe.resolveExecutable(head, io.env);
  if (exe.isInterpreter(head) || (found && exe.isInterpreterPath(found.real))) {
    out(io, 'Warning: `' + command + '` runs any code it is given, so every script it runs could read ' + name + '. Prefer the specific program (psql, terraform, gh).');
  }
  const writable = found ? exe.writableBy(found.real) : null;
  if (writable) {
    out(io, 'Warning: `' + head + '` runs ' + found.real + ', and your user account can write ' + writable +
      ': any program you run (an agent too) could replace it. zn checks the file before each use and asks again if it changed. ' +
      'This is normal for tools installed with nvm, volta, pipx or Homebrew; if a copy owned by root exists, prefer it.');
  }
}

async function existingMeta(vault, name) {
  const list = await vault.listSecrets();
  return (list || []).find((s) => s.name === name) || null;
}

/* ------------------------------ secret ----------------------------- */

async function secretSet(args, io) {
  const { flags, positional } = parseFlags(args, { multi: ['host', 'command', 'in'], bool: ['clipboard', 'force'] });
  const name = positional[0];
  if (positional.length > 1) {
    throw deps.znError('ZN_USAGE', 'values are never accepted as arguments (they end up in shell history and agent transcripts). ' +
      'Run `zn secret set ' + (name || 'NAME') + '` and type or paste the value at the hidden prompt, or use --clipboard.');
  }
  const bad = markers.validateSecretName(name);
  if (bad) throw deps.znError('ZN_USAGE', 'invalid name: ' + bad);
  needHuman(io, 'zn secret set');
  const vault = await vaultOf(io);
  if (!flags.force && await existingMeta(vault, name)) {
    throw deps.znError('ZN_USAGE', name + ' already exists; use --force to replace it');
  }
  const value = flags.clipboard ? tty.readClipboard()
    : await (io.readSecret ? io.readSecret(name) : tty.readHidden('Value for ' + name + ' (hidden): ', io));
  if (!value) throw deps.znError('ZN_USAGE', 'empty value, nothing stored');
  const tooShort = validateSecretValue(value);
  if (tooShort) throw deps.znError('ZN_USAGE', tooShort + ' Nothing stored.');
  const meta = metaFromFlags(flags);
  await vault.setSecret(name, value, meta);
  out(io, 'Stored ' + name + ' (' + meta.mode + ' mode). Agents use it as ' + markers.markerFor(name) + '.');
  if (meta.mode === 'proxy' && meta.allowHosts.length === 0) out(io, 'Tip: allow a host for secrets_http_request: zn secret allow ' + name + ' --host api.example.com');
  if (meta.mode === 'env' && meta.allowCommands.length === 0) out(io, 'Tip: allow a command for zn run: zn secret allow ' + name + ' --command psql');
  return 0;
}

async function secretList(args, io) {
  const vault = await vaultOf(io);
  const list = (await vault.listSecrets()) || [];
  if (list.length === 0) out(io, 'No secrets stored. Add one with: zn secret set NAME   or import a .env: zn env shadow .env');
  for (const s of list) {
    const parts = [s.name.padEnd(28), (s.mode || 'proxy').padEnd(6)];
    if ((s.allowHosts || []).length) parts.push('hosts=' + s.allowHosts.join(','));
    if ((s.allowCommands || []).length) parts.push('commands=' + s.allowCommands.join(','));
    if (s.lastUsed) parts.push('last used ' + s.lastUsed);
    out(io, '  ' + parts.join('  '));
  }
  try {
    const lines = fs.readFileSync(path.join(io.home, '.zn', 'requests.jsonl'), 'utf8').trim().split('\n').filter(Boolean);
    const have = new Set(list.map((s) => s.name));
    const pending = [...new Map(lines.map((l) => { try { const r = JSON.parse(l); return [r.name, r]; } catch (_) { return [null, null]; } })).values()]
      .filter((r) => r && r.name && !have.has(r.name));
    if (pending.length) {
      out(io, '\nRequested by agents (add with zn secret set NAME):');
      for (const r of pending) out(io, '  ' + r.name + (r.reason ? '  - ' + r.reason : ''));
    }
  } catch (_) { /* no requests */ }
  return 0;
}

async function secretRm(args, io) {
  const name = args[0];
  const bad = markers.validateSecretName(name);
  if (bad) throw deps.znError('ZN_USAGE', 'invalid name: ' + bad);
  needHuman(io, 'zn secret rm');
  const vault = await vaultOf(io);
  if (!await existingMeta(vault, name)) throw deps.znError('ZN_NOT_FOUND', name + ' is not in the vault');
  const ok = await (io.confirm ? io.confirm('Remove ' + name + '?') : tty.confirm('Remove ' + name + '?', io));
  if (!ok) { out(io, 'Kept ' + name + '.'); return 1; }
  await vault.removeSecret(name);
  out(io, 'Removed ' + name + '.');
  return 0;
}

/** Add hosts/commands (or change the mode) of an existing secret. */
async function secretAllow(args, io) {
  const { flags, positional } = parseFlags(args, { multi: ['host', 'command', 'in'], bool: ['replace'] });
  const name = positional[0];
  const bad = markers.validateSecretName(name);
  if (bad) throw deps.znError('ZN_USAGE', 'invalid name: ' + bad);
  if (!flags.host && !flags.command && !flags.mode && !flags.in) {
    throw deps.znError('ZN_USAGE', 'usage: zn secret allow NAME [--host H] [--command C] [--in header|query|body] [--mode proxy|env|file] [--replace]');
  }
  checkPlacements(flags.in);
  needHuman(io, 'zn secret allow');
  const vault = await vaultOf(io);
  const cur = await existingMeta(vault, name);
  if (!cur) throw deps.znError('ZN_NOT_FOUND', name + ' is not in the vault');
  const merge = (a, b) => (flags.replace ? (b || a || []) : [...new Set([...(a || []), ...(b || [])])]);
  const meta = {
    mode: flags.mode || (flags.command && cur.mode !== 'env' && !flags.host ? 'env' : cur.mode),
    allowHosts: merge(cur.allowHosts, flags.host),
    allowCommands: merge(cur.allowCommands, flags.command),
    allowIn: [...new Set(['header', ...merge(cur.allowIn, flags.in)])],
    source: cur.source,
    type: cur.type,
  };
  if (!MODES.has(meta.mode)) throw deps.znError('ZN_USAGE', '--mode must be proxy, env or file');
  for (const c of flags.command || []) commandWarnings(io, name, c);
  if ((flags.in || []).some((p) => p !== 'header')) {
    out(io, 'Warning: in the URL or the body, an injected prompt could make zn send ' + name + ' somewhere readable on an allowed host (a gist, an issue). Allow it only if the API needs it.');
  }
  out(io, 'Confirm the change in the zn vault prompt (system dialog or the `zn unlock --foreground` terminal).');
  await vault.updateSecretMeta(name, meta);
  out(io, name + ': mode=' + meta.mode + ' hosts=' + (meta.allowHosts.join(',') || '-') + ' commands=' + (meta.allowCommands.join(',') || '-') + ' http=' + meta.allowIn.join(','));
  return 0;
}

/** Record the first-use approval of (secret, command) ahead of time. */
async function secretApprove(args, io) {
  const { flags, positional } = parseFlags(args, { multi: [] });
  const name = positional[0];
  const bad = markers.validateSecretName(name);
  if (bad || !flags.command) throw deps.znError('ZN_USAGE', 'usage: zn secret approve NAME --command "<allowed command>"');
  needHuman(io, 'zn secret approve');
  const vault = await vaultOf(io);
  const cur = await existingMeta(vault, name);
  if (!cur) throw deps.znError('ZN_NOT_FOUND', name + ' is not in the vault');
  const wanted = flags.command.trim().split(/\s+/).join(' ');
  const entry = (cur.allowCommands || []).map((c) => String(c).trim().split(/\s+/).join(' ')).find((c) => c === wanted);
  if (!entry) throw deps.znError('ZN_POLICY_DENIED', '`' + wanted + '` is not in allowCommands for ' + name + '. First: zn secret allow ' + name + ' --command "' + wanted + '"');
  commandWarnings(io, name, entry);
  out(io, 'Confirm it in the zn vault prompt (system dialog or the `zn unlock --foreground` terminal).');
  await approvalStore({ vault }).recordApproval(name, entry);
  out(io, 'Approved ' + name + ' for `' + entry + '`.');
  return 0;
}

async function secretAdopt(args, io) {
  const { flags, positional } = parseFlags(args, { multi: ['host', 'command'] });
  const token = positional[0] || '';
  const tokenName = /^__ZN_(.+)__$/.exec(token) ? /^__ZN_(.+)__$/.exec(token)[1] : token;
  if (!markers.isDetectedName(tokenName)) throw deps.znError('ZN_USAGE', 'usage: zn secret adopt AWS_KEY_1 --name AWS_PROD [--host H] [--command C]');
  const bad = markers.validateSecretName(flags.name);
  if (bad) throw deps.znError('ZN_USAGE', 'invalid --name: ' + bad);
  needHuman(io, 'zn secret adopt');
  const vault = await vaultOf(io);
  if (await existingMeta(vault, flags.name)) throw deps.znError('ZN_USAGE', flags.name + ' already exists');
  const project = deps.findProjectRoot(io.cwd);
  const meta = metaFromFlags(flags, { source: 'adopted' });
  // The value moves inside the vault: it never comes back to this process.
  await vault.adoptToken(project, markers.markerFor(tokenName), flags.name, meta);
  out(io, 'Adopted ' + markers.markerFor(tokenName) + ' as ' + markers.markerFor(flags.name) + ' (' + meta.mode + ' mode).');
  return 0;
}

/* --------------------------- import / shadow ------------------------ */

function secretNameForKey(key) {
  const n = String(key).toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/^(\d)/, 'V$1');
  return n;
}

/**
 * Plan which .env values move to the vault. Returns
 * {parsed, items: [{entry, name, value, start, end}], skipped: [{key, why}]}
 */
function shortWhy(n) {
  return 'the value is only ' + n + ' character(s); values under ' + dotenv.MIN_SECRET_LEN
    + ' are not moved because they cannot be told apart from ordinary text. It stays in the file in plain text. Use a longer value.';
}

function planImport(text, flags) {
  const parsed = dotenv.parseDotenv(text);
  const items = [];
  const skipped = [];
  const notes = [];
  const only = flags.keys ? new Set(flags.keys) : null;
  for (const e of parsed.entries) {
    if (only && !only.has(e.key)) continue;
    if (!only && !flags.all && !dotenv.isSensitiveKey(e.key)) continue;
    if (e.multiline) { skipped.push({ key: e.key, why: 'multi-line value (store it with zn secret set)' }); continue; }
    if (!e.value || e.value.includes('__ZN_')) continue;
    const pw = dotenv.connectionPassword(e.value);
    let name = secretNameForKey(e.key);
    let value = e.value;
    let start = e.start;
    let end = e.end;
    if (pw) {
      const pass = e.value.slice(pw.start, pw.end);
      if (pass.length >= dotenv.MIN_SECRET_LEN) {
        name = name + '_PASSWORD';
        value = pass;
        start = e.start + pw.start;
        end = e.start + pw.end;
      } else if (e.value.length >= dotenv.MIN_SECRET_LEN) {
        // The password alone is too short to be found and hidden later, so
        // the whole URL moves to the vault instead and the password goes with it.
        notes.push({ key: e.key, why: 'the password in the URL is only ' + pass.length + ' character(s) long, so the whole URL was moved to the vault instead of just the password' });
      } else {
        skipped.push({ key: e.key, why: shortWhy(e.value.length) });
        continue;
      }
    } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(e.value)) {
      continue; // URL without credentials: nothing secret
    }
    if (value.length < dotenv.MIN_SECRET_LEN) { skipped.push({ key: e.key, why: shortWhy(value.length) }); continue; }
    const bad = markers.validateSecretName(name);
    if (bad) { skipped.push({ key: e.key, why: bad + ' (store it with zn secret set OTHER_NAME)' }); continue; }
    items.push({ entry: e, name, value, start, end });
  }
  return { parsed, items, skipped, notes };
}

async function storeItems(vault, items, flags, source, io) {
  const stored = [];
  for (const it of items) {
    const cur = await existingMeta(vault, it.name);
    if (cur && !flags.force) {
      const same = await vault.sameSecretValue(it.name, it.value);
      if (!same) {
        out(io, '  skip ' + it.name + ': a different value is already stored (use --force to replace)');
        continue;
      }
      stored.push(it);
      continue;
    }
    await vault.setSecret(it.name, it.value, metaFromFlags(flags, { mode: 'env', source }));
    stored.push(it);
  }
  return stored;
}

async function secretImport(args, io) {
  const { flags, positional } = parseFlags(args, { multi: ['host', 'command', 'keys'], bool: ['all', 'force'] });
  const file = path.resolve(io.cwd, positional[0] || '.env');
  needHuman(io, 'zn secret import');
  const text = fs.readFileSync(file, 'utf8');
  const plan = planImport(text, flags);
  const vault = await vaultOf(io);
  const stored = await storeItems(vault, plan.items, flags, 'dotenv:' + path.basename(file), io);
  out(io, 'Imported ' + stored.length + ' secret(s) from ' + path.basename(file) + ': ' + (stored.map((s) => s.name).join(', ') || '-'));
  for (const s of plan.skipped) out(io, '  skipped ' + s.key + ': ' + s.why);
  for (const s of plan.notes) out(io, '  note ' + s.key + ': ' + s.why);
  out(io, 'The file is unchanged. To replace its values with markers run: zn env shadow ' + path.relative(io.cwd, file));
  return 0;
}

function backupName(file) {
  const h = crypto.createHash('sha256').update(path.resolve(file)).digest('hex').slice(0, 8).toUpperCase();
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 12);
  return 'ENVBAK_X' + h + 'D' + stamp;
}

async function envShadow(args, io) {
  const { flags, positional } = parseFlags(args, { multi: ['host', 'command', 'keys'], bool: ['all', 'force', 'dry-run'] });
  const file = path.resolve(io.cwd, positional[0] || '.env');
  needHuman(io, 'zn env shadow');
  const text = fs.readFileSync(file, 'utf8');
  const plan = planImport(text, flags);
  if (plan.items.length === 0) {
    out(io, path.basename(file) + ': nothing to shadow' + (dotenv.isShadowed(text) ? ' (already shadowed)' : ''));
    for (const s of plan.skipped) out(io, '  skipped ' + s.key + ': ' + s.why);
    return 0;
  }
  if (flags['dry-run']) {
    for (const it of plan.items) out(io, '  ' + it.entry.key + ' -> ' + markers.markerFor(it.name));
    for (const s of plan.notes) out(io, '  note ' + s.key + ': ' + s.why);
    for (const s of plan.skipped) out(io, '  skipped ' + s.key + ': ' + s.why);
    return 0;
  }
  const vault = await vaultOf(io);
  const bak = backupName(file);
  await vault.setSecret(bak, text, { mode: 'backup', allowHosts: [], allowCommands: [], source: 'env-shadow:' + path.basename(file) });
  const stored = await storeItems(vault, plan.items, flags, 'dotenv:' + path.basename(file), io);
  const storedNames = new Set(stored.map((s) => s.name));
  const edits = plan.items.filter((it) => storedNames.has(it.name))
    .map((it) => ({ lineIndex: it.entry.lineIndex, start: it.start, end: it.end, text: markers.markerFor(it.name) }));
  const shadowed = dotenv.applyEdits(plan.parsed, edits);
  let mode = 0o600;
  try { mode = fs.statSync(file).mode & 0o777; } catch (_) { /* default */ }
  writeFileAtomic(file, shadowed, mode);
  out(io, 'Shadowed ' + edits.length + ' value(s) in ' + path.basename(file) + '. The file now holds only markers; the values are in the local vault.');
  out(io, 'Encrypted copy of the original: ' + bak + ' (restore with: zn env unshadow ' + path.relative(io.cwd, file) + ' --backup ' + bak + ')');
  for (const s of plan.notes) out(io, '  note ' + s.key + ': ' + s.why);
  for (const s of plan.skipped) out(io, '  skipped ' + s.key + ': ' + s.why);
  const names = stored.map((s) => s.name).join(',');
  if (!flags.command) {
    out(io, 'Next: allow the commands that need them, e.g. zn secret allow ' + stored[0].name + ' --command "npm run dev"');
  }
  out(io, 'Run your app with the real values: zn run --secrets ' + names + ' -- <command>');
  return 0;
}

async function envUnshadow(args, io) {
  const { flags, positional } = parseFlags(args, {});
  const file = path.resolve(io.cwd, positional[0] || '.env');
  if (!flags.backup || !/^ENVBAK_X[0-9A-F]{8}D\d{12}$/.test(flags.backup)) {
    throw deps.znError('ZN_USAGE', 'usage: zn env unshadow FILE --backup ENVBAK_X........D............ (printed by zn env shadow)');
  }
  needHuman(io, 'zn env unshadow');
  const vault = await vaultOf(io);
  const ok = await (io.confirm ? io.confirm('Write plain-text values back to ' + path.basename(file) + '?') : tty.confirm('Write plain-text values back to ' + path.basename(file) + '?', io));
  if (!ok) return 1;
  // The vault asks again on its own channel before the plain text leaves it.
  const text = await vault.readBackup(deps.findProjectRoot(io.cwd), flags.backup, file);
  if (text == null) throw deps.znError('ZN_NOT_FOUND', flags.backup + ' not found');
  writeFileAtomic(file, text, 0o600);
  out(io, 'Restored ' + path.basename(file) + ' from ' + flags.backup + '.');
  return 0;
}

/* ------------------------------ audit ------------------------------ */

async function audit(args, io) {
  if (args.includes('-h') || args.includes('--help')) {
    out(io, 'usage: zn vault log [--since 1h]   (also: zn secret log)');
    out(io, 'Shows who used which secret where (no values), then checks the audit log chain.');
    return 0;
  }
  const { flags } = parseFlags(args, {});
  let mod;
  try {
    mod = require('../vault/audit');
  } catch (err) {
    throw deps.znError('ZN_UNAVAILABLE', 'the audit log module is not installed yet (lib/vault/audit.js)');
  }
  const reader = mod.read || mod.query || mod.list;
  if (typeof reader !== 'function') throw deps.znError('ZN_UNAVAILABLE', 'lib/vault/audit.js has no read API');
  // An unlocked vault verifies the chain first and refuses to show a log that does not verify.
  let records;
  let verified;
  try {
    verified = await verifiedRead(flags.since);
  } catch (err) {
    // The vault is unlocked but could not check the log (an older daemon that is still running
    // after an upgrade does not know the operation): do not show a log nobody verified.
    out(io, 'The log is not shown because the unlocked vault could not check it (' + (err && err.message ? err.message : String(err)) + ').');
    out(io, 'If you just upgraded zn, restart the vault (`' + znCommand('lock') + '`, then `' + znCommand('unlock') + '`) and try again.');
    return 1;
  }
  if (verified && !verified.ok) {
    out(io, 'chain: BROKEN: ' + (verified.reason || verified.error || 'verification failed'));
    out(io, 'The log is not shown because it did not verify. Keep a copy of ~/.zn/audit.jsonl as evidence and run `' + znCommand('vault verify') + '`.');
    return 1;
  }
  if (verified) records = verified.events;
  else records = await reader({ since: flags.since });
  for (const r of records || []) {
    out(io, [r.ts, r.decision, r.secret, r.mode, r.agent, r.tool, r.argv0 || r.host || '', r.reason || ''].map((x) => x == null ? '-' : String(x)).join('  '));
  }
  const chain = await auditChain();
  out(io, chain.line);
  // Same exit code as `zn vault verify` for a broken chain; "not checked" is not an error.
  return chain.broken ? 1 : 0;
}

/** Verified read through the unlocked vault; null when the vault is locked or unreachable.
 *  Throws when the vault is unlocked but the verified read fails. */
async function verifiedRead(since) {
  let client;
  try {
    client = require('../vault/client').createClient({});
    let unlocked = false;
    try { unlocked = await client.isUnlocked(); } catch (err) { unlocked = false; }
    if (!unlocked) return null;
    return await client.auditRead({ since });
  } finally {
    if (client) client.close();
  }
}

/** The chain is checked with the key held by the unlocked vault (same check as `zn vault verify`). */
async function auditChain() {
  let client;
  try {
    client = require('../vault/client').createClient({});
    if (!(await client.isUnlocked())) {
      return { broken: false, line: 'chain: not checked: the vault is locked or unreachable (run `' + znCommand('unlock') + '`, then `' + znCommand('vault verify') + '`)' };
    }
    const v = await client.auditVerify();
    if (v && v.ok) return { broken: false, line: 'chain: valid, ' + v.records + ' records' };
    const where = v && v.line ? ' (record ' + v.line + ')' : '';
    return { broken: true, line: 'chain: BROKEN: ' + ((v && v.error) || 'verification failed') + where };
  } catch (err) {
    return { broken: false, line: 'chain: not checked: ' + (err && err.message ? err.message : String(err)) };
  } finally {
    if (client) client.close();
  }
}

/* ------------------------------ hooks ------------------------------ */

function hooksUsage() {
  return 'usage: zn hooks install|uninstall ' + require('../agents').listAdapters().join('|') + ' [--project] [--no-mcp]';
}

async function hooks(args, io) {
  const { flags, positional } = parseFlags(args, { bool: ['project', 'no-mcp'] });
  const [action, agentId] = positional;
  if (!['install', 'uninstall'].includes(action) || !agentId) {
    throw deps.znError('ZN_USAGE', hooksUsage());
  }
  // Check the agent name first, so a script or an agent is told the real reason.
  const unsupported = require('../agents').unsupportedAgentMessage(agentId);
  if (unsupported) throw deps.znError('ZN_USAGE', unsupported);
  needHuman(io, 'zn hooks ' + action);
  const adapter = require('../agents').getAdapter(agentId);
  const opts = { scope: flags.project ? 'project' : 'user', projectDir: io.cwd, home: io.home, env: io.env, mcp: !flags['no-mcp'], selfCheck: true };
  const report = action === 'install' ? adapter.install(opts) : adapter.uninstall(opts);
  out(io, (action === 'install' ? 'Installed' : 'Removed') + ' zn hooks for ' + adapter.id + ' in ' + report.settings);
  if (report.backup) out(io, '  backup: ' + report.backup);
  if (report.mcp) out(io, '  MCP server "secrets": ' + report.mcp);
  for (const w of report.warnings || []) out(io, '  note: ' + w);
  if (action === 'install' && /_npx[\\/]/.test(__dirname)) {
    out(io, '  note: zn is running from the npx cache; install it (npm i -g zn-gate) so the hook path stays valid.');
  }
  return 0;
}

/* ------------------------------ entry ------------------------------ */

const HELP = {
  'hooks': [
    hooksUsage(),
    'Adds the zn hooks to a coding agent, or removes them again.',
    '  install     add the hooks (and the secrets MCP server unless --no-mcp)',
    '  uninstall   remove them',
    '  --project   change the settings of this project instead of your user settings',
    '  --no-mcp    do not add the secrets MCP server',
  ],
  'secret': [
    'usage: zn secret set|list|rm|allow|approve|import|adopt|log ...',
    'Stores secrets in the zn vault so your agent can use them without seeing them.',
    'Run zn secret set NAME and type the value at the hidden prompt (or use --clipboard); values are never passed as arguments.',
  ],
  'uninstall': [
    'usage: zn-gate uninstall [--dry-run]',
    'Removes zn-gate from this computer: the zn-gate plugin of Claude Code, zn\'s hooks (your user and this project),',
    'and MCP servers wrapped by zn-gate init --wrap-mcp. It shows the plan and asks first; run it in your own terminal.',
    'The vault is only deleted if you confirm it separately (default no). .env files with markers are left alone.',
    '  --dry-run   show the plan and change nothing',
  ],
  'env': [
    'usage: zn env shadow [FILE] | zn env unshadow FILE --backup NAME',
    'shadow moves the secrets of a .env file into the vault and leaves placeholders; unshadow puts them back.',
  ],
};

/* -h / --help anywhere before a lone "--" prints the usage and exits 0,
 * before any option that takes a value can swallow it. */
function wantsHelp(args) {
  const end = args.indexOf('--');
  return (end === -1 ? args : args.slice(0, end)).some((a) => a === '-h' || a === '--help');
}

const SECRET_USAGE = 'usage: zn secret set|list|rm|allow|approve|import|adopt|log ...';

async function dispatch(group, args, ioIn) {
  const io = makeIo(ioIn);
  try {
    const helpKey = group === 'secrets' ? 'secret' : group;
    if (HELP[helpKey] && !(helpKey === 'secret' && args[0] === 'log') && wantsHelp(args)) {
      for (const line of HELP[helpKey]) out(io, line);
      return 0;
    }
    if (group === 'secret' || group === 'secrets') {
      const [sub, ...rest] = args;
      if (sub === 'set') return await secretSet(rest, io);
      if (sub === 'list' || sub === 'ls') return await secretList(rest, io);
      if (sub === 'rm' || sub === 'remove') return await secretRm(rest, io);
      if (sub === 'allow') return await secretAllow(rest, io);
      if (sub === 'approve') return await secretApprove(rest, io);
      if (sub === 'import') return await secretImport(rest, io);
      if (sub === 'adopt') return await secretAdopt(rest, io);
      if (sub === 'log') return await audit(rest, io);
      if (sub === 'get' || sub === 'reveal') {
        throw deps.znError('ZN_POLICY_DENIED', 'zn does not print secret values. To use one in a command, run: ' + znCommand('run --secrets NAME -- <command>'));
      }
      throw deps.znError('ZN_USAGE', SECRET_USAGE);
    }
    if (group === 'env') {
      const [sub, ...rest] = args;
      if (sub === 'shadow') return await envShadow(rest, io);
      if (sub === 'unshadow') return await envUnshadow(rest, io);
      throw deps.znError('ZN_USAGE', 'usage: zn env shadow [FILE] | zn env unshadow FILE --backup NAME');
    }
    if (group === 'vault') {
      // Reached from `zn vault log` (lib/vault/cli.js routes it here).
      if (args[0] === 'log') return await audit(args.slice(1), io);
      throw deps.znError('ZN_USAGE', 'usage: zn vault log [--since 1h]');
    }
    if (group === 'hooks') return await hooks(args, io);
    if (group === 'uninstall') return await require('../uninstall').run(args, io);
    throw deps.znError('ZN_USAGE', 'unknown command ' + group);
  } catch (err) {
    io.stderr.write('zn ' + group + ': ' + humanError(err) + '\n');
    return err.code === 'ZN_USAGE' ? 64 : err.code === 'ZN_POLICY_DENIED' ? 77 : 1;
  }
}

module.exports = { dispatch, parseFlags, planImport, secretNameForKey, backupName };
