'use strict';
/**
 * `zn vault purge`: delete the vault for good, backups included.
 *
 * `zn vault reset` sets the old vault aside (a `vault-backup-*` folder) and starts empty; it
 * never deletes anything. Purge is the other operation: it lists every file it will delete (the
 * vault, its token maps, the audit log, every backup, the session key), asks the person to
 * confirm, deletes them, and checks that none is left. It never says "deleted" when something
 * remains.
 *
 * Guards, each before anything is touched:
 *   - never an AI agent. A person at a terminal types the phrase; a script (no terminal, no
 *     agent) may pass --yes instead;
 *   - this computer is not part of a zn Team organization (same reason as the reset);
 *   - the vault is locked.
 */

const fs = require('fs');
const path = require('path');
const store = require('./store');
const keychain = require('./keychain');
const daemon = require('./daemon');
const tty = require('../broker/tty');
const messages = require('../messages');
const reset = require('./reset');
const policy = require('../team/policy');

const PHRASE = 'purge my vault';
const BACKUP_RE = /^vault-backup-/;

const zn = (args) => require('../zn-command').znCommand(args);

const KIND = {
  'secrets.age': 'secrets and first-use approvals',
  'identity.age': 'vault key (passphrase protected)',
  'keychain.json': 'vault settings',
};

function kindOf(rel) {
  const base = path.basename(rel);
  if (rel === 'audit.jsonl') return 'audit log';
  if (KIND[base]) return KIND[base];
  if (/^[0-9a-f]{32}\.age$/.test(base)) return 'token map of a project';
  return 'file';
}

function walk(dir, acc, dirs) {
  let names = [];
  try { names = fs.readdirSync(dir); } catch (err) { return acc; }
  for (const n of names) {
    const f = path.join(dir, n);
    let st;
    try { st = fs.lstatSync(f); } catch (err) { continue; }
    if (st.isDirectory()) { if (dirs) dirs.push(f); walk(f, acc, dirs); } else acc.push(f);
  }
  return acc;
}

const LINK_KIND = 'link to another folder (only the link is deleted, never what it points to)';

/** The native backend that holds a zn entry on this computer when keychain.json cannot say; else null. */
function probeNative() {
  let b = null;
  try { b = keychain.detectBackend(); } catch (err) { return null; }
  if (!b || b === 'passphrase' || !keychain._native[b]) return null;
  try { return keychain._native[b].load() ? b : null; } catch (err) { return null; }
}

function lstatOf(f) {
  try { return fs.lstatSync(f); } catch (err) { return null; }
}

/**
 * Everything purge would delete: { files: [{ path, kind }], dirs: [backup folders, deepest first],
 * backend }. A symbolic link is listed as the link itself and never followed: a `vault` or `run`
 * folder that is a link is deleted as a link, and the folder it points to is not read or touched.
 */
function targets(opts) {
  const p = store.paths(opts);
  const vaultSt = lstatOf(p.vaultDir);
  const vaultLink = !!(vaultSt && !vaultSt.isDirectory());
  const files = reset.vaultFiles(opts)
    .filter((f) => !vaultLink || path.dirname(f.src) !== p.vaultDir)
    .map((f) => ({ path: f.src, kind: kindOf(f.rel) }));
  if (vaultLink) files.push({ path: p.vaultDir, kind: vaultSt.isSymbolicLink() ? LINK_KIND : 'file in place of the vault folder' });
  // A link in place of one of the vault's own files (or of the audit log) is deleted as a link too.
  if (vaultSt && vaultSt.isDirectory()) {
    let names = [];
    try { names = fs.readdirSync(p.vaultDir); } catch (err) { /* unreadable: the second look reports it */ }
    for (const n of names) {
      if (!(Object.prototype.hasOwnProperty.call(KIND, n) || /^[0-9a-f]{32}\.age$/.test(n))) continue;
      const f = path.join(p.vaultDir, n);
      const st = lstatOf(f);
      if (st && st.isSymbolicLink()) files.push({ path: f, kind: LINK_KIND });
    }
  }
  const auditSt = lstatOf(p.auditFile);
  if (auditSt && auditSt.isSymbolicLink()) files.push({ path: p.auditFile, kind: LINK_KIND });
  const dirs = [];
  let names = [];
  try { names = fs.readdirSync(p.home); } catch (err) { /* no zn folder */ }
  for (const n of names.filter((x) => BACKUP_RE.test(x)).sort()) {
    const d = path.join(p.home, n);
    let st;
    try { st = fs.lstatSync(d); } catch (err) { continue; }
    if (!st.isDirectory()) { files.push({ path: d, kind: 'backup' }); continue; }
    for (const f of walk(d, [], dirs)) files.push({ path: f, kind: 'backup (' + n + ')' });
    dirs.push(d);
  }
  // The run folder holds a few plain files (the session key and the daemon's socket or pipe name): its first level only.
  const runSt = lstatOf(p.runDir);
  if (runSt && !runSt.isDirectory()) {
    files.push({ path: p.runDir, kind: runSt.isSymbolicLink() ? LINK_KIND : 'file' });
  } else if (runSt) {
    let runNames = [];
    try { runNames = fs.readdirSync(p.runDir).sort(); } catch (err) { /* unreadable: the second look reports it */ }
    for (const n of runNames) {
      const f = path.join(p.runDir, n);
      const st = lstatOf(f);
      if (!st || st.isDirectory()) continue;
      files.push({ path: f, kind: n === 'session.key' ? 'session key' : 'daemon runtime file' });
    }
  }
  const fails = path.join(p.home, 'unlock-failures');
  try { if (fs.lstatSync(fails).isFile()) files.push({ path: fails, kind: 'failed-unlock counter' }); } catch (err) { /* none */ }
  let backend = null;
  let probe = null;
  // keychain.json is read only from a real vault folder, never through a link. When it is damaged, ask the system backends.
  if (vaultSt && vaultSt.isDirectory()) {
    try { const m = keychain.readMeta(opts); backend = m && m.backend; } catch (err) { probe = probeNative(); }
  }
  return { files, dirs: dirs.sort((a, b) => b.length - a.length), backend, probe };
}

/** Is the folder holding this file inside the zn folder, once links are resolved? */
function insideHome(f, home) {
  try {
    const real = fs.realpathSync(path.dirname(f));
    const root = fs.realpathSync(home);
    return real === root || real.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
  } catch (err) { return false; }
}

/** Delete one file or link (a link is removed itself, never what it points to); returns true when it is gone. */
function unlinkGone(f, home) {
  if (home) {
    let dir = null;
    try { dir = fs.realpathSync(path.dirname(f)); } catch (err) { return !!err && err.code === 'ENOENT'; }
    if (!insideHome(f, home) || !dir) return false;
  }
  try { fs.unlinkSync(f); } catch (err) {
    if (!err || err.code === 'ENOENT') return true;
    // Windows: a link to a folder is removed like a folder.
    const st = lstatOf(f);
    if (!(st && st.isSymbolicLink() && (err.code === 'EPERM' || err.code === 'EISDIR'))) return false;
    try { fs.rmdirSync(f); } catch (err2) { return !lstatOf(f); }
  }
  return true;
}

/**
 * Delete everything targets() lists. Files first, the vault key last: if a file cannot be
 * removed the key stays, so what is left still opens. Returns
 * { removed: [paths], left: [paths still there], key: 'none'|'removed'|'kept'|'unconfirmed'|'left', backend }.
 */
async function removeAll(opts) {
  const t = targets(opts);
  const removed = [];
  const left = [];
  const home = store.paths(opts).home;
  for (const f of t.files) (unlinkGone(f.path, home) ? removed : left).push(f.path);
  let key = 'none';
  if (left.length) {
    key = t.backend && t.backend !== 'passphrase' ? 'kept' : 'none';
  } else if (t.backend && t.backend !== 'passphrase') {
    // Name the backend: the settings file that says which one is already gone.
    try { await keychain.deleteIdentity(Object.assign({}, opts, { backend: t.backend })); } catch (err) { /* checked below */ }
    try { key = keychain._native[t.backend].load() === null ? 'removed' : 'left'; } catch (err) { key = 'unconfirmed'; }
  }
  const p = store.paths(opts);
  for (const d of t.dirs) { try { fs.rmdirSync(d); } catch (err) { /* checked below */ } }
  for (const d of [p.runDir, p.vaultDir]) { try { fs.rmdirSync(d); } catch (err) { /* not empty or gone */ } }
  // Look again: what is still on disk counts, whatever each call said.
  for (const f of targets(opts).files) if (!left.includes(f.path)) left.push(f.path);
  for (const d of t.dirs) if (fs.existsSync(d) && !left.includes(d)) left.push(d);
  return { removed: removed.filter((f) => !left.includes(f)), left, key, backend: t.backend, probe: t.probe };
}

/** The sentence for a key that is not confirmed gone, or null. */
function keyProblem(r) {
  if (r.key === 'kept') return 'The vault key in your system keychain was kept, so what is left of the vault can still be opened.';
  if (r.key === 'left' || r.key === 'unconfirmed') {
    return 'The vault key could not be removed from your ' + r.backend + ' keychain' + (r.key === 'unconfirmed' ? ' (zn could not check)' : '') +
      '. It is harmless without the files; remove the "zn" entry by hand.';
  }
  return null;
}

/** A note (not a failure) when keychain.json is damaged and a system keychain still holds a zn entry, or null. */
function keyNote(r) {
  if (!r || !r.probe) return null;
  return 'zn could not read the vault settings (damaged), and your ' + r.probe + ' keychain still holds a "zn" entry. zn cannot tell whether it belongs to this vault, so it was not touched. It is harmless without the vault files; remove the "zn" entry by hand if you use no other vault.';
}

/**
 * Returns the exit code. opts: { yes }. io (tests): stdin, env, ancestry, ask(question), out(line).
 * Throws the "needs a person" refusals.
 */
async function purgeVault(opts, io) {
  const o = opts || {};
  const i = io || {};
  const out = i.out || ((s) => process.stdout.write(s + '\n'));
  if (o.yes) {
    // A script has no terminal, but an agent still may not purge.
    const agent = tty.agentDetected(i.env || process.env, i);
    if (agent) { const e = new Error(messages.agentRefusal('zn vault purge', agent)); e.code = 'ZN_POLICY_DENIED'; throw e; }
  } else {
    tty.requireHuman('zn vault purge', i);
  }
  const t = targets(o);
  if (!t.files.length) {
    out('There is no vault here to purge. Nothing was changed.');
    const note = keyNote(t);
    if (note) out(note);
    return 0;
  }
  const policyFiles = policy.paths(o);
  if ([policyFiles.teamFile, policyFiles.policyFile].some((x) => fs.existsSync(x))) { process.stderr.write('[zn] ' + reset.TEAM_REFUSAL + '\n'); return 1; }
  if (await daemon.isRunning(o)) { process.stderr.write('[zn] The vault is unlocked. Run `' + zn('lock') + '` first, then `' + zn('vault purge') + '`.\n'); return 1; }

  out('This deletes the vault for good, with every backup. It cannot be undone. These ' + t.files.length + ' files will be deleted:');
  for (const f of t.files) out('  - ' + f.path + '  (' + f.kind + ')');
  if (t.backend && t.backend !== 'passphrase') out('  - the vault key in your ' + t.backend + ' keychain');
  out('To keep an encrypted copy and start a new vault instead, use `' + zn('vault reset') + '`.');
  if (!o.yes) {
    const answer = await (i.ask || ((q) => reset.askLine(q, i)))('To go on, type "' + PHRASE + '" and press Enter: ');
    if (String(answer).trim().toLowerCase() !== PHRASE) { out('Nothing was purged: the phrase did not match. Your vault is as it was.'); return 1; }
  }

  const r = await removeAll(o);
  const problem = keyProblem(r);
  if (r.left.length || problem) {
    if (r.left.length) {
      out('The vault was NOT fully purged. These could not be removed:');
      for (const f of r.left) out('  - ' + f);
      out('Delete them by hand (or fix their permissions) and run `' + zn('vault purge') + '` again.');
    }
    if (problem) out(problem);
    return 1;
  }
  try { reset.clearUnlockFailures(o); } catch (err) { /* none */ }
  out('Purged: ' + r.removed.length + ' files deleted, and a new check found none left. Run `' + zn('unlock') + '` to create a new vault.');
  const note = keyNote(r);
  if (note) out(note);
  return 0;
}

/**
 * The list of what purge deletes, for a person to read before they answer: backups by folder, token
 * maps counted, every other file by name. Returns lines.
 */
function describe(t, opts) {
  const home = store.paths(opts).home;
  const lines = [];
  const backups = new Map();
  let maps = 0;
  let mapsDir = null;
  for (const f of t.files) {
    const m = /^backup \((.+)\)$/.exec(f.kind);
    if (m) { const k = backups.get(m[1]) || { n: 0 }; k.n += 1; backups.set(m[1], k); continue; }
    if (f.kind === 'token map of a project') { maps += 1; mapsDir = path.dirname(f.path); continue; }
    lines.push(f.path + '  (' + f.kind + ')');
  }
  if (maps) lines.push(mapsDir + '  (' + maps + ' token map' + (maps === 1 ? '' : 's') + ' of projects)');
  for (const [name, k] of [...backups].sort((a, b) => a[0].localeCompare(b[0]))) {
    lines.push(path.join(home, name) +'  (backup made by `zn vault reset`, ' + k.n + ' file' + (k.n === 1 ? '' : 's') + ')');
  }
  if (t.backend && t.backend !== 'passphrase') lines.push('the vault key in your ' + t.backend + ' keychain');
  return lines;
}

module.exports = { purgeVault, targets, removeAll, keyProblem, keyNote, describe, PHRASE, _unlinkGone: unlinkGone };
