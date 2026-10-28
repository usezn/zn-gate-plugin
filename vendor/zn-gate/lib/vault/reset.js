'use strict';
/**
 * `zn vault reset`: the way out when the vault passphrase is lost.
 *
 * It sets the old vault aside (a timestamped backup folder) and leaves
 * nothing behind, so the next `zn unlock` creates a new, empty vault. The
 * values stored in the old vault are not recoverable without the old
 * passphrase: that is what makes the vault safe, and a reset cannot change it.
 *
 * Guards, in this order, each before anything is touched:
 *   - a person at a terminal (no AI agent, no script; same check as the other
 *     commands only a person may run);
 *   - this computer is not part of a zn Team organization: the organization's
 *     controls live inside the vault, so a reset would drop them. It refuses;
 *   - the vault is locked;
 *   - the person types a confirmation phrase.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const store = require('./store');
const keychain = require('./keychain');
const daemon = require('./daemon');
const { requireHuman } = require('../broker/tty');
const policy = require('../team/policy');

const PHRASE = 'reset my vault';
const FAILS_BEFORE_HINT = 3;
const PROJECT_FILE_RE = /^[0-9a-f]{32}\.age$/;
const VAULT_FILES = ['secrets.age', 'identity.age', 'keychain.json'];

const zn = (args) => require('../zn-command').znCommand(args);

const TEAM_REFUSAL = 'This computer belongs to a zn Team organization, and its controls are kept inside the vault. ' +
  'A reset would remove them, so zn will not do it. Nothing was changed. Ask your organization administrator for help.';
const LOCK_FIRST = () => 'The vault is unlocked. Run `' + zn('lock') + '` first, then `' + zn('vault reset') + '`.';
const NOTHING = () => 'There is no vault here to reset. Run `' + zn('unlock') + '` to create one.';
const CANCELLED = 'Nothing was reset: the phrase did not match. Your vault is as it was.';
const UNREADABLE_HINT = 'The vault could not be opened, and the passphrase is not the problem. Do not reset the vault yet. More: https://usezn.com/docs/zn-gate/troubleshooting/';
const HINT = () => 'Forgot the passphrase? `' + zn('vault reset') + '` starts a new, empty vault (the old values are lost).';

/** The files of this vault that exist now: [{ src, rel }] with rel relative to the backup folder. */
function vaultFiles(opts) {
  const p = store.paths(opts);
  const found = [];
  const add = (src, rel) => { try { if (fs.lstatSync(src).isFile()) found.push({ src, rel }); } catch (err) { /* absent */ } };
  let names = [];
  try { if (fs.lstatSync(p.vaultDir).isDirectory()) names = fs.readdirSync(p.vaultDir); } catch (err) { /* no vault folder, or a link: never followed */ }
  for (const n of names) if (VAULT_FILES.includes(n) || PROJECT_FILE_RE.test(n)) add(path.join(p.vaultDir, n), path.join('vault', n));
  add(p.auditFile, 'audit.jsonl');
  return found;
}

function teamPresent(opts) {
  const f = policy.paths(opts);
  return [f.teamFile, f.policyFile].some((x) => fs.existsSync(x));
}

function stamp(now) {
  const d = now || new Date();
  const z = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + z(d.getMonth() + 1) + z(d.getDate()) + '-' + z(d.getHours()) + z(d.getMinutes()) + z(d.getSeconds());
}

/** Copy the files into a new private backup folder and check each copy. Returns the folder. */
function backup(files, opts, now) {
  const home = store.paths(opts).home;
  let dir = path.join(home, 'vault-backup-' + stamp(now));
  for (let i = 2; fs.existsSync(dir); i++) dir = path.join(home, 'vault-backup-' + stamp(now) + '-' + i);
  store.ensurePrivateDir(dir);
  for (const f of files) {
    const dest = path.join(dir, f.rel);
    store.ensurePrivateDir(path.dirname(dest));
    fs.copyFileSync(f.src, dest, fs.constants.COPYFILE_EXCL);
    if (process.platform !== 'win32') fs.chmodSync(dest, 0o600);
    if (fs.statSync(dest).size !== fs.statSync(f.src).size) throw new Error('the backup copy of ' + f.rel + ' is incomplete; nothing was reset');
  }
  return dir;
}

function askLine(question, io) {
  const input = io.stdin || process.stdin;
  const output = io.stderr || process.stderr;
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input, output, terminal: false });
    output.write(question);
    let got = false;
    rl.once('line', (l) => { got = true; rl.close(); resolve(l); });
    rl.once('close', () => { if (!got) resolve(''); });
  });
}

/**
 * Returns the exit code. io (tests): stdin, env, ancestry, ask(question), out(line), now.
 * Throws the "needs a person" refusals from requireHuman.
 */
async function resetVault(opts, io) {
  const o = opts || {};
  const i = io || {};
  const out = i.out || ((s) => process.stdout.write(s + '\n'));
  requireHuman('zn vault reset', i);
  const files = vaultFiles(o);
  if (!files.length) { out(NOTHING()); return 0; }
  if (teamPresent(o)) { process.stderr.write('[zn] ' + TEAM_REFUSAL + '\n'); return 1; }
  if (await daemon.isRunning(o)) { process.stderr.write('[zn] ' + LOCK_FIRST() + '\n'); return 1; }

  let backend = null;
  try { const m = keychain.readMeta(o); backend = m && m.backend; } catch (err) { /* damaged: the reset is the way out */ }
  out('This starts a new, empty vault. The old one is set aside, not deleted.');
  out('  - Every secret stored in it is lost. Without the old passphrase nobody can read them again, zn included.');
  out('  - The audit log of secret use starts again from zero.');
  if (backend && backend !== 'passphrase') out('  - The old vault key is replaced in your ' + backend + ' keychain, so the backup cannot be opened afterwards.');
  out('  - Your .env files and shadowed projects keep their markers; store the values again afterwards.');
  const answer = await (i.ask || ((q) => askLine(q, i)))('To go on, type "' + PHRASE + '" and press Enter: ');
  if (String(answer).trim().toLowerCase() !== PHRASE) { out(CANCELLED); return 1; }

  const dir = backup(files, o, i.now);
  for (const f of files) fs.unlinkSync(f.src);
  clearUnlockFailures(o);
  out('Old vault saved in ' + dir + ' (it stays encrypted). `' + zn('vault purge') + '` deletes it, with every other backup, when you no longer need it.');
  out('Done. Run `' + zn('unlock') + '` to create the new vault, then store your values again:');
  out('  ' + zn('env shadow .env') + '        move the values of a .env file into the vault');
  out('  ' + zn('secret set NAME') + '        store one value (typed at a hidden prompt)');
  return 0;
}

/* Failed unlocks are counted in a small file, so the hint also shows across separate `zn unlock` runs. */
function failFile(opts) { return path.join(store.paths(opts).home, 'unlock-failures'); }

function readFails(opts) {
  try { const n = parseInt(fs.readFileSync(failFile(opts), 'utf8'), 10); return Number.isSafeInteger(n) && n > 0 ? n : 0; } catch (err) { return 0; }
}

/** Counts one failed unlock; returns the hint once there were FAILS_BEFORE_HINT in a row, else null. */
function recordUnlockFailure(opts) {
  const n = readFails(opts) + 1;
  try { store.writePrivateFile(failFile(opts), String(n)); } catch (err) { /* the hint is a courtesy */ }
  return n >= FAILS_BEFORE_HINT ? HINT() : null;
}

function clearUnlockFailures(opts) {
  try { fs.unlinkSync(failFile(opts)); } catch (err) { /* none */ }
}

/**
 * The hint to print after `zn unlock` failed with ZN_LOCKED, or null.
 * Only a wrong passphrase counts toward the reset hint. Any other failure (a damaged vault
 * file, a keychain error) restarts the count and gets a hint that does not suggest a reset.
 */
function hintForUnlockError(err, opts) {
  if (err && err.reason === keychain.WRONG_PASSPHRASE) return recordUnlockFailure(opts);
  clearUnlockFailures(opts);
  // A damaged-file message already says what to do and links the page: do not say it twice.
  if (err && /vault reset/.test(String(err.message))) return null;
  return UNREADABLE_HINT;
}

module.exports = { askLine, hintForUnlockError, resetVault, recordUnlockFailure, clearUnlockFailures, vaultFiles, PHRASE, FAILS_BEFORE_HINT, UNREADABLE_HINT, TEAM_REFUSAL, CANCELLED };
// The sentences that name a command are built when read, so they show the form that works on this computer.
Object.defineProperties(module.exports, {
  HINT: { enumerable: true, get: HINT },
  LOCK_FIRST: { enumerable: true, get: LOCK_FIRST },
  NOTHING: { enumerable: true, get: NOTHING },
});
