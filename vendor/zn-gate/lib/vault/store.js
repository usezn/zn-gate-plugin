'use strict';
/**
 * Encrypted store on disk. Everything secret is an age file; nothing is
 * ever written in clear.
 *
 *   ~/.zn/                       (0700)   override with ZN_HOME
 *     vault/                     (0700)
 *       secrets.age              named secrets + local audit key
 *       <project-hash>.age       token map of one project (detected values)
 *       identity.age             age identity behind a passphrase (only when
 *                                no OS keychain is available)
 *       keychain.json            backend name + age recipient (public key)
 *     run/                       (0700)   daemon socket and session key
 *     audit.jsonl                (0600)   HMAC-chained audit log
 *
 * Files are written atomically (temporary file + rename) with mode 0600.
 * On POSIX the directories are checked to be owned by the current user and
 * closed to group and others; anything else is refused. On Windows they get an
 * explicit owner-only access list that is read back (lib/vault/winacl.js).
 *
 * Encryption: age X25519 recipients (age-encryption, by Filippo Valsorda);
 * scrypt recipients for the passphrase fallback. No custom cryptography.
 */

const fs = require('fs');
const { trimTrailing } = require('../linear-text');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { CODES, znError } = require('../errors');
const winacl = require('./winacl');

const PROJECT_FILE_RE = /^[0-9a-f]{32}\.age$/;
const STALE_DAYS = 30;

/* ------------------------------------------------------------------ */
/* Paths                                                               */
/* ------------------------------------------------------------------ */

function znHome(opts) {
  if (opts && opts.home) return path.resolve(opts.home);
  if (process.env.ZN_HOME) return path.resolve(process.env.ZN_HOME);
  return path.join(os.homedir(), '.zn');
}

function paths(opts) {
  const home = znHome(opts);
  const vaultDir = path.join(home, 'vault');
  const runDir = path.join(home, 'run');
  return {
    home,
    vaultDir,
    runDir,
    secretsFile: path.join(vaultDir, 'secrets.age'),
    identityFile: path.join(vaultDir, 'identity.age'),
    metaFile: path.join(vaultDir, 'keychain.json'),
    auditFile: path.join(home, 'audit.jsonl'),
  };
}

function normalizeProject(project) {
  const p = String(project == null ? '' : project);
  if (path.isAbsolute(p)) {
    let r = path.resolve(p);
    if (process.platform === 'win32') r = r.toLowerCase();
    return trimTrailing(r, '\\/') || r;
  }
  return p;
}

/** Stable, non-reversible file key for a project (hash of its path or id). */
function projectKey(project) {
  return crypto.createHash('sha256').update('zn-project-v1\0' + normalizeProject(project)).digest('hex').slice(0, 32);
}

function projectFile(project, opts) {
  return path.join(paths(opts).vaultDir, projectKey(project) + '.age');
}

/* ------------------------------------------------------------------ */
/* Permissions                                                         */
/* ------------------------------------------------------------------ */

function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw znError(CODES.POLICY_DENIED, 'not a directory: ' + dir);
  if (process.platform === 'win32') {
    // Explicit owner-only permissions, set and read back; refused if that fails.
    winacl.ensurePrivate(dir, { dir: true });
    return;
  }
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw znError(CODES.POLICY_DENIED, 'directory is owned by another user: ' + dir);
  }
  if ((st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
}

function ensureLayout(opts) {
  const p = paths(opts);
  ensurePrivateDir(p.home);
  ensurePrivateDir(p.vaultDir);
  ensurePrivateDir(p.runDir);
  return p;
}

/* ------------------------------------------------------------------ */
/* age                                                                 */
/* ------------------------------------------------------------------ */

let agePromise = null;
function loadAge() {
  if (!agePromise) {
    // Node 18 has WebCrypto but not as a global; age-encryption expects one.
    if (!globalThis.crypto || !globalThis.crypto.getRandomValues) {
      globalThis.crypto = require('crypto').webcrypto;
    }
    agePromise = import('age-encryption');
  }
  return agePromise;
}

async function generateIdentity() {
  const age = await loadAge();
  const identity = await age.generateX25519Identity();
  const recipient = await age.identityToRecipient(identity);
  return { identity, recipient };
}

async function recipientOf(identity) {
  const age = await loadAge();
  return age.identityToRecipient(identity);
}

async function encryptTo(recipient, plaintext) {
  const age = await loadAge();
  const e = new age.Encrypter();
  e.addRecipient(recipient);
  return e.encrypt(plaintext);
}

async function decryptWith(identity, ciphertext) {
  const age = await loadAge();
  const d = new age.Decrypter();
  d.addIdentity(identity);
  return d.decrypt(ciphertext, 'text');
}

async function encryptWithPassphrase(passphrase, plaintext, workFactor) {
  const age = await loadAge();
  const e = new age.Encrypter();
  e.setPassphrase(passphrase);
  if (workFactor) e.setScryptWorkFactor(workFactor);
  return e.encrypt(plaintext);
}

async function decryptWithPassphrase(passphrase, ciphertext) {
  const age = await loadAge();
  const d = new age.Decrypter();
  d.addPassphrase(passphrase);
  return d.decrypt(ciphertext, 'text');
}

/* ------------------------------------------------------------------ */
/* Atomic private files                                                */
/* ------------------------------------------------------------------ */

function writePrivateFile(file, data) {
  ensurePrivateDir(path.dirname(file));
  const tmp = file + '.' + process.pid + '.' + crypto.randomBytes(6).toString('hex') + '.tmp';
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch (e) { /* ignore */ }
    throw err;
  }
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}

function readPrivateFile(file) {
  let st;
  try { st = fs.lstatSync(file); } catch (err) { if (err.code === 'ENOENT') return null; throw err; }
  if (!st.isFile() || st.isSymbolicLink()) throw znError(CODES.POLICY_DENIED, 'not a regular file: ' + file);
  if (process.platform !== 'win32' && typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw znError(CODES.POLICY_DENIED, 'file is owned by another user: ' + file);
  }
  return fs.readFileSync(file);
}

/** Read and decrypt a JSON age file; null when it does not exist. */
async function readEncrypted(file, identity) {
  const buf = readPrivateFile(file);
  if (buf === null) return null;
  let text;
  try {
    text = await decryptWith(identity, new Uint8Array(buf));
  } catch (err) {
    throw znError(CODES.LOCKED, require('../messages').vaultDamaged(path.basename(file),
      'is corrupted or was encrypted to another key', (err && err.message) || err));
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    // The parser's message quotes the start of the decrypted text: never pass it on, not even with ZN_VERBOSE or DEBUG.
    throw znError(CODES.LOCKED, require('../messages').vaultDamaged(path.basename(file),
      'is corrupted or was encrypted to another key', 'not valid JSON'));
  }
}

/** true when this ZN_HOME already has history: an audit log or project maps. */
function hasPriorState(opts) {
  const p = paths(opts);
  try { if (fs.statSync(p.auditFile).size > 0) return true; } catch (err) { /* none */ }
  try { return fs.readdirSync(p.vaultDir).some((n) => PROJECT_FILE_RE.test(n)); } catch (err) { return false; }
}

/** Encrypt JSON to the recipient and write it atomically (0600). */
async function writeEncrypted(file, data, recipient) {
  const ct = await encryptTo(recipient, JSON.stringify(data));
  writePrivateFile(file, Buffer.from(ct));
}

/* ------------------------------------------------------------------ */
/* Housekeeping                                                        */
/* ------------------------------------------------------------------ */

const MAX_PLAUSIBLE_GAP_DAYS = 400;
const PRUNE_MARK = '.last-prune';
const PRUNE_SKIPPED = '.prune-skipped-since';

/** Delete project token maps unused for `days` (default 30). Returns count. */
function pruneStale(opts) {
  const days = (opts && opts.days) || STALE_DAYS;
  const dir = paths(opts).vaultDir;
  let removed = 0;
  let names = [];
  try { names = fs.readdirSync(dir); } catch (err) { return 0; }
  const now = Date.now();
  const limit = now - days * 86400000;
  const maps = [];
  let newest = -Infinity;
  for (const n of names) {
    if (!PROJECT_FILE_RE.test(n)) continue;
    const f = path.join(dir, n);
    try {
      const m = fs.statSync(f).mtimeMs;
      maps.push([f, m]);
      if (m > newest) newest = m;
    } catch (err) { /* ignore */ }
  }
  // A wrong clock must never delete token maps (there is no way back): skip when the newest map is dated
  // in the future, or when now is implausibly far ahead of it.
  if (maps.length && (newest > now + 86400000 || now - newest > MAX_PLAUSIBLE_GAP_DAYS * 86400000)) {
    process.stderr.write('zn-gate: vault prune skipped, the system clock looks wrong\n');
    return 0;
  }
  // The clock can also be wrong by 31 to 400 days, which the checks above cannot see. So every prune that
  // runs on a sane clock records its time on disk, and a later prune only deletes while the clock is within
  // `days` of that record. A jump ahead skips the prune and the record is not moved, so a wrong clock cannot
  // approve itself. The skip is time-bound (a user who was simply away must not keep stale maps for ever):
  // the first skip notes its time, and once the clock has kept running for 7 days since then it is accepted.
  // If the clock returns to normal before that, the next prune deletes as usual and the note is cleared.
  const run = paths(opts).runDir;
  const marker = path.join(run, PRUNE_MARK);
  const skipFile = path.join(run, PRUNE_SKIPPED);
  let last = NaN;
  let since = NaN;
  try { last = Number(fs.readFileSync(marker, 'utf8').trim()); } catch (err) { /* no record yet */ }
  try { since = Number(fs.readFileSync(skipFile, 'utf8').trim()); } catch (err) { /* not skipping */ }
  if (maps.length && Number.isFinite(last) && now - last > days * 86400000) {
    if (!(Number.isFinite(since) && now - since >= 7 * 86400000)) {
      if (!Number.isFinite(since)) {
        try { fs.mkdirSync(run, { recursive: true, mode: 0o700 }); fs.writeFileSync(skipFile, String(now), { mode: 0o600 }); } catch (err) { /* ignore */ }
      }
      process.stderr.write('zn-gate: vault prune skipped, the system clock looks wrong; it resumes after 7 days unless the clock is fixed\n');
      return 0;
    }
  }
  for (const [f, m] of maps) {
    try {
      if (m < limit) { fs.unlinkSync(f); removed++; }
    } catch (err) { /* ignore */ }
  }
  try { fs.mkdirSync(run, { recursive: true, mode: 0o700 }); fs.writeFileSync(marker, String(now), { mode: 0o600 }); } catch (err) { /* ignore */ }
  try { fs.unlinkSync(skipFile); } catch (err) { /* none */ }
  return removed;
}

/** Forget one project's token map (zn-gate scrub forget). */
function forgetProject(project, opts) {
  try { fs.unlinkSync(projectFile(project, opts)); return true; } catch (err) { return false; }
}

function touch(file) {
  const now = new Date();
  try { fs.utimesSync(file, now, now); } catch (err) { /* ignore */ }
}

module.exports = {
  znHome,
  paths,
  projectKey,
  projectFile,
  normalizeProject,
  ensureLayout,
  ensurePrivateDir,
  loadAge,
  generateIdentity,
  recipientOf,
  encryptTo,
  decryptWith,
  encryptWithPassphrase,
  decryptWithPassphrase,
  readEncrypted,
  writeEncrypted,
  hasPriorState,
  writePrivateFile,
  readPrivateFile,
  pruneStale,
  forgetProject,
  touch,
  STALE_DAYS,
};
