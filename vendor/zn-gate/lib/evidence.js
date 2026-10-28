'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
// rules (with the scrubber engine behind it), term and http are loaded where they are used, so an
// append that does not need them (a hook block, see _plainPreview in logEvidence) stays cheap.

const ZN_DIR = path.join(os.homedir(), '.zn');
const EVIDENCE_FILE = path.join(ZN_DIR, 'evidence.jsonl');
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// The ledger directory is private to the user; modes are POSIX only (ignored on Windows).
const LEDGER_DIR_MODE = 0o700;
const LEDGER_FILE_MODE = 0o600;

function ensureZnDir(filePath = EVIDENCE_FILE) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: LEDGER_DIR_MODE });
  }
}

/**
 * Appends one line to the ledger. The file is created with mode 0600, and an
 * existing ledger that others can read or write is restricted to 0600 through
 * the open descriptor before the line is written (POSIX only), so a symlink
 * swapped in between cannot redirect the chmod.
 */
function appendLedgerLine(filePath, line) {
  const fd = fs.openSync(filePath, 'a', LEDGER_FILE_MODE);
  try {
    if (process.platform !== 'win32') {
      try {
        if ((fs.fstatSync(fd).mode & 0o077) !== 0) fs.fchmodSync(fd, LEDGER_FILE_MODE);
      } catch {
        // Best effort: a file system without POSIX modes keeps its own.
      }
    }
    fs.writeSync(fd, line, null, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}

class EvidenceLedgerError extends Error {}

// Writers take an exclusive lock around "read the last hash + append", so two processes (for
// example two agents in the same project) cannot both chain onto the same record and fork the
// log. The lock is a sidecar file `<log>.lock` created with O_EXCL; the Python package uses the
// same file and the same rules, so the two exclude each other. A writer waits at most
// LOCK_WAIT_MS; if it cannot get the lock it skips the write (fail closed: the log is never
// written without the lock) and the caller goes on. A lock file older than LOCK_STALE_MS
// belongs to a process that died (or was suspended) and is broken. The lock holds its owner's
// token: a writer only deletes the lock while it is still its own, and checks that again just
// before it appends, so a writer that lost its lock to a takeover writes nothing.
const LOCK_WAIT_MS = 2000;
const LOCK_STALE_MS = 10000;

class EvidenceLockError extends Error {}

function sleepMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function readLockToken(lockPath) {
  try { return fs.readFileSync(lockPath, 'utf8'); } catch { return null; }
}

// Test seams: they let a test run code between two steps of the break protocol.
const testHooks = { afterMutexCreate: null, beforeMutexRelease: null, beforeMutexReclaim: null };

// The break mutex holds its owner's token, like the lock: a breaker only deletes the mutex while
// it is still its own. If it took longer than the stale window, another breaker may have
// reclaimed it and created a new one, and deleting by path would remove that one.
function releaseMutex(mutex, token) {
  if (readLockToken(mutex) === token) {
    try { fs.unlinkSync(mutex); } catch { /* best effort */ }
  }
}

// A mutex older than the stale window belongs to a breaker that died. Move it aside first (never
// delete by the shared path: a new mutex may have been created since we looked), and put it back
// with link() if what we moved turns out to be fresh.
function reclaimStaleMutex(mutex, token) {
  try {
    if (Math.abs(Date.now() - fs.statSync(mutex).mtimeMs) <= LOCK_STALE_MS) return;
    if (testHooks.beforeMutexReclaim) testHooks.beforeMutexReclaim(mutex);
    const aside = `${mutex}-reclaim-${token.replace(':', '-')}`;
    fs.renameSync(mutex, aside);
    let fresh = false;
    try { fresh = Math.abs(Date.now() - fs.statSync(aside).mtimeMs) <= LOCK_STALE_MS; } catch { /* gone */ }
    if (fresh) {
      try { fs.linkSync(aside, mutex); } catch { /* another mutex exists again: its owner checks its token */ }
    }
    try { fs.unlinkSync(aside); } catch { /* best effort */ }
  } catch { /* gone or busy: wait and retry */ }
}

/**
 * Breaks a stale lock. Breakers take a short-lived `<log>.lock.break` mutex first and judge the
 * lock stale again inside it: without it, a breaker that judged the old lock stale could rename
 * away a fresh lock another writer had just created, and that writer would then see its lock
 * "taken over" and drop its record. Returns true when the caller should retry at once.
 */
function breakStaleLock(lockPath, token) {
  const mutex = `${lockPath}.break`;
  let fd;
  try {
    fd = fs.openSync(mutex, 'wx', LEDGER_FILE_MODE);
    try { fs.writeSync(fd, token); } catch { /* best effort: without it the mutex is never released by us */ }
  } catch {
    // Another breaker is working. A mutex left by a dead process is removed after a while.
    reclaimStaleMutex(mutex, token);
    return false;
  }
  try {
    try { fs.closeSync(fd); } catch { /* best effort */ }
    if (testHooks.afterMutexCreate) testHooks.afterMutexCreate(mutex);
    // Inside the mutex only breakers touch a stale lock, and a fresh one cannot appear while
    // the stale file still exists, so what is judged stale here is still the stale file.
    let stale = false;
    try { stale = Math.abs(Date.now() - fs.statSync(lockPath).mtimeMs) > LOCK_STALE_MS; } catch { /* gone */ }
    if (!stale) return true;
    // Break it by renaming it away, then delete the renamed file. Never delete by the shared path.
    const aside = `${lockPath}.stale-${token.replace(':', '-')}`;
    let moved = false;
    try { fs.renameSync(lockPath, aside); moved = true; } catch { /* already gone, or busy on Windows: retry */ }
    if (moved) {
      // Defense in depth: if what we moved is not stale after all, put it back with link()
      // (atomic, fails if a lock exists again) before deleting our copy.
      let fresh = false;
      try { fresh = Math.abs(Date.now() - fs.statSync(aside).mtimeMs) <= LOCK_STALE_MS; } catch { /* gone */ }
      if (fresh) {
        try { fs.linkSync(aside, lockPath); } catch { /* a new lock exists: its owner checks its token */ }
      }
      try { fs.unlinkSync(aside); } catch { /* best effort */ }
      sweepStaleLeftovers(lockPath);
    }
    return moved;
  } finally {
    if (testHooks.beforeMutexRelease) testHooks.beforeMutexRelease(mutex);
    releaseMutex(mutex, token);
  }
}

/**
 * Takes the lock and returns this writer's token (pid + random bytes), which is written into
 * the lock file. The token lets a writer tell its own lock from one taken over after it was
 * considered stale: it only releases, and only appends, while the file still holds its token.
 */
function acquireLock(lockPath, waitMs = LOCK_WAIT_MS) {
  // NaN, Infinity or a negative wait would never time out (or time out at once): use the default.
  if (!(Number.isFinite(waitMs) && waitMs >= 0)) waitMs = LOCK_WAIT_MS;
  const deadline = Date.now() + waitMs;
  const token = `${process.pid}:${crypto.randomBytes(8).toString('hex')}`;
  let delay = 2;
  let missing = 0;
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', LEDGER_FILE_MODE);
      try { fs.writeSync(fd, token); } finally { fs.closeSync(fd); }
      return token;
    } catch (e) {
      // On Windows a lock that is being deleted answers EPERM/EACCES instead of EEXIST. If the
      // lock is not there, the real problem is permissions: report it at once, do not wait.
      const winBusy = process.platform === 'win32' && (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'EBUSY');
      if (!(e.code === 'EEXIST' || winBusy)) throw e;
      if (winBusy && !fs.existsSync(lockPath)) {
        // The lock may have been deleted a moment after the error; only a repeat means a real
        // permission problem.
        if (++missing >= 5) throw e;
        sleepMs(5);
        continue;
      }
      missing = 0;
    }
    if (Date.now() >= deadline) throw new EvidenceLockError('another process is writing to the log');
    let stale = false;
    try {
      // abs(): a lock dated in the future (clock moved back) is stale too.
      stale = Math.abs(Date.now() - fs.statSync(lockPath).mtimeMs) > LOCK_STALE_MS;
    } catch { /* gone or unreadable: wait a moment and try again */ }
    if (stale && breakStaleLock(lockPath, token)) continue;
    sleepMs(delay + Math.floor(Math.random() * delay));
    delay = Math.min(delay * 2, 50);
  }
}

// Leftovers `<log>.lock.stale-*` only exist when a process died between renaming a stale lock
// and deleting it. Remove a few old ones after a stale lock was broken; errors are ignored.
function sweepStaleLeftovers(lockPath) {
  try {
    const prefix = path.basename(lockPath) + '.stale-';
    const dir = path.dirname(lockPath);
    let n = 0;
    for (const name of fs.readdirSync(dir)) {
      if (!name.startsWith(prefix)) continue;
      if (++n > 5) break;
      try {
        const p = path.join(dir, name);
        if (Math.abs(Date.now() - fs.statSync(p).mtimeMs) > LOCK_STALE_MS) fs.unlinkSync(p);
      } catch { /* ignore */ }
    }
  } catch { /* ignore */ }
}

function ownsLock(lockPath, token) {
  return readLockToken(lockPath) === token;
}

// On Windows, deleting a file can fail for a moment while another process (a virus scanner, an
// indexer) has it open. A lock that stays behind blocks every other writer until it goes stale,
// so try again briefly before giving up. A missing file is fine.
function unlinkLock(lockPath) {
  for (let i = 0; i < 40; i++) {
    try { fs.unlinkSync(lockPath); return; } catch (e) {
      if (e.code === 'ENOENT') return;
      if (!(process.platform === 'win32' && (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'EBUSY')) || i === 39) return;
    }
    sleepMs(5);
  }
}

function releaseLock(lockPath, token) {
  // Only remove the lock if it is still ours; after a takeover it belongs to someone else.
  // If the file is missing it may be renamed aside by a breaker that is about to put it back
  // (link-back): look again a few times, and delete it if it reappears with our token.
  for (let i = 0; i < 4; i++) {
    const current = readLockToken(lockPath);
    if (current === token) {
      unlinkLock(lockPath);
      return;
    }
    if (current !== null) return;
    if (i < 3) sleepMs(5);
  }
}

// Canonical serialization of a record for hashing. Node writes UTF-8 as is; Python used to
// escape non-ASCII as \uXXXX. Verification accepts both forms, so a log written by either
// package (or by an older version) verifies in both. New records use the plain form.
function canonical(record) {
  return JSON.stringify(record);
}
function canonicalAscii(record) {
  return JSON.stringify(record).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

const HASH_RE = /^[0-9a-f]{64}$/;

// A damaged log makes logEvidence skip its writes. The warning is shown on the first skipped
// write and again at most every WARN_INTERVAL_MS, so the long-running MCP proxy (shield) does
// not go quiet after one line. Time based, not count based, so a quiet session still hears it.
const WARN_INTERVAL_MS = 5 * 60 * 1000;
let lastWarnAt = null;
let lastWriteWarnAt = null;

/** Tells the user how to get logging going again after damage. */
function recoveryHint(filePath = EVIDENCE_FILE) {
  const damaged = path.join(path.dirname(filePath), 'evidence.damaged.jsonl');
  const cmd = process.platform === 'win32' ? `move "${filePath}" "${damaged}"` : `mv "${filePath}" "${damaged}"`;
  return `To start a new log and keep the old file for review, move it aside (${cmd}); the next event starts a new chain.`;
}

// Only space, tab and CR are trimmed around a line (the Python package does the same).
const isWs = (b) => b === 0x20 || b === 0x09 || b === 0x0d;
function trimBytes(buf) {
  let a = 0;
  let b = buf.length;
  while (a < b && isWs(buf[a])) a++;
  while (b > a && isWs(buf[b - 1])) b--;
  return buf.subarray(a, b);
}

// ignoreBOM keeps a BOM in the text (so JSON.parse rejects it, as Python does) instead of dropping it.
const STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const LENIENT = new TextDecoder('utf-8', { ignoreBOM: true });

/**
 * Reads the ledger as raw bytes and decodes it line by line. Returns the non-empty
 * lines (undecodable bytes replaced) and `bad`, a Map from a 0-based line index to the
 * reason that line is not valid UTF-8. Throws EvidenceLedgerError if the file cannot be read.
 */
function readLedger(filePath) {
  let raw;
  try {
    raw = fs.readFileSync(filePath);
  } catch (e) {
    throw new EvidenceLedgerError(`Cannot read the evidence log: ${e.code || e.message}`);
  }
  const lines = [];
  const bad = new Map();
  let start = 0;
  while (start <= raw.length) {
    let end = raw.indexOf(0x0a, start);
    if (end === -1) end = raw.length;
    const chunk = trimBytes(raw.subarray(start, end));
    start = end + 1;
    if (chunk.length === 0) continue;
    try {
      lines.push(STRICT.decode(chunk));
    } catch {
      bad.set(lines.length, `Invalid UTF-8 bytes at line ${lines.length + 1}: the log was corrupted or modified.`);
      lines.push(LENIENT.decode(chunk));
    }
  }
  return { lines, bad };
}

/**
 * Returns the last non-empty line as a Buffer (null for an empty or whitespace-only file),
 * reading only the end of the file.
 */
function readLastLine(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const size = fs.fstatSync(fd).size;
    let window = 65536;
    for (;;) {
      const start = Math.max(0, size - window);
      const buf = Buffer.alloc(size - start);
      let got = 0;
      while (got < buf.length) {
        const n = fs.readSync(fd, buf, got, buf.length - got, start + got);
        if (n === 0) break;
        got += n;
      }
      let end = got;
      while (end > 0 && (isWs(buf[end - 1]) || buf[end - 1] === 0x0a)) end--;
      if (end > 0) {
        const nl = buf.lastIndexOf(0x0a, end - 1);
        if (nl >= 0 || start === 0) return trimBytes(buf.subarray(nl + 1, end));
      } else if (start === 0) {
        return null;
      }
      window *= 2;
    }
  } catch (e) {
    throw new EvidenceLedgerError(`Cannot read the evidence log: ${e.code || e.message}`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/**
 * Reads the last record's hash from the ledger (only the end of the file is read). A missing
 * or empty file is the start of a new chain (genesis). If the last line cannot be read or
 * trusted this throws EvidenceLedgerError: it never falls back to genesis, which would
 * silently restart the chain. Damage earlier in the file is for verifyEvidenceLedger to find.
 */
function getLastHash(filePath = EVIDENCE_FILE) {
  if (!fs.existsSync(filePath)) {
    return GENESIS_HASH;
  }
  const last = readLastLine(filePath);
  if (last === null) return GENESIS_HASH;
  let text;
  try {
    text = STRICT.decode(last);
  } catch {
    throw new EvidenceLedgerError('Invalid UTF-8 bytes in the last line: the log was corrupted or modified.');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new EvidenceLedgerError(`Malformed JSON in the last line: ${e.message}`);
  }
  const hash = parsed && typeof parsed === 'object' ? parsed.record_hash : undefined;
  if (typeof hash !== 'string' || !HASH_RE.test(hash)) {
    throw new EvidenceLedgerError('The last record has no valid record_hash.');
  }
  return hash;
}

/**
 * Records a security event with cryptographic hash-chaining.
 *
 * @param {object} event - Event details (agent, phase, tool_name, payload, verdict, rule, reason, latency_us, engine)
 * @param {string} [filePath] - Optional ledger path
 * @param {{lockWaitMs?: number}} [opts] - How long to wait for the write lock (default 2000)
 * @returns {object|null} The recorded evidence record, or null when the existing ledger is
 *   damaged: nothing is appended (the chain is never restarted), a warning is printed to
 *   stderr (first time, then at most every 5 minutes), and the caller carries on. It also
 *   returns null (with a warning) when the log cannot be written (permissions, disk) or the
 *   write lock stays busy for 2 seconds; it never throws for a log problem.
 */
function logEvidence(event, filePath = EVIDENCE_FILE, opts = {}) {
  if (filePath === EVIDENCE_FILE && !opts.noStats) {
    require('./stats').record({
      layer: 'shield', agent: event.agent || event.agent_environment || 'other', checked: 1,
      blocked: String(event.verdict || '').toLowerCase() === 'block' ? 1 : 0,
    });
  }

  const lockPath = filePath + '.lock';
  let token = null;
  try {
    ensureZnDir(filePath);
    token = acquireLock(lockPath, opts.lockWaitMs);
    let prevHash;
    try {
      prevHash = getLastHash(filePath);
    } catch (e) {
      if (!(e instanceof EvidenceLedgerError)) throw e;
      const now = Date.now();
      if (lastWarnAt === null || now - lastWarnAt >= WARN_INTERVAL_MS) {
        lastWarnAt = now;
        process.stderr.write(`zn-gate: the evidence log ${filePath} is damaged (${e.message}) Events are not being recorded. Run 'zn-gate evidence --verify' for details. ${recoveryHint(filePath)}\n`);
      }
      return null;
    }
    const finalRecord = buildRecord(event, prevHash, opts._plainPreview === true);
    // _beforeAppend is a test-only hook (internal, not part of the public options).
    if (typeof opts._beforeAppend === 'function') opts._beforeAppend();
    // Still our lock? If it was taken over (this process was stalled for over 10 s) the last
    // hash read above may be out of date: write nothing rather than fork the chain.
    if (!ownsLock(lockPath, token)) throw new EvidenceLockError('the write lock was taken over');
    appendLedgerLine(filePath, JSON.stringify(finalRecord) + '\n');
    return finalRecord;
  } catch (e) {
    // A log problem (no permission, a full disk, a busy lock) must never break the caller.
    const now = Date.now();
    if (lastWriteWarnAt === null || now - lastWriteWarnAt >= WARN_INTERVAL_MS) {
      lastWriteWarnAt = now;
      const why = e instanceof EvidenceLockError ? e.message : (e.code || e.message);
      process.stderr.write(`zn-gate: cannot write to the evidence log ${filePath} (${why}). Events are not being recorded; the log is left as it is.\n`);
    }
    return null;
  } finally {
    if (token !== null) releaseLock(lockPath, token);
  }
}

// The preview keeps 120 characters, so only the start of the payload is redacted for it: redacting a
// 40 MB tool output in full to keep 120 characters would be a second full pass. 64 KB leaves room for a
// long secret that starts in the first 120 characters (a private key block) to be matched whole.
const PREVIEW_REDACT_CHARS = 64 * 1024;

// The redacted start of a payload, cut to 120 characters. A private key block that runs past the redacted part
// has no END line there, so it is not matched: the preview then stops before its BEGIN line.
function previewOf(payloadStr) {
  const head = String(require('./rules').redactSecrets(payloadStr.slice(0, PREVIEW_REDACT_CHARS)).sanitized || '');
  const begin = head.search(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/);
  const cut = begin === -1 ? head : head.slice(0, begin) + '[REDACTED_PRIVATE_KEY]';
  return cut.slice(0, 120);
}

function buildRecord(event, prevHash, plainPreview = false) {
  const timestamp = new Date().toISOString();
  const id = 'ev_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');

  // Note: a payload with a lone surrogate hashes as U+FFFD here and as '?' in the Python package,
  // so payload_sha256 differs between the two for such text; record_hash and verification are
  // not affected.
  const payloadStr = typeof event.payload === 'string' ? event.payload : JSON.stringify(event.payload || '');
  const payloadSha256 = crypto.createHash('sha256').update(payloadStr).digest('hex');

  const baseRecord = {
    id,
    timestamp,
    agent_environment: event.agent || event.agent_environment || 'unknown',
    phase: event.phase || 'tool-call',
    tool_name: event.tool_name || event.tool || 'unknown',
    payload_sha256: payloadSha256,
    // Redact the full payload first, then cut, so a secret straddling the cut is not leaked. With
    // _plainPreview the caller built the payload from fixed fields only (no text the agent sent), so
    // it is cut as it is and the redaction engine is not loaded.
    payload_preview: plainPreview
      ? payloadStr.slice(0, 120)
      : previewOf(payloadStr),
    verdict: event.verdict || 'allow',
    rule: event.rule || null,
    reason: event.reason || null,
    confidence: event.confidence || 1.0,
    latency_us: event.latency_us || 0,
    engine: event.engine || 'oss-deterministic',
    prev_hash: prevHash,
  };

  // Record hash over prev_hash + canonical serialized content.
  const recordHash = crypto
    .createHash('sha256')
    .update(prevHash + ':' + canonical(baseRecord))
    .digest('hex');

  return { ...baseRecord, record_hash: recordHash };
}

/**
 * Verifies the cryptographic integrity of the entire evidence chain.
 *
 * @param {string} [filePath] - Optional ledger path
 * @returns {object} { valid: boolean, total: number, verified: number, broken_index: number|null, error: string|null }
 */
function verifyEvidenceLedger(filePath = EVIDENCE_FILE) {
  if (!fs.existsSync(filePath)) {
    return { valid: true, total: 0, verified: 0, broken_index: null, error: null };
  }

  let lines;
  let bad;
  try {
    ({ lines, bad } = readLedger(filePath));
  } catch (e) {
    return { valid: false, total: 0, verified: 0, broken_index: 0, error: e.message };
  }
  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < lines.length; i++) {
    if (bad.has(i)) {
      return { valid: false, total: lines.length, verified: i, broken_index: i, error: bad.get(i) };
    }
    let rec;
    try {
      rec = JSON.parse(lines[i]);
    } catch (e) {
      return { valid: false, total: lines.length, verified: i, broken_index: i, error: `Malformed JSON at line ${i + 1}: ${e.message}` };
    }
    if (rec === null || typeof rec !== 'object' || Array.isArray(rec)) {
      return { valid: false, total: lines.length, verified: i, broken_index: i, error: `Malformed record at line ${i + 1}: not a JSON object.` };
    }

    if (rec.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        total: lines.length,
        verified: i,
        broken_index: i,
        error: `Broken chain link at line ${i + 1} (record ${rec.id}): expected prev_hash ${expectedPrevHash.slice(0, 8)}... but found ${rec.prev_hash?.slice(0, 8)}...`
      };
    }

    const { record_hash, ...baseRecord } = rec;
    const hashOf = (text) => crypto.createHash('sha256').update(expectedPrevHash + ':' + text).digest('hex');
    // Records written by Python (or older versions) may have non-ASCII escaped: accept both forms.
    if (hashOf(canonical(baseRecord)) !== record_hash && hashOf(canonicalAscii(baseRecord)) !== record_hash) {
      return {
        valid: false,
        total: lines.length,
        verified: i,
        broken_index: i,
        error: `Tamper detected at line ${i + 1} (record ${rec.id}): hash mismatch. The content of this log was altered!`
      };
    }

    expectedPrevHash = record_hash;
  }

  return { valid: true, total: lines.length, verified: lines.length, broken_index: null, error: null };
}

/**
 * Generates aggregated metrics from the ledger.
 */
function getEvidenceStats(filePathOrLimit = EVIDENCE_FILE, maybeLimit = 50) {
  let filePath = EVIDENCE_FILE;
  let limit = 50;

  if (typeof filePathOrLimit === 'number') {
    limit = filePathOrLimit;
  } else if (typeof filePathOrLimit === 'string') {
    filePath = filePathOrLimit;
    if (typeof maybeLimit === 'number') limit = maybeLimit;
  }

  if (!fs.existsSync(filePath)) {
    return { total: 0, blocks: 0, blocked: 0, allows: 0, allowed: 0, shadows: 0, valid: true, top_rules: {}, top_tools: {}, recent: [] };
  }

  let lines;
  try {
    ({ lines } = readLedger(filePath));
  } catch (e) {
    return { total: 0, blocks: 0, blocked: 0, allows: 0, allowed: 0, shadows: 0, valid: false, error: e.message, top_rules: {}, top_tools: {}, recent: [] };
  }
  let blocked = 0;
  let allowed = 0;
  let shadows = 0;
  const topRules = {};
  const topTools = {};
  const recent = [];

  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const rec = JSON.parse(lines[i]);
      if (rec === null || typeof rec !== 'object') continue;
      if (rec.verdict === 'shadow') {
        shadows++;
      } else if (rec.verdict === 'block') {
        blocked++;
        if (rec.rule) topRules[rec.rule] = (topRules[rec.rule] || 0) + 1;
      } else {
        allowed++;
      }
      if (rec.tool_name) topTools[rec.tool_name] = (topTools[rec.tool_name] || 0) + 1;
      if (recent.length < limit) {
        recent.push(rec);
      }
    } catch {}
  }

  const check = verifyEvidenceLedger(filePath);

  return {
    total: lines.length,
    blocks: blocked,
    blocked,
    allows: allowed,
    allowed,
    shadows,
    valid: check.valid,
    error: check.error,
    top_rules: topRules,
    top_tools: topTools,
    recent,
  };
}

/**
 * Exports the evidence ledger into JSONL or CSV with cryptographic verification.
 * Suitable for enterprise compliance audits (SOC 2, ISO 27001, EU AI Act Art. 12).
 *
 * @param {string} [filePath]
 * @param {('jsonl'|'csv')} [format='jsonl']
 * @returns {{ content: string, format: string, valid: boolean, tip_hash: string, total: number }}
 */
function exportEvidenceLedger(filePath = EVIDENCE_FILE, format = 'jsonl') {
  const normFormat = (format || 'jsonl').toLowerCase() === 'csv' ? 'csv' : 'jsonl';

  if (!fs.existsSync(filePath)) {
    return {
      content: normFormat === 'csv' ? 'timestamp,verdict,phase,tool_name,agent_environment,rule,reason,payload_sha256,record_hash,prev_hash,latency_us\n' : '',
      format: normFormat,
      valid: true,
      tip_hash: GENESIS_HASH,
      total: 0,
    };
  }

  const verifyResult = verifyEvidenceLedger(filePath);
  let raw = '';
  let lines = [];
  try {
    raw = LENIENT.decode(fs.readFileSync(filePath));
    lines = readLedger(filePath).lines;
  } catch {
    // Unreadable: verifyResult already carries the reason.
  }

  let tipHash = GENESIS_HASH;
  if (lines.length > 0) {
    try {
      tipHash = JSON.parse(lines[lines.length - 1]).record_hash || GENESIS_HASH;
    } catch {}
  }

  if (normFormat === 'csv') {
    const headers = [
      'timestamp',
      'verdict',
      'phase',
      'tool_name',
      'agent_environment',
      'rule',
      'reason',
      'payload_sha256',
      'record_hash',
      'prev_hash',
      'latency_us'
    ];
    const rows = [headers.join(',')];
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        const row = headers.map(h => {
          const val = obj[h] !== undefined && obj[h] !== null ? String(obj[h]) : '';
          return `"${val.replace(/"/g, '""')}"`;
        });
        rows.push(row.join(','));
      } catch {}
    }

    return {
      content: rows.join('\n') + '\n',
      format: 'csv',
      valid: verifyResult.valid,
      error: verifyResult.error,
      tip_hash: tipHash,
      total: lines.length,
    };
  }

  return {
    content: raw.endsWith('\n') ? raw : raw + '\n',
    format: 'jsonl',
    valid: verifyResult.valid,
    error: verifyResult.error,
    tip_hash: tipHash,
    total: lines.length,
  };
}

/**
 * Escapes a value for use in HTML text and double-quoted attributes.
 * Ledger fields come from tool calls and must never be interpreted as markup.
 * Serialized into the dashboard page, so it must stay self-contained.
 */
function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Renders one ledger record as a table row. Every field is escaped.
 * Serialized into the dashboard page, so it may only call escapeHtml.
 */
function renderAuditRow(r) {
  const verdict = String(r.verdict || 'allow');
  const tagClass = verdict === 'block' ? 'tag-block' : (verdict === 'shadow' ? 'tag-shadow' : 'tag-allow');
  const ruleCell = (r.rule || r.reason) ? escapeHtml(r.rule || r.reason) : '<span style="color:var(--muted);">-</span>';
  const sha = String(r.payload_sha256 || '');
  const latency = typeof r.latency_us === 'number' && r.latency_us ? r.latency_us + ' µs' : '< 1 ms';
  return '<tr>' +
    '<td class="mono">' + escapeHtml(String(r.timestamp || '').replace('T', ' ').slice(0, 19)) + '</td>' +
    '<td><span class="tag ' + tagClass + '">' + escapeHtml(verdict.toUpperCase()) + '</span></td>' +
    '<td><strong>' + escapeHtml(r.tool_name || 'call') + '</strong> <span style="color:var(--muted); font-size:0.8rem;">(' + escapeHtml(r.agent_environment || 'agent') + ')</span></td>' +
    '<td>' + ruleCell + '</td>' +
    '<td class="mono" title="' + escapeHtml(sha) + '">' + escapeHtml(sha.slice(0, 12)) + '...</td>' +
    '<td class="mono">' + escapeHtml(latency) + '</td>' +
  '</tr>';
}

/**
 * Starts a zero-dependency local dashboard at 127.0.0.1:<port> (loopback only)
 */
function startEvidenceUi(port = 3100, filePath = EVIDENCE_FILE) {
  const server = require('http').createServer((req, res) => {
    // Only answer requests addressed to the loopback name and port, so a web
    // page cannot reach the dashboard through DNS rebinding.
    const addr = server.address();
    const boundPort = addr && typeof addr === 'object' ? addr.port : port;
    const host = String(req.headers.host || '').toLowerCase();
    if (host !== `127.0.0.1:${boundPort}` && host !== `localhost:${boundPort}`) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }
    // 1. API: Aggregated stats
    if (req.url === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getEvidenceStats(filePath)));
      return;
    }

    // 2. API: Cryptographic verification
    if (req.url === '/api/verify') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(verifyEvidenceLedger(filePath)));
      return;
    }

    // 3. API: Compliance Audit Exporter (/api/export?format=jsonl|csv)
    if (req.url.startsWith('/api/export')) {
      const urlObj = new URL(req.url, `http://127.0.0.1:${port}`);
      const format = urlObj.searchParams.get('format') === 'csv' ? 'csv' : 'jsonl';
      const exportData = exportEvidenceLedger(filePath, format);

      const contentType = format === 'csv' ? 'text/csv; charset=utf-8' : 'application/x-ndjson; charset=utf-8';
      const filename = `zn-audit-ledger-${new Date().toISOString().slice(0, 10)}.${format}`;

      res.writeHead(200, {
        'Content-Type': contentType,
        'Content-Disposition': `attachment; filename="${filename}"`,
        'X-Evidence-Integrity': exportData.valid ? 'valid' : 'tampered',
        'X-Evidence-Tip-Hash': exportData.tip_hash,
        'X-Evidence-Total': String(exportData.total),
      });
      res.end(exportData.content);
      return;
    }

    // 4. Single-page dashboard HTML
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>zn Evidence Engine - Cryptographic AI Audit Ledger</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card: #151c2e;
      --border: #263554;
      --accent: #10b981;
      --danger: #ef4444;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --mono: 'JetBrains Mono', 'Fira Code', monospace;
    }
    body {
      margin: 0;
      padding: 2rem;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { margin: 0; font-size: 1.5rem; display: flex; align-items: center; gap: 0.75rem; }
    .header-actions { display: flex; align-items: center; gap: 0.75rem; }
    .btn-export {
      background: var(--card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.45rem 0.85rem;
      border-radius: 6px;
      font-size: 0.82rem;
      text-decoration: none;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      transition: all 0.2s ease;
    }
    .btn-export:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: var(--muted);
      color: #fff;
    }
    .status-badge { padding: 0.35rem 0.8rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; gap: 0.5rem; }
    .badge-valid { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-invalid { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
    .card h3 { margin: 0 0 0.5rem 0; font-size: 0.85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .metric { font-size: 2rem; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    th { background: rgba(255, 255, 255, 0.03); color: var(--muted); font-weight: 600; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .mono { font-family: var(--mono); font-size: 0.82rem; }
    .tag { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .tag-block { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
    .tag-allow { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }
    .tag-shadow { background: rgba(245, 158, 11, 0.2); color: #fcd34d; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1><span>🛡️</span> zn Evidence Engine Dashboard</h1>
      <div class="header-actions">
        <a href="/api/export?format=jsonl" download class="btn-export">⬇ Export JSONL</a>
        <a href="/api/export?format=csv" download class="btn-export">⬇ Export CSV</a>
        <div id="integrity-badge" class="status-badge badge-valid">● SHA-256 Ledger Verified</div>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <h3>Total Audit Events</h3>
        <div class="metric" id="m-total">-</div>
      </div>
      <div class="card">
        <h3>Threats Intercepted</h3>
        <div class="metric" style="color: var(--danger);" id="m-blocks">-</div>
      </div>
      <div class="card">
        <h3>Operations Allowed</h3>
        <div class="metric" style="color: var(--accent);" id="m-allows">-</div>
      </div>
      <div class="card">
        <h3>Shadow Alerts</h3>
        <div class="metric" style="color: #f59e0b;" id="m-shadows">-</div>
      </div>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
      <h2 style="margin: 0; font-size: 1.15rem;">Recent Security Records (SHA-256 Chained)</h2>
      <span style="color: var(--muted); font-size: 0.85rem;">Live polling every 3s</span>
    </div>

    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Verdict</th>
          <th>Tool & Environment</th>
          <th>Rule / Detail</th>
          <th>Payload Hash</th>
          <th>Latency</th>
        </tr>
      </thead>
      <tbody id="audit-table">
        <tr><td colspan="6" style="text-align:center; color: var(--muted); padding: 2rem;">Loading evidence ledger...</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    ${escapeHtml.toString()}
    ${renderAuditRow.toString()}
    async function fetchData() {
      try {
        const [statsRes, verifyRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/verify')
        ]);
        const d = await statsRes.json();
        const v = await verifyRes.json();

        document.getElementById('m-total').textContent = d.total || 0;
        document.getElementById('m-blocks').textContent = d.blocks || 0;
        document.getElementById('m-allows').textContent = d.allows || 0;
        document.getElementById('m-shadows').textContent = d.shadows || 0;

        const badge = document.getElementById('integrity-badge');
        if (v.valid) {
          badge.className = 'status-badge badge-valid';
          badge.textContent = '● SHA-256 Chain Verified (Tamper-Free)';
        } else {
          badge.className = 'status-badge badge-invalid';
          badge.textContent = '✖ TAMPER DETECTED at record ' + v.broken_index;
        }

        const tbody = document.getElementById('audit-table');
        if (!d.recent || d.recent.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--muted); padding: 2rem;">No evidence records logged yet. Run an MCP tool call to see live data.</td></tr>';
          return;
        }

        tbody.innerHTML = d.recent.map(renderAuditRow).join('');
      } catch (err) {
        console.error('Failed fetching data:', err);
      }
    }
    fetchData();
    setInterval(fetchData, 3000);
  </script>
</body>
</html>`);
  });

  // Loopback only: the ledger must not be reachable from the network.
  const banner = require('./term').sym(process.env, '🛡️', null, '  ');
  server.listen(port, '127.0.0.1', () => {
    process.stdout.write(`
${banner}zn Evidence Engine Dashboard running at http://127.0.0.1:${server.address().port}
Ledger location: ${filePath}
Press Ctrl+C to stop dashboard.
\n`);
  });
  return server;
}

module.exports = {
  logEvidence,
  EvidenceLedgerError,
  recoveryHint,
  getLastHash,
  verifyEvidenceLedger,
  getEvidenceStats,
  exportEvidenceLedger,
  startEvidenceUi,
  escapeHtml,
  renderAuditRow,
  EVIDENCE_FILE,
  GENESIS_HASH,
  _testHooks: testHooks,
};
