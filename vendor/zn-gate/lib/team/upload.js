'use strict';
/**
 * Team upload: sends the local audit log to the zn server in batches.
 *
 * The server keeps one chain head per installation. This module keeps its
 * own copy of that head in a state file, uploads only the records after it,
 * and resynchronises when the server expects a different position.
 *
 * Only the metadata fields of an audit record are sent, plus v, seq, ts,
 * prev and mac. Anything else in a line is dropped.
 *
 * Expected failures (offline, revoked, rejected, busy, ...) are returned as a
 * status, never thrown. Bad arguments throw a TypeError.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { FIELDS } = require('../vault/audit');

const LOCK_TTL_MS = 10 * 60 * 1000;
const MAX_RESYNCS = 3;
const MAX_BATCH = 500;

const TEXT_DIVERGED = 'local audit log does not match what was uploaded';
const TEXT_LOCAL_GAP = 'local audit log has a gap in its sequence numbers';

/* ------------------------------------------------------------------ */
/* State file                                                          */
/* ------------------------------------------------------------------ */

function isHead(h) {
  return !!h && typeof h === 'object' && Number.isInteger(h.seq) && h.seq >= 1 &&
    typeof h.mac === 'string' && h.mac.length > 0;
}

/* A missing or corrupt state file means no head: the next upload starts from the first record. */
function readState(stateFile) {
  const empty = { head: null, last_upload: null, last_status: 'never' };
  let raw;
  try { raw = fs.readFileSync(stateFile, 'utf8'); } catch (err) { return empty; }
  let obj;
  try { obj = JSON.parse(raw); } catch (err) { return empty; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return empty;
  return {
    head: isHead(obj.head) ? { seq: obj.head.seq, mac: obj.head.mac } : null,
    last_upload: typeof obj.last_upload === 'string' ? obj.last_upload : null,
    last_status: typeof obj.last_status === 'string' ? obj.last_status : 'never',
    last_error: typeof obj.last_error === 'string' ? obj.last_error : undefined,
  };
}

/* Written to a temp file and renamed, so a crash never leaves a half-written state file. */
function writeState(stateFile, s) {
  fs.mkdirSync(path.dirname(stateFile), { recursive: true, mode: 0o700 });
  const data = {
    head: s.head,
    last_upload: s.last_upload,
    last_status: s.last_status,
  };
  if (s.last_error) data.last_error = s.last_error;
  const tmp = `${stateFile}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, stateFile);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch (e) { /* already gone */ }
    throw err;
  }
}

/* ------------------------------------------------------------------ */
/* Local audit log                                                     */
/* ------------------------------------------------------------------ */

function isRecord(r) {
  return !!r && typeof r === 'object' && !Array.isArray(r) &&
    Number.isInteger(r.seq) && r.seq >= 1 &&
    typeof r.prev === 'string' && typeof r.mac === 'string';
}

/*
 * Returns the parsed records in file order. Unparseable lines are skipped.
 * gapAt is the index of the first record whose seq is not previous + 1
 * (-1 when there is none); records from that index on are never sent.
 * Records up to `after` (a sequence number) are left out: they came before
 * the machine joined and were not consented to be shared.
 */
function readRecords(auditFile, after) {
  let text;
  try {
    text = fs.readFileSync(auditFile, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return { records: [], gapAt: -1 };
    throw err;
  }
  const records = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let rec;
    try { rec = JSON.parse(line); } catch (err) { continue; }
    if (isRecord(rec) && rec.seq > (after || 0)) records.push(rec);
  }
  let gapAt = -1;
  for (let i = 1; i < records.length; i++) {
    if (records[i].seq !== records[i - 1].seq + 1) { gapAt = i; break; }
  }
  return { records, gapAt };
}

/* Only the fields the server accepts, in the order the chain is computed in. */
function toEvent(rec) {
  const ev = { v: rec.v, seq: rec.seq, ts: rec.ts };
  for (const f of FIELDS) {
    if (rec[f] !== undefined) ev[f] = rec[f];
  }
  ev.prev = rec.prev;
  ev.mac = rec.mac;
  return ev;
}

function countPending(records, head) {
  return records.filter((r) => !head || r.seq > head.seq).length;
}

/* ------------------------------------------------------------------ */
/* Lock                                                                */
/* ------------------------------------------------------------------ */

/* Returns an open file descriptor, or null when another upload holds a fresh lock. */
function acquireLock(lockFile, nowMs) {
  fs.mkdirSync(path.dirname(lockFile), { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 3; attempt++) {
    let fd;
    try {
      fd = fs.openSync(lockFile, 'wx', 0o600);
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      let age;
      try {
        age = nowMs - fs.statSync(lockFile).mtimeMs;
      } catch (e) {
        if (e.code === 'ENOENT') continue;
        throw e;
      }
      if (age < LOCK_TTL_MS) return null;
      try { fs.unlinkSync(lockFile); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      continue;
    }
    fs.writeSync(fd, `${process.pid} ${new Date(nowMs).toISOString()}\n`);
    return fd;
  }
  return null;
}

function releaseLock(lockFile, fd) {
  // The lock may have been deleted meanwhile (`zn team leave`) and another one created by a new membership:
  // delete the file only if it is still the one this upload created.
  let ours = false;
  try {
    const mine = fs.fstatSync(fd, { bigint: true });
    const there = fs.statSync(lockFile, { bigint: true });
    ours = mine.ino === there.ino && mine.dev === there.dev;
  } catch (err) { ours = false; }
  try { fs.closeSync(fd); } catch (err) { /* already closed */ }
  if (ours) { try { fs.unlinkSync(lockFile); } catch (err) { /* already removed */ } }
}

/* ------------------------------------------------------------------ */
/* Upload                                                              */
/* ------------------------------------------------------------------ */

function checkOptions(opts) {
  if (!opts || typeof opts !== 'object') throw new TypeError('uploadPending: options object required');
  for (const k of ['auditFile', 'stateFile', 'lockFile', 'installId']) {
    if (typeof opts[k] !== 'string' || !opts[k]) throw new TypeError(`uploadPending: ${k} must be a non-empty string`);
  }
  if (!opts.api || typeof opts.api.ingest !== 'function') throw new TypeError('uploadPending: api.ingest must be a function');
  const batchSize = opts.batchSize === undefined ? 500 : opts.batchSize;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_BATCH) {
    throw new TypeError(`uploadPending: batchSize must be an integer from 1 to ${MAX_BATCH}`);
  }
  const maxBatches = opts.maxBatches === undefined ? 20 : opts.maxBatches;
  if (!Number.isInteger(maxBatches) || maxBatches < 1) throw new TypeError('uploadPending: maxBatches must be a positive integer');
  const now = opts.now === undefined ? Date.now : opts.now;
  if (typeof now !== 'function') throw new TypeError('uploadPending: now must be a function');
  const startAfterSeq = opts.startAfterSeq === undefined ? 0 : opts.startAfterSeq;
  if (!Number.isInteger(startAfterSeq) || startAfterSeq < 0) throw new TypeError('uploadPending: startAfterSeq must be a non-negative integer');
  return {
    startAfterSeq,
    auditFile: opts.auditFile,
    stateFile: opts.stateFile,
    lockFile: opts.lockFile,
    api: opts.api,
    installId: opts.installId,
    version: opts.version || undefined,
    batchSize,
    maxBatches,
    now,
    // Called before each batch; true stops the upload (the vault was locked).
    shouldStop: typeof opts.shouldStop === 'function' ? opts.shouldStop : () => false,
    // Async; false after a response means the membership changed during the request: nothing is written.
    isCurrent: typeof opts.isCurrent === 'function' ? opts.isCurrent : null,
    // Async; runs a write (the lock, the state file) in the caller's serialised section, only while the
    // membership that started the upload is current. Resolves {stale: true} (nothing run) or {value}.
    guard: typeof opts.guard === 'function' ? opts.guard : null,
  };
}

/* A write of this upload: through the caller's guard when there is one. */
function guarded(o, fn) {
  return o.guard ? o.guard(fn) : Promise.resolve({ value: fn() });
}

function isExpected(body) {
  return !!body && !!body.expected && Number.isInteger(body.expected.seq) &&
    body.expected.seq >= 1 && typeof body.expected.prev === 'string';
}

/* Maps a failed API call to a status. Status 0 means no answer from the network. */
function apiFailure(status) {
  if (status === 422) return { status: 'rejected', text: 'server rejected the batch (chain check failed)' };
  if (status === 401) return { status: 'revoked', text: 'installation was revoked (HTTP 401)' };
  if (status === 402) return { status: 'inactive', text: 'organization has no active subscription (HTTP 402)' };
  if (status === 0) return { status: 'offline', text: 'server unreachable' };
  if (status >= 500 && status <= 599) return { status: 'offline', text: `server unavailable (HTTP ${status})` };
  if (status === null) return { status: 'error', text: 'unexpected error while uploading' };
  return { status: 'error', text: `unexpected HTTP ${status}` };
}

/*
 * What a 200 answer confirms. The server says where its chain ends (head.seq,
 * and optionally head.mac) and how many records of the batch it stored
 * (accepted; fewer than the batch when the start overlapped what it held).
 * Without a head, `accepted` counts from the start of the batch. An answer
 * that says nothing, or contradicts itself or the batch, confirms nothing.
 */
function confirmedUpTo(batch, body) {
  const bad = (text) => ({ outcome: { status: 'error', text } });
  if (!body || typeof body !== 'object') return bad('unexpected response from server');
  const accepted = body.accepted;
  if (accepted !== undefined && (!Number.isInteger(accepted) || accepted < 0 || accepted > batch.length)) {
    return bad('server answer is inconsistent (records accepted)');
  }
  let index;
  if (body.head !== undefined) {
    const h = body.head;
    if (!h || typeof h !== 'object' || !Number.isInteger(h.seq)) return bad('server answer is inconsistent (chain head)');
    index = batch.findIndex((r) => r.seq === h.seq);
    if (index < 0) return bad('server confirmed a position outside the uploaded batch');
    if (h.mac !== undefined && h.mac !== batch[index].mac) return { outcome: { status: 'diverged', text: TEXT_DIVERGED } };
    if (accepted !== undefined && accepted > index + 1) return bad('server answer is inconsistent (records accepted)');
  } else if (accepted !== undefined) {
    if (accepted < 1) return bad('server stored none of the records');
    index = accepted - 1;
  } else {
    return bad('server answer does not say what it stored');
  }
  return { record: batch[index], accepted: accepted === undefined ? index + 1 : accepted };
}

function pendingOf(o, head) {
  try {
    return countPending(readRecords(o.auditFile, head ? 0 : o.startAfterSeq).records, head);
  } catch (err) {
    return -1;
  }
}

/* Records the failure in the state file. The head kept in memory is the one that was confirmed. */
async function fail(o, ctx, status, text) {
  const pending = pendingOf(o, ctx.head);
  try {
    await guarded(o, () => writeState(o.stateFile, { head: ctx.head, last_upload: ctx.lastUpload, last_status: status, last_error: text }));
  } catch (err) { /* the state file could not be written; the result still reports the status */ }
  return { status, uploaded: ctx.uploaded, head: ctx.head, pending };
}

async function sync(o, ctx) {
  // Without a confirmed head, the upload starts after the join (o.startAfterSeq), not at the first record.
  const { records, gapAt } = readRecords(o.auditFile, ctx.head ? 0 : o.startAfterSeq);
  const bySeq = new Map();
  let lastSeq = 0;
  for (const r of records) {
    bySeq.set(r.seq, r);
    if (r.seq > lastSeq) lastSeq = r.seq;
  }
  // Records after a local gap are never sent.
  const sendable = gapAt >= 0 ? records.slice(0, gapAt) : records;

  let outcome = null; // {status, text} when the upload stops before it finishes
  if (ctx.head) {
    const local = bySeq.get(ctx.head.seq);
    if (local && local.mac !== ctx.head.mac) {
      outcome = { status: 'diverged', text: TEXT_DIVERGED };
    } else if (!local && lastSeq < ctx.head.seq) {
      // The server has records that are no longer in the local log.
      outcome = { status: 'diverged', text: TEXT_DIVERGED };
    } else if (!local) {
      // The head record is inside a gap, so the chain cannot be checked.
      outcome = { status: 'local_gap', text: TEXT_LOCAL_GAP };
    }
  }

  let batches = 0;
  let resyncs = 0;
  while (!outcome) {
    const from = ctx.head ? ctx.head.seq : 0;
    const start = sendable.findIndex((r) => r.seq > from);
    if (start < 0 || batches >= o.maxBatches || await o.shouldStop()) break;

    const batch = sendable.slice(start, start + o.batchSize);
    const body = { install_id: o.installId };
    if (o.version) body.zn_gate_version = o.version;
    body.events = batch.map(toEvent);

    let res;
    try {
      res = await o.api.ingest(body);
    } catch (err) {
      const status = err && typeof err.status === 'number' ? err.status : null;
      if (status === 409 && isExpected(err.body)) {
        resyncs += 1;
        if (resyncs > MAX_RESYNCS) {
          outcome = { status: 'error', text: 'too many resyncs with the server' };
          break;
        }
        const exp = err.body.expected;
        const target = bySeq.get(exp.seq - 1);
        if (!target || target.mac !== exp.prev) {
          outcome = { status: 'diverged', text: TEXT_DIVERGED };
          break;
        }
        ctx.head = { seq: target.seq, mac: target.mac };
        continue;
      }
      outcome = apiFailure(status);
      break;
    }

    if (o.isCurrent && !(await o.isCurrent())) {
      ctx.stale = true;
      outcome = { status: 'stale', text: 'the organization membership changed during the upload' };
      break;
    }
    if (!res || res.status !== 200) {
      outcome = { status: 'error', text: 'unexpected response from server' };
      break;
    }
    const done = confirmedUpTo(batch, res.body);
    if (done.outcome) { outcome = done.outcome; break; }
    // The head moves only to the record the server confirmed, never past it.
    ctx.head = { seq: done.record.seq, mac: done.record.mac };
    ctx.uploaded += done.accepted;
    ctx.lastUpload = new Date(o.now()).toISOString();
    batches += 1;
    const wrote = await guarded(o, () => writeState(o.stateFile, { head: ctx.head, last_upload: ctx.lastUpload, last_status: 'in_progress' }));
    if (wrote.stale) {
      ctx.stale = true;
      outcome = { status: 'stale', text: 'the organization membership changed during the upload' };
      break;
    }
  }

  let status;
  let text = null;
  if (outcome) {
    status = outcome.status;
    text = outcome.text;
  } else if (gapAt >= 0) {
    status = 'local_gap';
    text = TEXT_LOCAL_GAP;
  } else {
    status = batches > 0 ? 'ok' : 'nothing';
  }

  const pending = countPending(records, ctx.head);
  if (o.isCurrent && !(await o.isCurrent())) ctx.stale = true;
  if (!ctx.stale) {
    const wrote = await guarded(o, () => writeState(o.stateFile, { head: ctx.head, last_upload: ctx.lastUpload, last_status: status, last_error: text }));
    if (wrote.stale) ctx.stale = true;
  }
  if (ctx.stale) return { status: 'stale', uploaded: ctx.uploaded, head: ctx.head, pending };
  return { status, uploaded: ctx.uploaded, head: ctx.head, pending };
}

/**
 * uploadPending(opts) -> {status, uploaded, head, pending}
 *
 * status: ok | nothing | busy | offline | revoked | inactive | rejected |
 *         diverged | local_gap | error
 * uploaded: records the server reports as stored by this call.
 * pending: records after the head that are still not on the server (-1 when
 *          the local log cannot be read).
 */
async function uploadPending(opts) {
  const o = checkOptions(opts);
  const state = readState(o.stateFile);
  const ctx = { head: state.head, lastUpload: state.last_upload, uploaded: 0 };
  let fd = null;
  try {
    // The lock is a file in ~/.zn: it is created only while the membership that started the upload is current.
    const locked = await guarded(o, () => acquireLock(o.lockFile, o.now()));
    if (locked.stale) return { status: 'stale', uploaded: 0, head: ctx.head, pending: pendingOf(o, ctx.head) };
    fd = locked.value;
    if (fd === null) {
      return { status: 'busy', uploaded: 0, head: ctx.head, pending: pendingOf(o, ctx.head) };
    }
    return await sync(o, ctx);
  } catch (err) {
    return await fail(o, ctx, 'error', 'local audit files could not be read or written');
  } finally {
    if (fd !== null) releaseLock(o.lockFile, fd);
  }
}

/* Cheap count for `zn team status`: records after the stored head (or after opts.startAfterSeq when there is none). */
function pendingCount(opts) {
  const o = opts || {};
  const head = readState(o.stateFile).head;
  const after = Number.isInteger(o.startAfterSeq) && o.startAfterSeq > 0 ? o.startAfterSeq : 0;
  return countPending(readRecords(o.auditFile, head ? 0 : after).records, head);
}

module.exports = { uploadPending, pendingCount };
