'use strict';
/**
 * Local audit log: ~/.zn/audit.jsonl, one JSON record per line, chained
 * with HMAC-SHA256 under a local key (kept inside the encrypted vault, so
 * only an unlocked daemon can append or verify).
 *
 * Record: {v, seq, ts, secret, mode, agent, tool, argv0, host, decision, reason, prev, mac}
 *   prev = mac of the previous record (64 zeros for the first one)
 *   mac  = HMAC(key, JSON of every other field, in this order)
 *
 * Metadata only. Fields are whitelisted and format-checked; anything else
 * is dropped. Values never enter the log, and neither do hashes of values
 * (a hash of a low-entropy value is reversible). As a last guard, any field
 * that contains a known secret value is replaced with "[redacted]".
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const GENESIS = '0'.repeat(64);
const FIELDS = ['secret', 'mode', 'agent', 'tool', 'argv0', 'host', 'decision', 'reason'];
const MODES = new Set(['proxy', 'env', 'file', 'named', 'detected', 'resolve', 'set', 'remove', 'unlock', 'lock', 'expire']);
const DECISIONS = new Set(['allow', 'deny', 'ask', 'ask:yes', 'ask:no', 'restore', 'withhold', 'error']);
const FORMATS = {
  secret: /^[A-Z0-9_]{1,80}$/,
  agent: /^[A-Za-z0-9_.:/-]{1,64}$/,
  tool: /^[A-Za-z0-9_.:/-]{1,64}$/,
  argv0: /^[A-Za-z0-9_.+-]{1,64}$/,
  host: /^[a-z0-9.-]{1,253}(?::\d{1,5})?$/,
  reason: /^[A-Za-z0-9_:.-]{1,64}$/,
};

function cleanField(name, value, knownValues) {
  if (value === undefined || value === null || value === '') return undefined;
  let v = String(value);
  if (knownValues) {
    for (const secret of knownValues) {
      if (secret && secret.length >= 8 && v.includes(secret)) return '[redacted]';
    }
  }
  if (name === 'mode') return MODES.has(v) ? v : 'other';
  if (name === 'decision') return DECISIONS.has(v) ? v : 'other';
  if (name === 'argv0') v = v.split(/[\\/]/).pop().split(/\s/)[0];
  if (name === 'host') v = v.toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@/]*@/, '').split('/')[0];
  return FORMATS[name].test(v) ? v : '[invalid]';
}

/** Whitelist and format-check an event. */
function sanitize(event, knownValues) {
  const out = {};
  for (const f of FIELDS) {
    const v = cleanField(f, event && event[f], knownValues);
    if (v !== undefined) out[f] = v;
  }
  return out;
}

function macOf(key, record) {
  return crypto.createHmac('sha256', key).update(JSON.stringify(record)).digest('hex');
}

/* Last record of the log (reads only the tail of the file). */
function lastRecord(file) {
  let fd;
  try { fd = fs.openSync(file, 'r'); } catch (err) { if (err.code === 'ENOENT') return null; throw err; }
  try {
    const size = fs.fstatSync(fd).size;
    if (size === 0) return null;
    let chunk = 4096;
    for (;;) {
      const len = Math.min(size, chunk);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, size - len);
      const text = buf.toString('utf8').replace(/\n+$/, '');
      const nl = text.lastIndexOf('\n');
      if (nl >= 0 || len === size) return JSON.parse(text.slice(nl + 1));
      chunk *= 4;
    }
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * append(event, {file, key, knownValues}) -> record
 * key: Buffer or hex string (32 bytes). Single writer (the daemon).
 */
function append(event, opts) {
  const o = opts || {};
  const key = Buffer.isBuffer(o.key) ? o.key : Buffer.from(String(o.key || ''), 'hex');
  if (key.length < 32) throw new Error('audit key missing');
  const file = o.file;
  const last = lastRecord(file);
  const record = Object.assign(
    { v: 1, seq: last ? last.seq + 1 : 1, ts: new Date().toISOString() },
    sanitize(event, o.knownValues),
    { prev: last ? last.mac : GENESIS },
  );
  record.mac = macOf(key, record);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.appendFileSync(file, JSON.stringify(record) + '\n', { mode: 0o600 });
  if (process.platform !== 'win32') { try { fs.chmodSync(file, 0o600); } catch (err) { /* ignore */ } }
  return record;
}

/**
 * verify({file, key}) -> {ok, records, error?, line?}
 * Checks every MAC, the prev links and the sequence numbers.
 */
function verify(opts) {
  const o = opts || {};
  const key = Buffer.isBuffer(o.key) ? o.key : Buffer.from(String(o.key || ''), 'hex');
  let text;
  try { text = fs.readFileSync(o.file, 'utf8'); } catch (err) {
    if (err.code === 'ENOENT') return { ok: true, records: 0 };
    throw err;
  }
  const lines = text.split('\n').filter((l) => l.length > 0);
  let prev = GENESIS;
  let seq = 0;
  for (let i = 0; i < lines.length; i++) {
    let rec;
    try { rec = JSON.parse(lines[i]); } catch (err) { return { ok: false, records: i, line: i + 1, error: 'unparseable record' }; }
    const mac = rec.mac;
    delete rec.mac;
    const expected = macOf(key, rec);
    if (typeof mac !== 'string' || mac.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(expected, 'hex'))) {
      return { ok: false, records: i, line: i + 1, error: 'bad mac' };
    }
    if (rec.prev !== prev) return { ok: false, records: i, line: i + 1, error: 'broken chain' };
    if (rec.seq !== seq + 1) return { ok: false, records: i, line: i + 1, error: 'bad sequence' };
    prev = mac;
    seq = rec.seq;
  }
  return { ok: true, records: lines.length };
}

function parseSince(since) {
  if (since === undefined || since === null || since === '') return null;
  if (since instanceof Date) return since.getTime();
  if (typeof since === 'number') return since;
  const m = /^(\d+)\s*(s|m|h|d)$/.exec(String(since));
  if (m) return Date.now() - Number(m[1]) * { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]];
  const t = Date.parse(String(since));
  if (Number.isNaN(t)) throw new Error('invalid since: ' + since);
  return t;
}

/**
 * read({file, since, limit}) -> events[] (oldest first)
 * since: Date, epoch ms, ISO string or a duration such as "1d" / "12h".
 * limit: keep only the newest N. Reading needs no key; it does not verify
 * the chain (use verify for that).
 */
function read(opts) {
  const o = opts || {};
  const file = o.file || require('./store').paths(o).auditFile;
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  const from = parseSince(o.since);
  const out = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    let rec;
    try { rec = JSON.parse(line); } catch (err) { continue; }
    if (from !== null && Date.parse(rec.ts) < from) continue;
    const ev = { seq: rec.seq, ts: rec.ts };
    for (const f of FIELDS) if (rec[f] !== undefined) ev[f] = rec[f];
    out.push(ev);
  }
  const limit = Number(o.limit) > 0 ? Number(o.limit) : 0;
  return limit ? out.slice(-limit) : out;
}

module.exports = { append, verify, read, sanitize, FIELDS, GENESIS };
