'use strict';

// Streams the evidence log into a jsonl or csv export while it checks the hash chain, so a log of
// any size is exported in bounded memory. The log is read in chunks up to the size it had when the
// export started (records appended meanwhile wait for the next export). The chain check gives the
// same result, with the same messages, as verifyEvidenceLedger, and any read error stops the export
// with an EvidenceLedgerError: an export is never reported complete when part of the log was not read.

const fs = require('fs');

const DEFAULT_CHUNK = 256 * 1024;
// CSV rows are handed out in batches of about this many characters.
const CSV_BATCH = 256 * 1024;

const CSV_HEADERS = [
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
  'latency_us',
];
const CSV_HEADER_LINE = CSV_HEADERS.join(',');

function csvRow(obj) {
  return CSV_HEADERS.map((h) => {
    const val = obj[h] !== undefined && obj[h] !== null ? String(obj[h]) : '';
    return `"${val.replace(/"/g, '""')}"`;
  }).join(',');
}

/**
 * deps: { trimBytes, canonicalForms, genesisHash, recordStart, truncatedTailResult,
 *         EvidenceLedgerError, testHooks }
 */
function createExporter(deps) {
  const { trimBytes, canonicalForms, genesisHash, recordStart, truncatedTailResult, EvidenceLedgerError, testHooks } = deps;
  const crypto = require('crypto');

  const readError = (e) => (e instanceof EvidenceLedgerError
    ? e
    : new EvidenceLedgerError(`Cannot read the evidence log: ${(e && (e.code || e.message)) || e}`));

  // The chain check, one line at a time. A line is checked once the next non-empty line (or the
  // end of the file) is known, because a malformed last line can be a cut-off write.
  function createChecker(endsWithNewline) {
    let expectedPrevHash = genesisHash;
    let failure = null;
    let index = 0;
    function check(text, rec, parseError, badUtf8, isLast) {
      const i = index++;
      if (failure) return;
      if (badUtf8) {
        failure = { verified: i, broken_index: i, error: `Invalid UTF-8 bytes at line ${i + 1}: the log was corrupted or modified.` };
        return;
      }
      if (parseError) {
        if (isLast && text.startsWith(recordStart) && !endsWithNewline()) {
          failure = { truncated: i };
          return;
        }
        failure = { verified: i, broken_index: i, error: `Malformed JSON at line ${i + 1}: ${parseError.message}` };
        return;
      }
      if (rec === null || typeof rec !== 'object' || Array.isArray(rec)) {
        failure = { verified: i, broken_index: i, error: `Malformed record at line ${i + 1}: not a JSON object.` };
        return;
      }
      if (rec.prev_hash !== expectedPrevHash) {
        failure = {
          verified: i,
          broken_index: i,
          error: `Broken chain link at line ${i + 1} (record ${rec.id}): expected prev_hash ${expectedPrevHash.slice(0, 8)}... but found ${rec.prev_hash?.slice(0, 8)}...`,
        };
        return;
      }
      const { record_hash, ...baseRecord } = rec;
      const hashOf = (t) => crypto.createHash('sha256').update(expectedPrevHash + ':' + t).digest('hex');
      if (!canonicalForms(baseRecord).some((t) => hashOf(t) === record_hash)) {
        failure = {
          verified: i,
          broken_index: i,
          error: `Tamper detected at line ${i + 1} (record ${rec.id}): hash mismatch. The content of this log was altered!`,
        };
        return;
      }
      expectedPrevHash = record_hash;
    }
    function result(total) {
      if (!failure) return { valid: true, total, verified: total, broken_index: null, error: null };
      if (failure.truncated !== undefined) return truncatedTailResult(total, failure.truncated);
      return { valid: false, total, verified: failure.verified, broken_index: failure.broken_index, error: failure.error };
    }
    return { check, result };
  }

  /**
   * Yields the export text in pieces. format: 'jsonl', 'csv' or 'none' (check only). When the
   * generator finishes, state.result holds { format, valid, total, verified, broken_index, error,
   * tip_hash, truncated_tail?, bytes }. opts.size limits the read to that many bytes (a size found
   * by an earlier pass). Throws EvidenceLedgerError when the log cannot be read in full.
   */
  function* exportChunks(filePath, format, state, opts = {}) {
    const chunkSize = Math.max(1, (testHooks && testHooks.exportChunkSize) || DEFAULT_CHUNK);
    if (!fs.existsSync(filePath)) {
      if (format === 'csv') yield CSV_HEADER_LINE + '\n';
      state.result = { format, valid: true, total: 0, verified: 0, broken_index: null, error: null, tip_hash: genesisHash, bytes: 0 };
      return;
    }
    let fd;
    let size;
    try {
      fd = fs.openSync(filePath, 'r');
      const st = fs.fstatSync(fd);
      // Windows opens a folder for reading without an error: a folder at the log path is unreadable, as elsewhere.
      if (st.isDirectory()) { const e = new Error('is a directory'); e.code = 'EISDIR'; throw e; }
      size = typeof opts.size === 'number' ? opts.size : st.size;
      if (st.size < size) { const e = new Error('the log got shorter'); e.code = 'ESHRUNK'; throw e; }
    } catch (e) {
      if (fd !== undefined) try { fs.closeSync(fd); } catch { /* ignore */ }
      throw readError(e);
    }

    let lastByte = 0x0a;
    const checker = createChecker(() => size === 0 || lastByte === 0x0a);
    const text = new TextDecoder('utf-8', { ignoreBOM: true });
    const strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    let total = 0;
    let tipText = null;
    // The line before the current one, held back until we know whether it is the last.
    let held = null;
    let csvParts = [];
    let csvLen = 0;
    if (format === 'csv') { csvParts.push(CSV_HEADER_LINE + '\n'); csvLen = CSV_HEADER_LINE.length + 1; }

    const flushHeld = (isLast) => {
      checker.check(held.text, held.rec, held.parseError, held.bad, isLast);
      held = null;
    };
    const takeLine = (bytes) => {
      const b = trimBytes(bytes);
      if (b.length === 0) return;
      let lineText;
      let bad = false;
      try {
        lineText = strict.decode(b);
      } catch {
        bad = true;
        lineText = new TextDecoder('utf-8', { ignoreBOM: true }).decode(b);
      }
      let rec;
      let parseError = null;
      try { rec = JSON.parse(lineText); } catch (e) { parseError = e; }
      if (held) flushHeld(false);
      held = { text: lineText, rec, parseError, bad };
      total++;
      tipText = lineText;
      if (format === 'csv' && !parseError) {
        let row = null;
        try { row = csvRow(rec); } catch { /* not a record: no row, as before */ }
        if (row !== null) { csvParts.push(row + '\n'); csvLen += row.length + 1; }
      }
    };

    const buf = Buffer.alloc(Math.min(chunkSize, Math.max(size, 1)));
    let pos = 0;
    let carry = [];
    try {
      while (pos < size) {
        if (testHooks && typeof testHooks.beforeExportRead === 'function') testHooks.beforeExportRead(pos);
        let n;
        try {
          n = fs.readSync(fd, buf, 0, Math.min(buf.length, size - pos), pos);
        } catch (e) {
          throw readError(e);
        }
        if (n === 0) { const e = new Error('the log got shorter'); e.code = 'ESHRUNK'; throw readError(e); }
        const chunk = buf.subarray(0, n);
        pos += n;
        lastByte = chunk[n - 1];
        let out = '';
        if (format === 'jsonl') out = text.decode(chunk, { stream: true });
        let start = 0;
        for (;;) {
          const nl = chunk.indexOf(0x0a, start);
          if (nl === -1) break;
          if (carry.length) {
            carry.push(chunk.subarray(start, nl));
            takeLine(Buffer.concat(carry));
            carry = [];
          } else {
            takeLine(chunk.subarray(start, nl));
          }
          start = nl + 1;
        }
        if (start < n) carry.push(Buffer.from(chunk.subarray(start, n)));
        if (out) yield out;
        if (csvLen >= CSV_BATCH) { yield csvParts.join(''); csvParts = []; csvLen = 0; }
        // A check-only pass yields an empty piece per chunk, so its caller can pause between chunks.
        if (format === 'none') yield '';
      }
      if (carry.length) { takeLine(Buffer.concat(carry)); carry = []; }
    } catch (e) {
      throw readError(e);
    } finally {
      try { fs.closeSync(fd); } catch { /* ignore */ }
    }
    if (held) flushHeld(true);

    if (format === 'jsonl') {
      const rest = text.decode();
      // The export always ends with a newline (an empty log gives one newline, as before).
      const tail = size > 0 && lastByte === 0x0a ? rest : rest + '\n';
      if (tail) yield tail;
    } else if (format === 'csv' && csvParts.length) {
      yield csvParts.join('');
    }

    let tipHash = genesisHash;
    if (tipText !== null) {
      try { tipHash = JSON.parse(tipText).record_hash || genesisHash; } catch { /* not a record */ }
    }
    state.result = { format, ...checker.result(total), tip_hash: tipHash, bytes: size };
  }

  /** Collects a whole export into one string (small logs, the library API). */
  function exportToString(filePath, format) {
    const state = {};
    const parts = [];
    for (const piece of exportChunks(filePath, format, state)) parts.push(piece);
    return { content: parts.join(''), result: state.result };
  }

  /**
   * Writes the export to a Writable stream, waiting when it is full. Read errors reject with an
   * EvidenceLedgerError; write errors reject with the stream's error (err.writeError = true).
   * The stream is not ended. Resolves with state.result.
   */
  async function writeExport(filePath, format, out, opts = {}) {
    let streamError = null;
    const onError = (e) => { if (!streamError) streamError = e; };
    out.on('error', onError);
    const state = {};
    try {
      for (const piece of exportChunks(filePath, format, state, opts)) {
        if (streamError) break;
        if (!piece) continue;
        if (!out.write(piece)) {
          await new Promise((resolve) => {
            const done = () => { out.off('drain', done); out.off('close', done); out.off('error', done); resolve(); };
            out.on('drain', done);
            out.on('close', done);
            out.on('error', done);
          });
        }
        if (out.destroyed && !streamError) streamError = new Error('the output was closed');
      }
    } finally {
      out.off('error', onError);
    }
    if (streamError) { streamError.writeError = true; throw streamError; }
    return state.result;
  }

  return { exportChunks, exportToString, writeExport, CSV_HEADER_LINE };
}

module.exports = { createExporter };
