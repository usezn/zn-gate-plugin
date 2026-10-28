'use strict';

// Transport layer of the shield proxy: line framing with a byte cap, a cheap shape check that runs before
// JSON.parse, and the id of a message that cannot be read in full. Nothing here inspects content.

const DEFAULT_LIMITS = {
  // Longest line accepted from the wrapped server (a tool result is checked in full up to 32 MiB, so this is above it).
  serverLineBytes: 64 * 1024 * 1024,
  // Longest line accepted from the client.
  clientLineBytes: 32 * 1024 * 1024,
  // Nesting depth of brackets and braces.
  depth: 128,
  // Values (array items and object members) in one line.
  elements: 4 * 1024 * 1024,
  // Messages in one JSON-RPC batch.
  batch: 1000,
  // Requests sent to the server whose answers are still awaited.
  pending: 5000,
  // Bytes of server output waiting to be checked before reading from the server is paused.
  queueHighWater: 8 * 1024 * 1024,
};

/**
 * The limits, with the ones named in ZN_SHIELD_LIMITS (a JSON object, for tests and unusual setups) replaced.
 * A value that is not a positive integer is ignored, and a value above the default is cut to the default.
 */
function resolveLimits(env = process.env) {
  const limits = { ...DEFAULT_LIMITS };
  const raw = env.ZN_SHIELD_LIMITS;
  if (!raw) return limits;
  try {
    const o = JSON.parse(raw);
    for (const k of Object.keys(DEFAULT_LIMITS)) {
      // Only lower: a value above the default is cut to it, so a setting cannot switch the limits off.
      if (o && Number.isInteger(o[k]) && o[k] > 0) limits[k] = Math.min(o[k], DEFAULT_LIMITS[k]);
    }
  } catch { /* not JSON: defaults */ }
  return limits;
}

/**
 * Splits a stream into lines (LF) as Buffers. A line longer than maxBytes is never held in memory: its bytes are
 * counted and dropped up to the next newline, and onOversize gets its length and its first bytes (to find the id).
 * The stream can be paused and resumed by the caller.
 */
function createLineReader(stream, { maxBytes, onLine, onOversize, onEnd, headBytes = 4096 }) {
  let parts = [];
  let size = 0;
  let head = Buffer.alloc(0);
  let skipping = false;
  let skipped = 0;
  const addHead = (piece) => {
    if (head.length < headBytes && piece.length) head = Buffer.concat([head, piece.subarray(0, headBytes - head.length)]);
  };
  const reset = () => { parts = []; size = 0; head = Buffer.alloc(0); skipping = false; skipped = 0; };
  const finishLine = () => {
    if (skipping) {
      const info = { bytes: skipped, head };
      reset();
      onOversize(info);
    } else {
      const line = parts.length === 1 ? parts[0] : Buffer.concat(parts, size);
      reset();
      onLine(line);
    }
  };
  stream.on('data', (chunk) => {
    let start = 0;
    while (start < chunk.length) {
      const nl = chunk.indexOf(10, start);
      const end = nl === -1 ? chunk.length : nl;
      const piece = chunk.subarray(start, end);
      addHead(piece);
      if (skipping) {
        skipped += piece.length;
      } else if (size + piece.length > maxBytes) {
        skipping = true;
        skipped = size + piece.length;
        parts = [];
        size = 0;
      } else if (piece.length) {
        // Copy, so a long line does not keep every chunk it was cut from alive twice over.
        parts.push(Buffer.from(piece));
        size += piece.length;
      }
      if (nl === -1) break;
      finishLine();
      start = nl + 1;
    }
  });
  stream.on('end', () => {
    if (skipping || size > 0) finishLine();
    if (onEnd) onEnd();
  });
}

const isWs = (c) => c === 32 || c === 9 || c === 13 || c === 10;

/**
 * Looks at the brackets of a JSON line without parsing it: nesting depth, number of values and, for a batch, the
 * number of messages. Returns null when the line is inside the limits, or the name of the limit it exceeds.
 * Strings are skipped, so brackets and commas inside them do not count.
 */
function shapeProblem(buf, limits) {
  let depth = 0;
  let elements = 0;
  let inString = false;
  let batch = 0;
  let isBatch = false;
  let first = true;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (inString) {
      if (c === 92) i++;
      else if (c === 34) inString = false;
      continue;
    }
    if (first && !isWs(c)) { first = false; isBatch = c === 91; }
    if (c === 34) inString = true;
    else if (c === 123 || c === 91) {
      if (++depth > limits.depth) return 'depth';
      if (++elements > limits.elements) return 'elements';
    } else if (c === 125 || c === 93) depth--;
    else if (c === 44) {
      if (++elements > limits.elements) return 'elements';
      // A batch of N messages has N - 1 commas at depth 1: it is refused from limits.batch messages on.
      if (isBatch && depth === 1 && ++batch >= limits.batch - 1) return 'batch';
    }
  }
  return null;
}

/**
 * The id of a message, read from its first bytes without parsing it, and whether it has a "method" (so it is a
 * request or notification, not an answer). Only keys of the top-level object count. { hasId, id, hasMethod }.
 */
function topLevelFields(buf) {
  const out = { hasId: false, id: undefined, hasMethod: false };
  let depth = 0;
  const n = buf.length;
  let i = 0;
  while (i < n) {
    const c = buf[i];
    if (c === 34) {
      let j = i + 1;
      while (j < n && buf[j] !== 34) { if (buf[j] === 92) j++; j++; }
      if (j >= n) break;
      if (depth === 1) {
        let k = j + 1;
        while (k < n && isWs(buf[k])) k++;
        if (buf[k] === 58) {
          const key = buf.toString('utf8', i + 1, j);
          k++;
          while (k < n && isWs(buf[k])) k++;
          if (key === 'method') out.hasMethod = true;
          else if (key === 'id' && !out.hasId) {
            let e = k;
            if (buf[e] === 34) {
              e++;
              while (e < n && buf[e] !== 34) { if (buf[e] === 92) e++; e++; }
              e++;
            } else {
              while (e < n && ((buf[e] >= 48 && buf[e] <= 57) || buf[e] === 45 || buf[e] === 43 || buf[e] === 46 || buf[e] === 101 || buf[e] === 69)) e++;
            }
            try {
              const v = JSON.parse(buf.toString('utf8', k, e));
              if (typeof v === 'string' || typeof v === 'number') { out.hasId = true; out.id = v; }
            } catch { /* truncated or not an id */ }
          }
        }
      }
      i = j + 1;
      continue;
    }
    if (c === 123 || c === 91) depth++;
    else if (c === 125 || c === 93) depth--;
    i++;
  }
  return out;
}

/**
 * For a line that is a batch ("[" first), the fields of each message object that starts in buf (a truncated head is
 * fine), as topLevelFields gives them. Returns null when the line is not a batch.
 */
function batchFields(buf) {
  let i = 0;
  while (i < buf.length && isWs(buf[i])) i++;
  if (buf[i] !== 91) return null;
  const out = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  for (; i < buf.length; i++) {
    const c = buf[i];
    if (inString) {
      if (c === 92) i++;
      else if (c === 34) inString = false;
      continue;
    }
    if (c === 34) inString = true;
    else if (c === 123 || c === 91) {
      depth++;
      if (c === 123 && depth === 2) start = i;
    } else if (c === 125 || c === 93) {
      if (c === 125 && depth === 2 && start >= 0) { out.push(topLevelFields(buf.subarray(start, i + 1))); start = -1; }
      depth--;
    }
  }
  if (start >= 0) out.push(topLevelFields(buf.subarray(start)));
  return out;
}

module.exports = { DEFAULT_LIMITS, resolveLimits, createLineReader, shapeProblem, topLevelFields, batchFields };
