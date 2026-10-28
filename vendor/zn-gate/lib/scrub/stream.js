'use strict';
/**
 * Streaming scrubber: stdin -> tokenize per line -> stdout.
 *
 *   <command> 2>&1 | node lib/scrub/stream.js
 *
 * Used by agent hooks for tools that stream a command's output to the model
 * line by line (Claude Code's Monitor), where no PostToolUse hook sees the
 * lines. Each complete line is tokenized like any tool output (destination
 * "assistant"); with the vault locked the engine redacts irreversibly.
 *
 * A partial line (no newline yet) is never cut where a secret could be: the
 * last WINDOW characters are always held back, since a secret still being
 * written can only lie there. After FLUSH_MS of silence (or once a partial
 * line passes MAX_LINE) only the text before that window is scrubbed and
 * written, and the cut is moved back so it never splits a detected secret.
 * The rest waits for its newline or the end of the stream. WINDOW is at
 * least WINDOW_MIN and grows to the longest exact value the scrubber knows
 * (for the vault's values the daemon reports the longest, and matches them).
 *
 * Fail-closed: if text cannot be scrubbed it is replaced with a notice,
 * never passed through.
 */

const engine = require('./engine');
const deps = require('../deps');

const FLUSH_MS = 250;
const MAX_LINE = 64 * 1024;
const WINDOW_MIN = 2048;
const WITHHELD = '[zn: line withheld: scrubber error]';

/* Longest exact value (any encoding) the prepared context will look for. */
function longestExact(c) {
  let n = 0;
  for (const e of (c && c.exactValues) || []) {
    for (const v of (e && (e.values || [e.value])) || []) if (typeof v === 'string' && v.length > n) n = v.length;
  }
  return n;
}

function windowFor(c) {
  return Math.min(MAX_LINE / 2, Math.max(WINDOW_MIN, longestExact(c), (c && c.vaultLongest) || 0));
}

/* Move a cut back so that it never falls inside a detected secret. */
async function safeCut(text, cut, c) {
  let spans;
  try { spans = await engine.scanAsync(text, c); } catch (_) { return 0; }
  for (let i = spans.length - 1; i >= 0; i--) {
    const s = spans[i];
    if (s.start < cut && s.end > cut) cut = s.start;
  }
  return cut;
}

/**
 * createStream({ctx, write}) -> {push(chunk), flushPartial(), end()}
 * All work runs in order on one promise chain; write() receives scrubbed text.
 */
function createStream(opts) {
  const ctx = opts.ctx;
  const write = opts.write;
  let pending = '';
  let chain = Promise.resolve();
  const run = (fn) => { chain = chain.then(fn).catch(() => {}); return chain; };

  async function scrub(text) {
    try {
      const res = await engine.tokenize(text, ctx);
      if (res && typeof res.text === 'string') return res.text;
    } catch (_) { /* fall through */ }
    return WITHHELD + (text.endsWith('\n') ? '\n' : '');
  }

  async function lines() {
    let nl;
    while ((nl = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, nl + 1);
      pending = pending.slice(nl + 1);
      write(await scrub(line));
    }
  }

  /* Write the part of the partial line that lies before the window. */
  async function head() {
    let c;
    try { c = await engine.prepare(ctx); } catch (_) { c = ctx; }
    const text = pending;
    let cut = text.length - windowFor(c);
    if (cut <= 0) return;
    cut = await safeCut(text, cut, c);
    /* Never cut between the two halves of a surrogate pair: each half would
       be written to stdout as a replacement character. */
    if (cut > 0 && cut < text.length) {
      const hi = text.charCodeAt(cut - 1);
      const lo = text.charCodeAt(cut);
      if (hi >= 0xd800 && hi <= 0xdbff && lo >= 0xdc00 && lo <= 0xdfff) cut -= 1;
    }
    if (cut <= 0) return;
    pending = pending.slice(cut);
    write(await scrub(text.slice(0, cut)));
  }

  return {
    push(chunk) {
      pending += chunk;
      return run(async () => {
        await lines();
        if (pending.length > MAX_LINE) await head();
      });
    },
    flushPartial() {
      return run(async () => { if (pending) await head(); });
    },
    end() {
      return run(async () => {
        await lines();
        if (pending) { const t = pending; pending = ''; write(await scrub(t)); }
      });
    },
  };
}

async function main() {
  let vault = null;
  try { vault = await deps.loadVault(); } catch (err) { vault = null; }
  const ctx = {
    project: deps.findProjectRoot(process.cwd()),
    agent: process.env.ZN_AGENT || 'stream',
    tool: 'stream',
    destination: 'assistant',
    vault,
  };
  const stream = createStream({ ctx, write: (t) => process.stdout.write(t) });
  let timer = null;
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    stream.push(chunk);
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { timer = null; stream.flushPartial(); }, FLUSH_MS);
  });
  process.stdin.on('end', async () => {
    if (timer) clearTimeout(timer);
    await stream.end();
    try { require('../vault/client').close(); } catch (_) { /* not loaded */ }
  });
}

module.exports = { main, createStream, FLUSH_MS, MAX_LINE, WINDOW_MIN };

if (require.main === module) main();
