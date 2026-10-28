'use strict';

/*
 * Tool-call guard for agents and LLM applications (same verdict rules as the
 * Python package's check_tool_call / guard). Local only: nothing here touches
 * the network.
 */

const { evaluate, scanWindows, sanitizeToolResult, tooInvisible, invisibleBlock, truncatedBlocks } = require('./rules');

const MAX_DEPTH = 10;
const ON_BLOCK_VALUES = ['throw', 'return'];

/** Plain text for a blocked call or tool result: what was blocked, why, and the next step. */
function blockMessage(assessment, target) {
  const raw = String((assessment && assessment.reason) || '');
  let end = raw.length;
  while (end > 0 && raw.charCodeAt(end - 1) === 46) end--; // drop trailing dots in linear time
  const reason = raw.slice(0, end);
  const rule = assessment && assessment.rule;
  const why = reason ? `Reason: ${reason} (rule: ${rule}).` : `Reason: the input matched rule ${rule}.`;
  const isResult = /:(result|tool_output)$/.test(target);
  if (isResult && rule === 'size:truncated') {
    return `zn-gate blocked '${target}'. zn could not check this whole result (over 4 MB), so it was blocked. ` +
      'If you trust this tool, set ZN_ALLOW_TRUNCATED=1 (or pass allowTruncated: true) to let large results through without a full check.';
  }
  const step = isResult
    ? 'Next step: do not use this result; ask the person who runs this agent where the data came from.'
    : 'Next step: do not retry with reworded text; tell the person who runs this agent.';
  return `zn-gate blocked '${target}'. ${why} ${step}`;
}

/** Thrown when a guarded tool call or its result is blocked (onBlock: 'throw'). */
class GuardBlockError extends Error {
  constructor(assessment, target = '', payload = undefined) {
    super(blockMessage(assessment, target));
    this.name = 'GuardBlockError';
    this.code = 'ZN_GUARD_BLOCK';
    this.assessment = assessment;
    this.target = target;
    this.payload = payload;
  }
}

/** Internal: a payload is nested deeper than the scanner is willing to walk. */
class NestingTooDeep extends Error {}

/**
 * Every string in a nested structure, object keys included. Walks arrays, sets,
 * maps (keys and values) and plain objects, and decodes Buffer / Uint8Array as
 * UTF-8. Throws NestingTooDeep instead of skipping content below the depth
 * limit, so callers can fail closed. A container that contains itself is walked
 * once.
 */
function extractStrings(data, maxDepth = MAX_DEPTH, path = new WeakSet()) {
  if (typeof data === 'string') return [data];
  if (data instanceof Uint8Array) return [Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString('utf8')];
  let children;
  if (Array.isArray(data) || data instanceof Set) {
    children = Array.from(data);
  } else if (data instanceof Map) {
    children = [];
    for (const [k, v] of data) children.push(k, v);
  } else if (data && typeof data === 'object') {
    children = [];
    for (const [k, v] of Object.entries(data)) children.push(k, v);
  } else {
    return [];
  }
  if (maxDepth <= 0) throw new NestingTooDeep();
  if (path.has(data)) return [];
  path.add(data);
  try {
    const out = [];
    for (const child of children) out.push(...extractStrings(child, maxDepth - 1, path));
    return out;
  } finally {
    path.delete(data);
  }
}

/** extractStrings, or a block assessment when the payload is nested too deeply to check. */
function stringsOrBlock(data, what) {
  try {
    return { strings: extractStrings(data) };
  } catch (e) {
    if (!(e instanceof NestingTooDeep)) throw e;
    return {
      block: {
        allowed: false, verdict: 'block', confidence: 1.0, rule: 'size:nesting',
        reason: `${what} nested too deeply to check`,
      },
    };
  }
}

function allow(advisory, extra) {
  const res = { allowed: true, verdict: 'allow', confidence: 1.0, rule: 'none', reason: null, ...extra };
  if (advisory) res.advisory = { ...advisory };
  return res;
}

/**
 * Decide whether an agent tool call is safe to run. Every string in `args`
 * (nested values and keys) is evaluated; the first block wins. Arguments nested
 * too deeply to check are blocked (rule size:nesting).
 * Returns { allowed, verdict, confidence, rule, reason, advisory? }.
 */
function checkToolCall(toolName, args, opts = {}) {
  let advisory = null;
  const { strings, block } = stringsOrBlock(args, 'Arguments');
  if (block) return block;
  for (const s of strings) {
    const res = evaluate(s, opts);
    if (res.verdict === 'block') return { allowed: false, ...res };
    advisory = advisory || res.advisory;
  }
  return allow(advisory);
}

/**
 * Decide whether data returned by a tool may enter the model context. Large
 * strings are scanned in overlapping windows; `truncated` is true when some
 * string was not scanned in full, and such output is blocked by default (rule
 * size:truncated); opts.allowTruncated or ZN_ALLOW_TRUNCATED=1 allows it.
 * Internal helper of guardTool; the public async variant is checkToolResult in lib/client.js.
 */
function scanToolResult(result, opts = {}) {
  let truncated = false;
  let advisory = null;
  const { strings, block } = stringsOrBlock(result, 'Result');
  if (block) return block;
  if (tooInvisible(strings)) return { allowed: false, ...invisibleBlock() };
  for (const s of strings) {
    const res = scanWindows(s, opts);
    if (res.verdict === 'block') return { allowed: false, ...res };
    truncated = truncated || res.truncated === true;
    advisory = advisory || res.advisory;
  }
  if (truncated && truncatedBlocks(opts)) {
    return {
      allowed: false, verdict: 'block', confidence: 1.0, rule: 'size:truncated',
      reason: 'Output too large to scan in full', truncated: true,
    };
  }
  return allow(advisory, { truncated });
}

function validateOptions(opts) {
  if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) {
    throw new TypeError('guardTool: options must be an object');
  }
  const onBlock = opts.onBlock === undefined ? 'throw' : opts.onBlock;
  if (!ON_BLOCK_VALUES.includes(onBlock)) {
    const allowed = ON_BLOCK_VALUES.map((v) => "'" + v + "'").join(', ');
    throw new TypeError('guardTool: onBlock must be one of ' + allowed + ' (got ' + JSON.stringify(onBlock) + ')');
  }
  for (const key of ['checkArgs', 'checkResult', 'maskSecrets', 'blockTruncated', 'allowTruncated']) {
    if (opts[key] !== undefined && typeof opts[key] !== 'boolean') {
      throw new TypeError('guardTool: ' + key + ' must be a boolean');
    }
  }
  if (opts.onBlockCallback !== undefined && typeof opts.onBlockCallback !== 'function') {
    throw new TypeError('guardTool: onBlockCallback must be a function');
  }
  return onBlock;
}

/**
 * Wrap a sync or async function as a guarded tool. The call arguments are
 * checked before it runs and, with checkResult: true, its result before it
 * is returned.
 *
 * opts:
 *   name            tool name used in messages (default: fn.name)
 *   onBlock         'throw' (default; GuardBlockError) or 'return' (returns opts.fallback, or the assessment when no fallback is given)
 *   fallback        value returned when onBlock is 'return'
 *   checkArgs       check the arguments (default true)
 *   checkResult     check the return value (default false)
 *   maskSecrets     redact credentials in the returned value (default false)
 *   blockTruncated  with checkResult, block a result too large to scan in full (now the default)
 *   allowTruncated  with checkResult, allow such a result (it is marked truncated)
 *   onBlockCallback called as (assessment, name, payload) before the block is applied
 *   strict          passed to the rules engine
 * An unknown onBlock (or a wrongly typed option) throws a TypeError at wrap time.
 */
function guardTool(fn, opts = {}) {
  if (typeof fn !== 'function') throw new TypeError('guardTool: first argument must be a function');
  const onBlock = validateOptions(opts);
  const name = opts.name || fn.name || 'anonymous';
  const checkArgs = opts.checkArgs !== false;
  const engineOpts = opts.strict === undefined ? {} : { strict: opts.strict };

  const blocked = (assessment, target, payload) => {
    if (opts.onBlockCallback) opts.onBlockCallback(assessment, name, payload);
    if (onBlock === 'throw') throw new GuardBlockError(assessment, target, payload);
    return { value: opts.fallback !== undefined ? opts.fallback : assessment };
  };

  const before = (args) => {
    if (!checkArgs) return null;
    const payload = { args };
    const assessment = checkToolCall(name, payload, engineOpts);
    return assessment.allowed ? null : blocked(assessment, name, payload);
  };

  const after = (res) => {
    if (opts.checkResult) {
      const assessment = scanToolResult(res, { ...engineOpts, blockTruncated: opts.blockTruncated === true, allowTruncated: opts.allowTruncated === true });
      if (!assessment.allowed) return blocked(assessment, name + ':result', res).value;
    }
    return opts.maskSecrets ? sanitizeToolResult(res).sanitized : res;
  };

  const isAsync = fn.constructor && fn.constructor.name === 'AsyncFunction';
  const wrapped = isAsync
    ? async function (...args) {
        const b = before(args);
        if (b) return b.value;
        return after(await fn.apply(this, args));
      }
    : function (...args) {
        const b = before(args);
        if (b) return b.value;
        const res = fn.apply(this, args);
        if (res && typeof res.then === 'function') return res.then(after);
        return after(res);
      };
  Object.defineProperty(wrapped, 'name', { value: fn.name, configurable: true });
  return wrapped;
}

module.exports = { checkToolCall, guardTool, GuardBlockError, blockMessage, extractStrings, scanToolResult, ON_BLOCK_VALUES };
