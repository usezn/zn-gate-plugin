'use strict';

const https = require('https');
const { deadlineLookup } = require('./dns-deadline');
const http = require('http');
const { URL } = require('url');
const { evaluate, redactSecrets, sanitizeToolResult, RULES_VERSION } = require('./rules');
const { checkCommand } = require('./destructive');
const { checkToolCall, guardTool, GuardBlockError } = require('./guard');
let PKG_VERSION = '1.6.0';
try {
  PKG_VERSION = require('../package.json').version || '1.6.0';
} catch (_) {}

/*
 * Data-flow contract (since 1.4.1):
 *
 *  - Tool results, tool-call arguments and tool/parameter descriptions are
 *    evaluated ONLY in-process (analyzeLocal / checkToolResult). They never
 *    leave the machine through this module's own entry points.
 *  - One opt-in exception (since 1.15): the Claude Code PostToolUse hook
 *    (lib/hooks/runner.js, cloudOutputNote) passes a capped sample of the
 *    output of web, MCP and shell tools to analyze() with pinOrigin, only when
 *    the person ran zn-gate connect and set hooks.cloudCheckToolOutput to true in their own user config (off by default).
 *  - Text reaches the network only through analyze(), in two cases: prompt
 *    analysis (the `analyze_prompt` MCP tool and the `zn-gate analyze` CLI
 *    command) and, as described above, the tool-output sample of the Claude
 *    Code hook. Either only when BOTH ZN_API_KEY and
 *    ZN_CLOUD=1 are set, or the user ran `zn-gate connect` (and
 *    ZN_LOCAL_ONLY is not "true"). Secrets are redacted locally with
 *    redactSecrets() before the request is built. `connect` and `disconnect`
 *    (lib/connect-cli.js) are the only other code that contacts the network
 *    here, only on the person's command, and only to https://api.usezn.com.
 */

const FIXED_API_ORIGIN = 'https://api.usezn.com';

/**
 * The gateway URL. A key that `zn-gate connect` stored (keychain or vault) is
 * only ever sent to https://api.usezn.com: --url and ZN_API_URL are ignored
 * for it (`stored: true`). A custom URL works only with a key the caller gave
 * explicitly (--key or ZN_API_KEY).
 */
function resolveEndpoint(options = {}, { stored = false } = {}) {
  if (!stored && (options.apiUrl || process.env.ZN_API_URL)) {
    return options.apiUrl || process.env.ZN_API_URL;
  }
  const stage = options.stage || process.env.ZN_STAGE || 'v30';
  if (stage === 'prod') {
    return 'https://api.usezn.com/prod/analyze';
  }
  return 'https://api.usezn.com/v30/analyze';
}

const cloudKey = require('./cloud-key');
const { isVerbose } = require('./verbose');
const { usableApiKey } = cloudKey;

/**
 * True only when the user explicitly opted in to cloud prompt analysis, and
 * not under a local-only override. Two ways to opt in:
 *   - an API key in ZN_API_KEY / --key AND ZN_CLOUD=1 (a key alone enables nothing);
 *   - `zn-gate connect`, which stores the key in the system keychain or the
 *     zn vault and leaves a marker (no key) in ~/.zn/config.json.
 * This check reads one small file at most; it never touches the keychain.
 * analyze() then looks the key up and falls back to local rules without one.
 */
function isCloudEnabled(options = {}) {
  const forceLocal = Boolean(options.localOnly) || process.env.ZN_LOCAL_ONLY === 'true';
  if (forceLocal) return false;
  if (explicitOptIn(options)) return true;
  return cloudKey.isConnected();
}

/** A usable key from --key / ZN_API_KEY together with ZN_CLOUD=1: the person's own, explicit opt-in. */
function explicitOptIn(options = {}) {
  // storedOnly (tool output in the hooks): the environment and --key never count, only what `zn-gate connect` saved.
  if (options.storedOnly) return false;
  return Boolean(usableApiKey(options.apiKey || process.env.ZN_API_KEY)) && process.env.ZN_CLOUD === '1';
}

/**
 * True when the key analyze() would use is the one `connect` stored: the cloud is on because of the marker
 * and not because of an explicit key plus ZN_CLOUD=1. A key in ZN_API_KEY or --key never takes part in that
 * case, so a marker written by hand cannot make zn-gate send text with an environment key or to another URL.
 */
function usesStoredKey(options = {}) {
  return !explicitOptIn(options) && cloudKey.isConnected();
}

let notedNoStoredKey = false;
function noteNoStoredKey() {
  if (notedNoStoredKey) return;
  notedNoStoredKey = true;
  try { process.stderr.write('[zn-gate] Connected, but the saved key is not readable (or does not match the marker), so prompts are checked locally only. Run zn-gate status.\n'); } catch (_) { /* no stderr */ }
}

/*
 * Long texts: the cloud gate reads the first 512 tokens unless the request
 * asks for overlapping windows ("long_input": "windows": 512-token windows,
 * stride 256, up to 20; the verdict comes from the window with the highest
 * score). Text over LONG_INPUT_MIN_CHARS (well under 512 tokens of English
 * prose) asks for windows unless ZN_LONG_INPUT / --long-input is "off"; a
 * text that fits one window gets the same result either way. Each window is
 * one more inference, so these requests are slower and get a longer timeout.
 */
const LONG_INPUT_MIN_CHARS = 1000;
const WINDOWS_TIMEOUT_MS = 12000;

function longInputMode(options = {}) {
  const v = String(options.longInput ?? process.env.ZN_LONG_INPUT ?? 'windows').trim().toLowerCase();
  return ['off', 'none', 'truncate', '0', 'false', 'no'].includes(v) ? 'off' : 'windows';
}

// One plain sentence on what a failed cloud call means and what to do (same wording as zn-gate-py).
function cloudErrorHint(err) {
  if (err && err.httpStatus) {
    if (err.httpStatus === 401 || err.httpStatus === 403) return 'The cloud service did not accept the API key: check ZN_API_KEY.';
    return `The cloud service answered with an error (HTTP ${err.httpStatus}): try again later.`;
  }
  if (err && err.code === 'ETIMEDOUT') return 'The cloud service took too long to answer: check your network connection.';
  if (err && typeof err.code === 'string') return 'The cloud service could not be reached: check your network connection and ZN_API_URL.';
  return 'The cloud check failed.';
}

// The cloud gate answers "allow" or "block". The verdict is read once here, without case or surrounding spaces, so every
// caller compares a lowercase value; any other verdict (missing, empty, unknown) blocks the text: fail closed. A body that
// is not a JSON object is a failed cloud call (the local rules decide), as in the Python package.
const UNKNOWN_CLOUD_VERDICT = {
  verdict: 'block', confidence: 1.0, rule: 'cloud:unknown-verdict',
  reason: 'The cloud gate answered with a verdict zn does not know, so the text is blocked.',
};
function cloudVerdict(parsed) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('the gateway response is not a JSON object');
  const v = typeof parsed.verdict === 'string' ? parsed.verdict.trim().toLowerCase() : '';
  if (v === 'allow' || v === 'block') return { ...parsed, verdict: v };
  return { ...parsed, ...UNKNOWN_CLOUD_VERDICT };
}

// When the gate could not reach its model, it still answers from the rules alone and says so in decided_by ("ml-error...").
// That answer is not a model verdict: it is marked degraded so callers can tell it apart.
const DEGRADED_REASON = 'model unavailable, rules only';
function degradedFields(cloudRes) {
  const decidedBy = typeof cloudRes.decided_by === 'string' ? cloudRes.decided_by.trim().toLowerCase() : '';
  return decidedBy.startsWith('ml-error') ? { degraded: true, degraded_reason: DEGRADED_REASON } : {};
}

function analyzeCloud(input, apiKey, endpointUrl, timeoutMs = 4000, extra = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpointUrl);
    const postData = JSON.stringify({ input, ...extra });
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const req = lib.request(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
          Authorization: `Bearer ${apiKey.trim()}`,
          'User-Agent': `zn-gate/${PKG_VERSION} (mcp-client)`,
        },
        timeout: timeoutMs,
        // Name resolution ends within the same time (getaddrinfo alone can take 20 s on a silent network).
        lookup: deadlineLookup(timeoutMs),
        // Always verify the certificate: NODE_TLS_REJECT_UNAUTHORIZED=0 must not let the key travel unverified.
        ...(isHttps ? { rejectUnauthorized: true } : {}),
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsed = JSON.parse(body);
              const stageName = endpointUrl.includes('/v30') ? 'cloud-v30' : 'cloud-prod';
              resolve({ ...cloudVerdict(parsed), engine: stageName });
            } catch (err) {
              reject(new Error(`Failed to parse gateway response: ${err.message}`));
            }
          } else {
            const err = new Error(`Gateway responded with HTTP ${res.statusCode}: ${body.slice(0, 120)}`);
            err.httpStatus = res.statusCode;
            reject(err);
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      const err = new Error('Gateway request timed out');
      err.code = 'ETIMEDOUT';
      reject(err);
    });

    req.on('error', (err) => reject(err));
    req.write(postData);
    req.end();
  });
}

/**
 * Local-only evaluation. Never touches the network.
 * Used for tool results, tool-call arguments and tool descriptions.
 */
function analyzeLocal(input, options = {}) {
  const local = evaluate(input, options);
  return {
    ...local,
    mode: local.verdict === 'block' ? 'hybrid-local-fastpath' : 'oss-local',
  };
}

/**
 * Prompt analysis. Local rules first; optional cloud second opinion only when
 * the user opted in (ZN_API_KEY + ZN_CLOUD=1, or `zn-gate connect`). The text is secret-redacted
 * locally before it is sent.
 */
async function analyze(input, options = {}) {
  const local = evaluate(input, options);
  if (local.verdict === 'block') {
    return {
      ...local,
      mode: 'hybrid-local-fastpath',
    };
  }

  if (!isCloudEnabled(options)) {
    return {
      ...local,
      mode: 'oss-local',
    };
  }

  // Only the marker turns the cloud on: use the key `connect` stored, never ZN_API_KEY or --key.
  // storedOnly never falls back to ZN_API_KEY or --key: if the saved key cannot be read, nothing is sent.
  const markerOnly = Boolean(options.storedOnly) || !explicitOptIn(options);
  const found = markerOnly
    ? await cloudKey.loadStoredKey().then((s) => (s ? { key: s.key, source: s.store } : null))
    : await cloudKey.resolveApiKey(options);
  if (!found) {
    // Connected, but the key is not readable now (empty keychain, vault locked, marker not matching): local rules only.
    if (markerOnly) noteNoStoredKey();
    return { ...local, mode: 'oss-local', fallback: true, cloud_error: 'no API key available (run zn-gate status)' };
  }
  const apiKey = found.key;
  const { sanitized, detections } = redactSecrets(typeof input === 'string' ? input : String(input ?? ''));
  const storedKey = found.source === 'keychain' || found.source === 'vault';
  // pinOrigin (the hooks): the key and the text go only to the fixed zn origin, with the TLS check held to the same strictness as a saved key,
  // because the environment of an agent can be set by the project it works in.
  const pinned = storedKey || Boolean(options.pinOrigin);
  const tlsWhy = pinned ? cloudKey.tlsRefusal() : null;
  if (tlsWhy) {
    // The saved key is never sent over a connection that is not checked against the system's authorities.
    return { ...local, mode: 'oss-local', fallback: true, cloud_error: tlsWhy };
  }
  const endpoint = resolveEndpoint(options, { stored: pinned });
  if (pinned && endpoint.indexOf(FIXED_API_ORIGIN + '/') !== 0) {
    return { ...local, mode: 'oss-local', fallback: true, cloud_error: 'the saved key is only sent to ' + FIXED_API_ORIGIN };
  }
  const urlIgnored = storedKey && Boolean(options.apiUrl || process.env.ZN_API_URL);
  const windows = longInputMode(options) === 'windows' && sanitized.length > LONG_INPUT_MIN_CHARS;
  try {
    const cloudRes = await analyzeCloud(sanitized, apiKey, endpoint,
      options.timeout || (windows ? WINDOWS_TIMEOUT_MS : 4000), windows ? { long_input: 'windows' } : {});
    const out = {
      ...cloudRes,
      mode: 'hybrid-cloud',
      secrets_redacted_before_upload: detections.length,
      ...degradedFields(cloudRes),
    };
    if (urlIgnored) out.note = 'The saved key is only sent to api.usezn.com, so the custom URL was ignored. Use --key or ZN_API_KEY to send to another URL.';
    if (cloudRes.long_input && cloudRes.long_input.capped) {
      out.warning = 'The text is longer than the cloud gate checks (' + cloudRes.long_input.windows + ' windows of 512 tokens): the end was not analyzed.';
    } else if (windows && cloudRes.long_input && cloudRes.long_input.mode === 'truncate') {
      out.warning = 'The cloud gate checked only the first 512 tokens of this text (' + (cloudRes.long_input.reason || 'no windows') + ').';
    }
    return out;
  } catch (err) {
    if (isVerbose()) {
      process.stderr.write(`[zn-gate] Warning: Cloud gate error (${err.message}). ${cloudErrorHint(err)} The local rules were used instead, so the text was checked on this machine only.\n`);
    }
    return {
      ...local,
      mode: 'oss-local',
      fallback: true,
      cloud_error: err.message,
    };
  }
}

/**
 * Inspect tool output before it enters the LLM context (indirect prompt
 * injection defense). Local only, and secrets are ALWAYS redacted from the
 * returned content via sanitizeToolResult().
 */
async function checkToolResult(toolName, content, options = {}) {
  const textContent = typeof content === 'string' ? content : JSON.stringify(content);

  // Fast-path for empty or tiny returns
  if (!textContent || textContent.length < 5) {
    return {
      tool_name: toolName,
      safe_to_ingest: true,
      truncated: false,
      secrets_redacted: 0,
      sanitized_content: textContent,
      assessment: { verdict: 'allow', confidence: 1.0, rule: 'none', engine: 'oss-local', mode: 'oss-local' },
    };
  }

  const res = sanitizeToolResult(String(toolName), textContent, { ...options, maskSecrets: true });
  return {
    ...res,
    assessment: { ...res.assessment, mode: res.safe_to_ingest ? 'oss-local' : 'hybrid-local-fastpath' },
  };
}

// The evidence ledger is loaded on first use, so requiring the client stays light.
function verifyEvidenceLedger(...args) {
  return require('./evidence').verifyEvidenceLedger(...args);
}

function logEvidence(...args) {
  return require('./evidence').logEvidence(...args);
}

module.exports = {
  _cloudVerdict: cloudVerdict,
  usableApiKey,
  analyze,
  analyzeLocal,
  checkToolResult,
  checkToolCall,
  guardTool,
  GuardBlockError,
  sanitizeToolResult,
  redactSecrets,
  verifyEvidenceLedger,
  logEvidence,
  isCloudEnabled,
  longInputMode,
  LONG_INPUT_MIN_CHARS,
  resolveEndpoint,
  usesStoredKey,
  evaluate,
  checkCommand,
  RULES_VERSION,
};
