'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');
const { evaluate, redactSecrets, sanitizeToolResult, RULES_VERSION } = require('./rules');
let PKG_VERSION = '1.6.0';
try {
  PKG_VERSION = require('../package.json').version || '1.6.0';
} catch (_) {}

/*
 * Data-flow contract (since 1.4.1):
 *
 *  - Tool results, tool-call arguments and tool/parameter descriptions are
 *    evaluated ONLY in-process (analyzeLocal / checkToolResult). They never
 *    leave the machine, under any configuration.
 *  - The only code path that can reach the network is analyze() — the
 *    prompt-analysis API used by the `analyze_prompt` MCP tool and the
 *    `zn-gate analyze` CLI command — and only when BOTH ZN_API_KEY and
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
              resolve({ ...parsed, engine: stageName });
            } catch (err) {
              reject(new Error(`Failed to parse gateway response: ${err.message}`));
            }
          } else {
            reject(new Error(`Gateway responded with HTTP ${res.statusCode}: ${body.slice(0, 120)}`));
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Gateway request timed out'));
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
  const markerOnly = !explicitOptIn(options);
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
  const tlsWhy = storedKey ? cloudKey.tlsRefusal() : null;
  if (tlsWhy) {
    // The saved key is never sent over a connection that is not checked against the system's authorities.
    return { ...local, mode: 'oss-local', fallback: true, cloud_error: tlsWhy };
  }
  const endpoint = resolveEndpoint(options, { stored: storedKey });
  if (storedKey && endpoint.indexOf(FIXED_API_ORIGIN + '/') !== 0) {
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
    };
    if (urlIgnored) out.note = 'The saved key is only sent to api.usezn.com, so the custom URL was ignored. Use --key or ZN_API_KEY to send to another URL.';
    if (cloudRes.long_input && cloudRes.long_input.capped) {
      out.warning = 'The text is longer than the cloud gate checks (' + cloudRes.long_input.windows + ' windows of 512 tokens): the end was not analyzed.';
    } else if (windows && cloudRes.long_input && cloudRes.long_input.mode === 'truncate') {
      out.warning = 'The cloud gate checked only the first 512 tokens of this text (' + (cloudRes.long_input.reason || 'no windows') + ').';
    }
    return out;
  } catch (err) {
    if (process.env.DEBUG || process.env.ZN_VERBOSE) {
      process.stderr.write(`[zn-gate] Warning: Cloud gate error (${err.message}). Using local rules result.\n`);
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

module.exports = {
  usableApiKey,
  analyze,
  analyzeLocal,
  checkToolResult,
  isCloudEnabled,
  longInputMode,
  LONG_INPUT_MIN_CHARS,
  resolveEndpoint,
  usesStoredKey,
  evaluate,
  RULES_VERSION,
};
