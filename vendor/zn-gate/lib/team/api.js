'use strict';
/*
 * HTTP client for the zn cloud team endpoints: join, signed policy download
 * and audit upload. Node built-ins only.
 *
 * Every request has a timeout, a capped response body and redirect: 'error'.
 * Error messages never contain the install token.
 */

const MAX_BODY_BYTES = 1024 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);
const ORG_RE = /^org_[A-Za-z0-9]{8,32}$/;
const INSTALL_TOKEN_RE = /^zni_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[A-Za-z0-9]{32}$/;
const KID_RE = /^[0-9a-f]{16}$/;
const PUBLIC_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/;
const JOIN_RESPONSE_FIELDS = new Set(['org', 'org_name', 'install_token', 'policy_url', 'audit_url', 'telemetry_url', 'policy_public_key']);
const PUBLIC_KEY_FIELDS = ['alg', 'kid', 'key'];
/*
 * Policy features this client understands, sent with every policy download.
 * A server must not send a rule that uses a feature the client did not list:
 * older clients refuse the whole policy when a rule has a field they do not
 * know.
 */
const POLICY_FEATURES_HEADER = 'X-ZN-Policy-Features';
const POLICY_FEATURES = 'warn';

class TeamApiError extends Error {
  constructor(message, { code, status = 0, body = null } = {}) {
    super(message);
    this.name = 'TeamApiError';
    this.code = code;
    this.status = status;
    this.body = body;
  }
}

function usageError(message) {
  const err = new Error(message);
  err.code = 'ZN_USAGE';
  return err;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function badResponse(what, status = 0) {
  return new TeamApiError(`zn cloud sent an unexpected response (${what})`, { code: 'ZN_TEAM_BAD_RESPONSE', status });
}

/**
 * Normalize the zn cloud base URL to its origin. https everywhere; plain http
 * only for loopback hosts (local development and tests).
 */
function checkBase(input) {
  if (typeof input !== 'string' || input === '') throw usageError('zn cloud URL must be a non-empty string');
  if (input.includes('?') || input.includes('#')) throw usageError('zn cloud URL must not contain a query or fragment');
  let url;
  try {
    url = new URL(input);
  } catch {
    throw usageError('zn cloud URL is not a valid URL');
  }
  if (url.username || url.password) throw usageError('zn cloud URL must not contain credentials');
  if (url.pathname !== '/') throw usageError('zn cloud URL must not contain a path');
  const loopbackHttp = url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !loopbackHttp) {
    throw usageError('zn cloud URL must use https (http is allowed only for 127.0.0.1, localhost or [::1])');
  }
  return `${url.protocol}//${url.host}`;
}

async function readBody(res) {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      throw badResponse('response body is too large', res.status);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/** null for an empty body, undefined when the body is not JSON. */
function parseJson(raw) {
  if (raw.length === 0) return null;
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    return undefined;
  }
}

function checkEndpoint(value, suffix, allowHttp) {
  if (typeof value !== 'string') return false;
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username || url.password || url.search || url.hash || url.pathname !== suffix) return false;
  if (url.protocol === 'https:') return true;
  return allowHttp && url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
}

function validateJoinResponse(data, allowHttp, status) {
  const fail = (what) => {
    throw badResponse(what, status);
  };
  for (const key of Object.keys(data)) {
    if (!JOIN_RESPONSE_FIELDS.has(key)) fail('unknown field');
  }
  if (typeof data.org !== 'string' || !ORG_RE.test(data.org)) fail('org id');
  if (data.org_name !== undefined && (typeof data.org_name !== 'string' || data.org_name.length < 1 || data.org_name.length > 100)) {
    fail('org name');
  }
  if (typeof data.install_token !== 'string' || !INSTALL_TOKEN_RE.test(data.install_token)) fail('install token');
  if (!checkEndpoint(data.policy_url, '/v1/org/policy', allowHttp)) fail('policy url');
  if (!checkEndpoint(data.audit_url, '/v1/audit/ingest', allowHttp)) fail('audit url');
  if (data.telemetry_url !== undefined && !checkEndpoint(data.telemetry_url, '/v1/telemetry', allowHttp)) fail('telemetry url');
  const key = data.policy_public_key;
  const keyOk = isObject(key)
    && Object.keys(key).length === PUBLIC_KEY_FIELDS.length
    && PUBLIC_KEY_FIELDS.every((f) => f in key)
    && key.alg === 'Ed25519'
    && typeof key.kid === 'string' && KID_RE.test(key.kid)
    && typeof key.key === 'string' && PUBLIC_KEY_RE.test(key.key);
  if (!keyOk) fail('policy public key');
}

function isSignedPolicy(data) {
  if (!isObject(data) || Object.keys(data).length !== 2 || !('policy' in data) || !('signature' in data)) return false;
  const p = data.policy;
  const s = data.signature;
  if (!isObject(p) || typeof p.org !== 'string' || !ORG_RE.test(p.org)) return false;
  if (!Number.isSafeInteger(p.version) || p.version < 1) return false;
  if (typeof p.issued_at !== 'string' || typeof p.expires_at !== 'string' || !Array.isArray(p.rules)) return false;
  return isObject(s)
    && Object.keys(s).length === 3
    && s.alg === 'Ed25519'
    && typeof s.kid === 'string' && KID_RE.test(s.kid)
    && typeof s.sig === 'string' && SIGNATURE_RE.test(s.sig);
}

/**
 * createApi({ base, token, timeoutMs, fetchImpl, userAgent }) -> { base, preview, join, getPolicy, ingest }
 *
 * base: zn cloud origin (see checkBase). token: install token (zni_...), needed
 * for getPolicy and ingest only. userAgent: the full User-Agent header value,
 * for example "zn-gate/1.5.0".
 */
function createApi(options = {}) {
  const {
    base: rawBase,
    token,
    timeoutMs = 10000,
    fetchImpl = globalThis.fetch,
    userAgent = 'zn-gate',
  } = options;
  const base = checkBase(rawBase);
  const allowHttp = base.startsWith('http://');
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) throw usageError('timeoutMs must be a positive integer');
  if (typeof fetchImpl !== 'function') throw usageError('fetch is not available; zn-gate needs Node 18 or later');
  if (typeof userAgent !== 'string' || userAgent === '') throw usageError('userAgent must be a non-empty string');

  const scrub = (text) => (typeof token === 'string' && token !== '' ? text.split(token).join('[token]') : text);

  const httpError = (status, data) => {
    const detail = isObject(data) && typeof data.error === 'string' ? data.error.slice(0, 200) : '';
    return new TeamApiError(scrub(`zn cloud answered HTTP ${status}${detail ? `: ${detail}` : ''}`), {
      code: 'ZN_TEAM_HTTP',
      status,
      body: data === undefined ? null : data,
    });
  };

  async function request(method, path, { auth = false, body, etag, extraHeaders } = {}) {
    const headers = { 'User-Agent': userAgent, Accept: 'application/json', ...extraHeaders };
    if (auth) {
      if (typeof token !== 'string' || token === '') throw usageError('this request needs an install token');
      headers.Authorization = `Bearer ${token}`;
    }
    if (etag) headers['If-None-Match'] = etag;
    let payload;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }

    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      const res = await fetchImpl(base + path, {
        method,
        headers,
        body: payload,
        redirect: 'error',
        signal: controller.signal,
      });
      const raw = await readBody(res);
      const resHeaders = res.headers;
      const resEtag = resHeaders && typeof resHeaders.get === 'function' ? resHeaders.get('etag') : null;
      const retryAfter = resHeaders && typeof resHeaders.get === 'function' ? resHeaders.get('retry-after') : null;
      return { status: res.status, etag: resEtag || undefined, retryAfter: retryAfter || undefined, data: parseJson(raw) };
    } catch (err) {
      if (err instanceof TeamApiError) throw err;
      if (timedOut) {
        throw new TeamApiError(`zn cloud did not answer within ${timeoutMs} ms`, { code: 'ZN_TEAM_TIMEOUT' });
      }
      throw new TeamApiError('could not reach zn cloud (network error)', { code: 'ZN_TEAM_NETWORK' });
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * What a join token is for, before joining: POST /v1/org/join-preview (the token travels in the
   * body and is not used up). Never throws for an HTTP answer:
   *   {ok: true, org_name, invited_by, expires_at}
   *   {ok: false, reason: 'invalid'}          unknown, expired or used-up token (404 invalid_join_token)
   *   {ok: false, reason: 'no_subscription'}  the organization has no active Team subscription (402)
   *   {ok: false, reason: 'unavailable', detail}  anything else (older server, rate limit, error, network)
   */
  async function preview(joinToken) {
    let r;
    try {
      r = await request('POST', '/v1/org/join-preview', { body: { join_token: joinToken } });
    } catch (err) {
      return { ok: false, reason: 'unavailable', detail: err && err.code ? err.code : 'network error' };
    }
    const code = isObject(r.data) && typeof r.data.code === 'string' ? r.data.code : '';
    if (r.status === 404 && code === 'invalid_join_token') return { ok: false, reason: 'invalid' };
    if (r.status === 402 && code === 'no_subscription') return { ok: false, reason: 'no_subscription' };
    if (r.status !== 200 || !isObject(r.data)) return { ok: false, reason: 'unavailable', detail: 'HTTP ' + r.status };
    const d = r.data;
    const okName = typeof d.org_name === 'string' && d.org_name.length > 0 && d.org_name.length <= 100;
    const okBy = d.invited_by === null || (typeof d.invited_by === 'string' && d.invited_by.length > 0 && d.invited_by.length <= 60);
    const okExp = typeof d.expires_at === 'string' && !Number.isNaN(Date.parse(d.expires_at));
    if (!okName || !okBy || !okExp) return { ok: false, reason: 'unavailable', detail: 'malformed preview' };
    return { ok: true, org_name: d.org_name, invited_by: d.invited_by, expires_at: d.expires_at };
  }

  /** Register this installation. No token is sent; the join token travels in the body. */
  async function join(body) {
    const r = await request('POST', '/v1/org/join', { body });
    if (r.status !== 200 && r.status !== 201) throw httpError(r.status, r.data);
    if (r.data === undefined) throw badResponse('body is not JSON', r.status);
    if (!isObject(r.data)) throw badResponse('join answer is not an object', r.status);
    validateJoinResponse(r.data, allowHttp, r.status);
    return r.data;
  }

  /** Fetch the signed policy. 404 when nothing is published, 304 when `etag` is still current. */
  async function getPolicy({ etag } = {}) {
    const r = await request('GET', '/v1/org/policy', { auth: true, etag, extraHeaders: { [POLICY_FEATURES_HEADER]: POLICY_FEATURES } });
    if (r.status === 304) return { status: 304, etag: r.etag || etag };
    if (r.status === 404) return { status: 404 };
    if (r.status !== 200) throw httpError(r.status, r.data);
    if (!isSignedPolicy(r.data)) throw badResponse('signed policy is malformed', r.status);
    return { status: 200, etag: r.etag, body: r.data };
  }

  /** Upload one batch of audit records. Resolves only for 200. */
  async function ingest(body) {
    const r = await request('POST', '/v1/audit/ingest', { auth: true, body });
    if (r.status !== 200) throw httpError(r.status, r.data);
    if (!isObject(r.data)) throw badResponse('ingest answer is not an object', r.status);
    return { status: 200, body: r.data };
  }

  /**
   * This installation revokes itself: POST /v1/org/install/leave, authenticated only by its own install token (no
   * body, no id). Never throws for an HTTP answer or a network failure:
   *   {done: true, reason: 'revoked' | 'already' | 'token_invalid'}   200 (both values), or 401: the token is no longer valid
   *   {done: false, error, status?, retryAfterSeconds?, unsupported?} 429, 5xx, a network error or timeout, and 404/405
   *                                                                   (an older server without the endpoint: never "revoked")
   */
  async function leaveInstall() {
    const client = /^zn-gate\/[0-9A-Za-z.+_-]{1,32}$/.test(userAgent) ? { 'X-ZN-Client': userAgent } : undefined;
    let r;
    try {
      r = await request('POST', '/v1/org/install/leave', { auth: true, extraHeaders: client });
    } catch (err) {
      if (err && err.code === 'ZN_USAGE') throw err;
      return { done: false, error: err && err.code === 'ZN_TEAM_TIMEOUT' ? 'the server did not answer in time' : 'could not reach the server' };
    }
    if (r.status === 200) {
      if (isObject(r.data) && r.data.revoked === true) return { done: true, reason: r.data.already === true ? 'already' : 'revoked' };
      return { done: false, error: 'unexpected answer from the server', status: 200 };
    }
    if (r.status === 401) return { done: true, reason: 'token_invalid' };
    if (r.status === 404 || r.status === 405) return { done: false, error: 'this server does not support leaving yet (HTTP ' + r.status + ')', status: r.status, unsupported: true };
    if (r.status === 429) {
      const secs = Number.parseInt(r.retryAfter, 10);
      return { done: false, error: 'the server asked to retry later (HTTP 429)', status: 429, ...(Number.isFinite(secs) && secs > 0 ? { retryAfterSeconds: Math.min(secs, 86400) } : {}) };
    }
    return { done: false, error: 'the server answered HTTP ' + r.status, status: r.status };
  }

  return { base, preview, join, getPolicy, ingest, leaveInstall };
}

module.exports = { checkBase, createApi, TeamApiError, POLICY_FEATURES_HEADER, POLICY_FEATURES };
