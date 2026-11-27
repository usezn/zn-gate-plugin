'use strict';

/**
 * Egress allowlist for `zn run --egress-allow HOST[:PORT],...` (opt-in).
 *
 * A small HTTP proxy on 127.0.0.1 (random port). The child gets it through
 * HTTP_PROXY / HTTPS_PROXY / ALL_PROXY, so curl, gh, Python requests/urllib
 * and axios send their requests to it, and so does Node when its version
 * honours NODE_USE_ENV_PROXY (older Node ignores it). It opens CONNECT tunnels and
 * absolute-form http:// requests only to the listed hosts, answers 403 to
 * anything else (before any DNS lookup), and logs the refused host, never the
 * request body or headers.
 *
 * Covers programs that use the proxy variables. Not covered: programs that
 * ignore them, raw sockets and DNS (see docs/secrets.md).
 */

const http = require('http');
const net = require('net');
const { URL } = require('url');
const { znError } = require('../deps');

const USAGE_HINT = '--egress-allow takes HOST or HOST:PORT, comma separated (for example api.example.com,api.example.org:8443)';
const HOST_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
// Idle time after which a proxied plain-HTTP upstream or tunnel is closed.
const IDLE_MS = 60000;
const SAFE_LOG_HOST = /^[a-z0-9.:[\]-]{1,260}$/;

function normHost(h) {
  let s = String(h || '').toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

function parsePort(p) {
  if (!/^\d{1,5}$/.test(p)) return NaN;
  const n = Number(p);
  return n >= 1 && n <= 65535 ? n : NaN;
}

/** One allowlist entry: {host, port}; port null means any port. Throws ZN_USAGE. */
function parseEntry(raw) {
  const s = String(raw).trim().toLowerCase();
  let host = s;
  let port = null;
  const bracket = /^\[([0-9a-f:.]+)\](?::(\d+))?$/.exec(s);
  if (bracket) {
    host = bracket[1];
    if (bracket[2] !== undefined) port = parsePort(bracket[2]);
  } else if (s.split(':').length === 2) {
    host = s.slice(0, s.indexOf(':'));
    port = parsePort(s.slice(s.indexOf(':') + 1));
  }
  host = normHost(host);
  const ok = (net.isIP(host) !== 0 || HOST_RE.test(host)) && host.length <= 253;
  if (!ok || (port !== null && Number.isNaN(port))) {
    throw znError('ZN_USAGE', 'invalid --egress-allow entry ' + JSON.stringify(String(raw)) + '. ' + USAGE_HINT);
  }
  return { host, port };
}

/** A comma separated list (or an array) of entries. Empty is an error. */
function parseAllowList(value) {
  const parts = (Array.isArray(value) ? value : [value]).join(',').split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) throw znError('ZN_USAGE', 'the --egress-allow list is empty. ' + USAGE_HINT);
  return parts.map(parseEntry);
}

function isAllowed(list, host, port) {
  const h = normHost(host);
  return list.some((e) => e.host === h && (e.port === null || e.port === port));
}

/** "host:port" or "[v6]:port" from a CONNECT line; null when malformed. */
function parseAuthority(s) {
  const m = /^\[([0-9a-f:.]+)\]:(\d+)$/i.exec(s) || /^([^:\s]+):(\d+)$/.exec(s);
  if (!m) return null;
  const port = parsePort(m[2]);
  return Number.isNaN(port) ? null : { host: normHost(m[1]), port };
}

function safeHost(h) {
  return SAFE_LOG_HOST.test(h) ? h : '(unprintable)';
}

/**
 * Starts the proxy. allow: the list from parseAllowList.
 * Resolves to {port, url, close()}.
 */
function startEgressProxy(allow, opts = {}) {
  const log = opts.log || (() => {});
  const sockets = new Set();
  const server = http.createServer();

  const refuse = (host, port) => {
    log('zn run: egress refused ' + safeHost(host) + ':' + port + ' (not in --egress-allow)');
  };

  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
    s.on('error', () => {});
  });

  // Plain http:// requests: the client sends the absolute URL to the proxy.
  server.on('request', (req, res) => {
    let target;
    try { target = new URL(req.url); } catch (_) { target = null; }
    if (!target || target.protocol !== 'http:') {
      res.writeHead(400, { 'Content-Type': 'text/plain', Connection: 'close' });
      res.end('zn run egress proxy: send an absolute http:// URL, or CONNECT for https\n');
      return;
    }
    const host = normHost(target.hostname);
    const port = Number(target.port || 80);
    if (!isAllowed(allow, host, port)) {
      refuse(host, port);
      res.writeHead(403, { 'Content-Type': 'text/plain', Connection: 'close' });
      res.end('zn run egress proxy: host not in --egress-allow\n');
      return;
    }
    const headers = { ...req.headers };
    delete headers['proxy-connection'];
    delete headers['proxy-authorization'];
    // The Host header names the listed target, whatever the client sent.
    headers.host = target.host;
    const out = http.request({
      host, port, method: req.method, path: target.pathname + target.search, headers, agent: false,
      autoSelectFamily: true, timeout: IDLE_MS,
    }, (up) => {
      res.writeHead(up.statusCode, up.headers);
      up.pipe(res);
    });
    sockets.add(out);
    out.once('close', () => sockets.delete(out));
    out.on('timeout', () => out.destroy());
    out.on('error', () => {
      if (!res.headersSent) res.writeHead(502, { Connection: 'close' });
      res.end();
    });
    // A client that goes away (or stalls) must not leave the upstream open.
    res.on('close', () => { if (!out.destroyed) out.destroy(); });
    req.on('aborted', () => out.destroy());
    req.pipe(out);
  });

  // https:// (and any tunnel): CONNECT host:port.
  server.on('connect', (req, client, head) => {
    client.on('error', () => {});
    const auth = parseAuthority(req.url || '');
    if (!auth || !isAllowed(allow, auth.host, auth.port)) {
      if (auth) refuse(auth.host, auth.port);
      client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    const up = net.connect({ host: auth.host, port: auth.port, autoSelectFamily: true });
    up.setTimeout(IDLE_MS, () => up.destroy());
    client.setTimeout(IDLE_MS, () => client.destroy());
    up.on('error', () => {
      client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    });
    up.on('connect', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    client.on('close', () => up.destroy());
    up.on('close', () => client.destroy());
    up.on('error', () => {});
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        url: 'http://127.0.0.1:' + port,
        close: () => new Promise((done) => {
          server.close(() => done());
          for (const s of sockets) s.destroy();
        }),
      });
    });
  });
}

/** The child's environment with the proxy set and any caller proxy setting removed (NO_PROXY, npm and global-agent settings included). */
function egressEnv(env, proxyUrl) {
  const out = { ...env };
  for (const k of Object.keys(out)) {
    if (/^(http|https|all|no)_proxy$/i.test(k) || /^npm_config_(proxy|https_proxy|noproxy)$/i.test(k) || /^global_agent_/i.test(k)) delete out[k];
  }
  for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) out[k] = proxyUrl;
  out.NODE_USE_ENV_PROXY = '1';
  return out;
}

module.exports = { parseAllowList, parseEntry, isAllowed, parseAuthority, startEgressProxy, egressEnv };
