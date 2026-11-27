'use strict';

/**
 * A `lookup` function for https.request whose name resolution ends within a time budget.
 *
 * The default lookup (dns.lookup, getaddrinfo in the threadpool) cannot be cancelled and keeps the process alive
 * until the system resolver gives up: about 20 s on a network that silently drops traffic, whatever the request
 * timeout says. Here the name is resolved with a dns.Resolver, whose queries are cancelled at the deadline, so the
 * call fails on time and the process can exit.
 *
 *   1. An entry in the hosts file wins, as it does with getaddrinfo.
 *   2. The system DNS servers are asked for A and AAAA (tries: 1, plus a timer that cancels them).
 *   3. If the servers answer "no such name" (not a timeout), the system resolver is tried for what is left of
 *      the budget, for setups where names only resolve through NSS.
 * A timeout in step 2 is final: it is the case this module exists for.
 */

const dns = require('dns');
const fs = require('fs');
const net = require('net');
const path = require('path');

function hostsPath() {
  if (process.platform === 'win32') return path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts');
  return '/etc/hosts';
}

/** Addresses the hosts file gives for `name`, or []. */
function hostsEntries(name, file) {
  let text;
  try { text = fs.readFileSync(file || hostsPath(), 'utf8'); } catch (_) { return []; }
  const want = String(name).toLowerCase();
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const fam = net.isIP(parts[0]);
    if (fam && parts.slice(1).some((h) => h.toLowerCase() === want)) out.push({ address: parts[0], family: fam });
  }
  return out;
}

function timeoutError(host) {
  const err = new Error('DNS lookup timed out for ' + host);
  err.code = 'ETIMEDOUT';
  err.syscall = 'getaddrinfo';
  err.hostname = host;
  return err;
}

/**
 * @param {number} budgetMs total time for the resolution
 * @param {object} [deps] test hooks: {Resolver, lookup, hostsFile}
 */
function deadlineLookup(budgetMs, deps = {}) {
  const Resolver = deps.Resolver || dns.Resolver;
  const sysLookup = deps.lookup || dns.lookup;
  return function lookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    options = typeof options === 'number' ? { family: options } : (options || {});
    const family = options.family === 'IPv4' ? 4 : options.family === 'IPv6' ? 6 : (options.family || 0);
    const started = Date.now();
    let settled = false;
    let timer = null;
    let resolver = null;
    const finish = (err, list) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (err) return callback(err);
      if (options.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    };
    const left = () => Math.max(0, budgetMs - (Date.now() - started));
    const fail = () => {
      if (resolver) { try { resolver.cancel(); } catch (_) { /* nothing left to cancel */ } }
      finish(timeoutError(hostname));
    };

    const ip = net.isIP(hostname);
    if (ip) { finish(null, [{ address: hostname, family: ip }]); return; }

    const pick = (list) => list.filter((e) => !family || e.family === family);
    const local = pick(hostsEntries(hostname, deps.hostsFile));
    if (local.length) { finish(null, local); return; }

    timer = setTimeout(fail, budgetMs);

    const viaSystem = (cause) => {
      if (settled) return;
      sysLookup(hostname, { ...options, all: true }, (err, list) => {
        if (settled) return;
        if (err) return finish(err.code === 'ENOTFOUND' && cause ? cause : err);
        finish(null, list);
      });
    };

    const a = [];
    const aaaa = [];
    let pending = 0;
    let timedOut = false;
    let lastErr = null;
    const done = () => {
      if (settled || --pending > 0) return;
      const found = pick(a.concat(aaaa));
      if (found.length) return finish(null, found);
      if (timedOut) return finish(timeoutError(hostname));
      if (left() <= 0) return fail();
      viaSystem(lastErr);
    };
    const query = (kind, store, fam) => {
      if (family && family !== fam) return;
      pending++;
      resolver[kind](hostname, (err, addrs) => {
        if (err) {
          if (err.code === 'ETIMEOUT' || err.code === 'ETIMEDOUT' || err.code === 'ECANCELLED') timedOut = true;
          else lastErr = lastErr || err;
        } else store.push(...addrs.map((address) => ({ address, family: fam })));
        done();
      });
    };
    try {
      resolver = new Resolver({ timeout: Math.max(200, budgetMs), tries: 1 });
    } catch (_) { viaSystem(null); return; }
    query('resolve4', a, 4);
    query('resolve6', aaaa, 6);
    if (pending === 0) viaSystem(null);
  };
}

module.exports = { deadlineLookup, hostsEntries };
