'use strict';

/**
 * zn-gate connect      turn on the optional cloud check (opt-in, you in your own terminal)
 * zn-gate disconnect   forget the key on this computer; asks first whether to revoke it on usezn.com too
 *
 * `connect` opens https://usezn.com/connect in the browser, where you create an
 * API key, then asks you to paste it into a hidden prompt here (no echo; never
 * an argument or an environment variable). The key is checked once against
 * https://api.usezn.com over TLS (a fixed host, nothing else is contacted) and
 * stored in the system keychain or the zn vault, never in a plain file.
 * See lib/cloud-key.js. Nothing here runs unless you run it, and hooks, the
 * shield and every other command stay local.
 */

const cloudKey = require('./cloud-key');

const CONNECT_URL = 'https://usezn.com/connect?source=cli&utm_source=cli';
// The only host this module talks to, and the routes on it.
const API_HOST = 'api.usezn.com';
// GET: 200 = a full-access key, 403 key_scope = a key limited to analyzing text, 401 = revoked or unknown.
const VERIFY_PATH = '/prod/usage';
// DELETE: 200 = this key is revoked, 401 = already revoked or unknown, 404/400 = not available, 500 = may still be valid.
const REVOKE_PATH = '/prod/keys/self';
const REQUEST_TIMEOUT_MS = 8000;
const MAX_BODY = 64 * 1024;

const USAGE_CONNECT = 'Usage: zn-gate connect [--reconnect]\n';
const USAGE_DISCONNECT = 'Usage: zn-gate disconnect [--revoke | --no-revoke]\n';

const STORE_WORDS = { keychain: 'your system keychain', vault: 'the zn vault' };

function defaults(io = {}) {
  return {
    out: io.out || ((s) => process.stdout.write(s)),
    err: io.err || ((s) => process.stderr.write(s)),
    tty: io.tty || require('./broker/tty'),
    https: io.https || require('https'),
    openBrowser: io.openBrowser || openBrowser,
    deps: io.deps,
    ttyIo: io.ttyIo || {},
  };
}

/** Open the URL with the system's own opener, by absolute path. Returns true when a helper started. */
function openBrowser(url) {
  const { spawnSync } = require('child_process');
  const fs = require('fs');
  let cmd = null;
  let args = [url];
  if (process.platform === 'darwin') cmd = '/usr/bin/open';
  else if (process.platform === 'win32') {
    cmd = require('./exe').systemPowerShell();
    args = ['-NoProfile', '-NonInteractive', '-Command', "Start-Process '" + url + "'"];
  } else {
    cmd = ['/usr/bin/xdg-open', '/bin/xdg-open', '/usr/local/bin/xdg-open'].find((p) => { try { return fs.statSync(p).isFile(); } catch (_) { return false; } }) || null;
  }
  if (!cmd) return false;
  try {
    const r = spawnSync(cmd, args, { stdio: 'ignore', timeout: 15000, windowsHide: true });
    return !r.error && r.status === 0;
  } catch (_) { return false; }
}

/** Text with the key (and anything shaped like one) removed. */
function scrub(text, key) {
  let s = String(text);
  if (key) s = s.split(key).join('[key]');
  return s.replace(/zn_[0-9a-f]{48}/g, '[key]');
}

/**
 * One HTTPS request to the fixed zn API host, with the key as a Bearer token.
 * Resolves {status, body} or {error}. Redirects are not followed, the
 * certificate is always verified, and the host cannot be changed by the caller.
 */
function request(h, method, path, key) {
  return new Promise((resolve) => {
    const why = cloudKey.tlsRefusal();
    if (why) { resolve({ error: why }); return; }
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let req;
    try {
      req = h.request({
        hostname: API_HOST,
        port: 443,
        path,
        method,
        headers: { Authorization: 'Bearer ' + key, Accept: 'application/json', 'User-Agent': 'zn-gate/' + version() + ' (connect)' },
        timeout: REQUEST_TIMEOUT_MS,
        rejectUnauthorized: true,
      }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { if (body.length < MAX_BODY) body += c; });
        res.on('end', () => finish({ status: res.statusCode, body }));
        res.on('error', (e) => finish({ error: scrub(e && e.message, key) }));
      });
    } catch (e) { finish({ error: scrub(e && e.message, key) }); return; }
    req.on('timeout', () => { req.destroy(); finish({ error: 'timed out' }); });
    req.on('error', (e) => finish({ error: scrub(e && (e.code || e.message), key) }));
    req.end();
  });
}

function version() {
  try { return require('../package.json').version; } catch (_) { return '0.0.0'; }
}

/**
 * What the server says about a key, from GET /prod/usage:
 *   'analyze'  403 {"error":"key_scope"}: a key that can only analyze text (the one connect accepts)
 *   'full'     200: a full-access key (refused)
 *   'rejected' 401: revoked, unknown or mistyped
 *   'failed'   anything else, or no answer: nothing is stored
 */
async function verifyKey(h, key) {
  const r = await request(h, 'GET', VERIFY_PATH, key);
  if (r.error) return { state: 'failed', detail: r.error };
  if (r.status === 200) return { state: 'full', detail: null };
  if (r.status === 401) return { state: 'rejected', detail: null };
  if (r.status === 403) {
    let code = null;
    try { code = JSON.parse(r.body).error; } catch (_) { /* not JSON */ }
    if (code === 'key_scope') return { state: 'analyze', detail: null };
  }
  return { state: 'failed', detail: 'HTTP ' + r.status };
}

function noStoreText() {
  return [
    'zn-gate will not keep the key in a plain file, and this computer has no system keychain',
    '(and the zn vault is not unlocked), so nothing was saved.',
    '',
    'To use the cloud check anyway, set the key in your own shell before starting your agent:',
    '  ZN_API_KEY=<your key> and ZN_CLOUD=1',
    'A key in ZN_API_KEY alone does nothing. Or run `zn unlock` first and then `zn-gate connect` again.',
    '',
  ].join('\n') + '\n';
}

async function connect(args, io) {
  const c = defaults(io);
  const rest = args.filter((a) => a !== '--reconnect');
  const reconnect = rest.length !== args.length;
  if (rest.length) {
    // A key must never travel as an argument (shell history, process list).
    const looksLikeKey = rest.some((a) => /zn_[A-Za-z0-9._-]{8,}/.test(a) || /^--?(key|api-key|token)\b/.test(a));
    c.err(looksLikeKey ? 'Never put the key on the command line. Run `zn-gate connect` and paste it at the hidden prompt.\n' : USAGE_CONNECT);
    return 2;
  }
  try { c.tty.requireHuman('zn-gate connect', c.ttyIo); } catch (e) {
    c.err(String(e.message) + '\n');
    return 1;
  }
  const marker = cloudKey.readMarker();
  if (marker && !reconnect) {
    c.out('Already connected: key ...' + (marker.last4 || '????') + ' is in ' + STORE_WORDS[marker.store] + '.\n'
      + 'Use `zn-gate connect --reconnect` to replace it, or `zn-gate disconnect` to remove it.\n');
    return 0;
  }
  const store = await cloudKey.availableStore(c.deps);
  if (!store) { c.out(noStoreText()); return 1; }

  c.out('zn-gate connect (optional)\n\n'
    + 'Right now zn-gate runs entirely on your computer and sends nothing.\n'
    + 'Connecting turns on an extra check: when you or your agent use the\n'
    + 'analyze_prompt tool, the text (with secrets hidden first) is also checked by\n'
    + 'usezn.com. Hooks and file/secret protection stay local and never use it.\n'
    + 'The key is kept in ' + STORE_WORDS[store] + ', never in a plain file.\n\n');
  if (!(await c.tty.confirm('Continue?', c.ttyIo))) {
    c.out('Nothing changed. zn-gate stays fully local.\n');
    return 1;
  }

  c.out('\nOpening ' + CONNECT_URL + ' in your browser...\n');
  if (!c.openBrowser(CONNECT_URL)) c.out('Could not open a browser. Open this address yourself:\n  ' + CONNECT_URL + '\n');
  c.out('Create a free account (or log in), create an analysis-only API key, and paste it here.\n');

  let key;
  try { key = (await c.tty.readHidden('API key (hidden): ', c.ttyIo)).trim(); } catch (e) {
    c.err('Cancelled. Nothing was saved.\n');
    return 1;
  }
  if (!cloudKey.looksLikeZnKey(key)) {
    c.err('That does not look like a zn API key (they start with zn_). Nothing was saved.\n');
    return 1;
  }

  const v = await verifyKey(c.https, key);
  if (v.state === 'rejected') {
    c.err('usezn.com did not accept this key (it may be revoked or mistyped). Nothing was saved.\n');
    return 1;
  }
  if (v.state === 'full') {
    c.err('This key can do more than analyze text, and zn-gate only accepts a key limited to analyzing. Create an analysis-only key on the connect page and paste that one: ' + CONNECT_URL + '\nNothing was saved.\n');
    return 1;
  }
  if (v.state !== 'analyze') {
    c.err('Could not verify the key with usezn.com (' + v.detail + '), so nothing was saved. Try again later.\n');
    return 1;
  }

  let where;
  try { where = await cloudKey.saveKey(key, c.deps); } catch (e) {
    if (e instanceof cloudKey.NoSecureStore || (e && e.code === 'ZN_NO_SECURE_STORE')) { c.out(noStoreText()); return 1; }
    c.err('Could not save the key: ' + scrub(e && e.message, key) + '. Nothing was kept.\n');
    return 1;
  }
  c.out('Key scope: analyze only. It cannot list or create keys; it can only revoke itself.\n');
  c.out('Saved in ' + STORE_WORDS[where] + '. Cloud check is ON for analyze_prompt. Key: ...' + cloudKey.last4(key) + '\n'
    + 'Turn it off any time: zn-gate disconnect\n'
    + 'Check what leaves your machine: zn-gate status\n');
  return 0;
}

const DASHBOARD = 'https://usezn.com/api-keys';

/**
 * Ask usezn.com to revoke the key it is sent: DELETE /prod/keys/self. Same fixed host, certificate
 * checks, environment refusals, no redirects, body cap and timeout as the other requests here.
 * Returns {state, detail}: 'revoked' (200), 'rejected' (401: already revoked or not valid),
 * 'unavailable' (404 or 400: the server cannot do it yet), 'maybe' (500: the key may still be valid),
 * 'failed' (no answer or anything else).
 */
async function revokeKey(h, key) {
  const r = await request(h, 'DELETE', REVOKE_PATH, key);
  if (r.error) return { state: 'failed', detail: r.error };
  if (r.status === 200) return { state: 'revoked', detail: null };
  if (r.status === 401) return { state: 'rejected', detail: null };
  if (r.status === 404 || r.status === 400) return { state: 'unavailable', detail: 'HTTP ' + r.status };
  if (r.status === 500) return { state: 'maybe', detail: 'HTTP 500' };
  return { state: 'failed', detail: 'HTTP ' + r.status };
}

// A key is named by its first 12 characters ("zn_" and 9 more), the same prefix the keys page on usezn.com shows.
function shown(key) { return key.slice(0, 12) + '...'; }

function revokeLine(res, key) {
  const k = shown(key);
  const link = ' Revoke it at ' + DASHBOARD + '.';
  switch (res.state) {
    case 'revoked': return { ok: true, text: 'Revoked key ' + k + ' on usezn.com: it no longer works.\n' };
    case 'rejected': return { ok: false, text: 'usezn.com did not accept key ' + k + ' (already revoked, or not valid), so nothing was revoked from here.' + link + '\n' };
    case 'unavailable': return { ok: false, text: 'usezn.com could not revoke key ' + k + ' from here (' + res.detail + '); it may still work.' + link + '\n' };
    case 'maybe': return { ok: false, text: 'usezn.com had an error (' + res.detail + '), so key ' + k + ' may still work.' + link + '\n' };
    default: return { ok: false, text: 'Could not reach usezn.com (' + scrub(res.detail, key) + '), so key ' + k + ' was not revoked.' + link + '\n' };
  }
}

async function disconnect(args, io) {
  const c = defaults(io);
  const flags = args.filter((a) => a === '--revoke' || a === '--no-revoke');
  if (flags.length !== args.length || new Set(flags).size > 1) { c.err(USAGE_DISCONNECT); return 2; }
  try { c.tty.requireHuman('zn-gate disconnect', c.ttyIo); } catch (e) {
    // Nothing is removed and nothing is revoked without a person at the terminal.
    c.err(String(e.message) + '\n'
      + 'Nothing was removed or revoked. To revoke the key yourself, use ' + DASHBOARD + '.\n');
    return 1;
  }
  const marker = cloudKey.readMarker();
  if (!marker) {
    c.out('Not connected. Nothing to remove.\n');
    return 0;
  }
  // The key is read only to revoke it. It is held in memory for this call and never printed.
  let stored = null;
  if (!flags.includes('--no-revoke')) {
    stored = await cloudKey.loadStoredKey(c.deps);
    if (!stored) {
      // Removing the local copy now would lose the only way to name and revoke this key from here.
      c.err('Could not read the saved key from ' + STORE_WORDS[marker.store] + ', so nothing was removed or revoked.'
        + (marker.store === 'vault' ? ' Run `zn unlock` and try again.' : '') + '\n'
        + 'Revoke the key at ' + DASHBOARD + ', or run `zn-gate disconnect --no-revoke` to only remove the local copy.\n');
      return 1;
    }
  }
  let revoke = false;
  if (stored) {
    revoke = flags.includes('--revoke')
      || await c.tty.confirm('Also revoke key ' + shown(stored.key) + ' on usezn.com, so it stops working everywhere?', c.ttyIo);
  }

  // The local copy goes first and in every case: a failed or interrupted call must not keep it.
  const del = await cloudKey.deleteKey(c.deps);
  let code = 0;
  if (!del.removed) {
    c.err('Could not remove the saved key from ' + STORE_WORDS[del.store] + ': ' + scrub(del.error && del.error.message, stored && stored.key)
      + (del.store === 'vault' ? '. Run `zn unlock`, then `zn-gate disconnect` again.' : '.') + '\n');
    code = 1;
  } else {
    c.out('Removed the saved key from ' + STORE_WORDS[del.store] + '. The cloud check is off; zn-gate runs only on your computer.\n');
  }

  if (revoke) {
    const line = revokeLine(await revokeKey(c.https, stored.key), stored.key);
    (line.ok ? c.out : c.err)(line.text);
    if (!line.ok) code = 1;
  } else if (del.removed) {
    c.out('The key itself still works until you revoke it. Revoke it at ' + DASHBOARD
      + (stored ? ' (it is listed as ' + shown(stored.key) + ').' : '.') + '\n');
  }
  stored = null;
  return code;
}

module.exports = { connect, disconnect, verifyKey, revokeKey, request, scrub, openBrowser, CONNECT_URL, API_HOST, VERIFY_PATH, REVOKE_PATH };
