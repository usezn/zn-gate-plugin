'use strict';

/**
 * Where the zn API key lives once `zn-gate connect` has stored it, and how
 * the rest of zn-gate finds it.
 *
 * The key is kept in exactly one of two places, never in a plain file:
 *
 *   keychain  the system keychain (macOS Keychain, Windows Credential Manager,
 *             Secret Service), under the service name `zn-cloud`
 *   vault     the zn vault (age-encrypted), as the secret ZN_CLOUD_API_KEY,
 *             only when the system has no keychain and the vault is unlocked
 *
 * With neither, nothing is stored and the person is told about ZN_API_KEY.
 *
 * ~/.zn/config.json holds only a marker under "cloud": where the key is and
 * when it was connected, plus its last four characters for display. It never
 * holds the key. The marker is what makes `connect` an explicit opt-in: a key
 * in ZN_API_KEY alone still enables nothing (see isCloudEnabled in client.js).
 *
 * This module must not require ./client (client.js requires it) and is never
 * loaded by the agent hooks.
 */

const fs = require('fs');
const path = require('path');

const KEY_RE = /^[A-Za-z0-9._-]{16,256}$/;
const VAULT_SECRET = 'ZN_CLOUD_API_KEY';
// The vault resolves the cloud key only for a request that says this: the hooks and the secrets broker never do.
const RESOLVE_PURPOSE = 'zn-cloud-key';
const STORES = ['keychain', 'vault'];
const TLS_REFUSAL = 'NODE_TLS_REJECT_UNAUTHORIZED=0 is set, so zn-gate will not send the saved key over a connection whose certificate is not checked';

/**
 * Why a saved key must not be sent now, or null. The key goes only over a connection checked against the
 * system's certificate authorities: not while the environment turns checking off or adds authorities or code
 * (NODE_TLS_REJECT_UNAUTHORIZED=0, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, NODE_DEBUG, or NODE_OPTIONS with --require, --import,
 * -r, --use-openssl-ca, --tls-keylog or --inspect*). A key given with --key or ZN_API_KEY is the person's own choice and is not held back.
 */
function tlsRefusal(env = process.env) {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0') return TLS_REFUSAL;
  for (const name of ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE']) {
    if (env[name]) return name + ' is set, so zn-gate will not send the saved key: the connection could trust other certificate authorities';
  }
  if (env.OPENSSL_CONF) return 'OPENSSL_CONF is set, so zn-gate will not send the saved key: the TLS settings could be changed';
  // Node prints the request headers, Authorization included, when NODE_DEBUG names http, https, tls or net: any value is refused.
  if (typeof env.NODE_DEBUG === 'string' && env.NODE_DEBUG.trim()) {
    return 'NODE_DEBUG is set, so zn-gate will not use the saved key: Node could print it';
  }
  if (nodeOptionsList(env.NODE_OPTIONS).some((t) => RISKY_NODE_OPTION.test(optionName(t)))) {
    return 'NODE_OPTIONS loads code, changes the TLS settings or opens a debugger, so zn-gate will not send the saved key';
  }
  return null;
}

// Options that load code, change the certificates or TLS settings Node uses, write the TLS session keys to a file,
// or open a debugger that can read the key from memory.
const RISKY_NODE_OPTION = /^(?:-r|--require|--import|--loader|--experimental-loader|--use-openssl-ca|--openssl-config|--openssl-shared-config|--tls-keylog|--inspect(?:-brk|-port|-wait)?)(?:=|$)/;

/** Node reads `_` in the name of a `--option` like `-` (--tls_keylog is --tls-keylog); the value after `=` is left alone. */
function optionName(token) {
  if (!token.startsWith('--')) return token;
  const eq = token.indexOf('=');
  return (eq < 0 ? token : token.slice(0, eq)).replace(/_/g, '-') + (eq < 0 ? '' : token.slice(eq));
}

/** NODE_OPTIONS split the way Node does: on spaces outside quotes, quotes removed (a backslash escapes inside double quotes). */
function nodeOptionsList(value) {
  const out = [];
  let cur = '';
  let inQuote = null;
  let has = false;
  const s = String(value || '');
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inQuote) {
      if (ch === '\\' && inQuote === '"' && i + 1 < s.length) { cur += s[++i]; continue; }
      if (ch === inQuote) { inQuote = null; continue; }
      cur += ch;
    } else if (ch === '"' || ch === "'") { inQuote = ch; has = true; }
    else if (/\s/.test(ch)) { if (has || cur) out.push(cur); cur = ''; has = false; }
    else { cur += ch; has = true; }
  }
  if (has || cur) out.push(cur);
  return out;
}

/**
 * A usable API key, or null. zn keys and tokens are letters, digits, `_`,
 * `-` and `.` only; anything else counts as unset: blank, too short, or a
 * placeholder a launcher did not expand (for example a plugin option left
 * empty, `${user_config.api_key}`, or `%ZN_API_KEY%`). Sending text to the
 * cloud with such a value would only get a 401.
 */
function usableApiKey(value) {
  if (typeof value !== 'string') return null;
  const k = value.trim();
  return KEY_RE.test(k) ? k : null;
}

/** The shape zn issues: `zn_` and more. `connect` refuses anything else. */
function looksLikeZnKey(value) {
  const k = usableApiKey(value);
  return Boolean(k && k.startsWith('zn_') && k.length > 8);
}

function last4(key) {
  return typeof key === 'string' && key.length >= 8 ? key.slice(-4) : null;
}

/* ------------------------------ marker ------------------------------ */

function znHome() {
  if (process.env.ZN_HOME) return path.resolve(process.env.ZN_HOME);
  return path.join(require('os').homedir(), '.zn');
}

function configFile() {
  return path.join(znHome(), 'config.json');
}

function readConfig() {
  try { return JSON.parse(fs.readFileSync(configFile(), 'utf8')) || {}; } catch (_) { return {}; }
}

function writeConfig(cfg) {
  const file = configFile();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** {store, connectedAt, last4} when `connect` stored a key, else null. Never the key. */
function readMarker() {
  const c = readConfig().cloud;
  if (!c || typeof c !== 'object' || !STORES.includes(c.store)) return null;
  return {
    store: c.store,
    connectedAt: typeof c.connectedAt === 'string' ? c.connectedAt : null,
    last4: typeof c.last4 === 'string' && /^[A-Za-z0-9._-]{4}$/.test(c.last4) ? c.last4 : null,
  };
}

function writeMarker(marker) {
  const cfg = readConfig();
  cfg.cloud = { store: marker.store, connectedAt: marker.connectedAt || new Date().toISOString(), last4: marker.last4 || undefined };
  writeConfig(cfg);
}

function clearMarker() {
  const cfg = readConfig();
  if (!('cloud' in cfg)) return;
  delete cfg.cloud;
  writeConfig(cfg);
}

/** True when `zn-gate connect` has stored a key (a cheap file read; no keychain access). */
function isConnected() {
  return readMarker() !== null;
}

/* ------------------------------ stores ------------------------------ */

let testDeps = null;
/** Tests only: replace the keychain and vault backends. Pass null to restore. */
function _use(deps) { testDeps = deps; }

/** The native keychain, or null when this system has none (Linux without a desktop session, WSL, CI). */
function nativeKeychain(deps) {
  const d = deps || testDeps;
  if (d && 'native' in d) return d.native;
  try {
    const kc = require('./vault/keychain');
    const name = kc.detectBackend();
    if (name === 'passphrase') return null;
    const impl = kc._native[name];
    return impl ? { name, impl, slot: kc.CLOUD_SLOT } : null;
  } catch (_) { return null; }
}

function vaultClient(deps) {
  const d = deps || testDeps;
  return (d && d.vault) || require('./vault/client');
}

async function vaultUnlocked(deps) {
  try { return Boolean(await vaultClient(deps).isUnlocked()); } catch (_) { return false; }
}

/** Where a new key could be kept: 'keychain', 'vault' or null. */
async function availableStore(deps) {
  if (nativeKeychain(deps)) return 'keychain';
  if (await vaultUnlocked(deps)) return 'vault';
  return null;
}

class NoSecureStore extends Error {
  constructor() {
    super('there is no secure place to keep the key on this computer');
    this.code = 'ZN_NO_SECURE_STORE';
  }
}

/** Store the key and record the marker. Returns the store used. Throws NoSecureStore or the store's error. */
async function saveKey(key, deps) {
  if (!usableApiKey(key)) throw new Error('not a usable API key');
  const store = await availableStore(deps);
  if (!store) throw new NoSecureStore();
  if (store === 'keychain') {
    const n = nativeKeychain(deps);
    n.impl.store(key, n.slot);
    // Read it back: a keychain that silently drops the item must fail here, not later.
    if (n.impl.load(n.slot) !== key) {
      try { n.impl.remove(n.slot); } catch (_) { /* nothing to undo */ }
      throw new Error('the system keychain did not return the stored key');
    }
  } else {
    await vaultClient(deps).setSecret(VAULT_SECRET, key, { mode: 'proxy', allowHosts: ['api.usezn.com'], source: 'local' });
  }
  writeMarker({ store, last4: last4(key) });
  return store;
}

/**
 * The marker must prove that `connect` wrote it: it carries the last four characters of the key it stored, and
 * the stored key must end the same way. A marker written by hand cannot know them, and without a matching stored
 * key it turns nothing on. (Not a secret: four characters, shown by `status`.)
 */
function provesMarker(marker, key) {
  return Boolean(marker.last4) && marker.last4 === last4(key);
}

/** The stored key {key, store}, or null (nothing stored, keychain empty, vault locked). Never throws. */
async function loadStoredKey(deps) {
  const m = readMarker();
  if (!m) return null;
  try {
    if (m.store === 'keychain') {
      const n = nativeKeychain(deps);
      const v = n ? usableApiKey(n.impl.load(n.slot)) : null;
      return v && provesMarker(m, v) ? { key: v, store: 'keychain' } : null;
    }
    const raw = await vaultClient(deps).resolve(process.cwd(), '__ZN_' + VAULT_SECRET + '__', { purpose: RESOLVE_PURPOSE });
    const v = usableApiKey(raw);
    return v && provesMarker(m, v) ? { key: v, store: 'vault' } : null;
  } catch (_) {
    return null;
  }
}

/**
 * Delete the local copy and the marker. Returns {removed: bool, store, error?}.
 * When the vault is locked the secret cannot be removed: the marker stays so a
 * second try after `zn unlock` still finds it.
 */
async function deleteKey(deps) {
  const m = readMarker();
  if (!m) return { removed: false, store: null };
  try {
    if (m.store === 'keychain') {
      const n = nativeKeychain(deps);
      if (!n) return { removed: false, store: m.store, error: new Error('the system keychain is not available here, so the key could not be removed') };
      n.impl.remove(n.slot);
      // remove() can fail without throwing: only a keychain that no longer returns the key counts.
      if (n.impl.load(n.slot)) return { removed: false, store: m.store, error: new Error('the key is still in the system keychain') };
    } else {
      await vaultClient(deps).removeSecret(VAULT_SECRET);
    }
  } catch (err) {
    const missing = err && err.code === 'ZN_NOT_FOUND';
    if (!missing) return { removed: false, store: m.store, error: err };
  }
  clearMarker();
  return { removed: true, store: m.store };
}

/**
 * The key to use and where it came from, or null.
 * Order: --key / ZN_API_KEY first, then the key `connect` stored.
 * source: 'flag' | 'environment' | 'keychain' | 'vault'.
 */
async function resolveApiKey(options = {}, deps) {
  const given = usableApiKey(options.apiKey || process.env.ZN_API_KEY);
  if (given) {
    const fromEnv = given === usableApiKey(process.env.ZN_API_KEY);
    return { key: given, source: fromEnv ? 'environment' : 'flag' };
  }
  const stored = await loadStoredKey(deps);
  return stored ? { key: stored.key, source: stored.store } : null;
}

module.exports = {
  usableApiKey,
  looksLikeZnKey,
  last4,
  readMarker,
  isConnected,
  availableStore,
  saveKey,
  loadStoredKey,
  deleteKey,
  resolveApiKey,
  NoSecureStore,
  TLS_REFUSAL,
  tlsRefusal,
  VAULT_SECRET,
  RESOLVE_PURPOSE,
  _use,
};
