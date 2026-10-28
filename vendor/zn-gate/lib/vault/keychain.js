'use strict';
/**
 * Where the age identity (the master key) lives.
 *
 *   macos       macOS Keychain, through /usr/bin/security
 *   windows     Windows Credential Manager (DPAPI-protected, per user),
 *               through CredRead/CredWrite called from PowerShell
 *   libsecret   Secret Service (GNOME Keyring, KWallet), through secret-tool
 *   passphrase  identity.age, encrypted with an age scrypt passphrase; for
 *               Linux without a desktop session, WSL and CI
 *
 * The identity never travels through command-line arguments or environment
 * variables: it goes to the helper on stdin and comes back on stdout.
 * keychain.json records which backend holds it and the matching recipient
 * (public key), so a wrong or missing identity is detected before use.
 *
 * Overrides (tests and unusual setups):
 *   ZN_KEYCHAIN_BACKEND   force a backend
 *   ZN_KEYCHAIN_SERVICE   service / target name (default "zn-vault")
 *   ZN_KEYCHAIN_PATH      macOS: keychain file to use instead of the default
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const store = require('./store');
const { CODES, znError } = require('../errors');
const messages = require('../messages');

const BACKENDS = ['macos', 'windows', 'libsecret', 'passphrase'];
const ACCOUNT = 'age-identity';
const SAFE_NAME = /^[A-Za-z0-9._-]{1,64}$/;
const DEFAULT_WORK_FACTOR = 18;
const MIN_PASSPHRASE = 12;

function service() {
  const s = process.env.ZN_KEYCHAIN_SERVICE || 'zn-vault';
  if (!SAFE_NAME.test(s)) throw znError(CODES.POLICY_DENIED, 'invalid ZN_KEYCHAIN_SERVICE. Next step: fix or remove this setting, or, if you are an agent, ask the user to do it.');
  return s;
}

/* The entry a backend reads and writes: service (target) name, account and label.
 * Default: the vault identity. `zn-gate connect` keeps its API key in a second slot (CLOUD_SLOT). */
function defaultSlot() {
  return { service: service(), account: ACCOUNT, label: 'zn-vault-identity' };
}
const CLOUD_SLOT = Object.freeze({ service: 'zn-cloud', account: 'cloud-api-key', label: 'zn-gate-cloud-api-key' });

/* Keychain helpers run by absolute path, never looked up on PATH: a
 * planted `secret-tool` or `powershell.exe` earlier on PATH would see the
 * identity. */
const SECRET_TOOL_DIRS = ['/usr/bin', '/bin', '/usr/local/bin', '/run/current-system/sw/bin'];

function secretToolPath() {
  for (const d of SECRET_TOOL_DIRS) {
    const p = path.join(d, 'secret-tool');
    try { if (fs.statSync(p).isFile()) return p; } catch (err) { /* next */ }
  }
  return null;
}

/* The system PowerShell only (never SystemRoot or PATH, which the caller controls): it receives the vault identity. */
function powershellPath() {
  return require('../exe').systemPowerShell();
}

function detectBackend() {
  const forced = process.env.ZN_KEYCHAIN_BACKEND;
  if (forced) {
    if (!BACKENDS.includes(forced)) throw znError(CODES.POLICY_DENIED, 'unknown keychain backend: ' + forced + '. Next step: set a backend this system supports, or remove the setting, or, if you are an agent, ask the user to do it.');
    return forced;
  }
  if (process.platform === 'darwin' && fs.existsSync('/usr/bin/security')) return 'macos';
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'linux' && process.env.DBUS_SESSION_BUS_ADDRESS && secretToolPath()) return 'libsecret';
  return 'passphrase';
}

function run(cmd, args, input, extraEnv) {
  const res = spawnSync(cmd, args, {
    input: input === undefined ? '' : input,
    encoding: 'utf8',
    timeout: 60000,
    windowsHide: true,
    env: extraEnv && extraEnv.PSModulePath ? require('../exe').psEnv(cmd, process.env, extraEnv) : Object.assign({}, process.env, extraEnv || {}),
    maxBuffer: 1024 * 1024,
  });
  if (res.error) throw znError(CODES.LOCKED, messages.keychainHelperFailed(cmd + ' (' + res.error.code + ')'));
  return res;
}

/* ------------------------------------------------------------------ */
/* macOS Keychain                                                      */
/* ------------------------------------------------------------------ */

function macKeychainArgs() {
  const kc = process.env.ZN_KEYCHAIN_PATH;
  return kc ? [kc] : [];
}

const macos = {
  store(identity, slot) {
    const sl = slot || defaultSlot();
    // `security -i` reads the command from stdin, so the identity never
    // shows up in the process list.
    const kc = process.env.ZN_KEYCHAIN_PATH;
    if (kc && /\s/.test(kc)) throw znError(CODES.POLICY_DENIED, 'ZN_KEYCHAIN_PATH must not contain spaces. Next step: choose a folder path without spaces, or, if you are an agent, ask the user to do it.');
    const line = ['add-generic-password', '-U', '-s', sl.service, '-a', sl.account, '-l', sl.label || 'zn-vault-identity', '-w', identity].concat(kc ? [kc] : []).join(' ') + '\n';
    const res = run('/usr/bin/security', ['-i'], line);
    if (res.status !== 0) throw znError(CODES.LOCKED, messages.keychainProblem('macos', 'save', { slotIsVault: !slot, detail: 'security exit ' + res.status }));
  },
  load(slot) {
    const sl = slot || defaultSlot();
    const res = run('/usr/bin/security', ['find-generic-password', '-s', sl.service, '-a', sl.account, '-w'].concat(macKeychainArgs()));
    if (res.status === 44) return null; // errSecItemNotFound
    if (res.status !== 0) throw znError(CODES.LOCKED, messages.keychainProblem('macos', 'read', { slotIsVault: !slot, detail: 'security exit ' + res.status }));
    return res.stdout.trim();
  },
  remove(slot) {
    const sl = slot || defaultSlot();
    const res = run('/usr/bin/security', ['delete-generic-password', '-s', sl.service, '-a', sl.account].concat(macKeychainArgs()));
    return res.status === 0;
  },
};

/* ------------------------------------------------------------------ */
/* Windows Credential Manager                                          */
/* ------------------------------------------------------------------ */

const WIN_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$src = @'",
  'using System;',
  'using System.Runtime.InteropServices;',
  'using System.Text;',
  'public static class ZnCred {',
  '  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]',
  '  public struct CREDENTIAL {',
  '    public UInt32 Flags; public UInt32 Type; public string TargetName; public string Comment;',
  '    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;',
  '    public UInt32 CredentialBlobSize; public IntPtr CredentialBlob; public UInt32 Persist;',
  '    public UInt32 AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;',
  '  }',
  '  [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]',
  '  static extern bool CredWrite(ref CREDENTIAL c, UInt32 flags);',
  '  [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]',
  '  static extern bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr c);',
  '  [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]',
  '  static extern bool CredDelete(string target, UInt32 type, UInt32 flags);',
  '  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);',
  '  public static void Write(string target, string user, string secret) {',
  '    byte[] blob = Encoding.UTF8.GetBytes(secret);',
  '    CREDENTIAL c = new CREDENTIAL();',
  '    c.Type = 1; c.TargetName = target; c.UserName = user; c.Persist = 2;',
  '    c.CredentialBlobSize = (UInt32)blob.Length;',
  '    c.CredentialBlob = Marshal.AllocHGlobal(blob.Length);',
  '    try {',
  '      Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length);',
  '      if (!CredWrite(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());',
  '    } finally {',
  '      for (int i = 0; i < blob.Length; i++) Marshal.WriteByte(c.CredentialBlob, i, 0);',
  '      Marshal.FreeHGlobal(c.CredentialBlob);',
  '      Array.Clear(blob, 0, blob.Length);',
  '    }',
  '  }',
  '  public static string Read(string target) {',
  '    IntPtr p;',
  '    if (!CredRead(target, 1, 0, out p)) {',
  '      int e = Marshal.GetLastWin32Error();',
  '      if (e == 1168) return null;',
  '      throw new System.ComponentModel.Win32Exception(e);',
  '    }',
  '    try {',
  '      CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));',
  '      byte[] blob = new byte[c.CredentialBlobSize];',
  '      Marshal.Copy(c.CredentialBlob, blob, 0, blob.Length);',
  '      return Encoding.UTF8.GetString(blob);',
  '    } finally { CredFree(p); }',
  '  }',
  '  public static bool Delete(string target) {',
  '    if (CredDelete(target, 1, 0)) return true;',
  '    int e = Marshal.GetLastWin32Error();',
  '    if (e == 1168) return false;',
  '    throw new System.ComponentModel.Win32Exception(e);',
  '  }',
  '}',
  "'@",
  'Add-Type -TypeDefinition $src -Language CSharp',
  '$t = $env:ZN_CRED_TARGET',
  'switch ($env:ZN_CRED_OP) {',
  "  'write'  { $s = [Console]::In.ReadToEnd(); [ZnCred]::Write($t, $env:USERNAME, $s.Trim()); [Console]::Out.Write('ok') }",
  "  'read'   { $v = [ZnCred]::Read($t); if ($null -eq $v) { exit 3 } else { [Console]::Out.Write($v) } }",
  "  'delete' { if ([ZnCred]::Delete($t)) { [Console]::Out.Write('ok') } else { exit 3 } }",
  '}',
].join('\r\n');

function winCred(op, input, slot) {
  const sl = slot || defaultSlot();
  const ps = powershellPath();
  if (!ps) {
    throw znError(CODES.LOCKED, messages.powershellMissing());
  }
  const encoded = Buffer.from(WIN_SCRIPT, 'utf16le').toString('base64');
  return run(ps, ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], input,
    { PSModulePath: require('../exe').systemPsModulePath(ps), ZN_CRED_OP: op, ZN_CRED_TARGET: sl.service + ':' + sl.account });
}

const windows = {
  store(identity, slot) {
    const res = winCred('write', identity, slot);
    if (res.status !== 0 || res.stdout.trim() !== 'ok') throw znError(CODES.LOCKED, messages.keychainProblem('windows', 'save', { slotIsVault: !slot, detail: 'exit ' + res.status }));
  },
  load(slot) {
    const res = winCred('read', undefined, slot);
    if (res.status === 3) return null;
    if (res.status !== 0) throw znError(CODES.LOCKED, messages.keychainProblem('windows', 'read', { slotIsVault: !slot, detail: 'exit ' + res.status }));
    return res.stdout.trim();
  },
  remove(slot) {
    return winCred('delete', undefined, slot).status === 0;
  },
};

/* ------------------------------------------------------------------ */
/* libsecret (Secret Service)                                          */
/* ------------------------------------------------------------------ */

function secretTool() {
  const p = secretToolPath();
  if (!p) throw znError(CODES.LOCKED, messages.secretToolMissing());
  return p;
}

const libsecret = {
  store(identity, slot) {
    const sl = slot || defaultSlot();
    const res = run(secretTool(), ['store', '--label=' + (slot ? 'zn-gate cloud API key' : 'zn vault identity'), 'service', sl.service, 'account', sl.account], identity);
    if (res.status !== 0) throw znError(CODES.LOCKED, messages.keychainProblem('libsecret', 'save', { slotIsVault: !slot, detail: 'secret-tool exit ' + res.status }));
  },
  load(slot) {
    const sl = slot || defaultSlot();
    const res = run(secretTool(), ['lookup', 'service', sl.service, 'account', sl.account]);
    const out = (res.stdout || '').trim();
    if (res.status !== 0 && !out) {
      if (res.status === 1) return null;
      throw znError(CODES.LOCKED, messages.keychainProblem('libsecret', 'read', { slotIsVault: !slot, detail: 'secret-tool exit ' + res.status }));
    }
    return out || null;
  },
  remove(slot) {
    const sl = slot || defaultSlot();
    return run(secretTool(), ['clear', 'service', sl.service, 'account', sl.account]).status === 0;
  },
};

const NATIVE = { macos, windows, libsecret };

/* ------------------------------------------------------------------ */
/* Metadata                                                            */
/* ------------------------------------------------------------------ */

function readMeta(opts) {
  const buf = store.readPrivateFile(store.paths(opts).metaFile);
  if (buf === null) return null;
  let meta = null;
  try { meta = JSON.parse(buf.toString('utf8')); } catch (err) { meta = null; }
  if (!meta || !BACKENDS.includes(meta.backend) || !/^age1[0-9a-z]+$/.test(meta.recipient || '')) {
    throw znError(CODES.LOCKED, require('../messages').vaultDamaged('keychain.json',
      'is corrupted (it records the keychain backend and the public key)'));
  }
  return meta;
}

function writeMeta(meta, opts) {
  store.writePrivateFile(store.paths(opts).metaFile, JSON.stringify(meta, null, 2) + '\n');
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

function checkPassphrase(p) {
  if (typeof p !== 'string' || p.length < MIN_PASSPHRASE) {
    throw znError(CODES.POLICY_DENIED, 'passphrase must be at least ' + MIN_PASSPHRASE + ' characters. Next step: choose a longer passphrase.');
  }
}

/**
 * storeIdentity(identity, {backend, passphrase, workFactor, home})
 * Saves the identity in the chosen backend.
 */
async function storeIdentity(identity, opts) {
  const o = opts || {};
  const backend = o.backend || detectBackend();
  if (!/^AGE-SECRET-KEY-1[0-9A-Z]+$/.test(identity || '')) throw znError(CODES.POLICY_DENIED, 'not an age X25519 identity. Next step: paste the full identity line, which starts with AGE-SECRET-KEY-1.');
  if (backend === 'passphrase') {
    checkPassphrase(o.passphrase);
    store.ensureLayout(o);
    const ct = await store.encryptWithPassphrase(o.passphrase, identity, o.workFactor || DEFAULT_WORK_FACTOR);
    store.writePrivateFile(store.paths(o).identityFile, Buffer.from(ct));
    return backend;
  }
  NATIVE[backend].store(identity);
  return backend;
}

/**
 * loadIdentity({backend, passphrase, home}) -> identity
 * Throws ZN_NOT_FOUND when the vault was never initialised and ZN_LOCKED
 * when the backend cannot produce a matching identity.
 */
async function loadIdentity(opts) {
  const o = opts || {};
  const meta = readMeta(o);
  if (!meta) throw znError(CODES.NOT_FOUND, 'vault not initialised. Next step: run zn unlock once in your own terminal to create it, or, if you are an agent, ask the user to do it.');
  const backend = o.backend || meta.backend;
  let identity = null;
  if (backend === 'passphrase') {
    if (typeof o.passphrase !== 'string') throw znError(CODES.LOCKED, 'passphrase required');
    const buf = store.readPrivateFile(store.paths(o).identityFile);
    if (buf === null) throw znError(CODES.NOT_FOUND, 'identity.age missing. Next step: restore the vault files from a backup; do not create a new vault over an existing one.');
    try {
      identity = await store.decryptWithPassphrase(o.passphrase, new Uint8Array(buf));
    } catch (err) {
      // age reports a wrong passphrase as "no identity matched"; a damaged file fails earlier
      // (bad header, bad tag). Only the first is a passphrase failure, so only it sets `reason`.
      if (err && /no identity matched/i.test(String(err.message))) {
        const e = znError(CODES.LOCKED, 'wrong passphrase, or vault file identity.age is corrupted');
        e.reason = WRONG_PASSPHRASE;
        throw e;
      }
      throw znError(CODES.LOCKED, require('../messages').vaultDamaged('identity.age',
        'looks damaged, so it cannot be opened with any passphrase', err && err.message));
    }
  } else {
    identity = NATIVE[backend].load();
    if (identity === null) throw znError(CODES.NOT_FOUND, 'identity not found in the ' + backend + ' keychain. Next step: sign in to the user account that created the vault, or restore the keychain entry from a backup.');
  }
  const recipient = await store.recipientOf(identity);
  if (recipient !== meta.recipient) throw znError(CODES.LOCKED, 'identity does not match this vault');
  return identity;
}

/**
 * initIdentity({backend, passphrase, workFactor, home}) -> {backend, recipient, identity}
 * Creates a new X25519 identity and stores it. Refuses to overwrite.
 */
async function initIdentity(opts) {
  const o = opts || {};
  if (readMeta(o)) throw znError(CODES.POLICY_DENIED, 'vault already initialised. Next step: nothing to do; the vault already exists.');
  const backend = o.backend || detectBackend();
  store.ensureLayout(o);
  const { identity, recipient } = await store.generateIdentity();
  await storeIdentity(identity, Object.assign({}, o, { backend }));
  // Read it back before recording the vault: a keychain that silently
  // drops the item must fail here, not after secrets were encrypted to it.
  if (backend !== 'passphrase') {
    const back = NATIVE[backend].load();
    if (back !== identity) throw znError(CODES.LOCKED, messages.keychainLostKey(backend));
  }
  writeMeta({ v: 1, backend, recipient, created: new Date().toISOString() }, o);
  return { backend, recipient, identity };
}

/**
 * Remove the identity from its backend (the vault becomes unreadable).
 * Safe default: the OS keychain slot does not depend on ZN_HOME, so it may
 * belong to another vault. Without keychain.json for this home and without an
 * explicit backend, nothing is deleted.
 * Returns {deleted, backend} or {deleted: false, reason}.
 */
async function deleteIdentity(opts) {
  const o = opts || {};
  const meta = readMeta(o);
  const backend = o.backend || (meta && meta.backend);
  if (!backend) {
    return { deleted: false, reason: 'no keychain.json in this vault and no backend given, so nothing was deleted (the keychain slot may belong to another vault). Next step: pass the backend explicitly.' };
  }
  if (backend === 'passphrase') {
    try { fs.unlinkSync(store.paths(o).identityFile); } catch (err) { /* ignore */ }
  } else {
    NATIVE[backend].remove();
  }
  try { fs.unlinkSync(store.paths(o).metaFile); } catch (err) { /* ignore */ }
  return { deleted: true, backend };
}

/** `err.reason` of a ZN_LOCKED error that came from a wrong passphrase (and from nothing else). */
const WRONG_PASSPHRASE = 'wrong_passphrase';

module.exports = {
  WRONG_PASSPHRASE,
  BACKENDS,
  detectBackend,
  storeIdentity,
  loadIdentity,
  initIdentity,
  deleteIdentity,
  readMeta,
  MIN_PASSPHRASE,
  DEFAULT_WORK_FACTOR,
  CLOUD_SLOT,
  _native: NATIVE,
};
