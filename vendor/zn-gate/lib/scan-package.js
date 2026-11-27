'use strict';
/**
 * `zn scan --package <name>[@version]`: download an npm package from the registry and unpack it into a
 * fresh temporary folder, so that the scan and the agent-config audit can read its files.
 *
 * Nothing in the package is run. There is no install, no lifecycle script and no require of its files:
 * the registry is read with plain HTTPS GET requests, the tarball is checked against the checksum the
 * registry gave, and the archive is unpacked by the code below (regular files and folders only; links,
 * devices and paths that leave the folder are refused; a file that cannot be written is reported, and the
 * scan is then incomplete). The tarball must come from the registry's own address, and redirects (at most
 * three) must stay on it.
 *
 *   describePackage(dir, safe) -> lines      (what npm would run for the package: read as text, never run)
 *
 *   parsePackageSpec(spec)  -> { name, version }            (throws PackageError)
 *   fetchPackageForScan(spec, { registry? })
 *       -> Promise<{ name, version, dir, cleanup() }>        (throws PackageError)
 *
 * The registry is https://registry.npmjs.org unless ZN_NPM_REGISTRY names another one (plain http is
 * accepted for localhost only, for tests and private mirrors on this machine).
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const DEFAULT_REGISTRY = 'https://registry.npmjs.org';
const TIMEOUT_MS = 20000;
const MAX_METADATA_BYTES = 5 * 1024 * 1024;
const MAX_TARBALL_BYTES = 50 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 200 * 1024 * 1024;
const MAX_ENTRIES = 20000;
// New npm names are lower-case; some old ones (JSONStream) have capitals and are still on the registry. Only
// characters that need no escaping in a URL are accepted (the scope slash is the one escaped by the caller).
// "~" is not accepted: npm itself refuses it in a name.
const NAME_RE = /^(?:@[A-Za-z0-9-][A-Za-z0-9._-]*\/)?[A-Za-z0-9-][A-Za-z0-9._-]*$/;
const MAX_REDIRECTS = 3;
const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const MAX_COMMAND_SHOWN = 300;
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const HASH_ORDER = ['sha512', 'sha384', 'sha256', 'sha1'];

class PackageError extends Error {}

function parsePackageSpec(spec) {
  const s = String(spec || '').trim();
  const at = s.lastIndexOf('@');
  const name = at > 0 ? s.slice(0, at) : s;
  const version = at > 0 ? s.slice(at + 1) : 'latest';
  if (!s || name.length > 214 || !NAME_RE.test(name)) {
    throw new PackageError('not an npm package name: ' + JSON.stringify(s.slice(0, 80)) + ' (use NAME or @SCOPE/NAME, with an optional @VERSION)');
  }
  if (!VERSION_RE.test(version)) {
    throw new PackageError('not a version or dist-tag: ' + JSON.stringify(version.slice(0, 80)));
  }
  return { name, version };
}

// Plain http is accepted for this machine only. A URL writes the IPv6 loopback address as "[::1]".
function isLocalHost(hostname) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

function isAllowedProtocol(u) {
  return u.protocol === 'https:' || (u.protocol === 'http:' && isLocalHost(u.hostname));
}

function registryBase(env) {
  const raw = String(env.ZN_NPM_REGISTRY || DEFAULT_REGISTRY).replace(/\/+$/, '');
  let u;
  try { u = new URL(raw); } catch (_) { throw new PackageError('ZN_NPM_REGISTRY is not a URL'); }
  if (!isAllowedProtocol(u)) {
    throw new PackageError('ZN_NPM_REGISTRY must be an https address (plain http is accepted for localhost only)');
  }
  return u.href.replace(/\/+$/, '');
}

const tooLarge = (what, max) => new PackageError(what + ' is too large to scan (over ' + Math.round(max / 1048576) + ' MiB)');

// Reads a response body with a size cap; a body over the cap is refused, not cut. The download stops at the cap,
// also when the registry sends no content-length.
async function readCapped(res, max, what) {
  const declared = Number(res.headers.get('content-length') || 0);
  if (declared > max) throw tooLarge(what, max);
  if (!res.body || typeof res.body.getReader !== 'function') {
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > max) throw tooLarge(what, max);
    return buf;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > max) {
        await reader.cancel().catch(() => {});
        throw tooLarge(what, max);
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.length));
    }
  } finally {
    try { reader.releaseLock(); } catch (_) { /* already released */ }
  }
  return Buffer.concat(chunks, total);
}

/**
 * The address a redirect leads to, resolved against the one it came from. It must have the origin the request
 * started from (same scheme, host and port), so a redirect never leaves the registry or drops to plain http.
 */
function checkRedirect(from, location, origin) {
  let u;
  try { u = new URL(location, from); } catch (_) { throw new PackageError('the registry redirected to an address that is not a URL'); }
  if (!isAllowedProtocol(u) || u.origin !== origin) {
    throw new PackageError('the registry redirected to an address that is not its own (' + u.origin + '); not followed');
  }
  return u.href;
}

// GET with the answer capped. Redirects are followed by hand, at most MAX_REDIRECTS, each one to the same origin.
async function get(url, what, max, origin) {
  let res;
  let current = url;
  try {
    for (let hop = 0; ; hop++) {
      res = await fetch(current, { headers: { accept: 'application/json' }, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (res.status < 300 || res.status > 399 || !res.headers.get('location')) break;
      if (hop >= MAX_REDIRECTS) throw new PackageError('the registry sent too many redirects for ' + what + '. Nothing was scanned.');
      await (res.body ? res.body.cancel().catch(() => {}) : Promise.resolve());
      current = checkRedirect(current, res.headers.get('location'), origin);
    }
  } catch (err) {
    if (err instanceof PackageError) throw err;
    const cause = (err && err.cause && (err.cause.code || err.cause.message)) || (err && err.name) || 'unknown error';
    throw new PackageError('could not reach the registry for ' + what + ' (' + String(cause).slice(0, 80) + '). Nothing was scanned; try again when you are online.');
  }
  if (res.status === 404) throw new PackageError(what + ' was not found on the registry. Nothing was scanned.');
  if (!res.ok) throw new PackageError('the registry answered HTTP ' + res.status + ' for ' + what + '. Nothing was scanned.');
  return readCapped(res, max, what);
}

function checkTarballUrl(url) {
  let u;
  try { u = new URL(url); } catch (_) { throw new PackageError('the registry gave a tarball address that is not a URL'); }
  if (!isAllowedProtocol(u)) {
    throw new PackageError('the registry gave a tarball address that is not https');
  }
  return u.href;
}

// The checksum the registry gave: the strongest "integrity" hash, or the sha1 "shasum". Missing both: refused.
function expectedChecksum(dist) {
  const tokens = String(dist.integrity || '').split(/\s+/).filter(Boolean);
  let best = null;
  for (const t of tokens) {
    const m = /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/]+=*)$/.exec(t);
    if (m && (best === null || HASH_ORDER.indexOf(m[1]) < HASH_ORDER.indexOf(best.algo))) best = { algo: m[1], value: m[2], base64: true };
  }
  if (best) return best;
  if (typeof dist.shasum === 'string' && /^[0-9a-f]{40}$/.test(dist.shasum)) return { algo: 'sha1', value: dist.shasum, base64: false };
  return null;
}

function verifyChecksum(buf, expected) {
  const digest = crypto.createHash(expected.algo).update(buf).digest(expected.base64 ? 'base64' : 'hex');
  if (digest !== expected.value) {
    throw new PackageError('the downloaded tarball does not match the checksum the registry gave. Nothing was scanned.');
  }
}

function cstr(buf, start, len) {
  const end = buf.indexOf(0, start);
  const stop = end === -1 || end > start + len ? start + len : end;
  return buf.toString('utf8', start, stop);
}

function octal(buf, start, len) {
  const s = cstr(buf, start, len).trim();
  if (s === '') return 0;
  if (!/^[0-7]+$/.test(s)) throw new PackageError('the archive is damaged (bad header)');
  return parseInt(s, 8);
}

function parsePax(body) {
  const out = {};
  let off = 0;
  while (off < body.length) {
    const sp = body.indexOf(0x20, off);
    if (sp === -1) break;
    const len = parseInt(body.toString('utf8', off, sp), 10);
    if (!(len > 0)) break;
    const rec = body.toString('utf8', sp + 1, off + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    off += len;
  }
  return out;
}

// The path inside the package, without the leading folder npm adds (package/). Null for the root itself.
function relativePath(name) {
  if (name.includes('\0') || name.includes('\\') || name.startsWith('/') || /^[A-Za-z]:/.test(name)) {
    throw new PackageError('the package has an unsafe file path: ' + JSON.stringify(name.slice(0, 80)));
  }
  const parts = name.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.includes('..')) throw new PackageError('the package has a file path that leaves its folder: ' + JSON.stringify(name.slice(0, 80)));
  const rest = parts.slice(1);
  return rest.length ? rest : null;
}

/**
 * Unpacks a gzipped tarball into an empty folder. Only regular files and folders are written. A link,
 * a device or a fifo makes the whole package refused (it is not scanned, not skipped in silence).
 */
function extractTarball(gz, dest, opts = { windows: process.platform === 'win32' }) {
  const notUnpacked = [];
  const written = new Set();
  let tar;
  try {
    tar = zlib.gunzipSync(gz, { maxOutputLength: MAX_UNPACKED_BYTES });
  } catch (err) {
    if (err instanceof RangeError) throw new PackageError('the package is too large to scan unpacked (over ' + Math.round(MAX_UNPACKED_BYTES / 1048576) + ' MiB)');
    throw new PackageError('the tarball is not a valid gzip archive');
  }
  const root = path.resolve(dest);
  let off = 0;
  let pax = null;
  let longName = null;
  let count = 0;
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) {
      // npm's tar reader stops only after two empty blocks in a row, so one empty block between entries
      // must not hide what follows. Whatever comes after the end marker has to be empty too.
      for (let i = off; i < tar.length; i++) {
        if (tar[i] !== 0) throw new PackageError('the archive has data after its end marker');
      }
      break;
    }
    // The checksum field counts as eight spaces.
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 0x20 : h[i];
    if (sum !== octal(h, 148, 8)) throw new PackageError('the archive is damaged (bad header checksum)');
    let name = cstr(h, 0, 100);
    if (cstr(h, 257, 6) === 'ustar') {
      const prefix = cstr(h, 345, 155);
      if (prefix) name = prefix + '/' + name;
    }
    const size = octal(h, 124, 12);
    const type = h[156] === 0 ? '0' : String.fromCharCode(h[156]);
    off += 512;
    if (off + size > tar.length) throw new PackageError('the archive is damaged (truncated entry)');
    const body = tar.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;

    if (type === 'x' || type === 'g') {
      const rec = parsePax(body);
      // Only a path is honoured. A size (or a link target) would change how npm reads the archive.
      for (const k of Object.keys(rec)) {
        if (k === 'size' || k === 'linkpath' || (type === 'g' && k === 'path')) {
          throw new PackageError('the archive has an extended header this scan does not follow (' + JSON.stringify(k) + ')');
        }
      }
      if (type === 'x') pax = rec;
      continue;
    }
    if (type === 'L') { longName = cstr(body, 0, body.length); continue; }
    if (pax && pax.path) name = pax.path;
    if (longName) name = longName;
    pax = null;
    longName = null;

    if (++count > MAX_ENTRIES) throw new PackageError('the package has too many files to scan (over ' + MAX_ENTRIES + ')');
    const rel = relativePath(name);
    if (type !== '0' && type !== '7' && type !== '5') {
      throw new PackageError('the package contains a link or a special file (' + JSON.stringify(name.slice(0, 80)) + '). It is refused, not scanned.');
    }
    if (rel === null) continue;
    const target = path.resolve(root, ...rel);
    if (target !== root && !target.startsWith(root + path.sep)) {
      throw new PackageError('the package has a file path that leaves its folder');
    }
    const shown = rel.join('/');
    // A name this system cannot write is not skipped in silence: it is listed, and the scan is incomplete.
    if (opts.windows && unsafeOnWindows(rel)) {
      notUnpacked.push({ path: shown, reason: 'a name Windows cannot write' });
      continue;
    }
    try {
      if (type === '5') {
        fs.mkdirSync(target, { recursive: true });
      } else {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        // On a file system that ignores case, a second name that differs only by case would replace the first.
        if (written.has(shown) === false && fs.existsSync(target)) {
          notUnpacked.push({ path: shown, reason: 'same name as another file, apart from letter case' });
          continue;
        }
        fs.writeFileSync(target, body);
        written.add(shown);
      }
    } catch (err) {
      notUnpacked.push({ path: shown, reason: String((err && err.code) || 'write error').slice(0, 40) });
    }
  }
  return { files: count, notUnpacked };
}

// Names Windows cannot create: device names (NUL, CON, COM1...), a colon (NTFS streams), characters it forbids,
// and a trailing dot or space. `parts` are the path segments.
function unsafeOnWindows(parts) {
  return parts.some((p) => /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i.test(p) || /[<>:"|?*]/.test(p) || /[. ]$/.test(p));
}

/**
 * Looks the package up, downloads its tarball, checks it and unpacks it into a new temporary folder.
 * The caller scans `dir` and then calls `cleanup()`.
 */
async function fetchPackageForScan(spec, opts = {}) {
  const { name, version } = parsePackageSpec(spec);
  const base = opts.registry || registryBase(process.env);
  const encoded = name.replace(/\//g, '%2F');
  const label = name + '@' + version;

  const origin = new URL(base).origin;
  const body = await get(base + '/' + encoded + '/' + encodeURIComponent(version), label, MAX_METADATA_BYTES, origin);
  let doc;
  try {
    doc = JSON.parse(body.toString('utf8'));
  } catch (_) {
    throw new PackageError('the registry answered with something that is not JSON for ' + label + '. Nothing was scanned.');
  }
  if (!doc || doc.name !== name || typeof doc.version !== 'string' || !doc.dist || typeof doc.dist.tarball !== 'string') {
    throw new PackageError('the registry gave no usable metadata for ' + label + '. Nothing was scanned.');
  }
  const expected = expectedChecksum(doc.dist);
  if (!expected) throw new PackageError('the registry gave no checksum for ' + label + '; refusing to scan an unverified tarball.');
  const tarballUrl = checkTarballUrl(doc.dist.tarball);
  // The checksum comes from the same registry, so the tarball must come from there too.
  if (new URL(tarballUrl).origin !== origin) {
    throw new PackageError('the registry gave a tarball address that is not on the registry\'s own address (' + new URL(tarballUrl).origin + '). Nothing was downloaded or scanned.');
  }

  const gz = await get(tarballUrl, doc.name + '@' + doc.version + ' (tarball)', MAX_TARBALL_BYTES, origin);
  verifyChecksum(gz, expected);

  const dir = fs.mkdtempSync(path.join(opts.tmpBase || os.tmpdir(), 'zn-scan-pkg-'));
  const cleanup = () => fs.rmSync(dir, { recursive: true, force: true });
  let unpacked;
  try {
    unpacked = extractTarball(gz, dir);
  } catch (err) {
    cleanup();
    throw err;
  }
  return { name, version: doc.version, dir, cleanup, notUnpacked: unpacked.notUnpacked };
}

/**
 * What npm would run, and what it would put on your path, if you installed the package in `dir`: read from its
 * package.json as text, never run. Returns the lines to print (they are not findings and do not change the
 * exit code). `safe` makes a string printable (control characters of a package never reach the terminal).
 */
function describePackage(dir, safe) {
  const lines = [];
  const clip = (s) => (s.length > MAX_COMMAND_SHOWN ? s.slice(0, MAX_COMMAND_SHOWN) + ' [...]' : s);
  let pkg = null;
  const file = path.join(dir, 'package.json');
  try {
    if (fs.statSync(file).size > MAX_PACKAGE_JSON_BYTES) throw new Error('large');
    pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    pkg = null;
  }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    lines.push('Install scripts: unknown (package.json is missing, too large or not valid JSON, so they were not listed)');
    return lines;
  }
  const scripts = pkg.scripts && typeof pkg.scripts === 'object' && !Array.isArray(pkg.scripts) ? pkg.scripts : {};
  const command = (n) => (typeof scripts[n] === 'string' ? scripts[n] : null);
  const run = ['preinstall', 'install', 'postinstall'].filter((n) => command(n) !== null);
  if (run.length) {
    lines.push('Install scripts (npm runs these when you install it):');
    for (const n of run) lines.push('  ' + n + ': ' + safe(clip(command(n))));
  } else {
    lines.push('Install scripts: none (no preinstall, install or postinstall)');
  }
  if (command('prepare') !== null) {
    lines.push('Other script: prepare: ' + safe(clip(command('prepare'))) + ' (npm runs it when a package is installed from git, not from the registry)');
  }
  if (!run.includes('preinstall') && !run.includes('install') && fs.existsSync(path.join(dir, 'binding.gyp'))) {
    lines.push('Native build: binding.gyp is present and no install script is set, so npm runs "node-gyp rebuild" when you install it.');
  }
  let bin = [];
  if (typeof pkg.bin === 'string') bin = [[String(pkg.name || '').split('/').pop(), pkg.bin]];
  else if (pkg.bin && typeof pkg.bin === 'object' && !Array.isArray(pkg.bin)) bin = Object.entries(pkg.bin).filter(([, v]) => typeof v === 'string');
  if (bin.length) {
    const shown = bin.slice(0, 20).map(([k, v]) => safe(clip(k)) + ' -> ' + safe(clip(v)));
    lines.push('Commands it adds (bin): ' + shown.join('; ') + (bin.length > 20 ? '; ... and ' + (bin.length - 20) + ' more' : ''));
  }
  return lines;
}

// What the agent-config audit did not read in full, as short phrases ([] when it walked everything).
function auditCoverageGaps(result) {
  const gaps = [];
  if (result.truncated) gaps.push('it stopped early (time budget or entry limit), so some files were not checked');
  const dirs = (result.skippedDirs || []).length;
  if (dirs) gaps.push(dirs + ' folder(s) were not read');
  const files = new Set((result.findings || []).filter((f) => f.id === 'ZNA020').map((f) => f.file)).size;
  if (files) gaps.push(files + ' file(s) were not fully checked');
  return gaps;
}

module.exports = { auditCoverageGaps, PackageError, parsePackageSpec, fetchPackageForScan, extractTarball, registryBase, checkTarballUrl, checkRedirect, unsafeOnWindows, describePackage };
