'use strict';

/**
 * The online part of the package install check (hooks.packageInstallCheck = "online"). Loaded only in that mode.
 *
 * For each package name it makes one unauthenticated GET to the public registry the package would come from anyway:
 *   https://registry.npmjs.org/<name>      (a scoped name as @scope%2Fname)
 *   https://pypi.org/pypi/<name>/json
 * and nothing else leaves the machine: no cookies, no headers beyond Accept, no command, path, project or user data.
 * The name is validated before it is put in the URL. A redirect is never followed, a reply over 4 MiB is dropped,
 * and a lookup that has not finished in 2 seconds is given up. Any failure (network, timeout, status other than
 * 200 and 404, a reply that is not the expected JSON) gives no answer, and the caller then asks no question.
 *
 * The answers are kept for one day in ~/.zn/package-registry-cache.json (written atomically, mode 0600), an answer about
 * the latest version for one hour. A cache that cannot be read or written is ignored. Only the name, whether it exists,
 * the date of its first release and, when asked, the version and its publish date are kept.
 */

const fs = require('fs');
const path = require('path');

const HOSTS = new Set(['registry.npmjs.org', 'pypi.org']);
const TIMEOUT_MS = 2000;
const MAX_BYTES = 4 * 1024 * 1024;
const TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CACHE_ENTRIES = 2000;
const MAX_NAMES = 8;
const CACHE_FILE = 'package-registry-cache.json';
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
// An answer about the latest version can change within the day (a new release), so it is kept for an hour only.
const LATEST_TTL_MS = HOUR_MS;

const NPM_OK = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const PYPI_OK = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** The registry URL for a validated name, or null. A scoped npm name keeps its @ and has the slash encoded. */
function urlFor(eco, name) {
  if (typeof name !== 'string' || name.length > 214) return null;
  if (eco === 'npm') return NPM_OK.test(name) ? 'https://registry.npmjs.org/' + name.replace(/\//g, '%2F') : null;
  if (eco === 'pypi') return PYPI_OK.test(name) && name.length <= 100 ? 'https://pypi.org/pypi/' + name + '/json' : null;
  return null;
}

/* The options of the one request: certificate checks are set explicitly, so NODE_TLS_REJECT_UNAUTHORIZED in the environment cannot switch them off. */
function requestOptions(u, timeoutMs) {
  return { hostname: u.hostname, path: u.pathname, method: 'GET', agent: false, timeout: timeoutMs, rejectUnauthorized: true, headers: { Accept: 'application/json' } };
}

/* The real fetch: https.request, no redirects, no cookies, capped size, short timeout. Resolves { status, body }. */
function httpsFetch(url, { timeoutMs = TIMEOUT_MS, maxBytes = MAX_BYTES } = {}) {
  const https = require('https');
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { reject(new Error('bad url')); return; }
    if (u.protocol !== 'https:' || !HOSTS.has(u.hostname) || u.username || u.password) { reject(new Error('host not allowed')); return; }
    let done = false;
    const finish = (fn, v) => { if (!done) { done = true; clearTimeout(timer); fn(v); } };
    const req = https.request(requestOptions(u, timeoutMs), (res) => {
      const status = res.statusCode;
      // A redirect is not followed: it has no verdict.
      if (status !== 200 && status !== 404) { res.resume(); finish(resolve, { status, body: '' }); return; }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) { req.destroy(new Error('too large')); return; }
        chunks.push(c);
      });
      res.on('end', () => finish(resolve, { status, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', (e) => finish(reject, e));
    });
    const timer = setTimeout(() => { req.destroy(new Error('timeout')); }, timeoutMs);
   
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => finish(reject, e));
    req.end();
  });
}

const ok = (t) => (Number.isFinite(t) ? t : null);

/* Milliseconds of the earliest upload among a PyPI release's files, or null. */
function firstUploadOf(files) {
  let first = Infinity;
  for (const f of Array.isArray(files) ? files : []) {
    if (!f || typeof f !== 'object') continue;
    const s = typeof f.upload_time_iso_8601 === 'string' ? f.upload_time_iso_8601 : typeof f.upload_time === 'string' ? f.upload_time + 'Z' : '';
    const t = Date.parse(s);
    if (Number.isFinite(t) && t < first) first = t;
  }
  return first === Infinity ? null : first;
}

/* Milliseconds of the first release in the registry's JSON, or null when it cannot be told. */
function createdOf(eco, doc) {
  if (eco === 'npm') {
    const t = doc && doc.time && typeof doc.time.created === 'string' ? Date.parse(doc.time.created) : NaN;
    return ok(t);
  }
  let first = Infinity;
  const releases = doc && typeof doc.releases === 'object' && doc.releases ? doc.releases : {};
  for (const files of Object.values(releases)) {
    const t = firstUploadOf(files);
    if (t !== null && t < first) first = t;
  }
  return first === Infinity ? null : first;
}

/*
 * The version the agent asks for: `wanted` is an exact version, or 'latest' (no version in the command). Returns
 * { version, created } with the version the registry resolves to and its publish time (ms, or null), or null.
 */
function versionOf(eco, doc, wanted) {
  if (eco === 'npm') {
    const tags = doc['dist-tags'] && typeof doc['dist-tags'] === 'object' ? doc['dist-tags'] : {};
    const version = wanted === 'latest' ? tags.latest : wanted;
    if (typeof version !== 'string' || !version) return null;
    const t = doc.time && typeof doc.time[version] === 'string' ? Date.parse(doc.time[version]) : NaN;
    return { version, created: ok(t) };
  }
  const info = doc.info && typeof doc.info === 'object' ? doc.info : {};
  const version = wanted === 'latest' ? info.version : wanted;
  if (typeof version !== 'string' || !version) return null;
  const files = doc.releases && typeof doc.releases === 'object' ? doc.releases[version] : undefined;
  return { version, created: firstUploadOf(files) };
}

/* One lookup: { state: 'missing' | 'found', created, version, versionCreated } or throws an Error with a short reason. */
async function fetchOne(eco, name, fetch, timeoutMs, maxBytes, wanted) {
  const url = urlFor(eco, name);
  if (!url) throw new Error('name not valid');
  let timer;
  const limit = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), timeoutMs); });
  let res;
  try { res = await Promise.race([Promise.resolve().then(() => fetch(url, { timeoutMs, maxBytes })), limit]); } finally { clearTimeout(timer); }
  if (!res || typeof res.status !== 'number') throw new Error('no reply');
  if (res.status === 404) return { state: 'missing', created: null, version: null, versionCreated: null };
  if (res.status !== 200) throw new Error('status ' + res.status);
  if (typeof res.body !== 'string') throw new Error('no body');
  if (res.body.length > maxBytes) throw new Error('reply too large');
  let doc;
  try { doc = JSON.parse(res.body); } catch (e) { throw new Error('reply is not JSON'); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('reply not understood');
  const v = wanted ? versionOf(eco, doc, wanted) : null;
  return { state: 'found', created: createdOf(eco, doc), version: v ? v.version : null, versionCreated: v ? v.created : null };
}

function readCache(file) {
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (data && data.v === 1 && data.e && typeof data.e === 'object') return data.e;
  } catch (e) { /* no cache, or one that cannot be read */ }
  return {};
}

function writeCache(file, entries) {
  const keys = Object.keys(entries);
  if (keys.length > MAX_CACHE_ENTRIES) {
    keys.sort((a, b) => entries[a].t - entries[b].t).slice(0, keys.length - MAX_CACHE_ENTRIES).forEach((k) => { delete entries[k]; });
  }
  const tmp = file + '.' + process.pid + '.tmp';
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(tmp, JSON.stringify({ v: 1, e: entries }), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (e2) { /* nothing was written */ }
  }
}

/* The answer for one name from a cache entry or a fresh reply: { state, ageDays, version, versionAgeHours }. */
function answerOf(entry, now) {
  return {
    state: entry.s,
    ageDays: typeof entry.c === 'number' ? (now - entry.c) / DAY_MS : null,
    version: typeof entry.vv === 'string' ? entry.vv : null,
    versionAgeHours: typeof entry.vc === 'number' ? (now - entry.vc) / HOUR_MS : null,
  };
}

/**
 * Looks the names up. items: [{ eco, name, version? }]. `version` is set only when the caller needs the publish time of
 * a version: an exact version, or 'latest' for a name with no version in the command. Returns a Map `eco:name` ->
 * { state, ageDays, version, versionAgeHours } or { error }.
 * opts: { fetch, now (function, ms), stateDir, timeoutMs, maxBytes }
 */
async function lookupMany(items, opts = {}) {
  const fetch = typeof opts.fetch === 'function' ? opts.fetch : httpsFetch;
  const now = typeof opts.now === 'function' ? opts.now() : Date.now();
  const timeoutMs = opts.timeoutMs || TIMEOUT_MS;
  const maxBytes = opts.maxBytes || MAX_BYTES;
  const file = opts.stateDir ? path.join(opts.stateDir, CACHE_FILE) : null;
  const cache = file ? readCache(file) : {};
  const out = new Map();
  const todo = [];
  for (const it of items.slice(MAX_NAMES)) out.set(it.eco + ':' + it.name, { error: 'too many names' });
  for (const it of items.slice(0, MAX_NAMES)) {
    const key = it.eco + ':' + it.name;
    const hit = cache[key];
    const wanted = typeof it.version === 'string' ? it.version : null;
    const ttl = hit && hit.vr === 'latest' ? LATEST_TTL_MS : TTL_MS;
    const sameVersion = !wanted || (hit && hit.vr === wanted);
    if (hit && typeof hit.t === 'number' && now - hit.t < ttl && now >= hit.t && (hit.s === 'missing' || hit.s === 'found') && sameVersion) {
      out.set(key, answerOf(hit, now));
    } else todo.push(it);
  }
  let changed = false;
  await Promise.all(todo.map(async (it) => {
    const key = it.eco + ':' + it.name;
    const wanted = typeof it.version === 'string' ? it.version : null;
    try {
      const r = await fetchOne(it.eco, it.name, fetch, timeoutMs, maxBytes, wanted);
      const entry = { t: now, s: r.state, c: r.created };
      if (wanted) Object.assign(entry, { vr: wanted, vv: r.version, vc: r.versionCreated });
      cache[key] = entry;
      changed = true;
      out.set(key, answerOf({ s: r.state, c: r.created, vv: r.version, vc: r.versionCreated }, now));
    } catch (e) {
      out.set(key, { error: String((e && e.message) || 'failed').replace(/[^A-Za-z0-9 .:-]/g, '').slice(0, 60) });
    }
  }));
  if (file && changed) writeCache(file, cache);
  return out;
}

/* ------------------- another registry in the user's settings ------------------- */

const READ_LIMIT = 65536;
// A settings file larger than the read limit cannot be read whole: it counts as pointing at another registry (fail closed).
const OVERSIZED_MARK = '\nregistry=https://oversized-settings.invalid\nindex-url=https://oversized-settings.invalid\n';

function readSmall(file) {
  try {
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(READ_LIMIT + 1);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      if (n > READ_LIMIT) return buf.toString('utf8', 0, READ_LIMIT) + OVERSIZED_MARK;
      return buf.toString('utf8', 0, n);
    } finally { fs.closeSync(fd); }
  } catch (e) { return ''; }
}

const NPM_HOST_OK = /^https?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)(?:[/:]|$)/i;

/**
 * The folders whose settings apply to a command run in cwd: cwd itself and each parent up to the git root (the
 * folder holding .git) or the home folder, whichever comes first. Bounded depth: if the bound is hit before a
 * boundary, the list is marked incomplete and the caller treats the registry as private (fail closed).
 */
const MAX_WALK = 64;
function projectDirs(cwd, home) {
  if (!cwd) return [];
  const out = [];
  let dir = path.resolve(cwd);
  const stop = home ? path.resolve(home) : null;
  out.incomplete = true;
  for (let i = 0; i < MAX_WALK; i++) {
    out.push(dir);
    if (stop && dir === stop) { out.incomplete = false; break; }
    let isRoot = false;
    try { isRoot = fs.existsSync(path.join(dir, '.git')); } catch (e) { /* unreadable: keep walking */ }
    if (isRoot) { out.incomplete = false; break; }
    const up = path.dirname(dir);
    if (up === dir) { out.incomplete = false; break; }
    dir = up;
  }
  return out;
}

/* Where npm reads its global settings, computed without starting npm. */
function npmGlobalConfigs(env) {
  const files = [];
  const explicit = env.NPM_CONFIG_GLOBALCONFIG || env.npm_config_globalconfig;
  if (explicit) files.push(explicit);
  const prefix = env.NPM_CONFIG_PREFIX || env.npm_config_prefix || env.PREFIX
    || (process.platform === 'win32' ? path.dirname(process.execPath) : path.dirname(path.dirname(process.execPath)));
  files.push(path.join(prefix, 'etc', 'npmrc'));
  // npm's default global prefix on Windows is %APPDATA%\npm; the Node folder is kept as well.
  if (env.APPDATA) files.push(path.join(env.APPDATA, 'npm', 'etc', 'npmrc'));
  if (process.platform === 'win32') files.push(path.join(path.dirname(process.execPath), 'etc', 'npmrc'));
  if (process.platform !== 'win32') files.push('/etc/npmrc');
  return files;
}

/* pnpm's own user settings. */
function pnpmUserConfigs(env, home) {
  const files = [];
  if (env.XDG_CONFIG_HOME) files.push(path.join(env.XDG_CONFIG_HOME, 'pnpm', 'rc'));
  if (home) files.push(path.join(home, '.config', 'pnpm', 'rc'), path.join(home, 'Library', 'Preferences', 'pnpm', 'rc'));
  if (env.LOCALAPPDATA) files.push(path.join(env.LOCALAPPDATA, 'pnpm', 'config', 'rc'));
  return files;
}

/**
 * uv settings (uv.toml, or the uv, poetry and pdm index tables of pyproject.toml): true when they name an index other than public PyPI.
 * A small strict line reader, no TOML dependency. It understands table headers ([[index]], [[tool.uv.index]], [tool.uv])
 * and key = value lines. Fails closed: an index table whose url is not the public PyPI host is private, and so is an
 * index-url / extra-index-url / default-index / find-links key or an inline index list. isPyproject restricts the keys
 * to the tool.uv tables.
 */
const PYPROJECT_INDEX_TABLES = new Set(['tool.uv.index', 'tool.poetry.source', 'tool.pdm.source']);
const PYPI_INDEX_OK = /^https?:\/\/(?:pypi\.org|files\.pythonhosted\.org)(?:[/:?#]|$)/i;
function uvConfigPrivate(text, isPyproject) {
  let section = isPyproject ? null : '';
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/^\s+/, '');
    if (!line || line[0] === '#') continue;
    const head = /^\[\[?\s*([^\]]*?)\s*\]\]?/.exec(line);
    if (head) {
      section = head[1].replace(/\s*\.\s*/g, '.').replace(/["']/g, '');
      continue;
    }
    if (section === null) continue;
    const kv = /^["']?([A-Za-z0-9_-]+)["']?\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1];
    const value = kv[2];
    const inIndexTable = isPyproject ? PYPROJECT_INDEX_TABLES.has(section) : section === 'index';
    const inUv = isPyproject ? (section === 'tool.uv' || section === 'tool.uv.pip') : section === '' || section === 'pip';
    if (inIndexTable) {
      if (key === 'url') {
        const u = /["']([^"']*)["']/.exec(value);
        if (!u || !PYPI_INDEX_OK.test(u[1])) return true;
      }
    } else if (inUv && /^(?:index-url|extra-index-url|find-links|default-index|index)$/.test(key)) {
      const u = /^["']([^"']*)["']\s*(?:#.*)?$/.exec(value.trim());
      if (!(key === 'index-url' && u && PYPI_INDEX_OK.test(u[1]))) return true;
    }
  }
  return false;
}

/**
 * True when the user's own settings point the ecosystem at a registry other than the public one (an .npmrc or
 * pip.conf with another index, an environment variable, a uv or pyproject index). The public registry is then not
 * asked about that ecosystem's names: a private package name must never be sent to it. Reads settings files only
 * in online mode. opts: { cwd, home, env }.
 */
/* The folders of an XDG_CONFIG_DIRS value. The list uses the platform's separator: ';' on Windows, where ':' also
 * follows the drive letter (C:\cfg), so a ':' split would break every entry there. Empty entries are skipped. */
function xdgConfigDirs(value, delimiter = path.delimiter) {
  return String(value || '').split(delimiter).filter(Boolean);
}

function privateRegistry(eco, opts = {}) {
  const env = opts.env || process.env;
  const cwd = opts.cwd;
  const home = opts.home;
  if (eco === 'npm') {
    if (env.NPM_CONFIG_REGISTRY || env.npm_config_registry || env.YARN_NPM_REGISTRY_SERVER || env.BUN_CONFIG_REGISTRY || env.YARN_REGISTRY) return true;
    const extra = npmGlobalConfigs(env).concat(pnpmUserConfigs(env, home)).map((f) => readSmall(f)).join('\n');
    const npmDirs = projectDirs(cwd, home);
    if (npmDirs.incomplete) return true;
    for (const dir of npmDirs.concat(home ? [home] : [])) {
      const text = extra + '\n' + readSmall(path.join(dir, '.pnpmrc')) + '\n' + readSmall(path.join(dir, 'pnpm-workspace.yaml')) + '\n' + readSmall(path.join(dir, '.npmrc')) + '\n' + readSmall(path.join(dir, '.yarnrc.yml')) + '\n' + readSmall(path.join(dir, '.yarnrc')) + '\n'
        + readSmall(path.join(dir, 'bunfig.toml')) + '\n' + readSmall(path.join(dir, '.bunfig.toml')) + '\n'
        + (env.NPM_CONFIG_USERCONFIG || env.npm_config_userconfig ? readSmall(env.NPM_CONFIG_USERCONFIG || env.npm_config_userconfig) : '');
      for (const m of text.matchAll(/^\s*(?:@[\w.-]+:)?registry\s*=\s*["']?([^\s"']+)/gim)) if (!NPM_HOST_OK.test(m[1])) return true;
      // yarn v1: registry "https://..."
      for (const m of text.matchAll(/^\s*"?(?:@[\w.-]+:)?registry"?\s+"?(https?:[^\s"]+)/gim)) if (!NPM_HOST_OK.test(m[1])) return true;
      // pnpm-workspace.yaml: registry: https://... or a registries: map
      for (const m of text.matchAll(/^\s*["']?(?:@[\w.-]+:)?registry["']?\s*:\s*["']?(https?:[^\s"']+)/gim)) if (!NPM_HOST_OK.test(m[1])) return true;
      if (/^\s*registries\s*:/m.test(text)) return true;
      for (const m of text.matchAll(/^\s*npmRegistryServer\s*:\s*(\S+)/gim)) if (!NPM_HOST_OK.test(m[1].replace(/['"]/g, ''))) return true;
      if (/^\s*(?:npmScopes|npmRegistries)\s*:/m.test(text)) return true;
    }
    return false;
  }
  for (const v of ['PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_FIND_LINKS', 'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL', 'UV_INDEX', 'UV_DEFAULT_INDEX', 'UV_FIND_LINKS']) {
    if (env[v]) return true;
  }
  for (const k of Object.keys(env)) if (/^UV_INDEX_[A-Z0-9_]+$/.test(k) && env[k]) return true;
  const files = [];
  if (home) files.push(path.join(home, '.config', 'pip', 'pip.conf'), path.join(home, '.pip', 'pip.conf'), path.join(home, 'pip', 'pip.ini'), path.join(home, '.config', 'uv', 'uv.toml'),
    path.join(home, 'Library', 'Application Support', 'pip', 'pip.conf'), path.join(home, 'AppData', 'Roaming', 'pip', 'pip.ini'));
  if (env.XDG_CONFIG_HOME) files.push(path.join(env.XDG_CONFIG_HOME, 'pip', 'pip.conf'), path.join(env.XDG_CONFIG_HOME, 'uv', 'uv.toml'));
  if (env.APPDATA) files.push(path.join(env.APPDATA, 'pip', 'pip.ini'), path.join(env.APPDATA, 'uv', 'uv.toml'));
  if (env.VIRTUAL_ENV) files.push(path.join(env.VIRTUAL_ENV, 'pip.conf'));
  for (const v of ['PIP_CONFIG_FILE', 'UV_CONFIG_FILE']) if (env[v]) files.push(env[v]);
  if (env.VIRTUAL_ENV) files.push(path.join(env.VIRTUAL_ENV, 'pip.ini'));
  const projectDirList = projectDirs(cwd, home);
  if (projectDirList.incomplete) return true;
  for (const dir of projectDirList) files.push(path.join(dir, 'uv.toml'), path.join(dir, 'pip.conf'));
  files.push('/etc/pip.conf', '/etc/xdg/pip/pip.conf', '/etc/uv/uv.toml');
  for (const d of xdgConfigDirs(env.XDG_CONFIG_DIRS)) files.push(path.join(d, 'pip', 'pip.conf'));
  const programData = env.ProgramData || env.PROGRAMDATA;
  if (programData) files.push(path.join(programData, 'pip', 'pip.ini'), path.join(programData, 'uv', 'uv.toml'));
  for (const f of files) {
    const text = readSmall(f);
    if (/^\s*(?:index-url|extra-index-url|find-links|default-index|index)\b/im.test(text)) return true;
    if ((path.basename(f).toLowerCase() === 'uv.toml' || f === env.UV_CONFIG_FILE) && uvConfigPrivate(text, false)) return true;
  }
  for (const dir of projectDirList) {
    const pyproject = readSmall(path.join(dir, 'pyproject.toml'));
    // Union of the table reader (uv, poetry and pdm sources) and the bare keys anywhere in the file: fail closed.
    if (uvConfigPrivate(pyproject, true) || /^\s*(?:index-url|extra-index-url|find-links)\s*=/m.test(pyproject)) return true;
  }
  return false;
}

module.exports = { lookupMany, urlFor, httpsFetch, requestOptions, createdOf, versionOf, privateRegistry, xdgConfigDirs, CACHE_FILE, TTL_MS, LATEST_TTL_MS, TIMEOUT_MS, MAX_BYTES };
