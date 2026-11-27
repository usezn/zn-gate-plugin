'use strict';

// Baseline of the executable configuration of a project: what the person approved, as one hash per entry, so a later change to a command,
// a hook (its matcher included), an environment override, a permission or an install script can be told apart from a harmless reformat.
// Only entry names and hashes are stored (never a value or a path), in a file private to the user.
//
//   extractSurface(root)           -> { '<file>#<kind>:<name>': '<sha256 hex>' }
//   diffSurface(base, now)         -> { added: [...], changed: [...], removed: [...] }
//   baselinePath(home, root)       -> where the baseline of this project is kept (the real folder, not the way it was spelled)
//   saveBaseline / loadBaseline    -> write it (0600) / read it (null when missing or damaged)
//
// Plugin code of OpenCode and the agent and rule files of Amazon Q are one entry each, `<file>#file`, hashed by content.
//
// A file that is there but cannot be read (too large, not valid, a link that leaves the project or is broken) is one entry of its own,
// `<file>#unreadable`, hashed from what can still be told of it, so turning a file into one of those is a change, not a removal.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { parseJsonc, parseToml } = require('./parse');

const MAX_FILE = 1024 * 1024;
const MAX_HASHED = 8 * 1024 * 1024;
const MAX_LISTED = 500;
// Past MAX_LISTED files in one folder the rest is still hashed by content, all together, up to MAX_OVER_CAP more; past
// that the folder gets a fixed over-limit entry (a documented limit). Folders below MAX_DEPTH levels are one entry.
const MAX_OVER_CAP = 5000;
const MAX_DEPTH = 8;
// At most this many folders are read in one walk (links can make a small tree look huge); past it, one entry.
const MAX_FOLDERS = 2000;
const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepack', 'postpack'];
const SETTINGS_FILES = ['.claude/settings.json', '.claude/settings.local.json', '.codex/config.json', '.cursor/hooks.json', '.gemini/settings.json'];
const MCP_FILES = [
  ['.mcp.json', 'mcpServers'], ['.cursor/mcp.json', 'mcpServers'], ['.vscode/mcp.json', 'servers'], ['.gemini/settings.json', 'mcpServers'],
  ['.amazonq/mcp.json', 'mcpServers'], ['opencode.json', 'mcp'], ['opencode.jsonc', 'mcp'], ['.opencode/opencode.json', 'mcp'], ['.codex/config.toml', 'mcp_servers'],
];
const SCALAR_SETTINGS = ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'statusLine', 'enableAllProjectMcpServers', 'enabledMcpjsonServers', 'disableAllHooks', 'otelHeadersHelper'];
const ENV_RE = /^(?:(?:ANTHROPIC|OPENAI|GOOGLE|GEMINI)_.*(?:URL|ENDPOINT|HOST)|(?:HTTPS?|ALL)_PROXY|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|CLAUDE_CODE_SHELL_PREFIX|PERL5OPT|BASH_ENV|ENV|PATH|PYTHONPATH|GIT_SSH_COMMAND|SSL_CERT_FILE|REQUESTS_CA_BUNDLE)$/i;
// Code and text an agent loads from the project as it is: plugin code (OpenCode runs it) and the agent definitions and rules of Amazon Q.
// [folder, picks a file name, how many folder levels below it are searched (-1: none, the agent loads only the top level)].
// Amazon Q's `mcp.json` is read as MCP servers above, not here.
const WHOLE_FILES = [
  ['.opencode/plugin', (n) => n.endsWith('.js'), -1], ['.opencode/plugins', (n) => n.endsWith('.js'), -1],
  ['.amazonq/cli-agents', (n) => n.endsWith('.json'), -1], ['.amazonq/agents', (n) => n.endsWith('.json'), -1],
  ['.amazonq/rules', (n) => n.endsWith('.md'), MAX_DEPTH],
];
const WHOLE_SINGLE = ['.amazonq/default.mcp.json'];
const DEVCONTAINER_FILES = ['.devcontainer/devcontainer.json', '.devcontainer.json'];
const DEVCONTAINER_KEYS = ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'];

function sha(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function realOf(p) {
  try { return fs.realpathSync.native(p); } catch (_) { return path.resolve(p); }
}

function insideOf(realRoot, real) {
  const r = path.relative(realRoot, real);
  return r === '' || (r !== '..' && !r.startsWith('..' + path.sep) && !path.isAbsolute(r));
}

/** { kind: 'missing' } | { kind: 'bad', hash } | { kind: 'raw', size, buf, digest }. A link is followed when it stays inside the project. */
function readRaw(root, realRoot, rel) {
  const file = path.join(root, rel);
  let lst;
  try { lst = fs.lstatSync(file); } catch (_) { return { kind: 'missing' }; }
  let target = file;
  if (lst.isSymbolicLink()) {
    let real;
    try { real = fs.realpathSync.native(file); } catch (_) { return { kind: 'bad', hash: sha(['broken-link']) }; }
    if (!insideOf(realRoot, real)) {
      // What the agent loads is the content of the target: its size and digest are the hash (the path is not kept).
      try {
        const st0 = fs.statSync(real);
        const body = st0.isFile() && st0.size <= MAX_HASHED ? fs.readFileSync(real) : null;
        return { kind: 'bad', hash: sha(['link-outside', st0.size, body ? crypto.createHash('sha256').update(body).digest('hex') : '']) };
      } catch (_) {
        return { kind: 'bad', hash: sha(['link-outside-unreadable']) };
      }
    }
    target = real;
  }
  let st;
  try { st = fs.statSync(target); } catch (_) { return { kind: 'bad', hash: sha(['unreadable']) }; }
  if (!st.isFile()) return { kind: 'bad', hash: sha(['not-a-file']) };
  let buf;
  try { buf = st.size <= MAX_HASHED ? fs.readFileSync(target) : null; } catch (_) { return { kind: 'bad', hash: sha(['unreadable']) }; }
  const digest = buf ? crypto.createHash('sha256').update(buf).digest('hex') : '';
  return { kind: 'raw', size: st.size, buf, digest };
}

/** { kind: 'missing' } | { kind: 'ok', value } | { kind: 'bad', hash }. */
function readConfig(root, realRoot, rel) {
  const r = readRaw(root, realRoot, rel);
  if (r.kind !== 'raw') return r;
  if (r.size > MAX_FILE) return { kind: 'bad', hash: sha(['large', r.size, r.digest]) };
  try {
    const text = r.buf.toString('utf8');
    const v = rel.endsWith('.toml') ? parseToml(text).data : parseJsonc(text);
    if (v && typeof v === 'object' && !Array.isArray(v)) return { kind: 'ok', value: v };
  } catch (_) { /* below */ }
  return { kind: 'bad', hash: sha(['invalid', r.digest]) };
}

/** { kind: 'missing' } | { kind: 'ok', hash } | { kind: 'bad', hash }: a file taken as it is (code or text), hashed by its content. */
function readWhole(root, realRoot, rel) {
  const r = readRaw(root, realRoot, rel);
  if (r.kind !== 'raw') return r;
  if (r.size > MAX_FILE) return { kind: 'bad', hash: sha(['large', r.size, r.digest]) };
  return { kind: 'ok', hash: r.digest };
}

/**
 * The files of a folder that an agent loads as they are, as project-relative names in a fixed order. A folder that is a link leaving the
 * project is not listed (it is one entry of its own); a link to a file is left to readRaw. `pick` chooses the files; `deep` goes into folders.
 */
// A file found by the walk: the first MAX_LISTED are listed, the next MAX_OVER_CAP are hashed together, and past that
// only their number is kept (memory stays bounded whatever the folder holds).
function keep(out, r) {
  if (out.files.length < MAX_LISTED) out.files.push(r);
  else if (out.extra.length < MAX_OVER_CAP) out.extra.push(r);
  else out.overLimit++;
}

function listFiles(root, realRoot, rel, pick, deep, out, bad) {
  const dir = path.join(root, rel);
  let lst;
  try { lst = fs.lstatSync(dir); } catch (_) { return; }
  if (lst.isSymbolicLink()) {
    let real;
    try { real = fs.realpathSync.native(dir); } catch (_) { bad(rel, sha(['broken-link'])); return; }
    if (!insideOf(realRoot, real)) { bad(rel, sha(['link-outside-folder'])); return; }
  }
  if (!lst.isDirectory() && !lst.isSymbolicLink()) { bad(rel, sha(['not-a-folder'])); return; }
  // Each real folder is read once per walk: a link back to a folder already seen (a loop) is one entry of its own.
  let realDir;
  try { realDir = fs.realpathSync.native(dir); } catch (_) { realDir = path.resolve(dir); }
  if (out.seen.has(realDir)) { bad(rel, sha(['folder-seen-before'])); return; }
  out.seen.add(realDir);
  if (out.seen.size > MAX_FOLDERS) { bad(rel, sha(['too-many-folders'])); return; }
  let list;
  // A folder that exists but cannot be listed counts as a change, like a file that cannot be read.
  try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { bad(rel, sha(['unreadable-folder', e && e.code])); return; }
  list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const e of list) {
    const r = rel + '/' + e.name;
    let isDir = e.isDirectory();
    if (e.isSymbolicLink()) {
      // A link to a folder inside the project is followed like a folder (it counts against the depth); one that
      // leaves the project, or that cannot be resolved, is an entry of its own. A link to a file is left to readRaw.
      let real = null;
      try { real = fs.realpathSync.native(path.join(root, r)); } catch (_) { real = null; }
      if (!real) {
        if (pick(e.name)) keep(out, r);
        continue;
      }
      let st = null;
      try { st = fs.statSync(real); } catch (_) { st = null; }
      // In a folder that is not searched below its top level, a link is left to readRaw like any file of that name.
      if (st && st.isDirectory() && deep >= 0) {
        if (!insideOf(realRoot, real)) { bad(r, sha(['link-outside-folder'])); continue; }
        isDir = true;
      }
    }
    if (isDir) {
      if (deep > 0) listFiles(root, realRoot, r, pick, deep - 1, out, bad);
      else if (deep === 0) bad(r, sha(['too-deep'])); // deeper than the search: recorded, not dropped
      continue;
    }
    if (!pick(e.name)) continue;
    keep(out, r);
  }
}

// An object with its keys sorted, so reordering is not a change; arrays keep their order (arguments are ordered).
function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}

// Each hook is hashed with the matcher of its group: a hook that no longer matches the tools it guarded is a change.
function hookCommands(hooks, out, rel) {
  if (!hooks || typeof hooks !== 'object') return;
  for (const event of Object.keys(hooks).sort()) {
    const groups = Array.isArray(hooks[event]) ? hooks[event] : [];
    groups.forEach((g, gi) => {
      const grouped = g && Array.isArray(g.hooks);
      const list = grouped ? g.hooks : [g];
      list.forEach((h, hi) => {
        if (h && typeof h === 'object') out[rel + '#hook:' + event + '.' + gi + '.' + hi] = sha(canon(grouped ? { matcher: g.matcher, hook: h } : h));
      });
    });
  }
}

function extractSurface(root) {
  const out = {};
  const realRoot = realOf(root);
  const bad = new Set();
  const read = (rel) => {
    const c = readConfig(root, realRoot, rel);
    if (c.kind === 'bad' && !bad.has(rel)) { bad.add(rel); out[rel + '#unreadable'] = c.hash; }
    return c.kind === 'ok' ? c.value : null;
  };
  for (const [rel, field] of MCP_FILES) {
    const j = read(rel);
    const servers = j && j[field];
    if (servers && typeof servers === 'object') for (const name of Object.keys(servers).sort()) out[rel + '#mcp:' + name] = sha(canon(servers[name]));
  }
  for (const rel of SETTINGS_FILES) {
    const j = read(rel);
    if (!j) continue;
    hookCommands(j.hooks, out, rel);
    if (j.env && typeof j.env === 'object') for (const k of Object.keys(j.env).sort()) if (ENV_RE.test(k)) out[rel + '#env:' + k] = sha(j.env[k]);
    if (j.permissions !== undefined) out[rel + '#permissions'] = sha(canon(j.permissions));
    for (const k of SCALAR_SETTINGS) if (j[k] !== undefined) out[rel + '#setting:' + k] = sha(canon(j[k]));
  }
  for (const rel of DEVCONTAINER_FILES) {
    const j = read(rel);
    if (j) for (const k of DEVCONTAINER_KEYS) if (j[k] !== undefined) out[rel + '#devcontainer:' + k] = sha(canon(j[k]));
  }
  const listed = [];
  // The cap is per folder: files in one folder cannot push another folder's files out of the baseline.
  for (const [dir, pick, deep] of WHOLE_FILES) {
    const found = { files: [], extra: [], overLimit: 0, seen: new Set() };
    listFiles(root, realRoot, dir, pick, deep, found, (rel, hash) => { out[rel + '#unreadable'] = hash; });
    listed.push(...found.files);
    if (found.extra.length || found.overLimit) {
      // The files past the cap are hashed by content (like the listed ones), together, so a change in one is a change.
      const parts = found.extra.map((rel) => {
        const c = readWhole(root, realRoot, rel);
        return [rel, c.kind, c.hash || null];
      });
      if (found.overLimit) parts.push(['over-limit', found.overLimit]);
      out[dir + '#over-cap'] = sha(parts);
    }
  }
  for (const rel of [...WHOLE_SINGLE, ...listed]) {
    const c = readWhole(root, realRoot, rel);
    if (c.kind === 'ok') out[rel + '#file'] = c.hash;
    else if (c.kind === 'bad') out[rel + '#unreadable'] = c.hash;
  }
  const pkg = read('package.json');
  if (pkg && pkg.scripts && typeof pkg.scripts === 'object') for (const k of LIFECYCLE) if (typeof pkg.scripts[k] === 'string') out['package.json#script:' + k] = sha(pkg.scripts[k]);
  const tasks = read('.vscode/tasks.json');
  if (tasks && Array.isArray(tasks.tasks)) {
    tasks.tasks.forEach((t, i) => {
      if (t && t.runOptions && t.runOptions.runOn === 'folderOpen') out['.vscode/tasks.json#task:' + String(t.label || i)] = sha(canon(t));
    });
  }
  return out;
}

function diffSurface(base, now) {
  const b = base && typeof base === 'object' ? base : {};
  const n = now && typeof now === 'object' ? now : {};
  const added = Object.keys(n).filter((k) => !(k in b)).sort();
  const removed = Object.keys(b).filter((k) => !(k in n)).sort();
  const changed = Object.keys(n).filter((k) => k in b && b[k] !== n[k]).sort();
  return { added, changed, removed };
}

// The real folder, with letter case folded where the file system ignores it, so a symlink to the project or another spelling finds the same baseline.
function baselinePath(home, root) {
  let real = realOf(root);
  if (process.platform === 'win32' || process.platform === 'darwin') real = real.toLowerCase();
  const id = crypto.createHash('sha256').update(real).digest('hex').slice(0, 32);
  return path.join(home, '.zn', 'baselines', id + '.json');
}

function saveBaseline(home, root, surface, now = new Date()) {
  const file = baselinePath(home, root);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, approved_at: now.toISOString(), entries: surface }), { mode: 0o600 });
  fs.renameSync(tmp, file);
  return file;
}

function loadBaseline(home, root) {
  try {
    const j = JSON.parse(fs.readFileSync(baselinePath(home, root), 'utf8'));
    if (!j || j.version !== 1 || !j.entries || typeof j.entries !== 'object' || Array.isArray(j.entries)) return null;
    for (const v of Object.values(j.entries)) if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v)) return null;
    return j.entries;
  } catch (_) {
    return null;
  }
}

module.exports = { extractSurface, diffSurface, baselinePath, saveBaseline, loadBaseline };
