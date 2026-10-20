'use strict';
/**
 * `zn audit`: static review of the agent configuration a repository ships.
 * Nothing is executed and nothing leaves the machine.
 *
 *   audit({ root, agents, includeHome, home, env }) -> { root, files, findings, truncated }
 *
 * Each finding: { id, severity, agent, file, line, title, detail, evidence,
 * fix, references }. `file` is relative to root (forward slashes), or starts
 * with "~/" for --include-home files. Evidence and detail go through the
 * scrubber, so secret values are never part of a finding.
 */

const fs = require('fs');
const { LINE_BREAKS } = require('../linear-text');
const os = require('os');
const path = require('path');
const { parseJsonc, parseToml } = require('./parse');
const P = require('./patterns');
const { BY_ID, RANK } = require('./rules');

const AGENTS = ['claude', 'codex', 'cursor', 'opencode', 'amazonq', 'copilot', 'gemini'];
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_DEPTH = 64;
const TIME_BUDGET_MS = 120000;
const LOCATE_WINDOW = 400;
const MAX_ENTRIES = 50000;
const EVIDENCE_MAX = 160;
const INSTRUCTION_READERS = ['codex', 'cursor', 'opencode', 'amazonq', 'copilot', 'gemini'];

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'vendor', 'dist', 'build', 'out', 'target', '.next', '.nuxt', '.turbo',
  '.venv', 'venv', '__pycache__', '.tox', '.mypy_cache', '.pytest_cache', '.ruff_cache', 'coverage', '.gradle',
  '.idea', 'Pods', 'bower_components', '.cache', 'site-packages', '.terraform', '.yarn', '.pnpm-store',
]);

/* ---------------------------- redaction ---------------------------- */

let scrubEngine = null;
function engine() {
  if (scrubEngine === null) {
    try { scrubEngine = require('../scrub/engine'); } catch (_) { scrubEngine = false; }
  }
  return scrubEngine || null;
}
let rulesLib = null;
function rules() {
  if (rulesLib === null) rulesLib = require('../rules');
  return rulesLib;
}

function secretSpans(text) {
  const e = engine();
  if (!e || !text) return [];
  try {
    return e.scan(text, { exact: false, pii: false });
  } catch (_) {
    return [];
  }
}

/** Text with every detected secret replaced by [REDACTED:<TYPE>]. */
function redact(text) {
  let s = String(text == null ? '' : text);
  const spans = secretSpans(s).sort((a, b) => b.start - a.start);
  for (const sp of spans) s = s.slice(0, sp.start) + '[REDACTED:' + sp.type + ']' + s.slice(sp.end);
  try { s = rules().redactSecrets(s).sanitized; } catch (_) { /* keep scrubber result */ }
  // Credentials in URLs (https://user:pass@host), and their query strings and
  // fragments, which often carry keys (?key=..., #access_token=...).
  s = s.replace(/(\b[a-z][a-z0-9+.-]{1,15}:\/\/)[^\s/@'"]{1,256}@/gi, '$1[REDACTED]@');
  s = s.replace(/(\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s?#'"]{1,2048})[?#][^\s'"]{1,4096}/gi, '$1?[REDACTED]');
  return redactByContext(s);
}

// Values in an unknown format, found by what precedes them: a credential flag (--token v, --api-key=v,
// --pat v), user:password after -u, an auth header (Authorization: Bearer v, x-api-key: v), a bearer token,
// or a name that ends in a secret word (API_TOKEN=v, "apiKey": "v", also inside escaped JSON).
// The secret word must end the name, so MAX_TOKENS or author are not secrets.
// References ($VAR, ${VAR}, %VAR%), zn markers and values already redacted are kept.
const SECRET_WORD = '(?:token|secret|passw(?:or)?d|pwd|api[-_]?key|access[-_]?key|private[-_]?key|auth|credentials?)';
// A quoted value runs to its closing quote, or to the end of the text when it has none; an unquoted one to
// the next delimiter. No length limit, so a long token (a JWT) is hidden whole. A value opened with \" (JSON
// inside a string) ends at the next \"; one opened with " may hold escaped quotes. Each alternative excludes
// what the other takes, so matching stays linear for each place a lead matches.
// Inside \"...\", a backslash arrives as \\\\ and an escaped quote as \\\": both stay in the value, the
// backslash tried first so that a value ending in one (\\\\\") still ends at its own \".
const QUOTED = String.raw`\\"(?:[^"\\\n]|\\\\\\\\|\\\\\\"|\\\\|\\[^"\\\n])+(?:\\")?|"(?:[^"\\\n]|\\.)+"?|'[^'\n]+'?`;
const CONTEXT_RES = [
  new RegExp('(--?[A-Za-z0-9]{0,40}(?:' + SECRET_WORD + '|pat|key)(?![a-z])[A-Za-z0-9-]{0,40}(?:=|\\s{1,8}))(' + QUOTED + '|[^\\s"\'`]+)', 'gi'),
  // user:password after -u or --user; attached to -u (-uuser:pass) too, but there not a URL, because a flag
  // such as -url:https://... is not a password.
  new RegExp('((?:^|\\s)(?:-u|--user)(?:=|\\s{1,8})["\']?[^\\s:"\']{1,128}:)([^\\s"\'@]+)', 'g'),
  new RegExp('((?:^|\\s)-u["\']?[^\\s:"\']{1,128}:)(?!//|[A-Za-z][A-Za-z0-9+.-]{0,15}://)([^\\s"\'@]+)', 'g'),
  new RegExp('(\\b(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|cookie)\\s{0,8}:\\s{0,8}(?:(?:bearer|basic|token)\\s{1,8})?)([^\\s"\'\\\\]+)', 'gi'),
  new RegExp('(\\bbearer\\s{1,8})([A-Za-z0-9._~+/=-]{8,})', 'gi'),
  // The flag and its value as two items of a JSON or TOML array (MCP server args): "--api-key", "v" (also
  // escaped, single-quoted, or with the value on the next line).
  new RegExp(String.raw`(\\{0,7}["']--?[A-Za-z0-9-]{0,40}(?:` + SECRET_WORD + String.raw`|pat|key)(?![a-z])[A-Za-z0-9-]{0,40}\\{0,7}["']\s{0,8},(?:\s|\\{1,3}[nrt]){0,128})(` + String.raw`\\{2,7}"(?:[^"\\\n]|\\{1,7}(?!"))+(?:\\{1,7}")?|` + QUOTED + ')', 'gi'),
  new RegExp('(\\b[A-Za-z0-9_]{0,60}' + SECRET_WORD + '(?![A-Za-z0-9])\\\\?["\']?\\s{0,8}[=:]\\s{0,8})(' + QUOTED + '|[^\\s"\'\\\\,;`]+)', 'gi'),
];
// A line that ends with a quoted flag item and a comma: the value is on the next line.
// Group 1 is the flag item; the line is tested after its trailing comment has been removed (stripComment).
const FLAG_ITEM_END = new RegExp(String.raw`(\\{0,7}["']--?[A-Za-z0-9-]{0,40}(?:` + SECRET_WORD + String.raw`|pat|key)(?![a-z])[A-Za-z0-9-]{0,40}\\{0,7}["']\s{0,8},?)$`, 'i');
// The line without its trailing comment (#, // or /*), found in one pass that knows about quoted strings.
function stripComment(l) {
  let q = '';
  for (let i = 0; i < l.length; i++) {
    const c = l[i];
    if (q) {
      if (c === '\\' && q === '"') i++;
      else if (c === q) q = '';
    } else if (c === '"' || c === "'") q = c;
    else if (c === '#' || (c === '/' && (l[i + 1] === '/' || l[i + 1] === '*'))) return l.slice(0, i);
  }
  return l;
}
const COMMENT_ONLY = /^\s*(?:#|\/\/|\/\*)/;
// How many blank or comment-only lines may sit between a flag and its value, and how much of the flag line
// (its end) is examined.
const GAP_LINES = 8;
const FLAG_LINE_TAIL = 512;
function keepValue(v) {
  const t = v.replace(/^\\{0,7}["']|\\{0,7}["']$/g, '');
  return !t || /^(?:\$\{?[A-Za-z_]|%[A-Za-z_]|\[REDACTED|__ZN_|<)/.test(t);
}
function redactByContext(s) {
  for (const re of CONTEXT_RES) s = s.replace(re, (m, lead, v) => (keepValue(v) ? m : lead + '[REDACTED]'));
  return s;
}

// Never clip before redacting: a value cut in half is no longer recognised. Only where far less than
// REDACT_SPAN is shown afterwards, text is cut first, at a space, after its whitespace is collapsed as
// clip() does: the word that the cut would split is dropped whole, so no part of a value reaches a finding.
const REDACT_SPAN = 8192;
function redactSpan(s) {
  let t = String(s == null ? '' : s).replace(/\s+/g, ' ');
  if (t.length > REDACT_SPAN) t = t.slice(0, REDACT_SPAN).replace(/\S*$/, '');
  return t;
}
function clip(s, max) {
  const t = String(s).replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max - 3) + '...' : t;
}

/** Redacted, then shortened: the only way raw file text enters a finding. */
function short(s, max) {
  return clip(redact(s), max);
}

/* --------------------------- file context -------------------------- */

// One level lower, for a file that may be the user's own (see FileCtx).
const LOWER = { critical: 'high', high: 'medium', medium: 'low', low: 'low' };
const IGNORED_ENV_NOTE = ' The .env file is listed in .gitignore: if it is your own local file and not one the repository ships, this does not apply.';

class FileCtx {
  constructor(rec, raw, out) {
    this.rec = rec;
    this.raw = raw;
    this.lines = raw.split(/\r?\n/);
    this.out = out;
    // Each source line is redacted once, however many findings it has.
    this.redacted = new Map();
  }

  redactedLine(ln) {
    // Only the start of a long line is ever shown, so only that much is redacted (well past what is shown).
    if (!this.redacted.has(ln)) {
      const cur = redactSpan(this.lines[ln - 1] || '');
      // A pretty-printed array puts a credential flag and its value on two lines, maybe with blank or comment
      // lines between: when the closest code line above ends with a quoted flag item (and maybe a comment),
      // redact both together and keep the second.
      let flag = null;
      for (let i = ln - 2, n = 0; i >= 0 && n < GAP_LINES + 1; i--, n++) {
        let l = this.lines[i];
        if (!l.trim() || COMMENT_ONLY.test(l)) continue;
        const t = l.trimEnd();
        if (t.endsWith('*/') && !t.includes('/*')) {
          // The end of a block comment that opened on an earlier line: skip it, up to its first line.
          let j = i - 1;
          while (j >= 0 && n < GAP_LINES && !this.lines[j].includes('/*')) { j--; n++; }
          if (j < 0 || n >= GAP_LINES) break;
          i = j;
          n++;
          l = this.lines[j];
          if (!l.slice(0, l.indexOf('/*')).trim()) continue;
        }
        const m = FLAG_ITEM_END.exec(stripComment(l).trimEnd().slice(-FLAG_LINE_TAIL));
        if (m) flag = m[1];
        break;
      }
      if (flag) {
        const joined = redact(flag + '\n' + cur);
        const at = joined.lastIndexOf('\n');
        this.redacted.set(ln, at >= 0 ? joined.slice(at + 1) : redact(cur));
      } else {
        this.redacted.set(ln, redact(cur));
      }
    }
    return this.redacted.get(ln);
  }

  /** Lines on which each JSON string token appears, built once per file. */
  tokens() {
    if (!this.tokenIndex) {
      this.tokenIndex = new Map();
      const re = /"(?:[^"\\\n]|\\.){0,512}"/g;
      this.lines.forEach((l, i) => {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(l)) !== null) {
          const list = this.tokenIndex.get(m[0]);
          if (!list) this.tokenIndex.set(m[0], [i + 1]);
          else if (list[list.length - 1] !== i + 1) list.push(i + 1);
        }
      });
    }
    return this.tokenIndex;
  }

  /**
   * 1-based line of `needle` at or after line `from`. A whole JSON string
   * token is looked up in the token index (binary search); any other text is
   * searched in the next WINDOW lines only, so locating stays linear overall.
   */
  find(needle, from) {
    const start = Math.max(1, from || 1);
    if (needle == null || needle === '') return start;
    if (needle.length > 1 && needle[0] === '"' && needle[needle.length - 1] === '"') {
      const list = this.tokens().get(needle);
      if (!list) return start;
      let lo = 0;
      let hi = list.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid] < start) lo = mid + 1; else hi = mid; }
      return lo < list.length ? list[lo] : list[0];
    }
    const end = Math.min(this.lines.length, start - 1 + LOCATE_WINDOW);
    for (let i = start - 1; i < end; i++) if (this.lines[i].includes(needle)) return i + 1;
    return start;
  }

  /** Line of a JSON key path (keys searched in order) and optional value. */
  locate(keys, value) {
    let line = 1;
    for (const k of keys) line = this.find(JSON.stringify(String(k)), line);
    if (value !== undefined && value !== null) {
      const v = JSON.stringify(String(value)).slice(1, -1).slice(0, 60);
      line = this.find(v, line);
    }
    return line;
  }

  add(id, severity, line, detail, extra) {
    const rule = BY_ID[id];
    const ln = Math.max(1, Math.min(line || 1, this.lines.length || 1));
    // A committed .env also listed in .gitignore: reported one level lower.
    if (this.rec.envIgnored) {
      severity = LOWER[severity] || severity;
      detail = String(detail) + IGNORED_ENV_NOTE;
    }
    this.out.push({
      id,
      severity,
      agent: (extra && extra.agent) || this.rec.agent,
      file: this.rec.display,
      line: ln,
      title: (extra && extra.title) || rule.title,
      detail: clip(redact(redactSpan(detail)), 600),
      evidence: clip((extra && extra.evidence != null) ? redact(extra.evidence) : this.redactedLine(ln), EVIDENCE_MAX),
      fix: (extra && extra.fix) || rule.fix,
      references: (extra && extra.references) || rule.references.slice(),
      _readers: (extra && extra.readers) || this.rec.readers,
    });
  }

  get home() { return this.rec.scope === 'home'; }
}

function capHome(ctx, severity) {
  if (!ctx.home) return severity;
  return RANK[severity] > RANK.medium ? 'medium' : severity;
}

/* ----------------------------- helpers ----------------------------- */

// The exact commands `zn hooks install` writes (lib/agents/config-file.js),
// matched against the whole command. A path may not contain shell
// metacharacters, so nothing can run before or after the zn runner.
const HOOK_AGENTS = '(?:claude-code|codex|cursor|opencode)';
const SAFE_ABS = '(?:/|[A-Za-z]:/)[^;&|$`<>(){}!*?"\'\\r\\n\\\\]{1,4096}';
const OUR_HOOKS = [
  new RegExp('^zn(?:-gate)?(?:\\.cmd|\\.exe)? hook ' + HOOK_AGENTS + '$'),
  new RegExp('^"(' + SAFE_ABS + ')" "(' + SAFE_ABS + '/zn-gate/lib/hooks/runner\\.js)" ' + HOOK_AGENTS + '$'),
  new RegExp('^powershell\\.exe -NoProfile -NonInteractive -Command "& \'(' + SAFE_ABS + ')\' \'(' + SAFE_ABS + '/zn-gate/lib/hooks/runner\\.js)\' ' + HOOK_AGENTS + '"$'),
];

function insideDir(dir, p) {
  const rel = path.relative(dir, p);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function realRootOf(ctx) {
  if (!ctx.rec.realRoot) {
    try { ctx.rec.realRoot = fs.realpathSync(ctx.rec.root); } catch (_) { ctx.rec.realRoot = path.resolve(ctx.rec.root); }
  }
  return ctx.rec.realRoot;
}

/**
 * Real path of `p` when it exists and lies outside the audited repository
 * and the current directory, after resolving every symbolic link (an
 * outside link or a /proc alias that points back into the checkout does not
 * count as outside). Null otherwise, including paths of another system.
 */
function realOutside(ctx, p) {
  if (process.platform !== 'win32' && /^[A-Za-z]:\//.test(p)) return null;
  let real;
  try { real = fs.realpathSync(p); } catch (_) { return null; }
  if (insideDir(realRootOf(ctx), real)) return null;
  let cwd = null;
  try { cwd = fs.realpathSync(process.cwd()); } catch (_) { cwd = null; }
  if (cwd && insideDir(cwd, real)) return null;
  return real;
}

/** Whether `real` is the file `relFile` of an installed zn-gate package. */
function znGateFile(real, relFile) {
  const norm = real.split(path.sep).join('/');
  if (!norm.endsWith('/' + relFile)) return false;
  const pkgRoot = real.slice(0, real.length - relFile.length - 1);
  const r = readBounded(path.join(pkgRoot, 'package.json'), 64 * 1024, true);
  if (!r.text) return false;
  try { return JSON.parse(r.text).name === 'zn-gate'; } catch (_) { return false; }
}

// Node.js interpreter names (`nodejs` on Debian and Ubuntu).
const NODE_NAME = /^(?:node|nodejs)(?:\.exe)?$/i;

function nodeOutside(ctx, p) {
  if (NODE_NAME.test(p)) return true; // resolved through PATH
  const real = realOutside(ctx, p);
  return Boolean(real) && NODE_NAME.test(path.basename(real));
}

/**
 * Whether a hook command is exactly one that `zn hooks install` writes, with
 * the interpreter and the runner resolved to a real zn-gate installation
 * outside the repository. Such hooks are still reported, as low.
 */
function isOurHook(command, ctx) {
  if (typeof command !== 'string') return false;
  const c = command.trim();
  for (const re of OUR_HOOKS) {
    const m = re.exec(c);
    if (!m) continue;
    if (!m[2]) return true; // `zn hook <agent>`: zn from PATH (a planted zn in the root is ZNA016)
    if (!nodeOutside(ctx, m[1])) return false;
    const runner = realOutside(ctx, m[2]);
    return Boolean(runner) && znGateFile(runner, 'lib/hooks/runner.js');
  }
  return false;
}

/** Every command string under a hooks tree: [{command, event}]. */
function hookCommands(tree) {
  const out = [];
  function walk(node, event, depth) {
    if (depth > 8 || node == null) return;
    if (Array.isArray(node)) { for (const n of node) walk(n, event, depth + 1); return; }
    if (typeof node !== 'object') return;
    for (const key of ['command', 'bash', 'powershell', 'commandWindows', 'windows', 'linux', 'osx']) {
      const v = node[key];
      if (typeof v === 'string' && v.trim()) out.push({ command: v, event });
      else if (Array.isArray(v) && v.length && v.every((x) => typeof x === 'string')) out.push({ command: v.join(' '), event });
    }
    for (const [k, v] of Object.entries(node)) {
      if (v && typeof v === 'object') walk(v, event || k, depth + 1);
    }
  }
  walk(tree, null, 0);
  return out;
}

function checkDownloadRun(ctx, command, line, what) {
  const hit = P.downloadAndRun(command);
  if (!hit) return false;
  ctx.add('ZNA002', 'critical', line, what + ' downloads code and runs it: ' + short(command, 200));
  return true;
}

function checkAutoRun(ctx, command, line, what) {
  checkDownloadRun(ctx, command, line, what);
  if (ctx.home) return;
  // Plugin hooks run only once someone installs and enables the plugin;
  // project settings act as soon as the folder is opened.
  const plugin = ctx.rec.kind === 'plugin-hooks' || ctx.rec.kind === 'claude-plugin';
  ctx.add('ZNA001', plugin ? 'medium' : 'high', line, what + (plugin ? ' runs automatically once the plugin is enabled: ' : ' runs automatically: ') + short(command, 200));
}

function checkHooks(ctx, tree, keyPath) {
  for (const h of hookCommands(tree)) {
    const line = ctx.locate(keyPath.concat(h.event ? [h.event] : []), h.command);
    if (isOurHook(h.command, ctx)) {
      // Never hidden: the zn hook stays visible, at low severity.
      if (!ctx.home) ctx.add('ZNA001', 'low', line, (h.event ? '"' + h.event + '" hook' : 'Hook') + ' runs the zn-gate hook installed by zn hooks install: ' + short(h.command, 200), { title: 'zn-gate hook' });
      continue;
    }
    checkAutoRun(ctx, h.command, line, (h.event ? '"' + h.event + '" hook' : 'Hook'));
  }
}

function checkEnv(ctx, env, keyPath, opts) {
  if (!env || typeof env !== 'object' || Array.isArray(env)) return;
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string' && typeof v !== 'number') continue;
    const c = P.classifyEnv(k, v);
    if (!c) continue;
    const line = opts && opts.lineOf ? opts.lineOf(k) : ctx.locate(keyPath.concat([k]));
    if (opts && opts.server) {
      // Environment of one MCP server: code loading is as bad as anywhere;
      // an endpoint or proxy redirects that server's own credentials.
      const who = 'MCP server "' + opts.server + '": ';
      if (c.kind === 'endpoint') ctx.add('ZNA007', capHome(ctx, c.loopback ? 'low' : 'medium'), line, who + k + ' points to ' + P.safeUrl(v) + '; the server sends its requests and credentials there.', { title: 'MCP server endpoint overridden by the project' });
      else if (c.kind === 'proxy') ctx.add('ZNA007', capHome(ctx, c.loopback ? 'low' : 'medium'), line, who + k + ' routes the server\'s traffic through ' + (c.host || 'a proxy') + '.', { title: 'MCP server traffic routed through a proxy set by the project' });
      else ctx.add('ZNA008', capHome(ctx, 'high'), line, who + k + ' is set for the server process' + (c.kind === 'confdir' ? ' and moves where it reads its configuration.' : ' and loads code or certificates into it.'));
      continue;
    }
    if (c.kind === 'endpoint') {
      const sev = capHome(ctx, c.loopback ? 'medium' : 'critical');
      ctx.add('ZNA007', sev, line, k + ' points to ' + P.safeUrl(v) + (c.loopback ? ' (a local address)' : '') + '; the agent sends its API key and prompts there.');
    } else if (c.kind === 'proxy') {
      const sev = capHome(ctx, c.loopback ? 'medium' : 'high');
      ctx.add('ZNA007', sev, line, k + ' routes the agent\'s traffic through ' + (c.host || 'a proxy') + '.', { title: 'Agent traffic routed through a proxy set by the project' });
    } else if (c.kind === 'confdir') {
      ctx.add('ZNA008', capHome(ctx, 'high'), line, k + ' moves where the agent reads its own configuration (to ' + v + '), so a config shipped in the repository is loaded instead of yours.', { title: 'Environment variable redirects the agent configuration' });
    } else {
      ctx.add('ZNA008', capHome(ctx, 'high'), line, k + ' is set for every process the agent starts.');
    }
  }
}

function endpointValue(ctx, key, value, line) {
  if (typeof value !== 'string' || P.isPlaceholder(value)) return;
  const host = P.hostOf(value);
  if (!host) return;
  const loop = P.isLoopback(host);
  ctx.add('ZNA007', capHome(ctx, loop ? 'medium' : 'critical'), line, key + ' points to ' + P.safeUrl(value) + (loop ? ' (a local address)' : '') + '; the agent sends its API key and prompts there.');
}

// The exact "secrets" MCP server `zn hooks install` writes: `zn secrets-mcp`
// or `<node> <abs>/zn-gate/bin/cli.js secrets-mcp`, with nothing else, the
// paths resolved to a real zn-gate installation outside the repository.
function isOurMcp(argv, ctx) {
  let words = argv.map(String);
  // `zn hooks install` adds "--agent <id>" (an id as `zn run` accepts it).
  if (words.length >= 4 && words[words.length - 2] === '--agent' && /^[a-z0-9-]{1,32}$/.test(words[words.length - 1])) {
    words = words.slice(0, -2);
  }
  if (words[words.length - 1] !== 'secrets-mcp') return false;
  if (words.length === 2) return /^zn(?:-gate)?(?:\.cmd|\.exe)?$/.test(words[0]);
  if (words.length !== 3) return false;
  const node = words[0].replace(/\\/g, '/');
  if (!NODE_NAME.test(node) && !new RegExp('^' + SAFE_ABS + '/(?:node|nodejs)(?:\\.exe)?$', 'i').test(node)) return false;
  if (!nodeOutside(ctx, node)) return false;
  const cli = words[1].replace(/\\/g, '/');
  if (!new RegExp('^' + SAFE_ABS + '/zn-gate/bin/cli\\.js$').test(cli)) return false;
  const real = realOutside(ctx, cli);
  return Boolean(real) && znGateFile(real, 'bin/cli.js');
}

function mcpArgv(cfg) {
  if (Array.isArray(cfg.command)) return cfg.command.map(String);
  if (typeof cfg.command !== 'string' || !cfg.command.trim()) return null;
  const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
  return args.length ? [cfg.command].concat(args) : P.splitCommand(cfg.command);
}

function checkMcpServers(ctx, servers, keyPath, opts) {
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return;
  const o = opts || {};
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;
    const line = o.lineOf ? o.lineOf(name) : ctx.locate(keyPath.concat([name]));
    const own = (k) => Object.prototype.hasOwnProperty.call(cfg, k);
    if ((own('disabled') && cfg.disabled === true) || (own('enabled') && cfg.enabled === false)) continue;
    // The environment of every server, zn's own included.
    const env = cfg.env || cfg.environment;
    if (env) checkEnv(ctx, env, keyPath.concat([name, cfg.env ? 'env' : 'environment']), { server: name, lineOf: o.envLineOf ? o.envLineOf(name) : undefined });
    const argv = mcpArgv(cfg);
    if (argv && argv.length) {
      const cmd = argv.join(' ');
      if (isOurMcp(argv, ctx)) {
        if (!ctx.home) ctx.add('ZNA003', 'low', line, 'MCP server "' + name + '" is the zn secrets server installed by zn hooks install: ' + short(cmd, 200), { title: 'zn-gate secrets MCP server' });
      } else {
        checkDownloadRun(ctx, cmd, line, 'MCP server "' + name + '"');
        if (!ctx.home) {
          const sev = o.severity || 'medium';
          ctx.add('ZNA003', sev, line, 'MCP server "' + name + '" runs: ' + short(cmd, 200) + (o.note ? ' ' + o.note : ''));
        }
        for (const pkg of P.packagesOf(argv)) {
          if (!pkg.pinned) ctx.add('ZNA005', 'medium', line, 'MCP server "' + name + '" runs ' + pkg.spec + ' through ' + pkg.manager + ' without an exact version.');
        }
      }
    }
    const url = [cfg.url, cfg.httpUrl, cfg.serverUrl, cfg.endpoint].find((u) => typeof u === 'string' && u.trim());
    if (url && !P.isPlaceholder(url)) {
      const host = P.hostOf(url);
      if (host && !P.isLoopback(host)) {
        const plain = /^http:/i.test(url) || /^ws:/i.test(url);
        if (plain) ctx.add('ZNA006', 'medium', line, 'MCP server "' + name + '" uses unencrypted ' + P.safeUrl(url) + '.');
        else if (!ctx.home) ctx.add('ZNA006', 'low', line, 'MCP server "' + name + '" is remote: ' + P.safeUrl(url) + '.');
      }
    }
  }
}

/* ------------------------- per-kind checks ------------------------- */

const HELPER_KEYS = ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper', 'gcpAuthRefresh'];

function checkClaudeSettings(ctx, data) {
  if (data.hooks && typeof data.hooks === 'object') checkHooks(ctx, data.hooks, ['hooks']);
  if (data.statusLine && typeof data.statusLine === 'object' && typeof data.statusLine.command === 'string') {
    checkAutoRun(ctx, data.statusLine.command, ctx.locate(['statusLine', 'command']), 'Status line command');
  }
  if (data.fileSuggestion && typeof data.fileSuggestion === 'object' && typeof data.fileSuggestion.command === 'string') {
    checkAutoRun(ctx, data.fileSuggestion.command, ctx.locate(['fileSuggestion', 'command']), 'File suggestion command');
  }
  for (const k of HELPER_KEYS) {
    if (typeof data[k] !== 'string' || !data[k].trim()) continue;
    const line = ctx.locate([k]);
    checkDownloadRun(ctx, data[k], line, k);
    if (!ctx.home) ctx.add('ZNA009', 'high', line, k + ' runs: ' + short(data[k], 200));
  }
  checkEnv(ctx, data.env, ['env']);
  const perms = data.permissions && typeof data.permissions === 'object' ? data.permissions : {};
  if (Array.isArray(perms.allow)) {
    for (const entry of perms.allow) {
      const sev = P.claudePermission(entry);
      if (sev) ctx.add('ZNA010', capHome(ctx, sev), ctx.locate(['permissions', 'allow'], entry), 'permissions.allow contains ' + JSON.stringify(String(entry)) + ', which allows any command.');
    }
  }
  if (perms.defaultMode === 'bypassPermissions') {
    ctx.add('ZNA010', capHome(ctx, 'high'), ctx.locate(['permissions', 'defaultMode']), 'permissions.defaultMode is bypassPermissions: no prompts at all.');
  }
  if (data.skipDangerousModePermissionPrompt === true) {
    ctx.add('ZNA010', capHome(ctx, 'medium'), ctx.locate(['skipDangerousModePermissionPrompt']), 'skipDangerousModePermissionPrompt hides the warning before bypass mode.');
  }
  if (!ctx.home) {
    if (data.enableAllProjectMcpServers === true) {
      ctx.add('ZNA004', 'high', ctx.locate(['enableAllProjectMcpServers']), 'enableAllProjectMcpServers starts every server in .mcp.json without asking.');
    }
    if (Array.isArray(data.enabledMcpjsonServers) && data.enabledMcpjsonServers.length) {
      ctx.add('ZNA004', 'medium', ctx.locate(['enabledMcpjsonServers']), 'enabledMcpjsonServers approves ' + data.enabledMcpjsonServers.map(String).slice(0, 5).join(', ') + ' in advance.');
    }
    const plugins = data.enabledPlugins && typeof data.enabledPlugins === 'object' ? Object.keys(data.enabledPlugins).filter((k) => data.enabledPlugins[k]) : [];
    if (plugins.length) ctx.add('ZNA017', 'medium', ctx.locate(['enabledPlugins']), 'enabledPlugins turns on ' + plugins.slice(0, 5).join(', ') + '.');
    if (data.extraKnownMarketplaces && typeof data.extraKnownMarketplaces === 'object' && Object.keys(data.extraKnownMarketplaces).length) {
      ctx.add('ZNA017', 'medium', ctx.locate(['extraKnownMarketplaces']), 'extraKnownMarketplaces adds ' + Object.keys(data.extraKnownMarketplaces).slice(0, 5).join(', ') + ' as plugin sources.');
    }
  }
  if (data.mcpServers) checkMcpServers(ctx, data.mcpServers, ['mcpServers'], { severity: 'medium' });
}

function checkClaudeUserJson(ctx, data) {
  checkMcpServers(ctx, data.mcpServers, ['mcpServers']);
  if (data.projects && typeof data.projects === 'object') {
    for (const [proj, cfg] of Object.entries(data.projects)) {
      if (cfg && cfg.mcpServers) checkMcpServers(ctx, cfg.mcpServers, ['projects', proj, 'mcpServers']);
    }
  }
}

const MCP_SEVERITY = { amazonq: 'high', codex: 'high' };

function checkMcpJson(ctx, data) {
  const key = ctx.rec.kind === 'vscode-mcp' ? 'servers' : 'mcpServers';
  const sev = MCP_SEVERITY[ctx.rec.agent] || 'medium';
  const note = sev === 'high' ? '(' + (ctx.rec.agent === 'amazonq' ? 'Amazon Q' : 'Codex') + ' versions affected by ' + (ctx.rec.agent === 'amazonq' ? 'CVE-2026-12957' : 'CVE-2025-61260') + ' start it without asking.)' : '';
  checkMcpServers(ctx, data[key], [key], { severity: sev, note });
}

function tomlLineOf(lines, prefix) {
  return (k) => lines[prefix.concat([k]).join('.')] || lines[prefix.join('.')] || 1;
}

function checkCodexToml(ctx, data, lines) {
  if (data.mcp_servers && typeof data.mcp_servers === 'object') {
    checkMcpServers(ctx, data.mcp_servers, [], {
      severity: 'high',
      note: '(Codex versions affected by CVE-2025-61260 start it without asking.)',
      lineOf: tomlLineOf(lines, ['mcp_servers']),
      envLineOf: (name) => tomlLineOf(lines, ['mcp_servers', name, 'env']),
    });
  }
  if (Array.isArray(data.notify) && data.notify.length) {
    checkAutoRun(ctx, data.notify.map(String).join(' '), lines.notify || 1, 'notify command');
  }
  const scopes = [{ cfg: data, prefix: [] }];
  if (data.profiles && typeof data.profiles === 'object') {
    for (const [name, p] of Object.entries(data.profiles)) if (p && typeof p === 'object') scopes.push({ cfg: p, prefix: ['profiles', name] });
  }
  for (const { cfg, prefix } of scopes) {
    const where = prefix.length ? ' (profile ' + prefix[1] + ')' : '';
    const never = cfg.approval_policy === 'never';
    const full = cfg.sandbox_mode === 'danger-full-access';
    const ln = lines[prefix.concat([full ? 'sandbox_mode' : 'approval_policy']).join('.')] || 1;
    if (never && full) ctx.add('ZNA010', capHome(ctx, 'high'), ln, 'approval_policy = "never" with sandbox_mode = "danger-full-access"' + where + ': any command, no prompt, no sandbox.');
    else if (full) ctx.add('ZNA010', capHome(ctx, 'medium'), ln, 'sandbox_mode = "danger-full-access"' + where + ' turns the sandbox off.');
    else if (never && !ctx.home) ctx.add('ZNA010', 'medium', ln, 'approval_policy = "never"' + where + ': commands run without a prompt.');
    for (const k of ['openai_base_url', 'chatgpt_base_url', 'experimental_base_url']) {
      if (typeof cfg[k] === 'string') endpointValue(ctx, k, cfg[k], lines[prefix.concat([k]).join('.')] || 1);
    }
  }
  if (data.model_providers && typeof data.model_providers === 'object') {
    for (const [name, p] of Object.entries(data.model_providers)) {
      if (p && typeof p.base_url === 'string') endpointValue(ctx, 'model_providers.' + name + '.base_url', p.base_url, lines['model_providers.' + name + '.base_url'] || lines['model_providers.' + name] || 1);
    }
  }
  const sep = data.shell_environment_policy;
  if (sep && sep.set && typeof sep.set === 'object') {
    checkEnv(ctx, sep.set, [], { lineOf: tomlLineOf(lines, ['shell_environment_policy', 'set']) });
  }
}

function checkHooksJson(ctx, data) {
  if (data.hooks && typeof data.hooks === 'object') checkHooks(ctx, data.hooks, ['hooks']);
}

function checkAmazonqAgent(ctx, data) {
  checkMcpServers(ctx, data.mcpServers, ['mcpServers'], { severity: 'high', note: '(Amazon Q versions affected by CVE-2026-12957 start it without asking.)' });
  if (data.hooks && typeof data.hooks === 'object') checkHooks(ctx, data.hooks, ['hooks']);
  if (Array.isArray(data.allowedTools)) {
    for (const t of data.allowedTools) {
      if (t === '*' || t === '@builtin' || t === 'execute_bash' || t === 'execute_cmd' || t === 'shell') {
        ctx.add('ZNA010', capHome(ctx, 'high'), ctx.locate(['allowedTools'], t), 'allowedTools contains ' + JSON.stringify(t) + ': shell commands run without a prompt.');
      }
    }
  }
}

function checkVscodeSettings(ctx, data) {
  for (const k of ['chat.tools.autoApprove', 'chat.tools.global.autoApprove']) {
    if (data[k] === true) ctx.add('ZNA010', capHome(ctx, 'high'), ctx.locate([k]), k + ' approves every tool call, terminal commands included.', { agent: 'copilot' });
  }
}

function checkVscodeTasks(ctx, data) {
  if (!Array.isArray(data.tasks)) return;
  for (const t of data.tasks) {
    if (!t || typeof t !== 'object' || !t.runOptions || t.runOptions.runOn !== 'folderOpen') continue;
    const argv = [t.command].concat(Array.isArray(t.args) ? t.args : []).filter((x) => typeof x === 'string');
    const cmd = argv.join(' ') || String(t.label || 'task');
    checkAutoRun(ctx, cmd, ctx.locate(['runOn'], 'folderOpen'), 'Task "' + String(t.label || '?') + '" (runOn: folderOpen)');
  }
}

function checkCursorCli(ctx, data) {
  const allow = data.permissions && Array.isArray(data.permissions.allow) ? data.permissions.allow : [];
  for (const entry of allow) {
    const sev = P.claudePermission(entry);
    if (sev) ctx.add('ZNA010', capHome(ctx, sev), ctx.locate(['permissions', 'allow'], entry), 'permissions.allow contains ' + JSON.stringify(String(entry)) + ', which allows any command.');
  }
}

function checkGeminiSettings(ctx, data) {
  checkMcpServers(ctx, data.mcpServers, ['mcpServers']);
  if (data.hooks && typeof data.hooks === 'object') checkHooks(ctx, data.hooks, ['hooks']);
  const allowed = data.tools && Array.isArray(data.tools.allowed) ? data.tools.allowed : (Array.isArray(data.coreToolsAllowed) ? data.coreToolsAllowed : []);
  for (const t of allowed) {
    if (t === 'run_shell_command' || t === 'ShellTool' || t === '*') ctx.add('ZNA010', capHome(ctx, 'high'), ctx.locate(['allowed'], t), 'The shell tool is allowed without a prompt.');
  }
}

function checkOpencodeJson(ctx, data) {
  if (data.mcp && typeof data.mcp === 'object') checkMcpServers(ctx, data.mcp, ['mcp']);
  const perm = data.permission;
  const bash = perm && typeof perm === 'object' ? perm.bash : undefined;
  if (perm === 'allow' || (perm && perm['*'] === 'allow')) {
    ctx.add('ZNA010', capHome(ctx, 'high'), ctx.locate(['permission']), 'permission allows every tool without a prompt.');
  } else if (bash === 'allow' || (bash && typeof bash === 'object' && bash['*'] === 'allow')) {
    ctx.add('ZNA010', capHome(ctx, 'high'), ctx.locate(['permission', 'bash']), 'permission.bash allows every command without a prompt.');
  }
  if (Array.isArray(data.plugin) && data.plugin.length) {
    const npm = data.plugin.filter((p) => typeof p === 'string' && P.npmSpec(p));
    if (npm.length && !ctx.home) ctx.add('ZNA017', 'medium', ctx.locate(['plugin']), 'OpenCode loads the npm plugins ' + npm.slice(0, 5).join(', ') + ' at start.');
    for (const p of npm) {
      if (!P.pinnedNpm(P.npmSpec(p).version)) ctx.add('ZNA005', 'medium', ctx.locate(['plugin'], p), 'Plugin ' + p + ' has no exact version.');
    }
  }
  if (Array.isArray(data.instructions)) {
    for (const ins of data.instructions) {
      if (typeof ins !== 'string' || !/^https?:\/\//i.test(ins)) continue;
      const plain = /^http:/i.test(ins);
      if (plain || !ctx.home) ctx.add('ZNA006', plain ? 'medium' : 'low', ctx.locate(['instructions'], ins), 'Instructions are loaded from ' + P.safeUrl(ins) + ' and can change after review.', { title: 'Agent instructions loaded from a URL' });
    }
  }
  if (data.provider && typeof data.provider === 'object') {
    for (const [name, p] of Object.entries(data.provider)) {
      const url = p && p.options && (p.options.baseURL || p.options.baseUrl);
      if (typeof url === 'string') endpointValue(ctx, 'provider.' + name + '.options.baseURL', url, ctx.locate(['provider', name, 'baseURL']));
    }
  }
}

function checkClaudePlugin(ctx, data) {
  if (data.hooks && typeof data.hooks === 'object') checkHooks(ctx, data.hooks, ['hooks']);
  if (data.mcpServers && typeof data.mcpServers === 'object') checkMcpServers(ctx, data.mcpServers, ['mcpServers']);
}

function checkDotenv(ctx) {
  ctx.lines.forEach((l, i) => {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(l);
    if (!m) return;
    const value = m[2].trim().replace(/^(['"])(.*)\1$/, '$2');
    checkEnv(ctx, { [m[1]]: value }, [], { lineOf: () => i + 1 });
  });
}

function checkOpencodePlugin(ctx) {
  ctx.add('ZNA001', 'high', 1, 'OpenCode loads ' + path.basename(ctx.rec.abs) + ' as a plugin and runs it at start.', { evidence: ctx.lines.find((l) => l.trim()) || '' });
  ctx.lines.forEach((l, i) => { checkDownloadRun(ctx, l, i + 1, 'The plugin'); });
}

/* ------------------------- instruction files ------------------------ */

const INVISIBLE = /[\u{E0000}-\u{E007F}\u{202A}-\u{202E}\u{2066}-\u{2069}]/u;
const INVISIBLE_ALL = /[\u{E0000}-\u{E007F}\u{202A}-\u{202E}\u{2066}-\u{2069}]/gu;
// Rules tuned for prompts that are too noisy in documentation ("act as",
// "never print tokens", mentions of .env): left to ZNA011 and ZNA014.
const NOISY_IN_DOCS = /^(?:secret|path):|^exfil:credentials$|^pi:(?:act_as|pretend|roleplay|bypass)$/;
// "Any prompt injection (e.g. 'Ignore previous instructions...') is spam":
// an attack quoted as an example.
const EXAMPLE_QUOTE = /\b(?:e\.g\.|eg\.|i\.e\.|for example|for instance|such as|like)\s{0,3}[,:]?\s{0,3}["'`]/i;
const EXAMPLE_QUOTED_TEXT = /(\b(?:e\.g\.|eg\.|i\.e\.|for example|for instance|such as|like)\s{0,3}[,:]?\s{0,3})(["'`])[^"'`\n]{0,400}\2/gi;

/** Whether the strong pattern of `text` sits inside the quotes of an example. */
function insideQuotedExample(text) {
  const without = text.replace(EXAMPLE_QUOTED_TEXT, '$1""');
  if (without === text) return false;
  let res = null;
  try { res = rules().evaluate(without, { strict: true }); } catch (_) { return false; }
  return !(res && res.verdict === 'block' && STRONG_IN_DOCS.test(String(res.rule)));
}
const STRONG_IN_DOCS =/^(?:pi:(?:ignore_previous|disregard|system_tag|system_bracket|template_boundary|multi_\w+)|indirect:|evasion:|exfil:markdown_image)/;

function checkInstructions(ctx) {
  const claudeExt = /(^|\/)\.claude\/(commands|agents|skills)\//.test(ctx.rec.rel);
  // Supporting notes of a skill (not SKILL.md itself): the only files here
  // that are not read as instructions.
  const supporting = /(^|\/)skills?\/.+\//.test(ctx.rec.rel) && !/(^|\/)SKILL\.md$/i.test(ctx.rec.rel);
  let inFront = ctx.lines[0] && ctx.lines[0].trim() === '---';
  // Lines inside code fences that are closed again (an unclosed fence runs
  // to the end of the file and counts as plain text).
  const fenced = new Set();
  for (let i = 0, open = -1; i < ctx.lines.length; i++) {
    if (!/^\s*(?:```|~~~)/.test(ctx.lines[i])) continue;
    if (open < 0) { open = i; continue; }
    for (let k = open + 1; k < i; k++) fenced.add(k);
    open = -1;
  }
  ctx.lines.forEach((raw, i) => {
    const ln = i + 1;
    const line = raw.length > P.MAX_LINE ? raw.slice(0, P.MAX_LINE) : raw;
    if (inFront && i > 0 && line.trim() === '---') inFront = false;
    if (inFront && claudeExt) {
      const m = /^\s*(?:allowed-tools|tools)\s*:\s*(.*)$/.exec(line) || /^\s*-\s*(.+)$/.exec(line);
      if (m) {
        for (const entry of m[1].replace(/^\[|\]$/g, '').split(/,(?![^(]*\))/)) {
          const e = entry.trim().replace(/^["']|["']$/g, '');
          if (e && P.claudePermission(e)) ctx.add('ZNA010', 'high', ln, 'The extension allows ' + JSON.stringify(e) + ' without a prompt.');
        }
      }
    }
    const t = line.trim();
    if (t.length < 8) return;
    if (INVISIBLE.test(line)) {
      ctx.add('ZNA012', 'high', ln, 'The line contains invisible Unicode (tag or bidirectional control characters) that can hide text from reviewers.', { evidence: line.replace(INVISIBLE_ALL, '?') });
    } else {
      let res = null;
      // Strict mode: audit grades each finding itself (high, medium, info).
      try { res = rules().evaluate(t, { strict: true }); } catch (_) { res = null; }
      if (res && res.verdict === 'block' && !NOISY_IN_DOCS.test(String(res.rule))) {
        // Strong patterns are high, weaker ones medium. In the files an agent
        // reads as its instructions a strong pattern is never lowered: the
        // agent reads it the same, quoted or not. In supporting files (a
        // skill's reference notes) it is lowered only when the match lies
        // inside the quotes of an example ("e.g. '...'"): the line without
        // the quoted text must no longer match. A weak pattern is lowered by
        // an example marker or a properly closed code block. A blockquote or
        // an unclosed fence never lowers anything.
        const strong = STRONG_IN_DOCS.test(String(res.rule));
        let sev = strong ? 'high' : 'medium';
        let quoted;
        if (strong) quoted = supporting && insideQuotedExample(t);
        else quoted = EXAMPLE_QUOTE.test(t) || fenced.has(i);
        if (quoted) sev = strong ? 'medium' : 'low';
        ctx.add('ZNA012', sev, ln, 'Rules engine: ' + (res.reason || res.rule) + (quoted ? ' (in quoted or code text)' : '') + '.');
      }
    }
    const dl = P.downloadAndRun(t, { prose: true });
    if (dl) ctx.add('ZNA013', dl.knownInstaller ? 'low' : 'medium', ln, (dl.knownInstaller ? 'A well-known installer is piped into a shell: ' : 'The instructions pipe a download into a shell: ') + short(t, 160));
    const ex = P.exfiltration(t);
    if (ex) ctx.add('ZNA014', 'high', ln, 'The instructions send sensitive material out: ' + short(t, 160));
    const wk = P.weakening(t);
    if (wk) ctx.add('ZNA015', 'medium', ln, 'The instructions weaken a safety check: ' + short(t, 160));
  });
}

/* ---------------------------- workflows ----------------------------- */

const CI_AGENT_ACTIONS = [
  [/anthropics\/claude-code(?:-base)?-action@/i, 'claude'],
  [/google-github-actions\/run-gemini-cli@/i, 'gemini'],
  [/openai\/codex-action@/i, 'codex'],
  [/(?:sst|anomalyco)\/opencode[\w/-]*@/i, 'opencode'],
  [/aws-actions\/[\w-]*amazon-q[\w-]*@/i, 'amazonq'],
  [/github\/copilot[\w-]*@/i, 'copilot'],
];
const CI_AGENT_RUN = [
  [/\bclaude\s+(?:-p|--print)\b/, 'claude'],
  [/\bcodex\s+exec\b/, 'codex'],
  [/\bgemini\s+(?:-p|--prompt)\b/, 'gemini'],
  [/\bopencode\s+run\b/, 'opencode'],
  [/\bq\s+chat\s+--no-interactive\b/, 'amazonq'],
];
const UNTRUSTED_TRIGGERS = ['issue_comment', 'issues', 'pull_request_target', 'pull_request_review_comment', 'pull_request_review', 'discussion', 'discussion_comment'];

function checkWorkflow(ctx) {
  let agentLine = 0;
  let agent = null;
  let viaRun = false;
  ctx.lines.forEach((l, i) => {
    if (agent) return;
    if (/^\s*#/.test(l)) return;
    for (const [re, a] of CI_AGENT_ACTIONS) if (/\buses\s*:/.test(l) && re.test(l)) { agent = a; agentLine = i + 1; return; }
    for (const [re, a] of CI_AGENT_RUN) if (re.test(l)) { agent = a; agentLine = i + 1; viaRun = true; return; }
  });
  if (!agent) return;
  const jobsAt = ctx.lines.findIndex((l) => /^jobs\s*:/.test(l));
  const head = (jobsAt < 0 ? ctx.lines : ctx.lines.slice(0, jobsAt)).filter((l) => !/^\s*#/.test(l)).join('\n');
  const triggers = UNTRUSTED_TRIGGERS.filter((t) => new RegExp('(?:^|[\\s\\[,])' + t + '(?:\\s*:|\\s*[,\\]]|\\s*$)', 'm').test(head));
  if (!triggers.length) return;
  const text = ctx.lines.filter((l) => !/^\s*#/.test(l)).join('\n');
  const prt = triggers.includes('pull_request_target');
  const write = /permissions\s*:\s*write-all\b/.test(text) || grantsWrite(text);
  const interpolated = /\$\{\{\s*github\.event\.(?:issue|comment|pull_request|review|discussion)\.(?:body|title)\b/.test(text);
  const authorFilter = /author_association|github\.actor\s*==|github\.event\.(?:comment|issue|sender)\.user\.login\s*==/.test(text);
  // Opened to any author on purpose (claude-code-action otherwise requires
  // the actor to have write access to the repository).
  const opened = /\ballowed_non_write_users\s*:|\ballow[_-]users\s*:\s*["']?\*/.test(text);
  // High only when untrusted text clearly reaches the agent with privileges;
  // write permissions alone are medium, since the common agent actions check
  // the actor's own permission before running.
  // A CLI run step has no built-in actor check, so write access without an
  // author filter is high there too.
  const severity = prt || interpolated || opened || (viaRun && write && !authorFilter) ? 'high' : 'medium';
  const why = [];
  why.push('triggered by ' + triggers.join(', '));
  if (prt) why.push('pull_request_target runs with the base repository\'s secrets');
  if (interpolated) why.push('issue or comment text is pasted into the workflow');
  if (opened) why.push('the action is opened to users without write access');
  if (write) why.push('the workflow has write permissions');
  if (authorFilter) why.push('an author filter is present');
  ctx.add('ZNA019', severity, agentLine, 'An AI agent (' + agent + ') runs on input from outside the team: ' + why.join('; ') + '.', { agent, readers: [agent] });
}

/* ---------------------------- discovery ----------------------------- */

function rule(kind, agent, readers) {
  return { kind, agent, readers: readers || [agent] };
}

/** Classify a project file by its path relative to the root (forward slashes). */
function classify(rel, isRootLevel) {
  const base = rel.slice(rel.lastIndexOf('/') + 1);
  const lower = base.toLowerCase();
  const has = (re) => re.test(rel);
  if (has(/(^|\/)\.claude\/settings(\.local)?\.json$/)) return rule('claude-settings', 'claude', ['claude', 'cursor']);
  if (base === '.mcp.json') return rule('mcp-json', 'claude');
  if (has(/(^|\/)\.cursor\/mcp\.json$/)) return rule('mcp-json', 'cursor');
  if (has(/(^|\/)\.amazonq\/(?:default\.)?mcp\.json$/)) return rule('mcp-json', 'amazonq');
  if (has(/(^|\/)\.amazonq\/(?:cli-)?agents\/[^/]+\.json$/)) return rule('amazonq-agent', 'amazonq');
  if (has(/(^|\/)\.vscode\/mcp\.json$/)) return rule('vscode-mcp', 'copilot', ['copilot', 'cursor']);
  if (has(/(^|\/)\.vscode\/settings\.json$/)) return rule('vscode-settings', 'copilot', ['copilot', 'cursor']);
  if (has(/(^|\/)\.vscode\/tasks\.json$/)) return rule('vscode-tasks', 'cursor', ['cursor', 'copilot']);
  if (has(/(^|\/)\.codex\/config\.toml$/)) return rule('codex-toml', 'codex');
  if (has(/(^|\/)\.codex\/hooks\.json$/)) return rule('hooks-json', 'codex');
  if (has(/(^|\/)\.cursor\/hooks\.json$/)) return rule('hooks-json', 'cursor');
  if (has(/(^|\/)\.cursor\/cli\.json$/)) return rule('cursor-cli', 'cursor');
  if (has(/(^|\/)\.gemini\/settings\.json$/)) return rule('gemini-settings', 'gemini');
  if (/^opencode\.jsonc?$/.test(base) && (isRootLevel || has(/(^|\/)\.opencode\/opencode\.jsonc?$/) || !rel.includes('/'))) return rule('opencode-json', 'opencode');
  if (has(/(^|\/)\.opencode\/plugins?\/[^/]+\.(?:js|mjs|cjs|ts|mts)$/)) return rule('opencode-plugin', 'opencode');
  if (has(/(^|\/)\.claude-plugin\/plugin\.json$/)) return rule('claude-plugin', 'claude');
  if (has(/(^|\/)\.claude-plugin\/marketplace\.json$/)) return rule('config-other', 'claude');
  if (has(/(^|\/)hooks\/hooks\.json$/)) return rule('plugin-hooks', 'claude');
  if (base === '.env' && isRootLevel) return rule('dotenv', 'codex');
  if (has(/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/)) return rule('workflow', 'any', AGENTS);
  // Instruction files.
  if (base === 'AGENTS.md' || base === 'AGENTS.override.md') return rule('instructions', 'any', INSTRUCTION_READERS);
  if (base === 'CLAUDE.md' || base === 'CLAUDE.local.md') return rule('instructions', 'claude');
  if (base === 'GEMINI.md') return rule('instructions', 'gemini');
  if (base === '.cursorrules') return rule('instructions', 'cursor');
  if (base === '.windsurfrules') return rule('instructions', 'any', AGENTS);
  if (has(/(^|\/)\.clinerules(\/|$)/)) return rule('instructions', 'any', AGENTS);
  if (has(/(^|\/)\.github\/copilot-instructions\.md$/) || has(/(^|\/)\.github\/(?:instructions|prompts|agents|chatmodes)\/.+\.md$/)) return rule('instructions', 'copilot');
  if (has(/(^|\/)\.cursor\/(?:rules|commands|agents)\/.+\.(?:mdc|md)$/)) return rule('instructions', 'cursor');
  if (has(/(^|\/)\.claude\/(?:commands|agents|skills|output-styles)\/.+\.md$/)) return rule('instructions', 'claude');
  if (has(/(^|\/)\.codex\/prompts\/.+\.md$/)) return rule('instructions', 'codex');
  if (has(/(^|\/)\.opencode\/(?:commands?|agents?|skills?)\/.+\.md$/)) return rule('instructions', 'opencode');
  if (has(/(^|\/)\.amazonq\/rules\/.+\.md$/)) return rule('instructions', 'amazonq');
  if (has(/(^|\/)\.gemini\/commands\/.+\.toml$/)) return rule('instructions', 'gemini');
  if (lower === 'skill.md' && has(/(^|\/)skills\//)) return rule('instructions', 'claude');
  return null;
}

const EXTENSION_DIRS = [
  [/(^|\/)\.claude\/commands$/, 'claude', 'slash commands'],
  [/(^|\/)\.claude\/agents$/, 'claude', 'subagents'],
  [/(^|\/)\.claude\/skills$/, 'claude', 'skills'],
  [/(^|\/)\.claude-plugin$/, 'claude', 'a plugin'],
  [/(^|\/)\.codex\/prompts$/, 'codex', 'prompts'],
  [/(^|\/)\.cursor\/commands$/, 'cursor', 'commands'],
  [/(^|\/)\.opencode\/commands?$/, 'opencode', 'commands'],
  [/(^|\/)\.opencode\/agents?$/, 'opencode', 'agents'],
  [/(^|\/)\.opencode\/plugins?$/, 'opencode', 'plugins'],
  [/(^|\/)\.gemini\/commands$/, 'gemini', 'commands'],
  [/(^|\/)\.github\/(?:prompts|agents|chatmodes)$/, 'copilot', 'prompts or agents'],
  [/(^|\/)\.amazonq\/(?:cli-)?agents$/, 'amazonq', 'agents'],
];

// Directories agents read from. They are visited first, and inside them the
// SKIP_DIRS list does not apply (a skill may be called "build" or "dist").
const AGENT_DIRS = new Set(['.claude', '.codex', '.cursor', '.amazonq', '.vscode', '.opencode', '.gemini', '.github', '.claude-plugin', '.clinerules', 'skills']);

function isAgentDirName(name) {
  return AGENT_DIRS.has(name);
}

/* -------------------------- bounded reads --------------------------- */

const O_NOFOLLOW = (fs.constants && fs.constants.O_NOFOLLOW) || 0;
const O_NONBLOCK = (fs.constants && fs.constants.O_NONBLOCK) || 0;

/**
 * Read a regular file of at most `max` bytes. FIFOs, devices and sockets are
 * never opened for reading (no hang, no endless read); a final symbolic link
 * is not followed unless `follow` is set. Returns { text } or { skip, size }.
 */
function readBounded(abs, max, follow) {
  let st;
  try { st = follow ? fs.statSync(abs) : fs.lstatSync(abs); } catch (_) { return { skip: 'missing' }; }
  if (st.isSymbolicLink()) return { skip: 'symlink' };
  if (!st.isFile()) return { skip: 'not-file' };
  if (st.size > max) return { skip: 'too-large', size: st.size };
  let fd;
  try {
    fd = fs.openSync(abs, fs.constants.O_RDONLY | O_NONBLOCK | (follow ? 0 : O_NOFOLLOW));
    const fst = fs.fstatSync(fd);
    if (!fst.isFile()) return { skip: 'not-file' };
    const buf = Buffer.alloc(Math.min(fst.size, max) + 1);
    let n = 0;
    for (;;) {
      const r = fs.readSync(fd, buf, n, buf.length - n, n);
      if (r <= 0) break;
      n += r;
      if (n >= buf.length) break;
    }
    if (n > max) return { skip: 'too-large', size: n };
    let text = buf.toString('utf8', 0, n);
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    return { text };
  } catch (_) {
    return { skip: 'unreadable' };
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) { /* ignore */ }
  }
}

/* ------------------------------ walk -------------------------------- */

function walk(root, deadline, maxEntries) {
  const files = [];
  const extDirs = [];
  const unchecked = [];
  let entries = 0;
  let truncated = null;
  let realRoot = root;
  try { realRoot = fs.realpathSync(root); } catch (_) { /* keep */ }
  const visitedReal = new Set([realRoot]);
  const insideRoot = (p) => { const r = path.relative(realRoot, p); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };
  const priority = (name) => (isAgentDirName(name) || classify(name, true) ? 0 : 1);

  function addFile(abs, r, isRoot) {
    const c = classify(r, isRoot);
    if (c) files.push(Object.assign({ abs, rel: r, display: r, scope: 'project' }, c));
  }

  function visit(dir, rel, depth, inAgent) {
    if (truncated) return;
    let list;
    try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    list.sort((a, b) => (priority(a.name) - priority(b.name)) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of list) {
      if (truncated) return;
      if (++entries > maxEntries) { truncated = { reason: 'entries', at: rel || '.' }; return; }
      if ((entries & 1023) === 0 && Date.now() > deadline) { truncated = { reason: 'time', at: rel || '.' }; return; }
      const r = rel ? rel + '/' + d.name : d.name;
      const abs = path.join(dir, d.name);
      const agentHere = inAgent || isAgentDirName(d.name);
      if (d.isSymbolicLink()) {
        const asFile = classify(r, !rel);
        if (!asFile && !isAgentDirName(d.name)) continue;
        let real = null;
        try { real = fs.realpathSync(abs); } catch (_) { real = null; }
        let st = null;
        try { st = real && fs.statSync(real); } catch (_) { st = null; }
        if (!real || !st) {
          unchecked.push({ file: r, agent: asFile ? asFile.agent : 'any', readers: asFile ? asFile.readers : AGENTS, severity: 'medium', detail: r + ' is a broken symbolic link.' });
        } else if (!insideRoot(real)) {
          unchecked.push({ file: r, agent: asFile ? asFile.agent : 'any', readers: asFile ? asFile.readers : AGENTS, severity: 'high', detail: r + ' is a symbolic link to a location outside the audited directory. Agents follow it; zn audit does not read it.' });
        } else if (st.isDirectory() && isAgentDirName(d.name)) {
          if (!visitedReal.has(real)) { visitedReal.add(real); visit(real, r, depth + 1, true); }
        } else if (st.isFile() && asFile) {
          files.push(Object.assign({ abs: real, rel: r, display: r, scope: 'project' }, asFile));
        }
        continue;
      }
      if (d.isDirectory()) {
        if (d.name === '.git' || (!agentHere && SKIP_DIRS.has(d.name))) continue;
        const ext = EXTENSION_DIRS.find(([re]) => re.test(r));
        if (ext) extDirs.push({ rel: r, abs, agent: ext[1], what: ext[2] });
        if (depth < MAX_DEPTH) visit(abs, r, depth + 1, agentHere);
      } else if (d.isFile()) {
        addFile(abs, r, !rel);
      }
    }
  }
  visit(root, '', 0, false);
  return { files, extDirs, unchecked, truncated, entries };
}

function homeFiles(home, env) {
  const xdg = env.XDG_CONFIG_HOME ? path.resolve(env.XDG_CONFIG_HOME) : path.join(home, '.config');
  const codexHome = env.CODEX_HOME ? path.resolve(env.CODEX_HOME) : path.join(home, '.codex');
  const list = [
    [path.join(home, '.claude', 'settings.json'), 'claude-settings', 'claude'],
    [path.join(home, '.claude.json'), 'claude-user-json', 'claude'],
    [path.join(codexHome, 'config.toml'), 'codex-toml', 'codex'],
    [path.join(codexHome, 'hooks.json'), 'hooks-json', 'codex'],
    [path.join(home, '.cursor', 'mcp.json'), 'mcp-json', 'cursor'],
    [path.join(home, '.cursor', 'hooks.json'), 'hooks-json', 'cursor'],
    [path.join(home, '.aws', 'amazonq', 'mcp.json'), 'mcp-json', 'amazonq'],
    [path.join(xdg, 'opencode', 'opencode.json'), 'opencode-json', 'opencode'],
    [path.join(xdg, 'opencode', 'opencode.jsonc'), 'opencode-json', 'opencode'],
    [path.join(home, '.gemini', 'settings.json'), 'gemini-settings', 'gemini'],
  ];
  return list.map(([abs, kind, agent]) => {
    const rel = path.relative(home, abs).split(path.sep).join('/');
    const display = rel.startsWith('..') || path.isAbsolute(rel) ? abs.split(path.sep).join('/') : '~/' + rel;
    return { abs, rel, display, kind, agent, readers: [agent], scope: 'home' };
  });
}

/** Whether the root .gitignore ignores `name` (only used for the root .env). */
function gitIgnored(root, name) {
  const r = readBounded(path.join(root, '.gitignore'), 256 * 1024, false);
  if (!r.text) return false;
  let ignored = false;
  for (const l of r.text.split(/\r?\n/)) {
    const t = l.trim();
    if (!t || t.startsWith('#') || t.length > 200) continue;
    const neg = t.startsWith('!');
    const pat = (neg ? t.slice(1) : t).replace(/^\//, '').replace(/\/$/, '');
    const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*+/g, '[^/]*').replace(/\?/g, '[^/]') + '$');
    if (re.test(name)) ignored = !neg;
  }
  return ignored;
}

/**
 * Config directories a committed root .env points agents to (CODEX_HOME,
 * CLAUDE_CONFIG_DIR). When they are inside the repository, their config
 * files are audited like the default locations. A directory that leads
 * outside the repository through a symbolic link (or junction) is reported
 * in `unchecked`, never read. A .env listed in .gitignore is still audited:
 * in a fresh clone it exists only because it was committed.
 */
function redirectedConfigs(root, unchecked) {
  const r = readBounded(path.join(root, '.env'), MAX_FILE_BYTES, false);
  if (!r.text) return [];
  const envIgnored = gitIgnored(root, '.env');
  let realRoot;
  try { realRoot = fs.realpathSync(root); } catch (_) { return []; }
  const out = [];
  for (const l of r.text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?(CODEX_HOME|CLAUDE_CONFIG_DIR)\s*=\s*(.*)$/.exec(l);
    if (!m) continue;
    const value = m[2].trim().replace(/^(['"])(.*)\1$/, '$2');
    if (!value || P.isPlaceholder(value)) continue;
    const dir = path.resolve(root, value);
    const rel = path.relative(root, dir);
    if (rel.startsWith('..') || path.isAbsolute(rel)) continue;
    const relPosix = rel.split(path.sep).join('/');
    let realDir;
    try { realDir = fs.realpathSync(dir); } catch (_) { continue; }
    const realRel = path.relative(realRoot, realDir);
    if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
      if (unchecked) {
        unchecked.push({ file: relPosix || '.', agent: m[1] === 'CODEX_HOME' ? 'codex' : 'claude', severity: 'high',
          detail: '.env sets ' + m[1] + ' to ' + (relPosix || '.') + ', which leads outside the repository through a symbolic link; zn audit does not read it.' });
      }
      continue;
    }
    const add = (name, kind, agent, readers) => {
      const r2 = (relPosix ? relPosix + '/' : '') + name;
      out.push({ abs: path.join(dir, name), rel: r2, display: r2, scope: 'project', kind, agent, readers: readers || [agent], envIgnored });
    };
    if (m[1] === 'CODEX_HOME') { add('config.toml', 'codex-toml', 'codex'); add('hooks.json', 'hooks-json', 'codex'); }
    else { add('settings.json', 'claude-settings', 'claude', ['claude', 'cursor']); }
  }
  return out;
}

/* ----------------------- shadowing executables ---------------------- */

function readHead(abs) {
  let fd;
  try {
    fd = fs.openSync(abs, fs.constants.O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
    if (!fs.fstatSync(fd).isFile()) return Buffer.alloc(0);
    const b = Buffer.alloc(4);
    const n = fs.readSync(fd, b, 0, 4, 0);
    return b.slice(0, n);
  } catch (_) {
    return Buffer.alloc(0);
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) { /* ignore */ }
  }
}

function checkShadowing(root, out) {
  let list;
  try { list = fs.readdirSync(root, { withFileTypes: true }); } catch (_) { return; }
  for (const d of list) {
    if (!d.isFile() && !d.isSymbolicLink()) continue;
    const name = d.name;
    const lower = name.toLowerCase();
    const ext = path.extname(lower);
    const stem = ext ? lower.slice(0, -ext.length) : lower;
    if (!P.SHADOWED_TOOLS.has(stem)) continue;
    let severity = null;
    let why = '';
    const abs = path.join(root, name);
    if (P.WINDOWS_EXEC_EXT.has(ext)) {
      severity = 'critical';
      why = 'Windows runs ' + name + ' from the current directory before the real ' + stem + '.';
    } else if (!ext || ext === '.sh') {
      if (d.isSymbolicLink()) {
        severity = 'high';
        why = name + ' is a symbolic link named like the ' + stem + ' tool.';
      } else {
        let st;
        try { st = fs.lstatSync(abs); } catch (_) { continue; }
        const head = readHead(abs);
        const binary = head.length >= 2 && ((head[0] === 0x4d && head[1] === 0x5a) || (head.length >= 4 && head[0] === 0x7f && head.toString('latin1', 1, 4) === 'ELF') || (head.length >= 4 && (head.readUInt32BE(0) === 0xcffaedfe || head.readUInt32BE(0) === 0xfeedfacf)));
        const script = head.toString('latin1', 0, 2) === '#!';
        const execBit = process.platform !== 'win32' && (st.mode & 0o111) !== 0;
        if (binary || ((script || execBit) && !ext)) {
          severity = 'high';
          why = name + ' is ' + (binary ? 'a native executable' : 'an executable script') + ' named like the ' + stem + ' tool; any tool that searches the current directory or a PATH that includes it runs this file.';
        }
      }
    }
    if (!severity) continue;
    out.push({
      id: 'ZNA016', severity, agent: 'any', file: name, line: 1,
      title: BY_ID.ZNA016.title, detail: redact(why), evidence: redact(name),
      fix: BY_ID.ZNA016.fix, references: BY_ID.ZNA016.references.slice(), _readers: AGENTS,
    });
  }
}

/* ------------------------------ audit ------------------------------- */

const CHECKS = {
  'claude-settings': checkClaudeSettings,
  'claude-user-json': checkClaudeUserJson,
  'mcp-json': checkMcpJson,
  'vscode-mcp': checkMcpJson,
  'amazonq-agent': checkAmazonqAgent,
  'vscode-settings': checkVscodeSettings,
  'vscode-tasks': checkVscodeTasks,
  'hooks-json': checkHooksJson,
  'plugin-hooks': checkHooksJson,
  'cursor-cli': checkCursorCli,
  'gemini-settings': checkGeminiSettings,
  'opencode-json': checkOpencodeJson,
  'claude-plugin': checkClaudePlugin,
  'config-other': () => {},
};

// Config kinds that can start commands or redirect the agent: when one of
// them cannot be parsed, the text is searched for the risky keys instead.
const RISKY_KINDS = new Set(['claude-settings', 'claude-user-json', 'mcp-json', 'vscode-mcp', 'amazonq-agent', 'vscode-tasks', 'hooks-json', 'plugin-hooks', 'codex-toml', 'gemini-settings', 'opencode-json', 'claude-plugin', 'cursor-cli', 'vscode-settings']);
const RISKY_JSON_KEY = /"(hooks|command|args|mcpServers|servers|mcp|env|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper|statusLine|enableAllProjectMcpServers|enabledMcpjsonServers|enabledPlugins|extraKnownMarketplaces|permissions?|plugin|provider|runOn|allowedTools|chat\.tools\.(?:global\.)?autoApprove)"\s*:/;
const RISKY_TOML_KEY = /^\s*(?:\[\s*(?:mcp_servers|model_providers|shell_environment_policy|profiles)\b|(?:notify|approval_policy|sandbox_mode|openai_base_url|chatgpt_base_url|command|args)\s*=)/;

const WRITE_SCOPES = /contents|pull-requests|issues|actions|packages|id-token|deployments|statuses|checks/g;
const SCOPE_TAIL = /\s*:\s*write\b/y;

/**
 * A workflow permission line like "contents: write" (was
 * /^\s*(?:contents|...|checks)\s*:\s*write\b/m). Each scope name is checked
 * once: only whitespace back to a line start before it, then ": write" after
 * it. Linear, so a workflow full of blank lines cannot stall `zn audit`.
 */
function grantsWrite(text) {
  WRITE_SCOPES.lastIndex = 0;
  let m;
  while ((m = WRITE_SCOPES.exec(text)) !== null) {
    let i = m.index - 1;
    let lineStart = false;
    while (i >= 0 && /\s/.test(text[i])) {
      if (LINE_BREAKS.has(text[i])) lineStart = true;
      i--;
    }
    if (i >= 0 && !lineStart) continue;
    SCOPE_TAIL.lastIndex = m.index + m[0].length;
    if (SCOPE_TAIL.test(text)) return true;
  }
  return false;
}

/** s without a trailing '=' and the whitespace before it (was s.replace(/\s*=$/, '')). */
function withoutTrailingEquals(s) {
  return s.endsWith('=') ? s.slice(0, -1).trimEnd() : s;
}

function unparsable(ctx, err, what) {
  const keys = new Set();
  ctx.lines.forEach((l, i) => {
    const m = RISKY_JSON_KEY.exec(l) || RISKY_TOML_KEY.exec(l);
    if (m) keys.add(withoutTrailingEquals((m[1] || m[0]).trim()));
    checkDownloadRun(ctx, l, i + 1, 'A line of this file');
    if (ctx.rec.kind === 'vscode-tasks' && /"runOn"\s*:\s*"folderOpen"/.test(l)) {
      ctx.add('ZNA001', 'high', i + 1, 'A task runs when the folder is opened (runOn: folderOpen); the file could not be parsed to show the command.');
    }
  });
  // A reserved key (__proto__, constructor, prototype) has no use in a config
  // but to tamper with the reader: always high.
  const reserved = /reserved key/.test(err.message);
  if (reserved) keys.add('a reserved key');
  const risky = reserved || (RISKY_KINDS.has(ctx.rec.kind) && keys.size > 0);
  ctx.add('ZNA020', risky ? 'high' : 'low', err.line || 1, what + ' error: ' + err.message + (risky ? '. The file contains ' + Array.from(keys).slice(0, 6).join(', ') + ', which could not be checked.' : ''));
}

function auditFile(rec, out) {
  const r = readBounded(rec.abs, MAX_FILE_BYTES, rec.scope === 'home');
  if (r.skip === 'too-large') {
    out.push(uncheckedFinding({ file: rec.display, agent: rec.agent, readers: rec.readers, severity: 'high', detail: rec.display + ' is ' + r.size + ' bytes; zn audit reads agent files up to ' + MAX_FILE_BYTES + ' bytes, the agent reads all of it.' }));
    return true;
  }
  if (r.text === undefined) return false;
  const raw = r.text;
  const ctx = new FileCtx(rec, raw, out);

  if (rec.kind === 'plugin-hooks') {
    // Only a hooks.json that belongs to a Claude Code plugin.
    const pluginRoot = path.dirname(path.dirname(rec.abs));
    if (!fs.existsSync(path.join(pluginRoot, '.claude-plugin'))) return false;
  }
  if (rec.kind === 'dotenv') {
    // Listed in .gitignore but present in the clone: committed anyway.
    rec.envIgnored = gitIgnored(rec.root, '.env');
    checkDotenv(ctx);
    return true;
  }
  if (rec.kind === 'instructions') {
    checkSecrets(ctx);
    checkInstructions(ctx);
    return true;
  }
  if (rec.kind === 'workflow') {
    checkWorkflow(ctx);
    return true;
  }
  if (rec.kind === 'opencode-plugin') {
    if (path.basename(rec.abs) === 'zn-gate.js' && /zn-gate|\bzn hook\b/.test(raw)) return true;
    checkSecrets(ctx);
    checkOpencodePlugin(ctx);
    return true;
  }
  checkSecrets(ctx);
  if (rec.kind === 'codex-toml') {
    let parsed;
    try { parsed = parseToml(raw); } catch (err) {
      unparsable(ctx, err, 'TOML');
      return true;
    }
    checkCodexToml(ctx, parsed.data, parsed.lines);
    return true;
  }
  if (!raw.trim()) return true;
  let data;
  try { data = parseJsonc(raw); } catch (err) {
    unparsable(ctx, err, 'JSON');
    return true;
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return true;
  const fn = CHECKS[rec.kind];
  if (fn) fn(ctx, data);
  return true;
}

function checkSecrets(ctx) {
  const spans = secretSpans(ctx.raw);
  if (!spans.length) return;
  const seen = new Set();
  let offset = 0;
  const starts = ctx.lines.map((l) => { const s = offset; offset += l.length + 1; return s; });
  for (const sp of spans) {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= sp.start) lo = mid; else hi = mid - 1; }
    const key = lo + ':' + sp.type;
    if (seen.has(key)) continue;
    seen.add(key);
    ctx.add('ZNA011', 'high', lo + 1, 'A ' + sp.type + ' value is stored in the file.');
  }
}

function uncheckedFinding(u) {
  return {
    id: 'ZNA020', severity: u.severity, agent: u.agent, file: u.file, line: 1,
    title: BY_ID.ZNA020.title, detail: redact(u.detail), evidence: redact(u.file),
    fix: u.fix || BY_ID.ZNA020.fix, references: [], _readers: u.readers || AGENTS,
  };
}

function inventory(extDirs, out) {
  for (const d of extDirs) {
    let first = null;
    let count = 0;
    (function scan(dir, rel, depth) {
      let list;
      try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
      list.sort((a, b) => (a.name < b.name ? -1 : 1));
      for (const e of list) {
        if (e.isSymbolicLink()) continue;
        if (e.isFile()) { count++; if (!first) first = rel + '/' + e.name; } else if (e.isDirectory() && depth < 4) scan(path.join(dir, e.name), rel + '/' + e.name, depth + 1);
      }
    })(d.abs, d.rel, 0);
    if (!count) continue;
    out.push({
      id: 'ZNA018', severity: 'low', agent: d.agent, file: first, line: 1,
      title: BY_ID.ZNA018.title,
      detail: redact(d.rel + ' adds ' + d.what + ' to ' + d.agent + ' (' + count + ' file' + (count === 1 ? '' : 's') + ').'),
      evidence: redact(d.rel), fix: BY_ID.ZNA018.fix, references: [], _readers: [d.agent],
    });
  }
}

function normalizeAgents(list) {
  if (!list || list.length === 0 || list.includes('all')) return new Set(AGENTS);
  return new Set(list);
}

function audit(opts) {
  const o = opts || {};
  const root = path.resolve(o.root || '.');
  const selected = normalizeAgents(o.agents);
  const env = o.env || process.env;
  const deadline = Date.now() + (o.timeBudgetMs || TIME_BUDGET_MS);
  const out = [];
  const maxEntries = o.maxEntries || MAX_ENTRIES;
  const { files, extDirs, unchecked, truncated, entries } = walk(root, deadline, maxEntries);
  const known = new Set(files.map((f) => f.rel));
  for (const rec of redirectedConfigs(root, unchecked)) if (!known.has(rec.rel)) files.push(rec);
  let scanned = 0;
  let timedOut = truncated && truncated.reason === 'time';
  const wanted = (readers, agent) => agent === 'any' || (readers || []).some((r) => selected.has(r)) || selected.has(agent);
  for (const rec of files) {
    rec.root = root;
    if (rec.kind !== 'workflow' && !wanted(rec.readers, rec.agent)) continue;
    if (Date.now() > deadline) { timedOut = true; break; }
    if (auditFile(rec, out)) scanned++;
  }
  if (o.includeHome) {
    const home = o.home || os.homedir();
    for (const rec of homeFiles(home, env)) {
      rec.root = root;
      if (!wanted(rec.readers, rec.agent)) continue;
      if (!fs.existsSync(rec.abs)) continue;
      if (auditFile(rec, out)) scanned++;
    }
  }
  checkShadowing(root, out);
  inventory(extDirs, out);
  for (const u of unchecked) out.push(uncheckedFinding(u));
  if (truncated && truncated.reason === 'entries') {
    out.push(uncheckedFinding({ file: truncated.at, agent: 'any', severity: 'high', detail: 'zn audit stopped after ' + maxEntries + ' directory entries (in ' + truncated.at + '); agent directories were read first, but files after that point were not checked.' }));
  }
  if (timedOut) {
    out.push(uncheckedFinding({ file: (truncated && truncated.at) || '.', agent: 'any', severity: 'high', detail: 'zn audit stopped after its time budget of ' + Math.round((o.timeBudgetMs || TIME_BUDGET_MS) / 1000) + ' s; some files were not checked.' }));
  }

  const seen = new Set();
  const findings = [];
  for (const f of out) {
    if (!(f.agent === 'any' || selected.has(f.agent) || (f._readers || []).some((r) => selected.has(r)))) continue;
    const key = [f.id, f.file, f.line, f.severity, f.detail].join('\u0000');
    if (seen.has(key)) continue;
    seen.add(key);
    delete f._readers;
    findings.push(f);
  }
  findings.sort((a, b) => (RANK[b.severity] - RANK[a.severity]) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || (a.line - b.line) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { root, files: scanned, findings, truncated: Boolean(truncated) || timedOut, entries, agents: Array.from(selected) };
}

module.exports = { audit, classify, redact, AGENTS, _internal: { hookCommands, isOurHook, isOurMcp, gitIgnored, readBounded, grantsWrite, withoutTrailingEquals, OUR_HOOKS, SAFE_ABS, znGateFile } };
