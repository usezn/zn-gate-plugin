'use strict';

/**
 * Agent-independent policy used by the hook runner.
 *
 *  - Credential files: reads are denied (except .env files that only hold
 *    __ZN_ markers, see `zn env shadow`).
 *  - zn's own state (~/.zn) is off limits to agents, for reads and writes.
 *  - Commands that manage secrets (`zn secret set`, `zn env shadow`, ...)
 *    must be run by the user, never by an agent.
 *  - Bash commands with named markers are wrapped in `zn run --`, which
 *    applies allowCommands, first-use approval and output masking.
 *
 * Hooks are a guardrail, not a sandbox: a determined process can always
 * find another way to read a file. The goal is that secret values never
 * reach the model through the normal tool paths.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const dotenv = require('../broker/dotenv');
const markers = require('../broker/markers');
const { realTargetOf } = require('../broker/files');
const { powershellQuote, portablePath } = require('../shell-quote');
const { znCommand } = require('../zn-command');

// Version of the policy rules (credential paths, zn home, secret commands,
// command wrapping). Bump it when a rule changes; see CONTRIBUTING.md.
const POLICY_RULES_VERSION = '2026-10-17.8';

/* ------------------------------ paths ------------------------------ */

// Home and zn-home references written as shell variables (bash, PowerShell,
// cmd), so `cat $HOME/.zn/...` or `gc $env:USERPROFILE\.aws\credentials`
// are classified like their literal paths.
const HOME_VAR_RE = /^(?:\$\{?HOME\}?|\$env:(?:HOME|USERPROFILE)|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%)(?=$|[\\/])/i;
const ZN_HOME_VAR_RE = /^(?:\$\{?ZN_HOME\}?|\$env:ZN_HOME|%ZN_HOME%)(?=$|[\\/])/i;

function expandHome(p, home) {
  if (p === '~') return home;
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(home, p.slice(2));
  if (ZN_HOME_VAR_RE.test(p)) return path.join(home, '.zn', p.replace(ZN_HOME_VAR_RE, ''));
  if (HOME_VAR_RE.test(p)) return path.join(home, p.replace(HOME_VAR_RE, ''));
  return p;
}

function slash(p) {
  return String(p).replace(/\\/g, '/');
}

const DOTENV_BASENAME_RE = /^\.env(\.[A-Za-z0-9_.-]+)?$/;
const DOTENV_SAFE_RE = /\.(example|sample|template|dist|defaults|schema)$/i;
// Private keys kept outside ~/.ssh, for example in a project: an SSH key name is one wherever it is;
// a key container (.p12, .pfx) holds one; a .pem or .key file may be a public certificate, so its content decides.
const SSH_KEY_BASENAME_RE = /^id_(?:rsa|dsa|ecdsa|ed25519|xmss)(?:_sk)?$/;
const KEY_CONTAINER_RE = /\.(?:p12|pfx|jks|keystore|ppk)$/i;
const KEY_FILE_RE = /\.(?:pem|key|p8)$/i;
const PRIVATE_KEY_RE = /-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-/;
const KEY_SCAN_BYTES = 1024 * 1024;
const DOTENV_SCAN_BYTES = 8 * 1024 * 1024;

const CREDENTIAL_RES = [
  [/(^|\/)\.aws\/credentials$/, 'AWS credentials file'],
  [/(^|\/)\.ssh\/(id_[^/]+|[^/]+_key)$/, 'SSH private key'],
  [/(^|\/)[._]netrc$/, '.netrc credentials'],
  [/(^|\/)\.docker\/config\.json$/, 'Docker registry credentials'],
  [/(^|\/)\.config\/gh\/hosts\.ya?ml$/, 'GitHub CLI token'],
  [/(^|\/)\.git-credentials$/, 'git credentials'],
  [/(^|\/)\.pgpass$/, 'PostgreSQL password file'],
  [/(^|\/)\.kube\/config$/, 'Kubernetes credentials'],
  [/(^|\/)\.config\/gcloud\/(credentials\.db|access_tokens\.db|application_default_credentials\.json)$/, 'Google Cloud credentials'],
  [/(^|\/)\.azure\/(accessTokens\.json|msal_token_cache\.json)$/, 'Azure credentials'],
];

// Credential-file variables. A path given through one of them, or equal to
// its value, is a credential path. Directory variables cover everything below.
const CRED_ENV = ['AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE', 'GOOGLE_APPLICATION_CREDENTIALS', 'KUBECONFIG', 'DOCKER_CONFIG', 'NPM_CONFIG_USERCONFIG', 'AZURE_CONFIG_DIR'];
const CRED_ENV_DIRS = new Set(['AZURE_CONFIG_DIR', 'DOCKER_CONFIG']);
const ENV_REF_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$env:([A-Za-z_][A-Za-z0-9_]*)|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%/gi;

// Hook and plugin configuration of the agents. An agent that could change it
// could switch off the hooks that check it, so writes are refused like ~/.zn.
const AGENT_CONFIG_RES = [
  [/(^|\/)\.claude\/settings[^/]*\.json$/, 'Claude Code settings'],
  [/(^|\/)\.codex\/[^/]*$/, 'Codex hooks and configuration'],
  [/(^|\/)\.cursor\/hooks\.json$/, 'Cursor hooks'],
  [/(^|\/)opencode\.jsonc?$/, 'OpenCode configuration'],
  [/(^|\/)\.(config\/)?opencode\/plugins?\//, 'OpenCode plugins'],
  [/(^|\/)\.opencode\/plugins?\//, 'OpenCode plugins'],
];

// Windows and macOS file systems are case-insensitive by default. Read on each
// call, so tests can simulate those platforms on any system.
function caseInsensitive() {
  return process.platform === 'win32' || process.platform === 'darwin';
}
const keyOf = (s) => (caseInsensitive() ? s.toLowerCase() : s);
/** The pattern, ignoring case where the platform does. */
const ci = (re) => (caseInsensitive() && !re.flags.includes('i') ? new RegExp(re.source, re.flags + 'i') : re);

// Environment variables that name agent configuration. Unset, they cannot be
// resolved here, so a path that uses them is treated as agent configuration.
const AGENT_ENV = new Set(['CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'OPENCODE_CONFIG', 'OPENCODE_CONFIG_DIR', 'XDG_CONFIG_HOME']);

/** $NAME, ${NAME}, $env:NAME and %NAME% from env. Unset credential or agent variables are reported by name. */
function expandEnv(p, env) {
  let credentialVar = null;
  let agentVar = null;
  const text = p.replace(ENV_REF_RE, (m, a, b, c, d) => {
    const name = a || b || c || d;
    if (env[name]) return env[name];
    if (CRED_ENV.includes(name.toUpperCase())) credentialVar = name.toUpperCase();
    if (AGENT_ENV.has(name.toUpperCase())) agentVar = name.toUpperCase();
    return m;
  });
  return { text, credentialVar, agentVar };
}

/** Credential paths the environment names, as files and as directories (keys, not spelled as typed). */
function credentialEnvPaths(env, home, cwd) {
  const files = new Set();
  const dirs = new Set();
  for (const name of CRED_ENV) {
    if (!env[name]) continue;
    for (const raw of String(env[name]).split(path.delimiter)) {
      if (!raw.trim()) continue;
      const abs = path.resolve(cwd, expandHome(raw.trim(), home));
      for (const p of new Set([abs, realTargetOf(abs)])) (CRED_ENV_DIRS.has(name) ? dirs : files).add(keyOf(slash(p)));
    }
  }
  return { files, dirs: [...dirs] };
}

/** The project root above cwd (the directory with .git), or cwd when there is none. */
function projectRootOf(cwd) {
  let cur = path.resolve(cwd);
  for (;;) {
    if (fs.existsSync(path.join(cur, '.git'))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) return path.resolve(cwd);
    cur = parent;
  }
}

/** Keys of a path as typed and where it really leads. */
function keysOf(p) {
  return [...new Set([keyOf(slash(p)), keyOf(slash(realTargetOf(p)))])];
}

/**
 * Agent configuration: the directories that hold hook and plugin settings
 * (in the home directory, the project and the locations the environment
 * names), and the single files the environment names.
 */
function agentContext(home, cwd, env) {
  const dirs = new Set();
  const files = new Set();
  const rel = ['.claude', '.codex', '.cursor', '.opencode', path.join('.config', 'opencode')];
  for (const root of [home, projectRootOf(cwd)]) {
    for (const r of rel) for (const k of keysOf(path.join(root, r))) dirs.add(k);
  }
  const at = (p) => path.resolve(cwd, expandHome(p, home));
  if (env.CODEX_HOME) for (const k of keysOf(at(env.CODEX_HOME))) dirs.add(k);
  // Claude Code keeps its settings here when the variable is set, and zn installs its hooks there.
  if (env.CLAUDE_CONFIG_DIR) for (const k of keysOf(at(env.CLAUDE_CONFIG_DIR))) dirs.add(k);
  if (env.OPENCODE_CONFIG_DIR) for (const k of keysOf(at(env.OPENCODE_CONFIG_DIR))) dirs.add(k);
  if (env.XDG_CONFIG_HOME) for (const k of keysOf(path.join(at(env.XDG_CONFIG_HOME), 'opencode'))) dirs.add(k);
  if (env.OPENCODE_CONFIG) for (const k of keysOf(at(env.OPENCODE_CONFIG))) files.add(k);
  // Roots that hold agent configuration: removing or moving them removes it.
  // Only the directory itself is protected (listing it or reading it is fine).
  const roots = new Set(keysOf(path.join(home, '.config')));
  if (env.XDG_CONFIG_HOME) for (const k of keysOf(at(env.XDG_CONFIG_HOME))) roots.add(k);
  return { dirs: [...dirs], files, roots: [...roots] };
}

/** Everything a classification needs, from the options of one call. */
function contextOf(opts = {}) {
  // A caller that classifies many words passes the context it already built.
  if (opts.ctx) return opts.ctx;
  const home = opts.home || os.homedir();
  const cwd = opts.cwd || process.cwd();
  const env = opts.env || process.env;
  return { home, cwd, env, creds: credentialEnvPaths(env, home, cwd), agent: agentContext(home, cwd, env) };
}

/**
 * Classify a resolved absolute path. `ctx` comes from contextOf.
 */
function classifyResolved(abs, ctx) {
  const { home, creds, agent } = ctx;
  const s = keyOf(slash(abs));
  const h = keyOf(slash(path.resolve(home)));
  if (s === h + '/.zn' || s.startsWith(h + '/.zn/')) return { kind: 'zn_state', reason: 'zn keeps its vault and audit log in ~/.zn' };
  for (const [re, reason] of AGENT_CONFIG_RES) if (ci(re).test(s)) return { kind: 'agent_config', reason };
  // The directory itself (`cd ~/.claude`, `mv ~/.codex`, `rm -r ~/.cursor`) and the files directly in it.
  if (agent.dirs.includes(s) || agent.roots.includes(s)) return { kind: 'agent_config', reason: 'an agent configuration directory' };
  if (agent.dirs.some((d) => s.startsWith(d + '/') && !s.slice(d.length + 1).includes('/'))) {
    return { kind: 'agent_config', reason: 'a file in an agent configuration directory' };
  }
  if (agent.files.has(s)) return { kind: 'agent_config', reason: 'the agent configuration file the environment names' };
  if (s.endsWith('.pub')) return null;
  if (creds.files.has(s)) return { kind: 'credential', reason: 'a file named by a credential environment variable' };
  for (const d of creds.dirs) if (s === d || s.startsWith(d + '/')) return { kind: 'credential', reason: 'a directory named by a credential environment variable' };
  for (const [re, reason] of CREDENTIAL_RES) if (ci(re).test(s)) return { kind: 'credential', reason };
  if (s === h + '/.npmrc' || s === h + '/.pypirc') return { kind: 'credential', reason: 'package registry token' };
  const base = path.basename(abs);
  if (ci(DOTENV_BASENAME_RE).test(base) && !ci(DOTENV_SAFE_RE).test(base)) return { kind: 'dotenv', reason: '.env file' };
  if (ci(SSH_KEY_BASENAME_RE).test(base)) return { kind: 'credential', reason: 'SSH private key' };
  if (KEY_CONTAINER_RE.test(base)) return { kind: 'credential', reason: 'key store, which holds private keys' };
  if (KEY_FILE_RE.test(base)) return { kind: 'keyfile', reason: 'a private key file' };
  return null;
}

/** The absolute path a typed path names, after ~ and variables are expanded. */
function resolvedOf(p, opts = {}) {
  const home = opts.home || os.homedir();
  const cwd = opts.cwd || process.cwd();
  return path.resolve(cwd, expandEnv(expandHome(p, home), opts.env || process.env).text);
}

/**
 * Classify a path. Returns null or {kind, reason}:
 *   kind 'credential' | 'dotenv' | 'keyfile' | 'zn_state' | 'agent_config'
 * The path is checked as typed and where it really leads (symlinks resolved),
 * with ~, $HOME, %USERPROFILE%, $env:USERPROFILE and the credential variables
 * expanded, and case-insensitively on Windows and macOS.
 */
function classifyPath(p, opts = {}) {
  if (typeof p !== 'string' || !p) return null;
  const ctx = contextOf(opts);
  const expanded = expandEnv(expandHome(p, ctx.home), ctx.env);
  if (expanded.credentialVar) {
    return { kind: 'credential', reason: 'the path comes from $' + expanded.credentialVar + ', which names a credential file' };
  }
  if (expanded.agentVar) {
    return { kind: 'agent_config', reason: 'the path comes from $' + expanded.agentVar + ', the agent configuration location' };
  }
  const abs = path.resolve(ctx.cwd, expanded.text);
  for (const candidate of new Set([abs, realTargetOf(abs)])) {
    const c = classifyResolved(candidate, ctx);
    if (c) return c;
  }
  return null;
}

/* ---------------------------- globs, braces ---------------------------- */

const GLOB_RE = /[*?[\]{}]/;
// The first comma is matched by [^{},]*, so the pattern has one way to match and cannot backtrack.
const BRACE_RE = /\{([^{},]*,[^{}]*)\}/;

/** Alternatives of a word with brace lists (`a{b,c}` -> ab, ac); null when there are too many. */
function expandBraces(s, limit = 64) {
  const m = BRACE_RE.exec(s);
  if (!m) return [s];
  const out = [];
  for (const alt of m[1].split(',')) {
    const rest = expandBraces(s.slice(0, m.index) + alt + s.slice(m.index + m[0].length), limit);
    if (rest === null) return null;
    for (const x of rest) {
      out.push(x);
      if (out.length > limit) return null;
    }
  }
  return out;
}

// POSIX character classes inside a bracket expression ("[[:alpha:]]").
const GLOB_POSIX_CLASSES = {
  alpha: [['a', 'z'], ['A', 'Z']],
  digit: [['0', '9']],
  alnum: [['a', 'z'], ['A', 'Z'], ['0', '9']],
  lower: [['a', 'z']],
  upper: [['A', 'Z']],
  xdigit: [['0', '9'], ['a', 'f'], ['A', 'F']],
  space: [[' ', ' '], ['\t', '\r']],
  blank: [[' ', ' '], ['\t', '\t']],
  punct: [['!', '/'], [':', '@'], ['[', '`'], ['{', '~']],
};

/**
 * Index of the "]" that closes the bracket expression opened at `open`, read
 * as the shell reads it: after an optional "!" or "^", a "]" is a member, and
 * "[:name:]" is one item. Returns -1 when the expression is not closed (the
 * "[" is then a literal character).
 */
function globClassEnd(pattern, open, ends = globClassEnds(pattern)) {
  let k = open + 1;
  if (pattern[k] === '!' || pattern[k] === '^') k++;
  if (pattern[k] === ']') k++;
  return k < pattern.length ? ends[k] : -1;
}

/*
 * For every position k, where the scan of globClassEnd that reaches k stops:
 * the index of the closing "]", or -1. Computed once per pattern from right to
 * left, so a pattern with many "[" or "[:" costs one pass, not one per "[".
 */
function globClassEnds(pattern) {
  const n = pattern.length;
  const nextColonClose = new Int32Array(n + 2).fill(-1);
  for (let i = n - 2; i >= 0; i--) {
    nextColonClose[i] = pattern[i] === ':' && pattern[i + 1] === ']' ? i : nextColonClose[i + 1];
  }
  const ends = new Int32Array(n + 1).fill(-1);
  for (let k = n - 1; k >= 0; k--) {
    const colon = pattern[k] === '[' && pattern[k + 1] === ':' ? nextColonClose[k + 2] : -1;
    if (colon !== -1) ends[k] = colon + 2 <= n ? ends[colon + 2] : -1;
    else ends[k] = pattern[k] === ']' ? k : ends[k + 1];
  }
  return ends;
}

/**
 * A glob bracket expression ("[abc]", "[a-z]", "[!.]", "[]x]", "[[:alpha:]]")
 * as a regular expression that always compiles. Every character is written as
 * a \uXXXX escape (so "\", "]" and "^" are literal); a range written backwards
 * matches nothing, as in the shell; a negated class never matches "/"; an
 * unknown "[:name:]" class matches any character but "/" (matching more is the
 * safe side for a policy check). Characters outside the BMP are read as two
 * UTF-16 units, as before; no protected path name uses them.
 */
function globClassSource(body) {
  const esc = (ch) => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
  let neg = false;
  if (body[0] === '!' || body[0] === '^') { neg = true; body = body.slice(1); }
  let out = '';
  let any = false;
  // A "[:" with no ":]" after it is literal: look for ":]" only when one is left.
  const lastColonClose = body.lastIndexOf(':]');
  for (let k = 0; k < body.length; k++) {
    if (body.startsWith('[:', k) && k + 2 <= lastColonClose) {
      const end = body.indexOf(':]', k + 2);
      if (end !== -1) {
        const ranges = GLOB_POSIX_CLASSES[body.slice(k + 2, end)];
        if (ranges) for (const [a, b] of ranges) out += a === b ? esc(a) : esc(a) + '-' + esc(b);
        else any = true;
        k = end + 1;
        continue;
      }
    }
    if (body[k + 1] === '-' && k + 2 < body.length) {
      if (body[k] <= body[k + 2]) out += esc(body[k]) + '-' + esc(body[k + 2]);
      k += 2;
    } else out += esc(body[k]);
  }
  if (any) return '[^/]';
  if (neg) return '[^/' + out + ']';
  return out ? '[' + out + ']' : '(?!)';
}

const GLOB_STAR = Symbol('*');
const GLOB_ONE = Symbol('?');

/** One pattern token against one character: a literal, "?", or a bracket expression. */
function globOne(tok, ch) {
  if (tok === GLOB_ONE) return ch !== '/';
  if (typeof tok === 'string') return tok === ch;
  return tok.test(ch);
}

/*
 * Wildcard match of one path segment (no "/" in it) in O(pattern x text) time:
 * on a mismatch the last "*" takes one more character, so no input can make it
 * backtrack exponentially, whatever the number of "*".
 */
function globSegment(toks, s) {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < s.length) {
    if (p < toks.length && toks[p] === GLOB_STAR) {
      star = p++;
      mark = t;
    } else if (p < toks.length && globOne(toks[p], s[t])) {
      p++;
      t++;
    } else if (star !== -1) {
      p = star + 1;
      t = ++mark;
    } else return false;
  }
  while (p < toks.length && toks[p] === GLOB_STAR) p++;
  return p === toks.length;
}

/**
 * Shell glob matcher over a whole path: "*", "?" and bracket expressions stop
 * at a separator, so the pattern and the path are matched segment by segment.
 * Returns an object with test(path), like a regular expression. A bracket
 * expression is a one-character regular expression (globClassSource), which
 * cannot backtrack.
 */
function globRegExp(pattern) {
  const segs = [[]];
  const ends = pattern.includes('[') ? globClassEnds(pattern) : null;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    const end = c === '[' ? globClassEnd(pattern, i, ends) : -1;
    const cur = segs[segs.length - 1];
    if (c === '/') segs.push([]);
    else if (c === '*') { if (cur[cur.length - 1] !== GLOB_STAR) cur.push(GLOB_STAR); }
    else if (c === '?') cur.push(GLOB_ONE);
    else if (end !== -1) {
      cur.push(new RegExp('^' + globClassSource(pattern.slice(i + 1, end)) + '$'));
      i = end;
    } else cur.push(c);
  }
  // A name has at most 255 characters (NAME_MAX), so a segment that needs more
  // characters than that, not counting "*", cannot name any file.
  const impossible = segs.some((seg) => seg.filter((t) => t !== GLOB_STAR).length > 255);
  return {
    impossible,
    test(s) {
      if (impossible) return false;
      const parts = String(s).split('/');
      if (parts.length !== segs.length) return false;
      for (let k = 0; k < parts.length; k++) if (!globSegment(segs[k], parts[k])) return false;
      return true;
    },
  };
}

// Representative paths a glob could name: a glob that matches one of them
// is treated as naming that kind of file. Under the home directory and the project.
const GLOB_EXAMPLES = ['.aws/credentials', '.aws/config', '.ssh/id_rsa', '.ssh/id_ed25519', '.ssh/my_key', '.netrc', '_netrc',
  '.docker/config.json', '.config/gh/hosts.yml', '.git-credentials', '.pgpass', '.kube/config', '.config/gcloud/credentials.db',
  '.config/gcloud/access_tokens.db', '.config/gcloud/application_default_credentials.json',
  '.azure/accessTokens.json', '.azure/msal_token_cache.json', '.npmrc', '.pypirc', '.zn/secrets.age', '.claude/settings.json',
  '.codex/hooks.json', '.cursor/hooks.json', '.config/opencode/opencode.json', '.config/opencode/plugins/zn.js'];

// Most entries a glob may read from the disk before it is refused as too broad.
const GLOB_DISK_LIMIT = 5000;
const PROJECT_EXAMPLES = ['.env', '.env.local', '.claude/settings.json', 'opencode.json'];

/**
 * A word with glob or brace characters that could name a protected path.
 * Returns the classification of the path it matches, or null.
 */
// Most "[" a glob word may have: each one is read up to its "]", so more than
// this is refused as too broad to check instead of being read.
const GLOB_BRACKETS_MAX = 1000;
// Most characters times brace alternatives a glob word may need to check.
const GLOB_WORK_MAX = 2000000;

function globClass(word, opts = {}) {
  if (!GLOB_RE.test(word)) return null;
  let brackets = 0;
  for (let k = word.indexOf('['); k !== -1; k = word.indexOf('[', k + 1)) {
    if (++brackets > GLOB_BRACKETS_MAX) return { kind: 'credential', reason: 'a pattern too broad to check' };
  }
  const ctx = contextOf(opts);
  const alts = expandBraces(word);
  if (alts === null) return { kind: 'credential', reason: 'a brace pattern too broad to check' };
  // Each alternative is resolved and matched in full: past this much work the
  // pattern is refused as too broad instead of being checked.
  if (alts.length * word.length > GLOB_WORK_MAX) return { kind: 'credential', reason: 'a pattern too broad to check' };
  const examples = [...GLOB_EXAMPLES.map((e) => path.join(ctx.home, e)), ...PROJECT_EXAMPLES.map((e) => path.join(ctx.cwd, e))];
  for (const alt of alts) {
    const e = expandEnv(expandHome(alt, ctx.home), ctx.env);
    if (e.credentialVar) return { kind: 'credential', reason: 'a pattern built from $' + e.credentialVar };
    if (e.agentVar) return { kind: 'agent_config', reason: 'a pattern built from $' + e.agentVar };
    const abs = slash(path.resolve(ctx.cwd, e.text));
    // Any pattern whose last name starts with .env names a .env file.
    if (keyOf(path.posix.basename(abs)).startsWith('.env')) return { kind: 'credential', reason: 'a pattern that matches a .env file' };
    const re = globRegExp(keyOf(abs));
    if (re.impossible) continue;
    for (const ex of examples) {
      const c = classifyResolved(ex, ctx);
      if (c && re.test(keyOf(slash(ex)))) {
        return c.kind === 'dotenv' ? { kind: 'credential', reason: 'a pattern that matches a .env file' } : c;
      }
    }
    // What the pattern matches on the disk now, read with a limit.
    const hits = globOnDisk(abs);
    if (hits === 'too-broad') return { kind: 'credential', reason: 'a pattern too broad to check' };
    for (const hit of hits || []) {
      for (const cand of new Set([hit, realTargetOf(hit)])) {
        const c = classifyResolved(cand, ctx);
        if (c) return c.kind === 'dotenv' ? { kind: 'credential', reason: 'a pattern that matches a .env file' } : c;
      }
    }
  }
  return null;
}

/**
 * The paths a glob matches on the disk now: its literal start is read, and
 * each glob component is matched against the names in its directory.
 * Returns the matches, 'too-broad' past GLOB_DISK_LIMIT entries, or null.
 */
function globOnDisk(abs) {
  const parts = abs.split('/');
  let i = 0;
  while (i < parts.length && !GLOB_RE.test(parts[i])) i++;
  if (i === parts.length) return [abs];
  let dirs = [parts.slice(0, i).join('/') || '/'];
  let budget = GLOB_DISK_LIMIT;
  const join = (d, n) => (d.endsWith('/') ? d + n : d + '/' + n);
  for (; i < parts.length; i++) {
    const seg = parts[i];
    const next = [];
    if (!GLOB_RE.test(seg)) {
      for (const d of dirs) next.push(join(d, seg));
    } else {
      const segRe = globRegExp(keyOf(seg));
      for (const d of dirs) {
        let names;
        try { names = fs.readdirSync(d); } catch (_) { continue; }
        budget -= names.length;
        if (budget < 0) return 'too-broad';
        for (const n of names) if (segRe.test(keyOf(n))) next.push(join(d, n));
      }
    }
    dirs = next;
    if (dirs.length === 0) return null;
  }
  return dirs;
}

/** A typed word: a path, or a glob that could name one. */
function classifyWord(text, opts = {}) {
  const c = classifyPath(text, opts);
  // A .env name behind a glob (app*/.env, src/*/.env): the shell expands it to real files, which cannot be read
  // through the pattern to see whether they hold values, so the glob's own classification decides.
  if (c && c.kind === 'dotenv' && GLOB_RE.test(String(text))) return globClass(text, opts) || c;
  return c || globClass(text, opts);
}

/**
 * Decide on a read of `p`. Returns null (allowed) or a deny message.
 * .env files are allowed once shadowed (only markers inside).
 */
function readDenial(p, opts = {}) {
  const c = classifyPath(p, opts);
  if (!c || c.kind === 'agent_config') return null;
  if (c.kind === 'dotenv') {
    const abs = resolvedOf(p, opts);
    const head = readHead(abs, DOTENV_SCAN_BYTES);
    if (head === null) return null; // missing file: nothing to protect
    // Not a regular file (a FIFO), or too big to check whole: refused rather than read.
    let text = head === NOT_A_FILE ? null : Buffer.from(head, 'latin1').toString('utf8');
    if (text !== null && Buffer.byteLength(head, 'latin1') >= DOTENV_SCAN_BYTES) text = null;
    if (text !== null && dotenv.isShadowed(text)) return null;
    return 'zn: ' + path.basename(abs) + ' holds plain-text secrets. Ask the user to run `' +
      znCommand('env shadow ' + path.basename(abs)) + '` in their terminal: it moves the values to the local vault and leaves __ZN_<NAME>__ markers you can read and use.';
  }
  if (c.kind === 'zn_state') return vaultMessage(opts);
  if (c.kind === 'keyfile') return keyFileDenial(p, c, opts);
  return credentialDenial(p, c);
}

/* Spend `n` looks on disk from a command's budget; true once the time or the looks are used up. */
function overBudget(budget, n) {
  if (!budget) return false;
  budget.disk -= n;
  return budget.disk < 0 || Date.now() > budget.until;
}

/* The first `max` bytes of a file, as latin1 text. null when it does not exist; NOT_A_FILE for anything that is not
   a regular file (a FIFO, a device, a directory): opening is non-blocking, so a FIFO cannot hold the hook until the
   agent's timeout lets the command through. */
const NOT_A_FILE = Symbol('not a regular file');
function readHead(abs, max) {
  let fd;
  try {
    fd = fs.openSync(abs, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (_) {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (st.isDirectory()) return null; // a folder holds no values (a Python virtualenv named .env)
    if (!st.isFile()) return NOT_A_FILE;
    const n = Math.min(st.size, max);
    const buf = Buffer.allocUnsafe(n);
    let got = 0;
    while (got < n) {
      const r = fs.readSync(fd, buf, got, n - got, got);
      if (r <= 0) break;
      got += r;
    }
    return buf.toString('latin1', 0, got);
  } catch (_) {
    return NOT_A_FILE;
  } finally {
    fs.closeSync(fd);
  }
}

/* A .pem, .key or .p8 file: refused when it holds a private key, allowed when it is a certificate or a public key. */
function keyFileDenial(p, c, opts) {
  const text = readHead(resolvedOf(p, opts), KEY_SCAN_BYTES);
  if (text === null) return null; // missing file: nothing to protect
  if (text === NOT_A_FILE || PRIVATE_KEY_RE.test(text)) return credentialDenial(p, c);
  return null;
}

/* Reads of credential files: what was refused, why, and how to use a value instead. */
function credentialDenial(p, c) {
  return 'zn: ' + p + ' was not read because zn treats it as holding secrets (' + c.reason + '), and secret values never go to the model. ' +
    'If a command needs a value, ask the user to run `' + znCommand('secret set NAME') + '`, then write __ZN_NAME__ where the value goes.';
}

function agentConfigDenial(p, c) {
  return 'zn: ' + c.reason + ' (' + p + ') is protected: an agent may not change how zn and its hooks run. Ask the user to make this change.';
}

/** Writes are only blocked for zn's own state and the agents' hook and plugin configuration. */
function writeDenial(p, opts = {}) {
  const c = classifyPath(p, opts);
  if (c && c.kind === 'zn_state') return vaultMessage(opts);
  if (c && c.kind === 'agent_config') return agentConfigDenial(p, c);
  return null;
}

/* ------------------------------ shell ------------------------------ */

// Characters a backslash escapes in bash, outside and inside double quotes.
const ESCAPABLE = /[\\"'`$ \t;&|()<>\n#*?[\]{}~]/;
const DQ_ESCAPABLE = /["\\$`\n]/;

/**
 * Split a shell command into top-level words of its first simple command.
 * Returns {end, words: [{text, start, end}], substitution, operator}
 *   end: index where the first simple command stops (first top-level
 *        ; & | newline ( ) or end of string)
 *   substitution: true if $( or ` appears inside the first command
 *   words[].text is the word with quotes removed (approximation of bash)
 */
function scanFirstCommand(cmd, posix = false) {
  const s = String(cmd);
  const words = [];
  let i = 0;
  let cur = null;
  let substitution = false;
  let quote = null;
  const pushChar = (ch, at) => {
    if (!cur) cur = { text: '', start: at, end: at };
    cur.text += ch;
    cur.end = at + 1;
  };
  const endWord = () => {
    if (cur) words.push(cur);
    cur = null;
  };
  for (; i < s.length; i++) {
    const ch = s[i];
    if (quote === "'") {
      if (ch === "'") { quote = null; cur.end = i + 1; } else pushChar(ch, i);
      continue;
    }
    if (quote === '"') {
      if (ch === '\\' && i + 1 < s.length) {
        if (!DQ_ESCAPABLE.test(s[i + 1])) { pushChar(ch, i); continue; }
        pushChar(s[i + 1], i);
        i++;
        continue;
      }
      if (ch === '"') { quote = null; cur.end = i + 1; continue; }
      if (ch === '`' || (ch === '$' && s[i + 1] === '(')) substitution = true;
      pushChar(ch, i);
      continue;
    }
    if (ch === '\\' && i + 1 < s.length) {
      if (s[i + 1] === '\n') { i++; continue; }
      // A backslash before a letter or a dot is kept: on Windows it is the path
      // separator (C:\Users\me\.aws\credentials), and the escape would eat it.
      // bashDenial scans both readings (posix: every backslash escapes).
      if (!posix && !ESCAPABLE.test(s[i + 1])) { pushChar(ch, i); continue; }
      pushChar(s[i + 1], i);
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      if (!cur) cur = { text: '', start: i, end: i + 1 };
      continue;
    }
    if (ch === '`' || (ch === '$' && s[i + 1] === '(')) { substitution = true; pushChar(ch, i); continue; }
    if (ch === ';' || ch === '&' || ch === '|' || ch === '\n' || ch === '(' || ch === ')') {
      endWord();
      return { end: i, words, substitution, operator: ch, unterminated: false };
    }
    if (ch === ' ' || ch === '\t') { endWord(); continue; }
    pushChar(ch, i);
  }
  endWord();
  return { end: s.length, words, substitution, operator: null, unterminated: quote !== null };
}

/** Every word of the whole command (rough), with a flag for > / >> targets and the command name of its segment. */
// Enough simple commands for any command under SHELL_SCAN_CAP (each takes at least two characters).
const SIMPLE_COMMANDS_MAX = 50000;
function allWords(cmd, posix = false) {
  const out = [];
  let rest = String(cmd);
  let guard = 0;
  while (rest.length && guard++ < SIMPLE_COMMANDS_MAX) {
    const scan = scanFirstCommand(rest, posix);
    const head = commandName(scan.words);
    const sub = isGit(head) ? gitSubcommand(scan.words) : '';
    const gitArgs = sub ? scan.words.map((x) => x.text) : null;
    for (let k = 0; k < scan.words.length; k++) {
      const w = scan.words[k];
      const prev = k > 0 ? scan.words[k - 1].text : '';
      const isRedirTarget = /^[0-9]*>>?$/.test(prev) || /^[0-9]*>>?./.test(w.text);
      // Input redirections: <file, 0<file, <>file (read and write), {fd}<file.
      out.push({ text: w.text.replace(/^[0-9]*>>?/, '').replace(/^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?<>?/, ''), redirectTarget: isRedirTarget, head, seq: guard, sub, gitArgs });
    }
    rest = rest.slice(scan.end + 1);
  }
  // Simple commands past the limit were not read: the caller refuses the command rather than check only part of it.
  if (rest.length) out.truncated = true;
  return out;
}

/** Lower-case name of the program a simple command runs (after VAR=value assignments). */
function commandName(words) {
  const w = words.find((x) => !ASSIGNMENT_RE.test(x.text));
  return w ? w.text.split(/[\\/]/).pop().toLowerCase() : '';
}

// Commands that only read their arguments. Any other command may write them.
// (less and tree are not here: tree writes its output with -o, less can run commands.)
const READ_ONLY_CMDS = new Set(['cat', 'head', 'tail', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'ls', 'stat', 'wc', 'diff',
  'file', 'bat', 'jq', 'type', 'gc', 'get-content', 'select-string', 'findstr', 'dir', 'pwd', 'echo']);
const AGENT_CONFIG_MENTION_RE = /\.claude\/settings|\.codex\/|\.cursor\/hooks|opencode\.jsonc?|\.opencode\/|\.config\/opencode\//i;

const RESERVED_WORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'function', '{', '}', '!', '[[', 'time', 'coproc', 'select', 'eval', 'exec', 'source', '.', 'sudo', 'doas', 'env', 'xargs', 'nohup', 'command', 'builtin', 'export', 'declare', 'local', 'readonly', 'typeset', 'alias', 'set', 'unset', 'let']);
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Prefix the first simple command with `zn run --` so the broker applies
 * policy, approval and masking. Only when every named marker is inside the
 * first simple command; anything else is refused with guidance.
 * Returns {ok: true, command} or {ok: false, reason}.
 */
function wrapWithZnRun(cmd, znRunPrefix) {
  const s = String(cmd);
  const named = markers.findNamedMarkers(s);
  if (named.length === 0) return { ok: true, command: s, wrapped: false };
  const scan = scanFirstCommand(s);
  const tail = s.slice(scan.end);
  const guidance = ' zn fills in secrets only in the first command of a Bash call: run that command on its own, ' +
    'with __ZN_NAME__ where the value goes (for example: psql "postgres://app:__ZN_DB_PASSWORD__@db/app" -c "select 1").';
  if (scan.unterminated) return { ok: false, reason: 'zn: this command has a quote that is not closed, so zn cannot read it. Close the quote and try again.' };
  if (markers.findNamedMarkers(tail).length > 0) {
    return { ok: false, reason: 'zn: this command uses a secret after its first command.' + guidance };
  }
  if (scan.substitution) {
    return { ok: false, reason: 'zn: a secret cannot be used in a command that also has $( ) or backticks.' + guidance };
  }
  let k = 0;
  while (k < scan.words.length && ASSIGNMENT_RE.test(scan.words[k].text)) k++;
  if (k >= scan.words.length) {
    return { ok: false, reason: 'zn: putting a secret in a shell variable would store only its placeholder, not the value. ' +
      'To give a program a secret as an environment variable, use `' + znCommand('run --secrets NAME -- <command>') + '`.' };
  }
  for (let j = 0; j < k; j++) {
    if (markers.findNamedMarkers(scan.words[j].text).length) {
      return { ok: false, reason: 'zn: a secret in a VAR=__ZN_NAME__ assignment before a command cannot be filled in, so the command was blocked. ' +
        'Next step: give it to the program with `' + znCommand('run --secrets NAME -- <command>') + '` instead.' };
    }
  }
  const first = scan.words[k];
  if (RESERVED_WORDS.has(first.text)) {
    return { ok: false, reason: 'zn: a secret cannot be used with `' + first.text + '`, because it is a shell keyword, not a program zn can hand the value to.' + guidance };
  }
  // Already wrapped by the agent or a previous hook: leave it alone, zn run applies policy.
  if (/(^|[\\/])(zn|zn-gate)(\.js|\.cmd)?$/.test(first.text) && scan.words[k + 1] && scan.words[k + 1].text === 'run') {
    return { ok: true, command: s, wrapped: false };
  }
  return { ok: true, command: s.slice(0, first.start) + znRunPrefix + ' ' + s.slice(first.start), wrapped: true };
}

/* ---------------------------- PowerShell ---------------------------- */

// Aliases that Windows PowerShell maps to cmdlets (curl and wget are
// Invoke-WebRequest there): never treated as native commands.
const PS_ALIASES = new Set(['curl', 'wget', 'iwr', 'irm', 'iex', 'icm', 'cat', 'gc', 'type', 'echo', 'write', 'ls', 'dir', 'gci',
  'cp', 'copy', 'mv', 'move', 'rm', 'del', 'erase', 'ri', 'sc', 'ac', 'set', 'sv', 'sl', 'cd', 'chdir', 'pushd', 'popd',
  'start', 'saps', 'sajb', 'foreach', 'where', '%', '?', 'select', 'sort', 'measure', 'tee', 'ni', 'md', 'mkdir', 'sleep',
  'kill', 'spps', 'ps', 'gps', 'history', 'h', 'r', 'clear', 'cls', 'man', 'help', 'ipmo', 'ise', 'nal', 'sal']);
const PS_META = new Set([';', '|', '&', '(', ')', '{', '}', '@', '$', '`', '<', '>', ',', '\n', '\r']);

/**
 * Tokenize a PowerShell command line conservatively. Returns
 * {words: [{text, start, end}], simple} where simple is false when the line
 * has anything beyond one native command with plain arguments: pipelines,
 * statements, script blocks, variables, subexpressions, splatting,
 * redirection, or double-quoted strings that would expand.
 */
function scanPowerShell(cmd) {
  const s = String(cmd);
  const words = [];
  let cur = null;
  let simple = true;
  let quote = null;
  const push = (ch, at) => {
    if (!cur) cur = { text: '', start: at, end: at };
    cur.text += ch;
    cur.end = at + 1;
  };
  // PowerShell also treats typographic quotes (and dashes) as quote and
  // operator characters; zn does not model them, so they make a line non-simple.
  if (/[‘-‟–-―]/.test(s)) simple = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote === "'") {
      if (ch === "'" && s[i + 1] === "'") { push("'", i); i++; continue; }
      if (ch === "'") { quote = null; cur.end = i + 1; continue; }
      push(ch, i);
      continue;
    }
    if (quote === '"') {
      if (ch === '"') { quote = null; cur.end = i + 1; continue; }
      if (ch === '$' || ch === '`') simple = false;
      push(ch, i);
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      if (!cur) cur = { text: '', start: i, end: i + 1 };
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      if (cur) words.push(cur);
      cur = null;
      continue;
    }
    if (PS_META.has(ch)) simple = false;
    push(ch, i);
  }
  if (cur) words.push(cur);
  if (quote) simple = false;
  return { words, simple };
}

function psQuote(s) {
  return powershellQuote(portablePath(s));
}

/**
 * PowerShell counterpart of wrapWithZnRun. Commands with named markers are
 * only wrapped when the whole line is one native command with plain
 * arguments; anything else (cmdlets, aliases, pipelines, variables) is
 * refused, because zn cannot rewrite it safely.
 * opts: {nodePath, runJs, agent}
 */
function wrapPowerShell(cmd, opts) {
  const s = String(cmd);
  const named = markers.findNamedMarkers(s);
  if (named.length === 0) return { ok: true, command: s, wrapped: false };
  const guidance = ' Next step: start the command with the program name and put the secret in its arguments, for example: ' +
    "psql 'postgres://app:__ZN_DB_PASSWORD__@db/app' -c 'select 1'. For web requests, use the secrets_http_request tool of the zn \"secrets\" MCP server instead.";
  const scan = scanPowerShell(s);
  if (!scan.simple || scan.words.length === 0) {
    return { ok: false, reason: 'zn: this PowerShell command uses a pipeline, a variable or a script block, so zn cannot safely put a secret into it.' + guidance };
  }
  const first = scan.words[0].text;
  const base = path.basename(first.replace(/\\/g, '/')).toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, '');
  // zn-gate has the Verb-Noun shape of a cmdlet but is the zn program itself.
  if ((/^[a-z]+-[a-z]+$/i.test(first) && base !== 'zn-gate') || PS_ALIASES.has(first.toLowerCase())) {
    return { ok: false, reason: 'zn: "' + first + '" is a PowerShell command, not a program, so zn cannot pass a secret to it.' + guidance };
  }
  if (/\.ps1$/i.test(first)) {
    return { ok: false, reason: 'zn: this runs a PowerShell script (.ps1), and zn cannot pass secrets into scripts.' + guidance };
  }
  if (!/^[A-Za-z0-9_.\-\\/:]+$/.test(first)) {
    return { ok: false, reason: 'zn: this command does not start with a plain program name, so zn cannot tell which program to run.' + guidance };
  }
  if ((base === 'zn' || base === 'zn-gate') && scan.words[1] && scan.words[1].text === 'run') {
    return { ok: true, command: s, wrapped: false };
  }
  const prefix = '& ' + psQuote(opts.nodePath) + ' ' + psQuote(opts.runJs) + ' --agent ' + String(opts.agent).replace(/[^a-z0-9-]/g, '') + ' --';
  return { ok: true, command: prefix + ' ' + s.slice(scan.words[0].start), wrapped: true };
}

const NETWORK_RE = /(^|[\s;&|(`$'"])(curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|tftp|http|https|httpie|xh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)(?=$|[\s;&|)'"])|\bgit\s+(push|fetch|pull|clone|remote|ls-remote)\b|\b(npm|pnpm|yarn)\s+publish\b|\b(docker|podman)\s+(push|login)\b|\bhttps?:\/\/|\/dev\/(tcp|udp)\//i;

function hasNetworkSignals(cmd) {
  const s = String(cmd || '');
  if (NETWORK_RE.test(s)) return true;
  // Same heuristic as the engine's restore policy (network commands, URLs,
  // sockets and HTTP libraries in inline code).
  try { return require('../scrub/engine').isNetworkCommand(s); } catch (_) { return false; }
}

// The program is zn, zn-gate (also with a version: npx -y zn-gate@1.6.0, pnpm dlx zn-gate@latest) or the bin file.
const ZN_ADMIN_RE = /(^|[\s;&|(`$'"\\\/])((?:zn|zn-gate(?:@[^\s"'`;&|]+)?|cli\.js))(\.cmd|\.js|\.ps1)?["']?\s+(?:--\s+)?(secret\s+(set|get|rm|remove|import|adopt|approve|allow|reveal|link)|env\s+(shadow|unshadow)|unlock|lock|hooks\s+(install|uninstall)|init(?![^\n;&|#`$()'"<>\\]{0,512}[ \t]--(?:wrap-mcp|dry-run|revert|shadow)(?=[ \t\n]|$))|stats(?:\s+(?:-{1,2}[^\s-]\S*|\d+))*\s+share\s+on|["']?pins["']?\s+["']?approve)\b/i;

// `npm exec` (and `npm x`) keeps the options after the package for itself unless a `--` comes first, so
// `npm exec zn-gate init --dry-run` runs the guided init: the options do not count there. Checked per simple
// command, in one pass, with no length limit (padding the command must not hide it).
const NPM_EXEC_RE = /(?:^|[\s(`$'"\/\\])npm(?:-cli\.js|\.cmd|\.ps1)?["']?(?:\s+-\S+(?:\s+[^-\s]\S*)?)*\s+(?:exec|exe|x)(?=\s)/i;
const ZN_INIT_RE = /[\s\/\\'"](?:zn-gate|zn|cli\.js)(?:@[^\s"'`;&|]+)?["']?\s+["']?init(?=\s|$|["'])/i;
function npmExecInit(text) {
  for (const part of text.split(/[\n;&|]/)) {
    const e = NPM_EXEC_RE.exec(part);
    if (!e) continue;
    const rest = part.slice(e.index + e[0].length);
    const z = ZN_INIT_RE.exec(rest);
    if (z && !/(?:^|\s)--(?=\s|$)/.test(rest.slice(0, z.index))) return true;
  }
  return false;
}

function adminCommand(cmd) {
  const text = String(cmd || '');
  const m = ZN_ADMIN_RE.exec(text);
  if (m) return m[4].replace(/\s+/g, ' ');
  return npmExecInit(text) ? 'init' : null;
}

// Shell, PowerShell and Monitor commands longer than this are refused before
// any parsing, like the 1 MB limit for MCP calls: checking them could take
// longer than the agent waits for the hook, and a hook that times out lets the
// command run unchecked.
const SHELL_SCAN_CAP = 100 * 1024; // characters
function vaultMessage(opts = {}) {
  return 'zn blocked this: ~/.zn is where zn keeps your secrets, so agents may not read or change it. ' +
    'Next step: to use a secret in a command, write __ZN_NAME__ where the value goes (zn fills it in); to add one, ask the user to run `' +
    znCommand('secret set NAME', opts) + '` in their own terminal.';
}
const TOO_LONG_MESSAGE = 'zn: this command is too long for zn to check (over 100 KB), so it was blocked. Next step: tell the user; do not resend it in parts.';
// The agent runs a command unchecked when the hook times out (15 s in Claude Code), so checking a command has its
// own limits, well below that: a time budget and a number of looks on disk. Past either, the command is refused.
const CHECK_BUDGET_MS = 3000;
const TOO_MANY_MESSAGE = 'zn: this command chains more commands than zn checks at once, so it was blocked. Next step: run it as several shorter commands, or tell the user.';
const CHECK_BUDGET_DISK = 20000;
const TOO_SLOW_MESSAGE = 'zn: this command has too many paths for zn to check in time, so it was blocked. Next step: run it as several shorter commands, or tell the user.';

/**
 * Bash commands that read credential files or touch ~/.zn.
 * Returns null or a deny message.
 */
/*
 * Codex applies `apply_patch <<'PATCH' ... PATCH` itself when a model sends it as a shell command. When zn refuses
 * such a command, say which file the patch writes, instead of the first word that looked like a secret file.
 * Only the message changes: the decision is the one bashDenial made.
 */
const SHELL_PATCH_FILE_RE = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm;
// Each file name is resolved on disk, so a long patch is named by its first files only; the decision is already made.
const SHELL_PATCH_FILES_NAMED = 32;
function shellPatchMessage(cmd, deny, opts) {
  // Only a refused command that is a patch (apply_patch with *** lines); a too-long command keeps its own message.
  if (!deny || deny === TOO_LONG_MESSAGE || !/^\s*apply_patch\b/.test(String(cmd)) || !/^\*\*\* /m.test(String(cmd))) return deny;
  let seen = 0;
  for (const m of String(cmd).matchAll(SHELL_PATCH_FILE_RE)) {
    if (++seen > SHELL_PATCH_FILES_NAMED) break;
    const f = m[1].trim();
    const c = classifyPath(f, opts);
    // The name comes from the agent: no control characters, and short, in a message the user reads.
    const shown = f.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
    const name = shown.length > 120 ? shown.slice(0, 119) + '\u2026' : shown;
    if (!c || c.kind === 'agent_config' || c.kind === 'zn_state') continue;
    return 'zn: this patch was blocked because it writes to ' + name + ', which zn treats as holding secrets (' + c.reason + '). ' +
      'Next step: ask the user to make this change in that file.';
  }
  // Its *** lines read as file patterns that can match secret files, so zn refuses any patch in this form.
  return 'zn: this patch was blocked because it was sent as a shell command, which zn cannot check file by file ' +
    '(its *** lines look like file patterns that can match secret files). Next step: use the apply_patch tool, or write the file another way.';
}

function bashDenial(cmd, opts = {}) {
  return shellPatchMessage(cmd, bashDenialOf(cmd, opts), opts);
}

function bashDenialOf(cmd, opts = {}) {
  if (String(cmd || '').length > SHELL_SCAN_CAP) return TOO_LONG_MESSAGE;
  const admin = adminCommand(cmd);
  if (admin) return adminDenial(admin, opts, cmd);
  // The context (home, project, agent directories) is built once per command.
  opts = { ...opts, ctx: contextOf(opts) };
  opts.budget = { until: Date.now() + CHECK_BUDGET_MS, disk: CHECK_BUDGET_DISK };
  // The command is read three times: a backslash before a letter is a Windows
  // path separator or a bash escape, and a PowerShell backtick is an escape too.
  // A word protected in any reading is refused.
  const readings = [allWords(cmd, false), allWords(cmd, true), allWords(String(cmd).replace(/`(.)/gs, '$1'), false)];
  // Bash $'...' quoting spells characters as escapes ($'\x2eenv' is .env), and $"..." is a plain "...":
  // a fourth reading with them decoded.
  if (/\$['"]/.test(String(cmd))) readings.push(allWords(decodeAnsiC(String(cmd)), true));
  // A reading that could not be split to the end is refused, not checked in part.
  if (readings.some((r) => r.truncated)) return TOO_MANY_MESSAGE;
  const words = readings.flat();
  // Inside $( ) or backticks the text is not split into simple commands, so
  // every word of it is checked on its own, as if it were a word of the command.
  // The same for the code an interpreter runs (python -c "open('.env')"), where a path sits inside quotes and brackets.
  if (/\$\(|`/.test(String(cmd)) || words.some((w) => CODE_CMDS_RE.test(bareHead(w.head)))) {
    const split = [];
    for (const t of String(cmd).split(/[\s'"`$(){};|&<>=,]+/)) if (t) split.push({ text: t, redirectTarget: false, head: '', seq: 0 });
    words.push(...split);
    readings.push(split);
  }
  // Where a relative .env path may be read from once the command has changed directory (cd app && cat .env).
  // Each reading is followed on its own, so a cd counts once.
  opts.cdBases = cdBasesOf(readings, opts);
  opts.elsewhere = new Map();
  if (overBudget(opts.budget, 0)) return TOO_SLOW_MESSAGE;
  opts.cmdText = String(cmd);
  // A word is classified once per command: each classification resolves the path on disk, and a long command
  // often repeats the same words.
  const classified = new Map();
  // And so is its verdict, which may read the file (a .env, a .pem).
  const denied = new Map();
  // A word with * ? or [ can match a secret file; the message names a literal file when the command has one too.
  // The command is refused either way, so after a glob only a few more words are resolved on disk to find that file.
  const GLOB_NAME_LOOKAHEAD = 32;
  let globDeny = null;
  let afterGlob = 0;
  for (const w of words) {
    // --flag=value carries a path too (--kubeconfig=~/.kube/config).
    let text = w.text;
    if (text.startsWith('-')) {
      const eq = text.indexOf('=');
      // git log -L<range>:<file> names a file after the colon.
      const lineRange = isGit(w.head) ? /^-L[^:]*:(.+)$/.exec(text) : null;
      if (lineRange) text = lineRange[1];
      else if (eq < 0) continue;
      else text = text.slice(eq + 1);
    } else if (NAME_VALUE_RE.test(text)) {
      // name=value carries a path too (dd if=.env, ENV_FILE=.env).
      text = text.slice(text.indexOf('=') + 1);
    }
    if (!text) continue;
    const writing = !READ_ONLY_CMDS.has(w.head);
    if (!classified.has(text)) {
      if (globDeny && ++afterGlob > GLOB_NAME_LOOKAHEAD) return globDeny;
      if (overBudget(opts.budget, 1)) return TOO_SLOW_MESSAGE;
      classified.set(text, classifyWord(text, opts));
    }
    const c = classified.get(text);
    if ((!c || c.kind === 'dotenv') && isGit(w.head)) {
      // git show HEAD:.env, git cat-file -p :app/.env: a secret file read from the repository, not from disk.
      const deny = gitObjectDenial(text, opts) ||
        // git log -p -- .env, git checkout HEAD -- .env: its history, also once the file is gone from disk.
        (c && gitReadsContent(w.sub, w.gitArgs) ? gitHistoryDenial(text) : null);
      if (deny) return deny;
    }
    if (!c) {
      if (writing && AGENT_CONFIG_MENTION_RE.test(slash(text))) {
        return 'zn: this command would change agent hook or plugin settings, which is protected. Ask the user to make this change.';
      }
      continue;
    }
    if (c.kind === 'zn_state') return denialOf(c, text, opts);
    if (c.kind === 'agent_config') {
      if (w.redirectTarget || writing) return agentConfigDenial(text, c);
      continue; // reading the settings is allowed
    }
    if (w.redirectTarget) continue; // appending to .env is a write, not a read
    let deny;
    if (denied.has(text)) deny = denied.get(text);
    else { deny = denialOf(c, text, opts); denied.set(text, deny); }
    if (!deny && c.kind === 'dotenv') deny = dotenvElsewhereDenial(text, opts);
    if (deny && /[*?[]/.test(text)) { globDeny = globDeny || deny; continue; }
    if (deny) return deny;
  }
  return globDeny;
}

const NAME_VALUE_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}=/;
const ANSI_C_SIMPLE = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };

/* The command with each bash $'...' word decoded and quoted again as a plain '...' word, and $"..." read as "...". */
function decodeAnsiC(cmd) {
  return cmd.replace(/\$'((?:[^'\\]|\\[\s\S])*)'/g, (m, body) => {
    const text = body.replace(/\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c[\s\S]|[\s\S])/g, (e, x) => {
      if (/^[xuU]/.test(x)) {
        const n = parseInt(x.slice(1), 16);
        return n <= 0x10ffff ? String.fromCodePoint(n) : '';
      }
      if (/^[0-7]/.test(x)) return String.fromCharCode(parseInt(x, 8) & 0xff);
      if (x[0] === 'c' && x.length === 2) return String.fromCharCode(x.charCodeAt(1) & 0x1f);
      return Object.prototype.hasOwnProperty.call(ANSI_C_SIMPLE, x) ? ANSI_C_SIMPLE[x] : '\\' + x;
    });
    // Bash ends the string at the first NUL character.
    return "'" + text.split('\0')[0].replace(/'/g, "'\\''") + "'";
  }).replace(/\$"/g, '"');
}

// <rev>:<path> and :<path> name a file as git stores it (HEAD:.env, main~2:app/.env, :0:.env).
const GIT_OBJECT_RE = /^[^\s:]*:(?:[0-3]:)?([^:\s]\S*)$/;
// git subcommands that print or restore a file's stored content or history.
const GIT_READ_SUBCMDS = new Set(['show', 'log', 'diff', 'grep', 'archive', 'checkout', 'restore', 'blame', 'annotate', 'cat-file',
  'whatchanged', 'format-patch', 'difftool', 'stash', 'cherry-pick', 'apply', 'am']);
const GIT_VALUE_OPTS = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env']);

function isGit(head) {
  return String(head || '').replace(/\.exe$/, '') === 'git';
}

/* The subcommand of a git command: the first word after git that is not a global option (git -C app -c k=v log). */
function gitSubcommand(words) {
  let k = words.findIndex((x) => !ASSIGNMENT_RE.test(x.text));
  for (k++; k < words.length; k++) {
    const t = words[k].text;
    if (GIT_VALUE_OPTS.has(t)) { k++; continue; }
    if (t.startsWith('-')) continue;
    return t.toLowerCase();
  }
  return '';
}

// log, diff and show print only names or counts with one of these options...
const GIT_SUMMARY_OPTS = new Set(['--stat', '--shortstat', '--numstat', '--name-only', '--name-status', '--summary', '--dirstat', '--compact-summary']);
// ...as long as every other option is one that cannot add file content (an allowlist: -U3, --binary or
// --patch-with-stat bring the patch back, and git has many such options).
const GIT_SAFE_OPTS_RE = /^(?:--(?:stat|shortstat|numstat|name-only|name-status|summary|dirstat|compact-summary)(?:=[\w,.%-]*)?|--oneline|--no-color|--color(?:=\w+)?|--decorate(?:=\w+)?|--no-decorate|--graph|--reverse|--all|--follow|--no-merges|--merges|--first-parent|--abbrev-commit|--no-abbrev-commit|--cached|--staged|--no-renames|--relative|--date=[\w:%.-]+|--(?:since|until|after|before|author|committer|grep)=[^\s]*|--max-count=\d+|-n|-\d+|--(?:format|pretty)=[^\s]*)$/;

/* Whether a git command prints or brings back a file's stored content. Steps that only clean up stay allowed:
   git restore --staged .env, git checkout -- .env (from the index to disk), git stash push -- .env, git log --stat -- .env. */
function gitReadsContent(sub, args) {
  if (!GIT_READ_SUBCMDS.has(sub)) return false;
  const a = args || [];
  const at = a.findIndex((x) => x.toLowerCase() === sub);
  const rest = at >= 0 ? a.slice(at + 1) : a;
  const dashdash = rest.indexOf('--');
  const before = dashdash >= 0 ? rest.slice(0, dashdash) : rest;
  const positional = before.filter((x) => !x.startsWith('-'));
  if (sub === 'stash') return positional[0] === 'show';
  if (sub === 'restore') return rest.some((x) => x.startsWith('-s') || x.startsWith('--source'));
  // checkout <rev> -- <file> (or checkout <rev> <file>) brings back a stored copy; checkout -- <file> uses the index.
  if (sub === 'checkout') return dashdash >= 0 ? positional.length > 0 : positional.length > 1;
  if (['log', 'diff', 'show', 'whatchanged'].includes(sub)) {
    const opts = before.filter((x) => x.startsWith('-'));
    const summary = opts.some((x) => GIT_SUMMARY_OPTS.has(x.split('=')[0]));
    // git log --oneline lists commits only; git show --oneline still prints the patch.
    const listOnly = sub === 'log' && opts.includes('--oneline');
    if ((summary || listOnly) && opts.every((x) => GIT_SAFE_OPTS_RE.test(x))) return false;
  }
  return true;
}

function gitHistoryDenial(text) {
  return 'zn: this git command reads the stored content or history of ' + path.basename(text) + ', which zn treats as holding secrets, ' +
    'so it was not run. If the repository holds real values in it, tell the user: they should be rotated and removed from the history.';
}

/* A git object word whose path is a .env or credential file. The stored copy cannot be checked for values without
   running git, and a .env kept in the repository with values is the case to stop, so it is refused. */
function gitObjectDenial(text, opts) {
  const m = GIT_OBJECT_RE.exec(text);
  if (!m || /^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return null;
  // git drops leading ./ from the path (HEAD:././.env is .env).
  const file = m[1].replace(/^(?:\.\/)+/, '');
  const c = classifyPath(file, opts) || classifyPath(path.basename(file), opts);
  if (!c || c.kind === 'agent_config') return null;
  return 'zn: ' + text + ' reads ' + path.basename(file) + ' from the git repository, and zn treats that file as holding secrets, ' +
    'so it was not read. If the repository holds real values in it, tell the user: they should be rotated and removed from the history.';
}

// Commands that change the directory the rest of the command runs in.
const CD_CMDS = new Set(['cd', 'chdir', 'pushd', 'sl', 'set-location', 'push-location']);
// Interpreters and shells whose code argument can name a file inside quotes or brackets.
const CODE_CMDS_RE = /^(?:python[0-9.]*|py|node|nodejs|deno|bun|ruby|perl|php|lua|osascript|pwsh|powershell|bash|sh|zsh|dash|ksh|fish|cmd)(?:\.exe)?$/;
const CD_BASES_MAX = 16;

function bareHead(h) {
  return String(h || '').replace(/^\(+/, '');
}

/* The directories a relative path in the command may be read from: the working directory and every place a cd in it
   may lead to (a cd that fails leaves the command where it was, so earlier places stay). `unknown` is set when a cd goes
   somewhere zn cannot follow (cd -, cd $DIR, cd $(...)); `moved` when the command has any cd at all. */
function cdBasesOf(readings, opts) {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const cwd = path.resolve(opts.cwd || process.cwd());
  const all = new Set([cwd]);
  let unknown = false;
  let moved = false;
  for (const words of readings) {
    if (unknown) break;
    let bases = [cwd];
    for (let k = 0; k < words.length && !unknown; k++) {
      // Found by its text, not by the command's head, so { cd x; ... } and if cd x; then ... count too.
      if (!CD_CMDS.has(words[k].text.replace(/^[({]+/, '').toLowerCase())) continue;
      moved = true;
      // Each cd followed costs its new places; past the budget, the rest cannot be followed.
      if (overBudget(opts.budget, bases.length)) { unknown = true; break; }
      // The target: the next word of the same simple command that is not an option (cd -P dir, Set-Location -Path dir).
      let t = '~';
      for (let j = k + 1; j < words.length && words[j].seq === words[k].seq; j++) {
        const x = words[j].text.replace(/^["']|["']$/g, '').replace(/[;)}]+$/, '');
        if (!x || (x.startsWith('-') && x !== '-')) continue;
        t = x;
        break;
      }
      const target = t === '-' ? '-' : expandEnv(expandHome(t, home), env).text;
      if (target === '-' || /[$`*?[{]/.test(target)) { unknown = true; continue; }
      const next = new Set(bases);
      for (const b of bases) next.add(path.resolve(b, target));
      if (next.size > CD_BASES_MAX) { unknown = true; continue; }
      bases = [...next];
      for (const d of bases) all.add(d);
    }
  }
  return { dirs: [...all], unknown, moved };
}

/* A .env path the working directory alone does not settle: one built while the command runs ($DIR/.env, $(...)/.env),
   or one read after a cd. Refused when zn cannot rule out that it reaches a .env file with values.
   The answer is kept per word: the places a cd leads to are the same for the whole command. */
function dotenvElsewhereDenial(text, opts) {
  if (opts.elsewhere && opts.elsewhere.has(text)) return opts.elsewhere.get(text);
  const deny = dotenvElsewhereOf(text, opts);
  if (opts.elsewhere) opts.elsewhere.set(text, deny);
  return deny;
}

function dotenvElsewhereOf(text, opts) {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const expanded = expandEnv(expandHome(text, home), env).text;
  const missing = !fs.existsSync(resolvedOf(text, opts));
  // $DIR/.env with a variable zn does not know, or a path whose start is the output of another command
  // (`cat $(echo app)/.env` leaves the word /.env right after the closing bracket).
  const cmdText = opts.cmdText || '';
  const afterSubstitution = /[()]/.test(text) || cmdText.includes(')' + text) || cmdText.includes('`' + text);
  if (/[$`]/.test(expanded) || (missing && afterSubstitution)) {
    return 'zn: this command builds the path of a .env file while it runs (' + text + '), so zn cannot check whether it holds secrets. ' +
      'Name the file directly, for example `cat app/.env`; if it holds values, ask the user to run `' + znCommand('env shadow .env', opts) + '` in that folder.';
  }
  const bases = opts.cdBases || { dirs: [], unknown: false, moved: false };
  if (!bases.moved) return null;
  // $PWD follows the cd; any other absolute path does not.
  const pwdRef = /\$\{?PWD\b/.test(text);
  if (path.isAbsolute(expanded) && !pwdRef) return null;
  const cwd = path.resolve(opts.cwd || process.cwd());
  for (const dir of bases.dirs) {
    if (dir === cwd) continue;
    if (overBudget(opts.budget, 1)) return TOO_SLOW_MESSAGE;
    const deny = readDenial(text, { ...opts, cwd: dir, env: pwdRef ? { ...env, PWD: dir } : env });
    if (deny) {
      // The folder as the user would type it: relative below the current folder, absolute above it.
      const rel = path.relative(cwd, dir);
      const where = slash(rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : dir);
      return 'zn: this command changes to ' + where + ' first. ' + deny.replace(/^zn: /, '');
    }
  }
  if (bases.unknown) {
    return 'zn: this command changes to a folder zn cannot follow and then reads ' + text + ', so zn cannot check whether it holds secrets. ' +
      'Give the path from the current folder instead, for example `cat app/.env`.';
  }
  return null;
}

/* zn commands only the user may run: what the command does, why an agent may not, and the next step. */
function adminDenial(admin, opts = {}, cmd = '') {
  const run = (args) => 'Next step: ask the user to run `' + znCommand(args, opts) + '` in their own terminal.';
  const m = ZN_ADMIN_RE.exec(String(cmd));
  const words = m ? String(cmd).slice(m.index + m[0].length).trim().split(/[\s;&|]+/).slice(0, 8).map((w) => w.replace(/^["']|["']$/g, '')) : [];
  const next = words.find((w) => !w.startsWith('-')) || '';
  let arg = '';
  if (/^hooks/i.test(admin)) {
    arg = /^(claude-code|codex|cursor|opencode)$/.test(next) ? next : '<agent>';
    // The fixed options of zn hooks install, so the user installs in the same place the agent asked for.
    for (const o of ['--project', '--no-mcp']) if (words.includes(o)) arg += ' ' + o;
  } else if (/^secret (set|get|rm|remove|reveal|allow|approve|link)$/i.test(admin)) {
    arg = /^[A-Z_][A-Z0-9_]{0,63}$/.test(next) ? next : 'NAME';
  } else if (/^env/i.test(admin)) {
    const base = path.basename(next);
    arg = /^[\w.-]{1,128}$/.test(base) && !/^\.+$/.test(base) ? base : '.env';
  }
  const full = arg ? admin + ' ' + arg : admin;
  if (/pins/i.test(admin)) {
    return 'zn blocked this: approving changed MCP tools is the user\'s decision, so an agent may not run `zn-gate pins approve`. ' + run('pins approve');
  }
  if (/^init$/i.test(admin)) {
    return 'zn blocked this: `zn-gate init` turns zn\'s protection on for coding agents, which is the user\'s decision. ' +
      'Next step: ask the user to run it in their own terminal (`npx -y zn-gate init`).';
  }
  if (/^hooks/i.test(admin)) {
    return 'zn blocked this: `' + znCommand(admin, opts) + '` turns zn\'s protection on or off for a coding agent, which is the user\'s decision. ' + run(full);
  }
  if (/^(un)?lock$/i.test(admin)) {
    return 'zn blocked this: locking or unlocking the secret vault is the user\'s decision, so an agent may not run `' + znCommand(admin, opts) + '`. ' + run(admin);
  }
  if (/^stats/i.test(admin)) {
    return 'zn blocked this: only the user can turn on sharing of zn\'s usage statistics. ' + run('stats share on');
  }
  return 'zn blocked this: `' + znCommand(admin, opts) + '` reads or changes secret values, and secret values never go to the AI model. ' + run(full);
}

/** The deny message for a read or write classified by classifyWord. */
function denialOf(c, text, opts) {
  if (c.kind === 'zn_state') return vaultMessage(opts);
  if (c.kind === 'dotenv' || c.kind === 'keyfile') return readDenial(text, opts);
  return credentialDenial(text, c);
}

module.exports = {
  POLICY_RULES_VERSION,
  classifyPath,
  classifyWord,
  globClass,
  globRegExp,
  _globClassEnd: globClassEnd,
  _decodeAnsiC: decodeAnsiC,
  _globClassSource: globClassSource,
  expandBraces,
  readDenial,
  writeDenial,
  scanFirstCommand,
  wrapWithZnRun,
  scanPowerShell,
  wrapPowerShell,
  hasNetworkSignals,
  adminCommand,
  bashDenial,
  SHELL_SCAN_CAP,
};
