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
const POLICY_RULES_VERSION = '2026-10-18.31';

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
  // With "\" a separator too, so a Windows spelling names the same file on every platform.
  const base = path.basename(s);
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
  let keyHit = null;
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
    const hits = globOnDisk(abs, opts.budget);
    if (hits === 'too-broad' || hits === 'too-slow') return { kind: 'credential', reason: 'a pattern too broad to check' };
    for (const hit of hits || []) {
      for (const cand of new Set([hit, realTargetOf(hit)])) {
        const c = classifyResolved(cand, ctx);
        // A key file match is judged by its content (keyFileGlobDenial); a protected file found later still wins.
        if (c && c.kind === 'keyfile') { keyHit = keyHit || c; continue; }
        if (c) return c.kind === 'dotenv' ? { kind: 'credential', reason: 'a pattern that matches a .env file' } : c;
      }
    }
  }
  return keyHit;
}

/**
 * The paths a glob matches on the disk now: its literal start is read, and
 * each glob component is matched against the names in its directory.
 * Returns the matches, 'too-broad' past GLOB_DISK_LIMIT entries, or null.
 */
function globOnDisk(abs, cmdBudget) {
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
        // Reading the names of a folder also spends the command's own budget (an over-budget command is refused).
        if (cmdBudget && overBudget(cmdBudget, names.length)) return 'too-slow';
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
  if (GLOB_RE.test(p)) return keyFileGlobDenial(p, c, opts);
  const text = readHead(resolvedOf(p, opts), KEY_SCAN_BYTES);
  if (text === null) return null; // missing file: nothing to protect
  if (text === NOT_A_FILE || PRIVATE_KEY_RE.test(text)) return credentialDenial(p, c);
  return null;
}

/* A glob or brace word that can name a key file: what it matches on the disk now is read with the command's budget,
   and the word is refused when any match holds a private key (or is not a regular file). */
function keyFileGlobDenial(p, c, opts) {
  const ctx = contextOf(opts);
  const broad = { kind: 'keyfile', reason: 'a pattern too broad to check' };
  const alts = expandBraces(p);
  if (alts === null) return credentialDenial(p, broad);
  if (alts.length * p.length > GLOB_WORK_MAX) return credentialDenial(p, broad);
  for (const alt of alts) {
    if (overBudget(opts.budget, 1)) return TOO_SLOW_MESSAGE;
    const abs = slash(path.resolve(opts.cwd || ctx.cwd, expandEnv(expandHome(alt, ctx.home), opts.env || ctx.env).text));
    const hits = globOnDisk(abs, opts.budget);
    if (hits === 'too-slow') return TOO_SLOW_MESSAGE;
    if (hits === 'too-broad') return credentialDenial(p, broad);
    for (const hit of hits || []) {
      const hc = classifyPath(hit, { ...opts, ctx });
      if (!hc || hc.kind !== 'keyfile') continue;
      if (overBudget(opts.budget, 1)) return TOO_SLOW_MESSAGE;
      const text = readHead(hit, KEY_SCAN_BYTES);
      if (text !== null && (text === NOT_A_FILE || PRIVATE_KEY_RE.test(text))) return credentialDenial(p, hc);
    }
  }
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
    // git also runs behind sudo, env, command, xargs and the like.
    const gi = gitStart(scan.words);
    const sub = gi >= 0 ? gitSubcommand(scan.words.slice(gi)) : '';
    const gitArgs = sub ? scan.words.map((x) => x.text) : null;
    for (let k = 0; k < scan.words.length; k++) {
      const w = scan.words[k];
      const prev = k > 0 ? scan.words[k - 1].text : '';
      const isRedirTarget = /^[0-9]*>>?$/.test(prev) || /^[0-9]*>>?./.test(w.text);
      // Input redirections: <file, 0<file, <>file (read and write), {fd}<file.
      out.push({ text: w.text.replace(/^[0-9]*>>?/, '').replace(/^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?<>?/, ''), redirectTarget: isRedirTarget, head, seq: guard, sub, gitArgs, git: gi >= 0 });
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
const ZN_ADMIN_RE = /(^|[\s;&|(`$'"\\\/])((?:zn|zn-gate(?:@[^\s"'`;&|]+)?|cli\.js))(\.cmd|\.js|\.ps1)?["']?\s+(?:--\s+)?(secret\s+(set|get|rm|remove|import|adopt|approve|allow|reveal|link)|env\s+(shadow|unshadow)|unlock|lock|connect|disconnect|hooks\s+(install|uninstall)|init(?![^\n;&|#`$()'"<>\\]{0,512}[ \t]--(?:wrap-mcp|dry-run|revert|shadow)(?=[ \t\n]|$))|stats(?:\s+(?:-{1,2}[^\s-]\S*|\d+))*\s+share\s+on|["']?pins["']?\s+["']?approve)\b/i;

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

// How deep sh -c "sh -c '...'" is followed; deeper is refused.
const SHELL_CODE_DEPTH = 3;
const TOO_NESTED_MESSAGE = 'zn: this command nests shell code (sh -c "sh -c ...") deeper than zn checks, so it was blocked. Next step: run the inner command directly, or tell the user.';
const SHELL_NAMES = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'fish', 'csh', 'tcsh', 'rbash']);
const SHELL_C_FLAG_RE = /^-[A-Za-z]*c[A-Za-z]*$/;

function programName(text) {
  return String(text).replace(/^\(+/, '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
}

/* The code strings that programs which run code from a string would run: sh -c, bash -lc, su -c, flock -c, env -S,
   pwsh -Command, cmd /c, eval, watch, and "git <args>" for PowerShell's Start-Process git -ArgumentList. Only these
   launchers (found through sudo, env, xargs and the other wrappers) are read this way: the -c of psql or grep is not code. */
function shellCodesOf(words, out = new Set()) {
  let start = 0;
  while (start < words.length) {
    let end = start;
    while (end < words.length && words[end].seq === words[start].seq) end++;
    codesOfCommand(words.slice(start, end), out);
    start = end;
  }
  return out;
}

// Shells, PowerShell and cmd: when a wrapper chain does not resolve, the first of these words followed by code still counts.
const FALLBACK_LAUNCHERS = new Set([...SHELL_NAMES, 'busybox', 'pwsh', 'powershell', 'cmd', 'su', 'sg', 'runuser', 'script', 'flock']);
// Options of bash and zsh that take a value, which may sit between the shell and -c.
const SHELL_VALUE_OPTS = new Set(['-O', '+O', '-o', '+o', '--rcfile', '--init-file', '--init-command']);
const FALLBACK_HEAVY_MAX = 16;
const POWERSHELL_PARAM_RE = /^[-\/]([A-Za-z]+)$/;

/* The code strings a launcher at w[k] runs from a string; true when `name` is a launcher that was read (the rest of the
   command is then what it runs). env only reports its -S string and lets the wrapper chain go on. */
function launcherCodes(w, k, name, out) {
  const join = (from) => w.slice(from).map((x) => x.text).join(' ');
  if (name === 'eval' || name === 'iex' || name === 'invoke-expression') { out.add(join(k + 1)); return true; }
  if (name === 'watch') {
    let j = k + 1;
    while (j < w.length && w[j].text.startsWith('-')) j += w[j].text === '-n' || w[j].text === '--interval' ? 2 : 1;
    if (j < w.length) out.add(join(j));
    return true;
  }
  if (SHELL_NAMES.has(name)) {
    for (let j = k + 1; j < w.length; j++) {
      const t = w[j].text;
      if (t === '--' || !/^[-+]/.test(t)) break;
      if (SHELL_VALUE_OPTS.has(t)) { j++; continue; }
      if (name === 'fish' && (t === '-C' || t === '--init-command') && w[j + 1]) { out.add(w[j + 1].text); j++; continue; }
      if (SHELL_C_FLAG_RE.test(t)) { if (w[j + 1]) out.add(w[j + 1].text); break; }
    }
    return true;
  }
  if (name === 'su' || name === 'sg' || name === 'runuser' || name === 'script' || name === 'flock') {
    for (let j = k + 1; j < w.length; j++) {
      const t = w[j].text;
      if (t.startsWith('--command=')) out.add(t.slice(10));
      else if (t === '--command' || t === '-c' || (name !== 'flock' && SHELL_C_FLAG_RE.test(t))) { if (w[j + 1]) out.add(w[j + 1].text); }
    }
    // runuser -u user -- command goes on through the wrapper chain; the others are done.
    return name !== 'runuser';
  }
  if (name === 'pwsh' || name === 'powershell') {
    let first = -1;
    for (let j = k + 1; j < w.length; j++) {
      const t = w[j].text;
      const m = POWERSHELL_PARAM_RE.exec(t);
      if (!m) { if (first < 0) first = j; continue; }
      // Any unambiguous prefix of the parameter name works in PowerShell (-c, -com, /Command, -en, -EncodedCom).
      const n = m[1].toLowerCase();
      if ('command'.startsWith(n)) { out.add(join(j + 1)); return true; }
      if (n === 'e' || n === 'ec' || 'encodedcommand'.startsWith(n)) {
        // Base64 of UTF-16 text: decoded and read as code.
        if (w[j + 1]) out.add(Buffer.from(w[j + 1].text, 'base64').toString('utf16le'));
        return true;
      }
    }
    // Windows PowerShell reads the first argument that is not a parameter as the command.
    if (first >= 0) out.add(join(first));
    return true;
  }
  if (name === 'cmd') {
    for (let j = k + 1; j < w.length; j++) if (/^\/[ckr]$/i.test(w[j].text)) { out.add(join(j + 1)); return true; }
    return true;
  }
  if (name === 'env') {
    for (let j = k + 1; j < w.length && w[j].text.startsWith('-'); j++) {
      const t = w[j].text;
      if (t === '-S' || t === '--split-string') { if (w[j + 1]) out.add(w[j + 1].text); }
      else if (t.startsWith('--split-string=')) out.add(t.slice(15));
      else if (t.startsWith('-S')) out.add(t.slice(2));
    }
  }
  return false;
}

function codesOfCommand(w, out) {
  for (let j = 1; j < w.length; j++) {
    if (!/^-arg/i.test(w[j - 1].text) || !w[j].text) continue;
    for (let i = j - 2; i >= 0; i--) if (wordIsGit(w[i].text)) { out.add('git ' + w[j].text.replace(/,/g, ' ')); break; }
  }
  const first = w.findIndex((x) => !ASSIGNMENT_RE.test(x.text));
  let k = first;
  let resolved = false;
  for (let guard = 0; k >= 0 && k < w.length && guard < 16; guard++) {
    const name = programName(w[k].text);
    if (launcherCodes(w, k, name, out)) { resolved = true; break; }
    if (!Object.prototype.hasOwnProperty.call(GIT_WRAPPERS, name)) break;
    k = skipWrapper(w, k, name);
  }
  // The chain did not reach a launcher (an unknown wrapper, odd options): the first shell word counts as the launcher.
  if (!resolved && first >= 0) {
    // A shell word costs a look at the next few words; the launchers that read the whole rest are limited, and past
    // the limit the rest of the command is read as code (never skipped).
    let heavy = 0;
    for (let j = first; j < w.length; j++) {
      const name = programName(w[j].text);
      if (!FALLBACK_LAUNCHERS.has(name)) continue;
      if (!SHELL_NAMES.has(name) && ++heavy > FALLBACK_HEAVY_MAX) { out.add(w.slice(j).map((x) => x.text).join(' ')); break; }
      launcherCodes(w, j, name, out);
    }
  }
}

/* --------------------------- here-documents --------------------------- */

/*
 * The body of a here-document (`cat > f <<'EOF' ... EOF`) is data the shell
 * writes to a file or feeds to a program that reads it as data, not words of
 * the command line: a `*` in it names no file and a path in it is not read.
 * Such a body is dropped before the command is read, which also keeps a 100 KB
 * write cheap to check. A quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`)
 * turns the expansions off, so the body is dropped whole. A bare delimiter
 * (`<<EOF`) still expands the body first, so its `$( )`, backticks and `$VAR`
 * are put back as words; dropping them would hide a substitution that reads a
 * secret file.
 *
 * Only the body of a plain data command is dropped: the command that holds the
 * operator must be a plain simple one (no pipe, no process substitution, no
 * group closed before it), its program must be a known data program (`cat`,
 * `tee`, `dd`, ...) and not empty, and the command must not run code after the
 * here-document. Every other body keeps the check it had, which is the safe side.
 */

// A here-document operator starts a redirect. `<<` glued to the end of a word
// (`x<<y`, an arithmetic shift) is left alone: missing one only means its body
// is checked as if it were code, which is the safe side.
const HEREDOC_START_RE = /[\s;&|(\n]/;
// Characters that end a run and are read by stripHeredocs: quotes, escapes, a
// comment, a line break, and every separator or group bracket of the command.
const HEREDOC_SPECIAL_RE = /[<>(){};&|`'"\\#\n]/g;

/** The here-document operator at `from` (`<<`, `<<-`) with its delimiter, or null. */
function heredocAt(s, from) {
  if (s[from] !== '<' || s[from + 1] !== '<' || s[from + 2] === '<') return null;
  if (from > 0 && !HEREDOC_START_RE.test(s[from - 1])) return null;
  let j = from + 2;
  const stripTabs = s[j] === '-';
  if (stripTabs) j++;
  let quoted = false;
  let delimiter = '';
  while (j < s.length) {
    const c = s[j];
    if (c === "'" || c === '"') {
      const close = s.indexOf(c, j + 1);
      if (close === -1) return null;
      quoted = true;
      delimiter += s.slice(j + 1, close);
      j = close + 1;
      continue;
    }
    if (c === '\\') {
      if (j + 1 >= s.length) return null;
      quoted = true;
      delimiter += s[j + 1];
      j += 2;
      continue;
    }
    if (/[\s;&|()<>]/.test(c)) break;
    delimiter += c;
    j++;
  }
  if (!delimiter) return null;
  return { doc: { delimiter, quoted, stripTabs }, end: j };
}

/** What an unquoted here-document body still runs, as words: its `$( )`, backticks and `$VAR`. */
function heredocExpansions(body) {
  let out = '';
  const add = (text) => { out += (out && !/\s$/.test(out) ? ' ' : '') + text; };
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '\\') { i++; continue; }
    if (ch === '`') {
      const end = body.indexOf('`', i + 1);
      const stop = end === -1 ? body.length : end + 1;
      add(body.slice(i, stop));
      i = stop - 1;
      continue;
    }
    if (ch !== '$') continue;
    const n = body[i + 1];
    if (n === '(') {
      let depth = 0;
      let j = i + 1;
      for (; j < body.length; j++) {
        if (body[j] === '(') depth++;
        else if (body[j] === ')' && --depth === 0) { j++; break; }
      }
      add(body.slice(i, j));
      i = j - 1;
    } else if (n === '{') {
      const end = body.indexOf('}', i + 2);
      const stop = end === -1 ? body.length : end + 1;
      add(body.slice(i, stop));
      i = stop - 1;
    } else {
      const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(body.slice(i + 1));
      if (name) { add('$' + name[0]); i += name[0].length; }
    }
  }
  return out;
}

/*
 * Drop the bodies of the pending here-documents from `s`, starting at the line
 * after their operator, and return the index to read on from. `keep` receives
 * what is left of each unquoted body. A delimiter with no closing line makes
 * the shell feed the rest of the input as the body (it is not run), so the rest
 * is dropped too.
 */
function skipHeredocBodies(s, from, pending, keep) {
  let cursor = from;
  for (const doc of pending) {
    const bodyStart = cursor;
    let termStart = -1;
    let pos = cursor;
    for (;;) {
      const nl = s.indexOf('\n', pos);
      const lineEnd = nl === -1 ? s.length : nl;
      let line = s.slice(pos, lineEnd);
      if (doc.stripTabs) line = line.replace(/^\t+/, '');
      if (line.replace(/\r$/, '') === doc.delimiter) { termStart = pos; break; }
      if (nl === -1) break;
      pos = nl + 1;
    }
    const bodyEnd = termStart === -1 ? s.length : termStart;
    if (!doc.quoted) keep(heredocExpansions(s.slice(bodyStart, bodyEnd)));
    if (termStart === -1) return s.length;
    const nl = s.indexOf('\n', termStart);
    cursor = nl === -1 ? s.length : nl + 1;
  }
  return cursor;
}

/**
 * The command with the bodies of its data here-documents removed (see above).
 * A body is kept when its command is not a plain simple command with a known
 * data program: a pipe, a process substitution or an open group (also one opened
 * on an earlier line) makes that command not simple, a command that writes a
 * file and then runs it or that redefines how a name resolves keeps the check,
 * and so does a program that runs code after the here-document. `budget` bounds
 * the work; past it the command is left whole.
 */
function stripHeredocs(cmd, budget) {
  const s = String(cmd);
  if (s.indexOf('<<') === -1) return s;
  const parts = [];
  let outLen = 0;
  const keep = (t) => { if (t) { parts.push(t); outLen += t.length; } };
  let quote = null;
  let pending = [];
  // State of the simple command that holds the operator. A body is data only in
  // a plain simple command: no pipe or process substitution, no group closed
  // before it, and a non-empty known data program.
  let segStart = 0;
  let segProgram; // the program of the segment, computed once
  let segPipe = false;
  let segClose = false;
  let parens = 0; // `(` and `)` open here; a `)` with no `(` is a `case` pattern
  let braces = 0; // `{` and `}` open here; both are kept across lines
  let hasData = false;
  let tailStart = -1; // output length just before the first data operator
  let i = 0;
  let ticks = 0;
  // A separator ends the command: the next one starts after it, plain again.
  const reset = (at) => { segStart = at; segProgram = undefined; segPipe = false; segClose = false; };
  // A pipe, a process substitution or a group after an operator makes its body code.
  const drop = () => { if (pending.length) pending = []; };
  while (i < s.length) {
    if ((++ticks & 4095) === 0 && overBudget(budget, 0)) return s;
    if (quote === "'") {
      const end = s.indexOf("'", i + 1);
      keep(s.slice(i, end === -1 ? s.length : end + 1));
      i = end === -1 ? s.length : end + 1;
      if (end !== -1) quote = null;
      continue;
    }
    if (quote === '"') {
      let j = i;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      const stop = Math.min(j + 1, s.length);
      keep(s.slice(i, stop));
      i = stop;
      if (j < s.length) quote = null;
      continue;
    }
    HEREDOC_SPECIAL_RE.lastIndex = i;
    const m = HEREDOC_SPECIAL_RE.exec(s);
    if (!m) { keep(s.slice(i)); break; }
    if (m.index > i) { keep(s.slice(i, m.index)); i = m.index; }
    const ch = s[i];
    if (ch === "'" || ch === '"') { quote = ch; keep(ch); i++; continue; }
    if (ch === '\\') { keep(s.slice(i, i + 2)); i += 2; continue; }
    if (ch === '#' && (i === 0 || HEREDOC_START_RE.test(s[i - 1]))) {
      const nl = s.indexOf('\n', i);
      if (nl === -1) { keep(s.slice(i)); break; }
      keep(s.slice(i, nl));
      i = nl;
      continue;
    }
    if (ch === '\n') {
      keep('\n');
      i++;
      if (pending.length) { i = skipHeredocBodies(s, i, pending, keep); pending = []; }
      reset(i);
      continue;
    }
    if (ch === ';') { keep(ch); i++; reset(i); continue; }
    if (ch === '&') {
      // &> and &>> are redirects, as are >& and <& (a file-descriptor copy).
      if (s[i + 1] === '>' || s[i - 1] === '>' || s[i - 1] === '<') { keep(ch); i++; continue; }
      keep(ch); i++;
      if (s[i] === '&') { keep('&'); i++; } // && or the & of |&
      reset(i);
      continue;
    }
    if (ch === '|') {
      if (s[i + 1] === '|') { keep('||'); i += 2; reset(i); continue; } // || separates commands
      segPipe = true; drop(); // | or |&: a pipeline, not a simple command
      keep(ch); i++;
      if (s[i] === '&') { keep('&'); i++; }
      continue;
    }
    // A group or a substitution keeps the check on its bodies. The depth is kept
    // across lines, and each bracket only closes its own kind, so the `)` of a
    // `case` pattern does not close an open `{` group.
    if (ch === '{') { braces++; segClose = true; drop(); keep(ch); i++; continue; }
    if (ch === '}') { if (braces > 0) braces--; segClose = true; drop(); keep(ch); i++; continue; }
    if (ch === ')') { if (parens > 0) parens--; segClose = true; drop(); keep(ch); i++; continue; }
    if (ch === '<') {
      const h = heredocAt(s, i);
      if (h) {
        if (segProgram === undefined) segProgram = heredocConsumer(s.slice(segStart, Math.min(i, segStart + 512)));
        if (parens === 0 && braces === 0 && !segPipe && !segClose && segProgram && HEREDOC_DATA_CMDS.has(segProgram)) {
          if (tailStart === -1) tailStart = outLen;
          hasData = true;
          pending.push(h.doc);
        }
        keep(s.slice(i, h.end));
        i = h.end;
        continue;
      }
      if (s[i + 1] === '(') { segPipe = true; drop(); keep(ch); i++; continue; } // <( process substitution
      keep(ch); i++;
      continue;
    }
    if (ch === '>') {
      if (s[i + 1] === '(') { segPipe = true; drop(); keep(ch); i++; continue; } // >( process substitution
      keep(ch); i++;
      continue;
    }
    // Arithmetic (`$(( ))`, `(( ))`): a `<<` inside it is a shift, not a
    // here-document. The run is read once: closed it is kept whole, and unclosed
    // it is read to the end of its line, so a run of `(` stays linear.
    if (ch === '(' && s[i + 1] === '(') {
      let nesting = 0;
      let j = i;
      for (; j < s.length && s[j] !== '\n'; j++) {
        if ((++ticks & 4095) === 0 && overBudget(budget, 0)) return s;
        if (s[j] === '(') nesting++;
        else if (s[j] === ')' && --nesting === 0) { j++; break; }
      }
      keep(s.slice(i, j));
      i = j;
      segClose = true;
      drop();
      continue;
    }
    if (ch === '(') { parens++; segClose = true; drop(); keep(ch); i++; continue; }
    keep(ch);
    i++;
  }
  const out = parts.join('');
  if (!hasData) return out;
  const tail = out.slice(tailStart);
  // A command that writes a file and then runs it, redefines how a name resolves,
  // or pipes it on a later line, keeps the old check: the body is code that runs.
  if (HEREDOC_RUN_AFTER_RE.test(tail) || HEREDOC_DEFINES_RE.test(out) || runsCodeAfter(tail, writtenFiles(out))) return s;
  return out;
}

/*
 * A here-document whose body a program reads as plain data (`cat > f`, `tee`,
 * `dd`) cannot leak a secret by reading it, so its body is dropped before the
 * command is checked. A body a program runs as code (a shell, an interpreter,
 * apply_patch) still holds a command or a file pattern, so it keeps the check
 * it had. Only the data programs are listed: an unknown program keeps the
 * check, which is the safe side.
 */
const HEREDOC_DATA_CMDS = new Set(['cat', 'tac', 'tee', 'dd', 'tr', 'uniq', 'wc', 'head', 'tail', 'cut', 'paste',
  'join', 'grep', 'egrep', 'fgrep', 'rg', 'diff', 'cmp', 'comm', 'jq', 'base64', 'nl', 'od', 'xxd', 'hexdump',
  'sha256sum', 'sha1sum', 'sha512sum', 'md5sum', 'shasum', 'cksum', 'gzip', 'gunzip', 'zcat', 'bzip2', 'bunzip2',
  'xz', 'unxz', 'zstd', 'fold', 'expand', 'unexpand', 'fmt', 'column', 'rev']);

// `sort --compress-program` and `split --filter` run a program on the data, so
// neither is a plain data program. A command that defines a function or changes
// how a name resolves (`PATH`, `alias`, `hash`, `enable`) can do the same to any
// data program, so no body of it is data either.
const HEREDOC_DEFINES_RE = /(?:^|[^A-Za-z0-9_])(?:function\s+[A-Za-z_]|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\{|PATH\s*=|alias\s|hash\s|enable\s)/;

// A pipe or a process substitution that appears after the first data body can
// run that body when a group or a substitution was opened on an earlier line
// (`( case x in a) ... ) | awk '{system($0)}'`), where the walk cannot tell a
// `case` pattern from a group close. A `||` is not a pipe.
const HEREDOC_RUN_AFTER_RE = /(?<!\|)\|&?(?!\|)|>\(|<\(/;

// A redirect operator and its target (`> f`, `2>> f`, `<< EOF`) and the glued
// forms (`>f`, `2>f`, `<<EOF`). Read by runsCodeAfter so a target is not read as
// the command.
const REDIRECT_OP_RE = /^[0-9]*(?:>>?\|?|<<?-?|<>|<&|>&|&>>?|<|>)$/;
const REDIRECT_GLUED_RE = /^[0-9]*(?:>>?|<<?-?|<>|<&|>&|&>>?|<|>)[^<>&\s]+$/;

// Wrappers that turn their input into arguments or commands: their body is code,
// not data, so they are not read through like `sudo` or `env`.
const HEREDOC_RUNS_STDIN = new Set(['xargs', 'parallel']);

/** The program a here-document feeds, read through assignments, reserved words and wrappers (`sudo cat`). */
function heredocConsumer(segment) {
  const words = segment.split(/\s+/).filter(Boolean).map((text) => ({ text }));
  let k = 0;
  while (k < words.length && (ASSIGNMENT_RE.test(words[k].text) || RESERVED_WORDS.has(words[k].text))) {
    const name = programName(words[k].text);
    if (HEREDOC_RUNS_STDIN.has(name)) return name; // xargs turns its input into a command
    k++;
  }
  for (let guard = 0; k < words.length && guard < 16; guard++) {
    const name = programName(words[k].text);
    if (HEREDOC_RUNS_STDIN.has(name)) return name;
    if (!Object.prototype.hasOwnProperty.call(GIT_WRAPPERS, name)) return name;
    k = skipWrapper(words, k, name);
  }
  return k < words.length ? programName(words[k].text) : '';
}

/**
 * The files a command line writes: the target of a `>` or `>>` redirect, the
 * positional arguments of `tee`, and the `of=` of `dd`. Used to keep the body
 * when the same command later runs the file it writes, also by an absolute path.
 */
function writtenFiles(text) {
  const files = new Set();
  const words = text.split(/\s+/).filter(Boolean);
  const unquote = (w) => w.replace(/^["']+|["']+$/g, '');
  for (let k = 0; k < words.length; k++) {
    const w = words[k];
    if (w === '>' || w === '>>' || w === '>|') { if (words[k + 1]) { files.add(unquote(words[k + 1])); k++; } continue; }
    if (/^>>?[^>]/.test(w)) { files.add(unquote(w.replace(/^>>?/, ''))); continue; }
    if (/^of=/.test(w)) files.add(unquote(w.slice(3)));
  }
  const tee = words.indexOf('tee');
  if (tee !== -1) {
    for (let k = tee + 1; k < words.length && !/[;&|]/.test(words[k]); k++) {
      if (!words[k].startsWith('-') && !/^[<>]/.test(words[k])) files.add(unquote(words[k]));
    }
  }
  return files;
}

/**
 * Whether the command runs code: a shell, an interpreter, `source`, a program
 * that turns its input into a command, a path run directly (`./x.sh`), or a
 * command that names a file the same command writes. Used to keep the body of a
 * here-document a command then runs.
 */
function runsCodeAfter(text, targets) {
  // Any word that is a shell, an interpreter or a stdin-to-command wrapper keeps
  // the check, wherever it sits (the safe side).
  for (const token of text.split(/[\s;&|(){}<>`"']+/)) {
    if (!token) continue;
    const name = programName(token);
    if (CODE_CMDS_RE.test(name) || name === 'source' || name === 'eval' || name === '.' || HEREDOC_RUNS_STDIN.has(name)) return true;
    if (token.startsWith('./') || token.startsWith('../')) return true;
  }
  if (!targets || !targets.size) return false;
  // A file the command writes and then runs is named in command position, also
  // behind a wrapper (`nohup x.sh`, `timeout 5 x.sh`, `exec x.sh`, `sudo x.sh`).
  // A redirect and its target are skipped (`cat <<EOF > f`), so the target is not
  // read as the command.
  for (const segment of text.split(/[\n;|&(){}`"']+/)) {
    const words = segment.split(/\s+/).filter(Boolean).map((text) => ({ text }));
    let k = 0;
    for (let guard = 0; k < words.length && guard < 32; guard++) {
      const w = words[k].text;
      if (ASSIGNMENT_RE.test(w)) { k++; continue; }
      if (REDIRECT_OP_RE.test(w)) { k += 2; continue; }
      if (REDIRECT_GLUED_RE.test(w)) { k++; continue; }
      const name = programName(w);
      if (!Object.prototype.hasOwnProperty.call(GIT_WRAPPERS, name)) break;
      k = skipWrapper(words, k, name);
    }
    if (k < words.length && targets.has(words[k].text.replace(/^["']+|["']+$/g, ''))) return true;
  }
  return false;
}

/*
 * zn keeps the API key of `zn-gate connect` and the vault identity in the
 * system keychain, under zn's own service name. A command that asks the
 * keychain for that entry is refused; the same tools stay free for any other
 * entry. The tools: macOS `security find-generic-password` /
 * `find-internet-password`, Linux `secret-tool lookup` / `search`, Windows
 * `cmdkey /list:` and PowerShell `Get-StoredCredential` / CredRead.
 */
const KEYCHAIN_MESSAGE = 'zn: this command would read a zn secret (the API key or the vault key) from the system keychain, which is protected. Ask the user to do it.';
// A command is refused when it holds BOTH a word that reads a keychain AND one of zn's own entry names (or loads
// zn's key code). No wrapper, quoting, interpreter or heredoc has to be understood: the words are enough, and
// searching for the names with rg, grep or git grep (no keychain word) stays allowed.
const KEYCHAIN_WORD_RE = /(?:(?<![A-Za-z0-9_.-])(?:security(?:\.exe)?(?=\s)|secret-tool|cmdkey|vaultcmd|Get-StoredCredential|CredRead|CredEnumerate|keyring|keytar|PasswordVault)(?![A-Za-z0-9_-])|(?<![A-Za-z0-9_-])(?:getPassword|get_password)(?![A-Za-z0-9_-])|find-(?:generic|internet)-password)/i;
// The patterns below are matched one at a time, with no gap between parts: `security\s[^\n]*dump-keychain` takes time
// proportional to length times the number of candidates, and a bounded gap could be padded past its limit.
const KEYCHAIN_DUMP_RE = /\bdump-keychain\b/i;
const KEYCHAIN_SECURITY_RE = /(?<![A-Za-z0-9_.-])security(?:\.exe)?\s/i;
// zn's own modules, loaded to read the key.
const KEYCHAIN_LIB_LOAD_RE = /(?:require\s*\(|import\s*\(|\bimport\s|\bfrom\s)/;
// zn-gate's own client modules count only by their full path (node_modules, a global install or packages/zn-gate): a
// project's own lib/client is no business of ours. A relative ./lib/client inside zn-gate itself is not covered.
// Matching ignores case (macOS and Windows load ZN-GATE/LIB/CLIENT) and drops `/./` segments first.
const KEYCHAIN_LIB_NAME_RE = /(?:cloud-key(?![A-Za-z0-9_-])|vault[\\/]+keychain|zn-gate[\\/]+lib[\\/]+(?:vault[\\/]+)?client(?![A-Za-z0-9_-]))/i;
const KEYCHAIN_DOT_RE = /[\\/]\.(?=[\\/])/g;
// A name written with escapes (\x2f, \x2F, \u{2f}, \057) is the same name once the shell or the interpreter decodes
// it, so the name is also looked for in decoded copies. The decoded copies only add matches. One pass, no backtracking.
const KEYCHAIN_ESC_RE = /\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{0*([0-9A-Fa-f]{1,6})\}|([0-7]{1,3}))/g;
// bash $'...', printf and echo -e also take \x with 1-2 digits, \u with 1-4, \U with 1-8 and \0nnn.
const KEYCHAIN_SH_ESC_RE = /\\(?:x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|0?([0-7]{1,3}))/g;
function keychainUnescape(t, re = KEYCHAIN_ESC_RE) {
  return t.replace(re, (m, x, u, b, o) => {
    const cp = o !== undefined ? parseInt(o, 8) : parseInt(x || u || b, 16);
    return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
  });
}
// The shell drops quotes and line continuations before the interpreter decodes, so an escape split by them counts too.
const KEYCHAIN_SHELL_JOIN_RE = /\\\r?\n|['"]/g;
// A name that merely ends in zn-gate/lib/client (acme-zn-gate/lib/client) is refused on purpose: no left boundary, so a
// trick that leaves a letter before the name cannot get past the rule.
const keychainLibName = (t) => {
  const j = t.replace(KEYCHAIN_SHELL_JOIN_RE, '');
  return [t, keychainUnescape(j), keychainUnescape(j, KEYCHAIN_SH_ESC_RE)].some((c) => KEYCHAIN_LIB_NAME_RE.test(c.replace(KEYCHAIN_DOT_RE, '')));
};
const KEYCHAIN_LIB_USE_RE = /(?:loadStoredKey|resolveApiKey|\b_native\b|CLOUD_SLOT|loadIdentity|storeIdentity|\banalyze\b|\bisCloudEnabled\b)/;

/*
 * A single simple command that only writes or searches text: `git commit|grep|log|show`, `echo`, `printf`. Such a
 * command never reads the keychain, so a commit message or a search pattern may name zn's entries. Anything with a
 * second command, a pipe, a substitution or a newline is not exempt (the words are then checked as usual), and
 * neither is a git command that can run another program (-c, aliases, --open-files-in-pager, --exec).
 */
const TEXT_ONLY_GIT = new Set(['commit', 'grep', 'log', 'show']);
function textOnlyCommand(text) {
  if (/[;&|\n\r`]|\$\(|<\(|>\(/.test(text)) return false;
  const toks = text.trim().split(/\s+/).map((x) => x.replace(/^['"]+|['"]+$/g, ''));
  let i = 0;
  while (i < toks.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(toks[i]) || ['env', 'command', 'nohup', 'time'].includes(programBase(toks[i])))) i++;
  const prog = programBase(toks[i]);
  if (prog === 'echo' || prog === 'printf') return true;
  if (prog !== 'git') return false;
  i++;
  while (i < toks.length && (toks[i] === '--no-pager' || (toks[i] === '-C' && toks[i + 1] !== undefined))) i += toks[i] === '-C' ? 2 : 1;
  if (!TEXT_ONLY_GIT.has(toks[i])) return false;
  return !toks.slice(i + 1).some((x) => /^(?:-O|--open-files-in-pager|--exec|--ext-diff|--textconv|-c)(?:=|$)/.test(x) || /^-O./.test(x));
}

function programBase(word) {
  return String(word || '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
}

function keychainQuery(cmd, env) {
  const text = String(cmd || '');
  if (text.length > SHELL_SCAN_CAP) return false;
  if (textOnlyCommand(text)) return false;
  // zn's entries can be picked by service, account or label.
  const names = ['zn-vault', 'zn-cloud', 'cloud-api-key', 'age-identity', 'zn-gate-cloud-api-key', 'zn-vault-identity', 'zn vault identity', 'zn-gate cloud API key'];
  const custom = env && env.ZN_KEYCHAIN_SERVICE;
  if (typeof custom === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(custom) && !names.includes(custom)) names.push(custom);
  const named = (t) => names.some((n) => new RegExp('(?<![A-Za-z0-9._-])' + n.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&') + '(?![A-Za-z0-9._-])', 'i').test(t));
  // Quotes, backslashes and backticks inside a name do not change what the tool sees.
  for (const t of [text, text.replace(/['"`\\^]/g, '')]) {
    // Dumping the keychain would include zn's entries whatever name is given.
    if (KEYCHAIN_DUMP_RE.test(t) && KEYCHAIN_SECURITY_RE.test(t)) return true;
    if (KEYCHAIN_WORD_RE.test(t) && named(t)) return true;
    if (keychainLibName(t) && KEYCHAIN_LIB_LOAD_RE.test(t) && KEYCHAIN_LIB_USE_RE.test(t)) return true;
  }
  return false;
}

function bashDenial(cmd, opts = {}) {
  return shellPatchMessage(cmd, bashDenialOf(cmd, opts), opts);
}

function bashDenialOf(cmd, opts = {}) {
  if (String(cmd || '').length > SHELL_SCAN_CAP) return TOO_LONG_MESSAGE;
  const admin = adminCommand(cmd);
  if (admin) return adminDenial(admin, opts, cmd);
  if (keychainQuery(cmd, opts.env || process.env)) return KEYCHAIN_MESSAGE;
  // The context (home, project, agent directories) is built once per command.
  opts = { ...opts, ctx: contextOf(opts) };
  // The code of a shell inside the command (sh -c "...") is checked as a command of its own, with the same budget.
  const depth = opts.depth || 0;
  if (!depth || !opts.budget) opts.budget = { until: Date.now() + CHECK_BUDGET_MS, disk: CHECK_BUDGET_DISK };
  // The bodies of the here-documents read as data are data, not command-line words, and are dropped first.
  const text = stripHeredocs(cmd, opts.budget);
  // The command is read three times: a backslash before a letter is a Windows
  // path separator or a bash escape, and a PowerShell backtick is an escape too.
  // A word protected in any reading is refused.
  const readings = [allWords(text, false), allWords(text, true), allWords(text.replace(/`(.)/gs, '$1'), false)];
  // Bash $'...' quoting spells characters as escapes ($'\x2eenv' is .env), and $"..." is a plain "...":
  // a fourth reading with them decoded.
  if (/\$['"]/.test(text)) readings.push(allWords(decodeAnsiC(text), true));
  // A reading that could not be split to the end is refused, not checked in part.
  if (readings.some((r) => r.truncated)) return TOO_MANY_MESSAGE;
  const words = readings.flat();
  const codes = new Set();
  for (const r of readings) shellCodesOf(r, codes);
  if (codes.size) {
    if (depth >= SHELL_CODE_DEPTH) return TOO_NESTED_MESSAGE;
    for (const code of codes) {
      if (overBudget(opts.budget, 5)) return TOO_SLOW_MESSAGE;
      const deny = bashDenialOf(code, { ...opts, depth: depth + 1 });
      if (deny) return deny;
    }
  }
  // Inside $( ) or backticks the text is not split into simple commands, so
  // every word of it is checked on its own, as if it were a word of the command.
  // The same for the code an interpreter runs (python -c "open('.env')"), where a path sits inside quotes and brackets.
  if (/\$\(|`/.test(text) || words.some((w) => CODE_CMDS_RE.test(bareHead(w.head)))) {
    const split = [];
    for (const t of text.split(/[\s'"`$(){};|&<>=,]+/)) if (t) split.push({ text: t, redirectTarget: false, head: '', seq: 0 });
    words.push(...split);
    readings.push(split);
  }
  // Where a relative .env path may be read from once the command has changed directory (cd app && cat .env).
  // Each reading is followed on its own, so a cd counts once.
  opts.cdBases = cdBasesOf(readings, opts);
  opts.elsewhere = new Map();
  if (overBudget(opts.budget, 0)) return TOO_SLOW_MESSAGE;
  opts.cmdText = text;
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
  // A <rev>:<path> word is read as a git object in any command that runs git (echo HEAD:.env | xargs git show).
  const anyGit = words.some((x) => x.git || x.text === 'git' || x.text.endsWith('/git'));
  for (const w of words) {
    // --flag=value carries a path too (--kubeconfig=~/.kube/config).
    let text = w.text;
    if (text.startsWith('-')) {
      const eq = text.indexOf('=');
      // git log -L<range>:<file> names a file after the colon.
      const lineRange = w.git ? /^-L[^:]*:(.+)$/.exec(text) : null;
      if (lineRange) text = lineRange[1];
      else if (eq < 0) continue;
      else text = text.slice(eq + 1);
    } else if (NAME_VALUE_RE.test(text)) {
      // name=value carries a path too (dd if=.env, ENV_FILE=.env).
      text = text.slice(text.indexOf('=') + 1);
    }
    if (!text) continue;
    // A git pathspec with magic names the path after it.
    if (anyGit && text.charCodeAt(0) === 58) text = text.replace(PATHSPEC_MAGIC_RE, '') || text;
    const writing = !READ_ONLY_CMDS.has(w.head);
    if (!classified.has(text)) {
      if (globDeny && ++afterGlob > GLOB_NAME_LOOKAHEAD) return globDeny;
      if (overBudget(opts.budget, 1)) return TOO_SLOW_MESSAGE;
      classified.set(text, classifyWord(text, opts));
    }
    const c = classified.get(text);
    if ((!c || c.kind === 'dotenv' || c.kind === 'keyfile') && (w.git || anyGit)) {
      // git show HEAD:.env, git cat-file -p :app/.env: a secret file read from the repository, not from disk.
      const deny = gitObjectDenial(text, opts) ||
        // git log -p -- .env, git checkout HEAD -- .env: its history, also once the file is gone from disk.
        (c && w.git && gitReadsContent(w.sub, w.gitArgs) ? gitHistoryDenial(text) : null);
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
    if (!deny && (c.kind === 'dotenv' || c.kind === 'keyfile')) deny = dotenvElsewhereDenial(text, opts, c.kind);
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

// Programs that run the next command: git behind them is still git. For each, the short options that take a value
// (skipped with it); every other option is a flag. A wrapper not listed here, or a chain that does not resolve, falls
// back to the first word that is git (a refused command is the safe side).
const GIT_WRAPPERS = {
  sudo: 'ugphCDrtUTR', doas: 'uC', env: 'uCS', command: '', nohup: '', time: 'fo', builtin: '', exec: 'a', nice: 'n', timeout: 'sk',
  xargs: 'IinLPdEsa', setsid: '', ionice: 'cnpPu', stdbuf: 'ioe', busybox: '',
  chrt: '', taskset: 'c', chroot: 'ug', runuser: 'ugGsT', unbuffer: '', strace: 'eopsuEaOSbPIX', ltrace: 'eopsunal', nsenter: 'tSG', flock: 'wE',
};
// Wrappers that take positional arguments before the command: chrt <priority>, taskset <mask> (not with -c), chroot <newroot>, flock <lock>.
const WRAPPER_POSITIONAL = { chrt: 1, taskset: 1, chroot: 1, flock: 1 };
const WRAPPER_LONG_VALUE = new Set(['--user', '--group', '--chdir', '--unset', '--max-args', '--max-procs', '--replace', '--delimiter',
  '--arg-file', '--eof', '--signal', '--kill-after', '--split-string', '--cpu-list', '--host', '--prompt', '--close-from', '--role', '--type']);

function wordIsGit(text) {
  return isGit(String(text).replace(/^\(+/, '').split(/[\\/]/).pop().toLowerCase());
}

/* The index of the word after a wrapper and its options (and the values some take), env's assignments and timeout's duration. */
function skipWrapper(words, k, name) {
  const valueOpts = GIT_WRAPPERS[name];
  let sawC = false;
  k++;
  while (k < words.length) {
    const t = words[k].text;
    if (t === '--') { k++; break; }
    if (t.startsWith('--') && t.length > 2) { k += !t.includes('=') && WRAPPER_LONG_VALUE.has(t) ? 2 : 1; continue; }
    if (t.startsWith('-') && t.length > 1) {
      if (t === '-c') sawC = true;
      // -n, -E, -En: flags; a cluster ending in an option that takes a value (sudo -u root) takes the next word.
      k += /^-[A-Za-z]+$/.test(t) && valueOpts.includes(t[t.length - 1]) ? 2 : 1;
      continue;
    }
    if (ASSIGNMENT_RE.test(t) || (name === 'timeout' && /^[0-9.]+[smhd]?$/.test(t))) { k++; continue; }
    break;
  }
  if (WRAPPER_POSITIONAL[name] && k < words.length && !(name === 'taskset' && sawC)) k += WRAPPER_POSITIONAL[name];
  return k;
}

/* The index of the word that is git in a simple command, directly or behind wrappers; -1 when it is not git. */
function gitStart(words) {
  let k = words.findIndex((x) => !ASSIGNMENT_RE.test(x.text));
  if (k < 0) return -1;
  const first = k;
  for (let guard = 0; guard < 16; guard++) {
    if (wordIsGit(words[k].text)) return k;
    const name = String(words[k].text).replace(/^\(+/, '').split(/[\\/]/).pop().toLowerCase();
    if (!Object.prototype.hasOwnProperty.call(GIT_WRAPPERS, name)) break;
    k = skipWrapper(words, k, name);
    if (k >= words.length) break;
  }
  // The chain did not resolve to git: the first word that is git counts as the start, so nothing slips past.
  for (let j = first; j < words.length; j++) if (wordIsGit(words[j].text)) return j;
  return -1;
}

// A git pathspec starts with :(magic) or :/ ... before the path (':(top).env', ':/.env', ':(glob)**/.env').
const PATHSPEC_MAGIC_RE = /^:(?:\([^)]*\)|[\/!^])+(?=.)/;

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
const CODE_CMDS_RE = /^(?:python[0-9.]*|py|node|nodejs|deno|bun|ruby|perl|php|lua|osascript|pwsh|powershell|bash|sh|zsh|dash|ksh|fish|cmd|iex|invoke-expression)(?:\.exe)?$/;
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
function dotenvElsewhereDenial(text, opts, kind = 'dotenv') {
  const key = kind + '\0' + text;
  if (opts.elsewhere && opts.elsewhere.has(key)) return opts.elsewhere.get(key);
  const deny = dotenvElsewhereOf(text, opts, kind);
  if (opts.elsewhere) opts.elsewhere.set(key, deny);
  return deny;
}

function dotenvElsewhereOf(text, opts, kind = 'dotenv') {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const expanded = expandEnv(expandHome(text, home), env).text;
  const missing = !fs.existsSync(resolvedOf(text, opts));
  // $DIR/.env with a variable zn does not know, or a path whose start is the output of another command
  // (`cat $(echo app)/.env` leaves the word /.env right after the closing bracket).
  const cmdText = opts.cmdText || '';
  const afterSubstitution = /[()]/.test(text) || cmdText.includes(')' + text) || cmdText.includes('`' + text);
  // A path that starts at a Windows root or a network share (\\server\share\.env, \\?\C:\path\.env,
  // \folder\.env, //server/share/.env): zn cannot follow it, so a .env reached through it is refused.
  if (kind === 'dotenv' && (String(text).startsWith('\\') || String(text).startsWith('//'))) {
    return 'zn: this command reads ' + text + ' through a path zn cannot check (a Windows root or a network share), so it was blocked. ' +
      'Give the path from the current folder instead, for example `cat app/.env`.';
  }
  // A key file is judged by its content where the cd leads; only a .env is refused for a path built while the command runs.
  if (kind === 'dotenv' && (/[$`]|%[A-Za-z_][A-Za-z0-9_]*%/.test(expanded) || (missing && afterSubstitution))) {
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
    const where2 = { ...opts, cwd: dir, env: pwdRef ? { ...env, PWD: dir } : env };
    const deny = kind === 'keyfile' ? keyFileDenial(text, { kind }, where2) : readDenial(text, where2);
    if (deny) {
      // The folder as the user would type it: relative below the current folder, absolute above it.
      const rel = path.relative(cwd, dir);
      const where = slash(rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : dir);
      return 'zn: this command changes to ' + where + ' first. ' + deny.replace(/^zn: /, '');
    }
  }
  if (bases.unknown) {
    return 'zn: this command changes to a folder zn cannot follow and then reads ' + text + ', so zn cannot check whether it holds secrets. ' +
      'Give the path from the current folder instead, for example `' + (kind === 'keyfile' ? 'cat certs/server.pem' : 'cat app/.env') + '`.';
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
  if (/^(dis)?connect$/i.test(admin)) {
    return 'zn blocked this: `' + znCommand(admin, opts) + '` turns the optional cloud check on or off and handles your zn API key, which is the user\'s decision. ' + run(admin);
  }
  if (/^stats/i.test(admin)) {
    return 'zn blocked this: only the user can turn on sharing of zn\'s usage statistics. ' + run('stats share on');
  }
  return 'zn blocked this: `' + znCommand(admin, opts) + '` reads or changes secret values, and secret values never go to the AI model. ' + run(full);
}

/** The deny message for a read or write classified by classifyWord. */
function denialOf(c, text, opts) {
  if (c.kind === 'zn_state') return vaultMessage(opts);
  if (c.kind === 'keyfile') return keyFileDenial(text, c, opts);
  if (c.kind === 'dotenv') return readDenial(text, opts);
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
