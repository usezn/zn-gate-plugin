'use strict';
/**
 * Command and text patterns for `zn audit`. Every regular expression is
 * linear: no nested quantifiers, gaps are bounded, and inputs are cut to
 * MAX_LINE characters before matching.
 */

const path = require('path');
const { trimTrailing } = require('../linear-text');

const MAX_LINE = 4000;

/* ------------------------- download and run ------------------------- */

const FETCH = '(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|fetch)';
const RUNNER = '(?:sudo\\s+)?(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|deno|bun|perl|ruby|php|iex|invoke-expression|pwsh|powershell(?:\\.exe)?|cmd(?:\\.exe)?)';
const DOWNLOAD_RUN = [
  new RegExp('\\b' + FETCH + '\\b[^|\\n]{0,400}\\|\\s{0,5}' + RUNNER + '\\b', 'i'),
  /\b(?:ba|z)?sh\s{1,5}<\(\s{0,5}(?:curl|wget)\b/i,
  /\b(?:ba|z)?sh\s{1,5}-c\s{1,5}["']?\$\(\s{0,5}(?:curl|wget)\b/i,
  /\b(?:iex|invoke-expression)\s{0,5}\(\s{0,5}(?:\(?\s{0,5}new-object\s{1,5}(?:system\.)?net\.webclient|iwr|irm|invoke-webrequest|invoke-restmethod)/i,
];

// Installers that documentation commonly pipes into a shell.
const KNOWN_INSTALLERS = [
  'sh.rustup.rs', 'static.rust-lang.org', 'astral.sh', 'bun.sh', 'deno.land', 'get.docker.com',
  'raw.githubusercontent.com/nvm-sh/', 'raw.githubusercontent.com/homebrew/', 'install.python-poetry.org',
  'get.pnpm.io', 'sdk.cloud.google.com', 'cli.github.com', 'foundry.paradigm.xyz', 'get.helm.sh',
  'claude.ai/install.sh', 'opencode.ai/install', 'get.volta.sh', 'fnm.vercel.app', 'mise.run', 'pyenv.run',
];

function downloadAndRun(text, opts) {
  const t = String(text || '').slice(0, MAX_LINE);
  for (const re of DOWNLOAD_RUN) {
    const m = re.exec(t);
    if (m && opts && opts.prose && negated(t, m.index)) continue;
    if (m) return { match: m[0], knownInstaller: KNOWN_INSTALLERS.some((h) => t.toLowerCase().includes(h)) };
  }
  return null;
}

/* ------------------------------ argv ------------------------------- */

/** Split a shell command line into words (quotes respected, no expansion). */
function splitCommand(cmd) {
  const s = String(cmd || '').slice(0, MAX_LINE);
  const out = [];
  let cur = '';
  let quote = null;
  let has = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; has = true; continue; }
    if (/\s/.test(c)) {
      if (has || cur) out.push(cur);
      cur = '';
      has = false;
      continue;
    }
    cur += c;
    has = true;
  }
  if (has || cur) out.push(cur);
  return out;
}

function toolName(word) {
  return path.basename(String(word || '').replace(/\\/g, '/')).toLowerCase().replace(/\.(cmd|exe|bat|ps1)$/, '');
}

const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** npm spec "name", "name@1.2.3", "@scope/name@^1" -> {name, version} or null for paths and URLs. */
function npmSpec(spec) {
  const s = String(spec || '');
  if (!s || s.startsWith('.') || s.startsWith('/') || s.startsWith('~') || /^[A-Za-z]:[\\/]/.test(s)) return null;
  if (/^(?:file:|https?:|git[+:]|github:)/i.test(s)) return null;
  if (!s.startsWith('@') && s.includes('/')) return null; // a path, or a GitHub shorthand: not a registry package
  const at = s.indexOf('@', s.startsWith('@') ? 1 : 0);
  if (at < 0) return { name: s, version: '' };
  return { name: s.slice(0, at), version: s.slice(at + 1) };
}

function pinnedNpm(version) {
  return EXACT_VERSION.test(version);
}

const NPX_VALUE_FLAGS = new Set(['-p', '--package', '-c', '--call', '--cache', '--registry', '--prefix', '--userconfig']);
const UVX_VALUE_FLAGS = new Set(['--from', '--with', '-w', '--python', '-p', '--index', '--index-url', '--extra-index-url', '--with-requirements', '--directory', '--env-file']);
const DOCKER_VALUE_FLAGS = new Set(['-e', '--env', '-v', '--volume', '--name', '-p', '--publish', '--network', '--net', '--mount', '-w', '--workdir', '--entrypoint', '-u', '--user', '--env-file', '-l', '--label', '--platform', '--add-host', '--cap-add', '--cap-drop', '--device', '--memory', '-m', '--cpus', '--pull', '--restart', '--hostname', '-h', '--ipc', '--pid', '--security-opt', '--tmpfs', '--ulimit', '--gpus', '--runtime', '--log-driver', '--log-opt', '--dns', '--shm-size', '--stop-signal', '--init-path', '--expose']);

/**
 * Packages the argv fetches and runs, with whether each one is pinned:
 * [{manager, spec, pinned}]. Looks through wrappers such as
 * `zn-gate shield -- <inner>` and `cmd /c <inner>`.
 */
function packagesOf(argv) {
  const out = [];
  const words = (argv || []).map(String);
  for (let i = 0; i < words.length; i++) {
    const tool = toolName(words[i]);
    let rest = words.slice(i + 1);
    if (tool === 'npm' || tool === 'pnpm' || tool === 'yarn') {
      if (!['exec', 'x', 'dlx'].includes(rest[0])) continue;
      rest = rest.slice(1);
    }
    if (['npx', 'bunx', 'npm', 'pnpm', 'yarn'].includes(tool)) {
      let explicit = null;
      let first = null;
      for (let j = 0; j < rest.length; j++) {
        const w = rest[j];
        if (w === '--') break;
        if (w.startsWith('--package=')) { explicit = w.slice(10); continue; }
        if (w === '-p' || w === '--package') { explicit = rest[j + 1]; j++; continue; }
        if (NPX_VALUE_FLAGS.has(w)) { j++; continue; }
        if (w.startsWith('-')) continue;
        first = w;
        break;
      }
      const spec = npmSpec(explicit || first);
      if (spec) out.push({ manager: tool, spec: explicit || first, pinned: pinnedNpm(spec.version) });
      continue;
    }
    if (tool === 'uvx' || (tool === 'uv' && rest[0] === 'tool' && rest[1] === 'run') || (tool === 'pipx' && rest[0] === 'run')) {
      if (tool === 'uv') rest = rest.slice(2);
      if (tool === 'pipx') rest = rest.slice(1);
      let from = null;
      let first = null;
      for (let j = 0; j < rest.length; j++) {
        const w = rest[j];
        if (w.startsWith('--from=')) { from = w.slice(7); continue; }
        if (w === '--from' || w === '--spec') { from = rest[j + 1]; j++; continue; }
        if (UVX_VALUE_FLAGS.has(w)) { j++; continue; }
        if (w.startsWith('-')) continue;
        first = w;
        break;
      }
      const spec = from || first;
      if (spec && !/^[.~/]|^[A-Za-z]:[\\/]|^(?:git\+|https?:|file:)/.test(spec)) {
        out.push({ manager: tool === 'uv' ? 'uv' : tool, spec, pinned: /==\s*\d|@\s*\d+\.\d+/.test(spec) });
      }
      continue;
    }
    if ((tool === 'docker' || tool === 'podman') && rest[0] === 'run') {
      for (let j = 1; j < rest.length; j++) {
        const w = rest[j];
        if (w.includes('=') && w.startsWith('--')) continue;
        if (DOCKER_VALUE_FLAGS.has(w)) { j++; continue; }
        if (w.startsWith('-')) continue;
        const digest = w.includes('@sha256:');
        const tag = w.slice(w.lastIndexOf('/') + 1).split(':')[1];
        out.push({ manager: tool, spec: w, pinned: digest || Boolean(tag && tag !== 'latest') });
        break;
      }
    }
  }
  return out;
}

/* ---------------------------- endpoints ---------------------------- */

const ENDPOINT_KEY = /(?:^|_)(?:BASE_URL|API_BASE|API_BASE_URL|ENDPOINT|ENDPOINT_URL|API_URL|API_HOST)$/i;
const PROXY_KEY = /^(?:https?_proxy|all_proxy)$/i;
const CODE_ENV = new Set([
  'NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH',
  'PYTHONSTARTUP', 'PYTHONHOME', 'BASH_ENV', 'ENV', 'ZDOTDIR', 'PROMPT_COMMAND', 'PATH',
  'GIT_SSH_COMMAND', 'GIT_SSH', 'GIT_EXEC_PATH', 'GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_PROXY_COMMAND', 'GIT_EXTERNAL_DIFF',
  'PERL5OPT', 'PERL5LIB', 'RUBYOPT', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'DOTNET_STARTUP_HOOKS',
  'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
  'NODE_TLS_REJECT_UNAUTHORIZED', 'PYTHONHTTPSVERIFY', 'GIT_SSL_NO_VERIFY',
]);
// Variables that move where an agent reads its own configuration.
const CONFIG_DIR_ENV = new Set(['CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'XDG_CONFIG_HOME', 'OPENCODE_CONFIG', 'OPENCODE_CONFIG_DIR', 'GEMINI_CLI_HOME']);

function isPlaceholder(v) {
  const s = String(v == null ? '' : v).trim();
  return !s || /^\$\{?[A-Za-z_][A-Za-z0-9_]*(?::?-[^}]*)?\}?$/.test(s) || /^\$\{\{[^}]*\}\}$/.test(s) || /^\{env:[A-Za-z_][A-Za-z0-9_]*\}$/.test(s);
}

function hostOf(url) {
  try {
    const u = new URL(String(url));
    return u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  } catch (_) {
    return null;
  }
}

function isLoopback(host) {
  return host === 'localhost' || host === '::1' || host === '0.0.0.0' || /^127\./.test(host || '') || /\.localhost$/.test(host || '');
}

/** URL without user, password, query or fragment, for printing. */
function safeUrl(url) {
  try {
    const u = new URL(String(url));
    return u.protocol + '//' + u.host + (u.pathname === '/' ? '' : u.pathname);
  } catch (_) {
    return String(url).replace(/\/\/[^/@\s]*@/, '//').replace(/[?#].*$/, '');
  }
}

/** Classify an agent-level environment variable. */
function classifyEnv(key, value) {
  if (isPlaceholder(value)) return null;
  const k = String(key);
  const v = String(value);
  if (PROXY_KEY.test(k)) {
    const host = hostOf(/^[a-z]+:\/\//i.test(v) ? v : 'http://' + v);
    return { kind: 'proxy', host, loopback: isLoopback(host) };
  }
  if (ENDPOINT_KEY.test(k)) {
    const host = hostOf(v);
    if (!host) return null;
    return { kind: 'endpoint', host, loopback: isLoopback(host) };
  }
  const up = k.toUpperCase();
  if (CONFIG_DIR_ENV.has(up)) return { kind: 'confdir' };
  if (CODE_ENV.has(up)) {
    if (up === 'NODE_OPTIONS' && !/(?:^|\s)(?:-r|--require|--import|--loader|--experimental[-_]loader|--experimental[-_]policy)\b/.test(v)) return null;
    if ((up === 'NODE_TLS_REJECT_UNAUTHORIZED' || up === 'PYTHONHTTPSVERIFY') && v.trim() !== '0') return null;
    if (up === 'GIT_SSL_NO_VERIFY' && !/^(?:1|true|yes)$/i.test(v.trim())) return null;
    return { kind: 'code' };
  }
  return null;
}

/* --------------------------- permissions --------------------------- */

const INTERPRETERS = new Set([
  'sh', 'bash', 'zsh', 'dash', 'fish', 'pwsh', 'powershell', 'cmd', 'python', 'python3', 'py', 'node', 'deno', 'bun',
  'perl', 'ruby', 'php', 'eval', 'exec', 'curl', 'wget', 'npx', 'uvx', 'bunx', 'docker', 'podman', 'sudo', 'env', 'xargs',
  'source', 'osascript', 'iex', 'invoke-expression',
]);

/** Severity of one Claude Code permission rule, or null when it is narrow. */
function claudePermission(entry) {
  const e = String(entry || '').trim();
  if (e === '*' || /^(?:Bash|PowerShell|Shell)$/.test(e)) return 'high';
  const m = /^(Bash|PowerShell|Shell)\((.*)\)$/s.exec(e);
  if (!m) return null;
  const inner = m[2].trim();
  if (inner === '' || /^[*:\s]+$/.test(inner)) return 'high';
  const first = trimTrailing(inner.split(/[\s:]/)[0], '*');
  if (INTERPRETERS.has(first.toLowerCase()) && /[*]/.test(inner)) return 'high';
  return null;
}

/* ------------------------ instruction text ------------------------- */

const EXFIL = [
  // send / upload ... secret material ... to a destination
  /\b(?:send|upload|post|exfiltrate|forward|transmit|leak|e-?mail|copy|share|paste)\b[^\n]{0,120}?(?:\.env\b|~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.netrc|\.git-credentials|api[ _-]?keys?|access[ _-]?tokens?|secrets?|credentials?|passwords?|private[ _-]?keys?|environment variables)\b[^\n]{0,120}?(?:https?:\/\/|webhook|pastebin|discord(?:app)?\.com|gist\.github|ngrok|requestbin|attacker)/i,
  // curl/wget posting a sensitive file
  /\b(?:curl|wget|http|iwr|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}?(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file|-InFile|-Body)[\s=]{1,3}["']?@?[^\s"']{0,40}?(?:\.env\b|\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.netrc|\.git-credentials)/i,
  // dumping the environment or a key file into a network tool
  /\b(?:env|printenv|set|cat\s{1,5}[^\n|]{0,80}?(?:\.env\b|\.ssh\/|id_rsa|\.aws\/credentials|\.npmrc|\.netrc))\s{0,5}\|\s{0,5}(?:curl|wget|nc|ncat|netcat|socat|http)\b/i,
];

const WEAKEN = [
  /--no-verify\b/i,
  /--dangerously-skip-permissions\b/i,
  /--dangerously-bypass-approvals-and-sandbox\b/i,
  /--trust-all-tools\b/i,
  /--yolo\b/i,
  /\bbypassPermissions\b/,
  /\b(?:disable|turn off|bypass|skip|ignore|deactivate)\b[^\n.]{0,40}?\b(?:the\s+)?(?:sandbox|permission (?:prompts?|checks?)|approval prompts?|security (?:checks?|scans?|hooks?|tools?)|pre-commit hooks?|git hooks|antivirus|firewall|code review|secret scan(?:ning|ner)?|zn(?:-gate)?)\b/i,
  // Concealment only: "never ask the user" is a workflow choice, not hiding.
  /\b(?:do not|don't|never)\s{1,3}(?:tell|inform|mention|notify|alert|reveal)\b[^\n.]{0,30}?\bthe user\b/i,
  /\bwithout\s{1,3}(?:telling|informing|notifying|alerting)\b[^\n.]{0,20}?\bthe user\b/i,
  /\b(?:hide|conceal)\b[^\n.]{0,30}?\bfrom the user\b/i,
];

// "Never use --no-verify", "do not pipe curl into sh": a prohibition shortly
// before the match turns it into a safe instruction.
// The negation must govern the matched instruction: same clause (no sentence
// or clause boundary in between) and at most three words before it. "If the
// build does not work, run curl ... | sh" is not negated.
const CLAUSE_BOUNDARY = /[.;:!?,()]|\b(?:if|when|unless|otherwise|then|but|and|so|because)\b/gi;
const NEGATION_NEAR = /\b(?:never|not|don't|dont|avoid|without|no)\b(?:\W+\w+){0,3}\W*$/i;

function negated(text, index) {
  let seg = text.slice(Math.max(0, index - 80), index);
  CLAUSE_BOUNDARY.lastIndex = 0;
  let last = -1;
  let m;
  while ((m = CLAUSE_BOUNDARY.exec(seg)) !== null) last = m.index + m[0].length;
  if (last >= 0) seg = seg.slice(last);
  return NEGATION_NEAR.test(seg);
}

function exfiltration(text) {
  const t = String(text || '').slice(0, MAX_LINE);
  for (const re of EXFIL) {
    const m = re.exec(t);
    if (m && !negated(t, m.index)) return m[0];
  }
  return null;
}

function weakening(text) {
  const t = String(text || '').slice(0, MAX_LINE);
  for (let i = 0; i < WEAKEN.length; i++) {
    const m = WEAKEN[i].exec(t);
    // The last three patterns carry their own negation ("do not tell the user").
    if (m && (i >= WEAKEN.length - 3 || !negated(t, m.index))) return m[0];
  }
  return null;
}

/* ------------------------- shadowed tools -------------------------- */

const SHADOWED_TOOLS = new Set([
  'zn', 'zn-gate', 'zn-mcp', 'git', 'node', 'npm', 'npx', 'pnpm', 'yarn', 'bun', 'deno', 'python', 'python3', 'py', 'pip', 'pip3', 'uv', 'uvx',
  'ruby', 'perl', 'php', 'java', 'go', 'cargo', 'rustc', 'dotnet', 'make', 'cmake', 'gcc', 'cc', 'clang',
  'bash', 'sh', 'zsh', 'pwsh', 'powershell', 'cmd', 'conhost', 'where', 'whoami', 'curl', 'wget', 'ssh', 'scp', 'gpg', 'tar',
  'docker', 'kubectl', 'gh', 'code', 'cursor', 'rg', 'grep', 'find', 'ls', 'cat', 'tsc', 'eslint', 'prettier', 'claude', 'codex', 'opencode',
]);
const WINDOWS_EXEC_EXT = new Set(['.exe', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.msi']);

module.exports = {
  MAX_LINE,
  downloadAndRun,
  splitCommand,
  toolName,
  packagesOf,
  npmSpec,
  pinnedNpm,
  classifyEnv,
  isPlaceholder,
  hostOf,
  isLoopback,
  safeUrl,
  claudePermission,
  exfiltration,
  weakening,
  SHADOWED_TOOLS,
  WINDOWS_EXEC_EXT,
  INTERPRETERS,
};
