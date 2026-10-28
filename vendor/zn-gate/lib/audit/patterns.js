'use strict';
/**
 * Command and text patterns for `zn audit`. Every regular expression is
 * linear: no nested quantifiers, gaps are bounded, and inputs are cut to
 * MAX_LINE characters before matching.
 */

const path = require('path');

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

// Text that talks about the pattern instead of asking for it: a checklist of
// risky patterns, a rule that says what to flag, "`curl | sh` is unsafe".
// Same clause, up to 120 characters before the match, or a short verdict right
// after it. The warning word has to be about the pattern itself: words that
// also describe a tool or a goal in an install instruction ("detect", "scan
// for", "look for", "block", "risks", "vulnerabilities") are not used, and an
// imperative verb (run, install, use, pipe) between the warning word and the
// match, or at the start of the clause for the short verdict, makes it an
// instruction again ("Install the scanner: curl ... | sh").
const DISCUSS_BEFORE_SRC = '\\b(?:patterns?|anti-?patterns?|red flags?|flag(?:s|ged|ging)?|warn(?:s|ing)? about|forbidden|prohibited|banned|disallow(?:s|ed)?|reject(?:s|ed)?|refus(?:e|es|ed)|unsafe|insecure|dangerous|risky|harmful|malicious|suspicious)\\b';
const DISCUSS_AFTER = /^[`'"\s)\]]{0,5}(?:\b(?:is|are|was|were)\s+(?:a\s+|an\s+|considered\s+|very\s+)?(?:dangerous|unsafe|risky|insecure|bad|harmful|forbidden|blocked|not\s+allowed|an?\s+(?:anti-?pattern|risk)|a\s+red\s+flag)\b|\b(?:without\s+(?:a\s+)?(?:hash|checksum|verification|signature))\b)/i;
/** The clause (or list item) starts with a verb that gives an order. */
const IMPERATIVE_START = /^[\s>*_`\-+\d.)]*(?:(?:then|and|now|first|next|also|please|finally)[\s,]+)*(?:run|execute|install|pipe|use|type|paste|call|invoke|download|fetch|get|grab|set\s+up|bootstrap|add)\b/i;
const IMPERATIVE_WORD = /\b(?:run|runs|execute|install|pipe|use|type|paste|call|invoke|download|fetch|get|grab|set\s+up|bootstrap|add)\b/i;
/** A contrast or consequence word after the warning: "... is unsafe, so get it with curl ..." turns the warning into a reassurance. */
const CONTRAST_WORD = /\b(?:but|so|however|though|although|yet|still|instead|anyway|then|whereas)\b/i;
/** Warning words that describe a thing ("the old one was unsafe"); a colon after them introduces the command. */
const ADJECTIVE_WARNING = /^(?:unsafe|insecure|dangerous|risky|harmful|malicious|suspicious)$/i;

/** A separator after the warning word that introduces the command, like a colon does. */
const INTRODUCER = /(?::|—|–|\s-+\s|-+>|=>|\))/;

function discussed(text, index, length) {
  let seg = text.slice(Math.max(0, index - 120), index);
  const cut = Math.max(seg.lastIndexOf('. '), seg.lastIndexOf('; '), seg.lastIndexOf('! '), seg.lastIndexOf('? '));
  if (cut >= 0) seg = seg.slice(cut + 2);
  const re = new RegExp(DISCUSS_BEFORE_SRC, 'gi');
  let last = null;
  for (let m = re.exec(seg); m; m = re.exec(seg)) last = m;
  if (last) {
    const rest = seg.slice(last.index + last[0].length);
    const introduces = INTRODUCER.test(rest) && ADJECTIVE_WARNING.test(last[0]);
    if (!IMPERATIVE_WORD.test(rest) && !CONTRAST_WORD.test(rest) && !introduces) return true;
  }
  if (IMPERATIVE_START.test(seg)) return false;
  return DISCUSS_AFTER.test(text.slice(index + length, index + length + 80));
}

/** A heading that introduces a list of risky patterns ("Dangerous patterns", "What to flag"). */
const WARNING_HEADING = /^\s{0,3}#{1,6}\s.*\b(?:(?:dangerous|risky|unsafe|insecure|suspicious|bad)\s+(?:patterns?|commands?|practices?|snippets?|installers?)|anti-?patterns?|red flags?|risks? to (?:flag|detect|watch)|what to (?:flag|detect|look for))\b/i;
/** A verdict label at the start of a list item or line: "BAD: curl | sh ...". Severity labels are not verdicts. */
const WARNING_LABEL = /^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:\*\*|__)?(?:danger|bad|avoid|never|don'?t|do not|unsafe|risky|insecure|wrong|incorrect|forbidden)\b\s*(?:\*\*|__)?\s*(?::|-|—|–|\))/i;
/** A table cell that says the command was refused or is unsafe. */
const WARNING_CELL = /\b(?:blocked?|refus\w*|reject\w*|denied|flagged|unsafe|dangerous|risks?|risky)\b/i;
const DOWNLOAD_WORD = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i;

/** The cell has a warning word that is not negated ("no risk", "not blocked", "low risk"). */
function warningCell(cell) {
  const re = new RegExp(WARNING_CELL.source, 'gi');
  for (let m = re.exec(cell); m; m = re.exec(cell)) {
    const before = cell.slice(Math.max(0, m.index - 20), m.index);
    const negated = /\b(?:no|not|zero|low|without|never|non)[\s-]+(?:\w+\s+)?$/i.test(before) || /n['’]t\s+(?:\w+\s+)?$/i.test(before);
    const free = /^[\s-]*free\b/i.test(cell.slice(m.index + m[0].length));
    if (!negated && !free) return true;
  }
  return false;
}

function warningText(line) {
  const t = String(line || '').slice(0, MAX_LINE);
  const label = WARNING_LABEL.exec(t);
  if (label) return !IMPERATIVE_WORD.test(t.slice(label[0].length));
  if (/^\s*\|/.test(t)) return t.split('|').some((cell) => warningCell(cell) && !DOWNLOAD_WORD.test(cell));
  return false;
}
function warningHeading(line) {
  return WARNING_HEADING.test(String(line || '').slice(0, 300));
}
function imperativeStart(line) {
  return IMPERATIVE_START.test(String(line || '').slice(0, 300));
}

function downloadAndRun(text, opts) {
  const t = String(text || '').slice(0, MAX_LINE);
  for (const re of DOWNLOAD_RUN) {
    const m = re.exec(t);
    if (m && opts && opts.prose && (negated(t, m.index) || discussed(t, m.index, m[0].length))) continue;
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

// A flag whose value is a credential (--password, --token, --api-key, --client-secret, --pat ...), by the
// same names the redaction in index.js hides. A flag that only switches something off (--no-auth) takes no value.
// Credential flags whose name is exactly the word (or ends in it after a - or _): --bearer, --pass, --tokens,
// --keys, --jwt, --cookie. They are matched apart from the list above, which accepts any prefix, because
// --bypass or --compass must not count. --pass-through and --keys-only take no value, so they do not count.
// Not included on purpose: --license (usually a name such as MIT, or a file) and the short flags -t and -k
// (tag or tty, insecure for curl), which mean something else in many tools.
const CRED_FLAG_ONLY = '(?:bearer|pass|tokens|keys|jwt|cookie)(?![a-z])(?![-_]?(?:through|only)(?![a-z]))';
// The same with an optional prefix: --access-tokens, --user_pass, --my_jwt.
const CRED_FLAG_NAME = '(?:[A-Za-z0-9_-]{0,40}[-_])?' + CRED_FLAG_ONLY;
const CRED_FLAG_RE = new RegExp('^--?(?:\\/\\/[^\\s=]{1,200}:)?(?:[A-Za-z0-9_-]{0,40}(?:token|secret|passw(?:or)?d|passphrase|pwd|api[-_]?key|access[-_]?key|private[-_]?key|auth|credentials?|pat|key)(?![a-z])[A-Za-z0-9_-]{0,40}|' + CRED_FLAG_NAME + '[A-Za-z0-9_-]{0,40})$', 'i');
function isCredentialFlag(w) {
  return CRED_FLAG_RE.test(w) && !/^--(?:no|skip|disable|without)-/i.test(w);
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
      let hidden = false;
      for (let j = 0; j < rest.length; j++) {
        const w = rest[j];
        if (w === '--') break;
        if (w.startsWith('--package=')) { explicit = w.slice(10); continue; }
        if (w === '-p' || w === '--package') { explicit = rest[j + 1]; j++; continue; }
        if (NPX_VALUE_FLAGS.has(w)) { j++; continue; }
        // The word after a credential flag is its value, never the package.
        if (isCredentialFlag(w)) { if (!w.includes('=')) { if (j + 1 < rest.length) hidden = true; j++; } continue; }
        if (w.startsWith('-')) continue;
        first = w;
        break;
      }
      const spec = npmSpec(explicit || first);
      if (spec) out.push({ manager: tool, spec: explicit || first, pinned: pinnedNpm(spec.version) });
      else if (hidden && !explicit && !first) out.push({ manager: tool, spec: null, pinned: false, hidden: true });
      continue;
    }
    if (tool === 'uvx' || (tool === 'uv' && rest[0] === 'tool' && rest[1] === 'run') || (tool === 'pipx' && rest[0] === 'run')) {
      if (tool === 'uv') rest = rest.slice(2);
      if (tool === 'pipx') rest = rest.slice(1);
      let from = null;
      let first = null;
      let hidden = false;
      for (let j = 0; j < rest.length; j++) {
        const w = rest[j];
        if (w.startsWith('--from=')) { from = w.slice(7); continue; }
        if (w === '--from' || w === '--spec') { from = rest[j + 1]; j++; continue; }
        if (UVX_VALUE_FLAGS.has(w)) { j++; continue; }
        if (isCredentialFlag(w)) { if (!w.includes('=')) { if (j + 1 < rest.length) hidden = true; j++; } continue; }
        if (w.startsWith('-')) continue;
        first = w;
        break;
      }
      const spec = from || first;
      if (!spec && hidden) out.push({ manager: tool === 'uv' ? 'uv' : tool, spec: null, pinned: false, hidden: true });
      if (spec && !/^[.~/]|^[A-Za-z]:[\\/]|^(?:git\+|https?:|file:)/.test(spec)) {
        out.push({ manager: tool === 'uv' ? 'uv' : tool, spec, pinned: /==\s*\d|@\s*\d+\.\d+/.test(spec) });
      }
      continue;
    }
    if ((tool === 'docker' || tool === 'podman') && rest[0] === 'run') {
      let hidden = false;
      let found = false;
      for (let j = 1; j < rest.length; j++) {
        const w = rest[j];
        if (w.includes('=') && w.startsWith('--')) continue;
        if (DOCKER_VALUE_FLAGS.has(w)) { j++; continue; }
        if (isCredentialFlag(w)) { if (j + 1 < rest.length) hidden = true; j++; continue; }
        if (w.startsWith('-')) continue;
        const digest = w.includes('@sha256:');
        const tag = w.slice(w.lastIndexOf('/') + 1).split(':')[1];
        out.push({ manager: tool, spec: w, pinned: digest || Boolean(tag && tag !== 'latest') });
        found = true;
        break;
      }
      if (hidden && !found) out.push({ manager: tool, spec: null, pinned: false, hidden: true });
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

const PACKAGE_MANAGERS = new Set(['npm', 'pnpm', 'yarn', 'bun']);
const SAFE_WORD = /^[\w@%+=.,/~:-]+$/;
const SCRIPT_NAME = /^[\w][\w:-]*$/;
const PM_SUBS = new Set(['ci', 'remove', 'test', 'build', 'lint']);
const PM_TOOLS = new Set(['eslint', 'oxlint', 'prettier', 'tsc', 'vitest', 'jest', 'biome', 'knip', 'ruff', 'mypy', 'black']);
const PY_MODULES = new Set(['pytest', 'unittest', 'ruff', 'mypy', 'black', 'flake8', 'isort', 'pylint']);
const DENO_SUBS = new Set(['test', 'lint', 'fmt', 'check']);
const CONTAINER_READ = new Set(['ps', 'images', 'logs', 'inspect', 'version', 'info', 'stats', 'top']);

/**
 * True only for the exact, safe shapes of a scoped permission: a tool, a fixed
 * subcommand or script from a short allowlist, then literal arguments. Every
 * other shape (flags, groups such as "docker compose", run or exec, code
 * subcommands, bare tools) stays flagged.
 */
function scopedShape(words) {
  const first = words[0].toLowerCase();
  const sub = (words[1] || '').toLowerCase();
  if (!words.every((w) => SAFE_WORD.test(w))) return false;
  if (PACKAGE_MANAGERS.has(first)) {
    if (sub === 'run') return words.length > 2 && SCRIPT_NAME.test(words[2]);
    return PM_SUBS.has(sub);
  }
  if (first === 'npx' || first === 'bunx' || first === 'uvx') return PM_TOOLS.has(sub);
  if (first === 'python' || first === 'python3' || first === 'py') {
    if (sub === '-m') return PY_MODULES.has((words[2] || '').toLowerCase());
    return /^[\w./-]+\.py$/.test(words[1] || '');
  }
  if (first === 'node') return /^[\w./-]+\.[cm]?js$/.test(words[1] || '');
  if (first === 'sh' || first === 'bash' || first === 'zsh' || first === 'dash') return /^[\w./-]+\.sh$/.test(words[1] || '');
  if (first === 'deno') return DENO_SUBS.has(sub) || (sub === 'task' && words.length > 2 && SCRIPT_NAME.test(words[2]));
  if (first === 'docker' || first === 'podman') return CONTAINER_READ.has(sub);
  return false;
}

/** Severity of one Claude Code permission rule, or null when it is narrow. */
function claudePermission(entry) {
  const e = String(entry || '').trim();
  if (e === '*' || /^(?:Bash|PowerShell|Shell)$/.test(e)) return 'high';
  const m = /^(Bash|PowerShell|Shell)\((.*)\)$/s.exec(e);
  if (!m) return null;
  const inner = m[2].trim();
  if (inner === '' || /^[*:\s]+$/.test(inner)) return 'high';
  if (!/[*]/.test(inner)) return null;
  const firstWord = inner.split(/[\s:]/)[0].toLowerCase();
  if (firstWord.includes('*')) return 'high';
  if (!INTERPRETERS.has(firstWord) && !PACKAGE_MANAGERS.has(firstWord)) return null;
  // Only a final ":*" or " *" is a prefix wildcard; any other * can stand for a
  // flag or a subcommand, so it is flagged.
  const m2 = /^(.*?)(?::\*|\s\*)$/s.exec(inner);
  if (!m2 || m2[1].includes('*')) return 'high';
  const words = m2[1].split(/\s+/).filter(Boolean);
  return words.length > 0 && scopedShape(words) ? null : 'high';
}

/* ------------------------ instruction text ------------------------- */

const EXFIL = [
  // send / upload ... secret material ... to a destination (the secret must be
  // the thing sent: "create an API key at https://console..." is not)
  /\b(?:send|upload|post|exfiltrate|forward|transmit|leak|e-?mail)\b[^\n]{0,120}?(?:\.env\b|~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.netrc|\.git-credentials|api[ _-]?keys?|access[ _-]?tokens?|secrets?|credentials?|passwords?|private[ _-]?keys?|environment variables)\b[^\n]{0,120}?(?:https?:\/\/|webhook|pastebin|discord(?:app)?\.com|gist\.github|ngrok|requestbin|attacker)/i,
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

// Template env files hold placeholders, not secrets: "copy .env.example to
// .env" is a setup step.
const ENV_TEMPLATE = /\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist)\b|\.(?:example|sample|template)\.env\b/gi;

// copy / share / paste are also ordinary setup words ("copy your key from
// https://console... and paste it into config.json"). A known drop host always
// counts; for any other URL the line is exempt only when the URL is introduced by
// "from" or by create/generate/get/obtain/find (the console setup step).
const WEAK_EXFIL = /\b(?:copy|share|paste)\b[^\n]{0,120}?(?:\.env\b|~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.npmrc|\.netrc|\.git-credentials|api[ _-]?keys?|access[ _-]?tokens?|secrets?|credentials?|passwords?|private[ _-]?keys?|environment variables)\b[^\n]{0,120}?((?:https?:\/\/|webhook|pastebin|discord(?:app)?\.com|gist\.github|ngrok|requestbin|attacker))/gi;
const DROP_HOST = /webhook|pastebin|discord(?:app)?\.com|gist\.github|ngrok|requestbin|attacker/i;
// The setup verb has to govern the URL: "from (the)" right before it, or a
// create/generate/get/obtain/find clause (a new clause, not "to obtain ...") whose
// "at/on/in" leads straight to the URL, at most 5 words later and with no
// copy/share/paste/to/into/with in between.
const SETUP_FROM = /\bfrom\s+(?:the\s+)?$/i;
const SETUP_CREATE = /(?:[.;:!?,]|\b(?:and|then|first|next|also))\s+(?:create|generate|get|obtain|find)\b((?:\s+\S+){0,5}?)\s+(?:at|on|in)\s+(?:the\s+)?$/i;
const SETUP_BLOCK = /\b(?:copy|share|paste|to|into|with)\b/i;
// What the setup verb makes or fetches must be a credential or an account, right before "at/on/in" ("create an API
// key at", "get your token on"), in one clause: "get credits at" or "get your account verified at" after "paste your
// key here," does not exempt the line.
const SETUP_OBJECT = /\b(?:api[\s_-]?)?(?:keys?|tokens?|secrets?|credentials?|passwords?|accounts?)\s*$/i;
const SETUP_CLAUSE_BREAK = /[.,;:!?]|\b(?:and|then)\b/i;
function setupSource(pre) {
  if (SETUP_FROM.test(pre)) return true;
  const m = SETUP_CREATE.exec(pre);
  return !!m && !SETUP_BLOCK.test(m[1]) && !SETUP_CLAUSE_BREAK.test(m[1]) && SETUP_OBJECT.test(m[1]);
}
// After an exempt setup URL, another URL or a drop host on the same line is where the secret goes
// ("Copy your API key from <console> and paste it into <url>").
const LATER_TARGET = /https?:\/\/|webhook|pastebin|discord(?:app)?\.com|gist\.github|ngrok|requestbin|attacker/i;
function laterTarget(t, urlStart) {
  const rest = t.slice(urlStart).replace(/^\S+/, '');
  return LATER_TARGET.test(rest);
}

function weakExfiltration(t) {
  WEAK_EXFIL.lastIndex = 0;
  let m;
  while ((m = WEAK_EXFIL.exec(t)) !== null) {
    if (negated(t, m.index)) continue;
    const pre = m[0].slice(0, m[0].length - m[1].length);
    const urlStart = m.index + pre.length;
    if (DROP_HOST.test(t.slice(m.index)) || !setupSource(pre) || laterTarget(t, urlStart)) return m[0];
  }
  return null;
}

// Setup steps carry no secret out: "git clone <url>", "cp .env.example .env" and
// "create one at [Console](url)" are removed before the checks. The link is
// removed only when nothing earlier on the line sends, copies or pastes, so
// "Paste your API key here, get credits at [Free](url)" is still checked.
const SEND_VERB = /\b(?:send|upload|post|exfiltrate|forward|transmit|leak|e-?mail|paste|share|copy)\b/i;
// Earlier on the line only clear send verbs count ("your account email" is a noun).
const EARLIER_SEND = /\b(?:send|upload|exfiltrate|forward|transmit|leak|paste|share|copy)\b/i;
function stripSetupSteps(t) {
  let s = t;
  s = s.replace(/\b(?:git\s+)?clone\s+(?:--[\w-]+\s+)*(?:https?:\/\/|git@|ssh:\/\/)[^\s,;)]+/gi, ' ');
  s = s.replace(/\b(?:copy|cp)\s+\S*\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist)\b\S*\s+(?:to\s+)?\S*\.env\b/gi, ' ');
  s = s.replace(/\b((?:create|generate|get|obtain|find|grab)\b[^\n[]{0,60}?)\[[^\]\n]*\]\(\s*https?:\/\/[^\s)]*\s*\)/gi,
    (all, pre, offset, str) => (SEND_VERB.test(pre) || EARLIER_SEND.test(str.slice(0, offset)) ? all : pre));
  return s;
}

function exfiltration(text) {
  const t = stripSetupSteps(String(text || '').slice(0, MAX_LINE)).replace(ENV_TEMPLATE, 'env-template');
  for (const re of EXFIL) {
    const m = re.exec(t);
    if (m && !negated(t, m.index)) return m[0];
  }
  return weakExfiltration(t);
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
  CRED_FLAG_ONLY,
  CRED_FLAG_NAME,
  isCredentialFlag,
  downloadAndRun,
  warningText,
  warningHeading,
  imperativeStart,
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
