'use strict';

/**
 * Agent-independent policy used by the hook runner.
 *
 *  - Credential files: reads are denied (except .env files that only hold
 *    __ZN_ markers, see `zn env shadow`).
 *  - zn's own state (~/.zn) is off limits to agents, for reads and writes.
 *  - Commands that manage secrets (`zn secret set`, `zn env shadow`, ...)
 *    must be run by the user, never by an agent.
 *  - Bash commands with named markers in their arguments are refused with
 *    guidance: an argument is visible in the process list, so the secret goes
 *    to the program as an environment variable (`zn run --secrets NAME --`),
 *    which applies allowCommands, first-use approval and output masking.
 *
 * Hooks are a guardrail, not a sandbox: a determined process can always
 * find another way to read a file. The goal is that secret values never
 * reach the model through the normal tool paths.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const dotenv = require('../broker/dotenv');
const { hookStopAssignedIn, preloadAssignedIn, obscureLoaderKeyIn, loaderNameMentionedIn, shellDotenvWrite, OPAQUE_WRITE, PRELOAD_WRITE_NAMES } = require('../loader-env');
const markers = require('../broker/markers');
const { targetsOf } = require('../broker/files');
const { znCommand, cliName } = require('../zn-command');

// Version of the policy rules (credential paths, zn home, secret commands,
// command wrapping). Bump it when a rule changes; see CONTRIBUTING.md.
const shellVars = require('../shell-vars');
const POLICY_RULES_VERSION = '2026-11-26.3';

/* ------------------------------ paths ------------------------------ */

// Home and zn-home references written as shell variables (bash, PowerShell,
// cmd), so `cat $HOME/.zn/...` or `gc $env:USERPROFILE\.aws\credentials`
// are classified like their literal paths.
const HOME_VAR_RE = /^(?:\$\{?HOME\}?|\$env:(?:HOME|USERPROFILE)|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%)(?=$|[\\/])/i;
const ZN_HOME_VAR_RE = /^(?:\$\{?ZN_HOME\}?|\$env:ZN_HOME|%ZN_HOME%)(?=$|[\\/])/i;
// The Windows roaming application data folder, where GnuPG keeps its home folder.
const APPDATA_VAR_RE = /^(?:\$\{?APPDATA\}?|\$env:APPDATA|%APPDATA%)(?=$|[\\/])/i;

// A directory-stack entry other than the top (~1, ~+2, ~-1): zn does not know where it points.
const DIR_STACK_RE = /(?:^|[\s=@<:,{])~[+-]?[1-9]\d*(?=$|[\\/\s,}])/;

function expandHome(p, home) {
  if (p === '~') return home;
  if (p.charCodeAt(0) === 126) {
    // ~+ is $PWD: read as the working folder (a path relative to it), so ~+/.env is .env. ~- is $OLDPWD, which zn does not
    // know, and ~-0 is the same entry: both are turned into $OLDPWD so they are refused exactly like the variable.
    if (p === '~+') return '.';
    if (/^~\+[\\/]/.test(p)) return '.' + p.slice(2);
    if (/^~-(?:$|[\\/])/.test(p)) return '$OLDPWD' + p.slice(2);
    if (/^~-0(?=$|[\\/])/.test(p)) return '$OLDPWD' + p.slice(3);
    // ~0 and ~+0 are the top of the directory stack: the working folder. ~1, ~+2, ~-1 (deeper entries) are not known:
    // they are left as written and refused where a file is sent (DIR_STACK_RE).
    if (/^~\+?0(?=$|[\\/])/.test(p)) return '.' + p.replace(/^~\+?0/, '');
  }
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(home, p.slice(2));
  if (ZN_HOME_VAR_RE.test(p)) return path.join(home, '.zn', p.replace(ZN_HOME_VAR_RE, ''));
  if (HOME_VAR_RE.test(p)) return path.join(home, p.replace(HOME_VAR_RE, ''));
  if (APPDATA_VAR_RE.test(p)) return path.join(home, 'AppData', 'Roaming', p.replace(APPDATA_VAR_RE, '').replace(/^[\\/]+/, ''));
  return p;
}

function slash(p) {
  return String(p).replace(/\\/g, '/');
}

const DOTENV_BASENAME_RE = /^\.env(\.[A-Za-z0-9_.-]+)?$/;
const DOTENV_SAFE_RE = /\.(example|sample|template)$/i;
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
  [/(^|\/)\.zcode\/v2\/provider_config\.json$/, 'Zcode model provider credentials'],
  [/(^|\/)(?:\.gnupg|AppData\/Roaming\/gnupg)\/.+$/i, 'GnuPG keyring'],
];
// The GnuPG home folder itself: archiving, copying or searching it as a whole reads every key in it. Only the gpg
// programs, which use their own home folder, may name it.
const GNUPG_DIR_RE = /(^|\/)(?:\.gnupg|AppData\/Roaming\/gnupg)\/?$/i;
const GNUPG_DIR_REASON = 'GnuPG keyring folder';
const GPG_PROGRAMS = new Set(['gpg', 'gpg2', 'gpgconf', 'gpg-agent', 'gpg-connect-agent', 'gpgsm', 'gpgv']);
// The gpg programs that may name their own home folder, and only with read-only options spelled out in full (a
// closed list: GnuPG has many options that start a helper program, such as --agent-program, --dirmngr-program or
// --photo-viewer, and accepts abbreviations, so any option not on the list withdraws the exemption). gpg-agent and
// gpg-connect-agent can start another program (--daemon PROGRAM, --exec) and get no exemption at all.
const GPG_FOLDER_PROGRAMS = new Set(['gpg', 'gpg2', 'gpgconf', 'gpgsm', 'gpgv']);
const GPG_READONLY_OPTIONS = new Set(['--homedir', '--list-keys', '-k', '--list-public-keys', '--list-secret-keys', '-K',
  '--list-sigs', '--check-sigs', '--fingerprint', '--with-colons', '--with-fingerprint', '--with-subkey-fingerprint',
  '--keyid-format', '--batch', '--no-tty', '--quiet', '-q', '--verbose', '-v', '--list-dirs', '--list-components',
  '--list-options', '--verify', '--version', '--armor', '-a', '--export', '--export-ssh-key']);
function gpgReadOnlyCall(listed, w) {
  for (const x of listed) {
    if (x.head !== w.head || x.seq !== w.seq) continue;
    const t = String(x.text);
    if (!t.startsWith('-')) continue;
    if (!GPG_READONLY_OPTIONS.has(t.split('=')[0])) return false;
  }
  return true;
}
// Exporting a secret key prints or writes the private key, whatever folder gpg uses: --export-secret-keys,
// --export-secret-subkeys and gpgsm's --export-secret-key-p12/-p8/-raw, also abbreviated (gpg takes any unique
// prefix, and --export-se is the shortest one), and the agent's EXPORT_KEY command.
const GPG_SECRET_EXPORT_RE = /^--export-se/i;
const GPG_SECRET_EXPORT_MESSAGE = 'zn: this command would export a GnuPG secret key, which is protected. Ask the user to do it.';
// gpg-connect-agent also reads its commands from stdin, from a file (--run FILE, -r FILE, or its own /run FILE
// control command), and a shell can build them from a variable or a command substitution. zn cannot see such
// commands, so an EXPORT_KEY there could not be refused. Fail closed, with closed lists:
// - a command line that runs gpg-connect-agent and has a pipe, an input redirection, or a $ or backtick expansion;
// - an option of gpg-connect-agent that starts with --r (GnuPG accepts prefixes of long options) or a short option
//   group that contains r (-r FILE, -rFILE, -vr);
// - a control command other than /bye and /echo (/run, /definqfile and the others read or send files).
const GPG_AGENT_WORD_RE = /(?:^|[^\w.-])gpg-connect-agent(?:\.exe)?(?![\w.-])/i;
const GPG_AGENT_HIDDEN_INPUT_RE = /[|<`$]/;
const GPG_AGENT_RUN_OPTION_RE = /^(?:--r|-[A-Za-z]*r)/;
const GPG_AGENT_SAFE_CONTROL = new Set(['/bye', '/echo']);
const GPG_AGENT_HIDDEN_INPUT_MESSAGE = 'zn: gpg-connect-agent is allowed only with its commands written out as arguments: this command line could feed it commands zn cannot check (from stdin, a file, a variable or a command substitution) for a secret key export (EXPORT_KEY). Give the commands as arguments, or ask the user to run it.';
function gpgSecretExportDenial(words, text) {
  // The program is found on the words as the shell reads them (quotes and escapes removed: gpg-connect-"agent"),
  // and in the raw text as well.
  const runsAgent = words.some((w) => programName(w.head || '') === 'gpg-connect-agent') ||
    (typeof text === 'string' && GPG_AGENT_WORD_RE.test(text));
  if (runsAgent && typeof text === 'string' && GPG_AGENT_HIDDEN_INPUT_RE.test(text)) return GPG_AGENT_HIDDEN_INPUT_MESSAGE;
  for (const w of words) {
    const prog = programName(w.head || '');
    if (!GPG_PROGRAMS.has(prog)) continue;
    if (prog === 'gpg-connect-agent') {
      const t = String(w.text).trim();
      if (programName(t) === 'gpg-connect-agent') continue; // the program word itself, with or without a path
      if (GPG_AGENT_RUN_OPTION_RE.test(t)) return GPG_AGENT_HIDDEN_INPUT_MESSAGE;
      const first = t.split(/\s+/)[0].toLowerCase();
      if (first.startsWith('/') && !GPG_AGENT_SAFE_CONTROL.has(first)) return GPG_AGENT_HIDDEN_INPUT_MESSAGE;
    }
    if (GPG_SECRET_EXPORT_RE.test(w.text)) return GPG_SECRET_EXPORT_MESSAGE;
    if (prog === 'gpg-connect-agent' && /(^|[^A-Za-z_])export_key([^A-Za-z_]|$)/i.test(w.text)) return GPG_SECRET_EXPORT_MESSAGE;
  }
  return null;
}

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
  [/(^|\/)\.agents\/hooks\.json$/, 'Antigravity hooks'],
  [/(^|\/)\.gemini\/config\/hooks\.json$/, 'Antigravity hooks'],
  [/(^|\/)\.gemini\/antigravity-cli\/settings\.json$/, 'Antigravity settings and permissions'],
  [/(^|\/)\.github\/hooks\/[^/]*\.json$/, 'GitHub Copilot hooks'],
  [/(^|\/)\.github\/copilot\/settings(\.local)?\.json$/, 'GitHub Copilot settings'],
  [/(^|\/)\.copilot\/(hooks\/[^/]*|settings(\.local)?\.json|config\.json)$/, 'GitHub Copilot hooks and settings'],
  [/(^|\/)github-copilot\/policy\.d\/[^/]*$/, 'GitHub Copilot policy hooks'],
  [/(^|\/)\.gemini\/settings\.json$/, 'Gemini CLI settings and hooks'],
  [/(^|\/)gemini-cli\/settings\.json$/, 'Gemini CLI system settings'],
  [/(^|\/)\.zcode\/(cli\/)?config\.json$/, 'Zcode settings and hooks'],
  [/(^|\/)opencode\.jsonc?$/, 'OpenCode configuration'],
  [/(^|\/)\.(config\/)?opencode\/plugins?\//, 'OpenCode plugins'],
  [/(^|\/)\.opencode\/plugins?\//, 'OpenCode plugins'],
];

// The agents' plugin folders and plugin state, as paths relative to the home folder (a project's own .gemini or
// .claude/plugins folder is not the agent's): an installed plugin runs its hooks, so changing or removing one (or its
// list of installed plugins) changes or switches off the hooks that check the agent, zn's plugin included. The second
// pattern is Antigravity's plugin switches and the folders that hold the ZCode and Antigravity configuration and
// plugins, which cannot be removed, moved or created as such (the other files in them stay writable). Two patterns
// keep the check as fast as before (it runs on every path of every call).
// The agents' plugin folders and plugin state under the home folder, for their real places (a linked ~/.claude or
// ~/.claude/plugins): the folders whose contents are protected, and the entries protected themselves.
const HOME_PLUGIN_TREES = ['.claude/plugins', '.codex/plugins', '.cursor/plugins', '.zcode/cli/plugins', '.gemini/config/plugins',
  '.gemini/antigravity-cli/plugins'];
const HOME_PLUGIN_STATE = ['.gemini/config/config.json', '.zcode', '.zcode/cli', '.gemini', '.gemini/config', '.gemini/antigravity-cli'];
const HOME_PLUGIN_RES = [
  [/^(\.claude|\.codex|\.cursor|\.zcode\/cli|\.gemini\/config|\.gemini\/antigravity-cli)\/plugins(\/|$)/, 'the agent plugins'],
  [/^(\.gemini\/config\/config\.json|\.zcode(\/cli)?|\.gemini(\/config|\/antigravity-cli)?)$/, 'the agent configuration and plugin state'],
];

// Windows and macOS file systems are case-insensitive by default. Read on each
// call, so tests can simulate those platforms on any system.
function caseInsensitive() {
  return process.platform === 'win32' || process.platform === 'darwin';
}
// macOS reports names like "José" decomposed (NFD) while a typed path is usually composed (NFC),
// and its file systems treat both as the same folder, so every comparison uses NFC.
const keyOf = (s) => {
  const n = s.normalize('NFC');
  return caseInsensitive() ? n.toLowerCase() : n;
};
// NTFS alternate data streams: `.env::$DATA`, `credentials:stream` and `dir::$INDEX_ALLOCATION` all name the file
// or folder itself. A colon cannot be part of a Windows name, so on win32 everything after the first colon of a
// path segment is a stream (a drive letter stays). Elsewhere a colon is a valid name character, so only the
// explicit `::$DATA` style suffix is dropped.
const ADS_TYPE_RE = /(?::[^\\/:*?"<>|]*)?:\$(?:DATA|INDEX_ALLOCATION|BITMAP)$/i;
// The text before the first colon that is not inside a cmd variable pair: %NAME:~0,5% and !NAME:old=new! keep their modifier, which is not a stream.
function cutAtStream(seg) {
  let pct = false;
  let bang = false;
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (c === '%') pct = !pct;
    else if (c === '!') bang = !bang;
    else if (c === ':' && !pct && !bang) return seg.slice(0, i);
  }
  return seg;
}
function stripStreams(text) {
  if (typeof text !== 'string') return text;
  const win = process.platform === 'win32';
  if (!win && text.indexOf(':') < 0) return text;
  return text.split(/([\\/]+)/).map((seg, i) => {
    if (win) {
      if (/^[A-Za-z]:$/.test(seg)) return seg;
      if (i === 0 && /^[A-Za-z]:/.test(seg)) return seg.slice(0, 2) + dropTrailingDotsSpaces(cutAtStream(seg.slice(2)));
      return dropTrailingDotsSpaces(cutAtStream(seg));
    }
    return seg.replace(ADS_TYPE_RE, '');
  }).join('');
}
// Windows drops trailing dots and spaces from a name, so `settings.json.` and `settings.json ` open `settings.json`.
// A name made only of dots (`.`, `..`) is left alone. Scanned from the end, so a long run cannot cost more than its length.
function dropTrailingDotsSpaces(seg) {
  let end = seg.length;
  while (end > 0 && (seg.charCodeAt(end - 1) === 46 || seg.charCodeAt(end - 1) === 32)) end--;
  if (end === seg.length) return seg;
  if (/^\.*$/.test(seg)) return seg;
  return seg.slice(0, end);
}
// An 8.3 short name: up to six characters, `~`, digits, and an optional extension of up to three (`SETTIN~1.JSO`,
// `CLAUDE~1`). The long name it stands for cannot be read from the text, so on win32 it is checked as a pattern
// (`{,.}settin*.jso*`) against the protected names, like a typed glob.
const SHORT_NAME_RE = /^([^~\s.:*?"<>|\\/]{1,6})~[0-9]{1,6}(?:\.([^.\s:*?"<>|\\/]{1,3}))?$/;
function shortNameGlob(text) {
  if (process.platform !== 'win32' || typeof text !== 'string' || text.indexOf('~') < 0) return null;
  let found = false;
  let lastShort = false;
  const out = text.split(/([\\/]+)/).map((seg) => {
    const m = SHORT_NAME_RE.exec(seg);
    if (!/^[\\/]*$/.test(seg)) lastShort = !!m;
    if (!m) return seg;
    found = true;
    return '{,.}' + m[1] + '*' + (m[2] ? '.' + m[2] + '*' : '');
  }).join('');
  return found ? { glob: out, lastShort } : null;
}
/** The pattern, ignoring case where the platform does. */
const ci = (re) => (caseInsensitive() && !re.flags.includes('i') ? new RegExp(re.source, re.flags + 'i') : re);

// Environment variables that name agent configuration. Unset, they cannot be
// resolved here, so a path that uses them is treated as agent configuration.
const AGENT_ENV = new Set(['CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'OPENCODE_CONFIG', 'OPENCODE_CONFIG_DIR', 'XDG_CONFIG_HOME']);

// The same references plus !NAME!, which cmd.exe expands when delayed expansion is on (cmd /v:on).
// cmd.exe also takes a modifier inside the pair (%NAME:~0,5%, %NAME:old=new%, !NAME:~0,5!): the value it gives cannot be read here.
const PATH_REF_RE = new RegExp(ENV_REF_RE.source + '|!([A-Za-z_][A-Za-z0-9_]*)(?::[^%!\\r\\n]*)?!|%([A-Za-z_][A-Za-z0-9_]*):[^%!\\r\\n]*%', 'gi');
// A variable reference that stands right before a .env name (%D%.env, !D!.env, $D.env): when the variable holds a
// folder with its closing separator, the word names that folder's .env file.
const VAR_BEFORE_DOTENV_RE = /(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$env:[A-Za-z_][A-Za-z0-9_]*|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*(?::[^%!\r\n]*)?%|![A-Za-z_][A-Za-z0-9_]*(?::[^%!\r\n]*)?!)\.env(?:\.[A-Za-z0-9_.-]+)?$/i;

/** $NAME, ${NAME}, $env:NAME, %NAME% and !NAME! from env. Unset credential or agent variables are reported by name. */
function expandEnv(p, env) {
  let credentialVar = null;
  let agentVar = null;
  const text = p.replace(PATH_REF_RE, (m, a, b, c, d, e, f) => {
    const name = a || b || c || d || e || f;
    if (env[name] && !/^[%!][^%!]*:/.test(m)) return env[name];
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
      for (const p of new Set([abs, ...targetsOf(abs)])) (CRED_ENV_DIRS.has(name) ? dirs : files).add(keyOf(slash(p)));
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
  return [...new Set([keyOf(slash(p)), ...targetsOf(p).map((t) => keyOf(slash(t)))])];
}

// The home folder and the project root are resolved once per process: a hook process checks one call, and the
// other users of the policy (tests, the broker) pass the same few folders again and again.
const ROOT_KEYS = new Map();
function rootKeysOf(p) {
  const k = String(p);
  let v = ROOT_KEYS.get(k);
  if (!v) {
    if (ROOT_KEYS.size > 256) ROOT_KEYS.clear();
    v = keysOf(p);
    ROOT_KEYS.set(k, v);
  }
  return v;
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
  const projectRoot = projectRootOf(cwd);
  for (const root of [home, projectRoot]) {
    for (const r of rel) for (const k of keysOf(path.join(root, r))) dirs.add(k);
  }
  const at = (p) => path.resolve(cwd, expandHome(p, home));
  // Plugin folders under a moved configuration folder (the folder names there do not match the patterns): built from
  // the keys already resolved for that folder, so no other file system call.
  const plugins = new Set();
  // The home folder as typed and where it really leads (a linked home), for ~/.zn and the home plugin folders. A
  // relative HOME names no real place: the user's own home folder from the system is used as well.
  const homes = new Set(rootKeysOf(path.resolve(home)));
  if (!path.isAbsolute(String(home))) {
    try { for (const k of rootKeysOf(os.userInfo().homedir)) homes.add(k); } catch (_) { /* no user record */ }
  }
  // Where each plugin folder and plugin state entry under the home folder really is: a linked configuration folder
  // (dotfiles) or plugin folder puts them outside the home folder, where the home-relative patterns do not see them.
  const state = new Set();
  for (const r of HOME_PLUGIN_TREES) for (const k of keysOf(path.join(home, r))) plugins.add(k);
  for (const r of HOME_PLUGIN_STATE) for (const k of keysOf(path.join(home, r))) state.add(k);
  if (env.CODEX_HOME) {
    for (const k of keysOf(at(env.CODEX_HOME))) { dirs.add(k); plugins.add(k + '/plugins'); }
    for (const k of keysOf(path.join(at(env.CODEX_HOME), 'plugins'))) plugins.add(k);
  }
  // Claude Code keeps its settings here when the variable is set, and zn installs its hooks there.
  if (env.CLAUDE_CONFIG_DIR) {
    for (const k of keysOf(at(env.CLAUDE_CONFIG_DIR))) { dirs.add(k); plugins.add(k + '/plugins'); }
    for (const k of keysOf(path.join(at(env.CLAUDE_CONFIG_DIR), 'plugins'))) plugins.add(k);
  }
  if (env.OPENCODE_CONFIG_DIR) for (const k of keysOf(at(env.OPENCODE_CONFIG_DIR))) dirs.add(k);
  if (env.XDG_CONFIG_HOME) for (const k of keysOf(path.join(at(env.XDG_CONFIG_HOME), 'opencode'))) dirs.add(k);
  if (env.OPENCODE_CONFIG) for (const k of keysOf(at(env.OPENCODE_CONFIG))) files.add(k);
  // Claude Code keeps every plugin file and its plugin state under this folder when the variable is set.
  if (env.CLAUDE_CODE_PLUGIN_CACHE_DIR) for (const k of keysOf(at(env.CLAUDE_CODE_PLUGIN_CACHE_DIR))) plugins.add(k);
  // Antigravity's workspace plugins: only at the root of the project, as typed and where it really leads.
  for (const k of rootKeysOf(projectRoot)) plugins.add(k + '/.agents/plugins');
  // Roots that hold agent configuration: removing or moving them removes it.
  // Only the directory itself is protected (listing it or reading it is fine).
  const roots = new Set(keysOf(path.join(home, '.config')));
  if (env.XDG_CONFIG_HOME) for (const k of keysOf(at(env.XDG_CONFIG_HOME))) roots.add(k);
  return { dirs: [...dirs], files, roots: [...roots], plugins: [...plugins], homes: [...homes], state };
}

/** Everything a classification needs, from the options of one call. */
function contextOf(opts = {}) {
  // A caller that classifies many words passes the context it already built.
  if (opts.ctx) return opts.ctx;
  const home = opts.home || os.homedir();
  const cwd = opts.cwd || process.cwd();
  const env = opts.env || process.env;
  // zn's own folder when ZN_HOME moves it: protected like ~/.zn (the default folder is always protected as well).
  const znHome = env.ZN_HOME ? path.resolve(env.ZN_HOME) : null;
  return { home, cwd, env, znHome, creds: credentialEnvPaths(env, home, cwd), agent: agentContext(home, cwd, env) };
}

/**
 * Classify a resolved absolute path. `ctx` comes from contextOf.
 */
/* The protected class of a path relative to a home folder (.zn, the plugin folders and the plugin state), or null. */
function homeRelClass(rel) {
  const r = String(rel).replace(/^(?:\.\/)+/, '').replace(/\/+$/, '');
  if (ci(/^\.zn(\/|$)/).test(r)) return { kind: 'zn_state', reason: 'zn keeps its vault and audit log in ~/.zn' };
  for (const [re, reason] of HOME_PLUGIN_RES) if (ci(re).test(r)) return { kind: 'agent_config', reason };
  return null;
}

/* A write target zn cannot place on disk that may still name ~/.zn or an agent's plugins: a prefix that is a variable
   the environment does not set, a command substitution or another user's ~name (each may be a home folder), or a
   relative path after a cd (into the home folder, or to a place zn cannot follow). Returns the class or null. */
function protectedElsewhere(text, opts) {
  const t = slash(text);
  const m = /^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\([^)]*\)|`[^`]*`|~[A-Za-z0-9._-]+)\/(.*)$/.exec(t)
    // ${H}.zn: the variable's value may end with a slash.
    || /^\$\{[A-Za-z_][A-Za-z0-9_]*\}(.+)$/.exec(t)
    // The end of a substitution the shell split off ($(echo ~)/x reads as "$(echo" and "~)/x").
    || /^[^/]*[)`]\/(.*)$/.exec(t);
  // A variable the environment (or the command itself) sets was already expanded by the classification.
  const v = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)/.exec(t);
  const known = v && (opts.env || process.env)[v[1]] && !(opts.unknownVars && opts.unknownVars.has(v[1]));
  if (m && !known) {
    const c = homeRelClass(m[1]);
    if (c) return c;
  }
  // The word right after a substitution's closing bracket ($(echo ~)/.zn leaves /.zn): its start is the output of
  // another command, which may be the home folder.
  const cmdText = opts.cmdText || '';
  if (t.startsWith('/') && (cmdText.includes(')' + text) || cmdText.includes('`' + text))) {
    const c = homeRelClass(t.slice(1));
    if (c) return c;
  }
  const bases = opts.cdBases;
  if (!bases || !bases.moved || path.isAbsolute(t) || /^[~$`%]/.test(t)) return null;
  const cwd = path.resolve(opts.cwd || process.cwd());
  for (const b of bases.dirs) {
    if (b === cwd) continue;
    const c = classifyPath(path.join(b, text), opts);
    if (c && (c.kind === 'zn_state' || c.kind === 'agent_config')) return c;
  }
  // A cd zn cannot follow (cd $DIR, cd -) may lead to the home folder.
  return bases.unknown ? homeRelClass(t) : null;
}

function classifyResolved(abs, ctx) {
  const { home, creds, agent } = ctx;
  const s = keyOf(slash(abs));
  const h = keyOf(slash(path.resolve(home)));
  const homes = agent.homes || [h];
  for (const h of homes) {
    const prefix = h.endsWith('/') ? h : h + '/';          // a home of "/" is its own prefix
    if (s === prefix + '.zn' || s.startsWith(prefix + '.zn/')) return { kind: 'zn_state', reason: 'zn keeps its vault and audit log in ~/.zn' };
  }
  // A ZN_HOME that moves zn's folder elsewhere. A value that is a home folder or a drive root is not taken: it would
  // protect the whole home folder.
  if (ctx.znHome) {
    const zh = keyOf(slash(ctx.znHome)).replace(/\/+$/, '');
    // Only the root of a file system (/, a drive such as C:/, a network share) is refused, so a short folder such as /zn is protected.
    const fsRoot = keyOf(slash(path.parse(ctx.znHome).root)).replace(/\/+$/, '');
    const wide = zh === '' || zh === fsRoot || homes.some((x) => x.replace(/\/+$/, '') === zh);
    if (!wide && (s === zh || s.startsWith(zh + '/'))) return { kind: 'zn_state', reason: 'zn keeps its vault and audit log in ZN_HOME' };
  }
  for (const [re, reason] of AGENT_CONFIG_RES) if (ci(re).test(s)) return { kind: 'agent_config', reason };
  for (const h of homes) {
    const prefix = h.endsWith('/') ? h : h + '/';
    if (!s.startsWith(prefix)) continue;
    const c = homeRelClass(s.slice(prefix.length));
    if (c) return c;
  }
  // The directory itself (`cd ~/.claude`, `mv ~/.codex`, `rm -r ~/.cursor`) and the files directly in it.
  if (agent.dirs.includes(s) || agent.roots.includes(s)) return { kind: 'agent_config', reason: 'an agent configuration directory' };
  if (agent.dirs.some((d) => s.startsWith(d + '/') && !s.slice(d.length + 1).includes('/'))) {
    return { kind: 'agent_config', reason: 'a file in an agent configuration directory' };
  }
  if (agent.files.has(s)) return { kind: 'agent_config', reason: 'the agent configuration file the environment names' };
  if ((agent.plugins || []).some((d) => s === d || s.startsWith(d + '/'))) return { kind: 'agent_config', reason: 'the agent plugins' };
  if (agent.state && agent.state.has(s)) return { kind: 'agent_config', reason: 'the agent configuration and plugin state' };
  if (s.endsWith('.pub')) return null;
  if (creds.files.has(s)) return { kind: 'credential', reason: 'a file named by a credential environment variable' };
  for (const d of creds.dirs) if (s === d || s.startsWith(d + '/')) return { kind: 'credential', reason: 'a directory named by a credential environment variable' };
  for (const [re, reason] of CREDENTIAL_RES) if (ci(re).test(s)) return { kind: 'credential', reason };
  if (ci(GNUPG_DIR_RE).test(s)) return { kind: 'credential', reason: GNUPG_DIR_REASON };
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
  return path.resolve(cwd, stripStreams(expandEnv(expandHome(p, home), opts.env || process.env).text));
}

/**
 * The path a typed path names when every ".." is applied to the real place its left side leads to (links followed),
 * not to the text before it. null when the path has no "..". A part that does not exist is followed as written.
 */
function physicalDotDot(text, cwd) {
  if (typeof text !== 'string' || !/(^|[\\/])\.\.([\\/]|$)/.test(text)) return null;
  const full = path.isAbsolute(text) ? text : cwd + path.sep + text;
  const rootDir = path.parse(full).root;
  let cur = rootDir;
  for (const seg of full.slice(rootDir.length).split(/[\\/]+/)) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      let real = cur;
      try { real = fs.realpathSync(cur); } catch (_) { /* not there: followed as written */ }
      cur = path.dirname(real);
    } else {
      cur = path.join(cur, seg);
    }
  }
  return cur;
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
  expanded.text = stripStreams(expanded.text);
  // %D%.env, !D!.env, $D.env: a variable zn cannot expand right before the .env name (dotenvElsewhereOf refuses it).
  const lastName = expanded.text.split(/[\\/]/).pop();
  if (VAR_BEFORE_DOTENV_RE.test(lastName) && !ci(DOTENV_SAFE_RE).test(lastName)) return { kind: 'dotenv', reason: '.env file' };
  const abs = path.resolve(ctx.cwd, expanded.text);
  const candidates = new Set([abs, ...targetsOf(abs)]);
  // ag/../hooks.json, with ag a link to .agents/skills, names .agents/hooks.json: ".." is applied to where the link leads.
  const physical = physicalDotDot(expanded.text, ctx.cwd);
  if (physical) { candidates.add(physical); for (const t of targetsOf(physical)) candidates.add(t); }
  for (const candidate of candidates) {
    const c = classifyResolved(candidate, ctx);
    if (c) return c;
  }
  // A short name hides the long one: it counts as protected when it could stand for a protected file or folder.
  const short = shortNameGlob(expanded.text);
  // When the last name is written out, a .env there is judged by its own content (readDenial), not by the pattern.
  // A last name that is itself a glob (`*`, `.e*`) names whatever it matches, a plain .env included: no skipping then.
  if (short) return globClass(short.glob, short.lastShort || GLOB_RE.test(expanded.text) ? opts : { ...opts, skipDotenv: true });
  return null;
}

/* ---------------------------- globs, braces ---------------------------- */

const GLOB_RE = /[*?[\]{}]/;
// The first comma is matched by [^{},]*, so the pattern has one way to match and cannot backtrack.
const BRACE_RE = /\{([^{},]*,[^{}]*)\}/;

// A brace list has at least two alternatives, so more than 6 lists in one word always pass the default limit of 64.
// The recursion stops there instead of following one level per list (a word with 20000 lists overflowed the stack).
const BRACE_MAX_DEPTH = 8;

/** Alternatives of a word with brace lists (`a{b,c}` -> ab, ac); null when there are too many. */
function expandBraces(s, limit = 64, depth = 0) {
  const m = BRACE_RE.exec(s);
  if (!m) return [s];
  if (depth >= BRACE_MAX_DEPTH) return null;
  const out = [];
  let seen = 0; // every alternative counts towards the limit, repeated ones too
  for (const alt of m[1].split(',')) {
    const rest = expandBraces(s.slice(0, m.index) + alt + s.slice(m.index + m[0].length), limit, depth + 1);
    if (rest === null) return null;
    for (const x of rest) {
      if (++seen > limit) return null;
      if (!out.includes(x)) out.push(x); // the outer list repeats its other alternatives for each inner one
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
    if (!opts.skipDotenv && keyOf(path.posix.basename(abs)).startsWith('.env')) return { kind: 'credential', reason: 'a pattern that matches a .env file' };
    const re = globRegExp(keyOf(abs));
    if (re.impossible) continue;
    for (const ex of examples) {
      const c = classifyResolved(ex, ctx);
      if (c && !(opts.skipDotenv && c.kind === 'dotenv') && re.test(keyOf(slash(ex)))) {
        return c.kind === 'dotenv' ? { kind: 'credential', reason: 'a pattern that matches a .env file' } : c;
      }
    }
    // What the pattern matches on the disk now, read with a limit.
    const hits = globOnDisk(abs, opts.budget);
    if (hits === 'too-broad' || hits === 'too-slow') return { kind: 'credential', reason: 'a pattern too broad to check' };
    for (const hit of hits || []) {
      for (const cand of new Set([hit, ...targetsOf(hit)])) {
        const c = classifyResolved(cand, ctx);
        // A key file match is judged by its content (keyFileGlobDenial); a protected file found later still wins.
        if (c && c.kind === 'keyfile') { keyHit = keyHit || c; continue; }
        if (c && opts.skipDotenv && c.kind === 'dotenv') continue;
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
    const plain = text === null ? [] : dotenv.plainSecretNames(text);
    if (text !== null && plain.length === 0) return null;
    const left = plain.length
      ? ' Still holding a value: ' + plain.slice(0, 10).join(', ') + (plain.length > 10 ? ' and ' + (plain.length - 10) + ' more' : '') + '.'
      : '';
    return 'zn: ' + path.basename(abs) + ' holds plain-text secrets, and secret values never go to the model (rule: secret-file:dotenv).' + left + ' Ask the user to run `' +
      znCommand('env shadow ' + path.basename(abs)) + '` in their terminal: it moves the values to the local vault and leaves __ZN_<NAME>__ markers you can read and use.' +
      (plain.length ? ' A value that is too short for that stays in the file: store it with `' + znCommand('secret set <NAME>') + '` and write __ZN_<NAME>__ in its place.' : '');
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
  // A wildcard is not a file: `ls *` in a folder that has a .env file names no secret, so saying that `*` "holds secrets" confuses the person
  // reading it. For a pattern, say what the pattern would reach and what to do instead.
  if (/[*?[{]/.test(p) || /^an? (brace )?pattern/.test(c.reason)) {
    const broad = /too broad/.test(c.reason);
    const why = broad ? 'it is too broad for zn to check that it matches no file that holds secrets'
      : /\.env/.test(c.reason) ? 'it would also match a .env file, which holds secrets'
        : 'it would also match a file that holds secrets (' + c.reason + ')';
    return 'zn: the pattern ' + p + ' was not read because ' + why + ', and secret values never go to the AI model. ' +
      'Name the files you need instead (for example `cat notes.md` instead of `cat *`), or ask the user to run the command in their own terminal.';
  }
  return 'zn: ' + p + ' was not read because zn treats it as holding secrets (' + c.reason + '), and secret values never go to the model. ' +
    'If a command needs a value, ask the user to run `' + znCommand('secret set NAME') + '`, then run the command with `' + znCommand('run --secrets NAME -- <command>') + '` so the program gets it as an environment variable. ' +
    'Agents may not read the file itself (rule: secret-file:credential).';
}

function agentConfigDenial(p, c) {
  return 'zn: ' + c.reason + ' (' + p + ') is protected: an agent may not change how zn and its hooks run. Ask the user to make this change.';
}

/**
 * A write that would set a variable which stops every hook before it runs (LD_TRACE_LOADED_OBJECTS, LD_DEBUG with help: see
 * isHookStopVar in loader-env.js, the same test `zn audit` uses for ZNA008), or a preload library variable to a value (LD_PRELOAD,
 * LD_AUDIT, DYLD_INSERT_LIBRARIES ...: preloadAssignedIn), in a file the agent loads into its environment. Gemini CLI
 * loads a project .env and .gemini/.env; the agents' own settings files are refused whole (AGENT_CONFIG_RES), so the .env files are the
 * ones that need this check. `texts` is what the call would write (a file body, a replacement, a patch); returns a deny message or null.
 */
function loaderEnvWriteDenial(p, texts, opts = {}) {
  const c = classifyPath(p, opts);
  if (!c || c.kind !== 'dotenv') return null;
  // An edit that could not be applied to the file as it is: the result is unknown, so the write is refused.
  if (texts && texts.unresolved) {
    return 'zn: ' + path.basename(String(p)) + ' is a file the agent loads into its environment, and zn could not work out what this edit would leave in it. ' +
      'An agent may not make this change. Ask the user to make it, or rewrite the whole file.';
  }
  for (const t of texts || []) {
    if (typeof t !== 'string') continue;
    const name = hookStopAssignedIn(t);
    if (name) return loaderEnvDenial(name, p);
    // LD_PRELOAD, LD_AUDIT, DYLD_INSERT_LIBRARIES ... with a value: a library of the project's choosing loaded into every program.
    const preload = preloadAssignedIn(t);
    if (preload) return loaderPreloadDenial(preload, p);
    // A line whose name mentions LD_ or DYLD_ but is not a plain name (quotes, backslashes, $ inside it): which variable it sets is
    // not plain to see.
    if (obscureLoaderKeyIn(t)) {
      return 'zn: ' + path.basename(String(p)) + ' is a file the agent loads into its environment, and this write holds a variable name that mentions LD_ or DYLD_ ' +
        'but is not a plain name, so zn cannot tell which variable it sets. An agent may not make this change. Ask the user to make it.';
    }
  }
  return null;
}

function loaderEnvDenial(name, p) {
  return 'zn: ' + path.basename(String(p)) + ' would set ' + name + ' for the agent. On Linux that makes the dynamic loader end every program the agent starts ' +
    'before it runs, the shell of every zn hook included, so zn could no longer check any action. An agent may not make this change. Ask the user to make it.';
}

function loaderPreloadDenial(name, p) {
  return 'zn: ' + path.basename(String(p)) + ' would set ' + name + ' for the agent. That makes the dynamic loader load a library of the project\'s choosing ' +
    'into every program the agent starts, the shell of every zn hook included, before zn can check anything. An agent may not make this change. Ask the user to make it.';
}

function opaqueEnvWriteDenial(p) {
  const base = path.basename(String(p));
  return 'Edit ' + base + ' with the file editor tool; shell writes to .env files are blocked. zn cannot see what the shell actually writes.';
}

/** A program that names a watched dotenv file and is not proven read-only: zn cannot tell whether it writes the file. */
function unprovenEnvWriteDenial(p) {
  const base = path.basename(String(p));
  return 'zn cannot tell whether this command writes ' + base + ', so shell writes to .env files are blocked here. Edit ' + base +
    ' with the file editor tool. To load it, use --env-file (node, bun, deno, docker, podman) or dotenv -e; source and . run the ' +
    'file as shell code and are refused.';
}

/**
 * A call that names a watched dotenv file without giving zn the file it would leave there: a copy, move, rename, link, upload or
 * download, or a tool zn does not know. `texts` is what writtenTextsOf found; its `complete` flag says the resulting file is known in
 * full (a whole body, an edit applied to the file, a patch section). Refused whatever the tool is called: there is no read-only
 * exemption by name. An MCP server (or any tool whose name zn cannot tie to the agent's own tool list) may call a writing tool
 * read_file, so a name proves nothing. The agents' own read tools never reach this check: their adapters turn them into a plain
 * read, which only gets the read checks.
 */
function dotenvUnseenWriteDenial(p, texts, opts = {}) {
  const c = classifyPath(p, opts);
  if (!c || c.kind !== 'dotenv') return null;
  if (texts && texts.complete && !texts.unresolved) return null;
  const base = path.basename(String(p));
  return 'Edit ' + base + ' with the file editor tool; copies, moves, renames and tools zn does not know are blocked for .env files. ' +
    'zn cannot see what this call would leave in the file.';
}

/** The refusal for what a shell write to a dotenv file would do: a loader name it sets or mentions, or OPAQUE_WRITE. */
function dotenvShellWriteDenial(verdict, p) {
  if (verdict === OPAQUE_WRITE) return opaqueEnvWriteDenial(p);
  if (verdict === 'LD_DEBUG' || verdict === 'LD_TRACE_LOADED_OBJECTS') return loaderEnvDenial(verdict, p);
  return PRELOAD_WRITE_NAMES.includes(verdict) ? loaderPreloadDenial(verdict, p) : loaderEnvDenial(verdict, p);
}

/** Writes are only blocked for zn's own state and the agents' hook and plugin configuration. */
function writeDenial(p, opts = {}) {
  const c = classifyPath(p, opts);
  if (c && c.kind === 'zn_state') return vaultMessage(opts);
  if (c && c.kind === 'agent_config') return agentConfigDenial(p, c);
  return null;
}

/* ------------------- agent memory and instruction files ------------------- */

/*
 * The files where a coding agent keeps persistent memory and standing instructions. The agent reads them at the
 * start of later sessions, so text written there keeps working after the session, the skill or the tool that wrote it
 * is gone. This is the one list: change it here only. Reads are always allowed; writes ask the user (or are refused
 * in strict mode, see instructionWritesOf in runner.js).
 *
 *   by file name, in any folder: MEMORY.md, SOUL.md, AGENTS.md, CLAUDE.md (also ~/.claude/CLAUDE.md),
 *     CLAUDE.local.md, GEMINI.md, .cursorrules, .windsurfrules
 *   by place: .cursor/rules/* (any depth), .github/copilot-instructions.md,
 *     and the Claude Code memory folders <claude dir>/projects/<project>/memory/*
 */
const INSTRUCTION_FILE_NAMES = ['MEMORY.md', 'SOUL.md', 'AGENTS.md', 'CLAUDE.md', 'CLAUDE.local.md', 'GEMINI.md', '.cursorrules', '.windsurfrules'];
const INSTRUCTION_FILE_RES = [
  /(^|\/)\.cursor\/rules\/[^/]/,
  /(^|\/)\.github\/copilot-instructions\.md$/,
];

/** Whether a resolved absolute path is one of the instruction files above. `ctx` comes from contextOf. */
function isInstructionFile(abs, ctx) {
  const s = keyOf(slash(abs));
  const base = path.basename(s);
  if (INSTRUCTION_FILE_NAMES.some((n) => keyOf(n) === base)) return true;
  if (INSTRUCTION_FILE_RES.some((re) => ci(re).test(s))) return true;
  // <claude dir>/projects/<project>/memory/<file>, for ~/.claude, the project's .claude and CLAUDE_CONFIG_DIR.
  return ctx.agent.dirs.some((d) => s.startsWith(d + '/projects/') && /^[^/]+\/memory\/[^/]/.test(s.slice(d.length + 10)));
}

// On win32 a NEW file written under its 8.3 short name (`AGENTS~1.MD`) cannot be resolved, because it does not exist
// yet. The short name of an instruction file is built from the first six letters of its name (a leading dot is
// dropped: `.cursorrules` is `CURSOR~1`), so a short name with such a start and the same extension is reviewed. A
// short name made from a hash (`COP3F1~1.MD`) shows nothing of the long one, so it is reviewed in a folder that holds
// instruction files (`.github`). Anything else, like `NOTES~1.MD`, stays allowed. This only asks; it never denies more.
const SHORT_INSTRUCTION_NAMES = INSTRUCTION_FILE_NAMES.concat(['copilot-instructions.md']).map((n) => {
  const t = n.replace(/^\.+/, '');
  const dot = t.lastIndexOf('.');
  const base = (dot > 0 ? t.slice(0, dot) : t).replace(/[.\s]/g, '');
  return { base: base.slice(0, 6).toUpperCase(), ext: (dot > 0 ? t.slice(dot + 1) : '').slice(0, 3).toUpperCase() };
});
function isShortInstructionName(abs) {
  if (process.platform !== 'win32') return false;
  const parts = slash(abs).split('/');
  const m = SHORT_NAME_RE.exec(parts[parts.length - 1]);
  if (!m) return false;
  const pre = m[1].toUpperCase();
  const ext = (m[2] || '').toUpperCase();
  if (pre.length >= 4 && SHORT_INSTRUCTION_NAMES.some((n) => n.ext === ext && n.base.startsWith(pre))) return true;
  const parent = (parts[parts.length - 2] || '').toLowerCase();
  const inFolder = parent === '.github' || /^github~[0-9]+$/.test(parent) ||
    (parts.length > 2 && parts[parts.length - 3].toLowerCase() === '.cursor' && parent === 'rules');
  return inFolder && (ext === 'MD' || ext === '');
}

// Folders whose long name an 8.3 short name in the MIDDLE of a path can stand for (`CURSOR~1/rules/x.mdc` is
// .cursor/rules/x.mdc). A short name is its first six letters (a leading dot dropped), `~` and a number, so a folder
// segment that starts like one of these is read as that folder and the path is judged again with the long name, the
// way classifyPath reads a short segment as a pattern for the protected names.
const SHORT_INSTRUCTION_FOLDERS = ['.cursor', '.github', '.claude'];
function isInstructionUnderShortFolder(abs, ctx) {
  if (process.platform !== 'win32') return false;
  const parts = slash(abs).split('/');
  const choices = parts.map((seg, i) => {
    const m = i < parts.length - 1 ? SHORT_NAME_RE.exec(seg) : null;
    if (!m || m[2]) return [seg];
    const pre = m[1].toUpperCase();
    const longs = SHORT_INSTRUCTION_FOLDERS.filter((f) => f.replace(/^\.+/, '').slice(0, 6).toUpperCase() === pre);
    return longs.length ? [seg].concat(longs) : [seg];
  });
  const branching = choices.filter((c) => c.length > 1).length;
  if (branching === 0) return false;
  // More short folders than we expand (2^6 = 64 paths at most): ask rather than drop some of them unread.
  if (branching > 6) return true;
  let combos = [''];
  choices.forEach((c, i) => {
    const next = [];
    for (const base of combos) for (const alt of c) next.push(i ? base + '/' + alt : alt);
    combos = next;
  });
  return combos.some((c) => isInstructionFile(c, ctx));
}

/** Whether a typed path names an instruction file, as typed or where it really leads (links followed). */
function isInstructionPath(p, opts = {}) {
  if (typeof p !== 'string' || !p) return false;
  const ctx = contextOf(opts);
  const expanded = expandEnv(expandHome(p, ctx.home), ctx.env);
  // Windows drops trailing dots and spaces (and a stream suffix) from every name, so `AGENTS.md.` opens AGENTS.md:
  // the same normalization as classifyPath, on the text, so it also holds for a file that does not exist yet.
  expanded.text = stripStreams(expanded.text);
  const abs = path.resolve(ctx.cwd, expanded.text);
  const candidates = new Set([abs, ...targetsOf(abs)]);
  const physical = physicalDotDot(expanded.text, ctx.cwd);
  if (physical) { candidates.add(physical); for (const t of targetsOf(physical)) candidates.add(t); }
  for (const candidate of candidates) {
    if (isInstructionFile(candidate, ctx) || isShortInstructionName(candidate) || isInstructionUnderShortFolder(candidate, ctx)) return true;
  }
  return false;
}

/**
 * null when `p` is not an instruction file, else {file, ask, deny}: the messages for a write to it
 * (ask: the user decides; deny: strict mode).
 */
function instructionWriteNotice(p, opts = {}) {
  if (!isInstructionPath(p, opts)) return null;
  // The name comes from the agent: no control characters, and short, in a message the user reads.
  const shown = String(p).replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
  const file = shown.length > 80 ? shown.slice(0, 79) + '…' : shown;
  return {
    file,
    ask: 'zn: this writes to ' + file + ', which your agent reads as standing instructions in later sessions. Approve only if you asked for this change.',
    deny: 'zn: this writes to ' + file + ', which your agent reads as standing instructions in later sessions, and zn is set to block that. Ask the user to make this change.',
  };
}

// Programs that write the files they are given. cp, mv and the like write only their last argument; sed and perl
// only with an in-place flag; the others any file argument. A redirect target counts for every command.
const INSTRUCTION_WRITERS = new Set(['tee', 'cp', 'mv', 'install', 'rsync', 'ln', 'dd', 'truncate', 'touch', 'sed', 'perl', 'ex', 'ed', 'patch',
  'set-content', 'add-content', 'out-file', 'sc', 'ac', 'ni', 'new-item', 'copy-item', 'move-item', 'copy', 'move', 'ren', 'rename-item']);
const INSTRUCTION_DEST_LAST = new Set(['cp', 'mv', 'install', 'rsync', 'ln', 'copy', 'move', 'copy-item', 'move-item', 'ren', 'rename-item']);
const IN_PLACE_RE = /^(?:-[A-Za-z]*i|--in-place)/;
const INSTRUCTION_CHECKS_MAX = 64;
// A command that names more files than are checked (or runs the check out of budget) cannot be shown to leave the
// instruction files alone, so it gets the same decision as a write to one: ask, and a deny in strict mode.
const TOO_MANY_TARGETS_NOTICE = {
  file: 'too many files',
  ask: 'zn: this command names too many files to check whether it writes to a file your agent reads as standing instructions in later sessions (AGENTS.md, CLAUDE.md...). Approve only if you asked for this change.',
  deny: 'zn: this command names too many files to check whether it writes to a file your agent reads as standing instructions in later sessions (AGENTS.md, CLAUDE.md...), and zn is set to block that. Ask the user to split the command or run it themselves.',
};

// Words that run the next command: the command word is the first one after them (and their options).
// Each maps to the options that take a value.
const INSTRUCTION_WRAPPERS = new Map([
  ['sudo', new Set(['-u', '-g', '-h', '-p', '-C', '-U', '-D', '-R', '-T', '--user', '--group', '--host'])],
  ['doas', new Set(['-u', '-C'])],
  ['env', new Set(['-u', '-C', '-S'])],
  ['xargs', new Set(['-n', '-I', '-L', '-P', '-d', '-E', '-s', '-a'])],
  ['nice', new Set(['-n', '--adjustment'])],
  ['time', new Set(['-f', '-o', '--format', '--output'])],
  ['command', new Set()], ['builtin', new Set()], ['exec', new Set()], ['nohup', new Set()], ['chronic', new Set()],
  ['timeout', new Set(['-k', '-s', '--kill-after', '--signal'])],
  ['stdbuf', new Set(['-i', '-o', '-e', '--input', '--output', '--error'])],
  ['ionice', new Set(['-c', '-n', '-p', '-P', '-u', '--class', '--classdata', '--pid', '--pgid', '--uid'])],
  ['then', new Set()], ['do', new Set()], ['else', new Set()], ['if', new Set()], ['while', new Set()], ['until', new Set()],
  ['!', new Set()], ['{', new Set()],
]);

/** Index in `seg` of the command word of a simple command (after VAR=value, sudo, env, nohup, time, xargs...); -1 if none. */
function commandWordAt(seg, progs) {
  let i = 0;
  while (i < progs.length) {
    if (seg[i].redirectTarget || /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(seg[i].text)) { i++; continue; }
    const takesValue = INSTRUCTION_WRAPPERS.get(progs[i]);
    if (!takesValue) return i;
    const wrapper = progs[i];
    i++;
    while (i < progs.length && seg[i].text.length > 1 && seg[i].text.startsWith('-')) i += takesValue.has(seg[i].text) ? 2 : 1;
    if (wrapper === 'timeout') i++; // its first argument is the duration
  }
  return -1;
}

// Downloaders that write the file named by an output option. The value-taking short options (other than the
// output one) end a cluster such as `-sSo`: what follows them is their value.
const INSTRUCTION_DOWNLOADERS = {
  curl: { long: '--output', short: 'o', valued: 'AbcCdDeEFHKmPQrtTuUwxXyYz' },
  wget: { long: '--output-document', short: 'O', valued: 'abBeFHiIlnoPQtTUwX' },
};

/** The files a `curl` or `wget` command writes with -o/--output or -O/--output-document. */
function downloadTargets(name, rest) {
  const spec = INSTRUCTION_DOWNLOADERS[name];
  const out = [];
  for (let i = 0; i < rest.length; i++) {
    const x = rest[i];
    if (x === spec.long) {
      if (i + 1 < rest.length) out.push(rest[i + 1]);
      i++;
    } else if (x.startsWith(spec.long + '=')) {
      out.push(x.slice(spec.long.length + 1));
    } else if (/^-[A-Za-z]/.test(x)) {
      for (let k = 1; k < x.length; k++) {
        if (x[k] === spec.short) {
          const attached = x.slice(k + 1);
          if (attached) out.push(attached);
          else if (i + 1 < rest.length) { out.push(rest[i + 1]); i++; }
          break;
        }
        if (spec.valued.includes(x[k])) break;
      }
    }
  }
  return out;
}

const PS_COPY_MOVE = new Set(['copy', 'move', 'copy-item', 'move-item']);

/** The value of PowerShell's -Destination (any unambiguous prefix, also -Destination:value), or null. */
function psDestinationOf(rest) {
  for (let i = 0; i < rest.length; i++) {
    const m = /^-des(?:t(?:i(?:n(?:a(?:t(?:i(?:o(?:n)?)?)?)?)?)?)?)?(?::(.*))?$/i.exec(rest[i]);
    if (m) return m[1] ? m[1] : (i + 1 < rest.length ? rest[i + 1] : null);
  }
  return null;
}

/** The target directory named with -t DIR or --target-directory[=]DIR, or null. */
function targetDirectoryOf(rest) {
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '-t' || rest[i] === '--target-directory') return i + 1 < rest.length ? rest[i + 1] : null;
    if (rest[i].startsWith('--target-directory=')) return rest[i].slice('--target-directory='.length);
  }
  return null;
}

/** When `dest` is a directory (named with a trailing separator, forced by -t, or existing now), where each source lands in it. */
function intoDirectory(dest, sources, forced, opts) {
  let isDir = forced || /[\\/]$/.test(dest);
  if (!isDir) {
    try {
      const ctx = contextOf(opts);
      isDir = fs.statSync(path.resolve(ctx.cwd, expandEnv(expandHome(dest, ctx.home), ctx.env).text)).isDirectory();
    } catch (_) { isDir = false; }
  }
  if (!isDir) return [];
  const base = dest.replace(/[\\/]+$/, '');
  const landed = [];
  for (const src of sources) {
    const name = src.replace(/[\\/]+$/, '').split(/[\\/]/).pop();
    if (name && name !== '.' && name !== '..') landed.push(base + '/' + name);
  }
  return landed;
}

/** The files program `name` writes, given the words after it: the files of a downloader's output option, the destination of
 *  cp, mv, ln and the like, the of= of dd, an in-place sed or perl's files, and every other argument of the other writers. */
function programWriteTargets(name, rest, opts) {
  if (Object.prototype.hasOwnProperty.call(INSTRUCTION_DOWNLOADERS, name)) return downloadTargets(name, rest);
  const candidates = [];
  if (!INSTRUCTION_WRITERS.has(name)) return candidates;
  const args = rest.filter((x) => x && !x.startsWith('-') && !/^[0-9]*[<>]/.test(x));
  if (name === 'dd') {
    for (const x of rest) if (x.startsWith('of=')) candidates.push(x.slice(3));
  } else if ((name === 'sed' || name === 'perl') && !rest.some((x) => IN_PLACE_RE.test(x))) {
    // These only read their files without an in-place flag.
  } else if (INSTRUCTION_DEST_LAST.has(name)) {
    // Copy-Item -Path a -Destination b: the destination is named, whatever its place.
    const psDest = PS_COPY_MOVE.has(name) ? psDestinationOf(rest) : null;
    const dir = psDest !== null ? null : targetDirectoryOf(rest);
    if (psDest !== null) {
      candidates.push(psDest, ...intoDirectory(psDest, args.filter((x) => x !== psDest), false, opts));
    } else if (dir !== null) {
      // -t DIR: every other argument is a source, written into DIR.
      const at = args.indexOf(dir);
      const sources = args.filter((_, j) => j !== at);
      candidates.push(...intoDirectory(dir, sources, true, opts));
    } else if (args.length > 1) {
      const dest = args[args.length - 1];
      candidates.push(dest, ...intoDirectory(dest, args.slice(0, -1), false, opts));
    }
  } else {
    candidates.push(...args);
  }
  return candidates;
}

/**
 * Whether word `w` of a shell command is a file its program writes with content zn cannot see: a file that cp, mv, ln, rsync,
 * install, dd of=, curl -o or wget -O writes, the files of an in-place sed or perl, and every file word of tee, truncate, patch,
 * ex, ed, Set-Content, Add-Content, Out-File, New-Item and their aliases (also -Path:file). touch only changes times.
 */
function writtenByProgram(w, text, readings, opts) {
  const reading = readings.find((r) => r.includes(w));
  if (!reading) {
    const name = programName(w.head);
    return INSTRUCTION_WRITERS.has(name) && name !== 'touch';
  }
  const seg = reading.filter((x) => x.seq === w.seq);
  const progs = seg.map((x) => x.text.split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, ''));
  const at = commandWordAt(seg, progs);
  if (at < 0 || seg[at] === w) return false;
  const name = progs[at];
  if (name === 'touch') return false;
  const rest = seg.slice(at + 1).map((x) => x.text);
  // Writers that write every file they name: each dotenv word of theirs counts, whatever its form.
  if (INSTRUCTION_WRITERS.has(name) && name !== 'dd' && name !== 'sed' && name !== 'perl' && !INSTRUCTION_DEST_LAST.has(name)) return true;
  const targets = programWriteTargets(name, rest, opts);
  return targets.includes(text) || targets.includes(w.text);
}

/** The first notice for a word of a shell command that writes an instruction file; null when none does. */
function instructionWriteInWords(readings, opts) {
  const seen = new Set();
  for (const reading of readings) {
    const segments = new Map();
    for (const w of reading) {
      if (!segments.has(w.seq)) segments.set(w.seq, []);
      segments.get(w.seq).push(w);
    }
    for (const seg of segments.values()) {
      const progs = seg.map((x) => x.text.split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, ''));
      const at = commandWordAt(seg, progs);
      const candidates = [];
      for (const w of seg) if (w.redirectTarget) candidates.push(w.text);
      if (at >= 0) candidates.push(...programWriteTargets(progs[at], seg.slice(at + 1).map((x) => x.text), opts));
      for (const text of candidates) {
        if (!text || seen.has(text)) continue;
        seen.add(text);
        if (seen.size > INSTRUCTION_CHECKS_MAX || overBudget(opts.budget, 1)) return TOO_MANY_TARGETS_NOTICE;
        const n = instructionWriteNotice(text, opts);
        if (n) return n;
      }
    }
  }
  return null;
}

// The files an `apply_patch` sent as a shell command adds or updates (or moves to).
const SHELL_PATCH_WRITES_RE = /^\*\*\* (?:(?:Add|Update) File|Move to): (.+)$/gm;
function instructionWriteInPatch(cmd, opts) {
  if (!/^\s*apply_patch\b/.test(String(cmd))) return null;
  let seen = 0;
  for (const m of String(cmd).matchAll(SHELL_PATCH_WRITES_RE)) {
    if (++seen > SHELL_PATCH_FILES_NAMED) break;
    const n = instructionWriteNotice(m[1].trim(), opts);
    if (n) return n;
  }
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
    // `>|` is one redirection (it overrides noclobber), not a `>` followed by a pipe.
    if (ch === '|' && s[i - 1] === '>' && cur && cur.end === i && !cur.text.endsWith('>>')) { pushChar(ch, i); continue; }
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

// `>` or `>>` as a word of its own, with an optional fd or `*` (PowerShell: all streams) in front.
const REDIRECT_OP_WORD_RE = /^(?:[0-9]*|\*)(?:>\||>>?)$/;
// The same operator glued to the end of a word (`x>` in `echo x> file`), read on the raw source so a quoted ">" is not one.
const GLUED_END_RE = /(?<![\\<>&])(?:>\||>>?)$/;
// The read-write operator `<>` at the end of a word (`1<>`, `{fd}<>`, `x<>`): the next word is the file it opens for writing.
const RW_END_RE = /<>$/;
// What can stand in front of a redirect operator without being a word of its own: a file descriptor, `*` (PowerShell:
// all streams) or a bash `{name}` descriptor.
const REDIRECT_FD_PREFIX_RE = /^(?:[0-9]*|\*|\{[A-Za-z_][A-Za-z0-9_]*\})$/;
/**
 * `x>file`, `x>>file`, `"x">file`: find the first `>` of a raw word that is neither quoted nor escaped, in one pass
 * over the word. Returns {at, len} (the operator) or null when the word holds no such operator, has `<` before it,
 * or the operator is a descriptor copy (`>&2`) or the end of the word (a redirect whose target is the next word).
 */
function gluedRedirect(raw) {
  let quote = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote === "'") { if (ch === "'") quote = null; continue; }
    if (ch === '\\') { i++; continue; }
    if (quote === '"') { if (ch === '"') quote = null; continue; }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === '<') return null;
    if (ch !== '>') continue;
    const len = raw[i + 1] === '>' || raw[i + 1] === '|' ? 2 : 1; // `>|` overrides noclobber
    const next = raw[i + len];
    if (i === 0 || next === undefined || next === '&' || next === '>') return null;
    return { at: i, len };
  }
  return null;
}
// The text of a piece of a raw word, quotes removed the way the scanner removes them.
function dequoteFragment(frag, posix) {
  const w = scanFirstCommand(frag, posix).words;
  return w.length ? w[0].text : '';
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
      const prevRaw = k > 0 ? rest.slice(scan.words[k - 1].start, scan.words[k - 1].end) : '';
      const raw = rest.slice(w.start, w.end);
      // The operator can sit at the end of the word before (`echo x> file`, `echo x>> file`) or inside the word
      // (`echo x>file`): a redirect whatever the program, bash, cmd.exe or PowerShell.
      const glued = gluedRedirect(raw);
      const prefixRaw = glued ? raw.slice(0, glued.at) : '';
      // A descriptor in front (`2>x`, `{fd}>x`) belongs to the operator; any other prefix is an argument of its own.
      const gluedOp = glued !== null && !REDIRECT_FD_PREFIX_RE.test(prefixRaw);
      // `<>` opens a file for reading AND writing (`1<> .env`, `{fd}<>.env`, `x<>.env`): it is a write redirection.
      const rwAt = glued === null ? raw.indexOf('<>') : -1;
      const afterOp = REDIRECT_OP_WORD_RE.test(prev) || GLUED_END_RE.test(prevRaw) || RW_END_RE.test(prevRaw);
      const isRedirTarget = afterOp || /^(?:[0-9]*|\*)(?:>\||>>?)./.test(w.text) || glued !== null || rwAt >= 0;
      let t = w.text;
      let targetRaw = raw;
      if (rwAt >= 0) {
        const before = raw.slice(0, rwAt);
        if (before && !REDIRECT_FD_PREFIX_RE.test(before)) out.push({ text: dequoteFragment(before, posix), redirectTarget: afterOp, head, seq: guard, sub, gitArgs, git: gi >= 0 });
        targetRaw = raw.slice(rwAt + 2);
        t = dequoteFragment(targetRaw, posix);
      }
      if (glued) {
        targetRaw = raw.slice(glued.at + glued.len);
        t = dequoteFragment(targetRaw, posix);
        // `cat ~/.ssh/id_rsa>x` reads the file before it writes x: the part before the operator is checked as a word.
        if (gluedOp) out.push({ text: dequoteFragment(prefixRaw, posix), redirectTarget: afterOp, head, seq: guard, sub, gitArgs, git: gi >= 0 });
      }
      // Input redirections: <file, 0<file, <>file (read and write), {fd}<file.
      t = t.replace(/^(?:[0-9]*|\*)(?:>\||>>?)/, '').replace(/^(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?<>?/, '');
      // A drive path after a redirect (cmd.exe and PowerShell write them with "\"): the backslashes are separators,
      // not shell escapes, so the target is read as typed (C:\Users\me\.claude\*.json keeps its "\*").
      if (isRedirTarget) {
        const typed = targetRaw.replace(/^(?:[0-9]*|\*)(?:>\||>>?)/, '');
        if (/^[A-Za-z]:\\/.test(typed) && !/['"]/.test(typed)) t = typed;
      }
      out.push({ text: t, redirectTarget: isRedirTarget, head, seq: guard, sub, gitArgs, git: gi >= 0, opAfter: scan.operator });
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
// What a command that names a watched dotenv file may be, apart from READ_ONLY_CMDS: metadata-only commands and read-only git
// subcommands. Any other program that names the file (python3 -c, node -e, perl, awk, sed w, curl -o, iwr -OutFile, an unknown tool)
// is refused: zn cannot see whether it writes the file. less is not here (it can run commands).
// Deleting a file, changing folder and printing a name write no content into it. A shell that runs code (sh -c, bash -lc, powershell
// -Command) is judged by that code, which is checked on its own (shellCodesOf); `join-path` words are the same words with a folder added.
const DOTENV_METADATA_CMDS = new Set(['touch', 'test', '[', '[[', 'rm', 'rmdir', 'del', 'erase', 'remove-item', 'cd', 'pushd', 'popd', 'chdir',
  'set-location', 'sl', 'write-output', 'write-host', 'join-path',
  // Commands that only print: they come up inside $( ) in a command that reads the file.
  'date', 'true', 'false', 'whoami', 'hostname', 'uname', 'id', 'basename', 'dirname', 'printf', 'seq', 'expr', 'realpath', 'readlink']);
const SHELL_HEADS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'powershell', 'pwsh', 'cmd']);
// Programs whose --env-file option only reads the file it names, and the dotenv runners whose -e / -f / --env-file option does.
// Only the option's value counts as read; the program as a whole is judged as before (node -e can still write .env).
const ENV_FILE_OPTION_PROGRAMS = new Set(['node', 'nodejs', 'bun', 'deno', 'docker', 'podman', 'docker-compose', 'podman-compose']);
const DOTENV_RUNNERS = new Set(['dotenv', 'dotenv-cli', 'dotenvx']);
// A word that is one plain name: no quote, expansion, bracket or separator that could hide more than a file name.
const PLAIN_NAME_RE = /^[^\s'"`$(){};|&<>]+$/;
// git steps that read, or that only change the index or the history (add, commit). checkout, restore, reset and stash are not here:
// they write stored content into the file in the worktree, which zn cannot see.
const GIT_READ_SUBS = new Set(['status', 'diff', 'log', 'show', 'ls-files', 'check-ignore', 'blame', 'rev-parse',
  'add', 'commit']);
function dotenvReadOnlyWord(w, shellChecked) {
  // source and . are not here: they run the file as shell code, which can write the file itself.
  if (READ_ONLY_CMDS.has(w.head) || DOTENV_METADATA_CMDS.has(w.head)) return true;
  if (shellChecked && SHELL_HEADS.has(w.head)) return true;
  if (w.head !== 'git') return false;
  const args = w.gitArgs || [];
  if (args.some((x) => /^--output(=|$)/.test(x))) return false;
  if (GIT_READ_SUBS.has(w.sub)) return true;
  // git rm --cached .env only changes the index.
  return w.sub === 'rm' && args.includes('--cached');
}
/**
 * The words of a command that are the value of an env-file option: --env-file X or --env-file=X of node, bun, deno, docker or podman,
 * and -e / -f / --env-file X (or =X) of dotenv, dotenv-cli or dotenvx, before a `--`. Only a plain name that classifies as a watched
 * dotenv file counts. Returns a Map from the word to the name it reads.
 */
function envFileValueWords(words, opts) {
  const out = new Map();
  const isDotenvName = (t) => PLAIN_NAME_RE.test(t) && (() => { const c = classifyWord(t, opts); return !!c && c.kind === 'dotenv'; })();
  let seq = null;
  let runner = false;
  let ended = false;
  let envProg = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (w.seq !== seq) { seq = w.seq; runner = false; ended = false; envProg = ENV_FILE_OPTION_PROGRAMS.has(programName(w.head)); }
    if (w.head === '' || w.redirectTarget) continue;
    const t = w.text;
    // The words hold each reading of the command in turn; a reading starts again at the program word.
    if (programName(t) === programName(w.head)) { runner = false; ended = false; }
    if (t === '--') { ended = true; continue; }
    if (ended) continue;
    if (DOTENV_RUNNERS.has(programName(t))) { runner = true; continue; }
    const next = words[i + 1];
    const nextValue = () => next && next.seq === w.seq && !next.redirectTarget && next.head !== '' && isDotenvName(next.text);
    const glued = envProg ? /^--env-file=(.+)$/.exec(t) : runner ? /^(?:-e|-f|--env-file)=(.+)$/.exec(t) : null;
    if (glued && isDotenvName(glued[1])) { out.set(w, glued[1]); continue; }
    const opt = (envProg && t === '--env-file') || (runner && (t === '-e' || t === '-f' || t === '--env-file'));
    if (opt && nextValue()) { out.set(next, next.text); i++; }
  }
  return out;
}

const AGENT_CONFIG_MENTION_RE = /\.claude\/settings|\.codex\/|\.cursor\/hooks|\.gemini\/config\/hooks|\.copilot\/(?:hooks|settings|config)|\.github\/hooks|\.github\/copilot\/settings|github-copilot\/policy\.d|\.gemini\/settings|gemini-cli\/settings|\.zcode\/(?:cli\/)?config|antigravity-cli\/settings|opencode\.jsonc?|\.opencode\/|\.config\/opencode\//i;
// .agents is shared with other tools (Codex reads .agents/skills; Antigravity keeps rules and workflows there), so
// only the folder itself, its hooks file, globs or ".." inside it, and changing into it count as touching the hook.
// Written as three linear pieces (the one pattern it replaces retried the whole rest of a word at every `.agents/` in it):
// the folder named on its own, a start `.agents/`, and what may follow a start (names, then hooks.json, `..` or a glob).
const AGENTS_BARE_RE = /(?<=^|[\/\s"'=:])\.agents\/*(?=$|[\s"';&|)])/i;
const AGENTS_START_RE = /(?<=^|[\/\s"'=:])\.agents\//gi;
const AGENTS_TAIL_RE = /^(?:[^\s"'\/]*\/)*(?:hooks\.json|\.\.(?=$|[\/\s"';&|)])|[^\s"'\/]*[*?[{$`])/i;
const AGENTS_BREAK_RE = /[\s"']/g;
/** Same answer as the single pattern the three above replace, in time linear in the word. */
function agentsDirRiskyRe(t) {
  if (AGENTS_BARE_RE.test(t)) return true;
  AGENTS_START_RE.lastIndex = 0;
  let m;
  while ((m = AGENTS_START_RE.exec(t)) !== null) {
    const from = m.index + m[0].length;
    if (AGENTS_TAIL_RE.test(t.slice(from))) return true;
    // The tail of a start covers the rest of its word, so later starts in the same word cannot do better: go on after it.
    AGENTS_BREAK_RE.lastIndex = from;
    const brk = AGENTS_BREAK_RE.exec(t);
    if (!brk) break;
    AGENTS_START_RE.lastIndex = brk.index;
  }
  return false;
}
const AGENTS_DIR_ANY_RE = /(?:^|[\/\s"'=:])\.agents(?:\/|$|[\s"';&|)])/i;
// Commands that make a link: through a link, ".." no longer means what it says, so any mention of .agents counts.
const LINK_CMDS = new Set(['ln', 'mklink']);

const AGENTS_SEG_RE = /(^|\/)\.agents(\/|$)/i;
// A word like ag/../hooks.json: ".." after a name, which a link can turn into a path outside the folder it seems to be in.
const MID_DOTDOT_RE = /[^\/\\\s]\/\.\.(?:[\/\\]|$)/;
const AGENTS_PROTECTED = 'zn: this command would change agent hook or plugin settings, which is protected. Ask the user to make this change.';

/** Whether a writing word touches the .agents hook folder (see the notes above); w.link comes from markLinkWords. */
function agentsDirRisky(t, w) {
  // The first pattern is quadratic on long input: a word longer than a path can be is refused unchecked.
  if (t.length > 4096) return /\.agents/i.test(t);
  if (agentsDirRiskyRe(t)) return true;
  if (!AGENTS_DIR_ANY_RE.test(t)) return false;
  return CD_CMDS.has(bareHead(w.head).toLowerCase()) || w.link === true;
}

const LINK_WRAPPERS = new Set(['env', 'sudo', 'doas', 'command', 'exec', 'nohup', 'time', 'busybox', 'xargs', 'nice', 'builtin', 'stdbuf', 'timeout', '!', '{', 'then', 'do', 'else']);

/**
 * Marks (w.link) every word of a simple command that makes a link: ln, mklink, cp -s, New-Item with a link type,
 * after env, sudo, command, exec, nohup, time, busybox or xargs, with a path in front of the name or quotes in it.
 * The options are read only from that command's own words. A link made some other way (an interpreter) is not seen here;
 * a link that already exists is followed instead (physicalDotDot, cdBasesOf).
 */

/*
 * The curl and @file checks live in curl-files.js, loaded on the first command that can need them. They only act on a word
 * that names curl (programName lower-cases it, so a case-insensitive match is a superset), on a command with so many words
 * that the program of a group cannot be told (programOfGroup gives up after 64), or on a word atFileWords can read
 * something from.
 */
let curlFilesApi = null;
function curlFilesOf() {
  if (!curlFilesApi) {
    curlFilesApi = require('./curl-files')({ ASSIGNMENT_RE, CD_CMDS, DIR_STACK_RE, GIT_WRAPPERS, REDIRECT_OP_WORD_RE, bareHead, expandHome, programName, skipWrapper, slash });
  }
  return curlFilesApi;
}
const CURL_WORD_RE = /curl/i;
const CURL_GROUP_WORDS = 64;
function mayRunCurl(words) {
  return words.length >= CURL_GROUP_WORDS || words.some((w) => CURL_WORD_RE.test(String(w.text)));
}
// An upload option, an @file or < value, a variable or assignment, a {a,b} list, a space, a backslash escape: what
// atFileWords reads a file name out of. A word with none of them, and none of curl's marks, adds nothing.
const AT_FILE_WORD_RE = /[=$@<{\\\s]|upload-file/;
function mayHaveAtFiles(words) {
  return words.some((w) => {
    if (w.curl || w.upload || w.expandOpt) return true;
    const t = String(w.text);
    // -T, the short upload option (a dash and a T), tested with includes so a long word costs one pass each.
    return AT_FILE_WORD_RE.test(t) || (t.includes('T') && t.includes('-'));
  });
}

function markLinkWords(readings) {
  for (const r of readings) {
    let i = 0;
    while (i < r.length) {
      let j = i;
      while (j < r.length && r[j].seq === r[i].seq) j++;
      const clean = r.slice(i, j).map((x) => String(x.text).replace(/['"]/g, '').replace(/^\(+|[;)}]+$/g, ''));
      let k = 0;
      let head = '';
      for (; k < clean.length; k++) {
        const x = clean[k];
        if (!x || x.startsWith('-') || ASSIGNMENT_RE.test(x)) continue;
        const base = path.basename(slash(x)).toLowerCase().replace(/\.exe$/, '');
        if (LINK_WRAPPERS.has(base)) continue;
        head = base;
        break;
      }
      const rest = clean.slice(k + 1);
      const link = LINK_CMDS.has(head) ||
        ((head === 'cp' || head === 'gcp') && rest.some((x) => /^-[A-Za-z]*[sl][A-Za-z]*$/.test(x) || x === '--symbolic-link' || x === '--link')) ||
        ((head === 'new-item' || head === 'ni') && rest.some((x) => /symboliclink|junction|hardlink/i.test(x))) ||
        (head === 'cmd' && rest.some((x) => LINK_CMDS.has(x.toLowerCase())));
      if (link) for (let m = i; m < j; m++) r[m].link = true;
      i = j;
    }
  }
}

const RESERVED_WORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'function', '{', '}', '!', '[[', 'time', 'coproc', 'select', 'eval', 'exec', 'source', '.', 'sudo', 'doas', 'env', 'xargs', 'nohup', 'command', 'builtin', 'export', 'declare', 'local', 'readonly', 'typeset', 'alias', 'set', 'unset', 'let']);
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;   // NAME=value and NAME+=value

/**
 * Commands with named markers. A marker in a command's arguments is never
 * filled in (the value would show in the process list and in command-line
 * logs), so such a command is refused with the way to pass the secret as an
 * environment variable instead. A command the agent already started with
 * `zn run` is left to the broker, which applies the same rule.
 * Returns {ok: true, command} or {ok: false, reason}.
 */
function wrapWithZnRun(cmd, znRunPrefix) {
  const s = String(cmd);
  const named = markers.findNamedMarkers(s);
  if (named.length === 0) return { ok: true, command: s, wrapped: false };
  const scan = scanFirstCommand(s);
  const tail = s.slice(scan.end);
  const guidance = ' Next step: give the program the secret as an environment variable with `' + znCommand('run --secrets NAME -- <command>') + '` ' +
    'and have the program read it from there (for example psql reads PGPASSWORD). For web requests, use the secrets_http_request tool of the zn "secrets" MCP server.';
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
  return { ok: false, reason: 'zn: a secret marker in the arguments of a command is not filled in, because the value would show in the process list and in command-line logs.' + guidance };
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

/**
 * PowerShell counterpart of wrapWithZnRun. A command with named markers is
 * refused, with the way to pass the secret as an environment variable
 * instead; a command already started with `zn run` is left to the broker.
 * opts: {nodePath, runJs, agent} (kept for callers; nothing is rewritten)
 */
function wrapPowerShell(cmd, opts) {
  const s = String(cmd);
  const named = markers.findNamedMarkers(s);
  if (named.length === 0) return { ok: true, command: s, wrapped: false };
  const guidance = ' Next step: give the program the secret as an environment variable with `' + znCommand('run --secrets NAME -- <command>') + '` ' +
    'and have the program read it from there (for example psql reads PGPASSWORD). For web requests, use the secrets_http_request tool of the zn "secrets" MCP server instead.';
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
  return { ok: false, reason: 'zn: a secret marker in the arguments of a command is not filled in, because the value would show in the process list and in command-line logs.' + guidance };
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
const ZN_ADMIN_RE = /(^|[\s;&|(`$'"\\\/])((?:zn|zn-gate(?:@[^\s"'`;&|]+)?|cli\.js))(\.cmd|\.js|\.ps1)?["']?\s+(?:--\s+)?(secret\s+(set|get|rm|remove|import|adopt|approve|allow|reveal|link)|env\s+(shadow|unshadow)|unlock|lock|uninstall|vault\s+(?:reset|purge)|connect|disconnect|hooks\s+(install|uninstall)|init(?![^\n;&|#`$()'"<>\\]{0,512}[ \t]--(?:wrap-mcp|dry-run|revert|shadow)(?=[ \t\n]|$))|stats(?:\s+(?:-{1,2}[^\s-]\S*|\d+))*\s+share\s+on|["']?pins["']?\s+["']?approve|audit\b[^\n;&|]{0,512}?[ \t]--approve)\b/i;

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

/**
 * The command as the shell reads its words: $'...' decoded, quotes and backslashes taken out, a backslash-newline joined (so
 * `zn audit --appr''ove`, `zn "audit" --approve` and `zn a\udit --approve` read as the command they run). Only for recognising
 * zn's own commands; an unbalanced quote leaves the rest as it was.
 */
function dequoteShell(text) {
  const src = /\$['"]/.test(text) ? decodeAnsiC(text) : text;
  let out = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') {
      const nx = src[i + 1];
      if (nx === undefined) break;
      if (nx === '\n') { i++; continue; }
      if (nx === '\r' && src[i + 2] === '\n') { i += 2; continue; }
      out += nx;
      i++;
    } else if (c === "'") {
      const j = src.indexOf("'", i + 1);
      if (j < 0) { out += src.slice(i + 1); break; }
      out += src.slice(i + 1, j);
      i = j;
    } else if (c === '"') {
      let j = i + 1;
      for (; j < src.length && src[j] !== '"'; j++) {
        if (src[j] === '\\' && '"\\$`'.includes(src[j + 1])) j++;
        out += src[j];
      }
      i = j;
    } else {
      out += c;
    }
  }
  return out;
}
// `xargs zn audit` hands zn the --approve it reads from its input, which no text of the command shows.
const XARGS_AUDIT_RE = /(?:^|[\s;&|(`$'"\\/])xargs\b[^\n;&|]*[\s\/\\'"](?:zn|zn-gate(?:@[^\s"'`;&|]+)?|cli\.js)(?:\.cmd|\.js|\.ps1)?["']?\s+(?:--\s+)?audit\b/i;
/*
 * Commands that rewrite zn's hook launchers with the files of the installed zn-gate package. Each launcher runs the hook
 * only while the package's files match the digest it recorded; rewriting it records whatever the package holds now, also
 * files an agent changed. So, like `zn hooks install`, they are the user's to run:
 *  - running the package's launcher refresh (lib/agents/refresh.js, the postinstall step) or its launcher writer
 *    (lib/agents/launcher.js) with Node.js, Bun or Deno, or loading either from inline code (node -e). The path is read
 *    the way the file system would: ./ and ../ segments are resolved, case is ignored, and a cd, pushd or Set-Location
 *    earlier in the same command counts (cd <prefix>/lib/agents && node refresh.js);
 *  - a package manager that installs, updates, rebuilds or links zn-gate (npm i -g zn-gate, npm rebuild -g zn-gate,
 *    yarn global add zn-gate@1.0.0, npm i -g ./zn-gate-1.16.0.tgz, npm --prefix <...>/node_modules/zn-gate run postinstall,
 *    npm explore -g zn-gate -- ...), also after a cd into an installed zn-gate folder. Removing it (npm uninstall -g
 *    zn-gate) stays allowed: it runs no install script, and the launchers then block.
 * Reading the files (cat, grep), other package commands (npm test, npm install lodash, npm ls zn-gate) and text that only
 * names such a command (git commit -m "npm i -g zn-gate") stay allowed. Not seen here: a script file the agent wrote, a
 * cd made in an earlier tool call, and a link or copy of the file under another name (see the threat model). Each check is
 * one pass over the words, so a long command costs linear time.
 */
const REFRESH_HINT_RE = /refresh|launcher/i;
// The file, after normalizePathText: <anything>/lib/agents/refresh.js (or launcher, with .js, .cjs or no extension).
const REFRESH_FILE_RE = /(?:^|\/)lib\/agents\/(?:refresh|launcher)(?:\.c?js)?$/;
const JS_RUNNER_RE = /^(?:.*[\/\\])?(?:node|nodejs|bun|deno)(?:\.exe|\.cmd)?$/i;
const JS_EVAL_RE = /^(?:-e|-p|-pe|--eval|--print)(?:=|$)/;
const CD_WORD_RE = /^(?:cd|pushd|chdir|set-location|sl|push-location)$/i;
const PM_WORD_RE = /^(?:.*[\/\\])?(?:npm|pnpm|yarn|bun|cnpm|volta)(?:-cli\.js|\.cmd|\.ps1|\.exe)?$/i;
const PM_VERBS = new Set(['install', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'isntall', 'add', 'ci', 'clean-install',
  'ic', 'install-clean', 'isntall-clean', 'install-ci-test', 'cit', 'install-test', 'it', 'rebuild', 'rb', 'update', 'up', 'upgrade', 'udpate',
  'link', 'ln', 'explore']);
const PM_LIFECYCLE = new Set(['install', 'preinstall', 'postinstall', 'prepare']);
const PM_RUN_VERBS = new Set(['run', 'run-script', 'rum', 'urn']);
// Words after which the next program name is a command too: wrappers that run the rest (sudo npm ..., npx npm ...,
// xargs node ...) and the shell keywords that start a command (then npm ...).
const CMD_WRAPPERS = new Set(['sudo', 'doas', 'env', 'command', 'builtin', 'exec', 'nice', 'nohup', 'time', 'timeout', 'xargs', 'npx', 'corepack',
  'start-process', 'start', 'call', 'cmd', 'cmd.exe', '/c', 'then', 'do', 'else', '!', '{', 'stdbuf', 'ionice', 'setsid', 'script', 'watch']);
// zn-gate as a package spec or path: zn-gate, zn-gate@1.16.0, x@npm:zn-gate, ./zn-gate-1.16.0.tgz, <prefix>/node_modules/zn-gate.
const ZN_PKG_RE = /(?:^|[=:\/\\@])zn-gate(?:@[^\s\/\\]*|-\d[^\s\/\\]*\.tgz)?[\/\\]*$/i;
// An installed zn-gate folder named anywhere in the command (a cd into it, --prefix, -C).
const ZN_INSTALLED_DIR_RE = /node_modules[\/\\]+zn-gate(?=$|[\/\\\s"'\x60;&|)])/i;
const bareWord = (w) => w.replace(/^(?:\$\(|[("'\x60])+|["'\x60)]+$/g, '');

/* The words of each simple command of the (dequoted) text. */
function simpleCommands(text) {
  return text.split(/[\n;&|]+/).map((p) => p.trim().split(/\s+/).filter(Boolean)).filter((w) => w.length);
}
/* The index of the first word that matches `re` where a command starts: the first word after variable assignments, or any
   word after a wrapper (sudo, env, npx, xargs, then ...). -1 when there is none. */
function refreshProgramAt(words, re) {
  let wrapped = false;
  for (let i = 0; i < words.length; i++) {
    const w = bareWord(words[i]);
    if (re.test(w)) return i;
    if (CMD_WRAPPERS.has(w.toLowerCase())) wrapped = true;
    else if (!wrapped && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) return -1;
  }
  return -1;
}
/* A path as the file system reads it, in lower case with / separators: \ becomes /, repeated slashes and ./ segments go,
   and each ../ removes the segment before it. A relative path is read from `base` (a folder from an earlier cd) when known. */
function normalizePathText(p, base) {
  let s = String(p).replace(/\\/g, '/');
  if (base && !/^(?:\/|[A-Za-z]:\/|~)/.test(s)) s = base + '/' + s;
  const out = [];
  for (const seg of s.split('/')) {
    if (seg === '') { if (!out.length) out.push(''); continue; }
    if (seg === '.') continue;
    if (seg === '..') {
      const top = out[out.length - 1];
      if (out.length && top !== '..' && !(out.length === 1 && (top === '' || /^[A-Za-z]:$/.test(top)))) out.pop();
      else if (!out.length || top === '..') out.push('..');
      continue;
    }
    out.push(seg);
  }
  return out.join('/').toLowerCase();
}
/* The pieces of a word that can be a path: split at quotes, parentheses, commas, semicolons and = (--require=<path>). */
const pathPieces = (w) => w.split(/["'\x60(),;=]+/).filter(Boolean);
const isRefreshFile = (piece, base) => REFRESH_HINT_RE.test(piece) && REFRESH_FILE_RE.test(normalizePathText(piece, base));
/* True when the words after a package manager install, update, rebuild, link or explore a package, or run an install script. */
function pmMutates(rest) {
  let prev = '';
  for (const word of rest) {
    if (word.startsWith('-')) continue;
    const w = bareWord(word).toLowerCase();
    if (PM_VERBS.has(w) || (PM_RUN_VERBS.has(prev) && PM_LIFECYCLE.has(w))) return true;
    prev = w;
  }
  return false;
}
function refreshCommand(text) {
  const parts = simpleCommands(text);
  if (REFRESH_HINT_RE.test(text)) {
    let cwd = null; // the folder of the last cd, pushd or Set-Location in this command; null: the agent's own folder
    let inline = false; // a node -e earlier in the command: its code can span several simple commands
    for (const words of parts) {
      const at = refreshProgramAt(words, JS_RUNNER_RE);
      if (at >= 0) {
        // node [options] <...>/lib/agents/refresh.js, node -r <...>/launcher.js -e 0, node -e "require('./refresh')" after a cd
        for (let j = at + 1; j < words.length; j++) {
          if (JS_EVAL_RE.test(words[j])) inline = true;
          for (const piece of pathPieces(words[j])) if (isRefreshFile(piece, cwd)) return 'hooks refresh';
        }
      } else if (inline) {
        // The rest of inline code after a ; inside it: a require/import of the file.
        for (let j = 0; j < words.length; j++) {
          if (!/\b(?:require|import|from)\b/.test(words[j]) && !(j > 0 && /\b(?:require|import|from)\b/.test(words[j - 1]))) continue;
          for (const piece of pathPieces(words[j])) if (isRefreshFile(piece, cwd)) return 'hooks refresh';
        }
      }
      const c = refreshProgramAt(words, CD_WORD_RE);
      if (c >= 0) {
        const args = words.slice(c + 1).map(bareWord).filter((w) => w && !w.startsWith('-') && w.toLowerCase() !== '/d');
        const target = args[args.length - 1];
        cwd = !target || target === '-' ? null : normalizePathText(target, cwd);
        // A folder name longer than any real path is not followed (it keeps each step of a long chain of cd's short).
        if (cwd && cwd.length > 4096) cwd = null;
      }
    }
  }
  const installedDir = ZN_INSTALLED_DIR_RE.test(text);
  for (const words of parts) {
    const at = refreshProgramAt(words, PM_WORD_RE);
    if (at < 0) continue;
    const rest = words.slice(at + 1);
    if (pmMutates(rest) && (installedDir || rest.some((w) => ZN_PKG_RE.test(bareWord(w))))) return 'zn-gate package';
  }
  return null;
}
function adminCommand(cmd) {
  const text = String(cmd || '');
  for (const t of text.length <= 100 * 1024 ? [text, dequoteShell(text)] : [text]) {
    const m = ZN_ADMIN_RE.exec(t);
    if (m) return /^audit\b/i.test(m[4]) ? 'audit --approve' : m[4].replace(/\s+/g, ' ');
    if (XARGS_AUDIT_RE.test(t)) return 'audit --approve';
  }
  for (const t of text.length <= 100 * 1024 ? [text, dequoteShell(text)] : [text]) {
    const r = refreshCommand(t);
    if (r) return r;
  }
  return npmExecInit(text) ? 'init' : null;
}

// Shell, PowerShell and Monitor commands longer than this are refused before
// any parsing, like the 1 MB limit for MCP calls: checking them could take
// longer than the agent waits for the hook, and a hook that times out lets the
// command run unchecked.
const SHELL_SCAN_CAP = 100 * 1024; // characters
/* The folder named in the vault message: ~/.zn, or the ZN_HOME folder (with ~ for the home folder) when it moves zn's
   folder and is protected, that is, it is not empty, a file system root or a home folder. */
function vaultFolder(opts) {
  const env = opts.env || process.env;
  if (!env.ZN_HOME) return '~/.zn';
  const home = opts.home || os.homedir();
  const zh = path.resolve(env.ZN_HOME);
  const same = (a, b) => keyOf(slash(a)).replace(/\/+$/, '') === keyOf(slash(b)).replace(/\/+$/, '');
  if (same(zh, path.parse(zh).root) || same(zh, home)) return '~/.zn';
  const rel = path.relative(home, zh);
  const shown = rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? '~/' + rel.split(path.sep).join('/') : slash(zh);
  return shown + ' (set by ZN_HOME; ~/.zn is protected too)';
}
function vaultMessage(opts = {}) {
  return 'zn blocked this: ' + vaultFolder(opts) + ' is where zn keeps your secrets, so agents may not read or change it. ' +
    'Next step: to use a secret in a command, run it with `' + znCommand('run --secrets NAME -- <command>', opts) + '` so the program gets the value as an environment variable; ' +
    'for a web request, use the secrets_http_request tool with __ZN_NAME__ where the value goes; to add a secret, ask the user to run `' +
    znCommand('secret set NAME', opts) + '` in their own terminal.';
}
const TOO_LONG_MESSAGE = 'zn: this command is too long for zn to check (over 100 KB), so it was blocked (rule: size:command-too-long). Unchecked, it could read a secret or a protected file. ' +
  'Next step: tell the user; do not resend it in parts. Only the user can run it, in their own terminal.';
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
const KEYCHAIN_LIB_NAME_RE = /(?:cloud-key(?![A-Za-z0-9_-])|vault[\\/]+keychain|zn-gate(?:@[A-Za-z0-9._+-]*){0,6}(?:[\\/]+[0-9][A-Za-z0-9._+-]*)?[\\/]+lib[\\/]+(?:vault[\\/]+)?client(?![A-Za-z0-9_-]))/i;
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
// A name built in the command is the same name: a `+` or `.concat(` between two quoted pieces ('zn-' + 'gate/lib/client'),
// and a `,` between two quoted pieces in path.join('zn-gate', 'lib', 'client') or ['zn-gate', 'lib', 'client'].join('/')
// (read as a separator, and also as nothing for .join('')). Any whitespace, line break, line continuation or escaped quote
// may sit between the pieces, also after the shell decodes \x27. A Bun or Deno cache folder with a version is the same
// module. Each pattern is anchored on a quote, so it runs in linear time.
// Not covered, on purpose: a comment or parentheses between the pieces, `${"..."}` interpolation, a name assembled from
// variables or with String.fromCharCode, a URL-encoded name (%2D; require does not decode it), fullwidth look-alike
// letters (require does not fold them) and Windows 8.3 short names. This is a barrier, not a boundary.
const KEYCHAIN_CONCAT_RE = /\\?['"`][\s\\]*(?:\+|\.concat\()[\s\\]*['"`]/g;
const KEYCHAIN_LIST_RE = /\\?['"`][\s\\]*,[\s\\]*['"`]/g;
const keychainLibName = (t) => {
  const sh = keychainUnescape(t, KEYCHAIN_SH_ESC_RE);
  const joins = [];
  for (const b of sh === t ? [t] : [t, sh]) {
    const c = b.replace(KEYCHAIN_CONCAT_RE, '');
    for (const x of [c.replace(KEYCHAIN_LIST_RE, '/'), c.replace(KEYCHAIN_LIST_RE, '')]) if (x !== t && !joins.includes(x)) joins.push(x);
  }
  const out = [t];
  for (const u of [t, ...joins]) {
    const j = u.replace(KEYCHAIN_SHELL_JOIN_RE, '');
    out.push(keychainUnescape(j), keychainUnescape(j, KEYCHAIN_SH_ESC_RE));
  }
  out.push(...joins);
  return out.some((x) => KEYCHAIN_LIB_NAME_RE.test(x.replace(KEYCHAIN_DOT_RE, '')));
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
  while (i < toks.length && (/^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(toks[i]) || ['env', 'command', 'nohup', 'time'].includes(programBase(toks[i])))) i++;
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

/**
 * A deny message, or null. With `opts.instructionNotice` (an object the caller owns), a command that is allowed but writes
 * an agent memory or instruction file leaves the notice from instructionWriteNotice in `opts.instructionNotice.hit`.
 */
function bashDenial(cmd, opts = {}) {
  const deny = shellPatchMessage(cmd, bashDenialOf(cmd, opts), opts);
  const note = opts.instructionNotice;
  if (!deny && note && !note.hit) note.hit = instructionWriteInPatch(cmd, opts);
  return deny;
}

/* find ROOT ... -delete / -exec ...: a find that deletes, started at the home folder or above it, whose expression names
   zn's vault or an agent's plugin folders or state. The deny message, or null. */
const FIND_PROTECTED_NAME_RE = /^\.?(?:zn|gemini|zcode|claude|codex|cursor|agents)$|^(?:plugins|antigravity-cli|cli|config|installed_plugins\.json|known_marketplaces\.json|config\.json)$/i;
function findDeleteDenial(words, opts) {
  const ctx = opts.ctx || contextOf(opts);
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const cwd = path.resolve(opts.cwd || process.cwd());
  const homes = (ctx.agent && ctx.agent.homes) || [keyOf(slash(path.resolve(home)))];
  const bySeq = new Map();
  for (const w of words) {
    if (!bySeq.has(w.seq)) bySeq.set(w.seq, []);
    bySeq.get(w.seq).push(w);
  }
  for (const ws of bySeq.values()) {
    const texts = ws.map((w) => w.text.replace(/^["']|["']$/g, ''));
    const at = texts.findIndex((x) => /^find(?:\.exe)?$/i.test(path.basename(x)));
    if (at < 0) continue;
    const rest = texts.slice(at + 1);
    if (!rest.some((x) => /^-(?:delete|exec|execdir|ok|okdir)$/.test(x))) continue;
    const named = rest.some((x) => FIND_PROTECTED_NAME_RE.test(x.replace(/[*?[\]]/g, '').replace(/^\//, '')));
    if (!named) continue;
    for (const r of rest) {
      if (r.startsWith('-') || r === '(' || r === '!') break;
      const root = keyOf(slash(path.resolve(cwd, expandEnv(expandHome(r, home), env).text)));
      const rootPrefix = root.endsWith('/') ? root : root + '/';
      if (/[$`]/.test(r) || homes.some((h) => h === root || h.startsWith(rootPrefix))) {
        return 'zn: this find deletes files under ' + r + ', which holds zn\'s vault (~/.zn) or an agent\'s plugins, and the ' +
          'names it matches include them, so it was blocked: an agent may not change how zn and its hooks run. Ask the user to make this change.';
      }
    }
  }
  return null;
}

/* NAME=value words of the command (also after export, set or declare), with ~ and the variables already known
   expanded, as an environment overlay: {NAME: value} or null. A name set twice keeps its first value; the cases a
   later value would matter are covered by the targets check (protectedElsewhere). */
const ASSIGN_WORD_RE = /(?:^|[\s;&|(){}])(?:(?:export|declare|typeset|local|readonly)\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]{0,63})=("[^"]*"|'[^']*'|(?:\$\([^)]*\)|`[^`]*`|[^\s;&|()<>`])*)/g;
function shellAssignments(cmd, opts) {
  const home = opts.home || os.homedir();
  const env = opts.env || process.env;
  const out = {};
  const unknown = new Set();
  let n = 0;
  for (const m of String(cmd).matchAll(ASSIGN_WORD_RE)) {
    if (++n > 64) break;
    const name = m[1];
    // A name set twice may hold either value when it is used: zn does not know which.
    if (name in out || unknown.has(name)) { delete out[name]; unknown.add(name); continue; }
    let v = m[2];
    if (/^(["']).*\1$/s.test(v)) v = v.slice(1, -1);
    // The output of a command, or a variable zn cannot resolve, may be the home folder.
    if (/\$\(|`/.test(v)) { unknown.add(name); continue; }
    v = expandEnv(expandHome(v, home), { ...env, ...out }).text;
    if (/\$\{?[A-Za-z_]|%[A-Za-z_][A-Za-z0-9_]*(?::[^%!\r\n]*)?%|![A-Za-z_][A-Za-z0-9_]*(?::[^%!\r\n]*)?!/.test(v)) { unknown.add(name); continue; }
    out[name] = v;
  }
  return { env: Object.keys(out).length ? out : null, unknown };
}

function bashDenialOf(cmd, opts = {}) {
  if (String(cmd || '').length > SHELL_SCAN_CAP) return TOO_LONG_MESSAGE;
  const admin = adminCommand(cmd);
  if (admin) return adminDenial(admin, opts, cmd);
  if (keychainQuery(cmd, opts.env || process.env)) return KEYCHAIN_MESSAGE;
  // $PWD is the folder the command runs in (not the hook's own); $OLDPWD is not known.
  if (!opts.pwdSet) {
    const env0 = { ...(opts.env || process.env), PWD: path.resolve(opts.cwd || process.cwd()) };
    delete env0.OLDPWD;
    opts = { ...opts, env: env0, pwdSet: true };
  }
  // Variables the command sets itself (X=$HOME; rm -rf $X/.zn, export D=~/.zn) are expanded like the environment's.
  const assigned = shellAssignments(cmd, opts);
  if (assigned.env || assigned.unknown.size) {
    const env = { ...(opts.env || process.env), ...(assigned.env || {}) };
    for (const name of assigned.unknown) delete env[name];
    opts = { ...opts, env, unknownVars: assigned.unknown };
  }
  // The context (home, project, agent directories) is built once per command.
  opts = { ...opts, ctx: contextOf(opts) };
  // The code of a shell inside the command (sh -c "...") is checked as a command of its own, with the same budget.
  const depth = opts.depth || 0;
  if (!depth || !opts.budget) opts.budget = { until: Date.now() + CHECK_BUDGET_MS, disk: CHECK_BUDGET_DISK };
  // The bodies of the here-documents read as data are data, not command-line words, and are dropped first.
  const text = stripHeredocs(cmd, opts.budget);
  // Destructive shell commands (see lib/destructive.js). The runner passes the rules from the user's settings; with no
  // list, the two default rules apply. The bodies of data here-documents are not shell code and are not read.
  {
    const rules = Array.isArray(opts.destructiveRules) ? opts.destructiveRules : require('./../destructive').DEFAULT_RULES;
    if (rules.length) {
      // Loaded only now, so a hook with the check off does not pay for it.
      const destructiveDeny = require('../destructive').denial(text, rules);
      if (destructiveDeny) return destructiveDeny;
    }
  }
  // The command is read three times: a backslash before a letter is a Windows
  // path separator or a bash escape, and a PowerShell backtick is an escape too.
  // A word protected in any reading is refused.
  const readings = [allWords(text, false), allWords(text, true), allWords(text.replace(/`(.)/gs, '$1'), false)];
  // Bash $'...' quoting spells characters as escapes ($'\x2eenv' is .env), and $"..." is a plain "...":
  // a fourth reading with them decoded.
  if (/\$['"]/.test(text)) readings.push(allWords(decodeAnsiC(text), true));
  // And with the expansions that leave nothing (or a fixed word) taken out, the cmd variable units taken out, and cmd.exe's carets removed
  // after that (cmd expands % before it reads carets). The first two do not depend on the environment the hook sees.
  {
    const variants = new Set([text]);
    const add = (t) => { variants.add(t); };
    add(dropEmptyExpansions(text, opts.env || process.env));
    if (/[$`]/.test(text)) { add(stripExpansions(text, false)); add(stripExpansions(text, true)); }
    // A case pattern inside $( ) can end the unit early in the readings above: fallback readings take each $( case ... up to each `esac )` after it (16 and 16 at most).
    if (/\bcase\b/.test(text)) {
      const opens = [...text.matchAll(/\$\(\s*case\s/g)].slice(0, 16);
      for (const o of opens) {
        const tail = /\besac\s*\)/g;
        tail.lastIndex = o.index + o[0].length;
        let m;
        let n = 0;
        while ((m = tail.exec(text)) !== null && n++ < 16) add(text.slice(0, o.index) + text.slice(m.index + m[0].length));
      }
    }
    if (/[%!]/.test(text) && cmdContext(text)) for (const v of [...variants]) { add(stripCmdVars(v)); add(stripCmdVarsPerCommand(v)); add(stripCmdVarsNarrow(v)); }
    // With delayed expansion on, cmd removes a ! that has no partner (type .e!nv opens .env), so a reading without any ! is judged too.
    const delayed = text.indexOf('!') >= 0 && DELAYED_EXPANSION_RE.test(text) && cmdContext(text);
    if (delayed) for (const v of [...variants]) add(v.replace(/!/g, ''));
    if (/[$`]/.test(text) && /\$\(|`/.test(text)) add(substitutionOutputs(text));
    for (const v of [...variants]) if (v !== text) readings.push(allWords(v, false), allWords(v, true));
    if (/[$`%!]/.test(text)) {
      // Every expansion read as any text: refused when a path segment could be a protected name.
      const wild = wildText(text);
      if (wild !== text) {
        const wilds = [wild];
        if (cmdCaretsApply(wild)) wilds.push(dropCmdCarets(wild.replace(/(\/[ck]\s+)"([\s\S]*)"(\s*)$/i, '$1$2$3')));
        for (const w of wilds) {
          for (const r of [allWords(w, false), allWords(w, true)]) {
            if (r.truncated) return TOO_MANY_MESSAGE;
            for (const x of r) {
              if (typeof x.text === 'string' && WILD_ANY_RE.test(x.text) && !x.redirectTarget && wildWordProtected(x.text)) {
                return WILD_MESSAGE(x.text.replace(/[\u0001\u0002]/g, '*'));
              }
            }
          }
        }
      }
    }
    for (const v of [...variants]) {
      if (!cmdCaretsApply(v)) continue;
      const c = dropCmdCarets(v.replace(/(\/[ck]\s+)"([\s\S]*)"(\s*)$/i, '$1$2$3'));
      readings.push(allWords(c, false), allWords(c, true));
    }
  }
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
  // A program that is not read-only (awk 'BEGIN{print 1 > ".env"}', sed -n 'w .env') can name a dotenv file inside its own program text: its
  // words are split too.
  const envFileValues = envFileValueWords(words, opts);
  opts.envFileValues = envFileValues;
  if (/\$\(|`/.test(text) || words.some((w) => CODE_CMDS_RE.test(bareHead(w.head))) ||
      (/\.env/i.test(text) && words.some((w) => w.head !== '' && !envFileValues.has(w) && !dotenvReadOnlyWord(w, codes.size > 0)))) {
    const split = [];
    // A plain word already judged read-only on its own (cat .env, source .env, --env-file=.env) is not judged again here: one split
    // token per such word is set aside. A name that also appears in program text (node -e "...'.env'...") is still split and judged.
    const SPLIT_RE = /[\s'"`$(){};|&<>=,]+/;
    // Only the first reading is counted (the others repeat the same words), and nothing is set aside when a name printed by one
    // program can reach another (a pipe, $( ), xargs, find -exec, read, a loop): echo .env | xargs cp x {} writes .env.
    const accounted = new Map();
    const firstReading = Array.isArray(readings[0]) ? readings[0] : words;
    const namesCanFlow = /[|`]|\$\(|[<>]\(|<<<|(?:^|[\s;&(])(?:xargs|parallel|read|while|for|until|select)(?=$|[\s;&)])|\s-exec(?:dir)?\b|\s-ok\b/.test(text);
    // git checkout, restore, reset, stash and switch write stored content into the worktree without naming the file (git reset
    // --hard && cat .env): nothing is set aside then either.
    const gitWritesWorktree = words.some((w) => w.git && /^(?:checkout|restore|reset|stash|switch)$/.test(String(w.sub || '')));
    for (const w of namesCanFlow || gitWritesWorktree ? [] : firstReading) {
      if (w.head === '' || w.redirectTarget || !PLAIN_NAME_RE.test(w.text)) continue;
      if (!envFileValues.has(w) && !dotenvReadOnlyWord(w, codes.size > 0)) continue;
      for (const t of w.text.split(SPLIT_RE)) if (t) accounted.set(t, (accounted.get(t) || 0) + 1);
    }
    for (const t of text.split(SPLIT_RE)) {
      if (!t) continue;
      const n = accounted.get(t);
      if (n) { accounted.set(t, n - 1); continue; }
      split.push({ text: t, redirectTarget: false, head: '', seq: 0 });
    }
    words.push(...split);
    readings.push(split);
  }
  {
    const findDeny = findDeleteDenial(readings[0], opts);
    if (findDeny) return findDeny;
  }
  {
    const gpgDeny = gpgSecretExportDenial(words, text);
    if (gpgDeny) return gpgDeny;
  }
  // Where a relative .env path may be read from once the command has changed directory (cd app && cat .env).
  // Each reading is followed on its own, so a cd counts once.
  opts.cdBases = cdBasesOf(readings, opts);
  opts.elsewhere = new Map();
  markLinkWords(readings);
  if (mayRunCurl(words)) {
    const curlFiles = curlFilesOf();
    curlFiles.markCurlWords(readings, opts, text);
    if (words.some((x) => x.curlConfigUnreadable)) return curlFiles.CURL_CONFIG_UNREADABLE_MESSAGE;
    if (words.some((x) => x.curlConfigExpansionWrite)) return curlFiles.CURL_CONFIG_EXPANSION_WRITE_MESSAGE;
  }
  // The content of a curl configuration file zn could read (-K file, ~/.curlrc) is read like a word of the command:
  // its upload-file, -T, data @file and form lines name files that are sent.
  for (const x of words.slice()) {
    for (const c of x.curlConfigContents || []) {
      words.push({ text: c.content, head: 'curl', redirectTarget: false, seq: x.seq, curl: true, configText: true });
      for (const it of c.items) {
        words.push({
          text: it.value, head: 'curl', redirectTarget: false, seq: x.seq, curl: true, configText: true,
          upload: it.name === 'upload-file', urlencode: curlFilesOf().CURL_NAME_AT_FILE_OPTS.has('--' + it.name),
        });
      }
    }
  }
  {
    // After a cd, $PWD is wherever the cd led: left as written, the path rules follow it there.
    const atEnv = { ...(opts.env || process.env) };
    if (opts.cdBases && opts.cdBases.moved) delete atEnv.PWD;
    const atWords = mayHaveAtFiles(words) ? curlFilesOf().atFileWords(words, atEnv) : [];
    if (atWords === null) return curlFilesOf().GLOB_TOO_LARGE_MESSAGE;
    if (atWords.refuse) return atWords.refuse;
    words.push(...atWords);
  }
  // ~1, ~+2, ~-1 (directory-stack entries other than the top): zn does not know which folder they are, so each is read
  // in every folder the command may be in (the working folder and every place a cd or pushd leads to).
  for (const x of words.slice()) {
    if (String(x.text).charCodeAt(0) !== 126) continue;
    const m = /^~[+-]?[1-9]\d*(?=$|[\\/])/.exec(String(x.text));
    if (!m) continue;
    const rest = String(x.text).slice(m[0].length).replace(/^[\\/]+/, '');
    const dirs = new Set([path.resolve(opts.cwd || process.cwd()), ...((opts.cdBases && opts.cdBases.dirs) || []).map((d) => path.resolve(d))]);
    for (const d of dirs) words.push({ text: path.join(d, rest), head: x.head, redirectTarget: x.redirectTarget, seq: x.seq });
  }
  const mentionsAgents = /\.agents/i.test(text);
  const makesLink = words.some((x) => x.link === true);
  if (overBudget(opts.budget, 0)) return TOO_SLOW_MESSAGE;
  opts.cmdText = text;
  // A word is classified once per command: each classification resolves the path on disk, and a long command
  // often repeats the same words.
  const classified = new Map();
  // And so is its verdict, which may read the file (a .env, a .pem).
  const denied = new Map();
  // And whether a write target may still name ~/.zn or a plugin folder (protectedElsewhere).
  const elsewhereProt = new Map();
  // A word with * ? or [ can match a secret file; the message names a literal file when the command has one too.
  // The command is refused either way, so after a glob only a few more words are resolved on disk to find that file.
  const GLOB_NAME_LOOKAHEAD = 32;
  let globDeny = null;
  let afterGlob = 0;
  // A <rev>:<path> word is read as a git object in any command that runs git (echo HEAD:.env | xargs git show).
  const anyGit = words.some((x) => x.git || x.text === 'git' || x.text.endsWith('/git'));
  const listed = psListWords(words, opts, cmd);
  let dotenvWrite; // the verdict of shellDotenvWrite on this command, computed once
  // Whether every program of the command is a read-only or metadata-only one (see dotenvReadOnlyWord); the words with no program of
  // their own (the text inside quotes or $( ) that is split into words) are judged by this.
  const onlyReadOnly = words.every((x) => x.head === '' || (opts.envFileValues && opts.envFileValues.has(x)) || dotenvReadOnlyWord(x, codes.size > 0));
  // More distinct joined paths than zn judges (each adds two entries, backslash and slash forms, so 32 paths fill the 64-entry cap),
  // or a joined path too long to judge: refused, not checked in part.
  if (listed.over) return TOO_SLOW_MESSAGE;
  for (const w of withEqualsReadings(listed)) {
    // --flag=value carries a path too (--kubeconfig=~/.kube/config).
    let text = w.text;
    if (w.atFile) {
      // A file named by @file and its kin (atFileWords): classified as it is.
    } else if (text.startsWith('-')) {
      const eq = text.indexOf('=');
      // git log -L<range>:<file> names a file after the colon.
      const lineRange = w.git ? /^-L[^:]*:(.+)$/.exec(text) : null;
      // curl -d@.env, -sd@.env, -Ff=@.env: the value is glued to the option letter.
      const glued = w.curl && eq < 0 && !text.startsWith('--') ? /^-[A-Za-z0-9#:]*?[dFTH](.+)$/.exec(text) : null;
      // PowerShell binds a value with a colon (gc -Path:.env, -LiteralPath:.env, -Lit:.env).
      const psValue = w.git ? null : PS_COLON_PARAM_RE.exec(text);
      if (lineRange) text = lineRange[1];
      else if (glued) text = glued[1];
      else if (psValue) text = psValue[1];
      else if (eq < 0) continue;
      else text = text.slice(eq + 1);
    } else if (NAME_VALUE_RE.test(text)) {
      // name=value carries a path too (dd if=.env, ENV_FILE=.env).
      text = text.slice(text.indexOf('=') + 1);
    }
    // curl -d @.env, --json @.env, -F f=@.env, -F f=<.env: the file is sent as the body of the request.
    if (w.curl && text && !w.atFile) {
      const file = curlFilesOf().curlFileOf(text, w.urlencode === true);
      if (file) text = file;
    }
    if (!text) continue;
    // A git pathspec with magic names the path after it.
    if (anyGit && text.charCodeAt(0) === 58) text = text.replace(PATHSPEC_MAGIC_RE, '') || text;
    const writing = !READ_ONLY_CMDS.has(w.head);
    // After a cd that leads, through a link, into .agents, a writing command works inside the hook folder.
    if (writing && opts.cdBases.agentsDir && !CD_CMDS.has(bareHead(w.head).toLowerCase())) return AGENTS_PROTECTED;
    if (!classified.has(text)) {
      if (globDeny && ++afterGlob > GLOB_NAME_LOOKAHEAD) return globDeny;
      if (overBudget(opts.budget, 1)) return TOO_SLOW_MESSAGE;
      classified.set(text, classifyWord(text, opts));
    }
    let c = classified.get(text);
    // A cd's own target is not written to (where the cd leads is followed by cdBasesOf).
    if ((writing || w.redirectTarget) && !CD_CMDS.has(bareHead(w.head).toLowerCase()) &&
        (!c || (c.kind !== 'zn_state' && c.kind !== 'agent_config'))) {
      if (!elsewhereProt.has(text)) {
        if (overBudget(opts.budget, (opts.cdBases && opts.cdBases.dirs.length) || 1)) return TOO_SLOW_MESSAGE;
        elsewhereProt.set(text, protectedElsewhere(text, opts));
      }
      const e = elsewhereProt.get(text);
      if (e) c = e;
    }
    if ((!c || c.kind === 'dotenv' || c.kind === 'keyfile') && (w.git || anyGit)) {
      // git show HEAD:.env, git cat-file -p :app/.env: a secret file read from the repository, not from disk.
      const deny = gitObjectDenial(text, opts) ||
        // git log -p -- .env, git checkout HEAD -- .env: its history, also once the file is gone from disk.
        (c && w.git && gitReadsContent(w.sub, w.gitArgs) ? gitHistoryDenial(text) : null);
      if (deny) return deny;
    }
    if (!c) {
      // Segments that are just "." name the same place (.agents/. is the folder itself).
      const t = slash(text).replace(/(?:\/\.)+(?=\/|$)/g, '');
      if ((writing && (AGENT_CONFIG_MENTION_RE.test(t) || agentsDirRisky(t, w))) ||
          ((writing || w.redirectTarget) && (mentionsAgents || makesLink) && MID_DOTDOT_RE.test(t))) {
        return AGENTS_PROTECTED;
      }
      continue;
    }
    if (c.kind === 'zn_state') return denialOf(c, text, opts);
    if (c.kind === 'agent_config') {
      if (w.redirectTarget || writing) return agentConfigDenial(text, c);
      continue; // reading the settings is allowed
    }
    // A redirection to a pattern that matches a .env file (echo x > .en?) writes that file when the pattern matches it.
    const dotenvPattern = w.redirectTarget && c.kind === 'credential' && c.reason === 'a pattern that matches a .env file';
    let unprovenWrite = false;
    if ((c.kind === 'dotenv' || dotenvPattern) && (w.redirectTarget || writing)) {
      // A shell write to a file the agent loads into its environment is refused whatever it writes (shellDotenvWrite in loader-env.js): the
      // shell can run a different echo, printf or cat than the command shows, so zn cannot see the text. The agent uses the editor tool,
      // which zn checks. A program that writes the file from elsewhere (cp, tee, sed -i, dd of=, Set-Content ...) is refused the same way.
      // Any other program that names the file is refused unless it is a read-only or metadata-only one (dotenvReadOnlyWord).
      let verdict;
      if (w.redirectTarget) {
        if (dotenvWrite === undefined) {
          dotenvWrite = shellDotenvWrite(cmd, (t) => {
            let k = classifyWord(t, opts);
            const e = protectedElsewhere(t, opts);
            if (e) k = e;
            return !!k && k.kind === 'dotenv';
          });
        }
        // This reading found a redirection to the file that the scan did not: the two readings disagree, so the write is refused too.
        verdict = dotenvWrite.verdict || loaderNameMentionedIn(cmd) || OPAQUE_WRITE;
      } else if (writtenByProgram(w, text, readings, opts)) {
        verdict = loaderNameMentionedIn(cmd) || OPAQUE_WRITE;
      } else {
        // Any program that names the file is refused unless it is proven read-only or metadata-only.
        const readOnly = (opts.envFileValues && opts.envFileValues.has(w)) || (w.head === '' ? onlyReadOnly : dotenvReadOnlyWord(w, codes.size > 0));
        verdict = loaderNameMentionedIn(cmd);
        // Not proven read-only: refused, but a read of a secret file keeps its own (earlier) refusal below.
        // A backslash path (.\.env) names the file only where a backslash is a separator: on Windows or in PowerShell.
        const backslashElsewhere = text.indexOf(String.fromCharCode(92)) >= 0 && process.platform !== 'win32' && opts.powershell !== true;
        // Whether .env is a folder when the command is checked does not matter: the program may remove the folder and write a file there
        // (check, then act), so a program that is not proven read-only is refused for a name that is watched.
        unprovenWrite = !verdict && !readOnly && !backslashElsewhere;
      }
      if (verdict) return dotenvShellWriteDenial(verdict, text);
    }
    if (unprovenWrite && !w.redirectTarget) {
      const read = c ? denialOf(c, text, opts) : null;
      if (read) return read;
      return unprovenEnvWriteDenial(text);
    }
    if (w.redirectTarget) continue; // appending to .env is a write, not a read
    // The gpg programs use their own home folder (gpg --homedir ~/.gnupg --list-keys); any other program naming it reads it.
    if (c.reason === GNUPG_DIR_REASON && GPG_FOLDER_PROGRAMS.has(programName(w.head)) && gpgReadOnlyCall(listed, w)) continue;
    let deny;
    if (denied.has(text)) deny = denied.get(text);
    else { deny = denialOf(c, text, opts); denied.set(text, deny); }
    if (!deny && (c.kind === 'dotenv' || c.kind === 'keyfile')) deny = dotenvElsewhereDenial(text, opts, c.kind);
    if (deny && /[*?[]/.test(text)) { globDeny = globDeny || deny; continue; }
    if (deny) return deny;
  }
  if (!globDeny && opts.instructionNotice && !opts.instructionNotice.hit) opts.instructionNotice.hit = instructionWriteInWords(readings, opts);
  return globDeny;
}

const NAME_VALUE_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}=/;
/**
 * `-X:a=.env` is a PowerShell colon value ("a=.env") and also a --name=value word (".env"): the colon reading would hide the
 * second one, so the text after the first '=' is judged as a word of its own as well.
 */
function withEqualsReadings(words) {
  let extra = null;
  for (const w of words) {
    if (w.git || !w.text.startsWith('-')) continue;
    const eq = w.text.indexOf('=');
    if (eq > 0 && PS_COLON_PARAM_RE.test(w.text)) (extra || (extra = [])).push({ ...w, text: w.text.slice(eq + 1) });
  }
  return extra ? words.concat(extra) : words;
}
// -Name:value, a PowerShell parameter with its value attached.
const PS_COLON_PARAM_RE = /^-[A-Za-z][A-Za-z0-9]{0,63}:(.+)$/s;

/* PowerShell reads every path of a comma list (cat a,b  gc 'a','b'  type @('a','b')); in bash, a,b is one file name.
   Readers that take such lists, and the ones that exist only in PowerShell (read as PowerShell in any tool). */
const PS_LIST_READERS = new Set(['cat', 'gc', 'type', 'get-content', 'select-string', 'sls', 'import-csv', 'ipcsv', 'more', 'get-item',
  'gi', 'get-childitem', 'gci', 'ls', 'dir', 'copy-item', 'cpi', 'copy', 'cp', 'import-clixml', 'convertfrom-json']);
const PS_ONLY_READERS = new Set(['gc', 'get-content', 'select-string', 'sls', 'import-csv', 'ipcsv', 'get-item', 'gi', 'get-childitem',
  'gci', 'copy-item', 'cpi', 'import-clixml']);
// The operand of a .NET file read written as a PowerShell expression ([IO.File]::ReadAllText('.\.env')), or of a cmdlet that turns a
// name into a path (Resolve-Path .\.env, as in gc (Resolve-Path .\.env)), is read as a PowerShell path too.
const PS_DOTNET_FILE_READ_RE = /\]::(?:read|open|copy|append|get)\w*$/i;
// A word with ${ }, $( ), @( ), a variable or a backtick can read a file or run a command, so it is judged with the slash reading too.
const PS_EXPANDS_RE = /[${}()@`&;|<>]/;
// A statement with a pipeline, chain, redirect, new line or expansion can bind a printed path to a reader (echo .\.env | gi | gc).
const PS_COMPOUND_RE = /[$(){}@`&;|<>\r\n]/;
const PS_PATH_HELPERS = new Set(['resolve-path', 'rvpa', 'convert-path', 'cvpa', 'join-path']);
function psPathOperand(h) {
  const head = String(h || '').toLowerCase();
  return PS_DOTNET_FILE_READ_RE.test(head) || PS_PATH_HELPERS.has(head);
}
/*
 * Join-Path splits a path across its operands (Join-Path ~\.aws credentials, Join-Path -Path ~ -ChildPath .kube -AdditionalChildPath config),
 * so no single operand names the protected file. The joined path is judged as a word of its own, with a backslash and with a slash.
 * Operands are the words after the cmdlet in the same simple command; named ones (-Path, -ChildPath, -AdditionalChildPath, also
 * abbreviated or attached with a colon) take their own place, the others fill the free places in order. The operands in the order
 * they are written are joined too.
 */
function psJoinedPaths(words) {
  const out = [];
  const seen = new Set();
  // Set when a joined path is not judged (too many joins, or one too long): the caller then refuses the command.
  out.over = false;
  const add = (w, parts) => {
    const clean = parts.filter((x) => typeof x === 'string' && x !== '');
    if (clean.length < 2) return;
    const joined = clean.join('\\');
    if (seen.has(joined)) return;
    // Each distinct joined path adds two entries (backslash and slash forms), so the 64-entry cap is 32 distinct joined paths.
    if (joined.length > 4096 || out.length >= 64) { out.over = true; return; }
    seen.add(joined);
    out.push({ ...w, text: joined, head: 'join-path', redirectTarget: false }, { ...w, text: slash(joined), head: 'join-path', redirectTarget: false });
  };
  const slotOf = (name) => {
    const n = name.toLowerCase();
    if (n.length && 'path'.startsWith(n)) return 'path';
    if (n.length && 'childpath'.startsWith(n)) return 'child';
    if (n.length && 'additionalchildpath'.startsWith(n)) return 'extra';
    return null;
  };
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (typeof w.text !== 'string' || w.text.toLowerCase() !== 'join-path') continue;
    const named = {};
    const positional = [];
    const written = [];
    let pending = null;
    for (let j = i + 1; j < words.length && words[j].seq === w.seq; j++) {
      const t = words[j].text;
      if (typeof t !== 'string') continue;
      const flag = /^-([A-Za-z]+)(?::(.*))?$/.exec(t);
      if (flag) {
        const slot = slotOf(flag[1]);
        if (flag[2] !== undefined && flag[2] !== '') { if (slot) named[slot] = flag[2]; written.push(flag[2]); pending = null; } else pending = slot;
        continue;
      }
      written.push(t);
      if (pending) { named[pending] = t; pending = null; } else positional.push(t);
    }
    const slots = { path: named.path, child: named.child, extra: named.extra };
    for (const k of ['path', 'child', 'extra']) if (slots[k] === undefined && positional.length) slots[k] = positional.shift();
    add(w, [slots.path, slots.child, ...String(slots.extra || '').split(',').map((x) => x.trim())]);
    add(w, written.flatMap((x) => x.split(',')).map((x) => x.trim()));
  }
  return out;
}
/* The words of a command, each comma list of a PowerShell reader followed by the paths inside it. cmd is the whole command of this call. */
function psListWords(words, opts, cmd) {
  const out = [];
  let prev = null;
  const readerOf = (h) => {
    const head = bareHead(h || '').toLowerCase().replace(/\.exe$/, '');
    return PS_LIST_READERS.has(head) && (opts.powershell === true || PS_ONLY_READERS.has(head));
  };
  // PowerShell on Windows takes a backslash as a path separator (gc .\.env), but on another host the file ".\.env" does not exist
  // and the read would be let through; the same word with "/" is judged too.
  // The commands (by sequence number) that name a reader somewhere, so the operand of `$x = gc .\.env` or of `gc (Resolve-Path .\.env)`
  // is a path too.
  const readerSeqs = new Set();
  for (const w of words) if (typeof w.text === 'string' && readerOf(w.text)) readerSeqs.add(w.seq);
  let lastWord = '';
  const push = (x, head) => {
    const backslash = typeof x.text === 'string' && x.text.indexOf('\\') >= 0;
    const reads = readerOf(head) || readerSeqs.has(x.seq) || psPathOperand(lastWord);
    out.push(x);
    const compound = opts.powershell === true && typeof cmd === 'string' && PS_COMPOUND_RE.test(cmd);
    // A word that expands ("$PWD\.env"), or any word of a compound PowerShell statement, is judged with the slash reading too.
    // A lone statement (Write-Output .\.env) has no such reading: it names the file only where a backslash is a separator.
    if (backslash && x.text.length <= 4096 && (reads || compound || PS_EXPANDS_RE.test(x.text))) out.push({ ...x, text: slash(x.text) });
  };
  for (const w of words) {
    push(w, w.head);
    lastWord = w.text;
    // @('a','b'): the opening bracket starts a new command, so the word after "@" takes the head of the "@".
    const lead = prev && prev.text === '@' ? prev : w;
    const before = prev;
    prev = w;
    if (typeof w.text !== 'string' || w.text.indexOf(',') < 0 || w.text.length > 4096) continue;
    // gc ('a','b') and gc -Path ('a','b'): the bracket starts a new command too, so the word has itself as head and the
    // reader is the word before it.
    if (!readerOf(lead.head) && !(before && typeof before.text === 'string' && readerOf(before.head))) continue;
    const inner = w.text.replace(/^@?\(/, '').replace(/\)$/, '');
    const parts = inner.split(',').map((x) => x.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
    // A word that starts or ends with a comma is part of a list that goes on in the next or the previous word (gc a ,b).
    const open = /^,|,$/.test(inner.trim());
    if (parts.length < 2 && !open) continue;
    for (const part of parts) push({ ...w, text: part }, w.head);
  }
  const joined = psJoinedPaths(words);
  for (const j of joined) out.push(j);
  if (joined.over) out.over = true;
  return out;
}
const ANSI_C_SIMPLE = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };

/**
 * Two more readings of a command, for words a shell or cmd.exe rewrites before the program sees them.
 *  - cmd.exe: `^` escapes the next character outside double quotes, and a `^` at the end of a line joins it to the next one,
 *    so `type .e^nv` opens `.env`. Read only where cmd.exe is in play (Windows, or the text names cmd or a batch file): in a
 *    POSIX shell `^` is an ordinary character, and `grep ^.env notes.md` must stay allowed.
 *  - Expansions that leave nothing: an unset or empty variable, `${VAR:0:0}`, `${VAR:-}`, `$@`, `$*` and an empty command
 *    substitution, so `.en${EMPTY}v` and `.e${HOME:0:0}nv` open `.env`. The variable values are the ones the hook sees.
 * The original text is still read as typed; these are extra readings, so a word protected in any of them is refused.
 */
// cmd /v:on (or /v), or setlocal enabledelayedexpansion.
const DELAYED_EXPANSION_RE = /\/v(?::on)?(?=[\s"'\/]|$)|enabledelayedexpansion/i;
const CMD_CONTEXT_RE = /(?:^|[;&|(\"'`])\s*(?:(?:sudo|env|call|start|exec|nohup|time|xargs|command|wine)\s+(?:-\S+\s+)*)*(?:\S*[\\/])?(?:cmd(?:\.exe)?|[^\s;&|()\"'`]*\.(?:bat|cmd))(?=\s|$|[\"'])/i;
function cmdContext(text) {
  return process.platform === 'win32' || CMD_CONTEXT_RE.test(text);
}
function cmdCaretsApply(text) {
  return text.indexOf('^') >= 0 && cmdContext(text);
}
// A caret outside double quotes escapes the next character (an escaped quote does not open a quote); inside double quotes it is literal.
function dropCmdCarets(text) {
  let out = '';
  let inQuote = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { inQuote = !inQuote; out += c; continue; }
    if (c === '^' && !inQuote) {
      const nx = text[i + 1];
      if (nx === undefined) break;
      if (nx === '\r' && text[i + 2] === '\n') { i += 2; continue; }
      if (nx === '\n') { i++; continue; }
      out += nx;
      i++;
      continue;
    }
    out += c;
  }
  return out;
}
// Every cmd variable unit, with or without a modifier, taken out whole: its value is not known here (an undefined one is empty in a batch file).
// A cmd variable name is anything up to the next % or ! or colon: ProgramFiles(x86), =ExitCode, A.B and A-B are names too.
// Two readings, both judged: a name without spaces or cmd operators (the usual one: it cannot reach into the next command, so
// `echo a! & type .e!X!nv` is read per command), and a name that may hold spaces (`%A B%`), which can pair a % or ! with one of a later command.
const CMD_VAR_UNIT_RE = /%[^%!:\r\n]+(?::[^%!\r\n]*)?%|![^%!:\r\n]+(?::[^%!\r\n]*)?!/g;
const CMD_VAR_UNIT_NARROW_RE = /%[^%!:\s&|<>^"]+(?::[^%!\s&|<>"]*)?%|![^%!:\s&|<>^"]+(?::[^%!\s&|<>"]*)?!/g;
function stripCmdVars(text) {
  return text.replace(CMD_VAR_UNIT_RE, '');
}
// cmd expands a variable inside one command: the wide reading (a name may hold a space or a ^) is applied to each command on its own,
// split at & and | and at line breaks, so `echo a! & type .e!X Y!nv` reads `!X Y!` as one unit and not `! & type .e!`.
function stripCmdVarsPerCommand(text) {
  return text.split(/([&|\r\n]+)/).map((seg, i) => (i % 2 ? seg : stripCmdVars(seg))).join('');
}
function stripCmdVarsNarrow(text) {
  return text.replace(CMD_VAR_UNIT_NARROW_RE, '');
}
const UNIT_DEPTH = 64;
/** True when the word at `i` starts a command: at the start of the body or after ;  &  |  (  { or a line break (blanks skipped). */
function commandStart(text, i, from) {
  let j = i - 1;
  while (j >= from && (text[j] === ' ' || text[j] === '\t')) j--;
  return j < from || ';&|(\n{'.includes(text[j]);
}
/** The index after the esac that closes a case whose body starts at `from` (nested case counted), or -1. Quotes, comments and escapes hide words. */
function caseEnd(text, from) {
  let open = 1;
  let i = from;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '\\') { i += 2; continue; }
    if (c === "'" || c === '"') {
      let k = i + 1;
      while (k < n && text[k] !== c) k += c === '"' && text[k] === '\\' ? 2 : 1;
      i = k + 1;
      continue;
    }
    if (c === '#' && (i === from || /\s/.test(text[i - 1]))) {
      const k = text.indexOf('\n', i);
      if (k < 0) return -1;
      i = k + 1;
      continue;
    }
    if (/[A-Za-z_]/.test(c) && (i === 0 || !/[A-Za-z0-9_]/.test(text[i - 1]))) {
      let k = i;
      while (k < n && /[A-Za-z0-9_]/.test(text[k])) k++;
      const word = text.slice(i, k);
      // A reserved word only where a command starts: `my-esac` or `x esac` in an argument are words of the body.
      if ((word === 'case' || word === 'esac') && commandStart(text, i, from)) {
        if (word === 'case') open++;
        else if (--open === 0) return k;
      }
      i = k;
      continue;
    }
    i++;
  }
  return -1;
}
/**
 * The index after the bracket that closes a ${...} or $(...) whose content starts at `from`, or -1 when there is none (or it is nested
 * over UNIT_DEPTH levels). Bash honours quotes while it looks for the bracket: a `)` or `}` inside '...', "..." or after a backslash does
 * not close the unit, and nested ${ }, $( ) and backticks are units of their own; inside $( ) a bare ( nests too.
 */
function unitEnd(text, from, closer, depth) {
  if (depth > UNIT_DEPTH) return -1;
  const n = text.length;
  let j = from;
  while (j < n) {
    const ch = text[j];
    if (ch === '\\') { j += 2; continue; }
    if (ch === "'") {
      const k = text.indexOf("'", j + 1);
      if (k < 0) return -1;
      j = k + 1;
      continue;
    }
    if (ch === '`') {
      const k = text.indexOf('`', j + 1);
      if (k < 0) return -1;
      j = k + 1;
      continue;
    }
    if (ch === '"') {
      j++;
      for (;;) {
        if (j >= n) return -1;
        const q = text[j];
        if (q === '\\') { j += 2; continue; }
        if (q === '"') { j++; break; }
        if (q === '`') {
          const k = text.indexOf('`', j + 1);
          if (k < 0) return -1;
          j = k + 1;
          continue;
        }
        if (q === '$' && (text[j + 1] === '{' || text[j + 1] === '(')) {
          const e = unitEnd(text, j + 2, text[j + 1] === '{' ? '}' : ')', depth + 1);
          if (e < 0) return -1;
          j = e;
          continue;
        }
        j++;
      }
      continue;
    }
    if (ch === '$' && (text[j + 1] === '{' || text[j + 1] === '(')) {
      const e = unitEnd(text, j + 2, text[j + 1] === '{' ? '}' : ')', depth + 1);
      if (e < 0) return -1;
      j = e;
      continue;
    }
    if (closer === ')' && ch === 'c' && text.startsWith('case', j) && (j === from || /[\s;&|(]/.test(text[j - 1])) && /\s/.test(text[j + 4] || '')) {
      // a case pattern ends in a bare ): skip the whole case ... esac (nested ones counted; quoted words are not keywords)
      const e = caseEnd(text, j + 4);
      if (e < 0) return -1;
      j = e;
      continue;
    }
    if (ch === '(' && closer === ')') {
      const e = unitEnd(text, j + 1, ')', depth + 1);
      if (e < 0) return -1;
      j = e;
      continue;
    }
    if (ch === closer) return j + 1;
    j++;
  }
  return -1;
}
/**
 * The text with every shell expansion unit taken out whole, whatever the environment holds (a variable the hook sees may differ from the
 * agent's shell): balanced ${...} (any operator, nested), $NAME, $1, $@ $* $# $? $$ $!, balanced $(...) and backticks. With
 * `useDefaults`, ${NAME:-word}, ${NAME-word}, ${NAME:=word}, ${NAME=word}, ${NAME:+word} and ${NAME+word} become their word (quotes
 * removed, nested units read the same way). An unbalanced unit leaves the rest of the text as it was.
 */
function stripExpansions(text, useDefaults, mark = '', quotedMark = mark) {
  const n = text.length;
  let out = '';
  let i = 0;
  let sq = false;
  let dq = false;
  while (i < n) {
    const c = text[i];
    if (quotedMark !== mark) {
      // Track quoting so an expansion inside double quotes (no field splitting) gets its own mark.
      if (c === "'" && !dq) sq = !sq;
      else if (c === '"' && !sq) dq = !dq;
      else if (c === '\\' && !sq && text[i + 1] === '"') { out += c + '"'; i += 2; continue; }
    }
    const mk = dq ? quotedMark : mark;
    if (c === '`') {
      const j = text.indexOf('`', i + 1);
      if (j < 0) { out += text.slice(i); break; }
      out += mk;
      i = j + 1;
      continue;
    }
    if (c !== '$' || i + 1 >= n) { out += c; i++; continue; }
    const d = text[i + 1];
    if (d === '{' || d === '(') {
      const j = unitEnd(text, i + 2, d === '{' ? '}' : ')', 0);
      if (j < 0) { out += text.slice(i); break; }
      const content = text.slice(i + 2, j - 1);
      if (d === '{' && useDefaults) {
        const m = /^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*])(:?[-=+])([\s\S]*)$/.exec(content);
        if (m) out += stripExpansions(m[2], true).replace(/["']/g, '');
        else out += mk;
      } else out += mk;
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(d)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(text[j])) j++;
      out += mk;
      i = j;
      continue;
    }
    if (/[0-9@*#?$!]/.test(d)) { out += mk; i += 2; continue; }
    out += c;
    i++;
  }
  return out;
}
// ${NAME}, ${NAME:-word}, ${NAME-word}, ${NAME:+word}, ${NAME+word}, ${NAME:off} and ${NAME:off:len} (offset and length without a sign: a
// negative one needs a space or parentheses, which this does not read), $@, $* and an empty command substitution.
const EMPTY_EXPANSION_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*|[@*])(?:(:?[-+])([^}$`"'\\]*)|:([0-9]+)(?::([0-9]+))?)?\}|\$[@*]|\$\(\s*(?:true|:)?\s*\)|`\s*(?:true|:)?\s*`/g;
// cmd.exe: %NAME:~off,len% and %NAME:old=new% (and the !NAME...! forms of delayed expansion) give a piece of the value or a replaced one.
const CMD_SLICE_RE = /%([^%!:\s&|<>^"]+):~([0-9]+)(?:,([0-9]+))?%|!([^%!:\s&|<>^"]+):~([0-9]+)(?:,([0-9]+))?!/g;
const CMD_REPLACE_RE = /%([^%!:\s&|<>^"]+):([^%!=~*\r\n][^%!=\r\n]*)=([^%!\r\n]*)%|!([^%!:\s&|<>^"]+):([^%!=~*\r\n][^%!=\r\n]*)=([^%!\r\n]*)!/g;
function dropCmdExpansions(text, env) {
  const val = (name) => {
    const k = Object.keys(env).find((e) => e.toUpperCase() === name.toUpperCase());   // cmd variable names ignore case
    return k !== undefined && env[k] != null ? String(env[k]) : '';
  };
  return text
    .replace(CMD_SLICE_RE, (m, n1, o1, l1, n2, o2, l2) => {
      const v = val(n1 || n2);
      const off = Number(n1 ? o1 : o2);
      const len = n1 ? l1 : l2;
      return len === undefined ? v.slice(off) : v.substr(off, Number(len));
    })
    .replace(CMD_REPLACE_RE, (m, n1, a1, b1, n2, a2, b2) => {
      const v = val(n1 || n2);
      const from = n1 ? a1 : a2;
      return v.replace(new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), () => (n1 ? b1 : b2));
    });
}
/**
 * Expansions read as "any text". The value of `$X`, `${X}`, `$(cmd)`, a backtick substitution, `%X%` or `!X!` is not in the command: an
 * earlier command, `read`, the program's output or an environment the hook does not see can set it to anything. So each unit is
 * replaced by a mark, and a path segment that holds a mark and at least two literal characters of a protected name (.env, .env.*, an SSH
 * private key name) in the right places is refused: `.e${X}v`, `${D}env`, `.e$(echo n)v` and `.e%X:~0,1%v` can all spell `.env`.
 * It does not depend on the environment. What it cannot see is a name that is wholly inside the unit (`cat $(printf .env)` is read
 * through the words of the substitution, `cat ${NAME}` with NAME=.env only through the assignments of the same command).
 * A segment with fewer than two literal characters of the name (`${X}v`, `${CI_ENV}`, `config/${ENV}.json`) is allowed; so is
 * `.example`, `.sample` and `.template` at its end.
 */
const WILD = '\u0001';
// An expansion inside double quotes: bash does not split its value into words there.
const WILDQ = '\u0002';
const WILD_ANY_RE = /[\u0001\u0002]/;
const WILD_NAMES = [
  { name: '.env', tail: false, core: 4 }, { name: '.env.', tail: true, core: 4 },
  ...['rsa', 'dsa', 'ecdsa', 'ed25519', 'xmss'].flatMap((k) => [{ name: 'id_' + k, tail: false, core: 3 + k.length }, { name: 'id_' + k + '_sk', tail: false, core: 6 + k.length }]),
];
const WILD_SAFE_END_RE = /\.(?:example|sample|template)$/;
const WILD_SEGMENT_MAX = 512;
// Can the segment (marks match any text) spell the name, with two or more of its literal characters inside the first `core` characters of the name?
function wildSegmentMatches(seg, t) {
  const n = seg.length;
  const m = t.name.length;
  const memo = new Map();
  const f = (i, j, c) => {
    const key = (i * (m + 1) + j) * 3 + c;
    const hit = memo.get(key);
    if (hit !== undefined) return hit;
    let r;
    if (i === n) r = j === m && c >= 2;
    else if (seg[i] === WILD || seg[i] === WILDQ) r = f(i + 1, j, c) || (j < m && f(i, j + 1, c));
    else if (j < m) r = seg[i] === t.name[j] && f(i + 1, j + 1, Math.min(2, c + (j < t.core ? 1 : 0)));
    else r = t.tail && f(i + 1, j, c);
    memo.set(key, r);
    return r;
  };
  return f(0, 0, 0);
}
// Names a glob in a piece can match. The shell globs each word after it splits, so `.e*`, `.en?`, `.en[v]` and `?env` cut off by an
// unquoted expansion can read `.env`. The glob engine is the one the words without expansions use (globRegExp); a mark is any text.
// Like the literal reading, a piece needs two literal characters (a bracket expression counts as one), so `*` or `${X}*` alone is not refused.
const WILD_GLOB_NAMES = ['.env', '.env.local', '.env.example', '.env.sample', '.env.template', ...['rsa', 'dsa', 'ecdsa', 'ed25519', 'xmss'].flatMap((k) => ['id_' + k, 'id_' + k + '_sk', 'id_' + k + '.pub'])];
function wildPieceGlobMatches(piece) {
  if (!/[*?[]/.test(piece)) return false;
  const lits = piece.replace(/\[[^\]]*\]/g, 'x').replace(/[*?]/g, '').length;
  if (lits < 2) return false;
  let re;
  try { re = globRegExp(piece.replace(/[]/g, '*')); } catch (e) { return true; }
  if (re.impossible) return false;
  return WILD_GLOB_NAMES.some((n) => re.test(n));
}
// Can some word the segment may become spell a protected name? An unquoted expansion splits its value into words when the value holds
// spaces, so the segment is also read piece by piece: the start up to the first splitting mark, each piece between two of them, and the
// rest after the last, each with "any text" kept on the cut side. The safe endings (.example ...) apply only to a piece that really ends
// the word, never to the whole segment, because splitting happens before them.
function wildSegmentProtected(seg) {
  const check = (piece, safe) => {
    if (safe && WILD_SAFE_END_RE.test(piece)) return false;
    for (const t of WILD_NAMES) if (wildSegmentMatches(piece, t)) return true;
    return wildPieceGlobMatches(piece);
  };
  if (check(seg, true)) return true;
  if (seg.indexOf(WILD) < 0) return false;
  const parts = seg.split(WILD);
  const last = parts.length - 1;
  for (let i = 0; i <= last; i++) {
    if (parts[i] === '' ) continue;
    const piece = (i > 0 ? WILD : '') + parts[i] + (i < last ? WILD : '');
    if (check(piece, i === last)) return true;
  }
  return false;
}
function wildWordProtected(text) {
  const parts = text.indexOf('=') >= 0 ? [text, text.slice(text.indexOf('=') + 1)] : [text];
  for (const part of parts) {
    let afterMark = false;
    for (const raw of part.split(/[\\/]/)) {
      if (!WILD_ANY_RE.test(raw)) {
        // A glob in a later segment of a word that carries an expansion still reaches the file: `$PWD/.e*`, `${DIR}/.e*`.
        if (afterMark && /[*?[]/.test(raw)) {
          const later = raw.toLowerCase().replace(/^["']+|["']+$/g, '');
          if (!WILD_SAFE_END_RE.test(later) && wildPieceGlobMatches(later)) return true;
        }
        continue;
      }
      afterMark = true;
      const seg = raw.toLowerCase().replace(/^["']+|["']+$/g, '');
      if (seg.length > WILD_SEGMENT_MAX) return true;   // too long to follow: refused, not checked in part
      if (wildSegmentProtected(seg)) return true;
    }
  }
  return false;
}
function wildText(text) {
  let t = /[$`]/.test(text) ? stripExpansions(text, false, WILD, WILDQ) : text;
  if (/[%!]/.test(t) && cmdContext(text)) t = t.replace(CMD_VAR_UNIT_RE, WILD);
  return t;
}
// The text of a substitution that only prints a word: `$(printf .en)v` and `$(echo .en)v` read as `.env`.
function substitutionOutputs(text) {
  return text.replace(/\$\(([^()]*)\)|`([^`]*)`/g, (m, a, b) => {
    const toks = (a !== undefined ? a : b).trim().split(/\s+/);
    return toks[toks.length - 1].replace(/^["']|["']$/g, '');
  });
}
const WILD_MESSAGE = (word) => 'zn: ' + word + ' was not read because a variable, a command substitution or a cmd variable makes up part of the name, ' +
  'and what is left could spell a .env file or an SSH private key. Write the file name out in full, or ask the user to run the command.';
function dropEmptyExpansions(text, env) {
  if (/[%!]/.test(text) && cmdContext(text)) text = dropCmdExpansions(text, env);
  if (!/[$`]/.test(text)) return text;
  return text.replace(EMPTY_EXPANSION_RE, (m, name, op, word, off, len) => {
    if (!name) return '';
    const isSet = Object.prototype.hasOwnProperty.call(env, name) && env[name] != null;
    const v = isSet ? String(env[name]) : '';
    if (op) {
      const set = op[0] === ':' ? v !== '' : isSet;
      return op.endsWith('-') ? (set ? v : word) : (set ? word : '');
    }
    if (off === undefined) return v;
    return len === undefined ? v.slice(Number(off)) : v.substr(Number(off), Number(len));
  });
}

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
  chrt: 'TPD', taskset: 'c', chroot: 'ug', runuser: 'ugGsTw', unbuffer: '', strace: 'eopsuEaOSbPIX', ltrace: 'eopsunal', nsenter: 'tSG', flock: 'wE',
};
// Wrappers that take positional arguments before the command: chrt <priority>, taskset <mask> (not with -c), chroot <newroot>, flock <lock>.
const WRAPPER_POSITIONAL = { chrt: 1, taskset: 1, chroot: 1, flock: 1 };
// Long options of each wrapper that take the next word as their value, from its own manual (--opt=value is one word either way).
// Per wrapper: a name is read the way that tool reads it, and a long option not listed for the wrapper is a flag (so the chain is
// unsure and the later words are read as commands too). sudo --shell and --login, nsenter --pid and --user are flags.
const WRAPPER_LONG_VALUE = {
  sudo: new Set(['--user', '--group', '--host', '--prompt', '--chdir', '--role', '--type', '--close-from', '--other-user', '--command-timeout', '--chroot']),
  env: new Set(['--unset', '--chdir', '--split-string', '--argv0']),
  time: new Set(['--format', '--output']),
  nice: new Set(['--adjustment']),
  timeout: new Set(['--signal', '--kill-after']),
  xargs: new Set(['--max-args', '--max-procs', '--delimiter', '--arg-file', '--max-lines', '--max-chars', '--process-slot-var']),
  ionice: new Set(['--class', '--classdata', '--pid', '--pgid', '--uid']),
  stdbuf: new Set(['--input', '--output', '--error']),
  chrt: new Set(['--sched-runtime', '--sched-period', '--sched-deadline']),
  chroot: new Set(['--userspec', '--groups']),
  runuser: new Set(['--user', '--group', '--supp-group', '--shell', '--command', '--whitelist-environment', '--session-command']),
  flock: new Set(['--timeout', '--wait', '--conflict-exit-code', '--command']),
  nsenter: new Set(['--target', '--setuid', '--setgid']),
};
const NO_LONG_VALUE = new Set();
// A word taken as an option's value that names a program zn reads (rm, sh, find, curl ...) may really be the program, if the
// option was guessed wrong: the chain is then unsure, so that word and the later ones are read as commands too.
const SKIPPED_PROGRAM_RE = /^(?:rm|rmdir|del|erase|rd|ri|remove-item|shred|mkfs[a-z0-9.]*|mke2fs|mkswap|wipefs|blkdiscard|dd|find|chmod|chown|chgrp|sh|bash|zsh|dash|ksh|ash|mksh|rbash|su|eval|cmd|pwsh|powershell|python[0-9.]*|perl|ruby|node|curl|wget|iwr|irm|aria2c|fetch)$/i;
const skippedIsProgram = (t) => SKIPPED_PROGRAM_RE.test(String(t).replace(/^\(+/, '').split(/[\\/]/).pop());
// A word in command position that reads like an option value, not a program: a number or duration (10, +5, 1e3),
// a one-letter mode (stdbuf L), a user:group, a list or a format (%e).
const VALUE_LIKE_RE = /^[+-]?[0-9.]|^[A-Z]$|[:,%]/;

function wordIsGit(text) {
  return isGit(String(text).replace(/^\(+/, '').split(/[\\/]/).pop().toLowerCase());
}

/*
 * The index of the word after a wrapper and its options (and the values some take), env's assignments and timeout's duration.
 * With `info`, info.unsure is set when the chain may not end on the program: an option was read as a flag (it may take a
 * value zn does not know of, or be an abbreviation such as --adj, which GNU tools accept), or the word reached reads like an
 * option value. Callers then also read the later words as possible commands, so an unknown option cannot hide one.
 */
function skipWrapper(words, k, name, info) {
  const valueOpts = GIT_WRAPPERS[name];
  let sawC = false;
  let unsure = false;
  const textAt = (j) => (typeof words[j] === 'string' ? words[j] : words[j].text);
  k++;
  while (k < words.length) {
    const t = textAt(k);
    if (t === '--') { k++; break; }
    if (t.startsWith('--') && t.length > 2) {
      const valued = !t.includes('=') && (WRAPPER_LONG_VALUE[name] || NO_LONG_VALUE).has(t);
      if (!valued && !t.includes('=')) unsure = true;
      if (valued && k + 1 < words.length && skippedIsProgram(textAt(k + 1))) unsure = true;
      k += valued ? 2 : 1;
      continue;
    }
    if (t.startsWith('-') && t.length > 1) {
      if (t === '-c') sawC = true;
      // -n, -E, -En: flags; a cluster ending in an option that takes a value (sudo -u root) takes the next word.
      const valued = /^-[A-Za-z]+$/.test(t) && valueOpts.includes(t[t.length - 1]);
      if (!valued) unsure = true;
      if (valued && k + 1 < words.length && skippedIsProgram(textAt(k + 1))) unsure = true;
      k += valued ? 2 : 1;
      continue;
    }
    if (name !== 'timeout' && ASSIGNMENT_RE.test(t)) { k++; continue; }
    break;
  }
  // timeout's first operand is the duration, whatever its spelling (5, 1.5m, inf, 1e3, +5, 0x10): GNU reads it with strtod.
  if (name === 'timeout' && k < words.length) k++;
  if (WRAPPER_POSITIONAL[name] && k < words.length && !(name === 'taskset' && sawC)) k += WRAPPER_POSITIONAL[name];
  if (info && (unsure || (k < words.length && VALUE_LIKE_RE.test(textAt(k))))) info.unsure = true;
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
  let agentsDir = false;
  for (const words of readings) {
    if (unknown) break;
    let bases = [cwd];
    for (let k = 0; k < words.length && !unknown; k++) {
      // Found by its text, not by the command's head, so { cd x; ... } and if cd x; then ... count too.
      // env -C DIR, env --chdir=DIR and git -C DIR run the rest of the command in DIR, like a cd.
      let chdir = null;
      if (!CD_CMDS.has(words[k].text.replace(/^[({]+/, '').toLowerCase())) {
        const opt = words[k].text;
        if (!/^(?:env|git)$/i.test(bareHead(words[k].head)) || !/^(?:-C|--chdir(?:=.*)?)$/.test(opt)) continue;
        if (opt.startsWith('--chdir=')) chdir = opt.slice(8);
        else if (words[k + 1] && words[k + 1].seq === words[k].seq) chdir = words[k + 1].text;
        if (chdir === null || chdir === '') continue;
      }
      moved = true;
      // Each cd followed costs its new places; past the budget, the rest cannot be followed.
      if (overBudget(opts.budget, bases.length)) { unknown = true; break; }
      // The target: the next word of the same simple command that is not an option (cd -P dir, Set-Location -Path dir).
      let t = chdir !== null ? chdir.replace(/^["']|["']$/g, '') : '~';
      for (let j = k + 1; chdir === null && j < words.length && words[j].seq === words[k].seq; j++) {
        const x = words[j].text.replace(/^["']|["']$/g, '').replace(/[;)}]+$/, '');
        if (!x || (x.startsWith('-') && x !== '-')) continue;
        t = x;
        break;
      }
      const target = t === '-' ? '-' : expandEnv(expandHome(t, home), env).text;
      if (target === '-' || /[$`*?[{]/.test(target)) { unknown = true; continue; }
      const next = new Set(bases);
      for (const b of bases) {
        const lex = path.resolve(b, target);
        next.add(lex);
        // cd ag, cd -P ag/..: with ag a link into .agents, the real place is the hook folder.
        const pd = physicalDotDot(target, b);
        const real = new Set();
        if (pd) real.add(pd);
        for (const x of pd ? [lex, pd] : [lex]) { try { real.add(fs.realpathSync(x)); } catch (_) { /* not there */ } }
        for (const x of real) {
          if (x === lex) continue;
          next.add(x);
          if (AGENTS_SEG_RE.test(slash(x)) && !AGENTS_SEG_RE.test(slash(lex))) agentsDir = true;
        }
      }
      if (next.size > CD_BASES_MAX) { unknown = true; continue; }
      bases = [...next];
      for (const d of bases) all.add(d);
    }
  }
  return { dirs: [...all], unknown, moved, agentsDir };
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
  if (kind === 'dotenv' && (/[$`]|%[A-Za-z_][A-Za-z0-9_]*(?::[^%!\r\n]*)?%|![A-Za-z_][A-Za-z0-9_]*(?::[^%!\r\n]*)?!/.test(expanded) || (missing && afterSubstitution))) {
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
    arg = require('../agents').listAdapters().includes(next) ? next : '<agent>';
    // The fixed options of zn hooks install, so the user installs in the same place the agent asked for.
    for (const o of ['--project', '--no-mcp']) if (words.includes(o)) arg += ' ' + o;
  } else if (/^secret (set|get|rm|remove|reveal|allow|approve|link)$/i.test(admin)) {
    arg = /^[A-Z_][A-Z0-9_]{0,63}$/.test(next) ? next : 'NAME';
  } else if (/^env/i.test(admin)) {
    const base = path.basename(next);
    arg = /^[\w.-]{1,128}$/.test(base) && !/^\.+$/.test(base) ? base : '.env';
  }
  const full = arg ? admin + ' ' + arg : admin;
  if (admin === 'hooks refresh') {
    return 'zn blocked this: the hook launcher refresh of zn-gate records the files of the installed package as the ones your coding agents\' hooks trust, ' +
      'so running it is the user\'s decision and an agent may not. Next step: ask the user to run it in their own terminal, or to run `' + znCommand('hooks install <agent>', opts) + '` if the hooks need repairing.';
  }
  if (admin === 'zn-gate package') {
    return 'zn blocked this: installing, updating, rebuilding or linking the zn-gate package rewrites zn\'s hook launchers to trust the files it installs, ' +
      'so it is the user\'s decision and an agent may not run it. Next step: ask the user to run this command in their own terminal.';
  }
  if (/^audit/i.test(admin)) {
    return 'zn blocked this: `zn audit --approve` records the current MCP servers, hooks, permissions and install scripts of this project as the ones you accept, ' +
      'so approving them is the user\'s decision and an agent may not run it. ' + run('audit --approve');
  }
  if (/pins/i.test(admin)) {
    return 'zn blocked this: approving changed MCP tools is the user\'s decision, so an agent may not run `' + cliName('zn-gate') + ' pins approve`. ' + run('pins approve');
  }
  if (/^init$/i.test(admin)) {
    return 'zn blocked this: `' + cliName('zn-gate') + ' init` turns zn\'s protection on for coding agents, which is the user\'s decision. ' +
      'Next step: ask the user to run it in their own terminal (`' + cliName('npx') + ' -y zn-gate init`).';
  }
  if (/^hooks/i.test(admin)) {
    return 'zn blocked this: `' + znCommand(admin, opts) + '` turns zn\'s protection on or off for a coding agent, which is the user\'s decision. ' + run(full);
  }
  if (/^vault reset$/i.test(admin)) {
    return 'zn blocked this: `' + znCommand(admin, opts) + '` replaces the secret vault with an empty one, which is the user\'s decision. ' + run(admin);
  }
  if (/^vault purge$/i.test(admin)) {
    return 'zn blocked this: `' + znCommand(admin, opts) + '` deletes the secret vault and its backups for good, which is the user\'s decision. ' + run(admin);
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

/* ------------------------------ egress ------------------------------ */

/*
 * Network requests written in a command (curl, wget, Invoke-WebRequest and its aliases, inline python or node code that
 * opens a URL), in a WebFetch URL or in the arguments of an MCP call. egressParts() returns the places where data leaves
 * the computer (headers, credentials, query string, body, inline code) as plain text; the hook runner scans that text with
 * the scrubber engine for personal data and literal secrets. Values read from the environment ($TOKEN, ${API_KEY},
 * $env:TOKEN, %TOKEN%) and command substitutions are removed first: that is the safe way to pass a secret, and only
 * literal values are reported. A request whose hosts are all local (localhost, 127.0.0.1, ::1) or on the user's
 * allow-list (hooks.egressAllowHosts) is not checked.
 */
const EGRESS_URL_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const EGRESS_URL_LIKE_RE = /^(?:localhost|\$|\[|[\w${}-]+(?:\.[\w${}-]+)+|[\w.${}-]+:\d+)(?:[:/?#]|$)/i;
const EGRESS_URLS_IN_TEXT_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`)}\]>]+/gi;
const EGRESS_PROGRAMS = new Set(['curl', 'wget']);
// Words that start a command without being one. The wrappers themselves are one list, GIT_WRAPPERS, that the
// download-and-run rule (destructive.js) shares.
const EGRESS_KEYWORDS = new Set(['then', 'do', 'else', '!', '{']);
const EGRESS_INTERPRETER_RE = /^(?:python[0-9.]*|py|node|nodejs|deno|bun)$/;
const EGRESS_CODE_NET_RE = /\b(?:requests|httpx|urllib[0-9]?|urlopen|aiohttp|pycurl|http\.client|https?\.(?:get|request)|axios|undici|node-fetch|XMLHttpRequest|WebClient|socket)\b|\bfetch\s*\(|\bhttps?:\/\//i;
// Options that take a value, by tool. The kind says where the value goes; skip lists the others, so their value is not read as a URL.
const CURL_OPTIONS = {
  long: { header: 'header', user: 'credentials', cookie: 'header', 'proxy-header': 'header', 'proxy-user': 'credentials', 'oauth2-bearer': 'credentials', 'user-agent': 'header',
    referer: 'header', pass: 'credentials', data: 'body', 'data-raw': 'body', 'data-binary': 'body', 'data-ascii': 'body', 'data-urlencode': 'body', json: 'body',
    form: 'body', 'form-string': 'body', 'url-query': 'query', url: 'host', proxy: 'url', preproxy: 'url' },
  short: { H: 'header', u: 'credentials', b: 'header', A: 'header', e: 'header', d: 'body', F: 'body', x: 'url' },
  skip: new Set(['output', 'request', 'max-time', 'connect-timeout', 'retry', 'retry-delay', 'retry-max-time', 'write-out', 'cacert', 'cert', 'key', 'resolve', 'limit-rate',
    'max-redirs', 'range', 'time-cond', 'upload-file', 'config', 'dump-header', 'trace', 'trace-ascii', 'output-dir', 'connect-to', 'interface', 'local-port',
    'dns-servers', 'pinnedpubkey', 'capath', 'cert-type', 'key-type', 'unix-socket', 'cookie-jar', 'continue-at', 'max-filesize', 'speed-limit', 'speed-time',
    'stderr', 'variable', 'ciphers', 'curves', 'doh-url', 'hsts', 'alt-svc', 'noproxy', 'proxy-cacert', 'proxy-cert', 'proxy-key']),
  shortSkip: new Set('cCDEKmoPQrTwXyYzt'.split('')),
};
const WGET_OPTIONS = {
  long: { header: 'header', user: 'credentials', password: 'credentials', 'http-user': 'credentials', 'http-password': 'credentials', 'ftp-user': 'credentials', 'ftp-password': 'credentials',
    'proxy-user': 'credentials', 'proxy-password': 'credentials', 'user-agent': 'header', referer: 'header', 'post-data': 'body', 'body-data': 'body' },
  short: { U: 'header' },
  skip: new Set(['output-document', 'output-file', 'append-output', 'directory-prefix', 'tries', 'timeout', 'wait', 'waitretry', 'read-timeout', 'dns-timeout',
    'connect-timeout', 'limit-rate', 'quota', 'post-file', 'body-file', 'load-cookies', 'save-cookies', 'input-file', 'base', 'execute', 'bind-address',
    'ca-certificate', 'certificate', 'private-key', 'level', 'accept', 'reject', 'domains', 'exclude-domains', 'include-directories', 'exclude-directories',
    'default-page', 'method', 'config']),
  shortSkip: new Set('OPoaiBtTwQlARDIXe'.split('')),
};

/* The program a command word names, read as a shell would: 'curl', 'wget', an interpreter name, or '' when it is none
   of them. A glob that can only mean curl or wget (/usr/bin/cu?l, c*l) counts. */
function egressProgramOf(name) {
  if (EGRESS_PROGRAMS.has(name) || EGRESS_INTERPRETER_RE.test(name)) return name;
  if (name.length > 64 || !/[?*[]/.test(name) || name.replace(/[?*[\]]/g, '').length < 2) return '';
  const g = globRegExp(name);
  for (const p of EGRESS_PROGRAMS) if (g.test(p)) return p;
  return '';
}

// $(echo curl) and `echo curl` name a program as plain text: the same text without the substitution.
const EGRESS_ECHO_SUBST_RE = /\$\([ \t]{0,16}(?:echo|printf)[ \t]{1,16}(?:-[a-zA-Z]{1,3}[ \t]{1,16})?(?:(?:'%s'|"%s"|%s)[ \t]{1,16})?['"]?([A-Za-z0-9_.\/-]{1,64})['"]?[ \t]{0,16}\)|`[ \t]{0,16}(?:echo|printf)[ \t]{1,16}(?:-[a-zA-Z]{1,3}[ \t]{1,16})?(?:(?:'%s'|"%s"|%s)[ \t]{1,16})?['"]?([A-Za-z0-9_.\/-]{1,64})['"]?[ \t]{0,16}`/g;

/* The bodies of the $(...) and `...` substitutions of a text, as command text (single-quoted text is data).
   At most EGRESS_SUBST_MAX bodies; one pass. */
const EGRESS_SUBST_MAX = 64;
function egressSubstitutions(text) {
  const bodies = [];
  let quote = '';
  for (let i = 0; i < text.length && bodies.length < EGRESS_SUBST_MAX; i++) {
    const ch = text[i];
    if (quote === "'") { if (ch === "'") quote = ''; continue; }
    if (ch === '\\') { i++; continue; }
    if (ch === '"') { quote = quote === '"' ? '' : '"'; continue; }
    if (ch === "'" && quote === '') { quote = "'"; continue; }
    if (ch === '`') {
      let j = i + 1;
      for (; j < text.length && text[j] !== '`'; j++) if (text[j] === '\\') j++;
      bodies.push(text.slice(i + 1, j));
      i = j;
    } else if (ch === '$' && text[i + 1] === '(' && text[i + 2] !== '(') {
      let depth = 1;
      let j = i + 2;
      for (; j < text.length && depth > 0; j++) {
        if (text[j] === '(') depth++;
        else if (text[j] === ')') depth--;
      }
      bodies.push(text.slice(i + 2, depth === 0 ? j - 1 : j));
      // The nested substitutions are read when the body is read as a command: do not walk it again here.
      i = j - 1;
    }
  }
  return bodies;
}

/** Text with the values read from the environment, and command substitutions, removed. */
function egressStripEnv(text) {
  return String(text).replace(ENV_REF_RE, '').replace(/\$\([^()]*\)/g, '');
}

/** Lower-case host of a URL (scheme, user information, port and path removed); '' when there is none. */
function egressHostOf(raw) {
  let s = String(raw).trim().replace(EGRESS_URL_SCHEME_RE, '');
  s = s.split(/[/?#\\]/, 1)[0];
  s = s.slice(s.lastIndexOf('@') + 1);
  if (s[0] === '[') {
    const end = s.indexOf(']');
    return (end > 0 ? s.slice(1, end) : s).toLowerCase();
  }
  if (s.split(':').length === 2) s = s.slice(0, s.indexOf(':'));
  return s.toLowerCase();
}

/** True for a host that stays on this computer, or one the user listed ("example.com" or "*.example.com"). */
function egressHostAllowed(host, allow) {
  if (!host) return false;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost')) return true;
  for (const a of Array.isArray(allow) ? allow : []) {
    const h = String(a).toLowerCase();
    if (h === host || (h.startsWith('*.') && host.endsWith(h.slice(1)))) return true;
  }
  return false;
}

/** Splits the options of curl or wget. Returns {parts, urls}: the places data goes, and the URLs named. */
function egressOptions(words, spec) {
  const parts = [];
  const urls = [];
  const put = (kind, value) => {
    if (typeof value !== 'string' || value === '') return;
    if (kind === 'host') { urls.push(value); parts.push({ where: 'url', text: value }); }
    else if (kind === 'url') parts.push({ where: 'url', text: value });
    else if (value.startsWith('@')) return; // @file is a file read, not a literal value
    else {
      parts.push({ where: kind, text: value });
      // user:password is read like the credentials of a URL, so the detector of passwords in URLs applies to it.
      if (kind === 'credentials' && value.includes(':')) parts.push({ where: 'url', text: 'https://' + value + '@host.invalid/' });
    }
  };
  let restUrls = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (restUrls || w === '-' || w[0] !== '-') {
      if (restUrls || EGRESS_URL_SCHEME_RE.test(w) || EGRESS_URL_LIKE_RE.test(w)) put('host', w);
      continue;
    }
    if (w === '--') { restUrls = true; continue; }
    if (w.startsWith('--')) {
      const eq = w.indexOf('=');
      const name = (eq > 0 ? w.slice(2, eq) : w.slice(2)).toLowerCase();
      const known = Object.prototype.hasOwnProperty.call(spec.long, name);
      if (!known && !spec.skip.has(name)) continue;
      const value = eq > 0 ? w.slice(eq + 1) : words[++i];
      if (known) put(spec.long[name], value);
      continue;
    }
    for (let j = 1; j < w.length; j++) {
      const c = w[j];
      const known = Object.prototype.hasOwnProperty.call(spec.short, c);
      if (!known && !spec.shortSkip.has(c)) continue;
      let value = w.slice(j + 1);
      if (!value) value = words[++i];
      if (known) put(spec.short[c], value);
      break;
    }
  }
  return { parts, urls };
}

// PowerShell: the cmdlet's arguments are read as one text, up to the end of its line or pipeline.
function egressPowerShell(text, powershell, found) {
  const re = powershell
    ? /(?:^|[\s;|&(])(invoke-webrequest|invoke-restmethod|iwr|irm|curl|wget)(?=\s)/gi
    : /(?:^|[\s;|&(])(invoke-webrequest|invoke-restmethod|iwr|irm)(?=\s)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    // A backtick at the end of a line continues the command on the next one: join those lines before the cut.
    let rest = text.slice(m.index + m[0].length).replace(/`[ \t]*\r?\n/g, ' ');
    const cut = rest.search(/\r?\n|\s\|\s|&&/);
    if (cut >= 0) rest = rest.slice(0, cut);
    found.push({ urls: rest.match(EGRESS_URLS_IN_TEXT_RE) || [], parts: [{ where: 'ps', text: rest }] });
  }
}

// python -c, node -e, deno eval and python - <<EOF: the code is read as one text when it opens a URL.
function egressInterpreter(words, k, text, found) {
  const rest = words.slice(k + 1);
  let code = null;
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i].text;
    if (/^-[A-Za-z]*[cep]$/.test(t) || t === '--eval' || t === '--print' || (i === 0 && t === 'eval')) { code = rest[i + 1] ? rest[i + 1].text : null; break; }
  }
  if (code === null) {
    const h = /<<-?\s*['"]?[A-Za-z_]\w*/.exec(text);
    if (h && !rest.some((r) => /\.(?:py|js|mjs|cjs|ts)$/i.test(r.text))) code = text.slice(h.index);
  }
  if (!code || !EGRESS_CODE_NET_RE.test(code)) return;
  found.push({ urls: code.match(EGRESS_URLS_IN_TEXT_RE) || [], parts: [{ where: 'code', text: code }] });
}

// One reading of the command text: the requests it makes go to `found`. `raw` is the command as written (for heredocs).
function egressCollectText(raw, text, opts, depth, found) {
  const vars = shellVars.newScope();
  egressPowerShell(text, opts.powershell === true, found);
  let rest = text;
  let guard = 0;
  while (rest.length && guard++ < SIMPLE_COMMANDS_MAX) {
    const scan = scanFirstCommand(rest, false);
    let op = scan.operator;
    if ((op === '&' || op === '|') && rest[scan.end + 1] === op) op += op;
    // Literal variables assigned earlier on the line are filled in (X=curl; $X ...). A variable an assignment may not have
    // changed (after &&, in an if, ...) holds each of its values: every reading is looked at.
    const readings = shellVars.applyVariants(vars, scan.words.map((w) => w.text), op, 0);
    // Past the variable limits (too many possible values or combinations) the readings are incomplete: refuse rather
    // than check only some of them (the same marker as a command too nested to check).
    if (vars.overflow) {
      found.push({ urls: [], parts: [{ where: 'code', text: 'a command whose variables have too many possible values for zn to check' }] });
      return;
    }
    for (const filled of readings) {
      let words = scan.words;
      if (filled.length !== words.length || filled.some((t, i) => t !== words[i].text)) words = filled.map((t) => ({ text: t }));
      let k = -1;
      let prog = '';
      const chain = {};
      let i = 0;
      let chainAt = -1;
      while (i < words.length) {
        const t = words[i].text;
        let name = programName(t);
        // {curl,-H,x,URL} is the words curl -H x URL.
        if (t.indexOf('{') >= 0 && t.indexOf(',') > 0) {
          const alts = expandBraces(t);
          if (alts && alts.length > 1 && egressProgramOf(programName(alts[0]))) {
            words = words.slice(0, i).concat(alts.map((a) => ({ text: a })), words.slice(i + 1));
            name = programName(alts[0]);
          }
        }
        prog = egressProgramOf(name);
        if (prog) { k = i; break; }
        if (ASSIGNMENT_RE.test(t) || EGRESS_KEYWORDS.has(name)) { i++; continue; }
        if (Object.prototype.hasOwnProperty.call(GIT_WRAPPERS, name)) { if (chainAt < 0) chainAt = i; i = skipWrapper(words, i, name, chain); continue; }
        break;
      }
      // The wrappers did not end on a plausible program (an option zn does not know may have taken the next word): the
      // first later word that is a network program counts, so the request is not hidden behind the option.
      // The words an option may have taken are read too (from the first wrapper on), so a wrong skip cannot hide the request.
      if (k < 0 && chain.unsure) {
        for (let j = Math.max(chainAt, 0); j < words.length; j++) {
          prog = egressProgramOf(programName(words[j].text));
          if (prog) { k = j; break; }
        }
      }
      if (k >= 0) {
        if (EGRESS_INTERPRETER_RE.test(prog)) egressInterpreter(words, k, raw, found);
        // In the PowerShell tool, curl and wget are Invoke-WebRequest, read above; curl.exe is the real program.
        else if (!(opts.powershell === true && !/\.exe$/i.test(words[k].text))) {
          const r = egressOptions(words.slice(k + 1).map((w) => w.text), prog === 'curl' ? CURL_OPTIONS : WGET_OPTIONS);
          if (r.parts.length) found.push(r);
        }
      }
    }
    rest = rest.slice(scan.end + 1);
  }
  if (depth >= SHELL_CODE_DEPTH) return;
  // sh -c "curl ...": the code of a shell inside the command is a command of its own.
  if (/\b(?:sh|bash|zsh|dash|ksh|ash|eval|su|pwsh|powershell|cmd|watch|flock|xargs|busybox)\b/.test(text)) {
    for (const code of shellCodesOf(allWords(text, false))) found.push(...egressCollect(code, opts, depth + 1));
  }
  // echo "$(curl ...)" and R=`curl ...`: a command substitution runs its text as commands, quoted or not.
  if (text.indexOf('$(') >= 0 || text.indexOf('`') >= 0) {
    for (const body of egressSubstitutions(text)) found.push(...egressCollect(body, opts, depth + 1));
  }
}

// One shared amount of work for the whole egressCollect tree of a command (calls and text read): past it the
// answer fails closed, a request to nowhere that is always reported.
const EGRESS_WORK_MAX = 2000000;
function egressCollect(raw, opts, depth) {
  const found = [];
  if (!opts._work) opts._work = { left: EGRESS_WORK_MAX, over: false };
  const work = opts._work;
  work.left -= raw.length + 64;
  if (work.left < 0) {
    if (!work.over) { work.over = true; found.push({ urls: [], parts: [{ where: 'code', text: 'a command too nested for zn to check' }] }); }
    return found;
  }
  const text = stripHeredocs(raw, { until: Date.now() + CHECK_BUDGET_MS, disk: 0 });
  // The text as written, with $'curl' read as bash does, and with $(echo curl) read as the plain word.
  const readings = new Set([text]);
  const decoded = text.indexOf("$'") >= 0 ? decodeAnsiC(text) : text;
  readings.add(decoded);
  if (decoded.indexOf('$(') >= 0 || decoded.indexOf('`') >= 0) readings.add(decoded.replace(EGRESS_ECHO_SUBST_RE, (m, a, b) => a || b));
  for (const t of readings) egressCollectText(raw, t, opts, depth, found);
  if (found.length < 2) return found;
  // The readings and the substitution bodies overlap: one request is reported once.
  const seen = new Set();
  return found.filter((r) => { const key = JSON.stringify([r.urls, r.parts]); if (seen.has(key)) return false; seen.add(key); return true; });
}

function egressResult(found, allowOrFn) {
  const out = [];
  if (!found.length) return out;
  // The allow-list may be a function, read from the settings only when a request was found.
  const allow = typeof allowOrFn === 'function' ? allowOrFn() : allowOrFn;
  for (const r of found) {
    const hosts = r.urls.map(egressHostOf);
    if (hosts.length && hosts.every((h) => egressHostAllowed(h, allow))) continue;
    out.push({ hosts: [...new Set(hosts.filter(Boolean))], parts: r.parts.map((p) => ({ where: p.where, text: egressStripEnv(p.text) })) });
  }
  return out;
}

/*
 * The places in a shell command where data leaves the computer through a network request that is not local or
 * allow-listed. Returns [{hosts: [string], parts: [{where, text}]}], one entry per request. where: 'header',
 * 'body', 'query', 'url' (a URL as written), 'ps' (PowerShell arguments) or 'code' (inline code);
 * egressLabel() turns a detection inside a part into what a person reads.
 * opts: powershell (the PowerShell tool), allow (host allow-list, or a function that returns it).
 */
function egressParts(cmd, opts = {}) {
  const raw = String(cmd || '');
  if (!raw || raw.length > SHELL_SCAN_CAP) return [];
  if (!/curl|wget|invoke-|iwr|irm|python|py\b|node|deno|bun|https?:\/\/|\$|`|[?*{]/i.test(raw)) return [];
  return egressResult(egressCollect(raw, Object.assign({}, opts), 0), opts.allow);
}

/*
 * Percent-decoded copies of a text, for the scan: "%40" is how an email address is written in a URL or a form body, and
 * "+" is a space in a query or form. Returns [] when the text has no "%", else up to three distinct copies (decoded,
 * decoded with "+" as a space, and the first decoded once more for double encoding). Invalid sequences are left as
 * they are, nothing throws, and the work is linear in the text.
 */
function egressDecode(text) {
  return text.replace(/(?:%[0-9a-f]{2})+/gi, (seq) => {
    try { return decodeURIComponent(seq); } catch (e) { return seq; }
  });
}
function egressDecodedCopies(text) {
  if (typeof text !== 'string' || text.indexOf('%') < 0) return [];
  const out = new Set();
  const once = egressDecode(text);
  out.add(once);
  if (text.indexOf('+') >= 0) out.add(egressDecode(text.replace(/\+/g, ' ')));
  if (once.indexOf('%') >= 0) out.add(egressDecode(once));
  out.delete(text);
  return [...out];
}

/** The URL of a WebFetch call, in the shape egressParts returns ([] when its host is local or allow-listed). */
function egressUrlParts(url, opts = {}) {
  const u = String(url || '');
  if (!u) return [];
  return egressResult([{ urls: [u], parts: [{ where: 'url', text: u }] }], opts.allow);
}

const EGRESS_HEADER_KEY_RE = /(?:^|[_.-])(?:headers?|cookies?|authorization|auth|credentials?|bearer|token)(?:$|[_.-])/i;
const EGRESS_BODY_KEY_RE = /^(?:body|data|json|payload|form|params|query|variables)$/i;
const EGRESS_URL_KEY_RE = /^(?:url|uri|endpoint|href|webhook(?:_?url)?|base_?url)$/i;

/** The same for the arguments of an MCP call: only a call that has a URL or headers is a request. */
function egressMcpCollect(args) {
  const urls = [];
  const parts = [];
  let request = false;
  let leaves = 0;
  // complete: the walk reached every text in the arguments (depth and leaf limits not hit), so the parts cover all of it.
  let complete = true;
  const walk = (value, key, where, depth) => {
    if (depth > 6 || leaves > 2000) { complete = false; return; }
    if (typeof value === 'string') {
      leaves++;
      if (/^https?:\/\//i.test(value.trim()) || EGRESS_URL_KEY_RE.test(key)) { request = true; urls.push(value); parts.push({ where: 'url', text: value }); }
      else parts.push({ where: where || 'arguments', text: value });
      return;
    }
    if (Array.isArray(value)) { for (const v of value) walk(v, key, where, depth + 1); return; }
    if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) {
        leaves++;
        parts.push({ where: 'arguments', text: k });
        let w = where;
        if (!w && EGRESS_HEADER_KEY_RE.test(k)) w = 'header';
        else if (!w && EGRESS_BODY_KEY_RE.test(k)) w = 'body';
        if (/^headers?$/i.test(k)) request = true;
        walk(v, k, w, depth + 1);
      }
    }
  };
  walk(args, '', null, 0);
  return { request, urls, parts, complete };
}

/*
 * True when the egress check of an MCP call covers every text in its arguments: the call is a network request (a URL or
 * headers) and the walk was not cut short by the depth or leaf limits. Only then may the egress check answer the
 * personal-data question of the MCP check on its own; otherwise that question stays.
 */
function egressMcpCovers(args) {
  if (!args || typeof args !== 'object') return false;
  const c = egressMcpCollect(args);
  return c.request && c.complete;
}

/*
 * The places of an MCP call that the egress check scans. Only a call with a URL or headers is a request.
 * Host rule: the host allow-list (and the local hosts) governs only what goes to the network host, that is the URL,
 * headers and body parts. The MCP server receives all the arguments, whatever the host, so personal data in the other
 * texts of the call (where 'arguments') is still scanned for a local or allow-listed host: it is the question the MCP
 * check asks for a call that is not a request.
 */
function egressMcpParts(args, opts = {}) {
  if (!args || typeof args !== 'object') return [];
  const { request, urls, parts } = egressMcpCollect(args);
  if (!request) return [];
  const out = egressResult([{ urls, parts }], opts.allow);
  if (out.length) return out;
  const rest = parts.filter((p) => p.where === 'arguments');
  return rest.length ? [{ hosts: [], parts: rest.map((p) => ({ where: p.where, text: egressStripEnv(p.text) })) }] : [];
}

const EGRESS_PS_PARAMS = { headers: 'header', body: 'body', uri: 'URL', credential: 'credentials', authentication: 'credentials', token: 'credentials', useragent: 'header' };
const EGRESS_CODE_KEYS = { header: 'header', headers: 'header', cookie: 'header', cookies: 'header', auth: 'credentials', params: 'query string', data: 'body',
  json: 'body', body: 'body', payload: 'body', url: 'URL' };

/** What a person reads for a detection at index `start` of a part: 'header', 'body', 'query string', 'URL', 'credentials', 'code' or 'arguments'. */
function egressLabel(part, start) {
  const text = part.text;
  const before = text.slice(Math.max(0, start - 300), start);
  if (part.where === 'ps' || part.where === 'code') {
    // A detection inside a URL written in the text is named by its place in that URL.
    for (const m of text.matchAll(EGRESS_URLS_IN_TEXT_RE)) {
      if (start >= m.index && start < m.index + m[0].length) return egressLabel({ where: 'url', text: m[0] }, start - m.index);
    }
  }
  if (part.where === 'url') {
    const schemeEnd = (EGRESS_URL_SCHEME_RE.exec(text) || [''])[0].length;
    const slash = text.indexOf('/', schemeEnd);
    const q = text.indexOf('?');
    if (q >= 0 && start > q) return 'query string';
    return start >= schemeEnd && (slash < 0 || start < slash) && text.slice(0, start).length >= schemeEnd && /@/.test(text.slice(schemeEnd, slash < 0 ? undefined : slash)) ? 'credentials' : 'URL';
  }
  if (part.where === 'ps') {
    let last = null;
    for (const m of before.matchAll(/(?:^|\s)-(headers|body|uri|credential|authentication|token|useragent)\b/gi)) last = m[1].toLowerCase();
    return last ? EGRESS_PS_PARAMS[last] : 'arguments';
  }
  if (part.where === 'code') {
    let last = null;
    for (const m of before.matchAll(/\b(headers?|cookies?|auth|params|data|json|body|payload|url)\b['"]?\s*(?:=|:|\()/gi)) last = m[1].toLowerCase();
    return (last && EGRESS_CODE_KEYS[last]) || 'code';
  }
  return part.where === 'query' ? 'query string' : part.where;
}

module.exports = {
  POLICY_RULES_VERSION,
  WRAPPER_NAMES: new Set(Object.keys(GIT_WRAPPERS)),
  skipWrapper,
  gitStart,
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
  loaderEnvWriteDenial,
  dotenvUnseenWriteDenial,
  adminDenial,
  instructionWriteNotice,
  INSTRUCTION_FILE_NAMES,
  scanFirstCommand,
  wrapWithZnRun,
  scanPowerShell,
  wrapPowerShell,
  hasNetworkSignals,
  adminCommand,
  bashDenial,
  SHELL_SCAN_CAP,
  egressParts,
  egressUrlParts,
  egressMcpParts,
  egressMcpCovers,
  egressDecodedCopies,
  egressLabel,
};
