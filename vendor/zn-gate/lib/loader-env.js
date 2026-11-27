'use strict';

/**
 * Environment variables that make a program, or the interpreter it starts, load code or files of the caller's choosing:
 * the dynamic loader and C library (every LD_* and DYLD_*, GCONV_PATH, GLIBC_TUNABLES, OPENSSL_CONF ...) and interpreter
 * start-up options (NODE_OPTIONS=--require or --import, NODE_PATH, PYTHONPATH, PERL5OPT, JAVA_TOOL_OPTIONS, BASH_ENV ...).
 *
 * One list for every place zn starts a program with someone else's environment, so they cannot drift apart:
 *  - `zn run` drops them when it hands secret values to the approved program (broker/run.js);
 *  - the hook launchers (the sh script and the Windows PowerShell command in launcher.js) and the OpenCode plugin
 *    drop them before they start Node.js: a project can set the environment of the agent, and a NODE_OPTIONS=--require
 *    would run code inside the hook itself, where it could answer for the hook.
 *
 * Kept on purpose: NODE_EXTRA_CA_CERTS, SSL_CERT_FILE and the proxy variables. They add trust or route traffic, load no
 * code, and corporate networks need them.
 */

const LOADER_PREFIXES = ['LD_', 'DYLD_'];
// The variables that load a library into a program, or choose where it looks for one, before its first line runs (the shell of a hook
// launcher included): a script cannot undo them once it runs, so a launcher that finds one set refuses to answer.
// From ld.so(8) (glibc), ld-elf.so.1(1) (FreeBSD) and dyld(1) (macOS): the variables that load a library or change what the program
// does before its first line (a preload, an audit library, a trace or debug mode that ends the program). A launcher that finds one set
// refuses to answer, because it cannot undo them from inside the script.
const LOADER_PRELOAD = [
  'LD_PRELOAD', 'LD_AUDIT', 'LD_PROFILE', 'LD_LIBMAP', 'LD_32_PRELOAD',
  // A trace or the debug help: glibc's ld.so ends the shell with status 0 before the script runs for LD_TRACE_LOADED_OBJECTS (any value)
  // and for LD_DEBUG=help, so the refusal below cannot fire for them (docs/threat-model.md, accepted limits; `zn audit` reports a project
  // that sets them). The _FMT1, _FMT2 and _ALL forms act only with FreeBSD's loader; LD_DEBUG without "help" and LD_DEBUG_OUTPUT only log.
  'LD_TRACE_LOADED_OBJECTS', 'LD_TRACE_LOADED_OBJECTS_FMT1', 'LD_TRACE_LOADED_OBJECTS_FMT2', 'LD_TRACE_LOADED_OBJECTS_ALL', 'LD_DEBUG', 'LD_DEBUG_OUTPUT',
  'LD_PRELOAD_FDS', 'LD_LIBMAP_DISABLE', 'LD_LOADFLTR',
  'DYLD_INSERT_LIBRARIES', 'DYLD_IMAGE_SUFFIX', 'DYLD_SHARED_CACHE_DIR', 'DYLD_SHARED_REGION',
];
// Library search path variables: they only say where libraries are looked for, and many people set them (CUDA, vendor tools), so a launcher
// that finds one does not refuse; it removes them for the hook it starts, like the interpreter variables.
const LOADER_LIBPATH = [
  'LD_LIBRARY_PATH', 'LD_LIBRARY_PATH_FDS', 'LD_ORIGIN_PATH', 'LD_32_LIBRARY_PATH', 'LD_ELF_HINTS_PATH',
  'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH', 'DYLD_FALLBACK_LIBRARY_PATH', 'DYLD_FALLBACK_FRAMEWORK_PATH',
  'DYLD_VERSIONED_LIBRARY_PATH', 'DYLD_VERSIONED_FRAMEWORK_PATH', 'DYLD_ROOT_PATH',
];
const LOADER_NAMES = [
  'GCONV_PATH', 'GLIBC_TUNABLES', 'LOCPATH', 'NLSPATH', 'HOSTALIASES', 'RES_OPTIONS', 'OPENSSL_CONF',
  'NODE_OPTIONS', 'NODE_PATH', 'NODE_REPL_EXTERNAL_MODULE', 'NODE_V8_COVERAGE',
  'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONINSPECT', 'PYTHONUSERBASE', 'PERL5OPT', 'PERL5LIB', 'PERLLIB',
  'RUBYOPT', 'RUBYLIB', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'BASH_ENV', 'ENV',
];

// The names are plain (letters, digits and _), so they need no escaping in a regular expression or a shell pattern.
const LOADER_SOURCE = '^(' + LOADER_PREFIXES.join('|') + ')|^(' + LOADER_NAMES.join('|') + ')$';

// Case is ignored: Windows reads environment names without regard to case.
const LOADER_VAR = new RegExp(LOADER_SOURCE, 'i');

function isLoaderVar(name) {
  return LOADER_VAR.test(String(name));
}

/** The loader variables set (to any value, also empty) in an environment object, sorted. */
function loaderVarsIn(env) {
  return Object.keys(env || {}).filter(isLoaderVar).sort();
}

/** A copy of the environment object without the loader variables. */
function withoutLoaderVars(env) {
  const out = {};
  for (const [k, v] of Object.entries(env || {})) if (!isLoaderVar(k)) out[k] = v;
  return out;
}

// The names the fast scrub unsets: the list above, the loader variables the launchers refuse (LOADER_PRELOAD) and the other
// named ld.so and dyld settings.
const SH_UNSET_NAMES = [...new Set([...LOADER_NAMES, ...LOADER_PRELOAD, ...LOADER_LIBPATH, 'LD_BIND_NOW', 'LD_BIND_NOT', 'LD_DYNAMIC_WEAK',
  'LD_USE_LOAD_BIAS', 'LD_HWCAP_MASK', 'LD_WARN', 'LD_SHOW_AUXV', 'LD_ASSUME_KERNEL', 'LD_PROFILE_OUTPUT',
  'LD_PREFER_MAP_32BIT_EXEC', 'DYLD_FORCE_FLAT_NAMESPACE', 'DYLD_BIND_AT_LAUNCH', 'DYLD_NO_FIX_PREBINDING', 'DYLD_PRINT_LIBRARIES'])];

// A shell pattern that matches a name in any case: NODE_PATH -> [Nn][Oo][Dd][Ee]_[Pp][Aa][Tt][Hh].
const anyCase = (s) => s.replace(/[A-Za-z]/g, (c) => '[' + c.toUpperCase() + c.toLowerCase() + ']');

/**
 * Lines of POSIX sh that remove the loader variables from the script's environment, using shell built-ins only (the PATH of
 * a hook can be empty). The names are unset outright, then every exported name is read back from `export -p` and the ones
 * that match (in any case: Git Bash passes Windows names through as they were written) are unset too, which also covers
 * every LD_* and DYLD_* name. A value that spans lines can only add a name that matches the list, never keep one.
 */
function shScrubLines(opts = {}) {
  // fast: only the names listed here are unset, with `unset` alone: no `export -p`, no subshell and no loop over the whole environment
  // (that scan costs a measurable part of the start of every hook). It leaves the other LD_ and DYLD_ names (LD_DEBUG, LD_BIND_NOW ...)
  // and the same names written in another case, which only a Windows program reads that way, so it is for sh on Linux and macOS.
  if (opts.fast) {
    return [
      '# Variables that make Node.js or the dynamic loader load code of the caller\'s choosing (NODE_OPTIONS=--require, LD_PRELOAD and the',
      '# like) are removed before anything is started: a project can set the environment of the agent. NODE_EXTRA_CA_CERTS and the proxy settings stay.',
      'unset ' + SH_UNSET_NAMES.join(' '),
    ];
  }
  const pattern = [...LOADER_PREFIXES.map((p) => anyCase(p) + '*'), ...LOADER_NAMES.map(anyCase)].join('|');
  return [
    '# Variables that make Node.js or the dynamic loader load code of the caller\'s choosing (NODE_OPTIONS=--require, LD_PRELOAD and the',
    '# like) are removed before anything is started: a project can set the environment of the agent. NODE_EXTRA_CA_CERTS and the proxy settings stay.',
    'unset ' + LOADER_NAMES.join(' '),
    'set -f; IFS=\'',
    '\'; for ZN_V in $(export -p); do ZN_V=${ZN_V#export }; ZN_V=${ZN_V#declare -x }; ZN_V=${ZN_V%%=*}; ' +
      'case $ZN_V in ""|*[!A-Za-z0-9_]*) ;; ' + pattern + ') unset "$ZN_V" ;; esac; done; unset IFS ZN_V; set +f',
  ];
}

// The names of the list that make `node <script>` load code on Windows: NODE_OPTIONS (--require, --import), NODE_PATH
// (where a bare require is looked up) and OPENSSL_CONF (an OpenSSL engine is a DLL). The dynamic loader and C library
// settings (LD_*, DYLD_*, GCONV_PATH ...) do not exist there; NODE_REPL_EXTERNAL_MODULE acts only when Node.js starts a
// REPL, and NODE_V8_COVERAGE only names where coverage files go. The Windows launcher is one command line of at most 8191
// characters, so it carries only these.
const WINDOWS_NAMES = ['NODE_OPTIONS', 'NODE_PATH', 'OPENSSL_CONF'];
if (!WINDOWS_NAMES.every((n) => LOADER_NAMES.includes(n))) throw new Error('zn: the Windows loader names must come from the list');

/**
 * PowerShell that removes the loader variables from the process environment before Node.js starts (the children inherit
 * it). Setting an environment variable to $null removes it; no cmdlet is used (see the note on ZF in launcher.js), and
 * Windows names ignore case, so this also removes node_options.
 */
function psScrub() {
  return WINDOWS_NAMES.map((n) => '$env:' + n + '=$null; ').join('');
}

/**
 * Whether one environment variable, set for the agent, makes glibc's dynamic loader end every dynamically linked program before its
 * first line: LD_TRACE_LOADED_OBJECTS (to any value, even empty) or LD_DEBUG naming "help". The shell that runs a hook is such a program,
 * so each hook exits 0 having checked nothing. The one definition, used by `zn audit` (ZNA008) and by the checks on writes.
 */
function isHookStopVar(key, value) {
  return String(key) === 'LD_TRACE_LOADED_OBJECTS' || (String(key) === 'LD_DEBUG' && /(?:^|[\s,:])help(?:$|[\s,:])/.test(String(value)));
}


// NAME=value as it is written in a .env file or a patch, and NAME: value (the dotenv package reads that form too, with a space after
// the colon). Any white space, line breaks included, may stand around the = or the colon: the dotenv package reads NAME, a line break,
// then =value as one assignment, and a value on the line after the = or the colon. The captured value is quoted, or runs to the end of
// the line or to a shell separator, a sed slash or a closing bracket; it is only where the checks below start. Whether a write stops the
// hooks is decided on everything the value can run over (valueSpan), not on this capture. A bare NAME with no "=" sets nothing.
const HOOK_STOP_ASSIGNMENT_RE = /(?:(?<![A-Za-z0-9_])|(?<=\\[nrt]))(LD_TRACE_LOADED_OBJECTS|LD_DEBUG)(?![A-Za-z0-9_])["']?\s*(?:=|:(?=\s))\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\n"';&|/\\)}]*))?/g;

// glibc splits LD_DEBUG at spaces, commas and colons and acts on an option that reads exactly "help". A write is judged more widely:
// "help" with no letter, digit or _ on either side, once quotes and backslashes are removed. A value that a file reader cuts in another
// place than a regular expression would (x/,help, libs},help, "all" help) is then never taken as safe. This can refuse a value glibc
// would ignore (/opt/help); it never allows one glibc acts on.
const HELP_WORD_RE = /(?:^|[^A-Za-z0-9_])help(?![A-Za-z0-9_])/;

/**
 * The text a written value can run over, from just after the "=" of the assignment: past any white space and line breaks (the value
 * may stand on a later line), to the end of the line or, when the value opens with a quote, to the end of the line where that quote
 * closes (the dotenv package reads a quoted value over several lines; an unclosed quote runs to the end of the text).
 */
function valueSpan(s, from) {
  const rest = s.slice(from);
  const q = /^\s*(["'`])/.exec(rest);
  let start = /^\s*/.exec(rest)[0].length;
  if (q) {
    const close = quoteClose(rest, q[0].length, q[1]);
    if (close < 0) return rest;
    start = close + 1;
  }
  const eol = rest.slice(start).search(/[\n\r]/);
  return eol < 0 ? rest : rest.slice(0, start + eol);
}

/**
 * Index of the quote that closes a quoted value in a .env file, searching from `from` (just after the opening quote), or -1. The npm dotenv
 * package matches a quoted value as (?:\\Q|[^Q])* for all three quote characters, so a backslash before the quote character keeps the
 * value open, in single quotes and backticks too, whatever precedes that backslash. Its regular expression can also backtrack and close
 * at such a quote, so the value may be shorter than this scan says; the caller checks everything up to this index and to the end of its
 * line, which covers both readings. One forward pass.
 */
function quoteClose(text, from, quote) {
  for (let i = from; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === '\\' && text.charAt(i + 1) === quote) { i++; continue; }
    if (c === quote) return i;
  }
  return -1;
}

/** Whether the value of a file assignment opens a quote that nothing closes: unresolved, so an LD_DEBUG write is refused. */
function unterminatedQuote(s, from) {
  const rest = s.slice(from);
  const q = /^\s*(["'`])/.exec(rest);
  return !!q && quoteClose(rest, q[0].length, q[1]) < 0;
}

/**
 * Whether an assignment found in written text may stop the hooks: LD_TRACE_LOADED_OBJECTS to anything, or LD_DEBUG when "help" can be
 * one of its options (HELP_WORD_RE over the span; an escape such as \n counts as a break) or when the value refers to a variable ($X,
 * ${X}), because a loader that expands it would write a value the text does not show.
 */
function writtenValueStopsHooks(key, span) {
  if (key === 'LD_TRACE_LOADED_OBJECTS') return true;
  if (key !== 'LD_DEBUG') return false;
  const plain = String(span).replace(/\\[nrt]/g, ' ').replace(/["'`\\]/g, '');
  return HELP_WORD_RE.test(plain) || /\$/.test(String(span));
}

// Index of the first character after the "=" (or ":") of a match of HOOK_STOP_ASSIGNMENT_RE.
const valueStart = (m) => m.index + m[0].search(/[=:]/) + 1;

/**
 * A .env text as a shell that sources it reads the names: a backslash before a line break joins the lines (LD_\ then PRELOAD=x), and
 * quotes and backslashes inside a name vanish (LD_PRE''LOAD=x, LD_PRE\LOAD=x). Only the names change: the text before the first = or
 * colon of a line, or a line that is one word naming LD_ or DYLD_ (a name whose = is on the next line). The values keep their quotes,
 * so an empty value stays empty. The checks below judge the text both as written and in this form, so a name split that way is found.
 */
function flatDotenv(s) {
  const strip = (t) => t.replace(/["'`\\]/g, '');
  return String(s).replace(/\\\r?\n/g, '').split('\n').map((line) => {
    if (/^\s*#/.test(line)) return line; // a comment
    const at = line.search(/[=:]/);
    if (at >= 0) return strip(line.slice(0, at)) + line.slice(at);
    return /^\s*\S+\s*$/.test(line) && /(?:LD|DYLD)_/.test(strip(line)) ? strip(line) : line;
  }).join('\n');
}

/** The name of the first variable in `text` that is assigned a value that stops the hooks (see isHookStopVar), or null. */
function hookStopAssignedIn(text) {
  const raw = String(text);
  const flat = flatDotenv(raw);
  return hookStopAssignedInText(raw) || (flat !== raw ? hookStopAssignedInText(flat) : null);
}

function hookStopAssignedInText(s) {
  if (!s.includes('LD_')) return null;
  HOOK_STOP_ASSIGNMENT_RE.lastIndex = 0;
  let m;
  while ((m = HOOK_STOP_ASSIGNMENT_RE.exec(s))) {
    const value = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : (m[4] || '');
    if (isHookStopVar(m[1], value) || writtenValueStopsHooks(m[1], valueSpan(s, valueStart(m))) ||
      (m[1] === 'LD_DEBUG' && unterminatedQuote(s, valueStart(m)))) return m[1];
  }
  return null;
}

// The loader variables a .env file the agent loads may not set to a value: every LOADER_PRELOAD name but LD_DEBUG, which only logs
// unless it names help (hookStopAssignedIn judges that). A preload or audit library runs inside the shell of a hook launcher before the
// script's first line, so the launcher's own refusal comes too late. An empty value (LD_PRELOAD=) loads nothing and stays allowed.
const PRELOAD_WRITE_NAMES = LOADER_PRELOAD.filter((n) => n !== 'LD_DEBUG');
const PRELOAD_NAME_SRC = '(' + PRELOAD_WRITE_NAMES.join('|') + ')';
// NAME=value, NAME: value, export NAME=value, 'NAME'=value, $env:NAME='value', also right after a \n, \r or \t escape.
const PRELOAD_ASSIGNMENT_RE = new RegExp(String.raw`(?:(?<![A-Za-z0-9_])|(?<=\\[nrt]))` + PRELOAD_NAME_SRC +
  String.raw`(?![A-Za-z0-9_])["']?\s*(?:=|:(?=\s))`, 'g');
const PRELOAD_NAME_RE = new RegExp(String.raw`(?:(?<![A-Za-z0-9_])|(?<=\\[nrt]))` + PRELOAD_NAME_SRC + String.raw`(?![A-Za-z0-9_])`, 'g');

/**
 * Whether the value of a file assignment that starts at `from` is empty: past any white space and line breaks (the dotenv package can
 * read a value from a later line), only blanks and quote characters up to the end of the line where the value starts or, for a quoted
 * value, up to the end of the line where the quote closes (a line break inside the quotes counts as content). A quote that nothing
 * closes is not empty. So an empty assignment is one at the end of the text: LD_PRELOAD= followed by any other line is refused, since a
 * reader may take that line as the value.
 */
function emptyFileValue(s, from) {
  let i = from;
  while (i < s.length && /\s/.test(s.charAt(i))) i++;
  if (i >= s.length) return true;
  from = i;
  const q = s.charAt(i);
  let eolFrom = i;
  if (q === '"' || q === "'" || q === '`') {
    const close = quoteClose(s, i + 1, q);
    if (close < 0) return false;
    eolFrom = close + 1;
  }
  let end = eolFrom;
  while (end < s.length && s.charAt(end) !== '\n' && s.charAt(end) !== '\r') end++;
  for (let k = from; k < end; k++) if (!' \t"\'`'.includes(s.charAt(k))) return false;
  return true;
}

/** The name of the first preload variable (PRELOAD_WRITE_NAMES) that `text`, as a file body, assigns a non-empty value, or null. */
function preloadAssignedIn(text) {
  const raw = String(text);
  const flat = flatDotenv(raw);
  return preloadAssignedInText(raw) || (flat !== raw ? preloadAssignedInText(flat) : null);
}

function preloadAssignedInText(s) {
  if (!s.includes('LD_')) return null; // every name holds LD_ (DYLD_ too)
  PRELOAD_ASSIGNMENT_RE.lastIndex = 0;
  let m;
  while ((m = PRELOAD_ASSIGNMENT_RE.exec(s))) {
    if (!emptyFileValue(s, m.index + m[0].length)) return m[1];
  }
  return null;
}

// A plain .env name before its = or colon: optional export, then letters, digits, _, . and - only (a patch line may start with +, - or
// a space).
const PLAIN_DOTENV_KEY_RE = /^[+\- ]?\s*(?:export\s+)?[A-Za-z0-9_.-]+\s*$/;
const LOADER_FRAGMENT_RE = /(?<![A-Za-z0-9])(?:LD|DYLD)_/;

/**
 * Whether a .env text holds a line whose name, the text before its first = or colon, mentions a loader prefix (LD_, DYLD_) without being
 * a plain name: quotes, backslashes, $, spaces inside it (export LD_PRE''LOAD, "LD_PRELOAD", LD_${X}PRELOAD). zn cannot tell which
 * variable such a line sets, so a write that leaves one in a watched .env file is refused. Comment lines are skipped; lines joined by
 * a backslash before the line break are read as one.
 */
function obscureLoaderKeyIn(text) {
  const s = String(text);
  if (!/(?:LD|DYLD)/.test(s)) return false;
  for (const line of s.replace(/\\\r?\n/g, '').split(/[\n\r\v\f]/)) {
    if (/^\s*#/.test(line)) continue;
    const at = line.search(/[=:]/);
    if (at < 0) continue;
    const key = line.slice(0, at);
    if (!PLAIN_DOTENV_KEY_RE.test(key) && LOADER_FRAGMENT_RE.test(key.replace(/["'`\\]/g, ''))) return true;
  }
  return false;
}

// What may follow a preload name in a shell write (quotes and backslashes removed) for the write to set it empty: = or ": ", blanks, at
// most one redirection with its target, then the end of the command or line. echo LD_PRELOAD= x writes "LD_PRELOAD= x": not empty.
const EMPTY_SHELL_VALUE_RE = /[ \t]*(?:=|:(?=[ \t]))[ \t]*(?:(?:[0-9]*>>?|>\|)[ \t]*[^\s;&|<>]+[ \t]*)?(?=$|[\n;&|])/y;

/**
 * For a shell command that writes a dotenv file: the first preload name it mentions other than as an empty assignment, in the text as
 * written or once quotes and backslashes are removed (LD_PRE"LOAD"=x), or null. A mention that is not an assignment (printf '%s=%s'
 * LD_PRELOAD x, a name glued to other text) is refused too, because what the command then writes is not plain to see.
 */
function preloadNamedIn(s) {
  const flat = s.replace(/\\[nrt]/g, '\n').replace(/["'\\]/g, '');
  if (!flat.includes('LD_') && !s.includes('LD_')) return null;
  const count = (t) => { PRELOAD_NAME_RE.lastIndex = 0; return (t.match(PRELOAD_NAME_RE) || []).length; };
  PRELOAD_NAME_RE.lastIndex = 0;
  let m;
  while ((m = PRELOAD_NAME_RE.exec(flat))) {
    EMPTY_SHELL_VALUE_RE.lastIndex = m.index + m[0].length;
    if (!EMPTY_SHELL_VALUE_RE.test(flat)) return m[1];
  }
  if (count(s) > count(flat)) { PRELOAD_NAME_RE.lastIndex = 0; return PRELOAD_NAME_RE.exec(s)[1]; }
  return null;
}

// The two names as whole words, also right after a \n, \r or \t escape.
const HOOK_STOP_NAME_RE = /(?:(?<![A-Za-z0-9_])|(?<=\\[nrt]))(LD_TRACE_LOADED_OBJECTS|LD_DEBUG)(?![A-Za-z0-9_])/;

/**
 * For a command whose written text zn cannot see: the first loader name it mentions, LD_TRACE_LOADED_OBJECTS or LD_DEBUG anywhere
 * (in the text as written or once quotes and backslashes are removed), or a preload name other than as an empty assignment
 * (preloadNamedIn), or null. Only chooses which refusal to give: such a write is refused either way.
 */
function loaderNameMentionedIn(text) {
  const s = String(text);
  const flat = s.replace(/\\[nrt]/g, '\n').replace(/["'\\]/g, '');
  const m = HOOK_STOP_NAME_RE.exec(s) || HOOK_STOP_NAME_RE.exec(flat);
  return m ? m[1] : preloadNamedIn(s);
}

// What shellDotenvWrite returns for a write whose text zn cannot see.
const OPAQUE_WRITE = '<opaque>';

/*
 * Shell writes to a dotenv file. Every shell command that writes a watched dotenv file through a redirection is refused, whatever it
 * writes: the shell can run a different echo, printf or cat than the command shows (an inherited function, an alias or function from
 * an earlier command of a persistent shell, an untrusted PATH), so the text that reaches the file cannot be known from the command.
 * The agent edits the file with the editor tool, which zn checks on the real text.
 *
 * The command is read in one pass with POSIX quoting to find its redirections. Anything that reading does not model the way every
 * shell would (a back quote, $( ${ $' $", a here-document, a process substitution, PowerShell's <# comment, a backslash before a
 * quote, a comment that ends in a backslash, an unclosed quote) ends it: from that simple command on, every > is taken as a
 * redirection whatever the quotes, and one that may write a dotenv file refuses the command.
 */

// Characters no argument may hold anywhere.
const NOT_LITERAL_RE = /[%\\$`]/;
// Unquoted characters of a redirection target that make it a pattern (or bad syntax).
const TARGET_PATTERN_RE = /[*?[\]{}()]/;

/** Whether `s[i]` ends a simple command outside quotes: ; & | or a line break, but not the & or | of a redirection (>&2, &>, >|). */
function endsCommand(s, i) {
  const c = s.charAt(i);
  if (c === ';' || c === '\n' || c === '\r') return true;
  if (c === '&') return s.charAt(i - 1) !== '>' && s.charAt(i + 1) !== '>';
  if (c === '|') return s.charAt(i - 1) !== '>';
  return false;
}

/**
 * One simple command of `s` from `from`, with POSIX quoting: its words (text with quotes removed; `live` = the characters outside
 * quotes; `special` = holds % \ $ or a back quote anywhere), its redirections, its here-documents, where it ends, and `hazard` when it
 * uses syntax the scan does not model (see above).
 */
function readSimpleCommand(s, from) {
  const out = { end: s.length, words: [], redirs: [], heredocs: [], hazard: false };
  let word = null;
  let q = '';
  let pending = null; // a redirection waiting for its target word
  const open = (i) => { if (!word) word = { start: i, text: '', ps: '', live: '', special: false, raw: '' }; return word; };
  const close = (i) => {
    if (!word) return;
    word.raw = s.slice(word.start, i);
    if (pending) { pending.target = word; out.redirs.push(pending); pending = null; } else out.words.push(word);
    word = null;
  };
  let i = from;
  for (; i < s.length; i++) {
    const c = s.charAt(i);
    if (q === "'") {
      if (c === "'") q = ''; else { word.text += c; word.ps += c; if (NOT_LITERAL_RE.test(c)) word.special = true; }
      continue;
    }
    if (q === '"') {
      if (c === '"') { q = ''; continue; }
      if (NOT_LITERAL_RE.test(c)) word.special = true;
      if (c === '`' || (c === '$' && /[({'"]/.test(s.charAt(i + 1)))) out.hazard = true;
      if (c === '\\') {
        const n = s.charAt(i + 1);
        if (n === '"' || n === "'") out.hazard = true;
        if (n && '$`\\\n'.includes(n)) { word.text += n; word.ps += c + n; i++; continue; }
      }
      word.text += c; word.ps += c;
      continue;
    }
    if (c === ' ' || c === '\t') { close(i); continue; }
    if (endsCommand(s, i)) break;
    if (c === '#' && !word) {
      // A comment runs to the end of the line; shells disagree on a backslash right before that end.
      while (i < s.length && s.charAt(i) !== '\n' && s.charAt(i) !== '\r') i++;
      if (s.charAt(i - 1) === '\\') out.hazard = true;
      i--;
      continue;
    }
    if (c === '>' || (c === '&' && s.charAt(i + 1) === '>') || c === '<') {
      // A word of digits right before the operator is its file descriptor (2>x); any other word ends here.
      if (word && /^[0-9]+$/.test(s.slice(word.start, i))) word = null; else close(i);
      if (pending) { out.redirs.push(pending); pending = null; } // an operator with no target
      if (c === '<') {
        const n = s.charAt(i + 1);
        if (n === '(' || n === '#') { out.hazard = true; continue; }
        if (n === '<') {
          if (s.charAt(i + 2) === '<') { out.hazard = true; i += 2; continue; }
          // A here-document: its delimiter is the next word; any quote or backslash in it makes the body literal text.
          let k = i + 2;
          const dash = s.charAt(k) === '-';
          if (dash) k++;
          while (s.charAt(k) === ' ' || s.charAt(k) === '\t') k++;
          let e = k;
          let dq = '';
          while (e < s.length) {
            const d = s.charAt(e);
            if (dq) { if (d === dq) dq = ''; e++; continue; }
            if (d === "'" || d === '"') { dq = d; e++; continue; }
            if (/[\s;&|<>()]/.test(d)) break;
            e++;
          }
          if (dq) out.hazard = true;
          const raw = s.slice(k, e);
          out.heredocs.push({ quoted: /['"\\]/.test(raw), delim: raw.replace(/['"\\]/g, ''), dash });
          i = e - 1;
          continue;
        }
        pending = { op: '<', at: i, target: null };
        continue;
      }
      let k = i;
      if (c === '&') k++;
      k++; // past the first >
      if (s.charAt(k) === '(' && c === '>') { out.hazard = true; continue; }
      if (s.charAt(k) === '>' || s.charAt(k) === '|') k++;
      if (s.charAt(k) === '&') {
        // >&2, 2>&1, >&-: a copy of a descriptor, no file.
        let e = k + 1;
        while (/[0-9]/.test(s.charAt(e))) e++;
        if (s.charAt(e) === '-') e++;
        if (e > k + 1) { i = e - 1; continue; }
        k++;
      }
      pending = { op: '>', at: i, target: null };
      i = k - 1;
      continue;
    }
    if (c === '\\') {
      const n = s.charAt(i + 1);
      if (n === '"' || n === "'") out.hazard = true;
      const w = open(i);
      w.special = true;
      if (n === '\n') { i++; continue; } // a line continuation
      if (n) { w.text += n; w.ps += c + n; w.live += c; i++; }
      continue;
    }
    const w = open(i);
    if (c === "'" || c === '"') {
      q = c;
      continue;
    }
    if (c === '`' || (c === '$' && /[({'"]/.test(s.charAt(i + 1)))) out.hazard = true;
    if (NOT_LITERAL_RE.test(c)) w.special = true;
    w.text += c; w.ps += c; w.live += c;
  }
  if (q) out.hazard = true; // an unclosed quote
  close(i);
  if (pending) out.redirs.push(pending);
  out.end = i;
  return out;
}

/** The two readings of a redirection target: POSIX (a backslash escapes) and PowerShell or cmd.exe (a backslash is a separator). */
const targetTexts = (w) => (w.text === w.ps ? [w.text] : [w.text, w.ps]);

/**
 * The quote-blind fallback: from `from` on, every > is a redirection, and the word after it (quotes and backslashes removed, and
 * with backslashes kept) its target. Returns true when one may be a dotenv file. Linear: each character is read once.
 */
function blindDotenvTarget(s, from, isDotenv) {
  for (let i = s.indexOf('>', from); i >= 0 && i < s.length; i = s.indexOf('>', i)) {
    while (i < s.length && /[>|&\s]/.test(s.charAt(i))) i++;
    let e = i;
    while (e < s.length && !/[\s;&|<>()]/.test(s.charAt(e))) e++;
    const raw = s.slice(i, e);
    i = e;
    if (!raw) continue;
    if (/[$`*?[{%]/.test(raw)) return true;
    const kept = raw.replace(/['"]/g, '');
    if (isDotenv(kept) || isDotenv(kept.replace(/\\(.)/g, '$1'))) return true;
  }
  return false;
}

/**
 * Verdict on a shell command that writes a dotenv file through a redirection (> or >>). `isDotenv(text)` says whether a redirection
 * target names a dotenv file. Returns { verdict }: null when no redirection may write a dotenv file, else the loader name the command
 * mentions (to choose the refusal message) or OPAQUE_WRITE. One forward pass.
 */
function shellDotenvWrite(text, isDotenv) {
  const s = String(text);
  const refuse = () => ({ verdict: loaderNameMentionedIn(s) || OPAQUE_WRITE });
  let i = 0;
  while (i < s.length) {
    const cmd = readSimpleCommand(s, i);
    const dotenv = cmd.redirs.some((r) => r.op === '>' && (!r.target || /[%$`]/.test(r.target.raw) || TARGET_PATTERN_RE.test(r.target.live) ||
      targetTexts(r.target).some(isDotenv)));
    if (dotenv) return refuse();
    if (cmd.hazard || cmd.heredocs.length) {
      // Past syntax the scan does not model: any redirection that may write a dotenv file refuses the command.
      return blindDotenvTarget(s, i, isDotenv) ? refuse() : { verdict: null };
    }
    i = cmd.end + 1;
  }
  return { verdict: null };
}

module.exports = { isHookStopVar, hookStopAssignedIn, preloadAssignedIn, obscureLoaderKeyIn,preloadNamedIn, loaderNameMentionedIn, shellDotenvWrite, OPAQUE_WRITE, PRELOAD_WRITE_NAMES, SH_UNSET_NAMES, LOADER_LIBPATH, LOADER_PRELOAD, LOADER_PREFIXES, LOADER_NAMES, WINDOWS_NAMES, LOADER_SOURCE, LOADER_VAR, isLoaderVar, loaderVarsIn, withoutLoaderVars, shScrubLines, psScrub };
