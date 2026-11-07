'use strict';

/**
 * Optional policy for destructive shell commands.
 *
 * Off by default. The agent hooks apply it only when the user turns it on
 * (`{"hooks": {"blockDestructiveCommands": true}}` in ~/.zn/config.json, or
 * ZN_BLOCK_DESTRUCTIVE=1); the SDK function checkCommand() always applies it,
 * because calling it is the opt-in.
 *
 * Narrow on purpose: a command is blocked only when its shape is one of the
 * few below. It is a guardrail against a model's mistake or a bad suggestion,
 * not a sandbox: a command built at run time (`rm -rf "$DIR"` with an empty
 * variable, a script file the agent wrote and then runs) is not seen.
 *
 *   rm_root_home     recursive delete of the home folder, the filesystem root,
 *                    a top-level system folder or a drive root
 *   pipe_to_shell    a download that is run as a script (or by python, node, perl or ruby) without being read
 *   disk_overwrite   dd, mkfs, wipefs ... on a block device, or a redirect to one
 *   perm_root        chmod -R 777 or chown -R on the root or a system folder
 *   fork_bomb        the classic shell fork bomb
 *   rc_download     a download written into a shell startup file
 *
 * The command is split with the hook policy's own tokenizer (scanFirstCommand),
 * so quotes and escapes read the same as in the rest of the policy.
 */

const COMMAND_RULES_VERSION = '2026-10-29.5';

const REASONS = {
  rm_root_home: 'it deletes the home folder, the filesystem root or a system folder, recursively',
  pipe_to_shell: 'it downloads a script and runs it without anyone reading it first',
  disk_overwrite: 'it writes to or formats a disk device',
  perm_root: 'it changes permissions or owners across the whole filesystem or a system folder',
  fork_bomb: 'it is a fork bomb, which freezes the machine',
  rc_download: 'it writes downloaded content into a shell startup file, which runs in every new terminal',
};

const MAX_DEPTH = 3;
// Same limit as the policy's own tokenizer: enough simple commands for any text under the shell scan cap.
const MAX_SEGMENTS = 50000;
const OVERFLOW = 'too_many_commands';
const OVERFLOW_REASON = 'it has more commands than can be checked, so it is refused rather than guessed at';
const MAX_CHARS = 200 * 1024;
const QUOTE_SCAN_MAX = 20000;

const ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'rbash']);
const POWERSHELLS = new Set(['pwsh', 'powershell']);
const DOWNLOADERS = new Set(['curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod', 'aria2c', 'fetch']);
const RM_HEADS = new Set(['rm', 'remove-item', 'ri', 'del', 'erase', 'rd', 'rmdir']);
const CMD_HEADS = new Set(['rd', 'rmdir', 'del', 'erase']);
const DISK_TOOLS = /^(?:mkfs(?:\.[a-z0-9]+)?|mke2fs|mkswap|wipefs|shred|blkdiscard)$/;
const FIND_TESTS = /^-(?:i?name|i?path|i?wholename|i?regex|type|[acm]time|[acm]min|newer\w*|size|user|group|perm|empty|links|inum|samefile|executable|readable|writable|uid|gid)$/;
const SUDO_ARG_FLAGS = new Set(['-u', '-g', '-h', '-p', '-C', '-T', '-r', '-t', '-U', '-D', '-R']);

const SYSTEM_DIRS = new Set(['/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib32', '/lib64', '/opt', '/proc', '/root',
  '/sbin', '/srv', '/sys', '/usr', '/var', '/Users', '/System', '/Library', '/Applications', '/private', '/Volumes']);
const HOME_WORDS = new Set(['~', '$home', '${home}', '$userprofile', '${userprofile}', '%userprofile%', '$env:userprofile', '$env:home', '$env:homepath']);
const BLOCK_DEVICE_RE = /^\/dev\/(?:sd[a-z]+\d*|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|disk\d+(?:s\d+)?|rdisk\d+(?:s\d+)?|md\d+|dm-\d+|mapper\/[A-Za-z0-9._-]+)$/;
const RC_UNIX_RE = /\/\.(?:bashrc|bash_profile|bash_login|bash_aliases|profile|zshrc|zprofile|zshenv|zlogin|kshrc|cshrc|tcshrc)$|\/fish\/config\.fish$|^\/etc\/(?:profile|bash\.bashrc|zshrc|zsh\/zshrc|environment)$|^\/etc\/profile\.d\//;
const RC_PS_RE = /^\$profile(?:\.\w+)?$|(?:^|[\\/])(?:microsoft\.powershell_)?profile\.ps1$/i;

const QUOTED_RE = /'[^']*'|"(?:[^"\\]|\\.)*"/g;
const FORK_BOMB_RE = /(?<![\w:])([A-Za-z_:][\w:]*)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;?\s*\1(?!\w)/;
// Unquoted command substitutions and process substitutions are not split into words by the tokenizer.
const SHELL_RUNS_DOWNLOAD_RE = /(?:^|[\s;&|(])(?:eval|(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*-\w*c)\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b/;
const SOURCE_DOWNLOAD_RE = /(?:^|[\s;&|(])(?:source|\.|(?:ba|z|da|k)?sh)\s+(?:-\w+\s+)*<\(\s*(?:curl|wget)\b/;
const PS_PIPE_RE = /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b[^|;\n]{0,300}\|\s*(?:iex|invoke-expression)\b|\bdownloadstring\([^)]{0,300}\)\s*\|\s*(?:iex|invoke-expression)\b/i;
const PS_CALL_RE = /(?:^|[\s;&|(])(?:iex|invoke-expression)\b[\s($]*(?:\(\s*)*(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget|new-object\s+(?:system\.)?net\.webclient)\b/i;
// PowerShell escapes a character with a backtick (i`wr, Invoke-`Expression). Only a backtick inside a word counts: in
// POSIX shells a backtick starts a command substitution, so the text is never stripped for the other patterns.
const PS_NEXT_PIPE_RE = /\r?\n[ \t]*\|/g;
const PS_TICK_RE = /(?:(?<=[\s|;&(A-Za-z0-9_.-])|^)`(?=[A-Za-z-])/g;
const PS_DISK_RE = /(?:^|[\s;&|(])(?:format-volume|clear-disk)\b/i;

// Code an interpreter runs from its command line (python -c, node -e, perl -e, ruby -e) and a download piped into one.
// The option patterns are linear: an option word that may say "no program from stdin" has at most 32 letters on
// each side of its key letter. A longer word is not taken as such an option, so a pipe into it stays blocked.
const INTERPRETER_RE = /^(?:py|python(?:[23](?:\.\d+)?)?|pypy3?|node(?:js)?|perl|ruby)$/;
const INTERPRETERS = {
  py: { skip: new Set(['-W', '-X']), code: /^-[A-Za-z]*c$/, noStdin: /^(?:-[A-Za-z]{0,32}[cmVh][A-Za-z]{0,32}|--(?:version|help))$/ },
  node: { skip: new Set(['-r', '--require', '--import', '--loader', '--experimental-loader']), code: /^(?:-e|-p|-pe|--eval|--print)$/, noStdin: /^(?:-[A-Za-z]{0,32}[epcvh][A-Za-z]{0,32}|--(?:eval|print|check|version|help|test)(?:=.*)?)$/ },
  perl: { skip: new Set(['-I']), code: /^-[A-Za-z]*[eE]$/, noStdin: /^-[A-Za-z]{0,32}[eEcvVh][A-Za-z]{0,32}$/ },
  ruby: { skip: new Set(['-r', '-I']), code: /^-[A-Za-z]*e$/, noStdin: /^(?:-[A-Za-z]{0,32}[ecvh][A-Za-z]{0,32}|--(?:version|help))$/ },
};
// A recursive-delete call: shutil.rmtree, fs.rmSync / rmdirSync / rm / rmdir, rimraf, File::Path remove_tree / rmtree,
// FileUtils.rm_rf / rm_r / remove_entry, and Perl's unlink glob(...).
const OI_CALL_RE = /\b(rmtree|remove_tree|remove_entry_secure|remove_entry|remove_dir|rm_rf|rm_r|rimraf|removeSync|rmSync|rmdirSync|rmdir|rm)\b(?:\s{0,20}\.\s{0,20}sync\b)?\s{0,20}(\()?/g;
const OI_GLOB_RE = /\bunlink\s{0,20}\(?\s{0,20}glob\b\s{0,20}\(?/g;
const OI_NEEDS_PAREN = new Set(['rimraf', 'removeSync', 'rmSync', 'rmdirSync', 'rmdir', 'rm']);
const OI_NEEDS_RECURSIVE = new Set(['rmSync', 'rmdirSync', 'rmdir', 'rm']);
const OI_RECURSIVE_RE = /\brecursive['"]?\s{0,20}:\s{0,20}(?:true|1|!0)/;
const OI_PATH_WRAP_RE = /^(?:(?:pathlib\s{0,20}\.\s{0,20})?(?:Pure)?(?:Posix)?(?:Windows)?Path\s{0,20}\(\s{0,20}|(?:path|dirname|dir)\s{0,20}=\s{0,20})/;
// The home folder named by an expression and not by a literal: expanduser('~'), os.homedir(), Path.home(), Dir.home, $ENV{HOME} ...
const OI_HOME_RE = /^(?:(?:os\s{0,20}\.\s{0,20}path\s{0,20}\.\s{0,20})?expanduser\s{0,20}\(\s{0,20}['"]~\/?['"]\s{0,20}\)|(?:require\s{0,20}\(\s{0,20}['"](?:node:)?os['"]\s{0,20}\)\s{0,20}\.\s{0,20}|os\s{0,20}\.\s{0,20})?homedir\s{0,20}\(\s{0,20}\)|(?:pathlib\s{0,20}\.\s{0,20})?Path\s{0,20}\.\s{0,20}home\s{0,20}\(\s{0,20}\)|Dir\s{0,20}\.\s{0,20}home\b(?:\s{0,20}\(\s{0,20}\))?|File\s{0,20}\.\s{0,20}expand_path\s{0,20}\(\s{0,20}['"]~\/?['"]\s{0,20}\)|ENV\s{0,20}\[\s{0,20}['"]HOME['"]\s{0,20}\]|\$ENV\s{0,20}\{\s{0,20}['"]?HOME['"]?\s{0,20}\}|os\s{0,20}\.\s{0,20}environ\s{0,20}\[\s{0,20}['"]HOME['"]\s{0,20}\]|os\s{0,20}\.\s{0,20}(?:getenv|environ\s{0,20}\.\s{0,20}get)\s{0,20}\(\s{0,20}['"]HOME['"]\s{0,20}\)|process\s{0,20}\.\s{0,20}env\s{0,20}(?:\.\s{0,20}HOME\b|\[\s{0,20}['"]HOME['"]\s{0,20}\]))/;
const OI_LITERAL_RE = /^[rRbBuUfF]{0,2}(['"`])((?:[^'"`\\\r\n]|\\.){0,200})\1/;
const OI_ENV_HOME_RE = /\$ENV\{['"]?HOME['"]?\}|\$\{?HOME\}?|%USERPROFILE%/gi;

function programName(text) {
  return String(text).replace(/^\\+/, '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
}

/* Simple commands of a command line, with the operator that follows each: [{ words: string[], sep }]. */
function segmentsOf(cmd, posix = false) {
  const { scanFirstCommand } = require('./hooks/policy');
  // 2>&1 and &> are redirections, not the control operator &.
  // A drive root C:\ before a space is a path, not an escaped space.
  let rest = String(cmd).replace(/(\d*[<>]+)&(\d+|-)/g, '$1_$2').replace(/&>>?/g, '>').replace(/(^|[\s"'])([A-Za-z]:)\\(?=\s|$)/g, '$1$2/');
  const out = [];
  let guard = 0;
  for (; rest.length && guard < MAX_SEGMENTS; guard++) {
    const scan = scanFirstCommand(rest, posix);
    let sep = scan.operator;
    let adv = scan.end + 1;
    if (sep === '|' || sep === '&') {
      const next = rest[scan.end + 1];
      if (next === sep) { sep += sep; adv++; } else if (sep === '|' && next === '&') { sep = '|&'; adv++; }
    }
    out.push({ words: scan.words.map((w) => w.text), sep });
    rest = rest.slice(adv);
  }
  // Unread text left over: the caller must not treat the commands read so far as the whole line.
  out.truncated = rest.length > 0;
  return out;
}

const isPipe = (sep) => sep === '|' || sep === '|&';

/* The words of a command after wrappers that only run it (sudo, env, VAR=x, nohup, nice, time ...). */
function unwrap(args) {
  let i = 0;
  for (let guard = 0; guard < 8 && i < args.length; guard++) {
    const a = args[i];
    if (ASSIGN_RE.test(a)) { i++; continue; }
    const name = programName(a);
    if (name === 'sudo' || name === 'doas') {
      i++;
      while (i < args.length && args[i].startsWith('-')) { const f = args[i++]; if (SUDO_ARG_FLAGS.has(f)) i++; }
      continue;
    }
    if (name === 'env') {
      i++;
      while (i < args.length && (args[i].startsWith('-') || ASSIGN_RE.test(args[i]))) { const f = args[i++]; if (f === '-u' || f === '-C' || f === '-S') i++; }
      continue;
    }
    if (name === 'command' || name === 'exec' || name === 'nohup' || name === 'time' || name === 'builtin' || name === 'setsid') {
      i++;
      while (i < args.length && args[i].startsWith('-')) i++;
      continue;
    }
    if (name === 'nice' || name === 'ionice') {
      i++;
      while (i < args.length && args[i].startsWith('-')) { const f = args[i++]; if (f === '-n' || f === '-c') i++; }
      continue;
    }
    if (name === 'timeout') {
      i++;
      while (i < args.length && args[i].startsWith('-')) i++;
      i++; // the duration
      continue;
    }
    break;
  }
  return args.slice(i);
}

/* Resolves "." and ".." segments lexically (no filesystem) for a path that starts at a known point: "/", a drive, or a home word.
   A ".." above "/" or a drive root stays there; a ".." that steps out of the home folder names its parent. Relative paths are left alone. */
function resolveDots(t) {
  if (!/(?:^|\/)\.\.?(?:\/|$)/.test(t)) return t;
  let anchor = '';
  let rest = t;
  let home = false;
  const drive = /^[A-Za-z]:(?:\/|$)/.exec(t);
  if (t.startsWith('/')) { anchor = '/'; rest = t.slice(1); }
  else if (drive) { anchor = t.slice(0, 2) + '/'; rest = t.slice(drive[0].length); }
  else {
    const first = t.split('/')[0];
    if (!HOME_WORDS.has(first.toLowerCase())) return t;
    anchor = first + '/'; rest = t.slice(first.length + 1); home = true;
  }
  const out = [];
  for (const seg of rest.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg !== '..') { out.push(seg); continue; }
    if (out.length) out.pop();
    else if (home) return '/home';
  }
  return anchor + out.join('/');
}

/* The dangerous path a word names, as 'root', 'home' or 'system', or ''. */
function dangerousPath(word) {
  let t = String(word).replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  if (!t) return '';
  t = resolveDots(t);
  // Trailing "/", "/*", "/.*", "/." and a bare "*" (a PowerShell "~\*" reaches the tokenizer as "~*") name the same folder.
  for (let n = 0; n < 4; n++) {
    let s = t.replace(/\/(?:\*|\.\*|\.|\{\*,\.\*\})?$/, '');
    if (s === t && t.length > 1 && t.endsWith('*')) s = t.slice(0, -1);
    if (s === t) break;
    t = s;
    if (t === '') return 'root';
  }
  if (t === '*') return '';
  const low = t.toLowerCase();
  if (HOME_WORDS.has(low)) return 'home';
  if (SYSTEM_DIRS.has(t)) return 'system';
  if (/^\/(?:home|Users)\/[^/*.][^/*]*$/.test(t)) return 'home';
  if (/^[A-Za-z]:$/.test(t)) return 'root';
  if (/^[A-Za-z]:\/(?:windows|windows\/system32|users|program files|program files \(x86\)|programdata)$/i.test(t)) return 'system';
  if (/^[A-Za-z]:\/users\/[^/*]+$/i.test(t)) return 'home';
  return '';
}

function recursiveFlag(w, head) {
  // rm's own short flags only, so PowerShell's -Force is not read as a bundle with an r in it.
  if (/^-[fiIrRdvx]*[rR][fiIrRdvx]*$/.test(w) || w === '--recursive') return true;
  if (/^-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?$/i.test(w)) return true;
  return CMD_HEADS.has(head) && /^\/s$/i.test(w);
}

function isCmdFlag(w, head) { return CMD_HEADS.has(head) && /^\/[sqfaA]$/i.test(w); }

/* Words after the command name that are not flags (everything after "--" counts). */
function operands(args, head) {
  const out = [];
  let rest = false;
  for (const w of args) {
    if (!rest && w === '--') { rest = true; continue; }
    if (!rest && (w.startsWith('-') || isCmdFlag(w, head))) continue;
    out.push(w);
  }
  return out;
}

function redirectTargets(words) {
  const out = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (/^\d*>>?\|?$/.test(w)) { if (i + 1 < words.length) out.push(words[i + 1]); continue; }
    const m = /^\d*>>?\|?(.+)$/.exec(w);
    if (m) out.push(m[1]);
  }
  return out;
}

/* The interpreter family of a program name ('py', 'node', 'perl', 'ruby'), or ''. */
function interpreterKind(head) {
  if (!INTERPRETER_RE.test(head)) return '';
  if (head === 'py' || head.startsWith('py')) return 'py';
  return head.startsWith('node') ? 'node' : head;
}

/* The code strings given on the command line of an interpreter (python -c CODE, node -e CODE, perl -e CODE, ruby -e CODE). */
function interpreterCode(kind, rest) {
  const def = INTERPRETERS[kind];
  const out = [];
  for (let i = 0; i < rest.length; i++) {
    const w = rest[i];
    if (w === '--' || !w.startsWith('-')) break;
    if (def.code.test(w)) {
      if (i + 1 < rest.length) out.push(rest[i + 1]);
      i++;
      if (kind === 'py' || kind === 'node') break;
      continue;
    }
    const m = kind === 'node' ? /^--(?:eval|print)=([\s\S]*)$/.exec(w) : null;
    if (m) { out.push(m[1]); break; }
    if (def.skip.has(w)) i++;
  }
  return out;
}

/* True when the first argument of a delete call names the home folder, the root or a system folder. */
function protectedArgument(tail) {
  let t = tail.replace(/^\s{0,20}/, '');
  const wrap = OI_PATH_WRAP_RE.exec(t);
  if (wrap) t = t.slice(wrap[0].length);
  const home = OI_HOME_RE.exec(t);
  if (home) return /^\s{0,20}(?:[,)}\]]|$)/.test(t.slice(home[0].length));
  const lit = OI_LITERAL_RE.exec(t);
  return Boolean(lit) && Boolean(dangerousPath(lit[2].replace(OI_ENV_HOME_RE, '~')));
}

/* True when interpreter code calls a recursive delete on the home folder, the root or a system folder. */
function codeDeletesProtected(code) {
  for (const m of code.matchAll(OI_CALL_RE)) {
    const name = m[1];
    if (OI_NEEDS_PAREN.has(name) && !m[2]) continue;
    const from = m.index + m[0].length;
    const tail = code.slice(from, from + 300);
    if (OI_NEEDS_RECURSIVE.has(name) && !OI_RECURSIVE_RE.test(tail)) continue;
    if (protectedArgument(tail)) return true;
  }
  for (const m of code.matchAll(OI_GLOB_RE)) {
    const from = m.index + m[0].length;
    if (protectedArgument(code.slice(from, from + 300))) return true;
  }
  return false;
}

/* True when an interpreter in a pipeline reads its program from the pipe: no script file, -c, -e or -m. */
function readsScriptFromStdin(kind, rest) {
  const def = INTERPRETERS[kind];
  for (let i = 0; i < rest.length; i++) {
    const w = rest[i];
    if (w === '-') return true;
    if (def.noStdin.test(w)) return false;
    if (w.startsWith('-')) { if (def.skip.has(w)) i++; continue; }
    return false; // a script file: stdin is only data for it
  }
  return true;
}

function checkSimple(words, depth) {
  const args = unwrap(words);
  if (!args.length) return null;
  const head = programName(args[0]);
  const rest = args.slice(1);

  // Shell code inside the command: sh -c "...", eval "...", pwsh -Command "...", cmd /c "...", su -c "..."
  let code = null;
  if (SHELLS.has(head) || head === 'su') {
    const k = rest.findIndex((w) => /^-[A-Za-z]*c[A-Za-z]*$/.test(w));
    if (k >= 0 && k + 1 < rest.length) code = rest[k + 1];
  } else if (head === 'eval') {
    code = rest.join(' ');
  } else if (POWERSHELLS.has(head)) {
    const k = rest.findIndex((w) => /^-c(?:ommand)?$/i.test(w));
    if (k >= 0) code = rest.slice(k + 1).join(' ');
  } else if (head === 'cmd') {
    const k = rest.findIndex((w) => /^\/[ck]$/i.test(w));
    if (k >= 0) code = rest.slice(k + 1).join(' ');
  }
  if (code !== null && depth < MAX_DEPTH) {
    const hit = analyze(code, depth + 1);
    if (hit) return hit;
  }

  // Code an interpreter runs from its command line: python -c, node -e, perl -e, ruby -e.
  const kind = interpreterKind(head);
  if (kind && on('rm_root_home') && interpreterCode(kind, rest).some((c) => codeDeletesProtected(c))) return 'rm_root_home';

  if (RM_HEADS.has(head)) {
    if ((rest.some((w) => recursiveFlag(w, head)) && operands(rest, head).some((w) => dangerousPath(w))) && on('rm_root_home')) return 'rm_root_home';
  }
  if (head === 'find') {
    const paths = [];
    for (const w of rest) { if (w.startsWith('-') || w === '(' || w === '!') break; paths.push(w); }
    const del = rest.includes('-delete') || rest.some((w, i) => w === '-exec' && /^(?:rm|shred)$/.test(programName(rest[i + 1] || '')));
    // With a test (-name, -type, -mtime ...) find removes only some files; with none it removes everything below the path.
    const filtered = rest.some((w) => FIND_TESTS.test(w));
    if ((del && !filtered && paths.some((w) => dangerousPath(w))) && on('rm_root_home')) return 'rm_root_home';
  }
  if (head === 'chmod' || head === 'chown' || head === 'chgrp') {
    if (rest.some((w) => /^-[A-Za-z]*R[A-Za-z]*$/.test(w) || w === '--recursive')) {
      const ops = operands(rest, head);
      const mode = ops[0] || '';
      const targets = ops.slice(1).map(dangerousPath).filter(Boolean);
      if ((targets.includes('root') || targets.includes('system')) && on('perm_root')) return 'perm_root';
      if ((head === 'chmod' && targets.includes('home') && worldWritable(mode)) && on('perm_root')) return 'perm_root';
    }
  }
  if (head === 'dd') {
    if ((rest.some((w) => w.startsWith('of=') && BLOCK_DEVICE_RE.test(w.slice(3)))) && on('disk_overwrite')) return 'disk_overwrite';
  }
  if ((DISK_TOOLS.test(head) && rest.some((w) => BLOCK_DEVICE_RE.test(w))) && on('disk_overwrite')) return 'disk_overwrite';
  return null;
}

function worldWritable(mode) {
  if (/^0?[0-7]{2}[2367]$/.test(mode) || /^[0-7]{4}$/.test(mode) && /[2367]$/.test(mode)) return true;
  const m = /^([ugoa]*)[+=][rwxXst]*w[rwxXst]*$/.exec(mode);
  return Boolean(m && (m[1] === '' || /[ao]/.test(m[1])));
}

function isRcPath(w) {
  const t = String(w).replace(/\\/g, '/').replace(/^~\//, '/').replace(/^\$\{?home\}?\//i, '/');
  return RC_UNIX_RE.test(t) || RC_PS_RE.test(String(w));
}

/* The flag before the file a download is saved to: curl -o / --output, wget -O / --output-document, iwr -OutFile. */
function outFlag(w) {
  return /^-[A-Za-z]*[oO]$/.test(w) || /^--output(?:-document)?$/.test(w) || /^-out(?:f(?:i(?:l(?:e)?)?)?)?$/i.test(w);
}

/* {x..y} with one-character ends or one- and two-digit numbers, as the comma list bash expands it to ({u..u} -> u). */
function expandSequences(w) {
  return w.replace(/\{(?:([A-Za-z])\.\.([A-Za-z])|(\d{1,2})\.\.(\d{1,2}))\}/g, (all, a, b, n, m) => {
    const chr = a !== undefined;
    // mixed case: bash also walks the characters between the two, not worth following
    if (chr && (a < 'a') !== (b < 'a')) return all;
    const from = chr ? a.charCodeAt(0) : Number(n);
    const to = chr ? b.charCodeAt(0) : Number(m);
    const step = from <= to ? 1 : -1;
    const list = [];
    for (let c = from; ; c += step) {
      list.push(chr ? String.fromCharCode(c) : String(c));
      if (c === to) break;
    }
    return list.length === 1 ? list[0] : '{' + list.join(',') + '}';
  });
}

/* The words a brace list in `w` expands to (c{u,}rl -> curl, cl); just `w` when there is none, and null when there
   are too many: the caller reads that as a match, since the shell runs the first alternative and any of them may be it. */
function braceAlts(w) {
  return require('./hooks/policy').expandBraces(expandSequences(String(w)));
}

function isRcTarget(w) {
  const alts = braceAlts(w);
  return alts === null || alts.some(isRcPath);
}

function checkPipeline(pipe) {
  const heads = pipe.map((s) => {
    const a = unwrap(s.words);
    const alts = a.length ? braceAlts(a[0]) : [''];
    const names = (alts || [String(a[0])]).map(programName);
    return { args: a, head: names[0], names, overflow: alts === null };
  });
  const firstDl = heads.findIndex((h) => h.overflow || h.names.some((n) => DOWNLOADERS.has(n)));
  if (firstDl >= 0) {
    // a download whose output reaches a shell
    for (let j = firstDl + 1; j < pipe.length; j++) {
      const h = heads[j];
      // an interpreter that reads its program from the pipe (python3, python3 -, node, perl, ruby)
      const interp = h.overflow || h.names.some((n) => SHELLS.has(n)) ? '' : h.names.map(interpreterKind).find(Boolean);
      if (interp) {
        if (readsScriptFromStdin(interp, h.args.slice(1)) && on('pipe_to_shell')) return 'pipe_to_shell';
        continue;
      }
      if (!h.overflow && !h.names.some((n) => SHELLS.has(n))) continue;
      const rest = h.args.slice(1);
      // -c runs the code of its argument (checked on its own); -n only reads the script to check its syntax.
      if (rest.some((w) => /^-[A-Za-z]*[cn][A-Za-z]*$/.test(w))) continue;
      const files = rest.filter((w) => !w.startsWith('-'));
      if ((!files.length || rest.includes('-s') || rest.includes('-')) && on('pipe_to_shell')) return 'pipe_to_shell';
    }
    // a download written into a startup file
    for (let j = 0; j < pipe.length; j++) {
      const words = pipe[j].words;
      for (let i = 0; i < words.length; i++) {
        const w = words[i];
        const prev = i > 0 ? words[i - 1] : '';
        let target = null;
        if (/^\d*>>?\|?$/.test(prev)) target = w;
        else if (/^\d*>>?\|?.+$/.test(w)) target = w.replace(/^\d*>>?\|?/, '');
        else if (outFlag(prev)) target = w;
        else if (/^(?:--output|--output-document|-OutFile)[=:]/i.test(w)) target = w.replace(/^[^=:]*[=:]/, '');
        else if (heads[j].head === 'tee' && !w.startsWith('-') && i > 0) target = w;
        if ((target !== null && isRcTarget(target)) && on('rc_download')) return 'rc_download';
      }
    }
  }
  // A redirect to a block device, with or without a download.
  for (const s of pipe) {
    for (const t of redirectTargets(s.words)) if ((BLOCK_DEVICE_RE.test(t)) && on('disk_overwrite')) return 'disk_overwrite';
  }
  return null;
}

// The rules the current call looks for (null = all six). Set by checkCommand and denial; the check is synchronous.
let ENABLED = null;
function on(rule) { return ENABLED === null || ENABLED.has(rule); }

function checkSegments(segs, depth) {
  let pipe = [];
  for (const seg of segs) {
    const hit = checkSimple(seg.words, depth);
    if (hit) return hit;
    pipe.push(seg);
    if (!isPipe(seg.sep)) {
      const hit2 = checkPipeline(pipe);
      if (hit2) return hit2;
      pipe = [];
    }
  }
  return pipe.length ? checkPipeline(pipe) : null;
}

function analyze(cmd, depth = 0) {
  const text = String(cmd);
  if (text.length > MAX_CHARS) return ENABLED === null || ENABLED.size > 0 ? OVERFLOW : null;
  // Text inside quotes is data (echo "a fork bomb is :(){ :|:& };:"); the code a shell runs from a string is checked
  // again on its own below, so the patterns that do not need the quotes read the text without them.
  // (Past QUOTE_SCAN_MAX the quotes are left in: finding every pair is the one step that is not linear.)
  const bare = text.length > QUOTE_SCAN_MAX ? text : text.replace(QUOTED_RE, "''");
  if ((FORK_BOMB_RE.test(bare)) && on('fork_bomb')) return 'fork_bomb';
  // PowerShell reading: a backtick and a line break continue the line, and so does a next line that starts with a pipe
  // (PowerShell 7), so `iwr URL` + newline + `| iex` is `iwr URL | iex`.
  const psBare = bare.includes('`') || bare.includes('\n')
    ? bare.replace(/`\r?\n/g, ' ').replace(PS_TICK_RE, '').replace(PS_NEXT_PIPE_RE, ' |')
    : bare;
  if ((SHELL_RUNS_DOWNLOAD_RE.test(text) || SOURCE_DOWNLOAD_RE.test(bare) || PS_PIPE_RE.test(psBare) || PS_CALL_RE.test(psBare)) && on('pipe_to_shell')) return 'pipe_to_shell';
  if ((PS_DISK_RE.test(bare)) && on('disk_overwrite')) return 'disk_overwrite';
  const segs = segmentsOf(text);
  const hit = checkSegments(segs, depth);
  if (hit) return hit;
  // POSIX reading: an unquoted backslash escapes the next character and is removed (r\m, cu\rl, .bash\rc). The Windows
  // reading above keeps it as a path separator and runs first, so this one only adds blocks: any rule it hits counts.
  if (text.includes('\\')) {
    const posixHit = checkSegments(segmentsOf(text, true), depth);
    if (posixHit) return posixHit;
  }
  // ANSI-C quoting: bash reads $'\x63url' as curl. The words are decoded the way bash does, then read again; as above,
  // this reading only adds a block, and only for the rules that name a program, a file or a path ($'\x73h',
  // $'.bash\x72c', $'\x72m' -rf $'\x7e').
  if (text.includes("$'")) {
    const ansiHit = checkSegments(segmentsOf(require('./hooks/policy')._decodeAnsiC(text), true), depth);
    if (ansiHit === 'pipe_to_shell' || ansiHit === 'rc_download' || ansiHit === 'rm_root_home') return ansiHit;
  }
  // Fail closed: never allow a line whose tail was not read.
  return segs.truncated && (ENABLED === null || ENABLED.size > 0) ? OVERFLOW : null;
}

/**
 * Check one shell command (Bash, sh, zsh or PowerShell text).
 * Returns the same shape as evaluate(): { verdict: 'allow' | 'block', confidence, rule, reason, engine, rules_version }.
 */
function checkCommand(command) {
  const hit = typeof command === 'string' ? analyze(command, 0) : null;
  if (!hit) return { verdict: 'allow', confidence: 1.0, rule: 'none', reason: null, engine: 'oss-local', rules_version: COMMAND_RULES_VERSION };
  return {
    verdict: 'block',
    confidence: 0.95,
    rule: 'destructive:' + hit,
    reason: 'Destructive command: ' + (REASONS[hit] || OVERFLOW_REASON),
    engine: 'oss-local',
    rules_version: COMMAND_RULES_VERSION,
  };
}

/** The deny message for the agent hooks, or null. */
function denial(command, rules) {
  if (typeof command !== 'string') return null;
  const saved = ENABLED;
  ENABLED = rules ? new Set(rules) : null;
  let hit;
  try { hit = analyze(command, 0); } finally { ENABLED = saved; }
  if (!hit) return null;
  return 'zn blocked this: ' + (REASONS[hit] || OVERFLOW_REASON) + '. Ask the user to confirm before running this command. If they want it, they can run it in their own terminal; do not run it yourself.';
}

/** The rules the agent hooks apply when the user has not changed anything. The other four are opt-in. */
const DEFAULT_RULES = ['rm_root_home', 'disk_overwrite'];

module.exports = { checkCommand, denial, DEFAULT_RULES, COMMAND_RULES_VERSION, RULES: Object.keys(REASONS).map((k) => 'destructive:' + k) };
