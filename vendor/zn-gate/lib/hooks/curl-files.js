'use strict';
/*
 * The curl checks of the pre-tool hook: which files a curl command sends (@file values, -T uploads, -K configuration
 * files, ~/.curlrc) and which files or folders a word may name through an @file reference or a curl option. policy.js
 * loads this module lazily, on the first command that can need these checks (a word naming curl, an @file or an upload
 * option), so a command that cannot need them does not load or compile it. The helpers it shares with policy.js are
 * passed in by policy.js when the module is loaded.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

module.exports = function curlFiles(deps) {
  const { ASSIGNMENT_RE, CD_CMDS, DIR_STACK_RE, GIT_WRAPPERS, REDIRECT_OP_WORD_RE, bareHead, expandHome, programName, skipWrapper, slash } = deps;
/* Shell words that can stand before a command in the same simple command (then curl ..., ! curl ...). */
const PROGRAM_KEYWORDS = new Set(['then', 'do', 'else', '!', '{', 'if', 'while', 'until', 'elif']);

/* The program a simple command runs: the first word that is not an assignment, a shell keyword or a wrapper (sudo, env,
   nohup, timeout 5, stdbuf -o0...: the shared GIT_WRAPPERS table, with their options and values skipped by skipWrapper).
   Returns {name, at} (the lower-case name without .exe, and its index in `group`) or null. */
function programOfGroup(group) {
  let k = 0;
  for (let guard = 0; guard < 64 && k < group.length; guard++) {
    const t = String(group[k].text).replace(/^\(+/, '');
    if (!t || ASSIGNMENT_RE.test(t) || PROGRAM_KEYWORDS.has(t)) { k++; continue; }
    const name = programName(t.replace(/^[\\]+/, ''));
    if (Object.prototype.hasOwnProperty.call(GIT_WRAPPERS, name)) { k = skipWrapper(group, k, name); continue; }
    if (name === 'coproc') { k = afterCoprocName(group, k + 1); continue; }
    return { name, at: k };
  }
  // The guard ran out with words left (dozens of assignments or wrappers): the program is unknown, so every word is
  // read as curl's would be (fail closed).
  return k < group.length ? { name: 'curl', at: -1 } : null;
}

/* The words after `curl` in a command are marked (`curl`), and the one after --data-urlencode or --variable (`urlencode`):
   they may name a file to send as `@file`, `name=@file`, `name=<file` or `name@file`. */
/* A curl -K / --config value zn cannot read before curl does: standard input, a pipe or file descriptor, a process
   substitution, or a value built at run time. Its options (upload-file, data @file) could send any file, so the
   command is refused whatever the configuration holds (fail closed by structure, not by listing spellings). */
function curlConfigUnreadable(v) {
  const t = String(v).replace(/^["']+|["']+$/g, '');
  return t === '' || t === '-' || /^\/dev\/(?:stdin|fd\/)|^\/proc\/(?:self|\d+)\/fd\//.test(t) || t.startsWith('<(') ||
    t.startsWith('>(') || /[$`]/.test(t);
}

const CURL_CONFIG_MAX_BYTES = 1 << 20;
/* A curl configuration file named on the command line or read by default (~/.curlrc): resolved like curl opens it.
   Returns {content} for a regular file zn could read, or {refuse: true} for anything else: a path under /dev or
   /proc (however it is spelled: //dev/stdin, /dev/./stdin, ../../dev/stdin, /proc/thread-self/fd/0), a link or a
   fifo that leads there, a file that does not exist yet (written by this same command) or cannot be read. */
const CURL_CONFIG_DEPTH = 4;
// curl's short options that read a file or name one to send, as used in a configuration file (-T .env, -d @.env).
const CURL_SHORT_FILE_OPTS = { T: 'upload-file', K: 'config', d: 'data', F: 'form', H: 'header' };

/* The folders a relative path in a curl command may be opened from: the working folder and every place a cd in the
   command may lead to. null when a cd goes somewhere zn cannot follow. */
function curlBaseDirs(opts) {
  const cwd = path.resolve(opts.cwd || process.cwd());
  const bases = opts.cdBases;
  if (bases && bases.unknown) return null;
  const dirs = new Set([cwd]);
  if (bases && bases.dirs) for (const d of bases.dirs) dirs.add(path.resolve(d));
  return [...dirs];
}

function curlConfigFile(v, opts, depth = 0) {
  const t = String(v).replace(/^["']+|["']+$/g, '');
  if (curlConfigUnreadable(t) || /^~[+-]?[1-9]/.test(t)) return { refuse: true };
  const home = opts.home || os.homedir();
  const exp = expandHome(t, home);
  let cands;
  if (path.isAbsolute(exp)) cands = [path.resolve(exp)];
  else {
    const dirs = curlBaseDirs(opts);
    if (!dirs) return { refuse: true };
    cands = dirs.map((d) => path.resolve(d, exp));
  }
  const special = (q) => /^[\\/](?:dev|proc)(?:[\\/]|$)/.test(slash(q));
  const items = [];
  const paths = [];
  let found = 0;
  for (const abs of cands) {
    if (special(abs)) return { refuse: true };
    let real;
    try { real = fs.realpathSync(abs); } catch (_) {
      // A file that does not exist where curl may run: refused when it exists nowhere (written by this command).
      try { fs.lstatSync(abs); return { refuse: true }; } catch (_) { continue; }
    }
    if (special(real)) return { refuse: true };
    let content;
    try {
      const st = fs.statSync(real);
      if (!st.isFile() || st.size > CURL_CONFIG_MAX_BYTES) return { refuse: true };
      content = fs.readFileSync(real, 'utf8');
    } catch (_) {
      return { refuse: true };
    }
    found++;
    paths.push(abs, real);
    const parsed = parseCurlConfig(content, opts, depth);
    if (parsed.refuse) return { refuse: true };
    items.push(...parsed.items);
    paths.push(...parsed.paths);
    items.raw = (items.raw || []).concat([content], parsed.items.raw || []);
  }
  if (!found) return { refuse: true };
  return { items, paths, content: (items.raw || []).join('\n') };
}

/* The options of a curl configuration file, read the way curl reads them: one option per line (with or without
   leading dashes; a short option may hold its value, -T.env), then spaces, '=' or ':' and the value; a value in double
   quotes ends at the next quote, \t \n \r \v are control characters and any other \X is X. A config line is followed
   (to a depth of four); variable and expand-* lines are refused, since zn does not follow curl's variables there. */
function parseCurlConfig(content, opts, depth) {
  const items = [];
  const paths = [];
  items.raw = [];
  for (const line of String(content).split(/\r?\n|\r/)) {
    const s = line.replace(/^\s+/, '');
    if (!s || s[0] === '#') continue;
    let k = 0;
    while (k < s.length && !/[\s=:]/.test(s[k])) k++;
    const opt = s.slice(0, k);
    const rest = s.slice(k).replace(/^[\s=:]+/, '');
    let val = '';
    if (rest[0] === '"') {
      for (let q = 1; q < rest.length && rest[q] !== '"'; q++) {
        if (rest[q] === '\\' && q + 1 < rest.length) {
          q++;
          const c = rest[q];
          val += c === 't' ? '\t' : c === 'n' ? '\n' : c === 'r' ? '\r' : c === 'v' ? '\v' : c;
        } else {
          val += rest[q];
        }
      }
    } else {
      val = /^\S*/.exec(rest)[0];
    }
    const named = [];
    if (opt.startsWith('--')) named.push([opt.slice(2), val]);
    else if (opt.startsWith('-')) {
      for (let q = 1; q < opt.length; q++) {
        const long = CURL_SHORT_FILE_OPTS[opt[q]];
        if (long) { named.push([long, opt.slice(q + 1) || val]); break; }
      }
    } else {
      named.push([opt, val]);
    }
    for (const [name, value] of named) {
      if (name === 'variable' || name.startsWith('expand-')) return { refuse: true };
      if (name === 'config') {
        if (depth + 1 >= CURL_CONFIG_DEPTH) return { refuse: true };
        const sub = curlConfigFile(value, opts, depth + 1);
        if (sub.refuse) return { refuse: true };
        items.push(...sub.items);
        paths.push(...sub.paths);
        items.raw.push(...(sub.items.raw || []));
        continue;
      }
      items.push({ name, value });
    }
  }
  return { items, paths };
}

/* The expansions of one word of a command that may rewrite a curl configuration. $HOME and ${HOME} are the home folder.
   ${NAME:-literal} and ${NAME-literal} of a variable that zn does not track, with a plain literal default, are that
   literal. $PWD and ${PWD} stay for the caller. Every other expansion (positional and special parameters, a variable
   zn does not resolve, a variable with an operator, ${HOME:-x}, ${PWD:-x}, a default that holds another expansion such
   as ${a:-${b}}) may be empty or any folder: it becomes a marker. ${...} is read to its matching brace; a ${ that is
   never closed makes the rest of the word unknown. `marked` is the word with its markers; in `text` and `lead` each
   marker is `*`. A word that starts with a marker is a leading expansion, returned as `lead` with the text that
   follows it. { refuse: true } for $OLDPWD, which zn cannot follow. */
const UNKNOWN_EXP = '\u0001';
const OLDPWD_RE = /(?:^|\$\{?)OLDPWD(?![A-Za-z0-9_])/;
function expansionValue(inner) {
  if (OLDPWD_RE.test(inner)) return null;
  if (/^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*])$/.test(inner)) return inner === 'PWD' || inner === 'ZN_HOME' ? '${' + inner + '}' : UNKNOWN_EXP;
  const m = /^([A-Za-z_][A-Za-z0-9_]*)(?::?-)([A-Za-z0-9_.\/-]*)$/.exec(inner);
  if (m && !/^(?:HOME|PWD|OLDPWD)$/.test(m[1])) return m[2];
  return UNKNOWN_EXP;
}
function resolveWordExpansions(c, home) {
  // ~- (and ~-0) is $OLDPWD, which zn cannot follow: refused like the variable.
  if (/(?:^|[=:])~-0?(?=$|[\\/])/.test(String(c))) return { refuse: true };
  const src = String(c).replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g, () => home);
  if (!src.includes('$')) return { text: src, marked: src };
  let out = '';
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch !== '$') { out += ch; i++; continue; }
    if (src[i + 1] === '{') {
      let depth = 1;
      let j = i + 2;
      for (; j < src.length; j++) {
        if (src[j] === '{') depth++;
        else if (src[j] === '}' && --depth === 0) break;
      }
      if (depth > 0) {
        if (OLDPWD_RE.test(src.slice(i + 2))) return { refuse: true };
        out += UNKNOWN_EXP;
        break;
      }
      const v = expansionValue(src.slice(i + 2, j));
      if (v === null) return { refuse: true };
      out += v;
      i = j + 1;
      continue;
    }
    const bare = /^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*])/.exec(src.slice(i + 1));
    if (!bare) { out += ch; i++; continue; }
    const name = bare[0];
    if (name === 'OLDPWD') return { refuse: true };
    out += name === 'PWD' || name === 'ZN_HOME' ? '$' + name : UNKNOWN_EXP;
    i += 1 + name.length;
  }
  if (!out.includes(UNKNOWN_EXP)) return { text: out, marked: out };
  if (out.startsWith(UNKNOWN_EXP)) return { lead: out.replace(/^\u0001+/, '').replace(/\u0001/g, '*'), marked: out, unknown: true };
  return { text: out.replace(/\u0001/g, '*'), marked: out, unknown: true };
}

/* Whether the last name of a path (with its markers, see resolveWordExpansions) may be one of `names`. A path that ends
   in a folder (x/, x/., x/..) names no file. `loose`: a name with an unresolved expansion or a wildcard may be any
   name; otherwise only the name as written (each item of a {a,b} list) counts. */
function lastNameMayBe(marked, names, loose) {
  const s = slash(String(marked));
  if (!s || s.endsWith('/')) return false;
  const seg = s.slice(s.lastIndexOf('/') + 1);
  if (seg === '.' || seg === '..') return false;
  if (/[\u0001*?[]/.test(seg)) return loose;
  const list = seg.includes('{') ? braceNames(seg) : [seg];
  if (list === null) return loose;
  return list.some((n) => names.has(n));
}

// Programs that copy, move or link files into a destination, and the short options of each that take a value.
const COPY_PROGS_RE = /^(?:cp|mv|install|ln|rsync|gcp|gmv|ginstall|gln)$/;
const COPY_SHORT_VALUES = { install: 'Smog', ginstall: 'Smog', rsync: 'efBMT', cp: 'S', gcp: 'S', mv: 'S', gmv: 'S', ln: 'S', gln: 'S' };
const COPY_LONG_VALUES = new Set(['--suffix', '--mode', '--owner', '--group', '--rsh', '--exclude', '--include', '--filter',
  '--files-from', '--exclude-from', '--include-from', '--password-file', '--log-file', '--rsync-path', '--partial-dir',
  '--compare-dest', '--link-dest', '--copy-dest', '--temp-dir', '--block-size', '--remote-option', '--chmod', '--chown',
  '--backup-dir', '--out-format', '--max-size', '--min-size', '--timeout', '--bwlimit', '--info', '--debug', '--iconv']);
const TAR_SHORT_VALUES = 'fCTXbHINgKLV';

/* The words of a command that are the destination of a write and hold an expansion zn does not resolve, where that write
   can put a curl configuration in place (`names`: the file names a configuration may have): a redirect target (> and
   >>), a tee file, dd of=, a sed -i file, the folder an archive is extracted into (tar -x -C, unzip -d, 7z -o), and the
   destination of cp, mv, install, ln and rsync when the copy is recursive (cp -r/-a, rsync -r/-a), moves a folder,
   names a source that may be a configuration (its name is one of `names`, or holds an unresolved expansion or a
   wildcard) or names a destination file that may be one. Words are judged by where they sit in the command, never by
   the folders the expansion might stand for. */
/* The [word, value] pairs of the file that curl -o/--output or wget -O/--output-document writes. `args` are the words
   after the program. Fail closed on short options: when the output letter appears anywhere in a short cluster (-so,
   -ao, -pO, -nvO), the text after it and the next word are both taken as the file, whatever the other letters are. */
function outputTargets(args, prog) {
  const res = [];
  const short = prog === 'curl' ? 'o' : 'O';
  const longRe = prog === 'curl' ? /^--out(?:p(?:u(?:t)?)?)?(?:=(.*))?$/ : /^--output-d[a-z]*(?:=(.*))?$/;
  for (let k = 0; k < args.length; k++) {
    const t = String(args[k].text);
    if (t === '--') break;
    if (/^--/.test(t)) {
      const m = longRe.exec(t);
      if (!m) continue;
      if (m[1] !== undefined) res.push([args[k], m[1]]);
      else if (args[k + 1]) { res.push([args[k + 1], String(args[k + 1].text)]); k++; }
      continue;
    }
    if (!/^-./.test(t)) continue;
    const at = t.indexOf(short, 1);
    if (at < 0) continue;
    const rest = t.slice(at + 1);
    if (rest) res.push([args[k], rest]);
    if (args[k + 1]) res.push([args[k + 1], String(args[k + 1].text)]);
  }
  return res;
}

/* Compound commands can start behind `time` (with its -p and --) and `coproc` (with its optional name): `time -p for ...`,
   `coproc NAME { while ...; }`. leadingKeyword is the first word of a command that is not one of those prefixes. */
const COPROC_COMPOUND_START = /^(?:\{|\(|for|while|until|if|case|select)$/;
// Index of the word after `coproc`: its name is skipped only when a compound command follows it.
function afterCoprocName(group, k) {
  if (k + 1 < group.length && /^[A-Za-z_][A-Za-z0-9_]*$/.test(String(group[k].text)) &&
      COPROC_COMPOUND_START.test(String(group[k + 1].text))) return k + 1;
  return k;
}
function leadingKeyword(group) {
  let k = 0;
  while (k < group.length) {
    const t = String(group[k].text).replace(/^[({]+/, '');
    if (!t || ASSIGNMENT_RE.test(t) || /^(?:then|do|else|elif|if|!|\{)$/.test(t)) { k++; continue; }
    if (t === 'time') {
      k++;
      while (k < group.length && /^-/.test(String(group[k].text))) { const end = String(group[k].text) === '--'; k++; if (end) break; }
      continue;
    }
    if (t === 'coproc') { k = afterCoprocName(group, k + 1); continue; }
    return t;
  }
  return '';
}

function unresolvedConfigDestinations(readings, names, opts) {
  const out = new Set();
  const home = opts.home || os.homedir();
  const cwd = path.resolve(opts.cwd || process.cwd());
  const unknown = (v) => { const rr = resolveWordExpansions(v, home); return rr.refuse || rr.unknown ? rr : null; };
  for (const r of readings) {
    const groups = [];
    for (let i = 0; i < r.length;) {
      let j = i;
      while (j < r.length && r[j].seq === r[i].seq) j++;
      const group = r.slice(i, j);
      groups.push({ group, prog: programOfGroup(group) });
      i = j;
    }
    const curls = groups.filter((g) => g.prog && g.prog.name === 'curl').length;
    // Which groups sit inside a for/while/until loop: the curl of an earlier pass can write what a later pass reads.
    let loopDepth = 0;
    for (const g of groups) {
      // The first word that is not an assignment or a reserved word that can stand in front of a command.
      const first = leadingKeyword(g.group);
      if (/^(?:for|while|until|select)$/.test(first)) loopDepth++;
      g.inLoop = loopDepth > 0;
      if (first === 'done') loopDepth = Math.max(0, loopDepth - 1);
    }
    const lastCurl = groups.reduce((acc, g, k) => (g.prog && g.prog.name === 'curl' ? k : acc), -1);
    for (let gi = 0; gi < groups.length; gi++) {
      const { group, prog, inLoop } = groups[gi];
      const readsConfig = !!prog && prog.name === 'curl' &&
        group.some((w) => w.curlCfgValue || /^-[A-Za-z0-9#:]*K|^--config(?:=|$)/.test(String(w.text)));
      // The shell opens a redirect of curl's own command before curl starts: it can empty that curl's configuration
      // but not give it options. That only matters when no other curl in the command reads the file afterwards, and
      // not when the command loops (the next pass reads what the last one wrote) or that curl reads a -K file.
      const ownCurl = curls === 1 && !inLoop && !readsConfig && prog && prog.name === 'curl' && prog.at >= 0;
      if (!ownCurl) for (const w of group) if (w.redirectTarget && unknown(String(w.text))) out.add(w);
      if (!prog || prog.at < 0) continue;
      const name = prog.name;
      const args = group.slice(prog.at + 1).filter((w) => !w.redirectTarget && !REDIRECT_OP_WORD_RE.test(String(w.text)));
      const txt = (w) => String(w.text);
      const dest = (w, v) => { if (unknown(v)) out.add(w); };
      if (name === 'tee') {
        // `curl ... | tee FILE` only takes curl's own output: that curl has already read its configuration, so FILE
        // cannot change it unless the command loops or another curl runs after it.
        // The scanner ends a command at the & of `2>&1`, so the pipe may follow a lone fd word (`curl ... 2>&1 | tee F`).
        let pi = gi - 1;
        const fdWord = (g) => g && g.group.length === 1 && /^[0-9]+$/.test(String(g.group[0].text));
        if (fdWord(groups[pi]) && pi > 0 && groups[pi - 1].group[0].seq === groups[pi].group[0].seq - 1 &&
            groups[pi - 1].group[groups[pi - 1].group.length - 1].opAfter === '&') pi--;
        const prev = groups[pi];
        const fed = !!prev && !!prev.prog && prev.prog.name === 'curl' && !inLoop && !prev.inLoop && gi > lastCurl &&
          prev.group[0].seq === groups[gi - 1].group[0].seq - (gi - 1 - pi) &&
          groups[gi - 1].group[groups[gi - 1].group.length - 1].opAfter === '|' &&
          groups[gi - 1].group[0].seq === group[0].seq - 1;
        if (!fed) for (const w of args) if (!/^-/.test(txt(w))) dest(w, txt(w));
      } else if (name === 'curl' || name === 'wget') {
        // curl -o/--output and wget -O/--output-document write a file when the download ends. A lone curl has read its
        // configuration by then (unless the command loops or it reads a -K file); any other curl may read the file.
        if (!(name === 'curl' && curls === 1 && !inLoop && !readsConfig)) for (const [w, v] of outputTargets(args, name)) dest(w, v);
      } else if (name === 'dd') {
        for (const w of args) if (/^of=/.test(txt(w))) dest(w, txt(w).slice(3));
      } else if (/^g?sed$/.test(name)) {
        let inPlace = false;
        let script = false;
        const files = [];
        let ended = false;
        for (let k = 0; k < args.length; k++) {
          const t = txt(args[k]);
          if (!ended && t === '--') { ended = true; continue; }
          if (!ended && /^--/.test(t)) {
            if (/^--in-place/.test(t)) inPlace = true;
            if (/^--(?:expression|file)(?:=|$)/.test(t)) { script = true; if (!t.includes('=')) k++; }
            continue;
          }
          if (!ended && /^-./.test(t)) {
            for (let q = 1; q < t.length; q++) {
              if (t[q] === 'i') { inPlace = true; break; }
              if ('efl'.includes(t[q])) { if (t[q] !== 'l') script = true; if (q === t.length - 1) k++; break; }
            }
            continue;
          }
          if (!script) { script = true; continue; }
          files.push(args[k]);
        }
        if (inPlace) for (const w of files) dest(w, txt(w));
      } else if (/^(?:tar|gtar|bsdtar)$/.test(name)) {
        let extract = false;
        const dirs = [];
        for (let k = 0; k < args.length; k++) {
          const t = txt(args[k]);
          if (/^--(?:extract|get)$/.test(t)) { extract = true; continue; }
          if (/^--directory=/.test(t)) { dirs.push([args[k], t.slice(12)]); continue; }
          if (t === '--directory') { if (args[k + 1]) dirs.push([args[k + 1], txt(args[k + 1])]); k++; continue; }
          if (/^--/.test(t)) continue;
          const cluster = t.startsWith('-') ? t.slice(1) : (k === 0 ? t : '');
          for (let q = 0; q < cluster.length; q++) {
            if (cluster[q] === 'x') extract = true;
            if (TAR_SHORT_VALUES.includes(cluster[q])) {
              if (!t.startsWith('-')) continue;
              const rest = cluster.slice(q + 1);
              if (cluster[q] === 'C') dirs.push(rest ? [args[k], rest] : [args[k + 1], args[k + 1] ? txt(args[k + 1]) : '']);
              if (!rest) k++;
              break;
            }
          }
        }
        if (extract) for (const [w, v] of dirs) if (w) dest(w, v);
      } else if (/^(?:unzip|funzip|bsdunzip)$/.test(name)) {
        for (let k = 0; k < args.length; k++) {
          const t = txt(args[k]);
          if (!/^-[^-]/.test(t)) continue;
          for (let q = 1; q < t.length; q++) {
            if (t[q] === 'd' || t[q] === 'P') {
              const rest = t.slice(q + 1);
              if (t[q] === 'd') { if (rest) dest(args[k], rest); else if (args[k + 1]) dest(args[k + 1], txt(args[k + 1])); }
              if (!rest) k++;
              break;
            }
          }
        }
      } else if (/^(?:7z|7za|7zr|7zz)$/.test(name)) {
        for (const w of args) if (/^-o./.test(txt(w))) dest(w, txt(w).slice(2));
      } else if (COPY_PROGS_RE.test(name)) {
        const base = name.replace(/^g(?=cp|mv|install|ln)/, '');
        const shortValues = COPY_SHORT_VALUES[name] || '';
        let recursive = false;
        let dirsOnly = false;
        let target = null;
        const operands = [];
        let ended = false;
        for (let k = 0; k < args.length; k++) {
          const t = txt(args[k]);
          if (!ended && t === '--') { ended = true; continue; }
          if (!ended && /^--/.test(t)) {
            if (/^--(?:recursive|archive)$/.test(t) && (base === 'cp' || base === 'rsync')) recursive = true;
            if (t === '--directory' && base === 'install') dirsOnly = true;
            if (/^--target-directory=/.test(t)) target = [args[k], t.slice(19)];
            else if (t === '--target-directory') { if (args[k + 1]) target = [args[k + 1], txt(args[k + 1])]; k++; }
            else if (COPY_LONG_VALUES.has(t)) k++;
            continue;
          }
          if (!ended && /^-./.test(t)) {
            for (let q = 1; q < t.length; q++) {
              const c = t[q];
              if ((c === 'r' || c === 'R' || c === 'a') && (base === 'cp' || base === 'rsync')) recursive = true;
              if (c === 'd' && base === 'install') dirsOnly = true;
              if (c === 't' && base !== 'rsync') {
                const rest = t.slice(q + 1);
                if (rest) target = [args[k], rest];
                else { if (args[k + 1]) target = [args[k + 1], txt(args[k + 1])]; k++; }
                break;
              }
              if (shortValues.includes(c)) { if (q === t.length - 1) k++; break; }
            }
            continue;
          }
          operands.push(args[k]);
        }
        if (dirsOnly) continue;
        let destWord;
        let destValue;
        let sources;
        if (target) { [destWord, destValue] = target; sources = operands; }
        else {
          if (operands.length < 2) continue;
          destWord = operands[operands.length - 1];
          destValue = txt(destWord);
          sources = operands.slice(0, -1);
        }
        const rd = unknown(destValue);
        if (!rd) continue;
        // rsync to another host (host:path) writes nothing here.
        if (base === 'rsync' && /^[^/]*:/.test(slash(rd.marked || destValue))) continue;
        const sourceMayBe = sources.some((s) => {
          const v = txt(s);
          const rs = resolveWordExpansions(v, home);
          if (rs.refuse) return true;
          if (lastNameMayBe(rs.marked, names, true)) return true;
          // mv moves a folder with everything in it.
          if (base === 'mv' && (/[\\/]$/.test(v) || folderExists(rs.text, home, cwd))) return true;
          return false;
        });
        if (recursive || sourceMayBe || (!target && lastNameMayBe(rd.marked, names, true))) out.add(destWord);
      }
    }
  }
  return out;
}

function folderExists(p, home, cwd) {
  if (!p || /[*?[{$]/.test(p)) return false;
  try { return fs.statSync(path.resolve(cwd, expandHome(p, home))).isDirectory(); } catch (_) { return false; }
}

/* pathsNamedElsewhere answers this when the only reason is a write to a place built from an expansion zn does not
   resolve, so the denial can say how to avoid it. */
const NAMED_THROUGH_EXPANSION = 'expansion';
// The names curl reads its default configuration from.
const CURL_CONFIG_NAMES = ['.curlrc', '_curlrc', 'curlrc'];

/* True when a word of the command other than curl's own -K/--config value (and other than a cd target) may name one
   of the given paths, so the command may write that file before curl reads it: the path itself (cat > cfg <<EOF, cp,
   mv, ln -sf, sed -i, dd of=cfg), a folder that holds it (cp evil.cfg x/, cp -r dir/. ~/, rsync, cp -t x) or a
   pattern that may match it (stat*.cfg, static.{cfg,x}, x/*, ~/.c*). NAMED_THROUGH_EXPANSION when a write goes to a
   destination built from an expansion zn does not resolve and can put a configuration there (see
   unresolvedConfigDestinations), or a word that starts with such an expansion ends in a configuration's name. */
function pathsNamedElsewhere(readings, paths, opts) {
  if (!paths.length) return false;
  const want = [...new Set(paths.map((q) => path.resolve(q)))];
  const wantSet = new Set(want);
  const home = opts.home || os.homedir();
  const dirs = curlBaseDirs(opts) || [path.resolve(opts.cwd || process.cwd())];
  const names = new Set([...CURL_CONFIG_NAMES, ...want.map((q) => path.basename(q))]);
  const receivers = unresolvedConfigDestinations(readings, names, opts);
  const holds = (abs) => {
    if (wantSet.has(abs)) return true;
    const pre = abs.endsWith(path.sep) ? abs : abs + path.sep;
    return want.some((q) => q.startsWith(pre));
  };
  const at = (c) => {
    const exp = expandHome(c, home);
    return path.isAbsolute(exp) ? [path.resolve(exp)] : dirs.map((d) => path.resolve(d, exp));
  };
  for (const r of readings) {
    for (let wi = 0; wi < r.length; wi++) {
      const w = r[wi];
      if (w.curlCfgValue) continue;
      if (CD_CMDS.has(bareHead(w.head).toLowerCase())) continue;
      if (receivers.has(w)) return NAMED_THROUGH_EXPANSION;
      const t = String(w.text).replace(/^["']+|["']+$/g, '');
      if (!t || /^[a-z][a-z0-9+.-]*:\/\//i.test(t)) continue;
      // A bare / is what a destination built from an expansion becomes in the readings that drop the expansion; that
      // destination was judged above (receivers), and the root folder itself holds no project configuration.
      if (t === '/') continue;
      let cands = new Set();
      if (/^-/.test(t)) {
        // An option that holds a folder: --target-directory=DIR, --directory=DIR, and a glued short option of the
        // programs that write into a folder (cp/mv/install/ln -tDIR, tar -CDIR).
        const eq = t.indexOf('=');
        if (eq > 0) cands.add(t.slice(eq + 1));
        const prog = path.basename(bareHead(w.head)).toLowerCase();
        let m;
        if (/^(?:cp|mv|install|ln|gcp|gmv|ginstall|gln)$/.test(prog) && (m = /^-[A-Za-z]*?t(.+)$/.exec(t))) cands.add(m[1]);
        if (/^(?:tar|gtar|bsdtar)$/.test(prog) && (m = /^-[A-Za-z]*?C(.+)$/.exec(t))) cands.add(m[1]);
        // archive extraction into a folder: unzip -dDIR, 7z x -oDIR
        if (/^(?:unzip|funzip|bsdunzip)$/.test(prog) && (m = /^-[A-Za-z]*?d(.+)$/.exec(t))) cands.add(m[1]);
        if (/^(?:7z|7za|7zr|7zz)$/.test(prog) && (m = /^-o(.+)$/.exec(t))) cands.add(m[1]);
        if (!cands.size) continue;
      } else {
        cands.add(t);
        const eq = t.indexOf('=');
        if (eq >= 0) { cands.add(t.slice(eq + 1)); cands.add(t.slice(t.lastIndexOf('=') + 1)); }
      }
      // $PWD and ${PWD} are the folder the command is in (each place a cd may lead to); $OLDPWD is not known, so a word
      // that names a folder through it is taken to name the configuration.
      if ([...cands].some((c) => /\$\{?OLDPWD\b/.test(c))) return true;
      // Expansions of variables zn does not resolve (${HOME:-~}, ${PWD%/}, ${!v}, ${1:-.}, ${@}, $zz, ${a:-${b}}): an
      // unset variable is empty, so they may name any folder. A write into such a place was judged above by where it
      // sits in the command. A word that starts with one is otherwise only refused when it ends in a configuration's
      // name; an expansion glued after other text becomes a wildcard there. A default that is a plain literal
      // (${DIR:-.}) is that literal.
      {
        const next = new Set();
        for (const c of cands) {
          const rr = resolveWordExpansions(c, home);
          if (rr.refuse) return true;
          if (rr.lead === undefined) { next.add(rr.text); continue; }
          if (lastNameMayBe(rr.marked, names, false)) return NAMED_THROUGH_EXPANSION;
        }
        cands = next;
      }
      for (const c of [...cands]) {
        if (!/\$\{?PWD\b/.test(c)) continue;
        cands.delete(c);
        for (const d of dirs) cands.add(c.replace(/\$\{PWD\}|\$PWD\b/g, d));
      }
      for (const c0 of cands) {
        if (!c0) continue;
        const named = c0.includes('{') ? (braceNames(c0) || [c0]) : [c0];
        for (const c of named) {
          const g = c.search(/[*?[]/);
          if (g >= 0) {
            // a pattern: the folder before the first wildcard holds every name it can match
            const cut = c.slice(0, g);
            const slashAt = Math.max(cut.lastIndexOf('/'), cut.lastIndexOf('\\'));
            const dir = slashAt >= 0 ? cut.slice(0, slashAt + 1) : '.';
            for (const a of at(dir)) if (holds(a)) return true;
            continue;
          }
          for (const a of at(c)) {
            if (holds(a)) return true;
            if (want.some((q) => path.basename(q) === path.basename(a))) {
              try { if (wantSet.has(fs.realpathSync(a))) return true; } catch (_) { /* not there */ }
            }
          }
        }
      }
    }
  }
  return false;
}

function curlConfigNamedElsewhere(readings, paths, opts) {
  return pathsNamedElsewhere(readings, paths, opts);
}

/* The files curl looks for as its default configuration, in curl's own search order (whether they exist or not):
   .curlrc in CURL_HOME, then curlrc in XDG_CONFIG_HOME, then .curlrc in HOME; on Windows also _curlrc and .curlrc in
   USERPROFILE, APPDATA and USERPROFILE\Application Data, and last the folder of the curl program itself. zn models
   every one of those names and folders on every system (a stray file there is only checked, never run), so a default
   file with -T .env cannot send a protected file without an option on the command line. curlProgram is the word the
   command runs: a path gives its folder; a bare name is searched in PATH. A curl zn cannot find adds no folder. */
function curlDefaultConfigPlaces(opts, curlProgram) {
  const env = opts.env || process.env;
  const home = opts.home || os.homedir();
  const dirs = [home, path.join(home, 'Application Data')];
  for (const k of ['CURL_HOME', 'HOME', 'USERPROFILE', 'APPDATA']) if (env[k]) dirs.push(String(env[k]));
  if (env.USERPROFILE) dirs.push(path.join(String(env.USERPROFILE), 'Application Data'));
  if (env.HOMEDRIVE && env.HOMEPATH) dirs.push(String(env.HOMEDRIVE) + String(env.HOMEPATH));
  const exe = curlExecutableDir(env, opts.cwd || process.cwd(), curlProgram);
  if (exe) dirs.push(exe);
  const out = [path.join(home, '.config', 'curlrc')];
  if (env.XDG_CONFIG_HOME) out.push(path.join(String(env.XDG_CONFIG_HOME), 'curlrc'));
  for (const d of new Set(dirs)) for (const n of ['.curlrc', '_curlrc']) out.push(path.join(d, n));
  return [...new Set(out)];
}

/* The folder of the curl program a command runs: the folder of a path, or the first PATH folder holding curl or
   curl.exe. null when it cannot be found. */
function curlExecutableDir(env, cwd, program) {
  const word = program ? String(program).replace(/^["']+|["']+$/g, '') : '';
  if (/[\/]/.test(word) && !/[$`]/.test(word)) return path.dirname(path.resolve(cwd, word));
  const sepRe = process.platform === 'win32' ? /;/ : /:/;
  for (const d of String(env.PATH || env.Path || '').split(sepRe)) {
    if (!d) continue;
    for (const n of ['curl', 'curl.exe']) {
      try { if (fs.statSync(path.join(d, n)).isFile()) return path.resolve(cwd, d); } catch (_) { /* not here */ }
    }
  }
  return null;
}

/* A small file read for a curl --variable name@file: its content, or null when zn cannot read it. */
function curlVariableFile(f, opts) {
  const t = String(f).replace(/^["']+|["']+$/g, '');
  if (!t || t === '-' || /[$`]/.test(t) || /^~[+-]?[1-9]/.test(t)) return null;
  const exp = expandHome(t, opts.home || os.homedir());
  if (!path.isAbsolute(exp) && opts.cdBases && opts.cdBases.moved) return null;
  const abs = path.resolve(opts.cwd || process.cwd(), exp);
  try {
    const real = fs.realpathSync(abs);
    if (/^[\\/](?:dev|proc)(?:[\\/]|$)/.test(slash(real))) return null;
    const st = fs.statSync(real);
    if (!st.isFile() || st.size > CURL_CONFIG_MAX_BYTES) return null;
    return fs.readFileSync(real, 'utf8');
  } catch (_) {
    return null;
  }
}

/* The configuration files curl reads by default (unless -q/--disable is its first argument), that exist now. */
function curlDefaultConfigs(opts, curlProgram) {
  return curlDefaultConfigPlaces(opts, curlProgram).filter((f) => { try { return fs.statSync(f).isFile(); } catch (_) { return false; } });
}

/* True when this command names a curlrc anywhere but as an argument curl reads: a redirect target, a word of
   another command (printf ... | tee ~/.curlrc, cp x ~/.curlrc) or the output of curl -o. */
function curlrcWritten(readings, group) {
  const seq = group[0] ? group[0].seq : null;
  for (const r of readings) {
    for (let k = 0; k < r.length; k++) {
      const w = r[k];
      if (!/curlrc/i.test(String(w.text))) continue;
      if (w.redirectTarget || w.seq !== seq) return true;
      const prev = r[k - 1] ? String(r[k - 1].text) : '';
      if (/^(?:-[A-Za-z0-9#:]*o|--output|--output-dir|--dump-header|-D|--trace|--trace-ascii|--stderr|-c|--cookie-jar)$/.test(prev) || /^--(?:output|output-dir|dump-header|trace|trace-ascii|stderr|cookie-jar)=/.test(String(w.text))) return true;
    }
  }
  return false;
}

/* True when a word of the command (as the shell reads it: quotes and backslashes removed) sets CURL_HOME,
   XDG_CONFIG_HOME or HOME: env "CURL_HOME=x", export CURL_\HOME=x, declare -x 'HOME=x'. */
function curlHomeChanged(readings) {
  for (const r of readings) {
    for (const w of r) {
      const t = String(w.text).replace(/\\(.)/g, '$1').replace(/["']/g, '');
      if (/^(?:CURL_HOME|XDG_CONFIG_HOME|HOME|USERPROFILE|APPDATA|HOMEDRIVE|HOMEPATH)\+?=/i.test(t)) return true;
    }
  }
  return false;
}

/* Marks, in every reading, the words that are curl's own -K/--config values (glued or apart), so that another word
   naming the same file can be told from them. */
function markCurlConfigValues(readings) {
  for (const r of readings) {
    let i = 0;
    while (i < r.length) {
      let j = i;
      while (j < r.length && r[j].seq === r[i].seq) j++;
      const group = r.slice(i, j);
      const prog = programOfGroup(group);
      if (prog && prog.name === 'curl') {
        for (let m = prog.at + 1; m < group.length; m++) {
          const t = String(group[m].text);
          if ((/^-[A-Za-z0-9#:]*K$/.test(t) || t === '--config') && group[m + 1]) group[m + 1].curlCfgValue = true;
          else if (/^--config=/.test(t) || /^-[A-Za-z0-9#:]*?K(.+)$/.test(t)) group[m].curlCfgValue = true;
        }
      }
      i = j;
    }
  }
}

/* Marks curl's word when another word of the command may write a configuration it reads (see pathsNamedElsewhere).
   False when nothing does. */
function markConfigNamed(curlWord, why) {
  if (!why) return false;
  if (why === NAMED_THROUGH_EXPANSION) curlWord.curlConfigExpansionWrite = true;
  else curlWord.curlConfigUnreadable = true;
  return true;
}

// curl options whose value may be @file (or name=@file, name@file): the file's content is sent.
const CURL_AT_FILE_OPTS_RE = /^(?:-[A-Za-z0-9#:]*[dFH]|--data|--data-binary|--data-ascii|--data-urlencode|--json|--form|--url-query|--header)$/;

function markCurlWords(readings, opts = {}, cmdText = '') {
  markCurlConfigValues(readings);
  for (const r of readings) {
    let i = 0;
    while (i < r.length) {
      let j = i;
      while (j < r.length && r[j].seq === r[i].seq) j++;
      const group = r.slice(i, j);
      const prog = programOfGroup(group);
      if (prog && prog.name === 'curl') {
        const curlWord = group[Math.max(prog.at, 0)];
        const configs = [];
        // curl variables (--variable name=value, %ENV) for --expand-* options; a value zn does not know stays unknown.
        const vars = {};
        const envv = opts.env || process.env;
        for (let m = prog.at + 1; m < group.length; m++) {
          const t = String(group[m].text);
          const val = t === '--variable' ? (group[m + 1] ? String(group[m + 1].text) : null) : (t.startsWith('--variable=') ? t.slice(11) : null);
          if (val === null) continue;
          let mm;
          if ((mm = /^%([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$/.exec(val))) vars[mm[1]] = envv[mm[1]] !== undefined ? String(envv[mm[1]]) : (mm[2] !== undefined ? mm[2] : null);
          else if ((mm = /^([A-Za-z0-9_]+)=(.*)$/.exec(val))) vars[mm[1]] = mm[2];
          else if ((mm = /^([A-Za-z0-9_]+)@(.*)$/.exec(val))) vars[mm[1]] = curlVariableFile(mm[2], opts);   // the content of a file, or unknown
        }
        const expand = (v) => {
          let unknown = false;
          // {{name}} with its --variable value; a function ({{name:trim}}, {{name:64dec}}) or a value zn does not know
          // leaves the result unknown.
          const out = String(v).replace(/\{\{([A-Za-z0-9_]+)(:[^}]*)?\}\}/g, (x, n, fn) => {
            const val = Object.prototype.hasOwnProperty.call(vars, n) ? vars[n] : null;
            if (typeof val === 'string' && !fn) return val;
            unknown = true;
            return x;
          });
          return { out, unknown };
        };
        for (let m = prog.at + 1; m < group.length; m++) {
          const tx = String(group[m].text);
          let ex = null;
          if (/^--expand-[a-z-]+$/.test(tx) && group[m + 1]) ex = { opt: tx.slice(9), w: group[m + 1], v: String(group[m + 1].text) };
          else if (/^--expand-[a-z-]+=/.test(tx)) ex = { opt: tx.slice(9, tx.indexOf('=')), w: group[m], v: tx.slice(tx.indexOf('=') + 1) };
          if (ex) {
            const r2 = expand(ex.v);
            ex.w.expandOpt = ex.opt;
            ex.w.expanded = r2.out;
            ex.w.expandUnknown = r2.unknown;
          }
        }
        for (let m = prog.at + 1; m < group.length; m++) {
          group[m].curl = true;
          if (group[m - 1] && CURL_NAME_AT_FILE_OPTS.has(group[m - 1].text)) group[m].urlencode = true;
          if (group[m - 1] && CURL_AT_FILE_OPTS_RE.test(String(group[m - 1].text))) group[m].curlAtValue = true;
          // -T, a short-option cluster that ends in T (-sT, -vsT) or --upload-file: the next word is the file to upload.
          if (group[m - 1] && (/^-[A-Za-z0-9#:]*T$/.test(group[m - 1].text) || group[m - 1].text === '--upload-file')) group[m].upload = true;
          // -K / --config (also in a cluster, glued or with =): where curl reads more options from.
          const t = String(group[m].text);
          let cfg = null;
          if (/^-[A-Za-z0-9#:]*K$/.test(t) || t === '--config') cfg = group[m + 1] ? String(group[m + 1].text) : '';
          else if (/^--config=/.test(t)) cfg = t.slice('--config='.length);
          else if (/^-[A-Za-z0-9#:]*?K(.+)$/.test(t)) cfg = /^-[A-Za-z0-9#:]*?K(.+)$/.exec(t)[1];
          if (cfg !== null) {
            const c = curlConfigFile(cfg, opts);
            if (!markConfigNamed(curlWord, c.refuse || curlConfigNamedElsewhere(readings, c.paths, opts))) configs.push(c);
          }
        }
        // curl reads ~/.curlrc (or $CURL_HOME/.curlrc, $XDG_CONFIG_HOME/curlrc) unless -q/--disable comes first.
        const first = group[prog.at + 1] ? String(group[prog.at + 1].text) : '';
        if (first !== '-q' && first !== '--disable') {
          // A curlrc written by this command, or the folders curl looks in changed by it, cannot be checked.
          const placesNamed = pathsNamedElsewhere(readings, curlDefaultConfigPlaces(opts, curlWord.text), opts);
          if (curlrcWritten(readings, group) || curlHomeChanged(readings) || (placesNamed && placesNamed !== NAMED_THROUGH_EXPANSION) ||
            /(?:^|[\s;&|(`])(?:export\s+|declare\s+-x\s+|env\s+(?:-\S+\s+)*)?(?:CURL_HOME|XDG_CONFIG_HOME|HOME|USERPROFILE|APPDATA|HOMEDRIVE|HOMEPATH)\+?=/i.test(cmdText)) {
            curlWord.curlConfigUnreadable = true;
          } else markConfigNamed(curlWord, placesNamed);
          for (const f of curlDefaultConfigs(opts, curlWord.text)) {
            const c = curlConfigFile(f, opts);
            if (!markConfigNamed(curlWord, c.refuse || curlConfigNamedElsewhere(readings, c.paths, opts))) configs.push(c);
          }
        }
        if (configs.length) curlWord.curlConfigContents = configs;
      }
      i = j;
    }
  }
}

/* The file a curl data or form value reads: @file, name=@file and name=<file (and name@file after --data-urlencode),
   without the ;type= and ;filename= parameters of a form field. null when the value is plain data. */
function curlFileOf(value, urlencode) {
  let v = String(value);
  const named = /^[^=@<;'"]*=([@<].*)$/.exec(v);
  if (named) v = named[1];
  else if (urlencode) {
    const m = /^[^=@]*@(.+)$/.exec(v);
    if (m) v = '@' + m[1];
  }
  if (v[0] !== '@' && v[0] !== '<') return null;
  v = v.slice(1);
  if (v[0] === '"') {
    const end = v.indexOf('"', 1);
    v = v.slice(1, end > 0 ? end : undefined);
  } else {
    const semi = v.indexOf(';');
    if (semi >= 0) v = v.slice(0, semi);
  }
  return v || null;
}

/* curl options whose value may be name@file (the file's content is sent). */
const CURL_NAME_AT_FILE_OPTS = new Set(['--data-urlencode', '--url-query', '--variable']);

/* The files a word can make a program read and send, whatever the program: @file and @a,b (curl -d, -F with a list,
   gh -F, httpie), name=@file, name:=@file, name=<file, name@file (curl --data-urlencode/--url-query/--variable,
   httpie, xh; the name may hold any character but = and @: a/b@f, x:y@f, v[0-200]@f). A word with spaces (a curl
   config fed to -K -, printf 'data-binary @.env') is read piece by piece. A form field's ;type= and ;filename= and a
   trailing \n, \r or \t escape are dropped. The result is only refused when it names a protected path, so an e-mail
   address or @scope/pkg stays allowed. */
function atFilesOf(text) {
  const t = String(text);
  if (/\s/.test(t.trim())) {
    const all = [];
    for (const piece of t.split(/\s+/)) if (piece) all.push(...atFilesOf(piece));
    return all;
  }
  const out = [];
  const push = (raw) => {
    let v = String(raw).trim();
    if (v[0] === '"' || v[0] === "'") {
      const end = v.indexOf(v[0], 1);
      v = v.slice(1, end > 0 ? end : undefined);
    } else {
      const semi = v.indexOf(';');
      if (semi >= 0) v = v.slice(0, semi);
    }
    v = v.replace(/(?:\\[nrt])+$/, '').replace(/["']+$/, '');
    if (v && v !== '-') out.push(v);
  };
  const list = (raw) => { for (const part of String(raw).split(',')) push(part); };
  const word = t.trim().replace(/^["']+/, '');
  let m;
  if ((m = /^[@<](.+)$/.exec(word))) list(m[1]);
  else if ((m = /^[^=@<\s]*?(?::=@|=@|=<)(.+)$/.exec(word))) list(m[1]);
  else if ((m = /^[^=@]*@(.+)$/.exec(word))) push(m[1]);
  return out;
}

const BRACE_EXPANSION_CAP = 64;
const CURL_CONFIG_UNREADABLE_MESSAGE = 'zn: this curl command reads its options from a place zn cannot check (standard input, a pipe or a value built at run time such as -K - or -K "$VAR"; a configuration file that does not exist yet, that this command writes, or that names curl variables; or a CURL_HOME, XDG_CONFIG_HOME or HOME this command changes), so zn cannot see which files it sends, and it was blocked. Next step: write the curl options on the command line, or in a configuration file that already exists, and run curl in its own command.';
const CURL_CONFIG_EXPANSION_WRITE_MESSAGE = 'zn: this command writes to a place named by a variable zn cannot resolve, and a curl in the same command reads a configuration file (-K, or ~/.curlrc by default) that the write could replace, so zn cannot see which files curl sends, and it was blocked. Next step: give curl -q as its first option so it skips the default configuration, write the file to a fixed path, or run curl in its own command.';
const CURL_UPLOAD_UNKNOWN_MESSAGE = 'zn: this curl command uploads a file whose name is built at run time ($(...), backticks or an unknown variable), so zn cannot check it, and it was blocked. Next step: name the file to upload literally.';
const GLOB_TOO_LARGE_MESSAGE = 'zn: this command uploads files named by a pattern that stands for more names than zn checks, so it was blocked. Next step: name the files to upload one by one.';

/* The names a {..} glob stands for, as curl -T and the shell read it: every {a,b} or {x} group is replaced by each of
   its items, left to right (nested groups are read flat). null when there would be more than BRACE_EXPANSION_CAP
   names or more than BRACE_GROUP_CAP groups: the caller then refuses an upload (fail closed). A word without { is
   returned as it is. Iterative, so a word with thousands of groups costs no stack. */
const BRACE_GROUP_CAP = 256;
function braceNames(text) {
  let out = [''];
  let rest = String(text);
  for (let groups = 0; ; groups++) {
    const open = rest.indexOf('{');
    const close = open < 0 ? -1 : rest.indexOf('}', open + 1);
    if (open < 0 || close < 0) return out.map((o) => o + rest);
    if (groups >= BRACE_GROUP_CAP) return null;
    const head = rest.slice(0, open);
    const items = rest.slice(open + 1, close).replace(/\{/g, '').split(',');
    if (out.length * items.length > BRACE_EXPANSION_CAP) return null;
    const next = [];
    for (const o of out) for (const item of items) next.push(o + head + item);
    out = next;
    rest = rest.slice(close + 1);
  }
}

/* The text printf, echo -e or $'..' would produce from a word: \n \t \r \v \f, octal (\012, \0NN) and hex (\xNN)
   escapes decoded; a decoded control or space character becomes a space, so a configuration written on one line with
   escapes (printf 'silent\nupload-file .env') splits into its real lines. Only used to find extra file names to check. */
function decodeEscapes(text) {
  return String(text).replace(/\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|0[0-7]{0,3}|[1-7][0-7]{0,2}|[nrtvfab\\])/g, (m, e) => {
    let ch;
    if (e[0] === 'x') ch = String.fromCharCode(parseInt(e.slice(1), 16));
    else if (e[0] === 'u' || e[0] === 'U') {
      const cp = parseInt(e.slice(1), 16);
      ch = cp <= 0x10ffff ? String.fromCodePoint(cp) : ' ';
    }
    else if (/^[0-7]/.test(e)) ch = String.fromCharCode(parseInt(e, 8) & 255);
    else if (e === '\\') ch = '\\';
    else ch = ' ';
    return ch <= ' ' ? ' ' : ch;
  });
}

/* Upload lines in a word with spaces, as in a curl configuration fed with -K - (printf 'upload-file .env' | curl -K -):
   upload-file, --upload-file or -T, with the value after a space, = or :, or glued (-T.env, upload-file=".env"). */
function uploadNamesOf(text) {
  const pieces = String(text).trim().split(/\s+/);
  const out = [];
  const clean = (v) => String(v).replace(/^["']+/, '').replace(/(?:\\[nrt])+$/, '').replace(/["']+$/, '');
  for (let i = 0; i < pieces.length; i++) {
    const m = /^["']?(?:--upload-file|upload-file|-[A-Za-z0-9#:]*?T)(?:[=:])?(.*)$/.exec(pieces[i]);
    if (!m) continue;
    let v = m[1];
    let k = i + 1;
    if (!v) {
      v = pieces[k] || '';
      if (v === '=' || v === ':') v = pieces[++k] || '';
    }
    v = clean(v);
    if (v && v !== '-') out.push(v);
  }
  return out;
}

/* Extra words to classify, one per file a word may send (see atFilesOf), read as a read of that file. Long options
   carry it after = (--data-urlencode=k@.env); curl's short options can carry it glued (-d@.env, -Ff=@.env, -T.env,
   -sT{.env}, -H@file). Every name is also read through its {..} glob (curl -T .e{nv}). Returns null when a glob
   stands for too many names to check. */
function atFileWords(words, env = {}) {
  const extra = [];
  let tooMany = false;
  let dynamicUpload = false;
  // failClosed: an upload name (curl -T, --upload-file) whose glob is too large to read refuses the command. Other words
  // (a JSON body with many commas inside braces) are then only read as they are.
  const add = (w, files, failClosed = false) => {
    for (const f of files) {
      const names = braceNames(f);
      if (names === null) {
        if (failClosed) tooMany = true;
        if (f !== w.text) extra.push({ text: f, head: 'cat', redirectTarget: false, seq: w.seq, atFile: true });
        continue;
      }
      for (const n of names) if (n && n !== w.text) extra.push({ text: n, head: 'cat', redirectTarget: false, seq: w.seq, atFile: true });
    }
  };
  // $NAME and ${NAME} replaced by their values when zn knows them (the environment and assignments earlier in the command).
  const known = (t) => String(t).replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (m, n) => (Object.prototype.hasOwnProperty.call(env, n) ? String(env[n]) : m));
  for (const w of words) {
    const text = String(w.text);
    // The value of an assignment (c='-T .env', c='upload-file .env') and a word that is a known variable ($c) are read
    // like any word: their upload lines and @file references count.
    const assigned = /^[A-Za-z_][A-Za-z0-9_]*=([\s\S]*)$/.exec(text);
    const valueTexts = [];
    if (assigned) valueTexts.push(assigned[1]);
    const expanded = known(text);
    if (expanded !== text) valueTexts.push(expanded);
    for (const v of valueTexts) {
      add(w, uploadNamesOf(v), true);
      add(w, atFilesOf(v));
      const dv = decodeEscapes(v);
      if (dv !== v) { add(w, uploadNamesOf(dv), true); add(w, atFilesOf(dv)); }
    }
    // --expand-<option> values with {{name}} replaced by the curl --variable values.
    if (w.expandOpt) {
      if (w.expandUnknown && /^(?:upload-file|config|data|data-binary|data-raw|data-ascii|data-urlencode|json|form|form-string|url-query|header)$/.test(w.expandOpt)) dynamicUpload = true;
      else if (w.expandOpt === 'upload-file') add(w, [w.expanded], true);
      else if (w.expandOpt === 'config') dynamicUpload = true;
      else add(w, atFilesOf(w.expanded));
    }
    // An upload name built at run time ($(...), backticks, a variable zn does not know) cannot be checked.
    if (w.upload && /[$`]/.test(known(text))) dynamicUpload = true;
    // The same for a file sent with @file (-d @f, -F name=@f, --data-urlencode name@f), apart or glued to its option.
    if (w.curl && !w.configText) {
      const atBuilt = (v, urlencode) => {
        const f = curlFileOf(v, urlencode);
        return f !== null && /[$`]/.test(known(f).replace(/\$\{PWD\}|\$PWD(?![A-Za-z0-9_])/g, ''));
      };
      let lm;
      if (w.curlAtValue && atBuilt(text, w.urlencode)) dynamicUpload = true;
      else if ((lm = /^-[A-Za-z0-9#:]*?[dFH](.+)$/.exec(text)) && !text.startsWith('--') && atBuilt(lm[1], false)) dynamicUpload = true;
      else if ((lm = /^--(data|data-binary|data-raw|data-ascii|data-urlencode|json|form|url-query|header)=(.*)$/.exec(text)) &&
        atBuilt(lm[2], lm[1] === 'data-urlencode' || lm[1] === 'url-query')) dynamicUpload = true;
    }
    // ~1, ~+2, ~-1: a directory-stack entry zn does not know, in a curl word.
    if (w.curl && !w.configText && DIR_STACK_RE.test(text)) dynamicUpload = true;
    if (w.curl && /^-[A-Za-z0-9#:]*?T./.test(text) && !text.startsWith('--') && /[$`]/.test(known(text.replace(/^-[A-Za-z0-9#:]*?T/, '')))) dynamicUpload = true;
    if (/^--upload-file=/.test(text) && /[$`]/.test(known(text.slice('--upload-file='.length)))) dynamicUpload = true;
    // A word with spaces (a curl configuration fed on stdin: upload-file .env, -T .env) or an upload-file= line holds
    // upload names: each one is read through its {..} glob, failing closed past the cap.
    // Every word, as written and with its printf/echo escapes decoded: upload lines anywhere in it (a curl configuration
    // fed on stdin), and @file references in the decoded text.
    const decoded = decodeEscapes(text);
    add(w, uploadNamesOf(text), true);
    if (decoded !== text) {
      add(w, uploadNamesOf(decoded), true);
      add(w, atFilesOf(decoded));
    }
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      if (eq > 0) {
        const v = text.slice(eq + 1);
        add(w, atFilesOf(v));
        if (/^--upload-file=/.test(text)) add(w, [v], true);
      }
      continue;
    }
    if (text.startsWith('-')) {
      const glued = w.curl ? /^-[A-Za-z0-9#:]*?([dFTH])(.+)$/.exec(text) : null;
      if (glued) {
        if (glued[1] === 'T') add(w, [glued[2]], true);
        else add(w, atFilesOf(glued[2]));
      }
      continue;
    }
    add(w, atFilesOf(text));
    // The value of curl -T / --upload-file is a glob: each {..} expansion is a file sent (curl -T .e{nv}, -T {.e}nv).
    if (w.upload) add(w, [text], true);
    // Any other word with a {a,b} list names each item, as the shell expands it (cat {.e,x}nv).
    else if (text.includes('{') && text.includes(',') && text.includes('}')) add(w, [text]);
  }
  if (dynamicUpload) return { refuse: CURL_UPLOAD_UNKNOWN_MESSAGE };
  return tooMany ? null : extra;
}

  return {
    markCurlWords,
    atFileWords,
    curlFileOf,
    CURL_NAME_AT_FILE_OPTS,
    CURL_CONFIG_UNREADABLE_MESSAGE,
    CURL_CONFIG_EXPANSION_WRITE_MESSAGE,
    GLOB_TOO_LARGE_MESSAGE,
  };
};
