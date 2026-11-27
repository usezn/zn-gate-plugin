'use strict';

/**
 * GitHub Copilot adapter: Copilot in VS Code and GitHub Copilot CLI. Supported.
 *
 * VS Code documents that "VS Code, the GitHub Copilot app, and GitHub Copilot CLI share this harness and its hook
 * format" (https://code.visualstudio.com/docs/copilot/customization/hooks, section "Copilot harness"; read 2026-10-30,
 * hooks in VS Code are in Preview). The same page lists what that harness loads: "User hook files in ~/.copilot/hooks/, or
 * $COPILOT_HOME/hooks/ when COPILOT_HOME is set" and ".github/hooks/*.json at the repository root", with "version": 1,
 * "type": "command", the platform commands "bash" / "powershell" and "timeoutSec", and the events preToolUse and
 * postToolUse. The files zn writes are exactly those. Evidence level: documented, and run end to end only with Copilot
 * CLI 1.0.98; not tested in the VS Code app itself.
 *
 * Limits that VS Code and GitHub document, and that no hook format can lift:
 *  - "Timeouts are fail-open for every event, including preToolUse and admin-deployed policy hooks"
 *    (https://docs.github.com/en/copilot/reference/hooks-reference, "Exit codes"). zn does not wait for it: its own
 *    supervisor (runner armSupervisor) answers with a deny 4 s before timeoutSec, so only a hook that is stopped before it
 *    could start its timer (a machine so loaded that Node.js does not start in 11 s) is let through.
 *  - "Command and HTTP config-file userPromptSubmitted hooks have their output dropped, including modifiedPrompt"
 *    (same page, "userPromptSubmitted"): a typed prompt cannot be blocked from a hook file in VS Code or the CLI.
 *  - The Copilot harness also reads the repository .claude/settings(.local).json ("Cross-tool .claude/settings.json ...
 *    files in the repository are also read"; no setting needed: chat.useClaudeHooks is for VS Code's older Local harness) and runs
 *    "Applicable hooks from multiple sources ... together", so zn set up for Claude Code with --project runs twice.
 *    `zn-gate check` says so.
 *
 * Hook format (docs read 2026-10-19 and 2026-10-30):
 *  - https://docs.github.com/en/copilot/reference/hooks-reference
 *  - https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models (custom model endpoint)
 *
 *  Files: Copilot CLI loads every *.json in <project>/.github/hooks/ and in ~/.copilot/hooks/ ($COPILOT_HOME/hooks/
 *  when COPILOT_HOME is set), after the machine policy files (/etc/github-copilot/policy.d/*.json, which no user
 *  setting can switch off). zn writes its own file, zn-gate.json, in one of those folders and only edits what it
 *  wrote there:
 *    { "version": 1, "hooks": { "preToolUse": [ { "type": "command", "bash": "...", "powershell": "...", "timeoutSec": 15 } ] } }
 *
 *  stdin has two spellings, chosen by the casing of the event name in the hooks file: camelCase (preToolUse:
 *  sessionId, timestamp, cwd, toolName, toolArgs; postToolUse adds toolResult {resultType, textResultForLlm}) and
 *  the VS Code compatible one (PreToolUse: hook_event_name, session_id, tool_name, tool_input, tool_result). The
 *  camelCase payload does not name its event, so zn tells them apart by their fields. zn installs the camelCase keys.
 *  stdout of preToolUse: {permissionDecision: allow | deny | ask, permissionDecisionReason (required for deny)}.
 *  Empty output means "no opinion" (default behaviour), so zn never prints "allow".
 *  stdout of postToolUse: {modifiedResult: {resultType: "success", textResultForLlm}, additionalContext}.
 *  Exit codes: 0 = parse stdout; 2 = deny for preToolUse (a warning for the other events); any other non-zero =
 *  fail-closed for preToolUse and fail-open for the others. A TIMEOUT (default 30 s) always fails OPEN: zn answers first (see above).
 *
 *  Events: preToolUse is checked and can deny (zn also asks for confirmation when it needs one; Copilot turns
 *  "ask" into a deny in the cloud agent and in autopilot). postToolUse replaces secret values in the result of
 *  read-type and shell tools. userPromptSubmitted cannot block or rewrite for command hooks (modifiedPrompt is
 *  honoured only by SDK hooks) and sessionStart can only add context, so zn does not install them; if one arrives
 *  anyway it gets no opinion.
 *
 * Runtime tool names: bash, powershell (CLI only), view, create, edit, grep, glob, web_fetch, task, ask_user. The
 * argument names are not documented on that page, so this adapter finds the command and the files by likely key
 * names (like the Antigravity adapter) and refuses a known tool whose arguments it cannot read. How an MCP tool is
 * named is not documented: a tool zn cannot classify gets the path checks if it names a file and no opinion
 * otherwise.
 *
 * Checked against a real Copilot CLI 1.0.98 (bench/e2e/harness/run_copilot.sh, scripted provider): tool names bash, view,
 * create with the arguments command, path, file_text; a deny is shown to the model as "Denied by preToolUse hook: <reason>";
 * postToolUse modifiedResult reaches the model; no secret value reached the provider. Copilot's own events.jsonl keeps the original output.
 *
 * Switching hooks off: "disableAllHooks": true at the top of a hooks file skips that file; in a repository's
 * .github/copilot/settings(.local).json it skips every hook except the policy ones. `zn-gate check` reports both.
 */

const fs = require('fs');
const { fileURLToPath } = require('url');
const os = require('os');
const path = require('path');
const cfg = require('./config-file');
const launcher = require('./launcher');
const { shQuote } = require('../shell-quote');

const id = 'copilot';
const FILE_NAME = 'zn-gate.json';
const HOOK_TIMEOUT_S = 15;
const INSTALL_EVENTS = ['preToolUse', 'postToolUse'];

// The VS Code compatible spelling may carry Claude-style tool names.
const CLAUDE_NAMES = { Bash: 'bash', Read: 'view', Write: 'create', Edit: 'edit', MultiEdit: 'edit', Grep: 'grep', Glob: 'glob', WebFetch: 'web_fetch' };
const SHELL_TOOLS = new Set(['bash', 'powershell']);
const WRITE_TOOLS = new Set(['create', 'edit']);
const KNOWN_TOOLS = new Set(['bash', 'powershell', 'view', 'create', 'edit', 'grep', 'glob', 'web_fetch']);
const COMMAND_KEYS = ['command', 'cmd', 'Command', 'script'];
const PATH_KEY_RE = /path|file|target|uri|dir|source|destination/i;
const NOT_PATH_KEY_RE = /content|text|instruction|description|query|pattern|code|chunk|summary|title|str$/i;
const MAX_PATH_LEN = 4096;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

function firstString(obj, keys) {
  for (const k of keys) if (typeof obj[k] === 'string' && obj[k]) return obj[k];
  return undefined;
}

// The text of a patch tool call (VS Code's apply_patch sends {input: "*** Begin Patch ..."}): the tool named
// apply_patch, or any tool with a string argument that starts a patch. undefined = not a patch.
const PATCH_KEYS = ['input', 'patch', 'patchText', 'command', 'text'];
function patchTextOf(toolName, args) {
  if (toolName === 'apply_patch') return firstString(args, PATCH_KEYS) || '';
  for (const v of Object.values(args)) if (typeof v === 'string' && /^\*\*\* Begin Patch\b/m.test(v)) return v;
  return undefined;
}

/** The write input of a patch: every file it adds, updates, deletes or moves to (the Codex parser), checked like a write. */
function patchInput(text) {
  const { patchScan, PATCH_SCAN_CAP } = require('./codex');
  const tooLong = text.length > PATCH_SCAN_CAP;
  const scan = tooLong ? { files: [], suspicious: false } : patchScan(text);
  const files = scan.files;
  return { path: files[0], paths: files, alsoReadCheck: true, tooLong, unparsed: !tooLong && (files.length === 0 || scan.suspicious), texts: [{ key: ['input'], value: text }] };
}

/**
 * Whether VS Code's shell task builder wraps a plain string argument in strong quotes. Ported from the task system's
 * shell command line builder in the VS Code source (terminalTaskSystem.ts, needsQuotes): an argument that starts and
 * ends with the same quote character is left alone; otherwise it is scanned left to right, quotes open and close a
 * quoted stretch, and only a space outside a quoted stretch asks for quotes (a tab or a newline does not).
 * VS Code compares the character with its escape setting, which is an object for bash and zsh, so a backslash skips
 * nothing there; skipEscape reads the same argument the other way (a backslash skips the next character) so both
 * readings of the line are judged.
 */
function needsQuotes(value, skipEscape) {
  if (value.length >= 2 && (value[0] === "'" || value[0] === '"') && value[0] === value[value.length - 1]) return false;
  let quote;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === quote) quote = undefined;
    else if (quote !== undefined) continue;
    else if (skipEscape && ch === '\\') i++;
    else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === ' ') return true;
  }
  return false;
}

/**
 * One piece of a task line (a command or an argument) the way VS Code gives it: a string, or {value, quoting} with
 * quoting escape, strong or weak. Returns the text as VS Code puts it on a bash line (vs), the same with a backslash
 * read as an escape (vse), the bare value (raw) and a POSIX-quoted form (q); null when the piece has a shape zn
 * cannot read. VS Code wraps a plain string only when needsQuotes says so, without escaping a quote inside it, and
 * writes {value, quoting} with its own quoting (escape puts a backslash before a space, a double quote, a single
 * quote and a comma). A backslash already in an escape value is left as it is by VS Code, and the shell then reads
 * it together with the backslash VS Code adds, so the line could differ from the one judged: such a value is not
 * read (null), and the call is blocked.
 */
function taskPiece(x) {
  if (typeof x === 'string') {
    return {
      vs: needsQuotes(x, false) ? "'" + x + "'" : x,
      vse: needsQuotes(x, true) ? "'" + x + "'" : x,
      vw: /\s/.test(x) ? "'" + x + "'" : x,
      raw: x,
      q: shQuote(x),
    };
  }
  if (!isObj(x) || typeof x.value !== 'string') return null;
  const v = x.value;
  const k = x.quoting;
  if (k !== undefined && k !== 'escape' && k !== 'strong' && k !== 'weak') return null;
  if (k === 'escape' && v.includes('\\')) return null;
  const vs = k === 'strong' ? "'" + v + "'" : k === 'weak' ? '"' + v + '"' : k === 'escape' ? v.replace(/[ "',]/g, '\\$&') : v;
  return { vs, vse: vs, vw: vs, raw: v, q: shQuote(v) };
}

/**
 * A command one level down (create_and_run_task sends {task: {command, args}}) as the line(s) it runs.
 * For a shell task the line is built the way VS Code builds it, argument by argument (see needsQuotes), and that line
 * is judged; a newline or tab inside an argument VS Code leaves unquoted stays in the line, so the shell's second
 * command is seen. The same line with a backslash read as an escape, the bare values and every argument quoted are
 * judged as well and the stricter answer wins. With no arguments VS Code runs a string command as typed. A process
 * task has no shell, so each argument is quoted. undefined = no command here; null = a command or argument zn
 * cannot read (never dropped).
 */
function taskLineOf(v, hasShell) {
  const key = COMMAND_KEYS.find((k) => v[k] !== undefined);
  if (key === undefined) return undefined;
  const c = taskPiece(v[key]);
  if (!c || (typeof v[key] === 'string' && !v[key])) return null;
  let extra = [];
  if (v.args !== undefined) {
    if (!Array.isArray(v.args)) return null;
    extra = v.args.map(taskPiece);
    if (extra.some((p) => p === null)) return null;
  }
  const join = (f) => [c, ...extra].map(f).join(' ');
  if (!hasShell && typeof v.type === 'string' && v.type.toLowerCase() === 'process') return join((p) => p.q);
  const bare = typeof v[key] === 'string' && extra.length === 0;
  const lines = [bare ? c.raw : join((p) => p.vs), bare ? c.raw : join((p) => p.vse), bare ? c.raw : join((p) => p.vw), join((p) => p.raw), join((p) => p.q)];
  return lines.filter((l, i, arr) => arr.indexOf(l) === i).join('\n');
}

// Per-platform overrides VS Code reads on a task: the block for the running system replaces fields of the base task.
const TASK_PLATFORMS = ['linux', 'osx', 'windows'];

const { classifyEnv } = require('../audit/patterns');

// The shells a task may launch, and the only arguments zn accepts for them: each shell's own flags. Anything else
// (a program that is not a shell, or an argument that can carry code) is refused, because VS Code launches a custom
// shell as `executable args... commandLine`, so the code could sit in the shell settings.
const KNOWN_SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'fish', 'pwsh', 'powershell', 'cmd', 'nu']);
// Flags per shell, lower case. A flag of another shell is refused (bash with /c would run a path as a script, not the judged command).
const POSIX_FLAGS = new Set(['-c', '-l', '-i', '-lc', '--login']);
const SHELL_FLAGS = {
  bash: POSIX_FLAGS,
  sh: POSIX_FLAGS,
  zsh: POSIX_FLAGS,
  dash: POSIX_FLAGS,
  fish: new Set(['-c', '-l', '-i']),
  nu: new Set(['-c', '-l', '-i']),
  pwsh: new Set(['-c', '-command', '-noprofile', '-noninteractive']),
  powershell: new Set(['-c', '-command', '-noprofile', '-noninteractive']),
  cmd: new Set(['/c', '/d', '/s', '/q']),
};
// Keys VS Code reads under a task's options; any other key is refused so a new field fails closed.
const TASK_OPTION_KEYS = new Set(['cwd', 'env', 'shell']);

/** The settings of a task's options as {shell, cwd, env}; null = unreadable or not accepted. shell: false = none, or {exe, args}. */
// System folders a task shell given as a path may live in (POSIX and Windows): only folders an ordinary user
// cannot write to. /usr/local/bin and /opt/homebrew/bin are left out, because the user owns them on many Macs;
// a shell there is named bare (found on PATH) instead.
const SYSTEM_SHELL_DIR_RE = /^(?:\/(?:usr\/)?s?bin\/[^/]+|[A-Za-z]:\/Windows\/(?:System32|SysWOW64)\/(?:WindowsPowerShell\/v1\.0\/)?[^/]+|[A-Za-z]:\/Program Files\/(?:PowerShell\/\d+|Git\/(?:usr\/)?bin)\/[^/]+)$/i;

function taskOptions(o) {
  if (o === undefined) return { shell: false };
  if (!isObj(o)) return null;
  if (Object.keys(o).some((k) => !TASK_OPTION_KEYS.has(k))) return null;
  const out = { shell: false };
  if (o.cwd !== undefined) {
    if (typeof o.cwd !== 'string' || !o.cwd) return null;
    out.cwd = o.cwd;
  }
  if (o.env !== undefined) {
    if (!isObj(o.env)) return null;
    out.env = {};
    for (const [k, v] of Object.entries(o.env)) {
      if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') return null;
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) return null;
      if (classifyEnv(k, v) || /^(?:LD_|DYLD_)/i.test(k)) return null;
      out.env[k] = String(v);
    }
  }
  const sh = o.shell;
  if (sh === undefined) return out;
  if (!isObj(sh)) return null;
  if (sh.executable !== undefined && typeof sh.executable !== 'string') return null;
  if (sh.args !== undefined && (!Array.isArray(sh.args) || sh.args.some((a) => typeof a !== 'string'))) return null;
  const exe = sh.executable;
  const args = sh.args || [];
  if (exe !== undefined) {
    // Only a bare shell name (found on PATH) or an absolute path in a system folder: ./bash, a workspace file or a
    // temporary file named like a shell could be any program.
    const name = exe.split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
    if (!KNOWN_SHELLS.has(name)) return null;
    if (/[\\/]/.test(exe) && !SYSTEM_SHELL_DIR_RE.test(exe.replace(/\\/g, '/'))) return null;
    const flags = SHELL_FLAGS[name];
    if (!flags || args.some((a) => !flags.has(a.toLowerCase()))) return null;
  } else if (args.length) {
    return null; // flags without a named shell cannot be tied to one
  }
  out.shell = { exe, args };
  return out;
}

/** options.cwd as a folder: ${workspaceFolder}, ${userHome} and ${env:HOME} are replaced, any other ${...} is refused. */
function taskCwd(c, workspace) {
  const home = process.env.HOME || os.homedir();
  const t = c.replace(/\$\{(workspaceFolder|userHome|env:HOME)\}/g, (m, k) => (k === 'workspaceFolder' ? workspace : home));
  if (t.includes('${')) return null;
  return path.resolve(workspace, t);
}

/** Whether a folder is the workspace or inside it, links followed. A task folder outside it is refused: its relative names cannot be judged. */
function insideFolder(dir, workspace) {
  // A folder that does not exist yet keeps the links of its nearest existing parent (on macOS the temporary folder
  // /var is a link to /private/var), so ${workspaceFolder}/new stays inside a linked workspace.
  const real = (p) => {
    let cur = path.resolve(p);
    const rest = [];
    for (;;) {
      try { return path.join(fs.realpathSync(cur), ...rest); } catch (_) { /* go up */ }
      const up = path.dirname(cur);
      if (up === cur) return path.resolve(p);
      rest.unshift(path.basename(cur));
      cur = up;
    }
  };
  const rel = path.relative(real(workspace), real(dir));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/** Every line of a task variant: the built lines, run in the task's folder (cd) and, for a custom shell, as launched. */
function variantLines(task, opts, workspace) {
  const r = taskLineOf(task, opts.shell !== false);
  if (r === null || r === undefined) return r;
  let lines = r.split('\n');
  if (opts.shell && opts.shell.exe !== undefined) {
    const head = [opts.shell.exe, ...opts.shell.args].map(shQuote).join(' ');
    lines = lines.concat(lines.map((l) => head + ' ' + l));
  }
  if (opts.cwd !== undefined) {
    const dir = taskCwd(opts.cwd, workspace);
    if (dir === null || !insideFolder(dir, workspace)) return null;
    if (dir !== path.resolve(workspace)) lines = lines.map((l) => 'cd ' + shQuote(dir) + ' && ' + l);
  }
  // The task environment is exported before the line, so a value that names a file (F=<home>/.aws/credentials; cat $F)
  // is judged as the same bash line is.
  if (opts.env) {
    const exp = Object.keys(opts.env).map((k) => 'export ' + k + '=' + shQuote(opts.env[k]) + '; ').join('');
    if (exp) lines = lines.map((l) => exp + l);
  }
  return lines.join('\n');
}

/**
 * A task object as the line(s) it runs, across the base task and every platform override (linux, osx, windows): each
 * override is merged over the base the way VS Code applies it, every merged task is judged, and the stricter answer
 * wins. A custom options.shell (in the base or in an override) makes the task a shell task, whatever its type says; the
 * line is judged as launched (shell, its flags, then the command), and a shell that is not a known one, or a shell
 * argument that is not a flag, is refused. options.cwd (merged over the base) is where the line is judged, and a folder outside the workspace is refused, options.env (base keys, then the override's) is checked against the dangerous-environment list, exported before every judged line, and an unknown key under options is refused.
 * undefined = not a task; null = a shape zn cannot read (an override that is not an object, options of the wrong
 * shape, a type that is not a string, a command or argument it cannot read).
 */
function taskLines(v, workspace) {
  try {
    return taskLinesUnsafe(v, workspace);
  } catch (_) {
    return null; // fail closed: an error while reading a task blocks it
  }
}

function taskLinesUnsafe(v, workspace) {
  workspace = workspace || process.cwd();
  const overrides = TASK_PLATFORMS.filter((k) => v[k] !== undefined);
  const hasCommand = (o) => COMMAND_KEYS.some((k) => o[k] !== undefined);
  const isTask = hasCommand(v) || overrides.some((k) => isObj(v[k]) && hasCommand(v[k]));
  if (!isTask) return undefined;
  if (v.type !== undefined && typeof v.type !== 'string') return null;
  const baseOpts = taskOptions(v.options);
  if (baseOpts === null) return null;
  const base = {};
  for (const k of Object.keys(v)) if (!TASK_PLATFORMS.includes(k)) base[k] = v[k];
  const variants = [{ task: base, opts: baseOpts }];
  for (const k of overrides) {
    const ov = v[k];
    if (!isObj(ov)) return null;
    if (ov.type !== undefined && typeof ov.type !== 'string') return null;
    const ovOpts = taskOptions(ov.options);
    if (ovOpts === null) return null;
    const merged = { shell: ovOpts.shell || baseOpts.shell };
    const cwd = ovOpts.cwd !== undefined ? ovOpts.cwd : baseOpts.cwd;
    if (cwd !== undefined) merged.cwd = cwd;
    if (baseOpts.env || ovOpts.env) merged.env = Object.assign({}, baseOpts.env, ovOpts.env);
    variants.push({ task: Object.assign({}, base, ov), opts: merged });
  }
  const out = [];
  for (const { task, opts } of variants) {
    const r = variantLines(task, opts, workspace);
    if (r === null) return null;
    if (r !== undefined) out.push(r);
  }
  return out.length ? out.join('\n') : undefined;
}


// Bounds of the walk over the arguments of a tool zn does not know: deeper or larger than this cannot be checked, so it is refused.
// One depth limit for the text scan of the hooks runner and the path scan here (lib/nest-limits.js).
const { MAX_NEST_DEPTH } = require('../nest-limits');
const MAX_NEST_NODES = 500;

/**
 * Every command in the arguments of an unknown tool, at any level up to MAX_NEST_DEPTH (create_and_run_task sends
 * {task: {command, args}}), each built with taskLines, the way VS Code builds a task line, so every reading of the line
 * is judged. A command or argument zn cannot read (a number, a list, an object without a string value) is `bad` and the
 * call is refused, never dropped. `truncated` = the arguments are deeper or larger than the bounds.
 */
function commandScan(args, workspace) {
  const commands = [];
  let bad = false;
  let truncated = false;
  let nodes = 0;
  const walk = (obj, depth) => {
    if (++nodes > MAX_NEST_NODES || depth > MAX_NEST_DEPTH) { truncated = true; return; }
    let skip = null;
    if (!Array.isArray(obj)) {
      const r = taskLines(obj, workspace);
      if (r === null) bad = true;
      else if (r !== undefined) commands.push(r);
      if (r !== undefined) skip = new Set([...COMMAND_KEYS, 'args', ...TASK_PLATFORMS]);
    }
    const entries = Array.isArray(obj) ? obj.map((v) => [null, v]) : Object.entries(obj);
    for (const [k, v] of entries) {
      if (skip && skip.has(k)) continue;
      if (isObj(v) || Array.isArray(v)) walk(v, depth + 1);
    }
  };
  walk(args, 0);
  // The raw top-level command string is always judged as written too: a top-level `type: process` must not narrow
  // the check of an unknown tool to the quoted process form.
  const raw = isObj(args) ? firstString(args, COMMAND_KEYS) : undefined;
  if (typeof raw === 'string' && raw && !commands.includes(raw)) commands.unshift(raw);
  return { command: commands.length ? commands.join('\n') : undefined, bad, truncated };
}

/** The first command one level down (see taskLines), as the line(s) it runs; undefined = none, null = unreadable. */
function nestedCommand(args, workspace) {
  for (const v of Object.values(args)) {
    if (!isObj(v)) continue;
    const r = taskLines(v, workspace);
    if (r !== undefined) return r;
  }
  return undefined;
}

/**
 * A file: address with a host other than localhost would become a network (UNC) path on Windows, so it is refused
 * on every platform. A localhost host is dropped so the address stays a local path.
 */
function localFileUrl(v) {
  const u = new URL(v);
  if (u.hostname && u.hostname.toLowerCase() !== 'localhost') throw new Error('file: URL names a remote host');
  u.hostname = '';
  return u;
}

/**
 * Every string argument whose key looks like a file or folder (content-like keys skipped), down to MAX_NEST_DEPTH (the limit of the
 * text scan). Objects left unvisited because of the depth or node limit make the result `bad`: a path may be hidden there, so the
 * call is refused, never dropped.
 */
// A value that starts like a file name: ~ or . first, a drive letter, or a slash or backslash.
const STARTS_LIKE_PATH_RE = /^(?:[~.]|[A-Za-z]:[\\/]|[\\/])/;
// A value that ends in a dotenv name (sub/.env, .env.local): counted under any key, so a tool that takes one name per line is seen.
const ENDS_IN_DOTENV_RE = /(?:^|[\\/])\.env(?:\.[^\\/\s]*)?$/i;
/**
 * The file names a long or multi-line string value can stand for: the value itself when it has no line break, else its trimmed whole
 * (a server that trims whitespace opens that) and its trimmed lines. Under a file key (everyLine) every nonempty line counts, since a
 * tool may take one name per line (notes, then sub/.env); elsewhere only a line that starts like a path does, the rest is text.
 */
function pathCandidatesOf(v, everyLine = true) {
  if (!/[\r\n]/.test(v)) return [v];
  const out = [];
  const whole = v.trim();
  if (whole && !/[\r\n]/.test(whole)) out.push(whole);
  for (const line of v.split(/\r\n|\r|\n/)) {
    const t = line.trim();
    if (t && (everyLine || STARTS_LIKE_PATH_RE.test(t))) out.push(t);
  }
  return out;
}

function pathsOf(args, opts = {}) {
  const out = [];
  let bad = false;
  // loose (a tool zn does not know): a string that looks like a path counts under any key, deeper than the named keys.
  const loose = opts.loose === true;
  // A name like $DIR.env or %DIR%.env (a variable before a dotenv name) counts too.
  // A multi-line value counts when one of its lines starts like a path or it names a dotenv file anywhere (one name per line).
  const pathLike = (v) => /^[~.]|[\\/]/.test(v) || /^[$%!].*\.env(?:\.[A-Za-z0-9_.-]+)?$/i.test(v) ||
    (/[\r\n]/.test(v) && (/(?:^|[\r\n])[ \t]*[~.]/.test(v) || /\.env/i.test(v)));
  const add = (k, v) => {
    if (typeof v !== 'string' || !v) return;
    if (/^file:/i.test(v)) {
      try { out.push(fileURLToPath(localFileUrl(v))); } catch (_) { bad = true; }
      return;
    }
    if (/url/i.test(k) && !PATH_KEY_RE.test(k)) return;
    // A long value is classified like any other (classifyPath reads long input); a value with line breaks is checked by its trimmed
    // whole and each line that starts like a path. Under a key that is not a file key (loose mode) only a candidate that starts
    // like a path counts: prose with a slash somewhere is text, not a name.
    if (v.length > MAX_PATH_LEN || /[\r\n]/.test(v)) {
      const fileKey = keyOk(k);
      for (const x of pathCandidatesOf(v, true)) {
        if (!(fileKey || STARTS_LIKE_PATH_RE.test(x) || ENDS_IN_DOTENV_RE.test(x) || /^file:/i.test(x))) continue;
        // A file: URI on a line is decoded like a one-line value; one that cannot be decoded sets bad.
        if (/^file:/i.test(x)) { try { out.push(fileURLToPath(localFileUrl(x))); } catch (_) { bad = true; } } else out.push(x);
      }
      return;
    }
    out.push(v);
  };
  const keyOk = (k) => (PATH_KEY_RE.test(k) || /url/i.test(k)) && !NOT_PATH_KEY_RE.test(k);
  const maxDepth = MAX_NEST_DEPTH;
  let nodes = 0;
  const walk = (obj, depth) => {
    if (loose && ++nodes > MAX_NEST_NODES) { bad = true; return; }
    for (const [k, v] of Object.entries(obj)) {
      if (keyOk(k)) {
        if (Array.isArray(v)) v.forEach((x) => add(k, x)); else add(k, v);
      } else if (loose) {
        if (typeof v === 'string' && pathLike(v)) add(k, v);
        else if (Array.isArray(v)) v.forEach((x) => { if (typeof x === 'string' && pathLike(x)) add(k, x); });
      }
      if (depth < maxDepth) {
        if (isObj(v)) walk(v, depth + 1);
        else if (Array.isArray(v)) v.forEach((x) => { if (isObj(x)) walk(x, depth + 1); });
      } else if (isObj(v) || (Array.isArray(v) && v.some(isObj))) bad = true;
    }
  };
  walk(args, 0);
  return { paths: out, bad };
}

/** The event of a payload: the casing of the hooks file picks the spelling, and the camelCase one has no event name. */
function eventName(raw) {
  const named = raw.hook_event_name || raw.hookEventName;
  if (typeof named === 'string' && named) return named.charAt(0).toLowerCase() + named.slice(1);
  const has = (k) => raw[k] !== undefined && raw[k] !== null;
  if (has('toolResult') || has('tool_result')) return 'postToolUse';
  if (has('toolName') || has('tool_name') || has('toolArgs') || has('tool_input')) return has('error') ? 'postToolUseFailure' : 'preToolUse';
  if (typeof raw.prompt === 'string') return 'userPromptSubmitted';
  if (has('source')) return 'sessionStart';
  return null;
}

/** toolArgs / tool_input as an object. A JSON string is parsed too. null = could not be read. */
function argsOf(raw) {
  let a = raw.toolArgs !== undefined ? raw.toolArgs : raw.tool_input;
  if (a === undefined || a === null) return {};
  if (typeof a === 'string') {
    try { a = JSON.parse(a); } catch (_) { return null; }
  }
  return isObj(a) ? a : null;
}

function resultText(raw) {
  const r = raw.toolResult !== undefined ? raw.toolResult : raw.tool_result;
  if (!isObj(r)) return undefined;
  const type = r.resultType !== undefined ? r.resultType : r.result_type;
  const text = r.textResultForLlm !== undefined ? r.textResultForLlm : r.text_result_for_llm;
  // Only a successful result is rewritten: modifiedResult must say "success", so it cannot stand in for a failure.
  return type === 'success' && typeof text === 'string' ? text : undefined;
}

function normalize(raw) {
  if (!isObj(raw)) return null;
  const cwd = typeof raw.cwd === 'string' && raw.cwd ? raw.cwd : process.cwd();
  const base = { cwd, sessionId: raw.sessionId || raw.session_id || null, raw };
  const name = eventName(raw);
  if (name !== 'preToolUse' && name !== 'postToolUse') return { ...base, event: null };
  const rawName = String(raw.toolName !== undefined ? raw.toolName : raw.tool_name || '');
  const toolName = CLAUDE_NAMES[rawName] || rawName.toLowerCase();
  const args = argsOf(raw);
  const event = name === 'preToolUse' ? 'pre_tool' : 'post_tool';
  const ev = { ...base, event, toolName, rawArgs: args || {} };
  if (event === 'pre_tool' && !rawName) return { ...ev, tool: 'unreadable', input: { texts: [] }, unreadable: 'zn: could not read the tool name of this call, so zn cannot check it.' };
  if (event === 'post_tool') ev.output = resultText(raw);
  const unreadable = (what) => 'zn: could not read the ' + what + ' of this call, so zn cannot check it.';

  const known = KNOWN_TOOLS.has(toolName);
  if (args === null) {
    // Arguments that are not an object (or a JSON string of one) cannot be checked, whatever the tool is.
    return { ...ev, tool: toolName || 'unknown', input: { texts: [] }, unreadable: unreadable('arguments') };
  }
  if (!known) {
    const patch = patchTextOf(toolName, args);
    if (patch !== undefined) return { ...ev, tool: 'write', input: patchInput(patch) };
  }
  // A known tool: its top-level command string. A tool zn does not know: every command at any level within
  // bounds, built the way VS Code builds the line; unreadable or too deep = refused.
  const scan = known ? null : commandScan(args, cwd);
  if (scan && (scan.bad || scan.truncated)) {
    return { ...ev, tool: 'unreadable', input: { texts: [] }, unreadable: unreadable(scan.bad ? 'command' : 'arguments (too deeply nested)') };
  }
  const cmd = known ? firstString(args, COMMAND_KEYS) : scan.command;
  if (SHELL_TOOLS.has(toolName) || (!known && cmd !== undefined)) {
    const e = { ...ev, tool: toolName === 'powershell' ? 'powershell' : 'bash', input: { command: cmd || '', texts: [] } };
    if (cmd === undefined) e.unreadable = unreadable('command');
    if (!known) {
      // An unknown tool that carries a command and also names files: the files keep their read and write checks.
      const named = pathsOf(args, { loose: true });
      e.input.alsoPaths = named.paths;
      if (named.bad && !e.unreadable) e.unreadable = unreadable('file address');
    }
    return e;
  }
  const { paths, bad } = pathsOf(args, { loose: !known });
  const input = { path: paths[0], paths, texts: [] };
  const kind = toolName === 'view' ? 'read' : toolName === 'grep' ? 'grep' : WRITE_TOOLS.has(toolName) ? 'write' : null;
  if (kind) {
    const searchDir = kind === 'grep' ? (paths[0] ? path.resolve(cwd, paths[0]) : cwd) : null;
    const e = { ...ev, tool: kind, input: searchDir ? { ...input, scanDir: searchDir } : input };
    if (bad) e.unreadable = unreadable('file address');
    else if (kind !== 'grep' && !paths.length) e.unreadable = unreadable('file');
    return e;
  }
  if (toolName === 'web_fetch') {
    const url = firstString(args, ['url', 'uri', 'URL']);
    return { ...ev, tool: 'webfetch', input: { url: url || '', texts: [] } };
  }
  // glob lists names only. Any other tool that names a file (a plugin, an MCP server, a future tool) gets the read
  // and write checks on every path in it; tools with no path get no opinion.
  if (toolName !== 'glob' && (paths.length || bad)) {
    const e = { ...ev, tool: 'fileaccess', input };
    if (bad) e.unreadable = unreadable('file address');
    return e;
  }
  return { ...ev, tool: toolName || 'unknown', input: { texts: [] } };
}

function respond(d) {
  const ev = d && d.event;
  if (!ev || !ev.event) return null; // no opinion: empty output
  if (ev.event === 'post_tool') {
    if (typeof d.updatedOutput !== 'string') return null;
    const o = { modifiedResult: { resultType: 'success', textResultForLlm: d.updatedOutput } };
    if (d.message) o.additionalContext = d.message;
    return o;
  }
  const deny = (reason) => ({ permissionDecision: 'deny', permissionDecisionReason: reason });
  if (d.decision === 'deny') return deny(d.message || 'Blocked by zn');
  if (ev.unreadable) return deny(ev.unreadable);
  if (d.updatedInput && d.kind === 'wrap') {
    return deny('zn: this command uses a stored secret. Run it through zn instead, exactly like this: zn run -- ' + ev.input.command +
      '  (zn puts the value only into that process, if the user allowed this command for the secret).');
  }
  // A rewritten command is not applied (the argument names are not documented): the user is asked about the
  // original instead. Copilot turns "ask" into a deny where nobody can answer (cloud agent, autopilot).
  if (d.decision === 'ask' || d.updatedInput) return { permissionDecision: 'ask', permissionDecisionReason: d.message || 'zn asks for confirmation' };
  return null; // never "allow": zn has no opinion and Copilot's own permission rules decide
}

/* ------------------------ install / uninstall ---------------------- */

/** Copilot's user folder: $COPILOT_HOME, else ~/.copilot. */
function copilotHome(opts = {}) {
  const env = opts.env || process.env;
  return env.COPILOT_HOME || path.join(opts.home || os.homedir(), '.copilot');
}

function hooksFile(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.github', 'hooks', FILE_NAME);
  return path.join(copilotHome(opts), 'hooks', FILE_NAME);
}

const handlerIsOurs = (h) => isObj(h) && ['bash', 'powershell', 'command'].some((k) => cfg.isOurs(h[k], id));

/** Removes zn's handlers from a hooks file's data; true when something was removed. */
function stripOurs(data) {
  if (!isObj(data.hooks)) return false;
  let changed = false;
  for (const event of Object.keys(data.hooks)) {
    const list = data.hooks[event];
    if (!Array.isArray(list)) continue;
    const kept = list.filter((h) => !handlerIsOurs(h));
    if (kept.length !== list.length) changed = true;
    if (kept.length) data.hooks[event] = kept; else delete data.hooks[event];
  }
  return changed;
}

function install(opts = {}) {
  const file = hooksFile(opts);
  const project = (opts.scope || 'user') === 'project';
  const data = cfg.readJson(file);
  if (data.version !== undefined && data.version !== 1) throw new Error(file + ' has "version": ' + JSON.stringify(data.version) + ', not 1 (left unchanged)');
  cfg.hooksOf(data, file);
  const report = { settings: file, backup: cfg.backup(file), warnings: [] };
  if (report.backup && project) report.warnings.push('The backup ' + report.backup + ' sits inside the project: do not commit it.');
  stripOurs(data);
  const platform = opts.platform || process.platform;
  // A project install runs `zn` from the PATH inside zn's start guard (launcher.projectShCommand / projectWindowsScript): a missing zn or Node.js denies the call.
  const guarded = project && !opts.command;
  const bash = cfg.hookCommand(id, opts);
  const handlerFor = (event) => {
    if (guarded) return { type: 'command', bash: launcher.projectShCommand(id, event), powershell: launcher.windowsScriptCommand(launcher.projectWindowsScript(id, event)), timeoutSec: HOOK_TIMEOUT_S };
    const h = { type: 'command', bash, timeoutSec: HOOK_TIMEOUT_S };
    if (opts.command) h.powershell = opts.command;
    else if (project) h.powershell = bash;
    else if (platform === 'win32') h.powershell = cfg.hookCommandWindows(id, opts);
    return h;
  };
  data.version = 1;
  if (!isObj(data.hooks)) data.hooks = {};
  // "disableAllHooks" in a file zn wrote would switch its own hook off: an install turns it back on.
  if (data.disableAllHooks === true) {
    delete data.disableAllHooks;
    report.warnings.push('"disableAllHooks" was true in this file and was removed: it switched every hook of the file off.');
  }
  for (const event of INSTALL_EVENTS) {
    const list = Array.isArray(data.hooks[event]) ? data.hooks[event] : [];
    data.hooks[event] = [...list, handlerFor(event)];
  }
  cfg.writeJson(file, data);
  report.warnings.push('GitHub Copilot (VS Code and Copilot CLI) reads this file. zn checks tool calls before they run (preToolUse): it blocks reads and writes of secret files and shell commands that handle secrets, and it replaces secret values in the results of read-type and shell tools (postToolUse).');
  report.warnings.push('Copilot keeps its own session log (events.jsonl) with the original tool output on this machine: zn replaces secret values in what goes to the model, not in that local log.');
  report.warnings.push('Copilot drops the output of a command hook for a typed prompt (userPromptSubmitted), in VS Code and in Copilot CLI, so a secret pasted into a prompt is not stopped.');
  report.warnings.push('The hooks follow the VS Code and GitHub documentation; they were run end to end with Copilot CLI, not inside the VS Code app.');
  report.warnings.push('Copilot lets a call through when a hook times out (30 s by default; zn asks for ' + HOOK_TIMEOUT_S + ' s and blocks the call itself 4 s earlier), and its machine policy files (/etc/github-copilot/policy.d, or the Windows policy folder) are loaded in addition to this one.');
  if (project && !opts.command) report.warnings.push('The project hook runs `zn` from your PATH (zn hook copilot): every teammate who opens this project in Copilot CLI needs zn-gate installed, otherwise the hook cannot start. Copilot also asks each person to trust the folder before it runs repository hooks.');
  return report;
}

function uninstall(opts = {}) {
  const file = hooksFile(opts);
  const report = { settings: file, backup: null, removed: 0, warnings: [] };
  if (!fs.existsSync(file)) return report;
  const data = cfg.readJson(file);
  const before = JSON.stringify(data);
  if (!stripOurs(data) || JSON.stringify(data) === before) return report;
  report.backup = cfg.backup(file);
  report.removed = 1;
  const hooksLeft = isObj(data.hooks) ? Object.keys(data.hooks).length : 0;
  const others = Object.keys(data).filter((k) => k !== 'version' && k !== 'hooks' && k !== 'disableAllHooks');
  if (!hooksLeft && !others.length) {
    fs.unlinkSync(file);
  } else {
    if (!hooksLeft) delete data.hooks;
    cfg.writeJson(file, data);
  }
  return report;
}

function detect(opts = {}) {
  return fs.existsSync(copilotHome(opts));
}

module.exports = {
  id,
  HOOK_TIMEOUT_S,
  detect,
  install,
  uninstall,
  normalize,
  respond,
  capabilities: { ask: 'interactive', rewriteInput: false, rewriteOutput: true },
  hooksFile,
  copilotHome,
  pathsOf,
  pathCandidatesOf,
  firstString,
  COMMAND_KEYS,
  patchTextOf,
  patchInput,
  nestedCommand,
  commandScan,
  MAX_NEST_DEPTH,
  MAX_NEST_NODES,
};
