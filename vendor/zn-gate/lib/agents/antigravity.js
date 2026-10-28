'use strict';

/**
 * Google Antigravity adapter (App, CLI and IDE).
 *
 * Hook format (read 2026-10-18):
 *  - https://antigravity.google/docs/hooks
 *  - https://antigravity.google/docs/permissions (CLI rules; zn does not edit them)
 *  - https://antigravity.google/docs/mcp
 *
 *  Files: <project>/.agents/hooks.json (project) and ~/.gemini/config/hooks.json (user).
 *    { "<name>": { "enabled": true,
 *                  "PreToolUse": [ { "matcher": "<regex on the tool name>",
 *                                    "hooks": [ { "type": "command", "command": "...", "timeout": <seconds, default 30> } ] } ] } }
 *  Each top-level key is one named hook; zn writes its own under "zn-gate" and leaves the others alone.
 *
 *  stdin (camelCase): conversationId, workspacePaths, transcriptPath, artifactDirectoryPath, modelName;
 *    for PreToolUse also toolCall {name, args} and stepIdx. The event name is not part of stdin.
 *  stdout of PreToolUse: {decision: allow | auto_approve | deny | ask | force_ask | deny_unless_prior_grant,
 *    reason, overwrite, permissionOverrides}. "allow" means "proceed, deferring to the next hook or the
 *    default policy", so it is the way to say "no opinion" (never auto_approve).
 *
 * Tools named in the docs: run_command (shell), view_file, write_to_file, replace_file_content,
 * multi_replace_file_content, list_dir, find_by_name, grep_search, search_web, read_url_content,
 * and agent-management tools. The argument names are NOT documented (only that run_command takes a command
 * line), so this adapter finds the command by its likely names and finds file paths by key name
 * (anything called path, file, target, uri or dir), skipping keys that hold content. How an MCP tool is
 * named is not documented either: names that start with "mcp" are treated as MCP calls.
 * A tool zn cannot classify gets "allow" (no opinion).
 *
 * Observed on a real Antigravity (Windows, 2026-10-20): a PreToolUse hook that fails, prints nothing,
 * prints text that is not JSON or prints {} (no "decision") gets every tool call denied, with an empty
 * reason. So this adapter prints an explicit decision (allow or deny, with a reason) for every event it
 * answers, including when zn itself fails.
 * Not documented (re-read 2026-10-20: the hooks page gives no exit-code or failure semantics, only the timeout):
 * what happens when a hook crashes, times out or cannot start; whether an organization can turn hooks off. So a
 * user install goes through the launcher of lib/agents/launcher.js, which answers a deny JSON itself when the
 * Node.js is gone, and nothing is claimed for a timeout. PostToolUse can only return {}, so zn cannot rewrite or redact tool output here.
 */

const fs = require('fs');
const { spawnSync } = require('child_process');
const { fileURLToPath } = require('url');
const os = require('os');
const path = require('path');
const cfg = require('./config-file');
const launcher = require('./launcher');
const policy = require('../hooks/policy');

const id = 'antigravity';
const HOOK_NAME = 'zn-gate';
const HOOK_TIMEOUT_S = 15;
const MATCHER = '*';

const SHELL_TOOLS = new Set(['run_command']);
// Real names seen in the IDE (read_file, write_file, edit_file, run_command) and in the CLI (view_file, write_to_file, ...).
const READ_TOOLS = new Set(['read_file', 'view_file', 'list_dir', 'find_by_name']);
const NAMES_ONLY_TOOLS = new Set(['list_dir', 'find_by_name']);
const WRITE_TOOLS = new Set(['write_file', 'edit_file', 'write_to_file', 'replace_file_content', 'multi_replace_file_content']);
const COMMAND_KEYS = ['CommandLine', 'commandLine', 'command_line', 'command', 'Command'];
const PATH_KEY_RE = /path|file|target|uri|dir|source|destination/i;
const NOT_PATH_KEY_RE = /content|text|instruction|description|query|pattern|code|chunk|summary|title|^target$/i; // edit_file's "Target" holds text, not a path
const MAX_PATH_LEN = 4096;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

function firstString(obj, keys) {
  for (const k of keys) if (typeof obj[k] === 'string' && obj[k]) return obj[k];
  return undefined;
}

/**
 * Every string argument whose key looks like a file or folder (content-like keys are skipped), three levels of
 * objects and arrays deep. A key called url counts only when its value is a file: URI. A file: URI that cannot
 * be turned into a path sets `bad`, so the call is refused instead of passed.
 */
function pathsOf(args) {
  const out = [];
  let bad = false;
  const add = (k, v) => {
    if (typeof v !== 'string' || !v) return;
    if (/^file:/i.test(v)) {
      try { out.push(fileURLToPath(v)); } catch (_) { bad = true; }
      return;
    }
    if (/url/i.test(k) && !PATH_KEY_RE.test(k)) return;
    if (v.length > MAX_PATH_LEN || /[\r\n]/.test(v)) return;
    out.push(v);
  };
  const keyOk = (k) => (PATH_KEY_RE.test(k) || /url/i.test(k)) && !NOT_PATH_KEY_RE.test(k);
  const walk = (obj, depth) => {
    for (const [k, v] of Object.entries(obj)) {
      if (keyOk(k)) {
        if (Array.isArray(v)) v.forEach((x) => add(k, x)); else add(k, v);
      }
      if (depth < 3) {
        if (isObj(v)) walk(v, depth + 1);
        else if (Array.isArray(v)) v.forEach((x) => { if (isObj(x)) walk(x, depth + 1); });
      }
    }
  };
  walk(args, 0);
  return { paths: out, bad };
}

const SEARCH_CMDS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack']);
const RECURSIVE_BY_DEFAULT = new Set(['rg', 'ag', 'ack']);
// Programs that run another program given after their own options; options that take a value are listed so the
// value is not mistaken for the program.
const SEARCH_WRAPPERS = {
  sudo: 'ughCUpr', doas: 'u', env: 'uCS', command: '', exec: 'a', nohup: '', nice: 'n', time: 'fo', timeout: 'sk',
  xargs: 'nIiLPsdEa', builtin: '', stdbuf: 'ioe', '!': '', '{': '', then: '', do: '', else: '',
};
const CD_WORDS = new Set(['cd', 'pushd', 'chdir', 'set-location', 'sl']);
const SEGMENTS_MAX = 500;
const SEARCH_BASES_MAX = 64;
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash']);
// Search options whose value is the next word, so it is not taken for the pattern or a path.
const LONG_VALUE_OPTS = /^--(?:include|exclude|exclude-dir|glob|iglob|type|type-not|max-count|after-context|before-context|context|threads|max-columns|max-depth|label|binary-files|devices|directories)$/;

/** The words of a simple command after env assignments and wrappers (sudo, env, command, nice, timeout, xargs...). */
function searchHead(words) {
  let k = 0;
  for (let guard = 0; k < words.length && guard < 20; guard++) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k])) { k++; continue; }
    const name = path.basename(words[k]).toLowerCase();
    if (!Object.prototype.hasOwnProperty.call(SEARCH_WRAPPERS, name)) break;
    const valueOpts = SEARCH_WRAPPERS[name];
    k++;
    while (k < words.length) {
      const t = words[k];
      if (t === '--') { k++; break; }
      if (/^--./.test(t)) { k += /^--(?:user|group|signal|kill-after|max-args|max-procs|replace|delimiter)$/.test(t) ? 2 : 1; continue; }
      if (/^-./.test(t)) { k += /^-[A-Za-z]+$/.test(t) && valueOpts.includes(t[t.length - 1]) ? 2 : 1; continue; }
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) || (name === 'timeout' && /^[0-9.]+[smhd]?$/.test(t))) { k++; continue; }
      break;
    }
  }
  return words.slice(k);
}

/** [tool, operands, recursive, cwdOverride] of a search command, or null when it is not one. */
function searchOf(words) {
  const w = searchHead(words);
  let tool = path.basename(w[0] || '').toLowerCase();
  let rest = w.slice(1);
  let dir = null;
  let always = false;
  if (tool === 'git') {
    // git [-C dir] [-c k=v] [--no-pager ...] grep: it always walks the tree, with or without -r.
    let k = 0;
    while (k < rest.length && /^-/.test(rest[k])) {
      if (rest[k] === '-C' && k + 1 < rest.length) { dir = rest[k + 1]; k += 2; continue; }
      k += rest[k] === '-c' || rest[k] === '--git-dir' || rest[k] === '--work-tree' || rest[k] === '--namespace' ? 2 : 1;
    }
    if (rest[k] !== 'grep') return null;
    tool = 'grep';
    always = true;
    rest = rest.slice(k + 1);
  }
  if (!SEARCH_CMDS.has(tool)) return null;
  let recursive = always || RECURSIVE_BY_DEFAULT.has(tool);
  let hasPattern = false;
  const shortValue = tool === 'grep' || tool === 'egrep' || tool === 'fgrep' ? 'ABCmdD' : 'ABCmdgtTjME';
  const operands = [];
  for (let k = 0; k < rest.length; k++) {
    const t = rest[k];
    if (t === '--') { operands.push(...rest.slice(k + 1)); break; }
    if (/^--/.test(t)) {
      if (/^--(recursive|dereference-recursive)$/.test(t)) recursive = true;
      if (/^--(regexp|file)$/.test(t)) { hasPattern = true; k++; } else if (/^--(regexp|file)=/.test(t)) hasPattern = true;
      else if (LONG_VALUE_OPTS.test(t)) k++;
      continue;
    }
    if (/^-[A-Za-z0-9]+$/.test(t)) {
      if (/[rR]/.test(t)) recursive = true;
      if (/[ef]$/.test(t)) { hasPattern = true; k++; } else if (/[ef]/.test(t.slice(1)) && !/[0-9]/.test(t)) hasPattern = true;
      else if (/^-[A-Za-z]+$/.test(t) && shortValue.includes(t[t.length - 1])) k++;
      continue;
    }
    operands.push(t);
  }
  if (!recursive) return null;
  return { targets: hasPattern ? operands : operands.slice(1), dir };
}

/**
 * Folders a shell search covers, for the same "ask before a search over a folder with a plain-text .env" check a
 * search tool gets. Antigravity does not let zn rewrite the output, so this question is the only barrier in front
 * of a recursive search that would print a .env. Every simple command of the line is read (split by the shell
 * parser of lib/hooks/policy.js, which keeps quoted separators such as "A|B" inside their word): grep, egrep, fgrep,
 * rg, ag, ack or git grep, also behind sudo, env, command, nice, timeout or xargs; recursive (-r, -R, --recursive
 * or an option cluster with r or R; rg, ag, ack and git grep always are). A cd (or pushd) earlier in the line
 * moves the folder later commands run in; since a cd may fail or sit in a subshell, the folders from before it
 * are searched too. The set of candidate folders grows by at most two per cd (the folder reached by following
 * every cd, and the cd target from the starting folder), never by multiplication; past SEARCH_BASES_MAX folders,
 * or when a cd target or search path holds an unexpanded variable or substitution, or when more segments remain than SEGMENTS_MAX, the line is not followed any further and
 * the search is marked to ask. One level of bash -c, sh -c, zsh -c or dash -c is read the same way. A search's
 * first non-option word is the pattern (unless -e or -f gives it) and the rest are paths; with no path the working
 * folder is searched. Files named directly are checked by the shell command check, not here.
 * Returns { dirs, ask }: the folders found, and a reason when the line must be confirmed (or null).
 */
function homeOf(t) {
  // A leading ~ is the home folder the hook sees, not a folder named "~". On Windows ~\ counts too.
  if (t === '~' || t.startsWith('~/')) return path.join(os.homedir(), t.slice(1));
  if (process.platform === 'win32' && t.startsWith('~\\')) return path.join(os.homedir(), t.slice(2).replace(/\\/g, '/'));
  return t;
}

// ~+, ~-, ~user: the shell expands them to a folder zn does not resolve, so the folder is unknown.
function otherTilde(t) {
  return /^~[^/]/.test(t) && !(process.platform === 'win32' && t[1] === '\\');
}

function searchScan(command, cwd) {
  const origin = path.resolve(cwd);
  const found = new Set();
  const result = { dirs: found, ask: null };
  // state: { main: the folder after every cd, bases: Set of candidates }
  const walk = (text, state, depth) => {
    let rest = String(text);
    for (let n = 0; rest.length && n < SEGMENTS_MAX; n++) {
      if (result.ask) return '';
      const scan = policy.scanFirstCommand(rest);
      rest = rest.slice(scan.end + 1);
      const words = scan.words.map((x) => x.text).filter((x) => !/^[0-9]*[<>]/.test(x));
      if (!words.length) continue;
      const head = searchHead(words);
      if (head.length && CD_WORDS.has(path.basename(head[0]).toLowerCase())) {
        const target = head.slice(1).find((x) => x === '-' || !/^-/.test(x));
        // A variable or a substitution cannot be followed: the folder is unknown, so the next recursive search asks.
        // Other patterns (globs, braces) are not followed: the places so far stay, and so does the folder itself.
        if (target && (/[$`]/.test(target) || otherTilde(target))) state.unknown = true;
        else if (target && target !== '-' && !/[*?[{~]/.test(target.replace(/^~(?=\/|$)/, ''))) {
          const t = homeOf(target);
          state.bases.add(path.resolve(state.main, t));
          state.bases.add(path.resolve(origin, t));
          state.main = path.resolve(state.main, t);
        }
        continue;
      }
      if (head.length && SHELLS.has(path.basename(head[0]).toLowerCase()) && depth < 1) {
        const k = head.findIndex((x, i) => i > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(x));
        if (k > 0 && typeof head[k + 1] === 'string') {
          // The inner command runs in its own shell: a cd inside it does not move this one.
          if (walk(head[k + 1], { main: state.main, bases: new Set(state.bases), unknown: state.unknown }, depth + 1).trim().length) result.ask = 'long';
        }
        continue;
      }
      const s = searchOf(words);
      if (!s) continue;
      if (state.bases.size > SEARCH_BASES_MAX) { result.ask = 'long'; return ''; }
      if (state.unknown || s.targets.some((t) => /[$`]/.test(t) || otherTilde(t))) { result.ask = 'unknown'; return ''; }
      for (const b of state.bases) {
        const base = s.dir ? path.resolve(b, s.dir) : b;
        if (s.targets.length) for (const t of s.targets) found.add(path.resolve(base, homeOf(t)));
        else found.add(base);
      }
    }
    return rest;
  };
  const state = { main: origin, bases: new Set([origin]), unknown: false };
  const rest = walk(command, state, 0);
  // Segments left unread (a very long line) cannot be checked: ask rather than allow.
  if (rest.trim().length && !result.ask) result.ask = 'long';
  return { dirs: [...found], ask: result.ask };
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const wp = Array.isArray(raw.workspacePaths) && typeof raw.workspacePaths[0] === 'string' ? raw.workspacePaths[0] : null;
  const call = raw.toolCall && typeof raw.toolCall === 'object' ? raw.toolCall : null;
  const args = call && call.args && typeof call.args === 'object' && !Array.isArray(call.args) ? call.args : {};
  const cwd = (typeof args.Cwd === 'string' && args.Cwd) || (typeof args.cwd === 'string' && args.cwd) || wp || process.cwd();
  const base = { cwd, sessionId: raw.conversationId || null, raw };
  // The event name is not in Antigravity's stdin; if a caller adds one, anything but PreToolUse is ignored.
  const named = raw.hookEventName || raw.hook_event_name;
  if (named && named !== 'PreToolUse') return { ...base, event: null, otherEvent: true };
  // zn installs only PreToolUse: a payload without a tool call is a malformed one, and Antigravity must not get "allow" for it.
  if (!call) return { ...base, event: 'pre_tool', toolName: '', tool: 'unreadable', input: { texts: [] }, unreadable: 'zn: could not read the tool call of this event, so zn cannot check it.' };
  const toolName = String(call.name || '');
  const ev = { ...base, event: 'pre_tool', toolName, rawArgs: args };

  const mcp = /^mcp[_.\-:/]+(.+?)[_.\-:/]+(.+)$/i.exec(toolName);
  if (mcp) {
    const mp = pathsOf(args);
    const e = { ...ev, tool: 'mcp', mcp: { server: mcp[1], tool: mcp[2] }, input: { args, paths: mp.paths, texts: [] } };
    if (mp.bad) e.unreadable = 'zn: could not read a file address in this call, so zn cannot check it.';
    return e;
  }
  const cmd = firstString(args, COMMAND_KEYS);
  if (SHELL_TOOLS.has(toolName) || (!READ_TOOLS.has(toolName) && !WRITE_TOOLS.has(toolName) && cmd !== undefined)) {
    const scan = cmd ? searchScan(cmd, cwd) : { dirs: [], ask: null };
    const dirs = scan.dirs;
    const e = { ...ev, tool: 'bash', input: { command: cmd || '', texts: [], ...(dirs.length ? { scanDirs: dirs } : {}), ...(scan.ask ? { scanAsk: scan.ask } : {}) } };
    if (cmd === undefined) e.unreadable = 'zn: could not read the command of this call, so zn cannot check it.';
    return e;
  }
  const { paths, bad } = pathsOf(args);
  const input = { path: paths[0], paths, texts: [], ...(WRITE_TOOLS.has(toolName) ? { alsoReadCheck: true } : {}) };
  const searchDir = toolName === 'grep_search' ? (paths[0] ? path.resolve(cwd, paths[0]) : cwd) : null;
  const kind = (READ_TOOLS.has(toolName) && !NAMES_ONLY_TOOLS.has(toolName)) ? 'read' : NAMES_ONLY_TOOLS.has(toolName) ? 'read_names' : toolName === 'grep_search' ? 'grep' : WRITE_TOOLS.has(toolName) ? 'write' : null;
  if (kind) {
    const e = { ...ev, tool: kind === 'read_names' ? 'read' : kind, input: searchDir ? { ...input, scanDir: searchDir } : input };
    if (bad) e.unreadable = 'zn: could not read a file address in this call, so zn cannot check it.';
    else if ((kind === 'read' || kind === 'write') && !paths.length) e.unreadable = 'zn: could not read the file this call uses, so zn cannot check it. Name the file explicitly.';
    return e;
  }
  // Any other tool that names a file (a viewer, a reader, a future tool) gets the read and write checks on
  // every path in it. list_dir and find_by_name show names only, and tools with no path get no opinion.
  if (!READ_TOOLS.has(toolName) && (paths.length || bad)) {
    const e = { ...ev, tool: 'fileaccess', input };
    if (bad) e.unreadable = 'zn: could not read a file address in this call, so zn cannot check it.';
    return e;
  }
  return { ...ev, tool: toolName || 'unknown', input: { texts: [] } };
}

function out(decision, reason) {
  const o = { decision };
  if (reason) o.reason = reason;
  return o;
}

const UNREADABLE = 'zn: could not read this event, so it was blocked.';

function respond(d) {
  const ev = d && d.event;
  // Antigravity denies the call, with an empty reason, when the hook prints nothing or {}: always answer with a decision.
  if (!ev) return d && d.decision === 'deny' ? out('deny', d.message || UNREADABLE) : out('deny', UNREADABLE);
  // An event that is named and is not PreToolUse (zn installs only PreToolUse): its documented answer is {}.
  if (!ev.event && ev.otherEvent) return {};
  if (!ev.event) return out('allow'); // not a tool call: nothing to check
  if (d.decision === 'deny') return out('deny', d.message || 'Blocked by zn');
  if (ev.unreadable) return out('deny', ev.unreadable);
  if (d.updatedInput && d.kind === 'wrap') {
    const msg = 'zn: this command uses a stored secret. Run it through zn instead, exactly like this: zn run -- ' + ev.input.command +
      '  (zn puts the value only into that process, if the user allowed this command for the secret).';
    return out('deny', msg);
  }
  // A rewritten command or text is not applied (zn would need "overwrite" together with a decision that skips
  // the user's cached approvals): the user is asked about the original instead.
  if (d.decision === 'ask' || d.updatedInput) return out('force_ask', d.message || 'zn asks for confirmation');
  return out('allow'); // "allow" here defers to the default policy; zn never auto-approves
}

/* ------------------------ install / uninstall ---------------------- */

function hooksFile(opts = {}) {
  if ((opts.scope || 'user') === 'project') return path.join(path.resolve(opts.projectDir || process.cwd()), '.agents', 'hooks.json');
  return path.join(opts.home || os.homedir(), '.gemini', 'config', 'hooks.json');
}

/** Removes zn's handlers from every named hook; returns true when something was removed. */
function stripOurs(data) {
  let changed = false;
  for (const name of Object.keys(data)) {
    const entry = data[name];
    if (!isObj(entry)) continue;
    const before = changed;
    changed = false;
    for (const event of Object.keys(entry)) {
      const groups = entry[event];
      if (!Array.isArray(groups)) continue;
      const kept = [];
      for (const g of groups) {
        if (isObj(g) && Array.isArray(g.hooks)) {
          const hs = g.hooks.filter((h) => !(isObj(h) && cfg.isOurs(h.command, id)));
          if (hs.length !== g.hooks.length) changed = true;
          if (hs.length) kept.push({ ...g, hooks: hs });
        } else if (isObj(g) && cfg.isOurs(g.command, id)) {
          changed = true; // a handler placed directly in the event list
        } else {
          kept.push(g);
        }
      }
      if (kept.length) entry[event] = kept; else delete entry[event];
    }
    // An entry that only held zn's handlers goes away; one with other events or settings stays.
    if (changed && Object.keys(entry).every((k) => k === 'enabled')) delete data[name];
    changed = changed || before;
  }
  return changed;
}

const SELF_CHECK_DECISIONS = new Set(['allow', 'auto_approve', 'deny', 'ask', 'force_ask', 'deny_unless_prior_grant']);
const SELF_CHECK_EVENT = { conversationId: 'zn-self-check', workspacePaths: [os.tmpdir()], toolCall: { name: 'zn_self_check', args: {} }, stepIdx: 0 };

/**
 * Runs the hook command once with a harmless made-up PreToolUse event (a tool that names no file and no command)
 * and checks that it answers with a valid decision. Antigravity denies every tool call when the hook cannot
 * run or answers with anything else, so this is the one place to learn it before the agent does.
 * Returns {ok, detail}.
 */
function selfCheck(command, opts = {}) {
  const env = { ...(opts.env || process.env), ZN_STATS: 'off' };
  const spawnOpts = { input: opts.input !== undefined ? opts.input : JSON.stringify(SELF_CHECK_EVENT), encoding: 'utf8', timeout: opts.timeoutMs || 20000, env, windowsHide: true };
  // A command zn wrote is run the way Antigravity runs it: split on spaces, no shell (not where cmd.exe is needed).
  const parts = opts.splitOnSpaces && process.platform !== 'win32' ? String(command).split(' ') : null;
  // The first word (sh) from the absolute PATH entries only: install --project runs in the project folder.
  const first = parts ? require('../exe').findProgram(parts[0], env) : null;
  if (parts && !first) return { ok: false, detail: 'it could not be started (' + parts[0] + ' was not found on the PATH)' };
  const r = parts ? spawnSync(first, parts.slice(1), spawnOpts) : spawnSync(command, { shell: true, ...spawnOpts });
  // A hook that answers and exits before reading all its input makes the write fail with EPIPE although it ran: its status and output are the answer.
  const ranAndExited = r.error && r.error.code === 'EPIPE' && typeof r.status === 'number';
  if (r.error && !ranAndExited) return { ok: false, detail: r.error.code === 'ETIMEDOUT' ? 'it did not answer within 20 seconds' : 'it could not be started (' + (r.error.code || 'error') + ')' };
  const text = String(r.stdout || '').trim();
  let parsed;
  try { parsed = JSON.parse(text); } catch (_) { /* reported below */ }
  if (!isObj(parsed) || !SELF_CHECK_DECISIONS.has(parsed.decision)) {
    return { ok: false, detail: text ? 'it answered with something that is not a decision' : 'it printed nothing' + (r.status ? ' (exit code ' + r.status + ')' : '') };
  }
  if (parsed.decision !== 'allow') return { ok: false, detail: 'it answered "' + parsed.decision + '" to a harmless event' + (parsed.reason ? ': ' + String(parsed.reason).slice(0, 200) : '') };
  return { ok: true, detail: 'it answered with a valid decision' };
}

/**
 * The hook command. A user install goes through zn's launcher (lib/agents/launcher.js): a Node.js that has gone
 * away makes the launcher answer a deny with the repair step, where a command that cannot start would block with
 * no text from zn (or not at all). A project install writes `sh -c` (PowerShell on Windows) around `zn hook
 * antigravity` with the same deny answer when zn or node is missing. A command given by the caller stays as it is.
 */
function commandFor(opts = {}) {
  const platform = opts.platform || process.platform;
  if (opts.command) return cfg.hookCommand(id, opts);
  // A project install is shared through the repository, so it names `zn` on the PATH instead of this machine's
  // launcher, with its own guard: a missing zn or node ends in a deny that says how to repair it.
  if ((opts.scope || 'user') === 'project') {
    return platform === 'win32' ? launcher.windowsScriptCommand(launcher.projectWindowsScript(id)) : launcher.projectShCommand(id);
  }
  const node = opts.nodePath || process.execPath;
  const runner = opts.runnerPath || cfg.runnerPath();
  if (platform === 'win32') {
    const script = launcher.windowsScript(id, 'PreToolUse', node, runner);
    return script ? launcher.windowsScriptCommand(script) : cfg.hookCommandWindows(id, { ...opts, encodedCommand: true });
  }
  // Antigravity splits the command on spaces and runs it with no shell, so a quote becomes part of the file name
  // and the hook never starts: the launcher path goes in unquoted. A path that would need quotes cannot be used.
  // No path without spaces: nothing that Antigravity can start can be written, so refuse instead of writing a hook that never runs.
  const file = launcher.launcherFile(id, opts);
  if (!launcher.plainPathOk(file)) throw new Error(launcher.spaceMessage(file));
  return launcher.launcherCommand(launcher.writeLauncher(id, node, runner, { ...opts, deadlineS: launcher.launcherDeadlineS(HOOK_TIMEOUT_S), deadlineSoft: true }), 'PreToolUse', platform, { plain: true });
}

function install(opts = {}) {
  const file = hooksFile(opts);
  const command = commandFor(opts); // may refuse (a launcher path Antigravity cannot start): before anything is written
  const data = cfg.readJson(file);
  const report = { settings: file, backup: cfg.backup(file), warnings: [] };
  if (report.backup && (opts.scope || 'user') === 'project') report.warnings.push('The backup ' + report.backup + ' sits inside the project: do not commit it.');
  stripOurs(data);
  // Antigravity splits the hook command on spaces and ignores quotes, so on
  // Windows a quoted path such as C:/Program Files/... breaks the -Command form
  // and every tool call is blocked. -EncodedCommand has no space inside its
  // argument.
  // After the strip, a hook still called zn-gate is someone else's: zn never touches it (not even its enabled flag).
  let name = HOOK_NAME;
  while (data[name] !== undefined) name += '-zn';
  data[name] = { enabled: true, PreToolUse: [{ matcher: MATCHER, hooks: [{ type: 'command', command, timeout: HOOK_TIMEOUT_S }] }] };
  cfg.writeJson(file, data);
  report.warnings.push('zn checks tool calls before they run (PreToolUse): it blocks reads and writes of secret files and shell commands that handle secrets.');
  if ((opts.scope || 'user') === 'project' && !opts.command) report.warnings.push('The project hook runs `zn` from your PATH (zn hook antigravity): every teammate who opens this project in Antigravity needs zn-gate installed. Without it the hook answers a deny that says how to install it, so Antigravity blocks the call instead of running it unchecked. The command is written for this kind of machine (' + ((opts.platform || process.platform) === 'win32' ? 'Windows' : 'macOS and Linux') + '): a teammate on the other kind runs `zn hooks install antigravity --project` in their own copy of the project.');
  report.warnings.push('Antigravity hooks cannot rewrite or redact what a tool returns, so a value printed by a command or a file the agent is allowed to read reaches the model. Keep secrets in the vault.');
  report.warnings.push('Antigravity does not document what happens when a hook fails or times out. In our tests (Windows, October 2026) a hook that failed to start or answered with something that is not a decision made Antigravity deny every tool call; a timeout was not tested. If the Node.js zn was installed with goes away, the launcher script answers a deny that says how to repair it, and zn itself answers every event with an explicit decision. Run `zn-gate check` to see that the hook works.');
  if (opts.selfCheck) {
    report.selfCheck = selfCheck(command, { ...opts, splitOnSpaces: !opts.command });
    if (!report.selfCheck.ok) {
      const fix = (opts.scope || 'user') === 'project' && !opts.command
        ? 'install zn-gate for your user (npm install -g zn-gate) so that `zn` is on your PATH, then run this command again'
        : 'run `npx -y zn-gate check`, then `npm install -g zn-gate` and this command again; if it still fails, run `zn hooks uninstall antigravity` before you use Antigravity';
      report.warnings.push('SELF-CHECK FAILED: the hook was started once with a harmless test event and ' + report.selfCheck.detail + '. Antigravity would deny every tool call. Next step: ' + fix + '.');
    } else {
      report.warnings.push('Self-check passed: the hook was started once with a harmless test event and ' + report.selfCheck.detail + '.');
    }
  }
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
  if (Object.keys(data).length === 0) fs.unlinkSync(file);
  else cfg.writeJson(file, data);
  // The launcher (see commandFor) is shared by every config of this machine: one uninstall leaves it in place,
  // only the machine-wide uninstall (opts.removeLauncher) deletes it.
  if ((opts.scope || 'user') !== 'project' && opts.removeLauncher === true) {
    try { fs.unlinkSync(launcher.launcherFile(id, opts)); } catch (_) { /* none */ }
  }
  return report;
}

function detect(opts = {}) {
  const home = opts.home || os.homedir();
  return fs.existsSync(path.join(home, '.gemini', 'antigravity')) ||
    fs.existsSync(path.join(home, '.gemini', 'antigravity-cli')) ||
    fs.existsSync(path.join(home, '.gemini', 'config'));
}

module.exports = {
  id,
  HOOK_TIMEOUT_S,
  detect,
  install,
  uninstall,
  normalize,
  respond,
  selfCheck,
  capabilities: { ask: 'all', rewriteInput: false, rewriteOutput: false },
  HOOK_NAME,
  hooksFile,
};
