'use strict';

/**
 * Fail-closed launcher for agents whose hooks fail OPEN when the hook command
 * cannot start.
 *
 * `zn hooks install` used to write `<node> <runner.js> <agent>` with the
 * absolute path of the Node.js that ran the install. When that Node.js goes
 * away (nvm removes a version, an upgrade, a reinstall) the command exits 127
 * and the agent runs the call with no check. Codex documents only two ways to
 * block: a PreToolUse (or UserPromptSubmit) hook that exits with code 2 and
 * writes the reason to stderr, or one that prints a deny decision. Any other
 * failure "marks the hook run as failed, reports the error, and continues".
 *
 * So the hook command is now a small POSIX sh script owned by zn
 * (~/.zn/hooks/zn-hook-<agent>.sh, rewritten on every install):
 *  1. the Node.js and runner recorded at install time, if both still exist;
 *  2. else `zn hook <agent>` from the PATH of the hook (it needs `node` too);
 *  3. else it needs no Node.js at all: it blocks (exit 2 + reason on stderr,
 *     or the documented deny JSON for PermissionRequest) on the events where
 *     that is the documented way to block, and only warns (a systemMessage the
 *     user sees) on the others, where blocking would hide a tool result or loop
 *     the model.
 * The event name is the script's one argument, because without Node.js the
 * script cannot read it from stdin.
 *
 * Windows has no such script file: `commandWindows` is a PowerShell command
 * with the same three steps written inline (windowsCommand below).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { writeFileAtomic } = require('../broker/files');
const { shQuote, portablePath } = require('../shell-quote');

// Events where exit 2 with a reason on stderr is the documented block.
const BLOCK_EXIT = new Set(['PreToolUse', 'UserPromptSubmit']);
// PermissionRequest blocks with a decision on stdout (exit 2 is not documented there).
const BLOCK_JSON = new Set(['PermissionRequest']);
// Claude Code: exit 2 blocks PreToolUse, UserPromptSubmit and UserPromptExpansion; PermissionRequest is not hooked.
// Every other event (PostToolUse) only warns: exit 2 there cannot undo the tool call.
// Cursor: exit code 2 blocks, "equivalent to returning permission: deny"; the events that can deny are listed (postToolUse only observes).
// Gemini CLI: exit 2 "aborts" the tool; zn registers BeforeTool only.
const BLOCK_EXIT_BY_AGENT = {
  'claude-code': new Set(['PreToolUse', 'UserPromptSubmit', 'UserPromptExpansion']),
  cursor: new Set(['beforeMCPExecution', 'beforeReadFile', 'beforeShellExecution', 'beforeSubmitPrompt', 'preToolUse']),
  gemini: new Set(['BeforeTool']),
  // Antigravity: the hook answers with {decision:'deny',reason} on stdout (exit 0); its docs do not say what a failed hook does.
  antigravity: new Set(['PreToolUse']),
  // ZCode: exit code 2 blocks PreToolUse, PermissionRequest and UserPromptSubmit (docs: "Blocking shortcut"); any other failure only logs and the call runs.
  zcode: new Set(['PreToolUse', 'PermissionRequest', 'UserPromptSubmit']),
};
const BLOCK_JSON_BY_AGENT = { 'claude-code': new Set(), cursor: new Set(), gemini: new Set(), antigravity: new Set(), zcode: new Set() };
// Agents that read a block from a deny JSON on stdout with exit 0 (not from exit code 2).
const DENY_STDOUT = {
  antigravity: (r) => ({ decision: 'deny', reason: r }),
};
// Agents whose non-blocking events get the warning on stderr (exit 0) instead of a systemMessage on stdout.
const WARN_STDERR = new Set(['cursor']);
const blockExit = (agentId) => BLOCK_EXIT_BY_AGENT[agentId] || BLOCK_EXIT;
const blockJson = (agentId) => BLOCK_JSON_BY_AGENT[agentId] || BLOCK_JSON;

const FIX = 'run `npm install -g zn-gate` and then `zn hooks install codex` in your own terminal';

function reasonText(agentId) {
  return 'zn: its hook cannot start because the Node.js or the zn-gate files it was installed with are gone, so this was blocked. Ask the user to ' +
    FIX.replace('codex', agentId).replace('in your own terminal', 'in their terminal') + '.';
}

function crashText(agentId) {
  return 'zn: its hook failed, so this was blocked. Ask the user to run `zn-gate check` in their terminal to see why.';
}

function crashWarnText() {
  return 'zn is NOT protecting this session: its hook failed. Please run `zn-gate check` in your own terminal to see why.';
}

// The hook ran and ended with status 0 but did not confirm its answer: an older zn-gate answered (the zn on the PATH does not match the
// launcher), or the hook stopped half way.
function noAckText(agentId) {
  return 'zn: its hook ended without confirming its answer (the zn-gate that answered is older than this hook, or it stopped half way), so this was blocked. Ask the user to run `npm install -g zn-gate` and then `zn hooks install ' + agentId + '` in their terminal, or `zn-gate check` to see why.';
}

function noAckWarnText(agentId) {
  return 'zn is NOT protecting this session: its hook ended without confirming its answer (the zn-gate that answered is older than this hook, or it stopped half way). Please run `npm install -g zn-gate` and then `zn hooks install ' + agentId + '` in your own terminal.';
}

function warnText(agentId) {
  return 'zn is NOT protecting this session: its hook cannot start because the Node.js or the zn-gate files it was installed with are gone. Please ' +
    FIX.replace('codex', agentId) + '.';
}

/** Where zn keeps its launchers: ~/.zn/hooks (or $ZN_HOME/hooks, or $ZN_HOOK_DIR itself). */
function launcherDir(opts = {}) {
  const env = opts.env || process.env;
  if (env.ZN_HOOK_DIR) return path.resolve(env.ZN_HOOK_DIR);
  const base = env.ZN_HOME ? path.resolve(env.ZN_HOME) : path.join(opts.home || os.homedir(), '.zn');
  return path.join(base, 'hooks');
}

function launcherFile(agentId, opts = {}) {
  return path.join(launcherDir(opts), 'zn-hook-' + agentId + '.sh');
}

function checkAgentId(agentId) {
  if (!/^[a-z-]+$/.test(agentId)) throw new Error('zn: bad agent id ' + agentId);
  return agentId;
}

/**
 * Seconds the launcher lets the hook run for an agent whose own hook timeout is `hostTimeoutS`: two seconds less, so the
 * launcher answers (with the block of the event) before the agent gives up and, for most agents, runs the call.
 */
function launcherDeadlineS(hostTimeoutS) {
  return Math.max(1, Math.floor(hostTimeoutS) - 2);
}

/** The text of the launcher script. */
function unixScript(agentId, nodePath, runnerPath, opts = {}) {
  checkAgentId(agentId);
  // deadlineS (whole seconds, only for agents that fail open on a timeout): the launcher answers by itself when the hook has
  // not finished by then, so a hook stuck while it starts (before the runner arms its own watchdog) still blocks.
  const deadlineS = Number.isInteger(opts.deadlineS) && opts.deadlineS > 0 ? opts.deadlineS : 0;
  const run = (...w) => (deadlineS ? 'zn_run ' : 'zn_cap ') + w.join(' ');
  // Without a timer or private output a strict launcher (ZCode) does not run the hook and blocks; the others (the runner
  // has its own deadline too) run it directly, still through zn_cap (private output and the confirmation check).
  const noTimer = opts.deadlineSoft ? 'zn_cap "$@"' : 'ZN_RC=127';
  const reason = reasonText(agentId);
  const warn = warnText(agentId);
  const exitEvents = [...blockExit(agentId)];
  const jsonEvents = [...blockJson(agentId)];
  const crash = crashText(agentId);
  const crashWarn = crashWarnText();
  const pick = (ifRan, ifGone, ifNoAck) => (ifNoAck ? 'if [ -n "$ZN_NOACK" ]; then ' + ifNoAck + '; elif [ -n "$ZN_RAN" ]; then ' : 'if [ -n "$ZN_RAN" ]; then ') + ifRan + '; else ' + ifGone + '; fi';
  const noAck = noAckText(agentId);
  const noAckWarn = noAckWarnText(agentId);
  const deny = (r) => 'printf ' + shQuote('%s\\n') + ' ' + shQuote(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PermissionRequest', decision: { behavior: 'deny', message: r } } }));
  return [
    '#!/bin/sh',
    '# Written by `zn hooks install ' + agentId + '`; replaced on every install. Do not edit.',
    '# Runs the zn hook; if the Node.js or zn-gate it was installed with is gone, it blocks instead of letting the call run.',
    'ZN_EVENT="${1:-}"',
    'ZN_NODE=' + shQuote(nodePath),
    'ZN_RUNNER=' + shQuote(runnerPath),
    'ZN_RAN=',
    '# Removes private files by absolute path: the PATH of a hook can be empty, and a bare rm would leave them behind on every call.',
    '# rm from the system folders only (NixOS and Guix keep it under /run/current-system); with none, the Node.js the hook was installed with removes them.',
    'zn_rm() { for ZN_R in /bin/rm /usr/bin/rm /run/current-system/sw/bin/rm /run/current-system/profile/bin/rm; do [ -x "$ZN_R" ] && { "$ZN_R" -f -- "$@" 2>/dev/null; return 0; }; done; [ -x "$ZN_NODE" ] && "$ZN_NODE" -e \'for (const f of process.argv.slice(1)) { try { require("fs").unlinkSync(f); } catch (e) {} }\' -- "$@" 2>/dev/null; return 0; }',
    'zn_block() {',
    'case "$ZN_EVENT" in',
    '  ' + exitEvents.join('|') + ')',
    DENY_STDOUT[agentId]
      ? '    ' + pick('printf ' + shQuote('%s\\n') + ' ' + shQuote(JSON.stringify(DENY_STDOUT[agentId](crash))), 'printf ' + shQuote('%s\\n') + ' ' + shQuote(JSON.stringify(DENY_STDOUT[agentId](reason))), 'printf ' + shQuote('%s\n') + ' ' + shQuote(JSON.stringify(DENY_STDOUT[agentId](noAck))))
      : '    ' + pick('printf ' + shQuote('%s\\n') + ' ' + shQuote(crash) + ' >&2', 'printf ' + shQuote('%s\\n') + ' ' + shQuote(reason) + ' >&2', 'printf ' + shQuote('%s\n') + ' ' + shQuote(noAck) + ' >&2'),
    DENY_STDOUT[agentId] ? '    exit 0 ;;' : '    exit 2 ;;',
    ...(jsonEvents.length ? [
      '  ' + jsonEvents.join('|') + ')',
      '    ' + pick(deny(crash), deny(reason), deny(noAck)),
      '    exit 0 ;;',
    ] : []),
    '  *)',
    WARN_STDERR.has(agentId)
      ? '    ' + pick('printf ' + shQuote('%s\\n') + ' ' + shQuote(crashWarn) + ' >&2', 'printf ' + shQuote('%s\\n') + ' ' + shQuote(warn) + ' >&2', 'printf ' + shQuote('%s\n') + ' ' + shQuote(noAckWarn) + ' >&2')
      : '    ' + pick('printf ' + shQuote('%s\\n') + ' ' + shQuote(JSON.stringify({ systemMessage: crashWarn })), 'printf ' + shQuote('%s\\n') + ' ' + shQuote(JSON.stringify({ systemMessage: warn })), 'printf ' + shQuote('%s\n') + ' ' + shQuote(JSON.stringify({ systemMessage: noAckWarn }))),
    '    exit 0 ;;',
    'esac',
    '}',
    ...(deadlineS ? [
      'zn_term() {',
      '  [ -z "$ZN_P" ] || { kill -TERM -$ZN_P 2>/dev/null; kill -TERM $ZN_P 2>/dev/null; kill -KILL -$ZN_P 2>/dev/null; }',
      '  [ -z "$ZN_T" ] || kill -TERM $ZN_T 2>/dev/null',
      '  zn_rm "$ZN_OF" "$ZN_EF" "$ZN_AF"',
      '  ZN_RAN=1; zn_block',
      '}',
    ] : []),
    '# Exit codes other than 0 (done) and 2 (blocked) are failures: they fall through to the block below.',
    ...[
      '# Runs a command with its output in a private file: the answer reaches the agent only when the run is accepted (status 0 with the confirmation, or 2),',
      '# so a half answer is never passed on; when the answer cannot be passed on either, the run counts as failed.',
      'zn_cap() {',
      '  zn_mk out; ZN_OF=$ZN_MK',
      '  [ -n "$ZN_OF" ] || { ZN_RC=127; return 0; }',
      '  # TERM, HUP or INT (the agent gives up on the hook): the answer is the block of this event, like a hook that ran past its deadline.',
      '  trap \'zn_rm "$ZN_OF" "$ZN_AF"; ZN_RAN=1; zn_block\' HUP INT TERM',
      '  "$@" >"$ZN_OF"; ZN_RC=$?',
      '  # The command is done: a TERM, HUP or INT now must not cut the answer being passed on or add a second one after it.',
      '  trap \'\' HUP INT TERM',
      '  if [ "$ZN_RC" = 0 ]; then zn_acked || { ZN_RC=1; ZN_NOACK=1; }; fi',
      '  case $ZN_RC in 0|2) zn_relay "$ZN_OF" || ZN_RC=127 ;; esac',
      '  zn_rm "$ZN_OF"',
      '  return 0',
      '}',
    ],
    ...(deadlineS ? [
      '# Runs a command with a deadline of ' + deadlineS + ' s: after that the command is killed (TERM, then KILL one second later; exit 143 or 137), which falls through to the block below.',
      '# The hook input (stdin) is passed on through fd 3 (a background command would otherwise get /dev/null).',
      '# The hook runs in its own process group with its output in private files, so nothing it started can hold the pipes of the agent open or outlive the deadline: the launcher kills the whole group and prints the answer itself.',
      'zn_run() {',
      '  # No timer, no deadline, no private output: then the hook is not run at all and the launcher blocks.',
      '  [ -x /bin/sleep ] || { ' + noTimer + '; return 0; }',
      '  zn_mk out; ZN_OF=$ZN_MK; [ -n "$ZN_OF" ] || { ' + noTimer + '; return 0; }',
      '  zn_mk err; ZN_EF=$ZN_MK; [ -n "$ZN_EF" ] || { zn_rm "$ZN_OF"; ' + noTimer + '; return 0; }',
      '  trap \'zn_rm "$ZN_OF" "$ZN_EF" "$ZN_AF"\' EXIT',
      '  # TERM, HUP or INT (the agent gives up on the hook): stop the hook and answer with the block of this event, not with silence.',
      '  trap zn_term HUP INT TERM',
      '  # Own process group: setsid (Linux) or perl (macOS); with neither, only the hook itself is stopped at the deadline (its output is still private).',
      '  ZN_G=; for ZN_X in /usr/bin/setsid /bin/setsid; do [ -x "$ZN_X" ] && { ZN_G=1; ZN_GX=$ZN_X; break; }; done',
      '  [ -n "$ZN_G" ] || { [ -x /usr/bin/perl ] && { ZN_G=2; ZN_GX=/usr/bin/perl; }; }',
      '  exec 3<&0',
      '  case $ZN_G in',
      '    1) "$ZN_GX" "$@" <&3 3<&- >"$ZN_OF" 2>"$ZN_EF" & ;;',
      '    2) "$ZN_GX" -e \'setpgrp(0,0); exec { $ARGV[0] } @ARGV; exit 127\' "$@" <&3 3<&- >"$ZN_OF" 2>"$ZN_EF" & ;;',
      '    *) "$@" <&3 3<&- >"$ZN_OF" 2>"$ZN_EF" & ;;',
      '  esac',
      '  exec 3<&-',
      '  ZN_P=$!',
      '  # At the deadline the hook group gets TERM; if it is still there one second later (it ignores TERM) it gets KILL. A timer that cannot sleep ends the hook too.',
      '  ( trap \'kill $ZN_SP 2>/dev/null; exit 0\' TERM; /bin/sleep ' + deadlineS + ' & ZN_SP=$!; wait $ZN_SP; kill -TERM -$ZN_P 2>/dev/null; kill -TERM $ZN_P 2>/dev/null; /bin/sleep 1 & ZN_SP=$!; wait $ZN_SP; kill -KILL -$ZN_P 2>/dev/null; kill -KILL $ZN_P 2>/dev/null ) >/dev/null 2>&1 </dev/null &',
      '  ZN_T=$!',
      '  wait $ZN_P; ZN_RC=$?',
      '  # The hook is done: a TERM, HUP or INT now must not cut the answer being passed on or add a second one after it.',
      '  trap \'\' HUP INT TERM',
      '  # A status 0 counts only when the hook confirmed that its whole answer was written.',
      '  if [ "$ZN_RC" = 0 ]; then zn_acked || { ZN_RC=1; ZN_NOACK=1; }; fi',
      '  kill -TERM $ZN_T 2>/dev/null',
      '  kill -KILL -$ZN_P 2>/dev/null',
      '  case $ZN_RC in 0|2) zn_relay "$ZN_OF" || ZN_RC=127 ;; esac',
      '  zn_relay "$ZN_EF" >&2',
      '  return 0',
      '}',
    ] : []),
    '# The hook confirms through a private file (ZN_HOOK_ACK) that it wrote its whole answer: a status 0 without that confirmation (a hook that',
    '# could not write its answer, a runner that stopped half way) is a failure, not an answer. With no private file no run is accepted as done.',
    '# Private files: mktemp by absolute path (random name, exclusive creation). Without mktemp the name is predictable, so the file is opened read-write (that',
    '# never blocks on a FIFO) and used only when it is a new, empty, regular file of ours and not a link: a FIFO, link or foreign file planted there is skipped.',
    'zn_mk() {',
    '  ZN_MK=',
    '  for ZN_M in /usr/bin/mktemp /bin/mktemp /run/current-system/sw/bin/mktemp /run/current-system/profile/bin/mktemp; do [ -x "$ZN_M" ] && { ZN_MK=$(umask 077; "$ZN_M" "${TMPDIR:-/tmp}/zn-$1.XXXXXX" 2>/dev/null) && break; ZN_MK=; }; done',
    '  [ -z "$ZN_MK" ] || return 0',
    '  for ZN_I in 1 2 3 4 5 6; do',
    '    ZN_MK="${TMPDIR:-/tmp}/zn-$1.$$.$ZN_I"; (umask 077; : <>"$ZN_MK") 2>/dev/null',
    '    if [ -f "$ZN_MK" ] && [ ! -h "$ZN_MK" ] && [ -O "$ZN_MK" ] && [ ! -s "$ZN_MK" ]; then return 0; fi',
    '  done',
    '  ZN_MK=',
    '}',
    'zn_mk ack; ZN_AF=$ZN_MK',
    'export ZN_HOOK_ACK="$ZN_AF"',
    'trap \'zn_rm "$ZN_AF"\' EXIT',
    'zn_acked() { [ -n "$ZN_AF" ] || return 1; ZN_X=; read -r ZN_X <"$ZN_AF" 2>/dev/null; [ "$ZN_X" = ok ]; }',
    '# Passes a private output file on to the agent: cat by absolute path, else the shell alone (the PATH of a hook can be empty). A failed write is a failure.',
    'zn_relay() {',
    '  for ZN_X in /bin/cat /usr/bin/cat /run/current-system/sw/bin/cat /run/current-system/profile/bin/cat; do [ -x "$ZN_X" ] && { "$ZN_X" -- "$1"; return $?; }; done',
    '  while IFS= read -r ZN_L || [ -n "$ZN_L" ]; do printf \'%s\\n\' "$ZN_L" || return 1; done <"$1"',
    '}',
    'zn_leave() {',
    '  if [ "$1" = 0 ]; then zn_acked || { ZN_NOACK=1; return 0; }; fi',
    '  case $1 in 0|2) exit $1 ;; esac',
    '  return 0',
    '}',
    'ZN_RAN=',
    'if [ -x "$ZN_NODE" ] && [ -f "$ZN_RUNNER" ]; then ZN_RAN=1; ' + run('"$ZN_NODE" "$ZN_RUNNER" ' + agentId) + '; ' + 'zn_leave $ZN_RC; fi',
    '# Look up zn and node only in absolute PATH entries: a relative one depends on the folder the agent runs in.',
    'ZN_OLDIFS=$IFS; IFS=:; ZN_SAFE=',
    'for ZN_D in $PATH; do case "$ZN_D" in /*) ZN_SAFE="${ZN_SAFE:+$ZN_SAFE:}$ZN_D" ;; esac; done',
    'IFS=$ZN_OLDIFS',
    'ZN_CMD=; [ -z "$ZN_SAFE" ] || ZN_CMD=$(PATH="$ZN_SAFE" command -v zn 2>/dev/null)',
    'case "$ZN_CMD" in /*) ;; *) ZN_CMD= ;; esac',
    '# zn runs with that PATH too: its `#!/usr/bin/env node` line would otherwise find a node in a relative entry first.',
    'if [ -z "$ZN_RAN" ] && [ -n "$ZN_CMD" ] && PATH="$ZN_SAFE" command -v node >/dev/null 2>&1; then ZN_RAN=1; PATH=$ZN_SAFE; export PATH; : >"$ZN_AF" 2>/dev/null; ' + run('"$ZN_CMD" hook ' + agentId) + '; ' + 'zn_leave $ZN_RC; fi',
    'zn_block',
    '',
  ].join('\n');
}

/** Writes the launcher (directory 0700, file 0755) and returns its path. */
function writeLauncher(agentId, nodePath, runnerPath, opts = {}) {
  const file = launcherFile(agentId, opts);
  const dir = path.dirname(file);
  // ZN_HOOK_DIR names any folder: the launcher in it runs on every tool call, so the folder must be ours and private.
  if ((opts.env || process.env).ZN_HOOK_DIR) ensureSafeHookDir(dir, opts.platform || process.platform, { trustedRoot: opts.hookDirTrustedRoot, readWinAcls: opts.readWinAcls, setWinPrivate: opts.setWinPrivate });
  else fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  // On Windows the script runs in Git Bash: write the paths with / so that `zn-gate check` can read them back.
  const platform = opts.platform || process.platform;
  writeFileAtomic(file, unixScript(agentId, portablePath(nodePath, platform), portablePath(runnerPath, platform), { deadlineS: opts.deadlineS, deadlineSoft: opts.deadlineSoft }), 0o755);
  // Windows: the folder cannot be held open, so check the chain again after the write, now with the launcher file itself (owner
  // and access list, counting what it inherited from the folder); a swap in between removes the file.
  if (platform === 'win32' && (opts.env || process.env).ZN_HOOK_DIR) {
    try { ensureSafeHookDir(dir, platform, { trustedRoot: opts.hookDirTrustedRoot, readWinAcls: opts.readWinAcls, setWinPrivate: opts.setWinPrivate, file }); } catch (e) { try { fs.unlinkSync(file); } catch (_) { /* best effort */ } throw e; }
  }
  try { fs.chmodSync(file, 0o755); } catch (_) { /* best effort */ }
  return file;
}

/** The hook command for one event: the launcher, then the event name. */
function launcherCommand(file, event, platform = process.platform, opts = {}) {
  // `plain`: no quotes, for an agent that splits the command on spaces and runs it with no shell (Antigravity).
  // The caller has checked that the path needs no quoting (see plainPathOk).
  if (opts.plain) return portablePath(file, platform) + ' ' + event;
  return shQuote(portablePath(file, platform)) + ' ' + event;
}

/*
 * The hook command of a project install for an agent that reads a deny JSON on stdout and runs the command split on
 * spaces with no shell (Antigravity). A project file is shared through the repository, so it cannot name this
 * machine's launcher: it names `zn` on the PATH, and a `zn` or `node` that is missing must still end in a deny with
 * the repair step, where a plain `zn hook <agent>` would be exit 127 with no text from zn.
 *
 * The command is `sh -c <script>` with a script that holds no space, quote-free of anything the split could break:
 * each space is the expansion ${IFS} (field splitting turns it back into spaces) and each space inside the JSON text
 * is the printf escape \040. Only simple commands joined by ; && || are used, because a compound command
 * (if, case) is told apart by real whitespace. Steps: the first `zn` and `node` found on the PATH, each of which must come
 * from an absolute PATH entry (a relative or empty entry depends on the folder the agent runs in, which may be the
 * repository itself); run `zn hook <agent>`; its exit code 0 (an answer) or 2 (its own refusal, deny JSON already printed)
 * ends it; anything else, or no zn or node, prints the deny JSON and exits 0, the way the user launcher does.
 *
 * `command -v` alone cannot tell where a program was found: dash prints the relative path, but bash as sh (the sh of
 * macOS, and of Linux systems where sh is bash) turns a program found through `.`, `bin` or an empty entry into an
 * absolute path. So the folder of each program found must also be an entry of ":$PATH:" as written. Every operand of a
 * test starts with x: bash 3.2 drops an empty quoted word next to an unquoted ${IFS} expansion, so `[ -n "" ]` would
 * become `[ -n ]`, which is true.
 */
// The hook scripts below use no cmdlet (Test-Path, Get-Command, New-Object...): a cmdlet belongs to a module, and Windows PowerShell 5.1
// searches the user's own Documents\WindowsPowerShell\Modules first, so a module planted there by the same account could answer in
// its place (and make the hook look done). Only .NET types, operators and keywords: zf finds a program on the PATH the way
// Get-Command did, with [System.IO.File]::Exists.
// Before that, the PATH keeps only its absolute entries (C:\... or \\server\...) and cmd.exe no longer looks in the current folder
// first: zn.cmd starts `node` through cmd.exe when no node.exe sits next to it (a standard Node.js install), and a relative entry,
// or the folder the agent runs in (possibly the repository), could otherwise give a planted zn.cmd, node.exe or node.bat.
const ZF = "$env:NoDefaultCurrentDirectoryInExePath = '1'; $env:PATH = (($env:PATH -split ';') -match '^([A-Za-z]:\\\\|\\\\\\\\)') -join ';'; " +
  "function zf($x) { foreach ($d in ($env:PATH -split ';')) { try { if ($d) { $c = [System.IO.Path]::Combine($d, $x); if ([System.IO.File]::Exists($c)) { return $c } } } catch {} }; return $null }; ";

const IFS = '${IFS}';
const SH_SAFE_TEXT = /^[^'"\\%$\n\r]+$/;

function projectTexts(agentId) {
  const missing = 'zn: its hook cannot start because zn or Node.js was not found on the PATH, so this was blocked. Ask the user to run `npm install -g zn-gate` in their terminal.';
  const crash = crashText(agentId);
  const warnMissing = 'zn is NOT protecting this session: its hook cannot start because zn or Node.js was not found on the PATH. Please run `npm install -g zn-gate` in your own terminal.';
  const warnCrash = crashWarnText();
  for (const t of [missing, crash, warnMissing, warnCrash]) if (!SH_SAFE_TEXT.test(t)) throw new Error('zn: unsafe text in the project hook');
  return { missing, crash, warnMissing, warnCrash };
}

// What the guard prints when the hook cannot start, for the agents that read a block from a deny JSON on stdout (exit 0).
const PROJECT_DENY_JSON = {
  antigravity: (r) => ({ decision: 'deny', reason: r }),
  copilot: (r) => ({ permissionDecision: 'deny', permissionDecisionReason: r }),
};
// Windows: Cursor and Gemini CLI read the deny JSON only with exit 0 (see windowsScript), so there a block is the JSON plus exit 0.
const PROJECT_WIN_DENY_JSON = {
  cursor: (r) => ({ permission: 'deny', continue: false, user_message: r, agent_message: r }),
  gemini: (r) => ({ decision: 'deny', reason: r }),
};

/**
 * What the project hook of one agent and event answers when `zn` or Node.js cannot start (why: 'missing') or the hook ran and
 * failed (why: 'crash'): {stdout, stderr, exit}, each text or null. A blocking event answers the agent's own blocking response
 * (exit 2 with the reason on stderr, or the deny JSON); an event that cannot block only warns. Antigravity (no event given)
 * denies every call, as its project hook always did.
 */
function projectAnswer(agentId, event, why, win) {
  const t = projectTexts(agentId);
  const crash = why === 'crash';
  const block = agentId === 'antigravity' ? true : agentId === 'copilot' ? event === 'preToolUse' : blockExit(agentId).has(event);
  if (block) {
    const r = crash ? t.crash : t.missing;
    if (PROJECT_DENY_JSON[agentId]) return { stdout: JSON.stringify(PROJECT_DENY_JSON[agentId](r)), stderr: null, exit: 0 };
    if (win && PROJECT_WIN_DENY_JSON[agentId]) return { stdout: JSON.stringify(PROJECT_WIN_DENY_JSON[agentId](r)), stderr: r, exit: 0 };
    return { stdout: null, stderr: r, exit: 2 };
  }
  const w = crash ? t.warnCrash : t.warnMissing;
  if (agentId !== 'copilot' && blockJson(agentId).has(event)) {
    return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: 'PermissionRequest', decision: { behavior: 'deny', message: crash ? t.crash : t.missing } } }), stderr: null, exit: 0 };
  }
  if (agentId === 'copilot' || WARN_STDERR.has(agentId)) return { stdout: null, stderr: w, exit: 0 };
  return { stdout: JSON.stringify({ systemMessage: w }), stderr: null, exit: 0 };
}

// The project guard trusts the zn and node it found only when the folder of each one is an entry of the PATH as written:
// P is ":$PATH:"; T is set when the folder of $Z (with or without a final slash) is in it, U the same for $N.
const PROJECT_TRUST = [
  'P=:$PATH:',
  'ZD=${P#*":${Z%/*}:"}', 'ZS=${P#*":${Z%/*}/:"}', 'ND=${P#*":${N%/*}:"}', 'NS=${P#*":${N%/*}/:"}',
  'T=', '[ "$ZD" != "$P" ] && T=z', '[ "$ZS" != "$P" ] && T=z',
  'U=', '[ "$ND" != "$P" ] && U=n', '[ "$NS" != "$P" ] && U=n',
];

/**
 * The POSIX project hook command (see above) for one event (omit it for Antigravity). Every agent that runs project hooks
 * through a shell gets the same guard, so a `zn` or Node.js that is gone ends in that agent's own blocking answer instead of
 * exit 127, which the agents run through as a non-blocking error.
 */
function projectShCommand(agentId, event) {
  checkAgentId(agentId);
  if (event !== undefined && !/^[A-Za-z]+$/.test(String(event))) throw new Error('zn: bad event name');
  // An agent that runs the command through a shell (every one but Antigravity) gets the readable script in single quotes: the
  // ${IFS} form below is for a command split on spaces with no shell, and a shell such as zsh does not split an unquoted ${IFS}.
  if (agentId !== 'antigravity') {
    const crash = projectAnswer(agentId, event, 'crash', false);
    const missing = projectAnswer(agentId, event, 'missing', false);
    const say = (a) => [
      ...(a.stdout ? ["echo '" + a.stdout + "'"] : []),
      ...(a.stderr ? ["echo '" + a.stderr + "' >&2"] : []),
      'exit ' + a.exit,
    ].join('; ');
    const script = 'Z=$(command -v zn); N=$(command -v node); ' + PROJECT_TRUST.join('; ') + '; R=missing; ' +
      'if [ -n "$N" ] && [ "${Z#/}" != "$Z" ] && [ "${N#/}" != "$N" ] && [ -n "$T" ] && [ -n "$U" ]; then R=ran; "$Z" hook ' + agentId + '; C=$?; [ "$C" = 0 ] && exit 0; [ "$C" = 2 ] && exit 2; fi; ' +
      'if [ "$R" = ran ]; then ' + say(crash) + '; fi; ' + say(missing);
    return 'sh -c ' + shQuote(script);
  }
  const sp = (...w) => w.join(IFS);
  const esc = (x) => "'" + x.replace(/ /g, '\\040') + "\\n'";
  const say = (a) => [
    ...(a.stdout ? [sp('printf', esc(a.stdout))] : []),
    ...(a.stderr ? [sp('printf', esc(a.stderr)) + '>&2'] : []),
  ];
  const test = (...w) => '[' + IFS + w.join(IFS) + IFS + ']';
  const crash = projectAnswer(agentId, event, 'crash', false);
  const missing = projectAnswer(agentId, event, 'missing', false);
  const script = [
    ':',
    'Z=$(' + sp('command', '-v', 'zn') + ')',
    'N=$(' + sp('command', '-v', 'node') + ')',
    ...PROJECT_TRUST.map((x) => x.replace(/^\[ (.*) \] && /, (_, w) => test(...w.split(' ').map((o) => (o === '!=' ? o : o.replace(/^"/, '"x')))) + '&&')),
    'R=missing',
    [test('"x$N"', '!=', 'x'), test('"x${Z#/}"', '!=', '"x$Z"'), test('"x${N#/}"', '!=', '"x$N"'), test('"x$T"', '!=', 'x'), test('"x$U"', '!=', 'x')].join('&&') +
      '&&R=ran&&"$Z"' + IFS + 'hook' + IFS + agentId,
    'C=$?',
    test('"x$R"', '=', 'xran') + '&&' + test('"x$C"', '=', 'x0') + '&&' + sp('exit', '0'),
    test('"x$R"', '=', 'xran') + '&&' + test('"x$C"', '=', 'x2') + '&&' + sp('exit', '2'),
    [test('"x$R"', '=', 'xran'), ...say(crash), sp('exit', String(crash.exit))].join('&&'),
    ...say(missing),
    sp('exit', String(missing.exit)),
  ].join(';');
  if (/\s/.test(script)) throw new Error('zn: the project hook script holds a space');
  return 'sh -c ' + script;
}

/** The PowerShell text of the same project hook (for windowsScriptCommand). Ends with the comment that isOurs() reads. */
function projectWindowsScript(agentId, event) {
  checkAgentId(agentId);
  if (event !== undefined && !/^[A-Za-z]+$/.test(String(event))) throw new Error('zn: bad event name');
  const say = (a) => [
    ...(a.stdout ? ["[Console]::Out.WriteLine('" + a.stdout + "')"] : []),
    ...(a.stderr ? ["[Console]::Error.WriteLine('" + a.stderr + "')"] : []),
  ].join('; ') + '; exit ' + a.exit;
  const crash = projectAnswer(agentId, event, 'crash', true);
  const missing = projectAnswer(agentId, event, 'missing', true);
  // Only 0 (done) and 2 (blocked) leave early; with an answer that exits 0 (a deny JSON, a warning) the refusal passes on as exit 0.
  const leave = 'if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2) { exit ' + (crash.exit === 0 ? '0' : '$LASTEXITCODE') + ' }';
  return "$ProgressPreference='SilentlyContinue'; $zt=0; " + ZF +
    "if ((zf 'zn.cmd') -and ((zf 'node.exe') -or (zf 'node.cmd'))) { $zt=1; & (zf 'zn.cmd') hook " + agentId + '; ' + leave + ' }; ' +
    'if ($zt -eq 1) { ' + say(crash) + ' } else { ' + say(missing) + ' }; # zn hook ' + agentId;
}

/** Whether a command is the POSIX project hook of this agent as written by projectShCommand. */
function isProjectGuard(command, agentId) {
  try {
    if (typeof command !== 'string') return false;
    if (command === projectShCommand(agentId)) return true;
    // A later zn-gate may word the deny differently: recognize the guard by its structure (start and the hook call).
    if (command.startsWith("sh -c 'Z=$(command -v zn); N=$(command -v node); ") && command.includes('"$Z" hook ' + agentId + '; C=$?;')) return true;
    return command.startsWith('sh -c :;Z=$(' + ['command', '-v', 'zn'].join(IFS) + ')') && command.includes(IFS + 'hook' + IFS + agentId + ';');
  } catch (_) { return false; }
}

/** Whether a command is a Windows project hook script of this agent (the readable PowerShell text). */
function isProjectWindowsScript(script, agentId) {
  try {
    if (typeof script !== 'string') return false;
    if (script === projectWindowsScript(agentId)) return true;
    return script.startsWith("$ProgressPreference='SilentlyContinue'; $zt=0; ") && (script.includes('& zn.cmd hook ' + agentId + ';') || script.includes("& (zf 'zn.cmd') hook " + agentId + ';')) && script.endsWith('# zn hook ' + agentId);
  } catch (_) { return false; }
}

/** Every event name an installer writes the project guard for (any agent); the exact check tries each one. */
const GUARD_EVENTS = [undefined, 'PreToolUse', 'PostToolUse', 'UserPromptSubmit', 'UserPromptExpansion', 'PermissionRequest', 'BeforeTool',
  'beforeMCPExecution', 'beforeReadFile', 'beforeShellExecution', 'beforeSubmitPrompt', 'preToolUse', 'postToolUse'];

/** Whether a command is exactly a POSIX project guard that this version writes (any event of this agent). */
function isProjectGuardExact(command, agentId) {
  try {
    return typeof command === 'string' && GUARD_EVENTS.some((e) => command === projectShCommand(agentId, e));
  } catch (_) { return false; }
}

/** Whether a script is exactly a Windows project guard that this version writes (any event of this agent). */
function isProjectWindowsScriptExact(script, agentId) {
  try {
    return typeof script === 'string' && GUARD_EVENTS.some((e) => script === projectWindowsScript(agentId, e));
  } catch (_) { return false; }
}

/** Whether a path can be written into a command with no quotes: only letters, digits and a few punctuation marks. */
function plainPathOk(file) {
  return /^[A-Za-z0-9_\/.@+=,:~-]+$/.test(String(file));
}

/** A path as one shell word: as is when it is plain, else in single quotes. */
function shWord(p) {
  return plainPathOk(p) ? p : "'" + String(p).replace(/'/g, "'\\''") + "'";
}

/** Plain words for a file system error on one folder of the ZN_HOOK_DIR path (never a raw code on its own). */
function describeFsError(e, p) {
  const code = e && e.code;
  if (code === 'ENOENT') return 'the folder ' + p + ' does not exist (or it was removed while zn was checking it)';
  if (code === 'ENOTDIR') return p + ' is a file, not a folder, so nothing can be created in or below it';
  if (code === 'EACCES' || code === 'EPERM') return 'you are not allowed to read or create ' + p;
  if (code === 'EROFS') return p + ' is on a read-only disk';
  if (code === 'ELOOP') return 'the links at ' + p + ' lead in a circle';
  return 'the system refused to use ' + p + ' (' + (code || 'unknown error') + ')';
}

/**
 * Folders where a private launcher folder would pass the same rules as the check, tested on this machine: a link anywhere
 * in the path fails the rule, and /opt is one on some systems (Fedora Silverblue and other rpm-ostree systems: /opt -> /var/opt),
 * so each candidate is checked, not assumed. $XDG_DATA_HOME comes first when it is set, absolute and has no space.
 * `opts` (tests only): env, user, fs. Returns up to two { dir, command }.
 */
function hookDirSuggestions(opts = {}) {
  const env = opts.env || process.env;
  const fsx = opts.fs || fs;
  let user = opts.user;
  if (user === undefined) { try { user = os.userInfo().username; } catch (_) { user = ''; } }
  const who = /^[A-Za-z0-9_.-]{1,32}$/.test(String(user)) ? String(user) : '<you>';
  // The nearest existing folder of the path must be a real folder reached with no link; returns it, or null.
  const existingReal = (d) => {
    let e = d;
    for (;;) {
      let found = true;
      try { fsx.lstatSync(e); } catch (_) { found = false; }
      if (found) break;
      const up = path.dirname(e);
      if (up === e) return null;
      e = up;
    }
    try { return fsx.realpathSync(e) === e && fsx.statSync(e).isDirectory() ? e : null; } catch (_) { return null; }
  };
  const canWrite = (e) => { try { fsx.accessSync(e, fs.constants.W_OK); return true; } catch (_) { return false; } };
  const out = [];
  const xdg = env.XDG_DATA_HOME;
  if (xdg && path.isAbsolute(xdg)) {
    const d = path.join(xdg, 'zn-hooks');
    const e = plainPathOk(d) ? existingReal(d) : null;
    if (e) out.push({ dir: d, command: canWrite(e) ? 'mkdir -p -m 700 ' + d : 'sudo mkdir -p -m 700 ' + d + ' && sudo chown ' + who + ' ' + d });
  }
  for (const base of ['/opt', '/var/opt', '/usr/local']) {
    if (out.length >= 2) break;
    const d = base + '/' + who + '-zn-hooks';
    const e = plainPathOk(base + '/' + (who === '<you>' ? 'you' : who) + '-zn-hooks') ? existingReal(base) : null;
    if (e) out.push({ dir: d, command: canWrite(e) ? 'mkdir -m 700 ' + d : 'sudo mkdir -m 700 ' + d + ' && sudo chown ' + who + ' ' + d });
  }
  return out;
}

/** The "for example" sentence of the messages, built from hookDirSuggestions (and a note when /opt is a link here). */
function suggestionText(opts = {}) {
  const fsx = opts.fs || fs;
  const list = hookDirSuggestions(opts);
  let note = '';
  try {
    if (fsx.lstatSync('/opt').isSymbolicLink()) note = ' (/opt is a link on this machine, to ' + fsx.realpathSync('/opt') + ', so it does not qualify)';
  } catch (_) { /* no /opt, or not readable: no note */ }
  if (!list.length) return 'Choose any folder that meets these rules' + note + '.';
  return 'For example `' + list.map((x) => x.command).join('` or `') + '`' + note + ', and use that folder as ZN_HOOK_DIR.';
}

/** Why zn will not use a folder for the launchers (ZN_HOOK_DIR), and the way out. `fix` (optional) is the step for this exact problem. */
function unsafeDirMessage(dir, why, fix, opts) {
  return 'zn will not keep its hook launcher in ' + dir + ': ' + why + '. The launcher runs on every tool call, so anyone who can replace it could run commands as you. ' +
    (fix ? fix + ' ' : '') +
    'Use a folder that you own, whose path has no link, and where every folder above it belongs to you or to root and cannot be written by anyone else ' +
    '(/tmp and shared folders do not qualify, even with the sticky bit). ' + suggestionText(opts) +
    ' Or unset ZN_HOOK_DIR to use ~/.zn/hooks.';
}

/** The step that closes a folder others can write: nothing for a shared (sticky) one, no sudo for your own folder, sudo only for root's. */
function writableFix(p, st, me) {
  if ((st.mode & 0o1000) !== 0) return p + ' is a shared folder (sticky bit), so do not change it; choose a folder somewhere else.';
  if (me !== null && st.uid === me) return 'To close it, run `chmod g-w,o-w ' + shWord(p) + '`.';
  if (st.uid === 0) return p + ' belongs to root, so closing it takes administrator rights (`sudo chmod g-w,o-w ' + shWord(p) + '`), and other users of this machine may rely on it being shared; the safer way is to choose another folder.';
  return p + ' belongs to another user: ask them (or the administrator) to close it, or choose another folder.';
}

/**
 * Checks one folder of the chain that leads to the launcher folder (`leafPath`): a folder that exists, owned by root or the
 * current user, with no write for group or others (no exception for the sticky bit: /tmp itself fails). Throws a plain error
 * that names the folder that fails and why.
 */
function checkAncestor(dir, leafPath) {
  const leaf = dir === leafPath;
  let st;
  try { st = fs.lstatSync(dir); } catch (e) { throw new Error(unsafeDirMessage(leafPath, describeFsError(e, dir), 'Create the folder or choose another one.')); }
  if (leaf) {
    if (st.isSymbolicLink()) throw new Error(unsafeDirMessage(dir, 'it is a link', 'Use the folder it leads to instead, if that one meets these rules.'));
    if (!st.isDirectory()) throw new Error(unsafeDirMessage(dir, 'it is not a folder', 'Move or remove that file, or choose another folder.'));
  }
  const me = typeof process.getuid === 'function' ? process.getuid() : null;
  if (me !== null && st.uid !== me && !(!leaf && st.uid === 0)) {
    throw new Error(unsafeDirMessage(leafPath, leaf ? 'it belongs to another user' : 'the folder above it, ' + dir + ', belongs to another user (it must belong to you or to root)', 'Choose a folder under one you own.'));
  }
  if ((st.mode & 0o022) !== 0) {
    const mode = (st.mode & 0o777).toString(8);
    throw new Error(unsafeDirMessage(leafPath, leaf ? 'other users can write to it (mode ' + mode + ')' : 'the folder above it, ' + dir + ', can be written by other users (mode ' + mode + ')', writableFix(dir, st, me)));
  }
}

/** The first link in a path, from the top: { link, target }, or null. */
function firstLinkIn(start) {
  const parts = [];
  for (let p = start; ; p = path.dirname(p)) { parts.unshift(p); if (path.dirname(p) === p) break; }
  for (const p of parts) {
    try { if (fs.lstatSync(p).isSymbolicLink()) return { link: p, target: fs.realpathSync(p) }; } catch (_) { return null; }
  }
  return null;
}

/**
 * Checks the whole chain from `start` (a folder that exists) up to /: no link anywhere in the path (the real path must be
 * the path itself) and every folder trusted (checkAncestor). `trustedRoot` is internal and only for tests: the walk stops
 * before that folder, because the test folders live under the system temp folder, which is shared by design. Production
 * never passes it.
 */
function checkChain(start, trustedRoot, leafPath) {
  let real;
  try { real = fs.realpathSync(start); } catch (e) { throw new Error(unsafeDirMessage(leafPath, describeFsError(e, e.path || start), 'Create the folder or choose another one.')); }
  if (real !== start) {
    const l = firstLinkIn(start);
    throw new Error(unsafeDirMessage(start, l ? 'the path goes through a link: ' + l.link + ' leads to ' + l.target : 'a link is in its path (it leads to ' + real + ')',
      'Use ' + real + ' (the folder it really is) instead, if that folder meets these rules.'));
  }
  let p = start;
  for (;;) {
    if (trustedRoot && p === trustedRoot) return;
    checkAncestor(p, leafPath);
    const up = path.dirname(p);
    if (up === p) return;
    p = up;
  }
}

// ---- Windows rule for ZN_HOOK_DIR -------------------------------------------------------------------------------
// Windows has no uid or mode, so the same idea is checked with the owner and the access list (ACL) of every folder in the
// chain, read with the system PowerShell (.NET GetAccessControl, no module), plus "no link, junction or other reparse point
// anywhere in the path". A folder is refused when its owner is not you, SYSTEM, Administrators or TrustedInstaller, or when an
// allow entry for anybody else (Users, Everyone, Authenticated Users, another account) gives a right that lets them replace
// it or what is in it: delete it, delete what it holds, change its access list or owner, and (for the launcher folder itself)
// create or write files in it, directly or through an entry that new files inherit. The launcher file itself is checked after it
// is written: owner, and no allow entry for anybody else that lets them write, delete or re-permission it.
const WIN_TRUSTED_SIDS = new Set([
  'S-1-5-18', // SYSTEM
  'S-1-5-32-544', // Administrators
  'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', // TrustedInstaller
  'S-1-3-0', // CREATOR OWNER (takes the owner's rights; the owner is checked on its own)
  'S-1-3-4', // OWNER RIGHTS (the owner is checked on its own)
]);
const WIN_RIGHTS = { WRITE_DATA: 0x2, APPEND_DATA: 0x4, DELETE_CHILD: 0x40, DELETE: 0x10000, WRITE_DAC: 0x40000, WRITE_OWNER: 0x80000, GENERIC_ALL: 0x10000000, GENERIC_WRITE: 0x40000000 };
const WIN_OBJECT_INHERIT = 0x2;

/** True when an allow entry with these rights lets its holder replace the folder (or, for the leaf and the file, write to it). */
function winRisky(rights, kind) {
  const r = Number(rights) >>> 0;
  let mask = WIN_RIGHTS.DELETE_CHILD | WIN_RIGHTS.DELETE | WIN_RIGHTS.WRITE_DAC | WIN_RIGHTS.WRITE_OWNER | WIN_RIGHTS.GENERIC_ALL | WIN_RIGHTS.GENERIC_WRITE;
  if (kind !== 'ancestor') mask |= WIN_RIGHTS.WRITE_DATA | WIN_RIGHTS.APPEND_DATA;
  return (r & mask) !== 0;
}

/**
 * Why a folder (kind 'ancestor' or 'leaf') or the launcher file (kind 'file') cannot be trusted on Windows, or null.
 * `entry` = { path, owner, reparse, aces:[{sid,rights,type,inheritOnly,inh}] }. An inherit-only entry does not count for a
 * folder above the launcher, but it does for the launcher folder when files inherit it (ObjectInherit): the launcher would get it.
 */
function winProblem(entry, user, kind) {
  const who = kind === 'ancestor' ? 'a folder above it (' + entry.path + ')' : 'it';
  if (entry.reparse) return kind === 'file' ? 'the launcher is a link' : 'a link, junction or synced folder is in its path (' + entry.path + ')';
  if (!entry.owner || (entry.owner !== user && !WIN_TRUSTED_SIDS.has(entry.owner))) return kind === 'ancestor' ? who + ' belongs to another user' : (kind === 'file' ? 'the launcher file belongs to another user' : 'it belongs to another user');
  for (const a of entry.aces || []) {
    if (String(a.type).toLowerCase() !== 'allow' && Number(a.type) !== 0) continue;
    if (a.inheritOnly) {
      if (kind === 'ancestor') continue;
      if (kind === 'leaf' && !((Number(a.inh) || 0) & WIN_OBJECT_INHERIT)) continue;
      if (kind === 'file') continue;
    }
    if (a.sid === user || WIN_TRUSTED_SIDS.has(a.sid)) continue;
    if (winRisky(a.rights, kind)) return (kind === 'file' ? 'the launcher file' : who) + ' can be changed by other users (' + a.sid + ')';
  }
  return null;
}

// Both scripts are fixed text with no quotes of their own; the paths and the SID come in through the environment. They use no
// cmdlet at all: only .NET types, static methods, operators and keywords. A cmdlet (Get-Acl, ConvertTo-Json, New-Object...)
// belongs to a module, and Windows PowerShell 5.1 builds its module path with the user's own Documents\WindowsPowerShell\Modules
// FIRST, so a module planted there by the same account would answer in place of the real one. The answer is written by hand, one
// line per fact (see parseWinAcls), so there is no ConvertTo-Json either.
const WIN_ACL_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  '$t = [string][char]9',
  '$n = [string][char]10',
  '$sb = [System.Text.StringBuilder]::new()',
  '$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
  "[void]$sb.Append('U').Append($t).Append($me).Append($n)",
  "foreach ($p in ($env:ZN_ACL_PATHS -split '[|]')) {",
  '  $attr = [int][System.IO.File]::GetAttributes($p)',
  '  $dir = 0; if (($attr -band 16) -ne 0) { $dir = 1 }',
  '  $rp = 0; if (($attr -band 1024) -ne 0) { $rp = 1 }',
  '  if ($dir -eq 1) { $a = [System.IO.DirectoryInfo]::new($p).GetAccessControl() } else { $a = [System.IO.FileInfo]::new($p).GetAccessControl() }',
  '  $o = $a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value',
  '  $pb = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($p))',
  "  [void]$sb.Append('E').Append($t).Append($pb).Append($t).Append($o).Append($t).Append($dir).Append($t).Append($rp).Append($n)",
  '  foreach ($r in $a.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {',
  '    $io = 0; if (([int]$r.PropagationFlags -band 2) -ne 0) { $io = 1 }',
  "    [void]$sb.Append('A').Append($t).Append($r.IdentityReference.Value).Append($t).Append([int64]$r.FileSystemRights).Append($t).Append([string]$r.AccessControlType).Append($t).Append($io).Append($t).Append([int]$r.InheritanceFlags).Append($n)",
  '  }',
  '}',
  "[void]$sb.Append('Z').Append($n)",
  '[Console]::Out.Write($sb.ToString())',
].join('\n');

const WIN_PRIVATE_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  '$sid = [System.Security.Principal.SecurityIdentifier]::new($env:ZN_SID)',
  '$acl = [System.Security.AccessControl.DirectorySecurity]::new()',
  '$acl.SetAccessRuleProtection($true, $false)',
  '$inh = [System.Security.AccessControl.InheritanceFlags]([int]1 -bor [int]2)',
  '$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inh, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)',
  '$acl.AddAccessRule($rule)',
  '[System.IO.DirectoryInfo]::new($env:ZN_DIR).SetAccessControl($acl)',
].join('\n');

/**
 * Runs one fixed PowerShell script with the system PowerShell and a minimal environment. The program is the absolute
 * path found through the kernel's \SystemRoot link (lib/exe.js), never a name looked up in the current directory or PATH, and the
 * environment holds only SystemRoot, windir, SystemDrive, a PATH of System32, a PSModulePath that names only the system module
 * folder (so the user's own Documents folder is not searched) and `extra`; no profile. `io` is for tests: { spawnSync, powershell }.
 */
function runWinPowerShell(script, extra, io = {}) {
  const spawnSync = io.spawnSync || require('child_process').spawnSync;
  const ps = io.powershell !== undefined ? io.powershell : require('../exe').systemPowerShell();
  if (!ps) throw new Error('the system PowerShell was not found');
  const w = path.win32;
  const root = w.dirname(w.dirname(w.dirname(w.dirname(ps))));
  const env = { SystemRoot: root, windir: root, SystemDrive: root.slice(0, 2), PATH: w.join(root, 'System32'), ...extra };
  for (const k of Object.keys(env)) if (/^psmodulepath$/i.test(k)) delete env[k];
  env.PSModulePath = require('../exe').systemPsModulePath(ps);
  // No execution policy argument: the policy covers script files, not the text of -Command.
  return spawnSync(ps, ['-NoProfile', '-NonInteractive', '-Command', script], {
    env, cwd: root, encoding: 'utf8', timeout: 30000, windowsHide: true,
  });
}

/**
 * Reads the line format of WIN_ACL_SCRIPT (tab separated; `U sid`, then per path `E base64(path) owner dir reparse` followed by
 * its `A sid rights type inheritOnly inheritance` lines, then `Z`) into { user, entries }. Anything else, or no `Z`, throws.
 */
function parseWinAcls(text) {
  const bad = () => new Error('could not read the access list of the folder (unreadable answer)');
  const sid = (s) => (/^S-1-[0-9-]+$/.test(s) ? s : null);
  let user = null;
  let done = false;
  let cur = null;
  const entries = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line) continue;
    if (done) throw bad();
    const f = line.split('\t');
    if (f[0] === 'U' && f.length === 2 && !user && sid(f[1])) user = f[1];
    else if (f[0] === 'E' && f.length === 5 && user && sid(f[2]) && /^[01]$/.test(f[3]) && /^[01]$/.test(f[4])) {
      cur = { path: Buffer.from(f[1], 'base64').toString('utf8'), owner: f[2], dir: f[3] === '1', reparse: f[4] === '1', aces: [] };
      entries.push(cur);
    } else if (f[0] === 'A' && f.length === 6 && cur && sid(f[1]) && /^-?[0-9]+$/.test(f[2]) && /^[A-Za-z]+$/.test(f[3]) && /^[01]$/.test(f[4]) && /^[0-9]+$/.test(f[5])) {
      cur.aces.push({ sid: f[1], rights: Number(f[2]), type: f[3], inheritOnly: f[4] === '1', inh: Number(f[5]) });
    } else if (f[0] === 'Z' && f.length === 1 && user) done = true;
    else throw bad();
  }
  if (!user || !done) throw bad();
  return { user, entries };
}

/** Reads owner, ACL and reparse flag of each path with PowerShell: { user, entries }. Throws when it cannot (the caller fails closed). */
function readWinAcls(paths, io) {
  const res = runWinPowerShell(WIN_ACL_SCRIPT, { ZN_ACL_PATHS: paths.join('|') }, io);
  if (res.error || res.status !== 0) throw new Error('could not read the access list of the folder (' + ((res.error && res.error.message) || String(res.stderr || '').trim().slice(0, 200) || 'exit ' + res.status) + ')');
  return parseWinAcls(res.stdout);
}

/** Gives the folder one owner-only, non-inherited entry for `sid` (the same shape as the private file module). */
function setWinPrivate(dir, sid, io) {
  if (!/^S-1-[0-9-]+$/.test(String(sid))) throw new Error('could not make the folder private (unexpected account id)');
  const res = runWinPowerShell(WIN_PRIVATE_SCRIPT, { ZN_DIR: dir, ZN_SID: sid }, io);
  if (res.error || res.status !== 0) throw new Error('could not make the folder private (' + ((res.error && res.error.message) || String(res.stderr || res.stdout || '').trim().slice(0, 200) || 'exit ' + res.status) + ')');
}

function winUnsafeMessage(dir, why) {
  return 'zn will not keep its hook launcher in ' + dir + ': ' + why + '. The launcher runs on every tool call, so anyone who can replace it could run commands as you. ' +
    'Use a folder that you own, whose path has no link, junction or synced (OneDrive) folder, and where no folder above it can be changed by other users (only you, SYSTEM, Administrators and TrustedInstaller), ' +
    'or unset ZN_HOOK_DIR to use the .zn/hooks folder in your home folder.';
}

/**
 * Walks from `start` (a folder that exists) up to the drive root and refuses a link or junction in any folder of the path
 * (before any ACL is read), then checks owner, ACL and reparse flag of every folder (and of `file`, the launcher, when given)
 * with one PowerShell call. `trustedRoot` is the same internal test option as on Unix: the walk stops before that folder.
 * Returns the SID of the current user.
 */
function checkWinChain(start, trustedRoot, leafPath, readAcls, file) {
  const folders = [];
  let p = start;
  for (;;) {
    if (trustedRoot && p === trustedRoot) break;
    let st;
    try { st = fs.lstatSync(p); } catch (e) { throw new Error(winUnsafeMessage(p, describeFsError(e, p))); }
    if (st.isSymbolicLink()) throw new Error(winUnsafeMessage(start, p === leafPath ? 'it is a link' : 'a link or junction is in its path (' + p + ')'));
    if (!st.isDirectory()) throw new Error(winUnsafeMessage(p, 'it is not a folder'));
    folders.push(p);
    const up = path.dirname(p);
    if (up === p) break;
    p = up;
  }
  const targets = folders.slice();
  if (file) {
    let st;
    try { st = fs.lstatSync(file); } catch (e) { throw new Error(winUnsafeMessage(leafPath, 'the launcher file ' + file + ' cannot be read (' + describeFsError(e, file) + ')')); }
    if (st.isSymbolicLink() || !st.isFile()) throw new Error(winUnsafeMessage(leafPath, 'the launcher is not a plain file'));
    targets.push(file);
  }
  let doc;
  try { doc = readAcls(targets); } catch (e) { throw new Error(winUnsafeMessage(start, e.message)); }
  const byPath = new Map(doc.entries.map((e) => [e.path, e]));
  for (const f of targets) {
    const entry = byPath.get(f);
    if (!entry) throw new Error(winUnsafeMessage(start, 'its access list could not be read (' + f + ')'));
    const kind = f === file ? 'file' : (f === leafPath ? 'leaf' : 'ancestor');
    const why = winProblem(entry, doc.user, kind);
    if (why) throw new Error(winUnsafeMessage(kind === 'ancestor' ? start : leafPath, why));
  }
  return doc.user;
}

/**
 * Creates the missing folders one level at a time. A new folder inherits whatever its parent grants (under C:\ that is Modify
 * for Authenticated Users) until it is made private, so each level is made private to `user` and must then be EMPTY: a file
 * or folder another user dropped in during that window is refused rather than kept. On any failure the levels created here
 * are removed again (best effort).
 */
function createPrivateWinFolders(abs, existing, user, setPrivate) {
  const missing = [];
  for (let p = abs; p !== existing; p = path.dirname(p)) missing.unshift(p);
  const made = [];
  try {
    for (const p of missing) {
      fs.mkdirSync(p);
      made.push(p);
      setPrivate(p, user);
      const held = fs.readdirSync(p);
      if (held.length) throw new Error(winUnsafeMessage(abs, 'a new folder was not empty when it was made private (' + p + ' holds ' + held.length + ' item(s))'));
    }
  } catch (e) {
    for (const p of made.reverse()) { try { fs.rmdirSync(p); } catch (_) { /* best effort */ } }
    throw e;
  }
}

function ensureSafeWinHookDir(dir, opts = {}) {
  const abs = path.resolve(dir);
  const trusted = opts.trustedRoot ? path.resolve(opts.trustedRoot) : null;
  const readAcls = opts.readWinAcls || readWinAcls;
  const setPrivate = opts.setWinPrivate || setWinPrivate;
  let existing = abs;
  while (!fs.existsSync(existing) && !isLink(existing)) existing = path.dirname(existing);
  if (isLink(abs)) throw new Error(winUnsafeMessage(dir, 'it is a link'));
  const user = checkWinChain(existing, trusted, abs, readAcls, existing === abs ? opts.file : null);
  if (existing === abs) return;
  createPrivateWinFolders(abs, existing, user, setPrivate);
  try {
    checkWinChain(abs, trusted, abs, readAcls);
  } catch (e) {
    try { fs.rmdirSync(abs); } catch (_) { /* best effort */ }
    throw e;
  }
}

/**
 * Makes sure the folder that holds the launchers can be trusted. Nothing is created or written until the whole chain is
 * checked: the folder (or its nearest existing parent) must be a real folder with no link anywhere in its path, and it and
 * every folder above it up to / must belong to the current user or root and have no write for group or others. The sticky
 * bit is no excuse, so /tmp and a folder under it are refused: they can be emptied or replaced by someone else, while the
 * hook command keeps pointing at the old path. Creates the folder (0700) when it is missing. Throws a plain error
 * otherwise. On Windows the same rule is read from the owner and the ACL of every folder in the chain (see the Windows rule above),
 * and a missing folder is created owner-only.
 */
function ensureSafeHookDir(dir, platform = process.platform, opts = {}) {
  if (platform === 'win32') return ensureSafeWinHookDir(dir, opts);
  const abs = path.resolve(dir);
  const trusted = opts.trustedRoot ? path.resolve(opts.trustedRoot) : null;
  let existing = abs;
  while (!fs.existsSync(existing) && !isLink(existing)) existing = path.dirname(existing);
  if (isLink(abs)) throw new Error(unsafeDirMessage(dir, 'it is a link'));
  checkChain(existing, trusted, abs);
  try { fs.mkdirSync(abs, { recursive: true, mode: 0o700 }); } catch (e) { throw new Error(unsafeDirMessage(dir, describeFsError(e, abs), 'Choose a folder you can create.')); }
  checkChain(abs, trusted, abs);
}

function isLink(p) {
  try { return fs.lstatSync(p).isSymbolicLink(); } catch (_) { return false; }
}

/** Why zn will not install the Antigravity hook at this launcher path, and the way out. `opts` (tests only): env, user, fs. */
function spaceMessage(file, opts) {
  return 'zn cannot install the Antigravity hook: the launcher would be at ' + file + ', and Antigravity starts a hook by splitting the command on spaces, ' +
    'without a shell or quotes, so a path with a space or another special character never starts, so the hook would protect nothing. ' +
    'Choose a folder outside the home folder whose path has only letters, digits and - _ . / (nothing else). ' + suggestionText(opts) +
    ' Then run `ZN_HOOK_DIR=<that folder> zn hooks install antigravity`, and nothing else changes. ' +
    'The folder must be one you own, with no link in its path, and every folder above it must belong to you or to root and not be writable by others: zn-gate refuses anything else, because the launcher in it runs on every tool call.';
}

/**
 * The PowerShell text (for windowsCommand-style quoting by the caller) of the
 * same three steps, ending with a comment that names the agent so that
 * isOurs() recognizes it. Null when a path holds a character that would need
 * escaping inside the script: the caller then keeps the plain command.
 */
function windowsScriptRaw(agentId, event, nodePath, runnerPath, opts = {}) {
  checkAgentId(agentId);
  // deadlineS (whole seconds, only for agents that fail open on a timeout, as in unixScript): the hook runs as a child with a deadline.
  const deadlineS = Number.isInteger(opts.deadlineS) && opts.deadlineS > 0 ? opts.deadlineS : 0;
  const n = portablePath(nodePath, 'win32');
  const r = portablePath(runnerPath, 'win32');
  if (/['‘’‚‛\u0000-\u001f]/.test(n + r)) return null;
  const reason = reasonText(agentId);
  const DENY_JSON = {
    antigravity: (r) => ({ decision: 'deny', reason: r }),
    cursor: (r) => ({ permission: 'deny', continue: false, user_message: r, agent_message: r }),
    gemini: (r) => ({ decision: 'deny', reason: r }),
  };
  const jsonDeny = Boolean(DENY_JSON[agentId]);
  // The block text (the Node.js is gone) or, when the hook ran and failed or timed out, the crash text.
  const tailOf = (reason, warn) => {
  let tail;
  // A PowerShell inside the agent's own PowerShell (Cursor) turns a nested exit 2 into 1, and both Cursor and
  // Gemini CLI read the deny JSON only with exit 0. So for them a block is the deny JSON plus exit 0; the
  // runner's own refusal (exit 2, deny JSON already on stdout) is passed on as exit 0 too.
  if (blockExit(agentId).has(event)) {
    tail = jsonDeny
      ? "[Console]::Out.WriteLine('" + JSON.stringify(DENY_JSON[agentId](reason)) + "'); [Console]::Error.WriteLine('" + reason + "'); exit 0"
      : "[Console]::Error.WriteLine('" + reason + "'); exit 2";
  }
  else if (blockJson(agentId).has(event)) tail = "[Console]::Out.WriteLine('" + JSON.stringify({ hookSpecificOutput: { hookEventName: 'PermissionRequest', decision: { behavior: 'deny', message: reason } } }) + "'); exit 0";
  else if (WARN_STDERR.has(agentId)) tail = "[Console]::Error.WriteLine('" + warn + "'); exit 0";
  else tail = "[Console]::Out.WriteLine('" + JSON.stringify({ systemMessage: warn }) + "'); exit 0";
  return 'zd; ' + tail;
  };
  const tail = tailOf(reason, warnText(agentId));
  // Only 0 (done) and 2 (blocked) leave early: a crash, an empty $LASTEXITCODE (a script the execution policy
  // refused) or any other code falls through to the block. zn.cmd, not zn.ps1, which Restricted refuses to run.
  // A 0 counts only when the hook confirmed (zk: the ack file holds ok) that its whole answer was written.
  const leave = jsonDeny
    ? 'if (($LASTEXITCODE -eq 0 -and (zk)) -or $LASTEXITCODE -eq 2) { zx 0 }'
    : 'if (($LASTEXITCODE -eq 0 -and (zk)) -or $LASTEXITCODE -eq 2) { zx $LASTEXITCODE }';
  if (deadlineS) {
    // zr runs the command as a child with the hook input passed on (stdin) and its output left alone; after the deadline the
    // child and everything it started are killed (taskkill /T) and zr gives -1, which falls through to the block below.
    const zr = 'function zr($f, $a) { $rc = -1; try { $i = [System.Diagnostics.ProcessStartInfo]::new(); $i.FileName = $f; $i.Arguments = $a; $i.UseShellExecute = $false; ' +
      '$i.RedirectStandardInput = $true; $sw = [System.Diagnostics.Stopwatch]::StartNew(); $p = [System.Diagnostics.Process]::Start($i); ' +
      'try { $c = [Console]::OpenStandardInput().CopyToAsync($p.StandardInput.BaseStream); [void]$c.Wait(' + deadlineS * 1000 + ') } catch {}; ' +
      'try { $p.StandardInput.Close() } catch {}; ' +
      '$left = [Math]::Max(0, ' + deadlineS * 1000 + ' - $sw.ElapsedMilliseconds); ' +
      'if ($p.WaitForExit([int]$left)) { $rc = $p.ExitCode } else { try { & "$env:SystemRoot\\System32\\taskkill.exe" /PID $p.Id /T /F *> $null } catch {}; try { $p.Kill() } catch {} } } catch {}; return $rc }; ';
    const zleave = jsonDeny
      ? 'if (($rc -eq 0 -and (zk)) -or $rc -eq 2) { zx 0 }'
      : 'if (($rc -eq 0 -and (zk)) -or $rc -eq 2) { zx $rc }';
    return "$ProgressPreference='SilentlyContinue'; $zt=0; " + ZF + zr +
      "if ([System.IO.File]::Exists('" + n + "') -and [System.IO.File]::Exists('" + r + "')) { $zt=1; $rc = zr '\"" + n + "\"' '\"" + r + "\" " + agentId + "'; " + zleave + ' }; ' +
      "if (($zt -eq 0) -and (zf 'zn.cmd') -and ((zf 'node.exe') -or (zf 'node.cmd'))) { $zt=1; $rc = zr (zf 'zn.cmd') 'hook " + agentId + "'; " + zleave + ' }; ' +
      'if ($zt -eq 1) { ' + tailOf(crashText(agentId), crashWarnText()) + ' }; ' + tail + ' # zn hook ' + agentId;
  }
  return "$ProgressPreference='SilentlyContinue'; $zt=0; " + ZF +
    "if ([System.IO.File]::Exists('" + n + "') -and [System.IO.File]::Exists('" + r + "')) { $zt=1; & '" + n + "' '" + r + "' " + agentId + '; ' + leave + ' }; ' +
    "if (($zt -eq 0) -and (zf 'zn.cmd') -and ((zf 'node.exe') -or (zf 'node.cmd'))) { & (zf 'zn.cmd') hook " + agentId + '; ' + leave + ' }; ' +
    tail + ' # zn hook ' + agentId;
}

// The private file through which the hook confirms that it wrote its whole answer (ZN_HOOK_ACK). zk reads it and clears it: true
// only when it held ok. zx removes it and leaves. When the file cannot be made nothing is accepted as done (zk is always false).
const ZK = "$za = $null; try { $za = [System.IO.Path]::GetTempFileName(); $env:ZN_HOOK_ACK = $za } catch {}; " +
  "function zk { $ok = $false; try { if ($za) { $ok = ([System.IO.File]::ReadAllText($za) -eq 'ok'); [System.IO.File]::WriteAllText($za, '') } } catch {}; return $ok }; " +
  "function zx($c) { try { if ($za) { [System.IO.File]::Delete($za) } } catch {}; exit $c }; function zd { try { if ($za) { [System.IO.File]::Delete($za) } } catch {} }; ";

/** windowsScriptRaw plus the ack file: every exit of the script removes it (zx), a 0 is accepted only with the ack (zk). */
function windowsScript(agentId, event, nodePath, runnerPath, opts = {}) {
  const t = windowsScriptRaw(agentId, event, nodePath, runnerPath, opts);
  if (t === null) return null;
  const head = "$ProgressPreference='SilentlyContinue'; $zt=0; ";
  if (!t.startsWith(head)) throw new Error('zn: unexpected launcher script');
  return head + ZK + t.slice(head.length);
}

/**
 * A powershell.exe call of the script, passed as -EncodedCommand (base64 of UTF-16LE): the script holds `$`, quotes and
 * backticks that cmd.exe, PowerShell or Git Bash would otherwise act on (the same encoding lib/shell-quote.js uses).
 */
function windowsScriptCommand(script, opts = {}) {
  const q = require('../shell-quote');
  return (opts.cmd ? q.CMD_POWERSHELL : q.powershellExe()) + ' -NoProfile -NonInteractive -EncodedCommand ' + Buffer.from(script, 'utf16le').toString('base64');
}

module.exports = { launcherDeadlineS, parseWinAcls, WIN_ACL_SCRIPT, WIN_PRIVATE_SCRIPT, projectShCommand, projectWindowsScript, isProjectGuard, isProjectWindowsScript, isProjectGuardExact, isProjectWindowsScriptExact, blockExit, blockJson, windowsScriptCommand, launcherDir, launcherFile, unixScript, writeLauncher, launcherCommand, plainPathOk, spaceMessage, unsafeDirMessage, hookDirSuggestions, describeFsError, writableFix, ensureSafeHookDir, readWinAcls, setWinPrivate, winProblem, windowsScript, BLOCK_EXIT, BLOCK_JSON };
