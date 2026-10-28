'use strict';

/**
 * Quoting for the paths zn writes into commands that a shell runs later:
 * hook commands in agent configs and the rewritten Bash, PowerShell and
 * Monitor commands of the hooks.
 *
 * Which shell reads each command:
 *  - Claude Code hooks: `sh -c` on macOS and Linux, Git Bash on Windows
 *    (PowerShell only when Git Bash is not installed). Its Bash and Monitor
 *    tools run bash; its PowerShell tool runs PowerShell.
 *  - Codex hooks: `$SHELL -lc` (or /bin/sh) on macOS and Linux; on Windows
 *    `commandWindows` goes through `%COMSPEC% /C` (cmd.exe).
 *  - Cursor hooks: a shell on macOS and Linux; on Windows Cursor usually
 *    wraps the command in PowerShell, and some versions use Git Bash.
 *  - OpenCode: the plugin spawns node with an argument list (no shell); its
 *    bash tool runs the user's shell ($SHELL), on Windows PowerShell unless
 *    SHELL names another shell.
 *
 * Paths are never interpreted: POSIX single quotes for sh-family shells and
 * PowerShell single-quoted strings for PowerShell. For Windows, where the
 * shell that reads a hook command is not always known, windowsCommand()
 * builds a powershell.exe call that cmd.exe, PowerShell and Git Bash all
 * run the same way. An sh-quoted command read by PowerShell is not a valid
 * call, but nothing in a single-quoted path runs there either.
 */

function checkNul(v) {
  if (v.includes('\0')) throw new Error('zn: a path with a NUL character cannot be passed to a command');
  return v;
}

// PowerShell treats the typographic single quotes as ' too, inside and at
// the end of a single-quoted string.
const PS_SINGLE_QUOTES = /['‘’‚‛]/g;
// What shQuote() moves out of the single quotes: the quotes above and the backslash.
const SH_SPECIAL = /['‘’‚‛\\]/g;

/**
 * POSIX sh single quotes: nothing inside is interpreted ($, backticks, \, ",
 * newlines). A single quote (and each typographic single quote) is written
 * as '"'"' rather than the usual '\'': sh reads both the same, and if
 * PowerShell reads the command instead (see the list above), the quote stays
 * inside a "..." string there too, so no part of the path becomes code.
 * A backslash is written as '"\\"' too: fish (a possible $SHELL for Codex
 * hooks) reads \\ and \' as escapes even inside single quotes.
 */
function shQuote(s) {
  return "'" + checkNul(String(s)).replace(SH_SPECIAL, (c) => (c === '\\' ? "'\"\\\\\"'" : "'\"" + c + "\"'")) + "'";
}

/** The escapes shQuote() writes for a quote inside a single-quoted word. */
const SH_QUOTE_ESCAPE = /'"(?:['‘’‚‛]|\\\\)"'/g;

/** PowerShell single-quoted string: no variables, subexpressions or escapes inside. */
function powershellQuote(s) {
  return "'" + checkNul(String(s)).replace(PS_SINGLE_QUOTES, '$&$&') + "'";
}

/**
 * Windows accepts / as well as \ in paths, and zn writes / there so the same
 * path reads the same in every command it builds (hook commands, the Monitor
 * wrapper and the rewritten Bash and PowerShell commands). Quoting does not
 * depend on it. On other systems \ is an ordinary file name character and is
 * kept.
 */
function portablePath(p, platform = process.platform) {
  const s = String(p);
  return platform === 'win32' ? s.replace(/\\/g, '/') : s;
}

// Characters that cmd.exe (%, ! with delayed expansion, "), an outer
// PowerShell double-quoted string ($, backtick, typographic double quotes)
// or Git Bash ($, backtick, ") would act on inside "...", plus control
// characters. A command with any of them is passed encoded instead.
const UNSAFE_IN_DOUBLE_QUOTES = /[%!"$`“”„\u0000-\u001F\u007F]/;

// The Windows PowerShell a hook command names, by its absolute path: cmd.exe (Codex runs hook commands through it) and the
// process start of several agents look in the current folder first, where a repository could hold a powershell.exe of its
// own. On Windows it is the system PowerShell (lib/exe.js systemPowerShell); when that cannot be found nothing is written
// (an error), never the bare name. A command written for Windows on another system names the default install folder.
const DEFAULT_POWERSHELL = 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe';
// The Windows folder (one folder under a drive) and System32\WindowsPowerShell\v1.0 below it: nothing else is the system PowerShell.
const PLAIN_POWERSHELL = /^[A-Za-z]:\/[A-Za-z0-9_.-]+\/System32\/WindowsPowerShell\/v1\.0\/powershell\.exe$/i;
function powershellExe(platform = process.platform) {
  if (platform !== 'win32') return DEFAULT_POWERSHELL;
  const ps = require('./exe').systemPowerShell();
  const p = ps ? portablePath(ps, 'win32') : null;
  if (p && PLAIN_POWERSHELL.test(p)) return p;
  throw new Error('zn: the Windows PowerShell (System32\\WindowsPowerShell\\v1.0\\powershell.exe) was not found under the Windows folder, so no hook was written. Next step: run the command again in a normal Windows session; if it keeps failing, report it.');
}
// For a command that only cmd.exe reads and that is shared between machines (the project hook of Codex): cmd.exe expands
// %SystemRoot% to the Windows folder of the machine that runs it.
const CMD_POWERSHELL = '%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
// The powershell.exe at the start of a hook command: one of the two forms above, or the bare name (earlier versions).
// The folder names are matched in any case (Windows writes C:\WINDOWS\system32 as often as C:\Windows\System32).
const POWERSHELL_EXE = '(?:[A-Za-z]:/[A-Za-z0-9_.-]+/[Ss][Yy][Ss][Tt][Ee][Mm]32/[Ww][Ii][Nn][Dd][Oo][Ww][Ss][Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]/[Vv]1\\.0/|%SystemRoot%\\\\System32\\\\WindowsPowerShell\\\\v1\\.0\\\\)?powershell\\.exe';

/**
 * A command that runs `& <program> <args...>` in powershell.exe and reads the
 * same from cmd.exe, PowerShell and Git Bash. Plain paths stay readable
 * (-Command "..."); a path with a character one of those shells would act on
 * inside double quotes is passed as -EncodedCommand (base64 of UTF-16LE),
 * which no shell changes. `opts.encoded` always uses -EncodedCommand, for an
 * agent that splits the command on spaces and ignores quotes.
 */
function windowsCommand(program, args, extra = [], opts = {}) {
  const inner = '& ' + [program, ...args].map((a) => powershellQuote(portablePath(a, 'win32'))).join(' ') +
    (extra.length ? ' ' + extra.join(' ') : '');
  const head = powershellExe() + ' -NoProfile -NonInteractive ';
  if (!opts.encoded && !UNSAFE_IN_DOUBLE_QUOTES.test(inner)) return head + '-Command "' + inner + '"';
  return head + '-EncodedCommand ' + Buffer.from(inner, 'utf16le').toString('base64');
}

/** The PowerShell text of a windowsCommand() result, or null when it is not one. */
function windowsCommandScript(command) {
  const s = String(command || '');
  let m = new RegExp('^' + POWERSHELL_EXE + ' -NoProfile -NonInteractive -Command "(.*)"\\s*$', 's').exec(s);
  if (m) return m[1];
  m = new RegExp('^' + POWERSHELL_EXE + ' -NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)\\s*$').exec(s);
  if (m) return Buffer.from(m[1], 'base64').toString('utf16le');
  return null;
}

/**
 * A windowsCommand() result in its readable -Command form, so code that
 * recognises zn's own hook commands sees one shape for both spellings. Any
 * other command is returned as it is.
 */
function readableWindowsCommand(command) {
  const s = String(command || '');
  const head = new RegExp('^(' + POWERSHELL_EXE + ') -NoProfile -NonInteractive -EncodedCommand ').exec(s);
  if (!head) return s;
  const script = windowsCommandScript(s);
  return script === null ? s : head[1] + ' -NoProfile -NonInteractive -Command "' + script + '"';
}

module.exports = { shQuote, SH_QUOTE_ESCAPE, powershellQuote, portablePath, powershellExe, CMD_POWERSHELL, POWERSHELL_EXE, windowsCommand, windowsCommandScript, readableWindowsCommand };
