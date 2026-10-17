'use strict';
/**
 * Out-of-band confirmation for the vault daemon.
 *
 * First use of a secret by a command and every policy change that widens
 * what a secret may reach are confirmed by the person at the keyboard on a
 * channel the agent does not control: never on the terminal of the command
 * that asked (an agent can drive that one, including with a pseudo-terminal).
 *
 * Channels, chosen when the daemon starts:
 *   tty    `zn unlock --foreground`: the daemon keeps its own terminal and
 *          asks there. An agent's shell has a different terminal and cannot
 *          type into this one.
 *   gui    a native dialog shown by the daemon:
 *            macOS    /usr/bin/osascript (display dialog)
 *            Windows  the system powershell.exe (found through the kernel's \SystemRoot link, never %SystemRoot%)
 *                     (WScript.Shell Popup, topmost, "No" is the default)
 *            Linux    /usr/bin/zenity or /usr/bin/kdialog, only with a
 *                     desktop session (DISPLAY or WAYLAND_DISPLAY)
 *   none   no channel (headless, detached daemon): every request is refused
 *          with a message that explains how to get one.
 *
 * Helpers are called by absolute path, the text reaches them as an argument
 * or an environment variable (never spliced into a script), and an
 * unanswered prompt counts as "no" after the timeout.
 *
 * Limits (see docs/threat-model.md): this raises the bar against prompt
 * injection driving the agent's tools; it is not a boundary against
 * malware running as the same OS user, which can also click a dialog.
 */

const fs = require('fs');
const { spawn } = require('child_process');

const DEFAULT_TIMEOUT_MS = 120000;
const MAX_TEXT = 1500;
const MAX_FIELD = 300;

// Control, line-break and invisible formatting characters (bidi overrides,
// zero-width, soft hyphen): they could fake extra lines or reorder text.
const INVISIBLE = '\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u180e\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\ufeff\\ufff9-\\ufffb';
const INVISIBLE_RE = new RegExp('[' + INVISIBLE + ']', 'g');
const CLEAN_RE = new RegExp('[' + INVISIBLE.replace('\\u0000-\\u001f', '\\u0000-\\u0009\\u000b-\\u001f') + ']', 'g');

/* Free text written by zn itself: keeps newlines, drops other controls. */
function clean(text) {
  return String(text || '').replace(/\r\n?/g, '\n').replace(CLEAN_RE, ' ').slice(0, MAX_TEXT);
}

/* A value that came from a client (a path, a project): one visible line,
 * invisible characters shown as \uXXXX, long values shortened in the middle
 * so both ends stay visible. */
function field(value, max) {
  const limit = max || MAX_FIELD;
  let s = String(value == null ? '' : value).replace(INVISIBLE_RE, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  if (s.length > limit) {
    const keep = limit - 3;
    s = s.slice(0, Math.ceil(keep / 2)) + '...' + s.slice(s.length - Math.floor(keep / 2));
  }
  return s;
}

/**
 * Text of a request. Structured requests ({warnings, fields, footer}) put
 * the warnings first and in full, then one line per field: no field can add
 * lines or push the warnings out. Plain requests ({message}) are cleaned.
 */
function render(req) {
  const r = req || {};
  if (!Array.isArray(r.fields)) return clean(r.message);
  const lines = [];
  for (const w of r.warnings || []) lines.push(field(w, 600));
  for (const [label, value] of r.fields) lines.push(field(label, 40) + ': ' + field(value));
  if (r.footer) lines.push(field(r.footer, 200));
  return lines.join('\n');
}

/* ------------------------------ none ------------------------------ */

const NO_CHANNEL = 'zn could not ask you outside the agent: no confirmation channel. ' +
  'Start the vault with `zn unlock --foreground` in a terminal of its own (it asks there), ' +
  'or unlock it from a desktop session so zn can show a dialog.';

function noneChannel() {
  return {
    kind: 'none',
    async confirm() {
      const err = new Error(NO_CHANNEL);
      err.code = 'ZN_POLICY_DENIED';
      err.noChannel = true;
      throw err;
    },
  };
}

/* ------------------------------ tty ------------------------------- */

/**
 * Ask on the daemon's own terminal. One question at a time; anything but
 * "y"/"yes" (or no answer before the timeout) is a no.
 */
function ttyChannel(opts = {}) {
  const input = opts.input || process.stdin;
  const output = opts.output || process.stderr;
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  let queue = Promise.resolve();

  function askOnce(req) {
    return new Promise((resolve) => {
      let buf = '';
      let done = false;
      const finish = (answer) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        input.removeListener('data', onData);
        if (typeof input.pause === 'function') input.pause();
        output.write(answer ? '  -> allowed\n' : '  -> denied\n');
        resolve(answer);
      };
      const onData = (chunk) => {
        buf += String(chunk);
        const nl = buf.search(/[\r\n]/);
        if (nl !== -1) finish(/^\s*y(es)?\s*$/i.test(buf.slice(0, nl)));
      };
      const timer = setTimeout(() => { output.write('\n  (no answer)'); finish(false); }, timeoutMs);
      if (timer.unref) timer.unref();
      output.write('\n\u0007zn: ' + field(req.title, 200) + '\n' + render(req).replace(/^/gm, '    ') + '\n  Allow? [y/N] ');
      if (typeof input.setEncoding === 'function') input.setEncoding('utf8');
      input.on('data', onData);
      if (typeof input.resume === 'function') input.resume();
    });
  }

  return {
    kind: 'tty',
    confirm(req) {
      const next = queue.then(() => askOnce(req || {}));
      queue = next.catch(() => false);
      return next;
    },
  };
}

/* ------------------------------ gui ------------------------------- */

function exists(p) {
  try { return fs.statSync(p).isFile(); } catch (_) { return false; }
}

// Popup type: 4 Yes/No + 48 warning icon + 256 second button (No) default + 4096 topmost.
const WIN_SCRIPT = [
  '$s = New-Object -ComObject WScript.Shell',
  '$r = $s.Popup($env:ZN_CONFIRM_TEXT, [int]$env:ZN_CONFIRM_SECONDS, $env:ZN_CONFIRM_TITLE, 4 + 48 + 256 + 4096)',
  'if ($r -eq 6) { exit 0 } else { exit 1 }',
].join('\r\n');

/** The helper command for this platform, or null when there is none. */
function guiCommand(req, opts = {}) {
  const env = opts.env || process.env;
  const platform = opts.platform || process.platform;
  const has = opts.exists || exists;
  const seconds = Math.max(5, Math.round((opts.timeoutMs || DEFAULT_TIMEOUT_MS) / 1000));
  const title = 'zn: ' + field(req.title, 120);
  const text = render(req);
  if (platform === 'darwin') {
    if (!has('/usr/bin/osascript')) return null;
    const script = [
      'on run argv',
      'display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" with icon caution giving up after ' + seconds,
      'if gave up of result then error number -128',
      'end run',
    ];
    const args = [];
    for (const line of script) args.push('-e', line);
    return { file: '/usr/bin/osascript', args: args.concat([title, text]), env: {} };
  }
  if (platform === 'win32') {
    // The system PowerShell only (never SystemRoot or PATH): without it there is no dialog, and approvals are refused.
    const ps = opts.powershell !== undefined ? opts.powershell : require('../exe').systemPowerShell();
    if (!ps || !has(ps)) return null;
    const encoded = Buffer.from(WIN_SCRIPT, 'utf16le').toString('base64');
    return {
      file: ps,
      args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
      env: { ZN_CONFIRM_TEXT: text, ZN_CONFIRM_TITLE: title, ZN_CONFIRM_SECONDS: String(seconds) },
    };
  }
  if (platform === 'linux' || platform === 'freebsd' || platform === 'openbsd') {
    if (!env.DISPLAY && !env.WAYLAND_DISPLAY) return null;
    if (has('/usr/bin/zenity')) {
      return {
        file: '/usr/bin/zenity',
        args: ['--question', '--no-markup', '--title=' + title, '--text=' + text, '--ok-label=Allow', '--cancel-label=Deny', '--default-cancel', '--timeout=' + seconds],
        env: {},
      };
    }
    if (has('/usr/bin/kdialog')) {
      return { file: '/usr/bin/kdialog', args: ['--title', title, '--warningyesno', text, '--yes-label', 'Allow', '--no-label', 'Deny'], env: {} };
    }
  }
  return null;
}

function guiAvailable(opts = {}) {
  return guiCommand({ title: 'x', message: 'x' }, opts) !== null;
}

function guiChannel(opts = {}) {
  const env = opts.env || process.env;
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const spawnFn = opts.spawn || spawn;
  let queue = Promise.resolve();

  function askOnce(req) {
    const cmd = guiCommand(req, opts);
    if (!cmd) return noneChannel().confirm();
    return new Promise((resolve) => {
      let child;
      try {
        child = spawnFn(cmd.file, cmd.args, {
          env: Object.assign({}, env, cmd.env),
          stdio: 'ignore',
          windowsHide: false,
        });
      } catch (_) {
        resolve(false);
        return;
      }
      const timer = setTimeout(() => { try { child.kill(); } catch (_) { /* gone */ } }, timeoutMs + 10000);
      if (timer.unref) timer.unref();
      child.on('error', () => { clearTimeout(timer); resolve(false); });
      child.on('close', (code) => { clearTimeout(timer); resolve(code === 0); });
    });
  }

  return {
    kind: 'gui',
    confirm(req) {
      const next = queue.then(() => askOnce(req || {}));
      queue = next.catch(() => false);
      return next;
    },
  };
}

/**
 * Pick the channel for a daemon: tty when it runs in the foreground with a
 * terminal, else a native dialog when the platform has one, else none.
 */
function chooseChannel(opts = {}) {
  if (opts.foreground && opts.input && opts.input.isTTY) return ttyChannel(opts);
  if (guiAvailable(opts)) return guiChannel(opts);
  return noneChannel();
}

module.exports = {
  ttyChannel,
  guiChannel,
  noneChannel,
  chooseChannel,
  guiCommand,
  guiAvailable,
  render,
  field,
  INVISIBLE,
  NO_CHANNEL,
  DEFAULT_TIMEOUT_MS,
};
