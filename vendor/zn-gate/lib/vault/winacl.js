'use strict';
/**
 * Explicit Windows permissions for the vault's files, folders and pipe.
 *
 * On Windows a new file or folder inherits the permissions of its parent. Under
 * the user profile that is "your account, SYSTEM and administrators", but a
 * ZN_HOME outside the profile (C:\zn, D:\data) usually inherits read access for
 * every local user, so another account could read the session key and talk to
 * the daemon. Nothing here trusts what was inherited:
 *
 *   ensurePrivate(target, {dir})  sets a protected, owner-only access list
 *       (no inheritance, one allow entry for the current user's SID), then
 *       reads it back as SDDL (independent of the system language) and checks
 *       it. If it cannot be set or checked, it throws ZN_POLICY_DENIED: the
 *       vault does not start on a path it cannot protect.
 *   verifyPrivate(target, {dir}) only checks.
 *
 * The check accepts allow entries for the current user, SYSTEM and the
 * Administrators group (who can take any file anyway) and any deny entry. It
 * also requires that the owner is one of them: an owner can rewrite the list.
 * For folders the list must be protected from inheritance.
 *
 * Everything runs as .NET calls in the system PowerShell, the same way as the
 * hook folder's access list (lib/agents/launcher.js): the account SID, setting
 * the list and reading it back. The PowerShell is taken from the kernel's
 * \SystemRoot link (lib/exe.js), never from PATH, SystemRoot or the current
 * directory, which an agent can influence.
 */

const cp = require('child_process');
const { CODES, znError } = require('../errors');

const SYSTEM_SID = 'S-1-5-18';
const ADMINS_SID = 'S-1-5-32-544';
// SDDL writes some accounts as two-letter aliases. Fixed ones map to one SID everywhere; LA and LG (the machine's own Administrator,
// RID 500, and Guest, RID 501) depend on the machine, so they are resolved with the current user's own domain prefix. The SDDL form
// uses LA for the user itself on a machine where the user is the built-in Administrator (GitHub's Windows runners). Any alias not
// listed stays unresolved and is therefore never trusted.
const ALIASES = {
  SY: SYSTEM_SID, BA: ADMINS_SID, BU: 'S-1-5-32-545', BG: 'S-1-5-32-546', PU: 'S-1-5-32-547', AU: 'S-1-5-11', WD: 'S-1-1-0',
  OW: 'S-1-3-4', CO: 'S-1-3-0', CG: 'S-1-3-1', IU: 'S-1-5-4', NU: 'S-1-5-2', AN: 'S-1-5-7', LS: 'S-1-5-19', NS: 'S-1-5-20',
};
const MACHINE_RIDS = { LA: 500, LG: 501 };
const SID_RE = /^S-1-\d+(?:-\d+)+$/;
const TIMEOUT_MS = 30000;

const ok = new Set(); // paths already checked by this process
let sidMemo = null; // the account SID, read once per process (real tools only)

function lower(p) { return String(p).toLowerCase(); }

function defaultRun(file, args, env) {
  const r = cp.spawnSync(file, args, {
    encoding: 'utf8',
    windowsHide: true,
    timeout: TIMEOUT_MS,
    env: Object.assign({ SystemRoot: process.env.SystemRoot || process.env.windir || 'C:\\Windows' }, /powershell\.exe$/i.test(String(file)) ? { PSModulePath: require('../exe').systemPsModulePath(file) } : {}, env || {}),
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', error: r.error || null };
}

/**
 * The commands used, with an injectable runner for tests:
 * tools = {run(file, args, env) -> {status, stdout}, powershell}.
 */
function realTools() {
  return { run: defaultRun, powershell: require('../exe').systemPowerShell() };
}

/** A short, single-line reason from a failed command (never holds vault data: only tool messages). */
function why(r) {
  const t = String((r && (r.stderr || r.stdout)) || '').replace(/\s+/g, ' ').trim().slice(0, 160);
  return t ? ': ' + t : '';
}

function fail(what, detail) {
  return znError(CODES.POLICY_DENIED, 'zn could not make ' + what + ' private to your Windows account' + (detail ? ' (' + detail + ')' : '') +
    ', so it will not keep the vault there. Next step: use the default location (leave ZN_HOME unset), or a folder on a local NTFS drive where you can change permissions.');
}

const SID_SCRIPT = "$ErrorActionPreference='Stop'; [Console]::Out.Write([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)";

/** SID of the current user, from the process token (.NET WindowsIdentity). */
function currentUserSid(tools) {
  if (sidMemo && tools.run === defaultRun) return sidMemo;
  if (!tools.powershell) throw fail('the vault', 'the system PowerShell was not found');
  const r = tools.run(tools.powershell, ['-NoProfile', '-NonInteractive', '-Command', SID_SCRIPT]);
  const m = /^(S-1-\d+(?:-\d+)+)$/.exec(String(r.stdout || '').trim());
  if (r.status !== 0 || !m) throw fail('the vault', 'could not read the account SID');
  if (tools.run === defaultRun) sidMemo = m[1];
  return m[1];
}

/** SDDL of the owner and access list of a path: {owner, flags, aces:[{type, flags, rights, sid}]}. */
function parseSddl(sddl) {
  const s = String(sddl || '').trim();
  const o = /(?:^|[^A-Z])O:(S-1-\d+(?:-\d+)+|[A-Z]{2})/.exec(s);
  const d = s.indexOf('D:');
  if (d < 0) return { owner: o ? o[1] : null, hasDacl: false, flags: '', aces: [] };
  let rest = s.slice(d + 2);
  const sacl = rest.indexOf('S:');
  if (sacl >= 0) rest = rest.slice(0, sacl);
  const first = rest.indexOf('(');
  const flags = first < 0 ? rest : rest.slice(0, first);
  const aces = [];
  const re = /\(([^()]*)\)/g;
  let m;
  while ((m = re.exec(rest))) {
    const f = m[1].split(';');
    aces.push({ type: f[0], flags: f[1] || '', rights: f[2] || '', sid: f[5] || '' });
  }
  return { owner: o ? o[1] : null, hasDacl: true, flags, aces };
}

function norm(id, userSid) {
  const t = String(id || '').trim().toUpperCase();
  if (ALIASES[t]) return ALIASES[t];
  if (MACHINE_RIDS[t]) {
    const m = /^(S-1-5-21-\d+-\d+-\d+)-\d+$/.exec(String(userSid || '').trim().toUpperCase());
    return m ? m[1] + '-' + MACHINE_RIDS[t] : t;
  }
  return t;
}

/** Problems with an SDDL, as short strings; an empty list means private. */
function problems(sddl, userSid, opts) {
  const acl = parseSddl(sddl);
  const out = [];
  const me = norm(userSid);
  const trusted = (id) => { const n = norm(id, me); return n === me || n === SYSTEM_SID || n === ADMINS_SID; };
  if (!acl.hasDacl) return ['no access list (open to everyone)'];
  if (!acl.owner || !trusted(acl.owner)) out.push('owner is ' + (acl.owner || 'unknown'));
  if (opts && opts.dir && !/P/.test(acl.flags.replace(/AI|AR|NO_ACCESS_CONTROL/g, ''))) out.push('inherits permissions from its parent');
  for (const a of acl.aces) {
    if (/^(D|XD)$/.test(a.type)) continue; // a deny entry only narrows access
    if (!/^(A|XA)$/.test(a.type)) { out.push('entry type ' + a.type); continue; }
    if (a.flags.split(/(?=[A-Z]{2})/).includes('ID') && opts && opts.dir) { out.push('inherited entry for ' + a.sid); continue; }
    if (a.sid === '' || !trusted(a.sid)) out.push('allows ' + (a.sid || 'unknown'));
  }
  return out;
}

// PowerShell text without a cmdlet (Get-Acl, New-Object... belong to modules, and Windows PowerShell 5.1 searches the user's own
// Documents\WindowsPowerShell\Modules first, where a module planted by the same account would answer in their place): only .NET.
// Sections 14 = Access, Owner, Group: the same SDDL that Get-Acl(...).Sddl gave.
const SDDL_FN = "function sd($p) { if (([int][System.IO.File]::GetAttributes($p) -band 16) -ne 0) { $a = [System.IO.DirectoryInfo]::new($p).GetAccessControl() } else { $a = [System.IO.FileInfo]::new($p).GetAccessControl() }; return $a.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]14) }; ";

function readSddl(target, tools) {
  if (!tools.powershell) throw fail(target, 'the system PowerShell was not found');
  const script = "$ErrorActionPreference='Stop'; " + SDDL_FN + '[Console]::Out.Write((sd $env:ZN_ACL_PATH))';
  const r = tools.run(tools.powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { ZN_ACL_PATH: target });
  const text = String(r.stdout || '').trim();
  if (r.status !== 0 || !/D:/.test(text)) throw fail(target, 'could not read its permissions' + why(r));
  return text;
}

// A new access list that replaces the old one: protected from inheritance, with one FullControl entry for the account (inherited by
// files and subfolders for a folder), as the hook folder gets in lib/agents/launcher.js (WIN_PRIVATE_SCRIPT). The owner is not changed.
const PRIVATE_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  '$p = $env:ZN_ACL_PATH',
  '$sid = [System.Security.Principal.SecurityIdentifier]::new($env:ZN_ACL_SID)',
  '$full = [System.Security.AccessControl.FileSystemRights]::FullControl',
  '$allow = [System.Security.AccessControl.AccessControlType]::Allow',
  "if ($env:ZN_ACL_DIR -eq '1') {",
  '  $acl = [System.Security.AccessControl.DirectorySecurity]::new()',
  '  $acl.SetAccessRuleProtection($true, $false)',
  '  $inh = [System.Security.AccessControl.InheritanceFlags]([int]1 -bor [int]2)',
  '  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, $full, $inh, [System.Security.AccessControl.PropagationFlags]::None, $allow))',
  '  [System.IO.DirectoryInfo]::new($p).SetAccessControl($acl)',
  '} else {',
  '  $acl = [System.Security.AccessControl.FileSecurity]::new()',
  '  $acl.SetAccessRuleProtection($true, $false)',
  '  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, $full, $allow))',
  '  [System.IO.FileInfo]::new($p).SetAccessControl($acl)',
  '}',
].join('\n');

function applyAcl(target, isDir, userSid, tools) {
  if (!tools.powershell) throw fail(target, 'the system PowerShell was not found');
  const r = tools.run(tools.powershell, ['-NoProfile', '-NonInteractive', '-Command', PRIVATE_SCRIPT], { ZN_ACL_PATH: target, ZN_ACL_SID: userSid, ZN_ACL_DIR: isDir ? '1' : '0' });
  if (r.status !== 0) throw fail(target, 'could not set its permissions' + why(r));
}

/**
 * Make `target` owner-only and check it; throws ZN_POLICY_DENIED if that cannot
 * be done. Does nothing on other systems. Checked once per process and path.
 */
function ensurePrivate(target, opts) {
  const o = opts || {};
  if (process.platform !== 'win32' && !o.tools) return;
  const key = lower(target);
  if (ok.has(key) && !o.tools) return;
  const tools = o.tools || realTools();
  const sid = o.userSid || currentUserSid(tools);
  if (!SID_RE.test(sid)) throw fail(target, 'unexpected account SID');
  // Already private (the usual case after the first run): nothing to change.
  let issues = problems(readSddl(target, tools), sid, o);
  if (issues.length) {
    applyAcl(target, !!o.dir, sid, tools);
    issues = problems(readSddl(target, tools), sid, o);
    if (issues.length) throw fail(target, issues.slice(0, 2).join('; '));
  }
  if (!o.tools) ok.add(key);
}

/**
 * The daemon's named pipe. Node cannot give a pipe a security descriptor when
 * it creates one, and a pipe cannot be opened by name without taking a free
 * instance, so the list is set through one client connection opened with the
 * right to change permissions (the descriptor belongs to the pipe, not to the
 * instance): one allow entry for the current user and one for SYSTEM. It is
 * read back through the same connection. Throws ZN_POLICY_DENIED if that
 * cannot be done or the result is not private.
 */
function ensurePipe(address, opts) {
  const o = opts || {};
  if (process.platform !== 'win32' && !o.tools) return;
  const tools = o.tools || realTools();
  const sid = o.userSid || currentUserSid(tools);
  if (!SID_RE.test(sid)) throw fail('the daemon pipe', 'unexpected account SID');
  if (!tools.powershell) throw fail('the daemon pipe', 'the system PowerShell was not found');
  const script = [
    "$ErrorActionPreference='Stop'",
    "$p = $env:ZN_ACL_PATH; $n = $p.Substring($p.LastIndexOf('\\') + 1)",
    '$rights = [System.IO.Pipes.PipeAccessRights]::ReadWrite -bor [System.IO.Pipes.PipeAccessRights]::ChangePermissions -bor [System.IO.Pipes.PipeAccessRights]::ReadPermissions',
    "$c = [System.IO.Pipes.NamedPipeClientStream]::new('.', $n, $rights, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Identification, [System.IO.HandleInheritability]::None)",
    'try {',
    '  $c.Connect(10000)',
    '  $s = $c.GetAccessControl()',
    "  $s.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;' + $env:ZN_ACL_SID + ')(A;;FA;;;SY)', 'Access')",
    '  $c.SetAccessControl($s)',
    "  [Console]::Out.Write($c.GetAccessControl().GetSecurityDescriptorSddlForm('Access,Owner'))",
    '} finally { $c.Dispose() }',
  ].join('\n');
  const r = tools.run(tools.powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { ZN_ACL_PATH: address, ZN_ACL_SID: sid });
  const text = String(r.stdout || '').trim();
  if (r.status !== 0 || !/D:/.test(text)) throw fail('the daemon pipe', 'could not set its permissions' + why(r));
  const issues = problems(text, sid, {});
  if (issues.length) throw fail('the daemon pipe', issues.slice(0, 2).join('; '));
}

/** Check only (no change); returns the list of problems, or throws if it cannot read. */
function verifyPrivate(target, opts) {
  const o = opts || {};
  const tools = o.tools || realTools();
  return problems(readSddl(target, tools), o.userSid || currentUserSid(tools), o);
}

/* ------------------------ scripts (.cmd, .bat) ------------------------ */

const TRUSTED_EXTRA = new Set(['S-1-3-0', 'S-1-3-4', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464']);
const RIGHT_PAIRS = {
  FA: 0x1f01ff, FR: 0x120089, FW: 0x120116, FX: 0x1200a0,
  GA: 0x10000000, GR: 0x80000000, GW: 0x40000000, GX: 0x20000000,
  WD: 0x40000, WO: 0x80000, SD: 0x10000, RC: 0x20000,
};
// Rights that let a principal replace a file: write data or append, delete,
// change the permissions or the owner. For a folder: delete a child (replacing
// a file needs it), change permissions or owner. Adding files or subfolders to
// a folder cannot replace an existing file, so C:\ (where every user may add
// folders) is not a finding.
const FILE_WRITE_MASK = 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;
const DIR_WRITE_MASK = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;

const GROUP_NAMES = { BU: 'the Users group', WD: 'Everyone', AU: 'Authenticated Users', IU: 'interactive users', NU: 'network users', LG: 'Guests', AN: 'anonymous users' };
const who = (sid) => GROUP_NAMES[String(sid).toUpperCase()] || sid || 'an unknown account';

function rightsMask(r) {
  const t = String(r || '').trim();
  if (/^0x[0-9a-f]+$/i.test(t)) return Number(t) >>> 0;
  let m = 0;
  for (let i = 0; i + 1 < t.length; i += 2) m |= RIGHT_PAIRS[t.slice(i, i + 2).toUpperCase()] || 0;
  return m >>> 0;
}

/**
 * entries: [{path, dir, sddl}] for the script and each folder above it.
 * Returns {deny, warn}: deny = first path that another principal can rewrite
 * or that another principal owns; warn = first path where the current user can
 * (and nobody else outside SYSTEM, administrators and the installer service).
 */
function scriptEntriesRisk(entries, userSid) {
  const me = norm(userSid);
  const fix = (id) => norm(id, me); // norm already maps the CO and OW aliases to their SIDs
  const trusted = (id) => { const n = fix(id); return n === me || n === SYSTEM_SID || n === ADMINS_SID || TRUSTED_EXTRA.has(n); };
  let warn = null;
  for (const e of entries) {
    const acl = parseSddl(e.sddl);
    if (!acl.hasDacl) return { deny: e.path + ' (no access list: open to everyone)', warn };
    if (!acl.owner || !trusted(acl.owner)) return { deny: e.path + ' (owned by ' + (acl.owner || 'an unknown account') + ')', warn };
    const mask = e.dir ? DIR_WRITE_MASK : FILE_WRITE_MASK;
    for (const a of acl.aces) {
      if (!/^(A|XA)$/.test(a.type)) continue;
      if ((a.flags.match(/../g) || []).includes('IO')) continue; // applies to children only
      if ((rightsMask(a.rights) & mask) === 0) continue;
      if (!a.sid || !trusted(a.sid)) return { deny: e.path + ' (' + who(a.sid) + ' can write it)', warn };
      if (!warn && fix(a.sid) === me) warn = e.path;
    }
  }
  return { deny: null, warn };
}

/**
 * Can another account rewrite this script? Reads the permissions of the file
 * and every folder above it in one PowerShell call. {deny, warn} as above; if
 * the permissions cannot be read, the script is denied (fail closed).
 */
function scriptWriteRisk(target, opts) {
  const o = opts || {};
  const tools = o.tools || realTools();
  let sid;
  try { sid = o.userSid || currentUserSid(tools); } catch (e) { return { deny: target + ' (the account could not be identified)', warn: null }; }
  if (!tools.powershell) return { deny: target + ' (the system PowerShell was not found)', warn: null };
  const script = [
    "$ErrorActionPreference='Stop'",
    SDDL_FN,
    '$p = $env:ZN_ACL_PATH; $k = "F"',
    'while ($p) {',
    "  [Console]::Out.WriteLine($k + '|' + $p + '|' + (sd $p))",
    '  $n = [System.IO.Path]::GetDirectoryName($p)',
    '  if (-not $n -or $n -eq $p) { break }',
    '  $p = $n; $k = "D"',
    '}',
  ].join('\n');
  const r = tools.run(tools.powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { ZN_ACL_PATH: target });
  const entries = [];
  for (const line of String(r.stdout || '').split(/\r?\n/)) {
    const m = /^([FD])\|([^|]+)\|(.*D:.*)$/.exec(line);
    if (m) entries.push({ dir: m[1] === 'D', path: m[2], sddl: m[3] });
  }
  if (r.status !== 0 || entries.length === 0 || entries[0].dir) return { deny: target + ' (its permissions could not be read' + why(r) + ')', warn: null };
  return scriptEntriesRisk(entries, sid);
}

module.exports = { scriptWriteRisk, scriptEntriesRisk, rightsMask, ensurePrivate, ensurePipe, verifyPrivate, parseSddl, problems, currentUserSid, realTools, _forget: () => { ok.clear(); sidMemo = null; } };
