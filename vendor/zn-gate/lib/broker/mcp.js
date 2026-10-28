'use strict';

/**
 * MCP server "secrets" (stdio, JSON-RPC 2.0, same protocol handling as
 * lib/mcp.js, no dependencies):  zn secrets-mcp
 *
 * Tools:
 *   secrets_list           names and policy of the stored secrets, never values
 *   secrets_http_request   zn makes the HTTP request with __ZN_<NAME>__ markers
 *                          replaced, only for secrets in mode "proxy", only if
 *                          the host is in each secret's
 *                          allowHosts, and only in request headers unless the
 *                          secret also allows the URL ("query") or the body
 *                          (allowIn); the response is scrubbed before it returns
 *   secrets_render_file    render a template with markers into a git-ignored
 *                          file (or one outside any repository); secrets in
 *                          mode "file" only. A new file inside the project is
 *                          written directly; overwriting a file or writing
 *                          outside the project needs the user's confirmation
 *                          on the vault's own channel
 *   secrets_request        ask the user to add a secret; never takes a value
 *
 * There is deliberately no tool that returns a secret value.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const markers = require('./markers');
const { createMasker } = require('./mask');
const { gitStatusOf, realTargetOf } = require('./files');
const policy = require('../hooks/policy');
const deps = require('../deps');
const CLOUD_KEY_SECRET = require('../cloud-key').VAULT_SECRET;
const { pickOpening, warnNotice, WARN_REASON } = require('../team/effective');

// Not available on Windows: 0 there, and the path checks still run.
const O_NOFOLLOW = fs.constants.O_NOFOLLOW || 0;

const SERVER_NAME = 'zn-secrets';
let SERVER_VERSION = '0.0.0';
try { SERVER_VERSION = require('../../package.json').version; } catch (_) { /* keep default */ }
const proto = require('../mcp-protocol');

const PROTOCOL_VERSION = proto.LATEST_PROTOCOL_VERSION;

const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30000;
const FORBIDDEN_HEADERS = /^(host|proxy-.*|connection|content-length|transfer-encoding|upgrade|te|trailer|keep-alive)$/i;

const NO_GET = 'There is no tool that returns a secret value, by design: use the __ZN_<NAME>__ marker and zn fills it in where it is allowed.';

const TOOLS = [
  {
    name: 'secrets_list',
    annotations: { title: 'List stored secrets (names only)', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'List the secrets stored in the local zn vault: name, marker, mode, allowed hosts and allowed commands. Never returns values. ' + NO_GET,
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'secrets_http_request',
    annotations: { title: 'Send an HTTP request that uses a stored secret', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    description: 'Make an HTTP request that needs a secret. Write the secret as its marker in a header (for example "Authorization": "Bearer __ZN_GITHUB_TOKEN__"); zn sends the request with the real value, only if the host is in that secret\'s allowHosts, and returns the response with any secret replaced by markers. Markers in the URL or the body are refused unless the user allowed that placement for the secret. Use this instead of curl or WebFetch for authenticated APIs. ' + NO_GET,
    inputSchema: {
      type: 'object',
      properties: {
        method: { type: 'string', description: 'HTTP method, e.g. GET, POST, PATCH, DELETE.' },
        url: { type: 'string', description: 'Absolute https:// URL (http:// only for localhost).' },
        headers: { type: 'object', additionalProperties: { type: 'string' }, description: 'Request headers; values may contain __ZN_<NAME>__ markers.' },
        body: { type: 'string', description: 'Request body as text (JSON must be serialized); may contain markers.' },
      },
      required: ['method', 'url'],
    },
  },
  {
    name: 'secrets_render_file',
    annotations: { title: 'Write a config file from a template', readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    description: 'Render a template file that contains __ZN_<NAME>__ markers into an output file with the real values, for tools that need a config file (e.g. ~/.npmrc). Only for secrets in "file" mode, and the output must be git-ignored or outside any git repository. A new file inside the project is written directly; overwriting an existing file or writing outside the project waits for the user to confirm it in the zn vault prompt. Returns only the output path, never the content. ' + NO_GET,
    inputSchema: {
      type: 'object',
      properties: {
        template: { type: 'string', description: 'Path of the template file (with markers).' },
        out: { type: 'string', description: 'Path of the file to write (git-ignored or outside the repository).' },
      },
      required: ['template', 'out'],
    },
  },
  {
    name: 'secrets_request',
    annotations: { title: 'Ask the user to add a secret', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    description: 'Ask the user to add a secret you need (for example GITHUB_TOKEN). The user adds the value in their own terminal; you never receive it. Do not pass a value: if you already have it, it is exposed and the user should rotate it. ' + NO_GET,
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Secret name: upper case, digits and underscores, e.g. STRIPE_API_KEY.' },
        reason: { type: 'string', description: 'Why it is needed (shown to the user).' },
      },
      required: ['name', 'reason'],
    },
  },
];

function textResult(obj, isError = false) {
  return { isError, content: [{ type: 'text', text: typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2) }] };
}

function denied(message) {
  return textResult({ error: 'ZN_POLICY_DENIED', message }, true);
}

/**
 * Build a server bound to its dependencies.
 * opts: {vault, engine, fetch, cwd, home, agent, notify}
 */
function createSecretsServer(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const home = opts.home || os.homedir();
  const project = deps.findProjectRoot(cwd);
  const agent = opts.agent || process.env.ZN_AGENT || 'mcp';
  // Only an id from the MCP configuration zn wrote (`secrets-mcp --agent`)
  // decides which new hosts the organization policy may offer for approval;
  // ZN_AGENT is self-reported. No id ever lifts a restriction.
  const agentTrusted = Boolean(opts.agent);
  const doFetch = opts.fetch || globalThis.fetch;
  let vault = opts.vault;
  let engine = opts.engine;
  const getVault = async () => (vault = vault || await deps.loadVault());
  const getEngine = () => (engine = engine || deps.loadEngine());
  const notify = opts.notify || ((line) => process.stderr.write(line + '\n'));

  async function audit(ev) {
    try { await (await getVault()).audit({ agent, ...ev }); } catch (_) { /* never let audit change a decision */ }
  }

  /* Settings to enforce: the local ones with the organization policy
   * applied for this agent (zn Team). */
  async function metaMap() {
    const list = await (await getVault()).listSecrets({ effective: true, agent, agentTrusted });
    return new Map((list || []).map((s) => [s.name, s]));
  }

  async function scrub(text, masker) {
    const masked = masker.maskText(text);
    const res = await getEngine().tokenize(masked, { project, agent, tool: 'mcp:secrets_http_request', destination: 'assistant', vault: await getVault() });
    return res && typeof res.text === 'string' ? res.text : masked;
  }

  async function list() {
    const meta = await metaMap();
    return textResult({
      secrets: [...meta.values()].map((s) => ({
        name: s.name,
        marker: markers.markerFor(s.name),
        mode: s.mode || 'proxy',
        allowHosts: s.allowHosts || [],
        allowCommands: s.allowCommands || [],
        lastUsed: s.lastUsed || null,
      })),
      note: NO_GET,
    });
  }

  async function httpRequest(args) {
    const method = String(args.method || 'GET').toUpperCase();
    if (!/^[A-Z]{3,10}$/.test(method)) return denied('invalid HTTP method');
    let url;
    try { url = new URL(String(args.url || '')); } catch (_) { return denied('url must be an absolute URL'); }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && markers.isLoopbackHost(url.hostname))) {
      return denied('only https:// URLs are allowed (http:// only for localhost)');
    }
    if (url.username || url.password) return denied('put credentials in headers, not in the URL userinfo');
    const host = url.hostname.toLowerCase();
    const headers = {};
    for (const [k, v] of Object.entries(args.headers && typeof args.headers === 'object' ? args.headers : {})) {
      if (FORBIDDEN_HEADERS.test(k)) return denied('header ' + k + ' cannot be set');
      headers[k] = String(v);
    }
    const body = args.body === undefined || args.body === null ? undefined : (typeof args.body === 'string' ? args.body : JSON.stringify(args.body));

    const carriers = [String(args.url), ...Object.keys(headers), ...Object.values(headers), body || ''];
    const found = new Map();
    for (const c of carriers) for (const m of markers.findMarkers(c)) found.set(m.name, m);
    // Where each marker sits: a value in a header goes only to the API it
    // authenticates; in the URL or the body an injected prompt could make zn
    // publish it (a gist, an issue, a query string in logs) on an allowed host.
    const placements = (name) => {
      const where = new Set();
      const has = (t) => markers.findMarkers(t).some((m) => m.name === name);
      if (has(String(args.url))) where.add('query');
      if (Object.keys(headers).some(has) || Object.values(headers).some(has)) where.add('header');
      if (body && has(body)) where.add('body');
      return [...where];
    };
    const detected = [...found.values()].filter((m) => m.detected);
    if (detected.length) {
      return denied(detected.map((m) => m.marker).join(', ') + ' is a value the scrubber found in a file, not a stored secret. ' +
        'Ask the user to store it with `zn secret adopt ' + detected[0].name + ' --name <NAME> --host ' + host + '`.');
    }
    const named = [...found.values()];
    let meta = named.length ? await metaMap() : new Map();
    // A host the organization policy opens but this machine never allowed:
    // the user approves it once, on the vault's own channel. The settings
    // are then read again, so a change made while the dialog was open counts.
    let asked = false;
    for (const m of named) {
      const s = meta.get(m.name);
      if (!s || s.deny || (s.mode || 'proxy') !== 'proxy' || markers.hostAllowed(s.allowHosts, host)) continue;
      const open = pickOpening(s.orgPending, 'host', (v) => markers.hostAllowed([v], host));
      const v = await getVault();
      if (open && typeof v.confirmOrgOpening === 'function') {
        asked = true;
        try { await v.confirmOrgOpening(m.name, 'host', open.value, agent, agentTrusted); } catch (_) { /* declined or no channel: denied below */ }
      }
    }
    if (asked) meta = await metaMap();
    const values = new Map();
    for (const m of named) {
      const s = meta.get(m.name);
      if (!s) {
        await audit({ secret: m.name, mode: null, tool: 'mcp:secrets_http_request', argv0: null, host, decision: 'deny', reason: 'not found' });
        return textResult({ error: 'ZN_NOT_FOUND', message: 'secret ' + m.name + ' is not in the vault; use secrets_request to ask the user for it' }, true);
      }
      if (s.deny) {
        await audit({ secret: m.name, mode: s.mode, tool: 'mcp:secrets_http_request', argv0: null, host, decision: 'deny', reason: 'policy:org_deny' });
        return denied(m.marker + ' is blocked for this agent by your organization policy. No request was made.');
      }
      // The key `zn-gate connect` keeps in the vault is for zn-gate's own analysis calls only. An agent could use it
      // here to revoke the key (DELETE) or spend its quota, so this tool never fills it in, whatever its allowHosts.
      if (m.name === CLOUD_KEY_SECRET) {
        await audit({ secret: m.name, mode: s.mode, tool: 'mcp:secrets_http_request', argv0: null, host, decision: 'deny', reason: 'zn cloud key' });
        return denied(m.marker + ' is the key of `zn-gate connect`. Only zn-gate uses it, and revoking it is done in your own terminal (zn-gate disconnect). No request was made.');
      }
      // Only secrets the user made available to HTTP requests (mode proxy) leave through this tool, whatever their allowHosts say:
      // an env or file secret is meant for a local program, not for the network.
      if ((s.mode || 'proxy') !== 'proxy') {
        await audit({ secret: m.name, mode: s.mode, tool: 'mcp:secrets_http_request', argv0: null, host, decision: 'deny', reason: 'mode_not_proxy:' + s.mode });
        return denied(m.marker + ' is in ' + s.mode + ' mode, and secrets_http_request only sends secrets in proxy mode. No request was made. ' +
          'If the API really needs it, the user can change it in their own terminal: zn secret allow ' + m.name + ' --mode proxy');
      }
      if (!markers.hostAllowed(s.allowHosts, host)) {
        await audit({ secret: m.name, mode: s.mode, tool: 'mcp:secrets_http_request', argv0: null, host, decision: 'deny', reason: 'host not in allowHosts' });
        return denied(m.marker + ' may not be sent to ' + host + ' (allowed: ' + ((s.allowHosts || []).join(', ') || 'none') + '). No request was made.');
      }
      // An empty list (cut down by the organization policy) allows nowhere.
      const allowIn = Array.isArray(s.allowIn) ? s.allowIn : ['header'];
      const outside = placements(m.name).filter((p) => !allowIn.includes(p));
      if (outside.length) {
        await audit({ secret: m.name, mode: s.mode, tool: 'mcp:secrets_http_request', argv0: null, host, decision: 'deny', reason: 'placement not allowed: ' + outside.join(',') });
        const where = outside.map((p) => (p === 'query' ? 'the URL' : 'the body')).join(' and ');
        return denied(m.marker + ' may only be sent in request headers (' + where + ' is not allowed for this secret). No request was made. ' +
          'If the API really needs it there, the user can allow it in their own terminal: zn secret allow ' + m.name + ' --in ' + outside.join(' --in '));
      }
    }
    getEngine(); // fail before sending if the response cannot be scrubbed
    // `warn` rules of the organization policy: the request goes ahead, the
    // use is recorded as "warn" and the user and the agent are told.
    const warned = (m) => meta.get(m.name).warn === true;
    const notices = named.filter(warned).map((m) => warnNotice(m.name, meta.get(m.name).warnReason));
    const notice = notices.length ? notices.join(' ') : undefined;
    const used = (m, why) => (warned(m) ? { decision: 'warn', reason: WARN_REASON } : { decision: 'allow', reason: why });
    for (const m of named) {
      // The vault checks the mode, the host and the placements again when it hands the value over (purpose http).
      let v;
      try {
        v = await (await getVault()).resolve(project, m.marker, { purpose: 'http', agent, agentTrusted, tool: 'mcp:secrets_http_request', host, placements: placements(m.name) });
      } catch (err) {
        if (err && err.code === 'ZN_POLICY_DENIED') return denied(m.marker + ' was refused by the vault: ' + (err.message || 'not allowed here') + ' No request was made.');
        throw err;
      }
      if (v == null) return textResult({ error: 'ZN_NOT_FOUND', message: 'secret ' + m.name + ' has no value' }, true);
      values.set(m.name, String(v));
    }
    const masker = createMasker([...values.entries()].map(([name, value]) => ({ name, value })));
    const realHeaders = {};
    for (const [k, v] of Object.entries(headers)) realHeaders[markers.substitute(k, values)] = markers.substitute(v, values);
    const realUrl = markers.substitute(String(args.url), values);
    const realBody = body === undefined ? undefined : markers.substitute(body, values);

    let res;
    try {
      res = await doFetch(realUrl, {
        method,
        headers: realHeaders,
        body: method === 'GET' || method === 'HEAD' ? undefined : realBody,
        redirect: 'manual',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      for (const m of named) await audit({ secret: m.name, mode: meta.get(m.name).mode, tool: 'mcp:secrets_http_request', argv0: null, host, ...used(m, 'request failed') });
      for (const n of notices) notify(n);
      return textResult({ error: 'ZN_HTTP_ERROR', message: await scrub(String(err && err.message || err), masker), notice }, true);
    }
    for (const m of named) await audit({ secret: m.name, mode: meta.get(m.name).mode, tool: 'mcp:secrets_http_request', argv0: null, host, ...used(m, method + ' ' + res.status) });
    for (const n of notices) notify(n);

    const buf = Buffer.from(await res.arrayBuffer());
    const truncated = buf.length > MAX_RESPONSE_BYTES;
    const text = buf.subarray(0, MAX_RESPONSE_BYTES).toString('utf8');
    const outHeaders = {};
    for (const [k, v] of res.headers.entries()) outHeaders[await scrub(k, masker)] = await scrub(v, masker);
    return textResult({
      status: res.status,
      statusText: await scrub(String(res.statusText || ''), masker),
      redirected_to: res.status >= 300 && res.status < 400 ? (outHeaders.location || null) : undefined,
      headers: outHeaders,
      body: await scrub(text, masker),
      truncated,
      note: redirectNote(res.status),
      notice,
    });
  }

  function redirectNote(status) {
    return status >= 300 && status < 400 ? 'Redirects are not followed automatically; call again with the new URL if it is an allowed host.' : undefined;
  }

  function realOrSelf(p) {
    try { return fs.realpathSync(p); } catch (_) { return path.resolve(p); }
  }

  function insideProject(file) {
    let dir = path.dirname(path.resolve(file));
    while (!fs.existsSync(dir) && path.dirname(dir) !== dir) dir = path.dirname(dir);
    return markers.isInside(realOrSelf(dir), realOrSelf(project));
  }

  /**
   * Opens the file a secret value is about to be written to. The checks run on
   * the open descriptor, not on the name the path was typed as: the real
   * parent directory must be inside the real project root, fstat(fd) must be
   * the file at that real path, and the git check is repeated on it.
   * Without the user's approval (approvedAt null) the real directory must be
   * inside the project; with it, the file must be the very location they saw.
   * A new file is created with 'wx' and mode 0600 and removed on any mismatch.
   * An existing file (already confirmed) is only opened, never created or
   * truncated before the checks pass, and is left alone on a mismatch.
   * Returns { fd, real, where } or { refused }.
   */
  function openRenderTarget(out, exists, approvedAt) {
    try {
      fs.mkdirSync(path.dirname(out), { recursive: true });
    } catch (err) {
      return { refused: 'cannot create the directory for ' + out + ' (' + err.code + '); nothing was written' };
    }
    let fd;
    try {
      const flags = exists ? fs.constants.O_RDWR | O_NOFOLLOW
        : fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL;
      fd = fs.openSync(out, flags, 0o600);
    } catch (err) {
      return { refused: 'could not open ' + out + ' (' + err.code + '); nothing was written' };
    }
    let real = out;
    let fst = null;
    let why = null;
    let where = null;
    try {
      real = path.join(fs.realpathSync(path.dirname(out)), path.basename(out));
      fst = fs.fstatSync(fd);
      const lst = fs.lstatSync(real);
      const dest = policy.classifyPath(real, { home, cwd });
      if (!lst.isFile() || lst.isSymbolicLink() || fst.dev !== lst.dev || fst.ino !== lst.ino) {
        why = 'the file changed while it was being opened';
      } else if (exists && fst.nlink > 1) {
        why = 'it has other hard links, so it could be another file';
      } else if (dest && (dest.kind === 'agent_config' || dest.kind === 'zn_state')) {
        why = 'the location is agent or zn configuration';
      } else if (approvedAt === null && !markers.isInside(path.dirname(real), realOrSelf(project))) {
        why = 'its directory resolves outside the project';
      } else if (approvedAt !== null && real !== approvedAt) {
        why = 'it is not the location the user approved';
      } else {
        where = gitStatusOf(real);
        if (where !== 'ignored' && where !== 'outside') why = 'it is tracked by git (it could be committed)';
      }
    } catch (err) {
      why = 'it cannot be checked (' + err.code + ')';
    }
    if (why) {
      fs.closeSync(fd);
      // Only the file this call created is removed, and only while it is still
      // that file: a name swapped meanwhile is someone else's file.
      const ours = fst && (() => { try { const l = fs.lstatSync(real); return l.dev === fst.dev && l.ino === fst.ino; } catch (_) { return false; } })();
      if (!exists && ours) { try { fs.unlinkSync(real); } catch (_) { /* already gone */ } }
      return { refused: out + ': ' + why + '; nothing was written.' };
    }
    return { fd, real, where };
  }

  async function renderFile(args) {
    const tpl = path.resolve(cwd, String(args.template || ''));
    const out = path.resolve(cwd, String(args.out || ''));
    if (!args.template || !args.out) return denied('template and out are required');
    const readDeny = policy.readDenial(tpl, { cwd, home });
    if (readDeny) return denied(readDeny);
    const dest = policy.classifyPath(out, { cwd, home });
    if (dest && dest.kind === 'zn_state') return denied('cannot write into ~/.zn');
    // The agents' hook and plugin settings are never written from here: a
    // secret there could switch off the checks that protect it.
    if (dest && dest.kind === 'agent_config') return denied('cannot write agent hook or plugin configuration (' + dest.reason + ')');
    let exists = false;
    try {
      const st = fs.lstatSync(out);
      if (st.isSymbolicLink() || !st.isFile()) return denied('out exists and is not a regular file');
      exists = true;
    } catch (err) {
      if (err.code !== 'ENOENT') return denied('cannot inspect out: ' + err.code);
    }
    // Without asking, only a new file inside the project: the real path of
    // its nearest existing directory (symlinks resolved) must be inside the
    // project's real path. Anything else is confirmed by the user on the
    // vault's own channel, like the first use of a command.
    // A credential file is written only after the user confirms it, wherever it is.
    const needsConfirm = exists ? 'the file already exists and would be overwritten'
      : !insideProject(out) ? 'the file is outside the project'
        : dest && dest.kind === 'credential' ? 'the file is a credential file'
          : null;
    const where = gitStatusOf(out);
    if (where !== 'ignored' && where !== 'outside') {
      return denied(out + ' is ' + (where === 'unknown' ? 'in an unknown git state (git not available)' : 'tracked by git (it could be committed)') +
        '. Secret values are only written to git-ignored files or outside the repository.');
    }
    let template;
    try { template = fs.readFileSync(tpl, 'utf8'); } catch (err) { return denied('cannot read template: ' + err.code); }
    const found = markers.findMarkers(template);
    const named = found.filter((m) => !m.detected);
    if (named.length === 0) return denied('the template has no __ZN_<NAME>__ markers');
    const meta = await metaMap();
    const values = new Map();
    for (const m of named) {
      const s = meta.get(m.name);
      if (!s) return textResult({ error: 'ZN_NOT_FOUND', message: 'secret ' + m.name + ' is not in the vault' }, true);
      if (s.deny) {
        await audit({ secret: m.name, mode: s.mode, tool: 'mcp:secrets_render_file', argv0: null, host: null, decision: 'deny', reason: 'policy:org_deny' });
        return denied(m.marker + ' is blocked for this agent by your organization policy. Nothing was written.');
      }
      if (s.mode !== 'file') {
        await audit({ secret: m.name, mode: s.mode, tool: 'mcp:secrets_render_file', argv0: null, host: null, decision: 'deny', reason: 'mode is not file' });
        return denied(m.name + ' is in ' + (s.mode || 'proxy') + ' mode; only "file" mode secrets can be written to disk');
      }
    }
    // The user is shown the real path, and the checks below run again on it
    // after their answer: a location that moved meanwhile is refused.
    let approvedAt = null;
    if (needsConfirm) {
      const v = await getVault();
      if (typeof v.confirmFileWrite !== 'function') return denied(out + ': ' + needsConfirm + '; this vault cannot ask the user to confirm it. Render to a new file inside the project.');
      approvedAt = realTargetOf(out);
      try {
        await v.confirmFileWrite(project, approvedAt, named.map((m) => m.name), needsConfirm);
      } catch (err) {
        await audit({ secret: named[0].name, mode: 'file', tool: 'mcp:secrets_render_file', argv0: null, host: null, decision: 'deny', reason: 'file_write_not_confirmed' });
        return denied(out + ': ' + needsConfirm + ', and the user did not confirm it (' + String((err && err.message) || 'declined').slice(0, 200) + ').');
      }
    }
    for (const m of named) {
      const v = await (await getVault()).resolve(project, m.marker, { purpose: 'render', agent, agentTrusted, tool: 'mcp:secrets_render_file' });
      if (v == null) return textResult({ error: 'ZN_NOT_FOUND', message: 'secret ' + m.name + ' has no value' }, true);
      values.set(m.name, String(v));
    }
    if (approvedAt !== null && realTargetOf(out) !== approvedAt) {
      await audit({ secret: named[0].name, mode: 'file', tool: 'mcp:secrets_render_file', argv0: null, host: null, decision: 'deny', reason: 'file_write_moved' });
      return denied(out + ' resolved to a different location while it was waiting for the user; nothing was written.');
    }
    const opened = openRenderTarget(out, exists, approvedAt);
    if (opened.refused) {
      await audit({ secret: named[0].name, mode: 'file', tool: 'mcp:secrets_render_file', argv0: null, host: null, decision: 'deny', reason: 'path_changed' });
      return denied(opened.refused);
    }
    const text = markers.substitute(template, values);
    try {
      if (exists) {
        fs.fchmodSync(opened.fd, 0o600);
        fs.ftruncateSync(opened.fd, 0);
      }
      fs.writeFileSync(opened.fd, text);
    } catch (err) {
      if (!exists) { try { fs.unlinkSync(opened.real); } catch (_) { /* already gone */ } }
      return denied('could not write ' + out + ' (' + err.code + '); nothing was written');
    } finally {
      fs.closeSync(opened.fd);
    }
    const renderNotices = [];
    for (const m of named) {
      const s = meta.get(m.name);
      if (s.warn === true) {
        await audit({ secret: m.name, mode: 'file', tool: 'mcp:secrets_render_file', argv0: null, host: null, decision: 'warn', reason: WARN_REASON });
        renderNotices.push(warnNotice(m.name, s.warnReason));
      } else {
        await audit({ secret: m.name, mode: 'file', tool: 'mcp:secrets_render_file', argv0: null, host: null, decision: 'allow', reason: 'rendered to a ' + opened.where + ' path' });
      }
    }
    for (const n of renderNotices) notify(n);
    return textResult({
      written: out,
      secrets: named.map((m) => m.name),
      unresolved: found.filter((m) => m.detected).map((m) => m.marker),
      note: 'The file holds real values; reading it back returns markers.',
      notice: renderNotices.length ? renderNotices.join(' ') : undefined,
    });
  }

  async function request(args) {
    if (args.value !== undefined || args.secret !== undefined) {
      return denied('secrets_request never takes a value. If you already have it, it is exposed: tell the user to rotate it and store the new one with zn secret set.');
    }
    const name = String(args.name || '');
    const bad = markers.validateSecretName(name);
    if (bad) return denied('invalid name: ' + bad);
    const reason = String(args.reason || '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 300);
    const rec = { ts: new Date().toISOString(), name, reason, agent };
    try {
      const dir = path.join(home, '.zn');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.appendFileSync(path.join(dir, 'requests.jsonl'), JSON.stringify(rec) + '\n', { mode: 0o600 });
    } catch (_) { /* best effort */ }
    await audit({ secret: name, mode: null, tool: 'mcp:secrets_request', argv0: null, host: null, decision: 'ask', reason: reason.slice(0, 120) });
    notify('zn: ' + agent + ' asks for secret ' + name + (reason ? ' (' + reason + ')' : '') + '. Add it with: zn secret set ' + name);
    return textResult({
      requested: name,
      message: 'Asked the user. They add it in their own terminal with `zn secret set ' + name + '` (with --host or --command to allow its use). ' +
        'Tell the user this, then use the marker ' + markers.markerFor(name) + ' once it is stored.',
    });
  }

  async function callTool(name, args) {
    try {
      if (name === 'secrets_list') return await list();
      if (name === 'secrets_http_request') return await httpRequest(args || {});
      if (name === 'secrets_render_file') return await renderFile(args || {});
      if (name === 'secrets_request') return await request(args || {});
      return null;
    } catch (err) {
      const code = err && err.code && String(err.code).startsWith('ZN_') ? err.code : 'ZN_ERROR';
      return textResult({ error: code, message: String(err && err.message || err) }, true);
    }
  }

  // Version agreed in initialize (one client per stdio process); until then the latest.
  let negotiated = null;

  /** Handles a JSON-RPC batch: an array of replies, or one error when batches are not allowed (only 2025-03-26 has them). */
  async function handleBatch(messages) {
    if (!proto.allowsBatching(negotiated) || messages.length === 0) {
      return { jsonrpc: '2.0', id: null, error: { ...proto.BATCH_REJECTED } };
    }
    const replies = [];
    for (const m of messages) {
      const r = await handleMessage(m);
      if (r) replies.push(r);
    }
    return replies.length ? replies : null;
  }

  /** Returns the JSON-RPC response object, or null for notifications. */
  async function handleMessage(msg) {
    const { id, method, params } = msg || {};
    const ok = (result) => ({ jsonrpc: '2.0', id, result });
    const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
    switch (method) {
      case 'initialize':
        negotiated = proto.negotiateProtocolVersion(params);
        return ok({ protocolVersion: negotiated, capabilities: { tools: {} }, serverInfo: { name: SERVER_NAME, version: SERVER_VERSION } });
      case 'notifications/initialized':
        return null;
      case 'ping':
        return ok({});
      case 'tools/list':
        return ok({ tools: proto.toolsForVersion(TOOLS, negotiated) });
      case 'tools/call': {
        if (!params || typeof params.name !== 'string') return fail(-32602, 'Invalid params: name is required');
        const result = await callTool(params.name, params.arguments || {});
        if (!result) return fail(proto.unknownToolCode(negotiated), "Tool '" + params.name + "' not found. " + NO_GET);
        return ok(result);
      }
      default:
        return id === undefined ? null : fail(-32601, 'Unsupported method: ' + method);
    }
  }

  return { handleMessage, handleBatch, callTool, TOOLS };
}

function startSecretsMcp(opts = {}) {
  const server = createSecretsServer(opts);
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (err) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
      return;
    }
    const res = Array.isArray(msg) ? await server.handleBatch(msg) : await server.handleMessage(msg);
    if (res) process.stdout.write(JSON.stringify(res) + '\n');
  });
  rl.on('close', () => process.exit(0));
}

module.exports = { createSecretsServer, startSecretsMcp, TOOLS, SERVER_NAME, PROTOCOL_VERSION };
