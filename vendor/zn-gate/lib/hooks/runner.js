'use strict';

/**
 * Single entry point for agent hooks:  zn hook <agent-id>  (event JSON on stdin)
 *
 *   raw agent event -> adapter.normalize() -> decide() -> adapter.respond() -> stdout
 *
 * The runner keeps no state of its own: token mappings and secrets live in
 * the vault daemon, reached through lib/vault/client.js. Decisions:
 *
 *   pre_tool    deny reads of credential files and ~/.zn, deny secret
 *               management commands, deny MCP call arguments that carry
 *               markers or secret values (other servers than zn's own),
 *               wrap shell commands (Bash, PowerShell)
 *               that carry __ZN_<NAME>__ markers in `zn run --` (ask),
 *               restore detected tokens per the restore policy (ask), refuse
 *               markers in WebFetch URLs (use secrets_http_request instead),
 *               and pipe Monitor commands through the streaming scrubber.
 *   post_tool   replace secrets in the tool output with tokens (Read, Bash,
 *               PowerShell, Monitor, Grep, LSP, WebFetch, MCP tools and MCP
 *               resources), keeping the output's shape.
 *   user_prompt block prompts that contain a secret and suggest
 *               `zn secret set`.
 *
 * Vault locked (or its daemon unreachable): the engine still runs without
 * it and replaces values with irreversible __ZN_REDACTED_<TYPE>__ markers;
 * the user is told to run `zn unlock`. Secrets never pass through.
 *
 * Failure handling: every error fails closed: the tool call is denied, the
 * output withheld or the prompt blocked. That includes a missing engine (an
 * agent could rename the file); the user is told how to reinstall, and can
 * choose to let events pass while it is missing with
 * {"hooks": {"whenUnavailable": "allow"}} in ~/.zn/config.json.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const policy = require('./policy');
const markers = require('../broker/markers');
const { gitStatusOf } = require('../broker/files');
const deps = require('../deps');
const { shQuote, SH_QUOTE_ESCAPE, portablePath } = require('../shell-quote');
const { znCommand } = require('../zn-command');

const SECRET_SOURCES = new Set(['exact', 'pattern']);
const POST_TOOLS = new Set(['read', 'bash', 'powershell', 'monitor', 'grep', 'lsp', 'webfetch', 'mcp', 'mcpresource']);
const SHELL_TOOLS = new Set(['bash', 'powershell']);
const STREAM_JS = path.resolve(__dirname, '..', 'scrub', 'stream.js');

function readConfig(home) {
  try {
    return JSON.parse(fs.readFileSync(path.join(home || os.homedir(), '.zn', 'config.json'), 'utf8')) || {};
  } catch (_) {
    return {};
  }
}

/*
 * What to do when the scrubber engine is missing from the installation:
 * "closed" (default) denies, withholds or blocks like any other error;
 * "open" lets events pass with a warning. Open is set only in
 * ~/.zn/config.json as {"hooks": {"whenUnavailable": "allow"}} (agents cannot
 * write there). ZN_HOOK_FAIL_MODE=closed in the environment makes it stricter;
 * ZN_HOOK_FAIL_MODE=open is ignored, because the agent's environment can be
 * set by the project it works in.
 */
function failModeOf(opts) {
  if (opts.failMode) return String(opts.failMode).toLowerCase() === 'open' ? 'open' : 'closed';
  if (String(process.env.ZN_HOOK_FAIL_MODE || '').toLowerCase() === 'closed') return 'closed';
  const hooks = readConfig(opts.home).hooks || {};
  const when = String(hooks.whenUnavailable || '').toLowerCase();
  if (when === 'allow') return 'open';
  if (when === 'deny') return 'closed';
  return String(hooks.failMode || '').toLowerCase() === 'open' ? 'open' : 'closed';
}

// Reinstall the running version: `npm install -g zn-gate` alone could install an
// older release without hooks.
const { version: ZN_VERSION } = require('../../package.json');
const REINSTALL = 'The zn scrubber engine is missing from this installation (lib/scrub/engine.js), so zn cannot check this. ' +
  'Reinstall zn-gate (`npm install -g zn-gate@' + ZN_VERSION + '`) and run `zn hooks install` again. To let events pass unchecked while it is missing, ' +
  'set {"hooks": {"whenUnavailable": "allow"}} in ~/.zn/config.json.';

/** Map every string leaf of a JSON value through an async function, keeping the shape. */
async function mapStrings(value, fn) {
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value)) {
    const out = [];
    for (const v of value) out.push(await mapStrings(v, fn));
    return out;
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = await mapStrings(v, fn);
    return out;
  }
  return value;
}

function lazyDeps(opts) {
  let engine = opts.engine;
  let vault = opts.vault === null ? null : opts.vault;
  return {
    engine() {
      if (!engine) engine = deps.loadEngine();
      return engine;
    },
    // A vault that cannot be loaded is null, never a reason to skip the
    // scrubber; the engine redacts irreversibly without it.
    async vault() {
      if (vault === undefined) {
        try {
          vault = await deps.loadVault();
        } catch (err) {
          if (err.code !== 'ZN_LOCKED') throw err;
          vault = null;
        }
      }
      return vault;
    },
  };
}

/**
 * The `zn run` prefix put in front of a Bash command that uses a secret. The
 * agent runs the rewritten command in bash (Claude Code's Bash tool, Git Bash
 * on Windows) or in the user's shell (OpenCode), so each path is one
 * single-quoted sh word and nothing in it is expanded.
 */
function znRunPrefix(opts, agentId) {
  if (opts.znRunPrefix) return opts.znRunPrefix;
  const q = (s) => shQuote(portablePath(s));
  const runJs = opts.runJs || path.resolve(__dirname, '..', 'broker', 'run.js');
  return 'ZN_AGENT=' + String(agentId).replace(/[^a-z0-9-]/g, '') + ' ' + q(opts.nodePath || process.execPath) + ' ' + q(runJs) + ' --';
}

/* Custom secret formats from the zn Team policy (verified cache), compiled
 * once per hook process. They only add redactions. */
let orgDetectors = null;
function orgDetectorsFor(opts) {
  if (orgDetectors === null) {
    try {
      const team = require('../team/policy');
      const { detectorsOf } = require('../team/effective');
      orgDetectors = require('../team/detectors').compile(detectorsOf(team.state({ home: opts && opts.znHome })));
    } catch (_) { orgDetectors = []; }
  }
  return orgDetectors;
}

async function ctxFor(ev, d, agentId, destination, needVault = true) {
  return {
    project: deps.findProjectRoot(ev.cwd || process.cwd()),
    agent: agentId,
    tool: ev.toolName || ev.tool,
    destination,
    vault: needVault ? await d.vault() : undefined,
    detectors: d.detectors ? d.detectors() : orgDetectorsFor(),
  };
}

/* ---------------------------- pre_tool ---------------------------- */

async function decidePre(ev, d, agentId, opts) {
  const pathOpts = { cwd: ev.cwd, home: opts.home };
  const input = ev.input || {};
  const tool = ev.tool;

  if (tool === 'read' || tool === 'lsp' || (tool === 'grep' && input.path)) {
    const deny = policy.readDenial(input.path, pathOpts);
    if (deny) return { decision: 'deny', message: deny };
  }
  if (tool === 'write' || tool === 'edit' || tool === 'multiedit' || tool === 'notebookedit') {
    // A patch can touch several files: every one is checked, not only the first.
    if (input.unparsed) return { decision: 'deny', message: 'zn: could not read the file names in this patch, so zn cannot check it.' };
    for (const p of Array.isArray(input.paths) ? input.paths : [input.path]) {
      const deny = policy.writeDenial(p, pathOpts);
      if (deny) return { decision: 'deny', message: deny };
    }
  }

  if (tool === 'webfetch') {
    if (markers.findMarkers(input.url || '').length) {
      return {
        decision: 'deny',
        message: 'zn: WebFetch never receives secret values. For an authenticated HTTP call use the secrets_http_request tool ' +
          'of the zn "secrets" MCP server: zn sends the request with the real value, only to the hosts allowed for that secret.',
      };
    }
    return { decision: 'allow' };
  }

  if (tool === 'monitor') return decideMonitor(ev, pathOpts, opts);
  if (tool === 'mcp' && ev.input && ev.input.args !== undefined) return decideMcp(ev, d, agentId);

  if (SHELL_TOOLS.has(tool)) {
    const original = String(input.command || '');
    const deny = policy.bashDenial(original, pathOpts);
    if (deny) return { decision: 'deny', message: deny };

    let command = original;
    const notes = [];
    const wrap = tool === 'powershell'
      ? policy.wrapPowerShell(command, { nodePath: opts.nodePath || process.execPath, runJs: opts.runJs || path.resolve(__dirname, '..', 'broker', 'run.js'), agent: agentId })
      : policy.wrapWithZnRun(command, znRunPrefix(opts, agentId));
    if (!wrap.ok) return { decision: 'deny', message: wrap.reason };
    if (wrap.wrapped) {
      command = wrap.command;
      notes.push('runs through `zn run` for ' + markers.findNamedMarkers(original).map((m) => m.name).join(', ') +
        ' (allowCommands, first-use approval and output masking apply)');
    }

    const detected = markers.findMarkers(command).filter((m) => m.detected);
    if (detected.length) {
      const network = policy.hasNetworkSignals(command);
      const ctx = await ctxFor(ev, d, agentId, network ? 'bash_network' : 'bash_local');
      const res = await d.engine().detokenize(command, ctx);
      if (res && typeof res.text === 'string' && res.restored && res.restored.length) {
        command = res.text;
        notes.push('restores ' + res.restored.length + ' scrubbed value(s) for a local command');
      }
      if (res && res.withheld && res.withheld.length) {
        notes.push('kept ' + res.withheld.length + ' token(s) unresolved: ' +
          res.withheld.map((w) => w.token + ' (' + w.reason + ')').join(', '));
      }
    }

    if (command === original) {
      if (markers.findMarkers(original).length) {
        // A command that carries markers always asks, even when nothing was rewritten
        // (already wrapped in `zn run` by the agent, or tokens kept unresolved).
        // Never let it run on the user's allow rules alone.
        return { decision: 'ask', message: 'zn: this command carries secret markers' + (notes.length ? '; ' + notes.join('; ') : '') + '.' };
      }
      return notes.length ? { decision: 'allow', message: 'zn: ' + notes.join('; ') } : { decision: 'allow' };
    }
    // kind tells adapters that cannot rewrite input what the rewrite was for.
    return { decision: 'ask', updatedInput: { command }, kind: wrap.wrapped ? 'wrap' : 'restore', message: 'zn: this command ' + notes.join('; ') + '.' };
  }

  if ((tool === 'write' || tool === 'edit' || tool === 'multiedit' || tool === 'notebookedit') && Array.isArray(input.texts)) {
    const withMarkers = input.texts.filter((t) => markers.findMarkers(t.value).length);
    if (withMarkers.length === 0) return { decision: 'allow' };
    const status = input.path ? gitStatusOf(path.resolve(ev.cwd || process.cwd(), input.path)) : 'unknown';
    const destination = status === 'ignored' || status === 'outside' ? 'write_ignored' : 'write_tracked';
    const ctx = await ctxFor(ev, d, agentId, destination);
    const updates = [];
    let restored = 0;
    const withheld = [];
    for (const t of withMarkers) {
      const res = await d.engine().detokenize(t.value, ctx);
      if (res && res.restored && res.restored.length && res.text !== t.value) {
        updates.push({ key: t.key, value: res.text });
        restored += res.restored.length;
      }
      if (res && res.withheld) withheld.push(...res.withheld);
    }
    const why = withheld.length
      ? ' Kept as tokens: ' + withheld.map((w) => w.token).join(', ') + (destination === 'write_tracked'
        ? ' (this file can be committed, so secrets stay as markers; put real values in a git-ignored file such as .env.local).'
        : '.')
      : '';
    if (updates.length === 0) return { decision: 'allow', message: why ? 'zn:' + why : undefined };
    return {
      decision: 'ask',
      updatedInput: { texts: updates },
      kind: 'restore',
      message: 'zn: restores ' + restored + ' secret value(s) in a git-ignored file.' + why,
    };
  }

  return { decision: 'allow' };
}

/*
 * Monitor streams a command's output lines to the model as events that no
 * PostToolUse hook sees, so the command itself is rewritten to pipe through
 * the streaming scrubber (lib/scrub/stream.js). The rewrite is shown to the
 * user (ask). WebSocket monitors cannot be scrubbed and are refused.
 *
 * The original command runs as one argument of `bash -c` (single-quoted), so
 * nothing in it can close a group or end the pipeline early; pipefail keeps
 * its exit status. A command is left as it is only when it is exactly this
 * wrapper with our own node and stream.js paths; mentioning stream.js is not
 * enough.
 */
function monitorTail(opts) {
  const p = (s) => shQuote(portablePath(s));
  return ' 2>&1 | ' + p(opts.nodePath || process.execPath) + ' ' + p(STREAM_JS);
}

function wrapMonitor(original, opts) {
  return 'set -o pipefail; bash -c ' + shQuote(original) + monitorTail(opts);
}

function isMonitorWrapper(command, opts) {
  const head = 'set -o pipefail; bash -c \'';
  const tail = '\'' + monitorTail(opts);
  if (!command.startsWith(head) || !command.endsWith(tail)) return false;
  // The body must be one single-quoted word: a ' may appear in it only
  // within the escapes shQuote writes for a quote.
  const body = command.slice(head.length, command.length - tail.length);
  return body.replace(SH_QUOTE_ESCAPE, '').indexOf("'") === -1;
}

function decideMonitor(ev, pathOpts, opts) {
  const raw = (ev.raw && ev.raw.tool_input) || {};
  if (raw.ws !== undefined && raw.command === undefined) {
    return { decision: 'deny', message: 'zn: a WebSocket monitor streams data to the model without passing through the secret scrubber. Use a command instead (its output is scrubbed).' };
  }
  const original = String(ev.input.command || '');
  if (!original.trim()) return { decision: 'allow' };
  const deny = policy.bashDenial(original, pathOpts);
  if (deny) return { decision: 'deny', message: deny };
  if (markers.findMarkers(original).length) {
    return { decision: 'deny', message: 'zn: secret markers are not supported in Monitor commands. Run the command with the Bash tool (it goes through `zn run`).' };
  }
  if (isMonitorWrapper(original, opts)) return { decision: 'ask', message: 'zn: this monitor already pipes through the secret scrubber.' };
  const command = wrapMonitor(original, opts);
  return { decision: 'ask', updatedInput: { command }, kind: 'monitor', message: 'zn: the monitor output is piped through the local secret scrubber, so secret values in it are replaced with __ZN_ tokens.' };
}

/*
 * MCP tool calls. Only Cursor sends the arguments (input.args); any other
 * agent's MCP pre-tool call is allowed before the vault is touched. The
 * arguments are checked for __ZN_ markers, which servers other than zn's own
 * never receive, and for credentials the scrubber finds, which no server
 * should receive from the agent. zn's "secrets" server takes markers by design,
 * but only when it is identified strictly (see isOurSecretsServer); it still
 * gets the credential check. A call with no objection gets no answer, so the
 * agent's own MCP approval still applies.
 */
const MCP_SCAN_CAP = 1024 * 1024; // characters, all arguments together
const MCP_WINDOW = 128 * 1024; // the scrubber reads the text in windows of this size
const MCP_OVERLAP = 16 * 1024; // windows overlap, so a secret across a boundary is seen whole

/* Every string of an MCP call's arguments (values and keys), joined with
 * newlines, or null when they hold more than MCP_SCAN_CAP characters. */
function mcpArgumentText(args) {
  const out = [];
  let total = 0;
  const stack = [args];
  while (stack.length) {
    const v = stack.pop();
    if (typeof v === 'string') {
      total += v.length + 1;
      if (total > MCP_SCAN_CAP) return null;
      out.push(v);
    } else if (Array.isArray(v)) {
      for (const x of v) stack.push(x);
    } else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) stack.push(k, x);
    }
  }
  return out.join('\n');
}

/* zn's own "secrets" server: the exact command `zn hooks install` writes (the
 * matcher of `zn audit`, with the "--agent <id>" suffix it adds), outside the
 * project. A server reached by URL is never ours, and a name alone is not enough. */
function isOurSecretsServer(ev, root) {
  const raw = ev.raw || {};
  if (!ev.mcp || ev.mcp.server !== 'secrets') return false;
  if (raw.url || raw.mcp_server_url) return false;
  if (typeof raw.command !== 'string' || !raw.command.trim()) return false;
  const argv = require('../audit/patterns').splitCommand(raw.command);
  return Boolean(require('../audit')._internal.isOurMcp(argv, { rec: { root } }));
}

/* Server names come from the agent's config: keep the message to plain characters. */
function mcpServerLabel(server) {
  const s = String(server || '').replace(/[^A-Za-z0-9 ._-]/g, '').slice(0, 64).trim();
  return s ? 'the MCP server ' + s : 'an MCP server';
}

async function decideMcp(ev, d, agentId) {
  const text = mcpArgumentText(ev.input.args);
  if (text === null) {
    return { decision: 'deny', message: 'zn: the arguments of this MCP call are larger than 1 MB (counted in characters), so zn cannot check them.' };
  }
  if (!text) return { decision: 'allow' }; // nothing to check, so the vault is not loaded
  const server = ev.mcp && ev.mcp.server ? String(ev.mcp.server) : '';
  const ours = isOurSecretsServer(ev, deps.findProjectRoot(ev.cwd || process.cwd()));
  if (!ours && markers.findMarkers(text).length) {
    return {
      decision: 'deny',
      message: 'zn: MCP tools from other servers never receive secret values. For an authenticated HTTP call use the secrets_http_request tool ' +
        'of the zn "secrets" MCP server.',
    };
  }

  const engine = d.engine();
  let ctx = await ctxFor(ev, d, agentId, 'mcp_input');
  if (typeof engine.prepare === 'function') ctx = await engine.prepare(ctx);
  const kinds = new Set();
  for (let start = 0; ; start += MCP_WINDOW - MCP_OVERLAP) {
    for (const span of engine.scan(text.slice(start, start + MCP_WINDOW), ctx) || []) {
      if (SECRET_SOURCES.has(span.source)) kinds.add(kindLabel(span.type));
    }
    if (start + MCP_WINDOW >= text.length) break;
  }
  if (kinds.size === 0) return { decision: 'allow' };
  return {
    decision: 'deny',
    message: 'zn: this call would send a secret (' + [...kinds].join(', ') + ') to ' + mcpServerLabel(server) + '. ' +
      'Keep secrets in the vault and pass them with zn run or secrets_http_request.',
  };
}

/* ---------------------------- post_tool --------------------------- */

async function decidePost(ev, d, agentId) {
  if (!POST_TOOLS.has(ev.tool)) return { decision: 'allow' };
  if (ev.output === undefined || ev.output === null) return { decision: 'allow' };
  const engine = d.engine();
  const ctx = await ctxFor(ev, d, agentId, 'assistant');
  const types = new Map();
  let locked = false;
  const updated = await mapStrings(ev.output, async (s) => {
    if (s.length < 8) return s;
    const res = await engine.tokenize(s, ctx);
    if (!res || typeof res.text !== 'string') throw deps.znError('ZN_ENGINE', 'tokenize returned an unexpected shape');
    if (res.locked) locked = true;
    for (const r of res.replaced || []) types.set(r.type, (types.get(r.type) || 0) + 1);
    return res.text;
  });
  if (types.size === 0) return { decision: 'allow' };
  const total = [...types.values()].reduce((a, b) => a + b, 0);
  const summary = [...types.entries()].map(([t, n]) => t + (n > 1 ? ' x' + n : '')).join(', ');
  return {
    decision: 'allow',
    stats: { redacted: total, detections: Object.fromEntries(types) },
    updatedOutput: updated,
    message: 'zn: ' + total + ' secret value(s) in this output were replaced with __ZN_ tokens (' + summary + '). ' +
      (locked ? '__ZN_REDACTED_ markers cannot be restored, so do not retry to get the values. ' : 'Real values stay on this machine; use the tokens as they are.'),
    userMessage: locked ? lockedNotice() : undefined,
  };
}

/* Shown to the person (systemMessage) when the vault is locked. */
function lockedNotice() {
  return 'zn hid secret values in this output. Your vault is locked, so they cannot be put back afterwards. ' +
    'To keep them restorable next time, unlock it in your terminal: ' + znCommand('unlock');
}

/* --------------------------- user_prompt -------------------------- */

async function decidePrompt(ev, d, agentId) {
  const prompt = String((ev.input && ev.input.prompt) || '');
  if (prompt.length < 8) return { decision: 'allow' };
  const engine = d.engine();
  let ctx = await ctxFor(ev, d, agentId, 'assistant');
  // scan() is pure: prepare() first fetches the vault's exact values (and
  // local ones), so a pasted vault secret is caught even without a pattern.
  if (typeof engine.prepare === 'function') ctx = await engine.prepare(ctx);
  const spans = engine.scan(prompt, ctx) || [];
  const secrets = spans.filter((s) => SECRET_SOURCES.has(s.source));
  // Prompts only: NAME=value in the middle of a sentence, even when the value
  // does not look random (see lib/scrub/prompt.js).
  for (const a of require('../scrub/prompt').findPromptAssignments(prompt)) {
    if (!secrets.some((s) => s.start < a.end && a.start < s.end)) secrets.push(a);
  }
  if (secrets.length === 0) return { decision: 'allow' };
  const names = secrets.map(nameOf);
  const shown = [...new Set(secrets.map((s, i) => names[i] || kindLabel(s.type)))];
  const suggestion = names[0] || suggestedName(secrets[0]);
  return {
    decision: 'deny',
    stats: { detections: Object.fromEntries([...new Set(secrets.map((s) => s.type || 'SECRET'))].map((k) => [k, 1])) },
    message: 'zn: this prompt was not sent because it contains a secret (' + shown.join(', ') + '). ' +
      'Save it in your vault instead: ' + znCommand('secret set ' + suggestion) +
      ', then ask your agent to use it (as __ZN_' + suggestion + '__).',
  };
}

// A vault name: upper case, at most 64 characters. A JSON key such as
// "db_password" is shown as DB_PASSWORD; anything else falls back to the kind.
const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const GENERIC_TYPES = new Set(['SECRET', 'CREDENTIAL']);

function nameOf(span) {
  const n = String(span.name || '').toUpperCase();
  return NAME_RE.test(n) ? n : null;
}

// Words that keep their usual capitals in a message a person reads.
const ACRONYMS = new Set(['AWS', 'API', 'SSH', 'JWT', 'SSN', 'NIE', 'DNI', 'IBAN', 'PAT', 'DB', 'PII', 'URL', 'GCP', 'OAUTH', 'TLS', 'SSL', 'SMTP']);
const BRANDS = {
  ANTHROPIC: 'Anthropic', AZURE: 'Azure', DATABRICKS: 'Databricks', DIGITALOCEAN: 'DigitalOcean', DISCORD: 'Discord',
  DOCKERHUB: 'Docker Hub', GITHUB: 'GitHub', GITLAB: 'GitLab', GOOGLE: 'Google', MAILGUN: 'Mailgun', NEWRELIC: 'New Relic',
  NPM: 'npm', OPENAI: 'OpenAI', PYPI: 'PyPI', REPLICATE: 'Replicate', SENDGRID: 'SendGrid', SHOPIFY: 'Shopify',
  SLACK: 'Slack', STRIPE: 'Stripe', SUPABASE: 'Supabase', TELEGRAM: 'Telegram', TWILIO: 'Twilio', XAI: 'xAI',
};

/* "AWS_KEY" -> "an AWS key", "GITHUB_TOKEN" -> "a GitHub token", for a message
 * a person reads. Only known acronyms and brands get capitals. */
function kindLabel(type) {
  const words = String(type || '').split(/_+/).filter(Boolean).map((w) => {
    const u = w.toUpperCase();
    if (Object.prototype.hasOwnProperty.call(BRANDS, u)) return BRANDS[u];
    if (ACRONYMS.has(u)) return u;
    return w.toLowerCase();
  });
  const label = words.join(' ') || 'secret';
  return (/^([AEIOU]|AWS\b|API\b|SSH\b|SSN\b|IBAN\b|OAUTH\b)/i.test(label) ? 'an ' : 'a ') + label;
}

/* The name to suggest for `zn secret set` when the detection has no name. */
function suggestedName(span) {
  const t = String(span.type || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/_\d+$/, '');
  return t && !GENERIC_TYPES.has(t) ? t : 'MY_SECRET';
}

/* ------------------------------ entry ----------------------------- */

function failDecision(ev, err, mode) {
  const missing = err.code === 'ZN_UNAVAILABLE';
  const msg = 'zn: hook error (' + (err.code || 'error') + '): ' + (missing ? REINSTALL : err.message);
  // Fail open only when the engine itself is missing and the user chose so.
  if (mode === 'open' && missing) return { decision: 'allow', failOpen: true, warning: msg };
  const r = failClosed(ev, err, msg);
  // The user (not only the model) needs to hear how to fix a broken install.
  if (missing) r.userMessage = msg;
  return r;
}

function failClosed(ev, err, msg) {
  if (ev && ev.event === 'post_tool' && ev.output !== undefined) {
    const withheld = '[zn: output withheld because the secret scrubber is unavailable: ' + (err.code || 'error') + ']';
    const shape = (v) => (typeof v === 'string' ? withheld
      : Array.isArray(v) ? v.map(shape)
        : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shape(x)])) : v);
    return { decision: 'allow', updatedOutput: shape(ev.output), message: msg };
  }
  if (ev && ev.event === 'pre_tool') return { decision: 'deny', failClosed: true, message: msg + ' (fail-closed)' };
  return { decision: 'deny', failClosed: true, message: msg + ' (fail-closed)', userMessage: msg };
}

/**
 * Handle one raw event. Returns {output, stderr} where output is the JSON
 * value to print (or null for "no opinion").
 * opts: {engine, vault, failMode, home, znRunPrefix}
 */
async function handle(adapter, rawEvent, opts = {}) {
  const mode = failModeOf(opts);
  let ev = null;
  let decision;
  try {
    ev = adapter.normalize(rawEvent);
    const d = lazyDeps(opts);
    if (!ev || !ev.event) decision = { decision: 'allow' };
    else if (ev.event === 'pre_tool') decision = await decidePre(ev, d, adapter.id, opts);
    else if (ev.event === 'post_tool') decision = await decidePost(ev, d, adapter.id);
    else if (ev.event === 'user_prompt') decision = await decidePrompt(ev, d, adapter.id);
    else decision = { decision: 'allow' };
  } catch (err) {
    decision = failDecision(ev, err, mode);
  }
  const output = adapter.respond({ ...decision, event: ev });
  countHook(adapter.id, ev, decision, opts);
  return { output, stderr: decision.warning || null, decision };
}

/**
 * Local counts for `zn-gate stats` (best effort; never changes the decision). A denial because zn itself
 * failed (fail-closed) is not counted as a block; asks and fail-open passes count as warnings.
 */
function countHook(agentId, ev, decision, opts = {}) {
  try {
    if (!ev || !ev.event || !decision) return;
    const extra = decision.stats || {};
    const file = opts.home ? path.join(opts.home, '.zn', 'stats.json') : undefined;
    require('../stats').record({
      layer: 'hook', agent: agentId, checked: 1,
      blocked: decision.decision === 'deny' && !decision.failClosed ? 1 : 0,
      warned: decision.decision === 'ask' || decision.failOpen ? 1 : 0,
      redacted: extra.redacted || 0,
      detections: extra.detections || {},
    }, file ? { file } : {});
  } catch {
    /* counting must never affect a hook */
  }
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { raw += c; });
    process.stdin.on('end', () => resolve(raw));
    process.stdin.on('error', reject);
  });
}

/*
 * An event that cannot be read cannot be checked, so it is refused. Letting
 * it pass is a silent fail-open: the byte order mark of PowerShell did exactly
 * that until it was fixed. Exit code 2 blocks the call in Claude Code and
 * Codex (their documented block code for these events); Cursor documents exit
 * 2 as deny for preToolUse, beforeShellExecution and beforeReadFile, and its
 * deny answer is printed too, which covers beforeSubmitPrompt. With
 * hooks.whenUnavailable "allow" in ~/.zn/config.json, such events pass, as
 * they do when the engine is missing.
 */
function refuseInput(agentId, why) {
  if (failModeOf({}) === 'open') {
    process.stderr.write('zn hook: ' + why + '; passed through (hooks.whenUnavailable is "allow")\n');
    return;
  }
  const msg = 'zn: ' + why + ', so zn cannot check this call and it is denied. ' +
    'Set {"hooks": {"whenUnavailable": "allow"}} in ~/.zn/config.json to let such events pass.';
  process.stderr.write('zn hook: ' + msg + '\n');
  if (agentId === 'cursor') process.stdout.write(JSON.stringify({ permission: 'deny', continue: false, user_message: msg, agent_message: msg }));
  process.exitCode = 2;
}

async function main(args) {
  try {
    await handleEvent(args);
  } catch (err) {
    // Anything unexpected fails closed: the call is refused, not passed through.
    refuseInput(args[0], 'the hook failed (' + ((err && err.message) || String(err)) + ')');
  }
}

async function handleEvent(args) {
  const agentId = args[0];
  let adapter;
  try {
    adapter = require('../agents').getAdapter(agentId);
  } catch (err) {
    process.stderr.write('zn hook: ' + err.message + '\n');
    process.exitCode = 1;
    return;
  }
  // Windows PowerShell 5.1 writes a byte order mark when it pipes text to a
  // native command, which JSON.parse rejects.
  const text = (await readStdin()).replace(/^﻿/, '');
  if (!text.trim()) return refuseInput(agentId, 'stdin was empty');
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    return refuseInput(agentId, 'the event on stdin is not valid JSON (' + err.message + ')');
  }
  // Valid JSON that is not an object (a number, a string, an array) is not an event.
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return refuseInput(agentId, 'the event on stdin is not a JSON object');
  }
  const res = await handle(adapter, raw);
  if (res.stderr) process.stderr.write(res.stderr + ' (fail-open: event passed through)\n');
  try { require('../vault/client').close(); } catch (_) { /* not loaded */ }
  if (res.output !== null && res.output !== undefined) process.stdout.write(JSON.stringify(res.output));
}

module.exports = { handle, main, mapStrings, decidePre, decidePost, decidePrompt };

// Direct entry (`node lib/hooks/runner.js <agent>`): what installed hooks call,
// so a hook does not pay for loading the rest of the CLI.
if (require.main === module) main(process.argv.slice(2));
