'use strict';
/**
 * How an organization policy changes one secret's local settings on this
 * machine.
 *
 * Every rule whose secret pattern matches restricts the secret, for every
 * caller, whatever agents it names:
 *   - `deny` blocks the secret;
 *   - `warn` lets the use go ahead, records it with decision "warn" and
 *     tells the user (a `deny` in another matching rule still wins; the
 *     rule's other restrictions still apply);
 *   - `allowHosts` / `allowCommands` drop local entries the rule does not list;
 *   - `mode: proxy` is the most restrictive mode;
 *   - `injectAt` limits where secrets_http_request may put the value
 *     (the local `allowIn` list is cut down to it).
 * zn-gate cannot prove which agent is calling (any program on the machine
 * can start its tools and say it is some agent), so a restriction meant for
 * one agent applies to all of them.
 *
 * The organization can open only hosts, and only with a first-use approval
 * on this machine: a host the local settings do not already allow stays out
 * until the user approves it on the vault's own channel (`approvals`). A
 * stolen signing key therefore cannot send a secret somewhere new without
 * someone at this machine saying yes. Here the agent list matters: a host is
 * offered only to the agents its rule names (`*` for any). Commands, modes
 * and HTTP placements are never opened by the organization.
 *
 * It can never touch the base protections (credential files, ~/.zn, agent
 * configuration): those live in the hook policy, which org rules do not
 * reach.
 *
 * When the cached policy expired (offline for longer than its lifetime), the
 * strict mode keeps what restricts and withdraws what the organization had
 * opened, approved or not.
 */

const { INVISIBLE } = require('../vault/confirm');

const RESTRICTIVE_MODE = 'proxy';
const DEFAULT_ALLOW_IN = ['header'];
/** Audit reason of a use that a `warn` rule let through. */
const WARN_REASON = 'policy:warn';

function secretMatches(pattern, name) {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return name.startsWith(pattern.slice(0, -1));
  return pattern === name;
}

const rulesOf = (policy) => ((policy && Array.isArray(policy.rules)) ? policy.rules : []);

/* Does the local host list already cover `host`? Wildcards: "*.example.com"
 * covers sub.example.com and a.b.example.com, not example.com itself. */
function hostCovered(list, host) {
  const h = String(host).toLowerCase();
  for (const raw of list || []) {
    const e = String(raw).toLowerCase();
    if (e === h) return true;
    if (e.startsWith('*.')) {
      const suffix = e.slice(1); // ".example.com"
      if (h.startsWith('*.') ? h.slice(1).endsWith(suffix) : h.endsWith(suffix)) return true;
    }
  }
  return false;
}

const hasPort = (h) => /:\d+$/.test(String(h));
const approvalKey = (org, secret, kind, value) => [org, secret, kind, value].join('\u0000');

/**
 * effective(name, local, {policy, state, org, agent, agentTrusted, approvals}) ->
 *   {meta, deny, warn, reason?, rule?, warnRule?, warnReason?, pending: [{kind, value}], org?}
 *
 * local: the secret's local settings ({mode, allowHosts, allowCommands, allowIn, ...}).
 * state: 'active' | 'expired' (anything else: the policy is ignored).
 * agent / agentTrusted: which agent is asking, and whether the id comes from
 *   an MCP configuration zn wrote. They only decide which hosts can be offered
 *   for approval; they never lift a restriction.
 * approvals: Set or object of approvalKey() strings already approved on this machine.
 * meta: the settings to enforce; pending: openings that need an approval.
 */
function effective(name, local, opts) {
  const o = opts || {};
  const meta = Object.assign({}, local, {
    allowHosts: (local && local.allowHosts) || [],
    allowCommands: (local && local.allowCommands) || [],
    allowIn: (local && Array.isArray(local.allowIn) && local.allowIn.length) ? local.allowIn : DEFAULT_ALLOW_IN,
  });
  const out = { meta, deny: false, warn: false, pending: [] };
  if (!o.policy || (o.state !== 'active' && o.state !== 'expired')) return out;
  out.org = o.org || o.policy.org;
  const all = rulesOf(o.policy);
  const matching = all.filter((r) => secretMatches(r.secret, name));
  if (!matching.length) return out;
  out.rule = all.indexOf(matching[0]);
  const denying = matching.find((r) => r.deny === true);
  if (denying) {
    out.deny = true;
    out.reason = 'policy:org_deny';
    out.rule = all.indexOf(denying);
    return out;
  }
  const warning = matching.find((r) => r.warn === true);
  if (warning) {
    out.warn = true;
    out.warnRule = all.indexOf(warning);
    if (typeof warning.reason === 'string') out.warnReason = warning.reason;
  }

  const strict = o.state === 'expired';
  const agent = o.agentTrusted && o.agent ? o.agent : null;
  const approved = (value) => {
    const k = approvalKey(out.org, name, 'host', value);
    const a = o.approvals;
    return Boolean(a && (a instanceof Set ? a.has(k) : Object.prototype.hasOwnProperty.call(a, k)));
  };
  const pending = new Set();
  let narrowed = false;

  for (const r of matching) {
    if (r.mode === RESTRICTIVE_MODE) meta.mode = RESTRICTIVE_MODE;
    // A local entry allows its own word prefixes too ("git" allows "git push"),
    // so an organization entry it covers is a narrowing, not an opening.
    if (Array.isArray(r.allowCommands)) {
      const cur = meta.allowCommands;
      meta.allowCommands = r.allowCommands.filter((c) => cur.some((l) => c === l || c.startsWith(l + ' ')));
    }
    if (r.injectAt !== undefined) meta.allowIn = meta.allowIn.filter((p) => p === r.injectAt);
    if (Array.isArray(r.allowHosts)) {
      const agents = r.agents || [];
      const canOpen = !strict && (agents.includes('*') || (agent !== null && agents.includes(agent)));
      const current = meta.allowHosts;
      meta.allowHosts = r.allowHosts.filter((h) => {
        // A host with a port is never matched by the broker (it compares host
        // names): such an entry only restricts and is never offered.
        if (hasPort(h)) return false;
        if (hostCovered(current, h)) return true;
        // Not allowed so far. If an earlier rule already narrowed the hosts,
        // that restriction wins. Otherwise the host is new to this machine:
        // it can be opened, with an approval, for the agents the rule names.
        if (narrowed || !canOpen) return false;
        if (approved(h)) return true;
        pending.add(h);
        return false;
      });
      narrowed = true;
    }
  }
  // Offer only hosts that every later host list keeps: approving one that a
  // later rule removes would change nothing.
  const lists = matching.filter((r) => Array.isArray(r.allowHosts)).map((r) => r.allowHosts);
  out.pending = [...pending]
    .filter((h) => lists.every((l) => hostCovered(l, h)))
    .map((value) => ({ kind: 'host', value }));
  return out;
}

/**
 * The most specific pending opening that covers what is being used: an exact
 * entry before a wildcard one. {kind, value, wildcard} or null.
 */
function pickOpening(pending, kind, matches) {
  const list = (pending || []).filter((p) => p.kind === kind && matches(p.value));
  if (!list.length) return null;
  const exact = list.find((p) => !/[*]/.test(p.value));
  const best = exact || list.sort((a, b) => b.value.length - a.value.length)[0];
  return { kind, value: best.value, wildcard: /[*]/.test(best.value) };
}

const INVISIBLE_RE = new RegExp('[' + INVISIBLE + ']', 'g');

/**
 * The line shown to the user (and the agent) when a `warn` rule lets a
 * secret through. `reason` is the rule's text from the signed policy: text
 * from the organization's admin that reaches the agent, so it is cleaned
 * (the same invisible and control characters as the vault dialogs, cut at
 * 200 characters), quoted and labelled as a policy note. One line.
 */
function warnNotice(name, reason) {
  const why = typeof reason === 'string'
    ? reason.replace(INVISIBLE_RE, ' ').replace(/"/g, "'").replace(/\s+/g, ' ').trim().slice(0, 200).trim()
    : '';
  return 'zn: your team policy would block ' + name + ' here' + (why ? ' (policy note: "' + why + '")' : '') +
    '. It was allowed and recorded for your organization.';
}

/**
 * detectorsOf(state) -> [{id, pattern, type}] of the policy (also in strict
 * mode: an extra detector only redacts more).
 */
function detectorsOf(st) {
  if (!st || !st.policy || (st.state !== 'active' && st.state !== 'expired')) return [];
  return Array.isArray(st.policy.detectors) ? st.policy.detectors : [];
}

module.exports = { effective, hostCovered, approvalKey, pickOpening, detectorsOf, secretMatches, warnNotice, WARN_REASON };
