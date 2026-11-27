'use strict';
/**
 * `zn team status --rules`: the active organization policy in plain words.
 *
 * Reads only what policy.state() returns: the readable copy that `zn team sync`
 * wrote, checked again here with the key pinned at join. Nothing is fetched and
 * nothing is changed. A copy that does not verify, or that has expired, shows
 * no rules: it is never presented as the policy in force. Secrets appear by
 * name pattern only, never as values.
 */

const { INVISIBLE_ANY_RE } = require('../vault/confirm');

const clean = (s) => String(s).replace(INVISIBLE_ANY_RE, '');
const list = (a) => a.map(clean).join(', ');

function agentsText(agents) {
  return agents.includes('*') ? 'all agents' : 'agents: ' + list(agents);
}

/** What one rule does, in one sentence. */
function ruleText(r) {
  const parts = [];
  if (r.deny === true) parts.push('blocks use of');
  else if (r.warn === true) parts.push('allows, with a warning and an audit record, use of');
  else parts.push('restricts use of');
  parts.push('secrets named ' + clean(r.secret) + ' (' + agentsText(r.agents) + ')');
  const extra = [];
  if (r.mode) extra.push('mode ' + r.mode);
  if (r.allowHosts) extra.push('hosts allowed: ' + list(r.allowHosts));
  if (r.allowCommands) extra.push('commands allowed: ' + list(r.allowCommands));
  if (r.injectAt) extra.push('value only in the ' + r.injectAt);
  let text = parts.join(' ');
  if (extra.length) text += '; ' + extra.join('; ');
  if (r.reason) text += '. Reason: ' + clean(r.reason);
  return text;
}

/**
 * rulesView(state) -> the JSON shape and the reason none are shown.
 * state: the result of policy.state() (or null).
 */
function rulesView(st) {
  if (!st || st.state === 'none') return { shown: false, state: 'none', message: 'No organization policy has been received yet, so there are no rules to show. Run `zn team sync`.' };
  if (st.state === 'invalid') return { shown: false, state: 'invalid', message: 'The saved policy does not verify (' + (st.error || 'invalid') + '), so no rules are shown from it. Run `zn team sync`.' };
  if (st.state === 'expired') return { shown: false, state: 'expired', message: 'The saved policy (version ' + st.version + ') expired on ' + st.expires_at + ', so it is not active and no rules are shown from it. Only restrictions apply until a new policy arrives; run `zn team sync`.' };
  const p = st.policy;
  const env = (require('./policy').readCache() || {}).envelope || {};
  return {
    shown: true,
    state: 'active',
    version: p.version,
    key_id: (env.signature && env.signature.kid) || null,
    issued_at: p.issued_at,
    expires_at: p.expires_at,
    rules: p.rules.map((r) => ({
      secret: r.secret,
      agents: r.agents,
      action: r.deny === true ? 'block' : r.warn === true ? 'warn' : 'restrict',
      mode: r.mode || null,
      allow_hosts: r.allowHosts || null,
      allow_commands: r.allowCommands || null,
      inject_at: r.injectAt || null,
      reason: r.reason ? clean(r.reason) : null,
      text: ruleText(r),
    })),
    detectors: (p.detectors || []).map((d) => ({ id: d.id, type: d.type })),
    redaction: p.redaction || null,
  };
}

/** Lines for the terminal. */
function rulesLines(v) {
  if (!v.shown) return ['Rules: ' + v.message];
  const lines = [
    'Rules (verified policy, version ' + v.version + ', signed with key ' + (v.key_id || 'unknown') + ', valid until ' + v.expires_at + '):',
  ];
  if (!v.rules.length) lines.push('  This policy has no rules: it restricts nothing on its own.');
  v.rules.forEach((r, i) => lines.push('  ' + (i + 1) + '. ' + r.text));
  if (v.detectors.length) lines.push('  Custom detectors: ' + v.detectors.map((d) => d.id + ' (' + d.type + ')').join(', '));
  if (v.redaction) lines.push('  Redaction: ' + Object.keys(v.redaction).map((k) => k + ' ' + (v.redaction[k] ? 'on' : 'off')).join(', '));
  return lines;
}

module.exports = { rulesView, rulesLines, ruleText };
