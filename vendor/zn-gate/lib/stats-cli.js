'use strict';

/**
 * zn-gate stats            what zn-gate did on this machine in the last 30 days (local counts only)
 * zn-gate stats --days N   another window (1-90)
 * zn-gate stats --json     the same as JSON
 * zn-gate stats share on|off|status|show
 *                          opt-in sharing of pseudonymous daily counts (off by default; see lib/stats-share.js)
 */

const stats = require('./stats');
const share = require('./stats-share');

const LAYER_NAMES = { hook: 'agent hooks', shield: 'shield (wrapped MCP servers)', mcp: 'MCP tools', broker: 'secrets broker', cli: 'command line' };

function fmt(n) {
  return Number(n || 0).toLocaleString('en-US');
}

const USAGE = 'Usage: zn-gate stats [--days 1-90] [--json]\n       zn-gate stats share on|off|status|show\n';

function parse(args) {
  const o = { days: 30, json: false, rest: [], bad: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--json') o.json = true;
    else if (args[i] === '--days') o.days = Number(args[++i]);
    else if (args[i].startsWith('-')) o.bad = true;
    else o.rest.push(args[i]);
  }
  if (!Number.isInteger(o.days) || o.days < 1 || o.days > stats.KEEP_DAYS) o.bad = true;
  if (o.rest.length && o.rest[0] !== 'share') o.bad = true;
  return o;
}

/** Turning sharing on is a choice for the person, in their own terminal: never for an agent or a script. */
function confirmInTerminal(question) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return Promise.resolve(false);
  return new Promise((resolve) => {
    const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (a) => { rl.close(); resolve(/^y(es)?$/i.test(String(a).trim())); });
  });
}

function printSummary(s, out) {
  const t = s.total;
  out(`zn-gate on this machine, last ${s.days} day${s.days === 1 ? '' : 's'}` + (s.since ? ` (counting since ${s.since})` : '') + ':\n\n');
  if (!t.checked && !t.blocked && !t.redacted && !t.warned) {
    out('  Nothing recorded yet. Counts start once zn-gate checks something (hooks, MCP tools or wrapped servers).\n');
  } else {
    out(`  ${fmt(t.checked)} events checked (prompts, tool calls and tool results)\n`);
    out(`  ${fmt(t.blocked)} blocked (a secret file read, a pasted secret, a prompt injection or a risky call)\n`);
    out(`  ${fmt(t.redacted)} secret values replaced before the model saw them\n`);
    if (t.warned) out(`  ${fmt(t.warned)} warnings\n`);
    const types = Object.entries(s.detections).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (types.length) out('\n  Secret types found: ' + types.map(([k, n]) => `${k} ${fmt(n)}`).join(', ') + '\n');
    const keys = Object.entries(s.byKey).sort((a, b) => b[1].checked - a[1].checked);
    if (keys.length) {
      out('\n  By agent:\n');
      for (const [key, c] of keys) {
        const [layer, agent] = key.split(':');
        out(`    ${agent} (${LAYER_NAMES[layer] || layer}): ${fmt(c.checked)} events, ${fmt(c.blocked)} blocked, ${fmt(c.redacted)} replaced\n`);
      }
    }
  }
  const st = share.status();
  out('\n' + (st.share
    ? '  Sharing pseudonymous daily counts: on. Turn it off with `zn-gate stats share off`.\n'
    : '  These counts stay on this machine. To help improve zn-gate, you can share pseudonymous daily counts:\n  `zn-gate stats share show` shows exactly what would be sent, `zn-gate stats share on` turns it on.\n'));
  if (!stats.enabled()) out('  Counting is off on this machine (ZN_STATS=off).\n');
}

function explainShare(out) {
  out('What is shared, once a day, only if you turn sharing on: a random id for this installation (a new one each time you turn sharing on), the day, the zn-gate version, the operating system, the Node.js version, the agent and part of zn-gate used most that day, and how many secrets of each built-in type were found (for example AWS_KEY 3). Never secret values, prompts, variable or secret names, file names, paths, repository names, hosts or emails.\n');
  out(`Where: ${share.ENDPOINT}.\n`);
}

async function run(args, out = (s) => process.stdout.write(s), { confirm = confirmInTerminal } = {}) {
  const o = parse(args);
  if (o.bad) { out(USAGE); return 2; }
  if (o.rest[0] === 'share') {
    const sub = o.rest[1] || 'status';
    if (sub === 'on') {
      if (share.status().share) { out('Sharing pseudonymous daily counts is already on.\n'); return 0; }
      explainShare(out);
      if (!(await confirm('Turn on sharing of these pseudonymous daily counts? [y/N] '))) {
        out('Sharing stays off. (It can only be turned on by you, in your own terminal.)\n');
        return 1;
      }
      share.setShare(true);
      out('Sharing pseudonymous daily counts is on. Counts from today on are sent when you run `zn-gate stats`.\n');
      return 0;
    }
    if (sub === 'off') {
      share.setShare(false);
      out('Sharing is off. Nothing more is sent; your local counts stay on this machine.\n');
      return 0;
    }
    if (sub === 'show') {
      explainShare(out);
      if (!share.status().share) {
        const example = share.pendingReports(new Date(), { preview: true }).slice(-1);
        out('\nSharing is off, so nothing is sent.' + (example.length
          ? ' With sharing on, a report built from your counts would look like this:\n' + JSON.stringify(example[0]) + '\n'
          : ' There are no complete days of counts yet to show an example.\n'));
      } else {
        const pending = share.pendingReports();
        out(pending.length ? '\nWould be sent now:\n' + pending.map((r) => JSON.stringify(r)).join('\n') + '\n' : '\nNothing to send right now (only complete days are sent).\n');
      }
      return 0;
    }
    if (sub === 'status') {
      out(share.status().share ? 'Sharing pseudonymous daily counts: on.\n' : 'Sharing pseudonymous daily counts: off (the default).\n');
      return 0;
    }
    out('Usage: zn-gate stats share on|off|status|show\n');
    return 2;
  }
  const s = stats.summary({ days: o.days });
  let res = { sent: 0, failed: 0 };
  const sentDays = [];
  if (share.status().share) res = await share.sendPending({ print: (r) => sentDays.push(r.day) });
  if (o.json) {
    out(JSON.stringify({ ...s, sharing: share.status().share, sent_days: sentDays, send_failed: res.failed }, null, 2) + '\n');
  } else {
    printSummary(s, out);
    for (const d of sentDays) out(`  Shared pseudonymous counts for ${d}.\n`);
    if (res.failed) out(`  ${res.failed} day(s) could not be shared; they will be tried next time.\n`);
  }
  return 0;
}

module.exports = { run };
