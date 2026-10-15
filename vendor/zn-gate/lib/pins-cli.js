'use strict';

/**
 * zn-gate pins                      list the MCP servers the shield has pinned
 * zn-gate pins approve <server>     accept the changed or new tools of a server
 * zn-gate pins approve --all        accept them for every server
 *
 * <server> is the key that `zn-gate pins` prints. Approving is a decision for
 * you: it only runs in an interactive terminal and asks you to type the key
 * (or "all") again, and the agent hooks refuse the command from an agent.
 */

const readline = require('readline');
const pins = require('./mcp-pins');

function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    rl.question(question, (answer) => {
      rl.close();
      resolve(String(answer || '').trim());
    });
  });
}

async function run(args) {
  const [sub, which] = args;
  if (!sub || sub === 'list') {
    const servers = pins.list();
    if (!servers.length) {
      process.stdout.write('No MCP server has been pinned yet. Servers are pinned the first time `zn-gate shield` sees their tools.\n');
      return 0;
    }
    process.stdout.write('MCP tool pins (' + pins.pinsDir() + ', mode: ' + pins.mode() + ')\n\n');
    for (const s of servers) {
      process.stdout.write('  ' + s.key + '  ' + s.command + '\n');
      process.stdout.write('      ' + s.tools + ' tool(s) pinned' + (s.pinnedAt ? ' ' + s.pinnedAt : '') + '\n');
      if (s.pending.length) process.stdout.write('      changed or new since then: ' + s.pending.slice(0, 20).join(', ') + (s.pending.length > 20 ? ', ...' : '') + '\n');
    }
    if (servers.some((s) => s.pending.length)) {
      process.stdout.write('\nReview what changed, then accept it with: zn-gate pins approve <server>\n');
    }
    return 0;
  }
  if (sub === 'approve') {
    if (!which) {
      process.stderr.write('usage: zn-gate pins approve <server>|--all\n');
      return 2;
    }
    if (!process.stdin.isTTY || !process.stderr.isTTY) {
      process.stderr.write('zn-gate pins approve runs only in your own terminal, so that an agent cannot approve tool changes. Run it there.\n');
      return 2;
    }
    const expected = which === '--all' ? 'all' : which;
    const typed = await ask('Type ' + (which === '--all' ? '"all"' : 'the server key') + ' again to approve: ');
    if (typed !== expected) {
      process.stderr.write('Not approved.\n');
      return 2;
    }
    const r = pins.approve(which);
    if (r.error) {
      process.stderr.write('zn-gate pins: ' + r.error + '. Run zn-gate pins to see the servers and their full keys.\n');
      return 2;
    }
    if (!r.approved.length) {
      process.stdout.write('Nothing to approve.\n');
      return 0;
    }
    for (const a of r.approved) process.stdout.write('Approved ' + a.tools.join(', ') + ' of ' + a.command + '\n');
    return 0;
  }
  process.stderr.write('usage: zn-gate pins [list] | zn-gate pins approve <server>|--all\n');
  return 2;
}

module.exports = { run };
