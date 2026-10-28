'use strict';

/**
 * An agent whose hooks cannot ask the user (or whose "ask" the agent does not enforce) must not get a silent "no
 * opinion" for a call zn wanted to confirm: that would let the call run. zn blocks it instead, with the reason and
 * the way to approve it. Used by the Codex, Cursor (preToolUse, MCP and read hooks), OpenCode and Gemini adapters.
 */
function askAsDeny(agentName, d) {
  const why = (d && d.message) || 'zn needs your confirmation for this action.';
  return why + ' ' + agentName + ' cannot show that question, so zn blocked the action instead. ' +
    'Next step: tell the user exactly what was blocked and why. If the user approves it, they can run it themselves outside the agent, ' +
    'or ask you to try again after they have changed what zn objected to; do not retry the same action on your own.';
}

/**
 * The decision is a question that this agent cannot show. Not counted: a rewrite proposal (updatedInput), and a
 * "soft" ask, which only shows the user a reason while the action stays safe without the answer (a command already
 * wrapped in `zn run`, whose approval the vault asks for itself, or a write that keeps its markers). A real question
 * merged into a rewrite proposal or a soft ask carries confirm: true and is always a plain ask.
 */
function isPlainAsk(d) {
  return Boolean(d) && d.decision === 'ask' && (d.confirm === true || (!d.updatedInput && !d.soft));
}

module.exports = { askAsDeny, isPlainAsk };
