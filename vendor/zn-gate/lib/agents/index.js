'use strict';

/**
 * Agent adapter registry. Each adapter implements
 *   {id, detect(), install({scope}), uninstall(), normalize(raw), respond(decision)}
 */

const ADAPTERS = {
  'claude-code': () => require('./claude-code'),
  codex: () => require('./codex'),
  cursor: () => require('./cursor'),
  opencode: () => require('./opencode'),
  antigravity: () => require('./antigravity'),
  copilot: () => require('./copilot'),
  gemini: () => require('./gemini'),
  zcode: () => require('./zcode'),
};

const ALIASES = { claude: 'claude-code', claudecode: 'claude-code', 'gemini-cli': 'gemini', geminicli: 'gemini', 'z.ai': 'zcode', zai: 'zcode' };

const has = (obj, key) => Object.hasOwn(obj, key);

/** The agent id as it is safe to echo: control, format (incl. bidi overrides), line and paragraph separator and lone surrogate characters removed. */
function cleanId(id) {
  return String(id === undefined || id === null ? '' : id).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu, '');
}

function getAdapter(id) {
  const lower = String(id || '').toLowerCase();
  const key = has(ALIASES, lower) ? ALIASES[lower] : lower;
  if (!has(ADAPTERS, key)) {
    throw new Error('unknown agent "' + cleanId(id) + '" (supported: ' + Object.keys(ADAPTERS).join(', ') + ')');
  }
  return ADAPTERS[key]();
}

// Agents zn has no hooks for yet (display name by the name people type). None today:
// GitHub Copilot CLI got its adapter, so it is listed in ADAPTERS.
const NOT_COVERED = {};

function distance(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/** One plain sentence when `id` is not an agent zn can install hooks for, or null when it is. */
function unsupportedAgentMessage(id) {
  const key = String(id || '').toLowerCase();
  if (has(ALIASES, key) || has(ADAPTERS, key)) return null;
  const supported = 'Supported agents: ' + Object.keys(ADAPTERS).join(', ') + '.';
  if (has(NOT_COVERED, key)) return 'zn hooks are not available for ' + NOT_COVERED[key] + ' yet. ' + supported;
  let best = null;
  let bestD = 3;
  for (const name of [...Object.keys(ADAPTERS), ...Object.keys(ALIASES)]) {
    const d = distance(key, name);
    if (d < bestD) { best = name; bestD = d; }
  }
  return 'unknown agent "' + cleanId(id) + '".' + (best ? ' Did you mean "' + best + '"?' : '') + ' ' + supported;
}

function listAdapters() {
  return Object.keys(ADAPTERS);
}

module.exports = { getAdapter, listAdapters, unsupportedAgentMessage, AGENT_IDS: Object.freeze(Object.keys(ADAPTERS)) };
