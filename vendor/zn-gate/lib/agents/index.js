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
};

const ALIASES = { claude: 'claude-code', claudecode: 'claude-code' };

function getAdapter(id) {
  const key = ALIASES[String(id || '').toLowerCase()] || String(id || '').toLowerCase();
  const load = ADAPTERS[key];
  if (!load) {
    throw new Error('unknown agent "' + id + '" (supported: ' + Object.keys(ADAPTERS).join(', ') + ')');
  }
  return load();
}

function listAdapters() {
  return Object.keys(ADAPTERS);
}

module.exports = { getAdapter, listAdapters };
