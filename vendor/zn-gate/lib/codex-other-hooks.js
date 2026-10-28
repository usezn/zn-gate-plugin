'use strict';

/*
 * Other tools' Codex hooks that run before a call or before an approval prompt.
 *
 * Codex runs every matching PreToolUse hook at the same time, each with the original call. A hook that
 * answers "allow" together with a new input changes the call after zn looked at it, and a hook that answers
 * "allow" to a PermissionRequest can remove the approval prompt. zn cannot see what another hook does, so
 * `zn-gate check` reports that such a hook exists. Background (`async`) hooks cannot change a call and are
 * left out; so are zn's own hooks.
 */

const path = require('path');

const EVENTS = new Set(['PreToolUse', 'PermissionRequest']);
// The tools zn's Codex hooks match: the shell tool, patches and MCP calls.
const ZN_TOOLS = ['Bash', 'apply_patch', 'mcp__server__tool'];
const CAP = 256 * 1024;

function matches(matcher) {
  if (matcher === undefined || matcher === null || matcher === '' || matcher === '*') return true;
  return ZN_TOOLS.some((tool) => {
    try { return new RegExp('^(?:' + matcher + ')$').test(tool); } catch (_) { return String(matcher).split('|').includes(tool); }
  });
}

function isBackground(h) {
  return h.async === true || h.async === 'true';
}

/* Commands of the hooks in one parsed hooks tree ({hooks: {Event: [{matcher, hooks: [{command}]}]}}). */
function entriesOf(tree) {
  const out = [];
  const hooks = tree && typeof tree === 'object' && tree.hooks && typeof tree.hooks === 'object' ? tree.hooks : {};
  for (const [event, list] of Object.entries(hooks)) {
    if (!EVENTS.has(event) || !Array.isArray(list)) continue;
    for (const g of list) {
      if (!g || typeof g !== 'object') continue;
      const hs = Array.isArray(g.hooks) ? g.hooks : [];
      for (const h of typeof g.command === 'string' ? [g, ...hs] : hs) {
        if (h && typeof h === 'object' && typeof h.command === 'string') out.push({ event, matcher: g.matcher, command: h.command, async: h.async });
      }
    }
  }
  return out;
}

function parsedFile(file) {
  const { readBounded } = require('./audit')._internal;
  const r = readBounded(file, CAP, false);
  if (typeof r.text !== 'string') return null;
  try {
    return file.endsWith('.toml') ? require('./audit/parse').parseToml(r.text).data : JSON.parse(r.text.replace(/^\uFEFF/, ''));
  } catch (_) {
    return null;
  }
}

/*
 * The first hook of another tool that could change a call or answer an approval, in the Codex folder
 * (hooks.json, config.toml) and in the project's .codex folder; null if none.
 * Returns { file, event }.
 */
function findOtherHooks(codexHome, projectDir) {
  const { isOurs } = require('./agents/config-file');
  const files = [path.join(codexHome, 'hooks.json'), path.join(codexHome, 'config.toml')];
  if (projectDir) {
    const proj = [path.join(projectDir, '.codex', 'hooks.json'), path.join(projectDir, '.codex', 'config.toml')];
    for (const f of proj) if (!files.some((x) => path.resolve(x) === path.resolve(f))) files.push(f);
  }
  for (const file of files) {
    const hit = entriesOf(parsedFile(file)).find((e) => !isOurs(e.command, 'codex') && !isBackground(e) && matches(e.matcher));
    if (hit) return { file, event: hit.event };
  }
  return null;
}

module.exports = { findOtherHooks, _internal: { entriesOf, matches } };
