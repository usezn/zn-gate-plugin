'use strict';

/**
 * Lazy loading of the scrubber engine and the vault client.
 *
 * Hooks, the broker and the CLI never require lib/scrub or lib/vault at the
 * top level: callers receive {engine, vault} as parameters (tests inject
 * in-memory doubles) and production code loads the real modules here, on
 * first use. A missing module surfaces as a ZN_UNAVAILABLE error instead of
 * a crash at require time.
 */

const fs = require('fs');
const path = require('path');

function znError(code, message, extra) {
  const err = new Error(message);
  err.code = code;
  if (extra) Object.assign(err, extra);
  return err;
}

function isMissing(err, rel) {
  return err && err.code === 'MODULE_NOT_FOUND' &&
    String(err.message).replace(/\\/g, '/').includes(rel);
}

function loadEngine() {
  let mod;
  try {
    mod = require('./scrub/engine');
  } catch (err) {
    if (isMissing(err, 'scrub/engine')) {
      throw znError('ZN_UNAVAILABLE', 'scrubber engine is not installed (lib/scrub/engine.js)');
    }
    throw err;
  }
  if (!mod || typeof mod.tokenize !== 'function') {
    throw znError('ZN_UNAVAILABLE', 'scrubber engine does not export tokenize()');
  }
  return mod;
}

async function loadVault() {
  let mod;
  try {
    mod = require('./vault/client');
  } catch (err) {
    if (isMissing(err, 'vault/client')) {
      const { znCommand } = require('./zn-command');
      throw znError('ZN_LOCKED', 'secret vault is not available. Unlock it in your terminal with: ' + znCommand('unlock'));
    }
    throw err;
  }
  if (mod && typeof mod.createClient === 'function') return await mod.createClient();
  if (mod && typeof mod.connect === 'function') return await mod.connect();
  return mod;
}

/** Root of the project that contains `dir`: nearest parent with .git, else dir. */
function findProjectRoot(dir) {
  let cur = path.resolve(dir || process.cwd());
  for (;;) {
    if (fs.existsSync(path.join(cur, '.git'))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) return path.resolve(dir || process.cwd());
    cur = parent;
  }
}

module.exports = { znError, loadEngine, loadVault, findProjectRoot };
