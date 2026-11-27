'use strict';

/**
 * True when the hardening flag `name` (ZN_STRICT, ZN_BLOCK_TRUNCATED) is set to "1", the only value that turns it
 * on. Any other value (true, yes, on...) leaves it off, so it is said once on stderr rather than ignored silently.
 * Same rule and wording as env_flag in the Python package. Never writes to stdout: hooks talk JSON there.
 */
const warned = new Set();

function envFlag(name) {
  const value = process.env[name];
  if (value === '1') return true;
  if (value !== undefined && value !== '' && value !== '0') {
    const key = name + '\0' + value;
    if (!warned.has(key)) {
      warned.add(key);
      try {
        process.stderr.write(`zn_gate: ${name} is set to '${value.slice(0, 20)}', but only ${name}=1 turns it on, so it is off\n`);
      } catch (_) { /* a closed stderr must not change a verdict */ }
    }
  }
  return false;
}

module.exports = { envFlag, _warned: warned };
