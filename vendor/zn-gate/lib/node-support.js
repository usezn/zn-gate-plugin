'use strict';

/* Which Node.js versions still get security fixes. This is the one place that lists them: when the Node.js
   project ships another security release, change PATCHED_MINIMUM (and EOL_BELOW when a line reaches end of life).
   `zn-gate check` and `zn-gate status` only warn from it; they never block or change an exit code. */

// The first patched release of each supported even-numbered line (Node.js security releases of 21 Oct 2026).
const PATCHED_MINIMUM = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' };
// Even-numbered lines below this one are end-of-life (18 and 20 today). Odd-numbered lines are never judged.
const EOL_BELOW = 22;
const ADVISORY_URL = 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases';

function parse(version) {
  if (typeof version !== 'string') return null;
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function atLeast(have, want) {
  for (let i = 0; i < 3; i++) {
    if (have[i] !== want[i]) return have[i] > want[i];
  }
  return true;
}

/* nodeAdvice('20.19.0') -> null when there is nothing to say (patched, odd-numbered line, newer line, or a
   version it cannot read); otherwise {level: 'eol' | 'outdated', version, minimum, message}. Pure. */
function nodeAdvice(version) {
  const v = parse(version);
  if (!v) return null;
  const major = v[0];
  const shown = v.join('.');
  const patched = Object.values(PATCHED_MINIMUM).join(', ');
  if (major % 2 === 0 && major < EOL_BELOW) {
    const minimum = PATCHED_MINIMUM[EOL_BELOW];
    return {
      level: 'eol', version: shown, minimum,
      message: 'Node.js ' + shown + ' is end-of-life and no longer gets security fixes. Update to Node.js ' + minimum + ' or later (the patched releases are ' + patched + '): ' + ADVISORY_URL,
    };
  }
  const minimum = PATCHED_MINIMUM[major];
  if (minimum && !atLeast(v, parse(minimum))) {
    return {
      level: 'outdated', version: shown, minimum,
      message: 'Node.js ' + shown + ' has known security issues that Node.js ' + minimum + ' fixes. Update to Node.js ' + minimum + ' or later: ' + ADVISORY_URL,
    };
  }
  return null;
}

module.exports = { nodeAdvice, PATCHED_MINIMUM, EOL_BELOW, ADVISORY_URL };
