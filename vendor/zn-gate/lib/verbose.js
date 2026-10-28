'use strict';
/* One rule for "show technical detail": ZN_VERBOSE=1, or a DEBUG value that names zn
 * (entries split on commas or spaces: zn, zn*, zn:*, zn-gate, zn-gate:*). A bare DEBUG=* or
 * DEBUG=express:*, set by other tools, does not turn it on. */
function isVerbose(env = process.env) {
  if (env.ZN_VERBOSE === '1') return true;
  const debug = typeof env.DEBUG === 'string' ? env.DEBUG : '';
  return debug.split(/[\s,]+/).some((entry) => /^(zn|zn-gate)(\*|:.*)?$/.test(entry));
}

module.exports = { isVerbose };
