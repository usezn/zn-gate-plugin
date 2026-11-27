'use strict';

// How deep the hooks read the arguments of a tool they do not know. The path scan (agents/copilot.js) and the text scan
// (hooks/runner.js) share this limit, so a path is never found where the text next to it is skipped silently.
const MAX_NEST_DEPTH = 6;

// Most objects one path scan visits; past it the call is refused, never passed.
const MAX_NEST_NODES = 500;

module.exports = { MAX_NEST_DEPTH, MAX_NEST_NODES };
