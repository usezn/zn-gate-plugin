'use strict';

// The tools of zn's own "secrets" MCP server (lib/broker/mcp.js). A hook treats a call as going to zn's server only
// when the tool is exactly one of these: a server named "secrets_" or "secrets__x" sends names such as
// mcp__secrets___secrets_list or mcp__secrets__x__secrets_list, which a host's split reads as server "secrets" and
// a tool that is not in this list. Kept small so the hooks can load it without the server.
// test/secrets_tool_names.test.js keeps it equal to the TOOLS of lib/broker/mcp.js.
const SECRETS_TOOL_NAMES = Object.freeze(['secrets_list', 'secrets_http_request', 'secrets_render_file', 'secrets_request']);

/** Whether a tool name is one of zn's secrets server tools, exactly. */
function isSecretsToolName(tool) {
  return typeof tool === 'string' && SECRETS_TOOL_NAMES.includes(tool);
}

module.exports = { SECRETS_TOOL_NAMES, isSecretsToolName };
