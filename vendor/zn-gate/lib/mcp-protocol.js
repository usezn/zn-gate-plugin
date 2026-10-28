'use strict';

// MCP protocol versions the local servers (`zn-gate mcp` and `zn-gate secrets-mcp`) speak, and what changes on
// the wire for a stdio server between them. Spec changelogs:
//   2025-03-26  https://modelcontextprotocol.io/specification/2025-03-26/changelog  (batching added, tool annotations)
//   2025-06-18  https://modelcontextprotocol.io/specification/2025-06-18/changelog  (batching removed, tool `title`, structured output)
//   2025-11-25  https://modelcontextprotocol.io/specification/2025-11-25/changelog  (tasks, icons, input validation errors as tool results; nothing zn needs to change)
// Versions are ISO dates, so string comparison orders them.

const SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

/** The version to answer initialize with: the client's if supported, else the latest (the client then decides). */
function negotiateProtocolVersion(params) {
  const asked = params && params.protocolVersion;
  return typeof asked === 'string' && SUPPORTED_PROTOCOL_VERSIONS.includes(asked) ? asked : LATEST_PROTOCOL_VERSION;
}

/** JSON-RPC batching exists only in 2025-03-26: added there, removed in 2025-06-18 (2024-11-05 has none). */
function allowsBatching(version) {
  return version === '2025-03-26';
}

/**
 * Error code for tools/call with an unknown tool. The 2025-06-18 and 2025-11-25 tools pages give -32602 ("Unknown
 * tool") as the protocol error. Older versions, and a client that has not sent initialize yet, keep -32601.
 */
function unknownToolCode(version) {
  return version && version >= '2025-06-18' ? -32602 : -32601;
}

/** The tool definitions as valid for the negotiated version: annotations arrived in 2025-03-26, `title` in 2025-06-18. */
function toolsForVersion(tools, version) {
  const v = version || LATEST_PROTOCOL_VERSION;
  return tools.map((t) => {
    const { annotations, ...rest } = t;
    if (v < '2025-03-26') return rest;
    if (v < '2025-06-18') return t;
    return annotations && annotations.title ? { name: t.name, title: annotations.title, ...rest, annotations } : t;
  });
}

const BATCH_REJECTED = { code: -32600, message: 'Invalid Request: JSON-RPC batches are not supported from MCP 2025-06-18' };

module.exports = {
  SUPPORTED_PROTOCOL_VERSIONS,
  LATEST_PROTOCOL_VERSION,
  negotiateProtocolVersion,
  allowsBatching,
  unknownToolCode,
  toolsForVersion,
  BATCH_REJECTED,
};
