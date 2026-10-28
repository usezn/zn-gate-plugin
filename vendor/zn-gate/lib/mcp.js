'use strict';

const readline = require('readline');
const { analyze, analyzeLocal, checkToolResult, isCloudEnabled, RULES_VERSION, resolveEndpoint, usesStoredKey } = require('./client');
const { sanitizeToolResult } = require('./rules');

const SERVER_NAME = 'zn-gate';
let SERVER_VERSION = '1.6.0';
try {
  SERVER_VERSION = require('../package.json').version || '1.6.0';
} catch (_) {}
const { AsyncLocalStorage } = require('async_hooks');
const proto = require('./mcp-protocol');
const { isVerbose } = require('./verbose');

const PROTOCOL_VERSION = proto.LATEST_PROTOCOL_VERSION;
// Version agreed in initialize (one client per stdio process); until then the latest.
let negotiated = null;
// Replies of a JSON-RPC batch are collected here instead of being written one by one.
const batchSink = new AsyncLocalStorage();

function sendJsonRpc(response) {
  const sink = batchSink.getStore();
  if (sink) { sink.push(response); return; }
  process.stdout.write(JSON.stringify(response) + '\n');
}

function sendResult(id, result) {
  sendJsonRpc({
    jsonrpc: '2.0',
    id,
    result,
  });
}

function sendError(id, code, message, data) {
  sendJsonRpc({
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      ...(data !== undefined ? { data } : {}),
    },
  });
}

const TOOLS = [
  {
    name: 'analyze_prompt',
    annotations: { title: 'Check text for prompt injection', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Check a piece of text for prompt injection, jailbreak attempts, role hijacking and attempts to steal credentials. Use it on a user message, system prompt or message from another agent that should be checked before you act on it. The check runs on this computer. Only if the user has turned on the optional cloud check (ZN_CLOUD=1 with ZN_API_KEY, or zn-gate connect) is the text, with secrets removed, also sent to the zn cloud. Returns a verdict (allow or block), a confidence score and the rule that matched. Example input: {"text": "Summarize the meeting notes below."}',
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'The full text to check: a user message, a system prompt, or a message from another agent or tool. Send the whole text, not a summary. Text is checked as-is; a missing or non-text value is treated as empty.',
        },
      },
      required: ['text'],
    },
  },
  {
    name: 'check_tool_call',
    annotations: { title: 'Check a tool call before it runs', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Check a tool call before it runs. Call it with the tool name and its arguments right before the agent executes the tool, for example a shell command, a file write, a database query or a message to send. It runs the local rules on the arguments and looks for injected instructions, sensitive file paths and links that would send data out. It does not judge whether a command is destructive. Nothing leaves the computer. Returns safe_to_execute, the verdict (allow or block) and the arguments with sensitive values hidden. Example input: {"tool_name": "write_file", "arguments": {"path": "notes.txt", "content": "hello"}}',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'The name of the tool the agent is about to run, exactly as the agent calls it (for example bash, write_file, execute_sql or send_message).',
        },
        arguments: {
          type: 'object',
          description: 'The arguments the agent will pass to the tool, as a JSON object (for example {"command": "ls -la"}). Send exactly what the tool would receive. Nested objects and arrays are fine.',
        },
      },
      required: ['tool_name', 'arguments'],
    },
  },
  {
    name: 'check_tool_result',
    annotations: { title: 'Check a tool result before the model reads it', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Check the output of a tool before the model reads it. Call it on content that came from outside: web pages, search results, file contents, git commits, database query results and API responses. It looks for hidden instructions aimed at the model (indirect prompt injection) and for secrets such as API keys. Nothing leaves the computer. Returns the content with secrets redacted, or neutralized if an injection is found, plus the verdict. Example input: {"tool_name": "web_search", "content": "Search results here"}',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'The name of the tool that produced this output, for example fetch, web_search or read_file. It labels the result; it is not a permission list.',
        },
        content: {
          type: 'string',
          description: 'The output the tool returned, as text. Markdown and JSON are fine. Send the whole output, since a partial check can miss an injection placed at the end. Structured values are also accepted and are checked as their JSON text.',
        },
      },
      required: ['tool_name', 'content'],
    },
  },
  {
    name: 'zn_status',
    annotations: { title: 'zn-gate status', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Report the current zn-gate status: the detection engine, the rules version, and whether anything leaves this computer (and if so, what). Call it when the user asks what zn-gate is doing or whether their data is shared. It takes no arguments and changes nothing. Example: call it with no arguments.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

/* With the optional cloud check on (ZN_CLOUD=1 and an API key), analyze_prompt sends text to the zn cloud gate. */
function toolsFor(options) {
  const cloud = isCloudEnabled(options);
  return TOOLS.map((t) => (t.name === 'analyze_prompt' && cloud ? { ...t, annotations: { ...t.annotations, openWorldHint: true } } : t));
}

async function handleRequest(message, options) {
  const { id, method, params } = message;

  switch (method) {
    case 'initialize': {
      negotiated = proto.negotiateProtocolVersion(params);
      return sendResult(id, {
        protocolVersion: negotiated,
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: SERVER_NAME,
          version: SERVER_VERSION,
        },
      });
    }

    case 'notifications/initialized': {
      return;
    }

    case 'ping': {
      return sendResult(id, {});
    }

    case 'tools/list': {
      return sendResult(id, {
        tools: proto.toolsForVersion(toolsFor(options), negotiated),
      });
    }

    case 'tools/call': {
      // Local counts for `zn-gate stats` (best effort).
      function countMcp({ blocked = false, redacted = 0, detections = [] }) {
        const types = {};
        for (const d of detections) {
          const t = String(d && d.rule || '').replace(/^secret:/, '');
          if (t) types[t] = (types[t] || 0) + 1;
        }
        require('./stats').record({
          layer: 'mcp', agent: options.agent || 'mcp-client', checked: 1, blocked: blocked ? 1 : 0,
          redacted: redacted || detections.length, detections: types,
        });
      }
      if (!params || typeof params.name !== 'string') {
        return sendError(id, -32602, 'Invalid params: name is required');
      }

      const toolName = params.name;
      const args = params.arguments || {};

      if (toolName === 'analyze_prompt') {
        const text = typeof args.text === 'string' ? args.text : '';
        const assessment = await analyze(text, options);
        const isBlock = assessment.verdict?.toLowerCase() === 'block';
        countMcp({ blocked: isBlock });

        return sendResult(id, {
          isError: isBlock,
          content: [
            {
              type: 'text',
              text: JSON.stringify(assessment, null, 2),
            },
          ],
        });
      }

      if (toolName === 'check_tool_call') {
        const targetTool = String(args.tool_name || 'unknown');
        const toolArgs = args.arguments || {};

        const stringValues = [];
        function extractStrings(obj) {
          if (typeof obj === 'string') stringValues.push(obj);
          else if (Array.isArray(obj)) obj.forEach(extractStrings);
          else if (obj && typeof obj === 'object') Object.values(obj).forEach(extractStrings);
        }
        extractStrings(toolArgs);

        // Local only: tool-call arguments never leave the machine.
        let worstAssessment = analyzeLocal(`${targetTool}: ${JSON.stringify(toolArgs)}`, options);
        let isBlock = worstAssessment.verdict?.toLowerCase() === 'block';

        if (!isBlock) {
          for (const str of stringValues) {
            if (str.length >= 4) {
              const subRes = analyzeLocal(str, options);
              if (subRes.verdict?.toLowerCase() === 'block') {
                worstAssessment = subRes;
                isBlock = true;
                break;
              }
              if (!worstAssessment.advisory && subRes.advisory) {
                worstAssessment = { ...worstAssessment, advisory: { ...subRes.advisory } };
              }
            }
          }
        }

        const { sanitized: sanitizedArgs, detections } = sanitizeToolResult(toolArgs);
        countMcp({ blocked: isBlock, detections });

        const output = {
          tool_name: targetTool,
          safe_to_execute: !isBlock,
          assessment: worstAssessment,
          secrets_redacted: detections.length,
          sanitized_arguments: sanitizedArgs,
        };

        return sendResult(id, {
          isError: isBlock,
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2),
            },
          ],
        });
      }

      if (toolName === 'check_tool_result') {
        const targetTool = String(args.tool_name || 'unknown');
        const rawContent = args.content !== undefined ? (typeof args.content === 'string' ? args.content : JSON.stringify(args.content)) : '';

        const output = await checkToolResult(targetTool, rawContent, options);
        countMcp({ blocked: !output.safe_to_ingest, redacted: output.secrets_redacted || 0 });

        return sendResult(id, {
          isError: !output.safe_to_ingest,
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2),
            },
          ],
        });
      }

      if (toolName === 'zn_status') {
        const cloud = isCloudEnabled(options);
        const status = {
          package: `${SERVER_NAME}@${SERVER_VERSION}`,
          engine: cloud ? 'local-rules + cloud (analyze_prompt only)' : 'local-rules',
          endpoint: cloud ? resolveEndpoint(options, { stored: usesStoredKey(options) }) : 'none (local only)',
          rules_version: RULES_VERSION,
          cloud_enabled: cloud,
          leaves_machine: cloud
            ? 'analyze_prompt text only, with secrets redacted locally before sending. Tool results and tool-call arguments never leave the machine.'
            : 'nothing',
          lifecycle_coverage: 'bidirectional (prompt, pre-tool-call, post-tool-result)',
        };
        return sendResult(id, {
          content: [
            {
              type: 'text',
              text: JSON.stringify(status, null, 2),
            },
          ],
        });
      }

      return sendError(id, proto.unknownToolCode(negotiated), `Method or tool '${toolName}' not found`);
    }

    default: {
      if (id !== undefined) {
        return sendError(id, -32601, `Unsupported method: ${method}`);
      }
    }
  }
}

/* Batches exist only in 2025-03-26 (added there, removed in 2025-06-18); other versions are rejected. The replies go back as one array. */
async function handleBatch(messages, options) {
  if (!proto.allowsBatching(negotiated) || messages.length === 0) {
    return sendError(null, proto.BATCH_REJECTED.code, proto.BATCH_REJECTED.message);
  }
  const replies = [];
  await batchSink.run(replies, async () => {
    for (const m of messages) {
      try {
        await handleRequest(m || {}, options);
      } catch (err) {
        sendError(m && m.id !== undefined ? m.id : null, -32603, 'Internal error');
      }
    }
  });
  if (replies.length) process.stdout.write(JSON.stringify(replies) + '\n');
}

function startMcpServer(options = {}) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  if (isVerbose()) {
    process.stderr.write(`[zn-gate] MCP server listening on stdio (engine: ${isCloudEnabled(options) ? 'local + cloud for analyze_prompt' : 'local only'})...\n`);
  }

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const message = JSON.parse(trimmed);
      if (Array.isArray(message)) {
        await handleBatch(message, options);
        return;
      }
      await handleRequest(message, options);
    } catch (err) {
      if (isVerbose()) {
        process.stderr.write(`[zn-gate] JSON-RPC parse error: ${err.message}\n`);
      }
      sendJsonRpc({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32700,
          message: 'Parse error',
          data: err.message,
        },
      });
    }
  });

  rl.on('close', () => {
    process.exit(0);
  });
}

module.exports = {
  TOOLS,
  toolsFor,
  startMcpServer,
  handleRequest,
  handleBatch,
  SERVER_NAME,
  SERVER_VERSION,
  PROTOCOL_VERSION,
};
