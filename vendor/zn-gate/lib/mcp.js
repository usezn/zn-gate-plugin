'use strict';

const readline = require('readline');
const { analyze, analyzeLocal, checkToolResult, isCloudEnabled, RULES_VERSION, resolveEndpoint } = require('./client');
const { sanitizeToolResult } = require('./rules');

const SERVER_NAME = 'zn-gate';
let SERVER_VERSION = '1.6.0';
try {
  SERVER_VERSION = require('../package.json').version || '1.6.0';
} catch (_) {}
const PROTOCOL_VERSION = '2024-11-05';

function sendJsonRpc(response) {
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
    description: 'Analyze text, prompt, or agent messages for security threats (prompt injection, jailbreak, credential exfiltration, role hijacking). Runs locally; only if the user set ZN_CLOUD=1 and ZN_API_KEY is the text, with secrets redacted, also sent to the zn cloud gate. Returns threat assessment, confidence score, and matched rule.',
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'The user input, system prompt, or external message to inspect.',
        },
      },
      required: ['text'],
    },
  },
  {
    name: 'check_tool_call',
    annotations: { title: 'Check a tool call before it runs', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Pre-flight safety inspection for tool invocations and arguments before execution. Always local: arguments never leave the machine. Defends against tool poisoning, argument injection, and unauthorized exfiltration attempts.',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'The name of the tool to be called (e.g. bash, write_file, execute_sql, send_message).',
        },
        arguments: {
          type: 'object',
          description: 'Parameters/payload object that will be supplied to the tool.',
        },
      },
      required: ['tool_name', 'arguments'],
    },
  },
  {
    name: 'check_tool_result',
    annotations: { title: 'Check a tool result before the model reads it', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Post-execution safety inspection for tool outputs and third-party content (web pages, git commits, database queries) before LLM context assimilation. Always local: content never leaves the machine. Returns the content with secrets redacted, or neutralized if an injection is detected.',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'The name of the tool that produced the output (e.g. fetch, web_search, read_file).',
        },
        content: {
          type: 'string',
          description: 'The output text, markdown, or JSON payload returned by the tool.',
        },
      },
      required: ['tool_name', 'content'],
    },
  },
  {
    name: 'zn_status',
    annotations: { title: 'zn-gate status', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Get current zn-gate status: engine, rules version, and exactly what (if anything) leaves the machine.',
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
      return sendResult(id, {
        protocolVersion: PROTOCOL_VERSION,
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
        tools: toolsFor(options),
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
          endpoint: cloud ? resolveEndpoint(options) : 'none (local only)',
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

      return sendError(id, -32601, `Method or tool '${toolName}' not found`);
    }

    default: {
      if (id !== undefined) {
        return sendError(id, -32601, `Unsupported method: ${method}`);
      }
    }
  }
}

function startMcpServer(options = {}) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  if (process.env.DEBUG || process.env.ZN_VERBOSE) {
    process.stderr.write(`[zn-gate] MCP server listening on stdio (engine: ${isCloudEnabled(options) ? 'local + cloud for analyze_prompt' : 'local only'})...\n`);
  }

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const message = JSON.parse(trimmed);
      await handleRequest(message, options);
    } catch (err) {
      if (process.env.DEBUG) {
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
  SERVER_NAME,
  SERVER_VERSION,
  PROTOCOL_VERSION,
};
