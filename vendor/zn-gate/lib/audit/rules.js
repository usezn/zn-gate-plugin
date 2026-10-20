'use strict';
/**
 * Rule catalogue of `zn audit`. Ids are stable: a rule may improve, but an id
 * never changes meaning and is never reused. `severity` is the highest
 * severity the rule can report (SARIF `security-severity` is per rule).
 */

// Version of the rule catalogue and of the command patterns in audit/patterns.js.
// Bump it when a rule, a pattern or a rule id changes; see CONTRIBUTING.md.
const AUDIT_RULES_VERSION = '2026-10-17.1';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const RANK = { none: 99, low: 1, medium: 2, high: 3, critical: 4 };
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };

const CVE = {
  claudeBaseUrl: 'CVE-2026-21852',
  amazonqMcp: 'CVE-2026-12957',
  codexMcp: 'CVE-2025-61260',
  cursorHooks: 'CVE-2026-48124',
  cursorGit: 'CVE-2026-63093',
};

const RULES = [
  {
    id: 'ZNA001', severity: 'high', name: 'auto-run-command',
    title: 'Command runs automatically from a project config',
    help: 'Hooks, status lines, notify commands, editor tasks that run on folder open and agent plugin files run with your user rights as soon as an agent acts on the file, and some agent versions ran them without asking.',
    fix: 'Remove the command from the repository, or review it and keep it only in your own user settings.',
    references: [CVE.cursorHooks],
  },
  {
    id: 'ZNA002', severity: 'critical', name: 'download-and-run',
    title: 'Automatic command downloads code and runs it',
    help: 'A command that pipes a download into a shell or interpreter runs whatever the remote server returns at that moment, which can change after review.',
    fix: 'Remove the command. If the tool is needed, install a pinned version and verify its checksum.',
    references: [CVE.cursorHooks, CVE.amazonqMcp, CVE.codexMcp],
  },
  {
    id: 'ZNA003', severity: 'high', name: 'project-mcp-command',
    title: 'Project MCP server starts a local command',
    help: 'A project MCP server runs a command with your environment, credentials included. Agents ask before starting it, but vulnerable versions did not (Amazon Q, Codex).',
    fix: 'Check the command and its package before approving the server; prefer pinned versions, or move the server to your user config.',
    references: [CVE.amazonqMcp, CVE.codexMcp],
  },
  {
    id: 'ZNA004', severity: 'high', name: 'mcp-auto-approve',
    title: 'Project settings approve MCP servers in advance',
    help: '`enableAllProjectMcpServers` and `enabledMcpjsonServers` in a project file remove the prompt that asks you before a repository MCP server starts.',
    fix: 'Remove the setting from the project file and approve servers one by one.',
    references: [],
  },
  {
    id: 'ZNA005', severity: 'medium', name: 'unpinned-package',
    title: 'MCP server or agent plugin package is not pinned',
    help: 'Without an exact version the code that runs changes each time the package is published again; a compromised release reaches you on the next start.',
    fix: 'Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...).',
    references: [],
  },
  {
    id: 'ZNA006', severity: 'medium', name: 'remote-mcp',
    title: 'Remote MCP server or remote instructions',
    help: 'Tool calls and their content go to a third-party server. Over plain http anyone on the network path can read and change them.',
    fix: 'Use https and a server you trust; keep remote instructions out of the repository.',
    references: [],
  },
  {
    id: 'ZNA007', severity: 'critical', name: 'endpoint-override',
    title: 'Model API endpoint overridden by the project',
    help: 'A base URL or proxy set by the repository sends your API key and every prompt to that server.',
    fix: 'Remove the override from the project; set it in your user settings if you use a gateway.',
    references: [CVE.claudeBaseUrl, CVE.codexMcp],
  },
  {
    id: 'ZNA008', severity: 'high', name: 'code-loading-env',
    title: 'Environment variable that loads code or certificates',
    help: 'Variables such as NODE_OPTIONS, LD_PRELOAD, PATH or NODE_EXTRA_CA_CERTS make every process the agent starts load injected code or trust an injected certificate.',
    fix: 'Remove the variable from the project config.',
    references: [CVE.codexMcp],
  },
  {
    id: 'ZNA009', severity: 'high', name: 'credential-helper',
    title: 'Credential helper command in project settings',
    help: 'apiKeyHelper and the other helpers run a command to produce the credentials the agent uses.',
    fix: 'Remove the helper from the project file; configure it in your user settings.',
    references: [CVE.claudeBaseUrl],
  },
  {
    id: 'ZNA010', severity: 'high', name: 'broad-permissions',
    title: 'Agent permissions allow any command without a prompt',
    help: 'Wildcard shell permissions, interpreter wildcards, bypass modes and auto-approval let the agent run anything an injected instruction asks for.',
    fix: 'Allow specific commands (for example Bash(npm test)) instead of wildcards, and keep prompts on.',
    references: [],
  },
  {
    id: 'ZNA011', severity: 'high', name: 'secret-in-config',
    title: 'Secret value in an agent file',
    help: 'Credentials committed with agent configs leak with the repository. The value is never printed in the report.',
    fix: 'Revoke the secret, remove it from the file and its history, and reference it from the environment or a secret store.',
    references: [],
  },
  {
    id: 'ZNA012', severity: 'high', name: 'instruction-injection',
    title: 'Prompt-injection pattern in agent instructions',
    help: 'Agents read instruction files as trusted guidance. Overrides, fake system tags, hidden text and image beacons there steer the agent.',
    fix: 'Remove the text, or rewrite it so it reads as documentation rather than an instruction to the agent.',
    references: [],
  },
  {
    id: 'ZNA013', severity: 'medium', name: 'instruction-download-run',
    title: 'Instructions tell the agent to download and run code',
    help: 'An agent that follows the instruction runs whatever the URL serves.',
    fix: 'Pin the tool and its checksum, or document the install for people rather than for the agent.',
    references: [],
  },
  {
    id: 'ZNA014', severity: 'high', name: 'instruction-exfiltration',
    title: 'Instructions tell the agent to send secrets or files out',
    help: 'Instructions that send .env files, keys, tokens or the environment to a URL turn the agent into the exfiltration channel.',
    fix: 'Remove the instruction and check who added it.',
    references: [],
  },
  {
    id: 'ZNA015', severity: 'medium', name: 'instruction-weaken-checks',
    title: 'Instructions tell the agent to skip safety checks or hide actions',
    help: 'Skipping hooks, permission prompts or the sandbox, or keeping actions from the user, removes the checks that catch everything else.',
    fix: 'Remove the instruction.',
    references: [],
  },
  {
    id: 'ZNA016', severity: 'critical', name: 'shadowing-executable',
    title: 'Executable in the repository root shadows a common tool',
    help: 'Windows and some tools look in the current directory first, so a planted git.exe or node.exe runs instead of the real tool when an editor or agent starts.',
    fix: 'Delete the file unless you put it there on purpose.',
    references: [CVE.cursorGit],
  },
  {
    id: 'ZNA017', severity: 'medium', name: 'project-plugins',
    title: 'Project settings add plugin marketplaces or enable plugins',
    help: 'Plugins can add hooks, MCP servers and skills, and update themselves once the project is trusted.',
    fix: 'Install plugins from your user settings after reviewing them, at a pinned version.',
    references: [],
  },
  {
    id: 'ZNA018', severity: 'low', name: 'agent-extensions',
    title: 'Repository ships agent extensions',
    help: 'Commands, subagents, skills and plugins in the repository become part of your agent. Their content is checked by the other rules; this is an inventory note.',
    fix: 'Review them like code.',
    references: [],
  },
  {
    id: 'ZNA019', severity: 'high', name: 'ci-agent-untrusted-input',
    title: 'CI workflow runs an AI agent on input anyone can write',
    help: 'Issues, comments and pull requests from forks reach an agent that holds repository tokens and secrets.',
    fix: 'Restrict the trigger to trusted authors (author_association), avoid pull_request_target, and give the job read-only permissions.',
    references: [],
  },
  {
    id: 'ZNA020', severity: 'high', name: 'unchecked-agent-file',
    title: 'Agent file could not be checked',
    help: 'zn audit could not review this file or directory: a syntax error, a size over the limit, a symbolic link leaving the repository, or a scan that stopped early. Agents may still read and act on it. High when the file can run commands or redirect the agent, or when the scan did not finish.',
    fix: 'Fix the syntax error, move the content into the repository, or review the file by hand.',
    references: [],
  },
];

const BY_ID = Object.fromEntries(RULES.map((r) => [r.id, r]));

module.exports = { AUDIT_RULES_VERSION, RULES, BY_ID, SEVERITIES, RANK, SECURITY_SEVERITY, CVE };
