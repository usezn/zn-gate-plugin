<p align="center">
  <a href="https://usezn.com"><img src="https://raw.githubusercontent.com/usezn/zn/main/assets/brand/zn-logo-lime-on-forest.png" alt="zn" width="200"></a>
</p>

# zn-gate

[![CI](https://github.com/usezn/zn/actions/workflows/ci.yml/badge.svg)](https://github.com/usezn/zn/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/zn-gate?color=cb3837&logo=npm&logoColor=white)](https://www.npmjs.com/package/zn-gate)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/usezn/zn/blob/main/LICENSE)

**Use AI coding agents without exposing your secrets, your data or your systems.**

`zn-gate` is an open-source security layer that runs on your machine, between your agent and the tools and content it touches. It checks what the agent reads and calls for prompt injection, redacts secrets from tool output before the model sees it, and audits prompts, skills and configs. No account, no network by default, and no runtime dependencies except `age-encryption` (and its `@noble`/`@scure` dependencies) for the secret vault, bundled in the package at the versions pinned in `package-lock.json`.

**For:** developers using Claude Code, Codex CLI, Cursor, OpenCode or any MCP client. Python SDK: [`zn-gate` on PyPI](https://pypi.org/project/zn-gate/).

---

## Install

Everything runs on your machine; no account or API key is needed. You need Node.js 18 or later (the LTS version from [nodejs.org](https://nodejs.org/)).

**Claude Code (recommended): the plugin.** You also need Git and Claude Code 2.1.295 or later.

```bash
claude plugin marketplace add usezn/zn
claude plugin install zn-gate@usezn
```

Already ran `zn hooks install claude-code` before? Run `zn hooks uninstall claude-code` first, otherwise both sets of hooks run.

Start a new Claude Code session. Claude Code is then blocked from reading `.env` files with real values and credential files, secrets in what its tools return are replaced with markers or redacted before the model sees them, a secret pasted into a prompt is blocked, and Claude can check untrusted text for prompt injection. Not covered: Claude Code sessions in the cloud, Cowork and chat. Details: [plugins/zn-gate](https://github.com/usezn/zn/blob/main/plugins/zn-gate/README.md).

**Codex CLI, Cursor or OpenCode: the hooks.**

```bash
npm install -g zn-gate
zn hooks install codex           # or: cursor, opencode
```

In Codex, approve the new hooks with `/hooks`. In Cursor, shell output and file contents are not scrubbed. What each agent supports: [docs/compat.md](https://github.com/usezn/zn/blob/main/docs/compat.md).

**Other editors** (VS Code, Antigravity, Windsurf, Cline, Zed, JetBrains, Continue): zn-gate works there as an MCP server only. Setup for each one: [usezn.com/docs/integrations/editors](https://usezn.com/docs/integrations/editors/).

**Then keep your `.env` values in the vault.** With the plugin or the hooks, the agent cannot read `.env` files with real values; move them into zn-gate's encrypted vault, and the file keeps markers such as `__ZN_STRIPE_KEY__`:

```bash
npx -y zn-gate unlock            # creates the vault the first time
npx -y zn-gate env shadow .env
```

After this, your own app also reads the markers in `.env`: start it with zn-gate's `run` command once you allow it ([docs/secrets.md](https://github.com/usezn/zn/blob/main/docs/secrets.md)). `env shadow` tells you how to undo it.

Five-minute walkthrough: [docs/secrets.md](https://github.com/usezn/zn/blob/main/docs/secrets.md). Limits: [docs/threat-model.md](https://github.com/usezn/zn/blob/main/docs/threat-model.md).

> **Windows PowerShell:** `npm` and `npx` can fail with "running scripts is disabled on this system", because the default execution policy blocks `npm.ps1`. Use `npm.cmd`, `npx.cmd` and `zn.cmd` instead (for example `npm.cmd install -g zn-gate`), run the commands from Command Prompt, or allow local scripts for your account with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Python: for agents you build yourself** (rules engine and secret redaction for LangChain, CrewAI, LlamaIndex or plain tool calling). It does not protect Claude Code, Codex, Cursor or other coding agents. Install it in a virtual environment; many recent Linux systems, and Homebrew's Python on macOS, refuse `pip install` outside one ("externally-managed-environment"):

```bash
python3 -m venv .venv
.venv/bin/pip install zn-gate      # Windows: .venv\Scripts\pip install zn-gate
```

**zn-gate as an MCP server only** (the agent calls it when it decides to; not automatic protection):

```bash
claude mcp add zn-gate -- npx -y zn-gate mcp     # Claude Code
codex mcp add zn-gate -- npx -y zn-gate mcp      # Codex CLI
```

Cursor (`~/.cursor/mcp.json`) and other editors: `{ "mcpServers": { "zn-gate": { "command": "npx", "args": ["-y", "zn-gate", "mcp"] } } }`. OpenCode (`~/.config/opencode/opencode.json`): `{ "mcp": { "zn-gate": { "type": "local", "command": ["npx", "-y", "zn-gate", "mcp"], "enabled": true } } }`.

### Wrap the MCP servers you already use

`init` finds MCP servers in your agent config files, writes a backup, and wraps each local (stdio) server with `zn-gate shield`:

```bash
npx -y zn-gate init --dry-run   # preview, changes nothing
npx -y zn-gate init             # wrap (a .bak.<timestamp> copy is written first)
npx -y zn-gate init --shadow    # log detections without blocking
npx -y zn-gate init --revert    # restore the latest backup
```

| Agent | File | Format |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` (macOS `~/Library/Application Support/Claude/`, Windows `%APPDATA%\Claude\`, Linux `~/.config/Claude/`) | `mcpServers` JSON |
| Claude Code | `~/.claude.json` (user scope) | `mcpServers` JSON |
| Cursor | `~/.cursor/mcp.json` | `mcpServers` JSON |
| Codex CLI | `~/.codex/config.toml` (or `$CODEX_HOME/config.toml`) | `[mcp_servers.<name>]` TOML |
| OpenCode | `~/.config/opencode/opencode.json` | `mcp` JSON, `command` array |
| Antigravity | `~/.gemini/antigravity/mcp_config.json` (Google's MCP guides) and `~/.gemini/config/mcp_config.json` (shared settings, used by some setups); each one only if it exists | `mcpServers` JSON |
| Hermes / PiAgent | `~/.hermes/mcp.json` | `mcpServers` JSON (path not verified against official docs) |

Remote (URL) servers are left as they are. `init` never rewrites a file it cannot round-trip safely: OpenCode JSONC files with comments and Codex entries with multi-line `args` are reported as "wrap manually".

To wrap a single server by hand:
```bash
npx -y zn-gate shield -- uvx mcp-server-fetch
```

---

## Check that it works

```bash
npx -y zn-gate test
```

This runs the local self-test (51 curated vectors: 26 attacks, 25 benign) and shows per-decision latency on your machine. It is a smoke test, not a detection rate. Nothing is sent over the network.

**For developers: see the redaction by hand.** Send a tool output with a fake AWS key (AWS's documentation example) and a database password through zn-gate, exactly as your agent would, and look for `sanitized_content` in the output; that field is what the model would see:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_tool_result","arguments":{"tool_name":"read_file","content":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDATABASE_URL=postgres://app:hunter2@db:5432/main"}}}' \
  | npx -y zn-gate@latest mcp
```

---

## What each piece does

**Scrubber: secrets stay out of the model's context**
- Today: redacts AWS keys, OpenAI and Anthropic keys, GitHub tokens, JWTs, private keys and database URL passwords in everything that passes through zn-gate (`check_tool_result`, `check_tool_call`, and output of servers wrapped by `shield` / `init`).
- Not covered today: your agent's built-in tools (for example a native file read in Claude Code) unless their output goes through zn-gate.
- Roadmap: personal data (PII) detection; hooks for agents' built-in tools; stable placeholders backed by a local encrypted vault.

**Galvanize: prompt-injection detection**
- Today, local: a deterministic rules engine with normalization against homoglyphs, zero-width characters, BiDi overrides (CVE-2021-42574), comment splicing and Base64. It checks prompts, tool arguments, tool output and MCP tool descriptions.
- Today, optional cloud: the Galvanize 2 classifier ([open weights](https://huggingface.co/usezn/Galvanize-2), Apache-2.0) can also check prompts sent to `analyze_prompt`, only with `ZN_CLOUD=1` and `ZN_API_KEY`.
- Roadmap: running Galvanize locally inside zn-gate.

**Scan: audit what your agent is about to trust**
- Today: `npx -y zn-gate scan <path>` audits prompt templates, `AGENTS.md` / `SKILL.md` files and configs for injection traps and leaked secrets. It exits with code 1 on findings, for CI. MCP servers can be checked on the web at [usezn.com/scan](https://usezn.com/scan).
- Roadmap: auditing MCP servers and skills from the CLI before you add them.

### MCP tools

| Tool | Phase | What it does | Network |
|---|---|---|---|
| `analyze_prompt` | Before the LLM | Checks a prompt for injection, jailbreak and exfiltration patterns. | Only with `ZN_CLOUD=1` + key, redacted |
| `check_tool_call` | Before execution | Checks tool name and arguments; returns `sanitized_arguments` with secrets masked. | Never |
| `check_tool_result` | Before ingestion | Checks tool output for indirect injection; returns it with secrets redacted, or neutralized if blocked. | Never |
| `zn_status` | Any | Engine, rules version, and what (if anything) leaves the machine. | Never |

---

## What leaves your machine

**Nothing, by default.**

| Data | Evaluated | Sent anywhere? |
|---|---|---|
| Tool output (`check_tool_result`, `shield`) | Locally | **Never**, in any configuration |
| Tool-call arguments (`check_tool_call`, `shield`) | Locally | **Never**, in any configuration |
| MCP tool and parameter descriptions (`shield`) | Locally | **Never**, in any configuration |
| Counts of what zn-gate did (`zn-gate stats`: checks, blocks, secrets replaced, per secret type) | Written locally to `~/.zn/stats.json` | **Never**, unless you turn on `zn-gate stats share on`: then one report a day with a random installation id, the day, the zn-gate, OS and Node.js versions, the agent and part of zn-gate used most, and the number of secrets found per built-in type (never values, prompts, variable or secret names, paths, hosts or emails). `zn-gate stats share show` shows it first. |
| Prompts (`analyze_prompt`, `zn-gate analyze`) | Locally | Only if you set **both** `ZN_CLOUD=1` and `ZN_API_KEY`. Secrets are redacted locally before sending. |

`ZN_API_KEY` alone enables nothing. `ZN_LOCAL_ONLY=true` (or `--local-only`) overrides `ZN_CLOUD=1`. `npx -y zn-gate status` prints what your configuration sends. Data-flow diagrams: [repository README](https://github.com/usezn/zn#what-leaves-your-machine).

> **1.4.0 and earlier:** with `ZN_API_KEY` set, tool output and tool-call arguments not blocked locally were sent to `api.usezn.com` without redaction. 1.4.1 removes that path. See the [CHANGELOG](https://github.com/usezn/zn/blob/main/CHANGELOG.md).

---

## Performance (local rules engine, no network)

Measured 2026-10-11 on a 2-vCPU Intel Xeon Platinum 8259CL (AWS), Node 24, zn-gate 1.4.1, uncached inputs. p50 is the median of 3 runs; p99 is the worst of 3 runs.

| Input size | `evaluate()` p50 | `evaluate()` p99 | `check_tool_result` p50 | `check_tool_result` p99 |
|---|---|---|---|---|
| 200 B (typical prompt) | 0.012 ms | 0.09 ms | 0.045 ms | 0.19 ms |
| 4 KB (typical tool output) | 0.16 ms | 0.45 ms | 0.30 ms | 0.81 ms |
| 64 KB (large file) | 2.4 ms | 4.8 ms | 3.8 ms | 6.7 ms |

`check_tool_result` includes secret redaction. Latency grows roughly linearly with input size. The MCP stdio round-trip for a 4 KB `check_tool_result` was 0.5 ms p50 on the same host.

Reproduce with `node bench/bench_by_size.js` from the [repository](https://github.com/usezn/zn). Please send us your numbers.

## Accuracy: what the local rules catch, and what they don't

The local engine is a deterministic signature and normalization layer. It is fast and explainable, but it is not a semantic classifier.

- **Self-test:** 51 curated vectors pass. That is a smoke test, not a detection or false-positive rate.
- **Known limitation:** on whole source files, as seen by `check_tool_result`, the rules can flag ordinary code comments. 1.5.0 reduces these on code and documentation, at the cost of letting some loosely worded override attempts through the local rules. Prefer `check_tool_result` for web and third-party content rather than your own repository files.
- **Detection rates:** on a private held-out set of 3,309 examples, Galvanize 2 has 83.4% recall at a 0.81% false positive rate (serving threshold 0.662); these numbers are for the cloud classifier, not the local rules engine. Method, per-language results, known weak spots and a reproducible benchmark are in the [model card](https://huggingface.co/usezn/Galvanize-2) and the [announcement](https://usezn.com/blog/introducing-galvanize-2/). It is one layer of defense, not a guarantee.

---

## Configuration

- `ZN_CLOUD`: `1` lets `analyze_prompt` / `zn-gate analyze` also query the cloud classifier. Requires `ZN_API_KEY`. Off by default.
- `ZN_API_KEY`: API key from [usezn.com/dashboard](https://usezn.com/dashboard/). No effect without `ZN_CLOUD=1`.
- `ZN_LOCAL_ONLY`: `true` forces local-only, even with `ZN_CLOUD=1`.
- `ZN_STRICT`: `1` also blocks the rules that only warn by default (see below).
- `ZN_LONG_INPUT`: how a long text (over 1,000 characters) is sent to the cloud classifier. `windows` (default) asks it to check overlapping 512-token windows, up to 20, so an injection in the middle or at the end of a long document is not missed; `off` checks only the first 512 tokens. Also `--long-input windows|off`. Windows are slower and slightly more likely to flag a long benign text, and cloud checks are billed by text size with or without windows, so `off` does not lower the count (1 call up to 2,000 characters, 1 more per further 1,000; `billed_calls` in the result); see the [changelog](https://github.com/usezn/zn/blob/main/CHANGELOG.md).
- `ZN_STAGE`: `v30` (default, current production API) or `prod` (legacy endpoint). `ZN_API_URL` overrides both.

To enable the cloud check for one MCP server, add to its entry: `"env": { "ZN_CLOUD": "1", "ZN_API_KEY": "zn_live_..." }`.

### Custom rules (`.znrules` or `zn.config.json`)

```ini
# .znrules
path:.env.production
path:/etc/secrets
CONFIDENTIAL_INTERNAL_PROJECT_[A-Z0-9]+
```

### Local audit log

`zn-gate shield` appends every decision to `~/.zn/evidence.jsonl` as a hash-chained (SHA-256) record with a secret-redacted preview. It detects accidental or partial edits. It is not tamper-proof against someone with write access to the file, who can recompute the whole chain.

```bash
npx -y zn-gate evidence --verify
npx -y zn-gate evidence --ui        # local dashboard on http://localhost:3100
npx -y zn-gate evidence --tail 20
```

---

## What is blocked and what only warns

zn-gate blocks what is almost certainly an attack or a leak: reading credential files (`.env`, `~/.aws/credentials`, SSH keys), asking for API keys or passwords, sending data out through hidden image links, hidden instructions in Base64 or invisible characters, "ignore all previous instructions", and dangerous commands.

Some other patterns also appear in ordinary text, such as `system:` keys in YAML, "bypass the cache" or an article that explains what a jailbreak is. For those, zn-gate lets the text through and adds a short warning (`advisory` in the result) so you or your agent can take a look.

To block those too, turn on strict mode: set `ZN_STRICT=1`, or add `"strict": true` to `zn.config.json` in your project (or a line `strict` in `.znrules`).

## FAQ

**Do I need an account or API key?** No. Everything local works without one.

**Will it block legitimate content?** Sometimes. Use `--shadow` with `init` or `shield` to log detections without blocking while you evaluate it.

**How do I remove it?** `npx -y zn-gate init --revert` restores your configs from the backup. For a standalone server, remove the `zn-gate` entry from your agent config.

## Security

Report vulnerabilities to [security@usezn.com](mailto:security@usezn.com). Policy and safe harbor: [SECURITY.md](https://github.com/usezn/zn/blob/main/SECURITY.md).

## License

MIT © [usezn](https://usezn.com)

The package bundles age-encryption (BSD-3-Clause) and its @noble / @scure dependencies (MIT); see [THIRD_PARTY_NOTICES.md](https://github.com/usezn/zn/blob/main/packages/zn-gate/THIRD_PARTY_NOTICES.md).
