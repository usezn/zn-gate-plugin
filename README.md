# zn-gate plugin for Claude Code

zn-gate is a local security layer for coding agents. This plugin brings it to Claude Code:

- **Hooks** keep secret values out of what Claude sends to the model: tool input, tool output (shell, file, web and MCP tools) and prompts. A prompt that contains a secret is not sent, and a plain message says what to do next.
- A local **`secrets` MCP server** lets Claude use a secret without seeing it: it makes an HTTP request with the value filled in, only to hosts you allowed for that secret. Real values stay in an encrypted vault on your machine.
- A local **`zn-gate` MCP server** checks untrusted text and tool calls for prompt injection with local rules.

This repository is generated from [usezn/zn](https://github.com/usezn/zn) by its release workflow and is not edited by hand. Please open issues and pull requests in [usezn/zn](https://github.com/usezn/zn).

## Requirements

Node.js 20.12 or later. Nothing is downloaded or installed when the plugin is installed: zn-gate is included in this repository (see below).

## What leaves your machine

Nothing, by default. The hooks and both MCP servers run locally. The `secrets` server makes only the HTTP requests Claude asks for, to hosts you allowed for each secret. Optional: if you enter a zn API key in the plugin settings, the `analyze_prompt` tool also sends the text it checks, with secrets redacted first, to api.usezn.com. See https://usezn.com/privacy

## How the code you run is checked

- `vendor/zn-gate` holds the published zn-gate release, without TypeScript sources and source maps. Every file is byte for byte the file in the npm package.
- `scripts/zn-gate.lock.json` lists every file of `vendor/zn-gate` with its SHA-256. Every hook and MCP server starts through `scripts/zn-launch.js`, which checks that `vendor/zn-gate` holds exactly those files, with no links, and then runs zn-gate's code from the bytes it checked. The encryption libraries zn-gate uses for the vault are JavaScript modules that Node reads from the same checked folder after the check. If the check fails, prompts and tool calls are refused and the MCP servers do not start.
- These checks catch files that were changed, added or removed after the release was published. They do not make a published release trustworthy: that comes from the release process in usezn/zn and the npm provenance attestation.
- How to repeat the release checks yourself: [PROVENANCE.md](PROVENANCE.md).

## Documentation

https://usezn.com/docs

## License

MIT. zn-gate's bundled dependencies keep their own licenses: see the LICENSE file in each package folder under `vendor/zn-gate/node_modules`.
