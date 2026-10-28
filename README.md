# zn-gate plugin for Claude Code

zn-gate is a local security layer for coding agents. This plugin brings it to Claude Code:

- **Hooks** keep secret values out of what Claude sends to the model: tool input, tool output (shell, file, web and MCP tools) and prompts. A prompt that contains a secret is not sent, and a plain message says what to do next.
- A **skill** tells Claude how to work with secrets under zn-gate.

Since version 1.14.0 the plugin registers no MCP server: Claude Code started those servers with `node` by name, so a `node` of the project could start before anything was checked. For the `secrets` MCP server, which lets Claude use a secret without seeing it, install zn-gate with npm and run `zn hooks install claude-code`: it registers the server with Node.js by its full path.

This repository is generated from [usezn/zn](https://github.com/usezn/zn) by its release workflow and is not edited by hand. Please open issues and pull requests in [usezn/zn](https://github.com/usezn/zn).

## Requirements

Node.js 20.19 or later. Nothing is downloaded or installed when the plugin is installed: zn-gate is included in this repository (see below).

## What leaves your machine

Nothing. The hooks run locally and make no network requests. See https://usezn.com/privacy

## How the code you run is checked

- `vendor/zn-gate` holds the published zn-gate release, without TypeScript sources and source maps. Every file is byte for byte the file in the npm package.
- `scripts/zn-gate.lock.json` lists every file of `vendor/zn-gate` with its SHA-256. Every hook starts through `scripts/zn-launch.js` (the hooks through `scripts/zn-node.sh`, which finds Node.js only in absolute PATH entries outside the project, so a `node` placed in the project folder, its git work tree or a `node_modules` folder is never run), which checks that `vendor/zn-gate` holds exactly those files, with no links, and then runs zn-gate's code from the bytes it checked. The encryption libraries zn-gate uses for the vault are JavaScript modules that Node reads from the same checked folder after the check. If the check fails, prompts and tool calls are refused.
- These checks catch files that were changed, added or removed after the release was published. They do not make a published release trustworthy: that comes from the release process in usezn/zn and the npm provenance attestation.
- How to repeat the release checks yourself: [PROVENANCE.md](PROVENANCE.md).

## Documentation

https://usezn.com/docs

## License

MIT. zn-gate's bundled dependencies keep their own licenses: see the LICENSE file in each package folder under `vendor/zn-gate/node_modules`.
