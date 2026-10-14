# zn-gate plugin for Claude Code

zn-gate is a local security layer for coding agents. This repository will hold its plugin for Claude Code: hooks that keep secret values out of what Claude sends to the model, a local `secrets` MCP server that uses credentials without revealing them, and a local `zn-gate` MCP server that checks untrusted text for prompt injection.

The plugin will be published here with zn-gate 1.7.0. This repository is generated from [usezn/zn](https://github.com/usezn/zn) by its release workflow and is not edited by hand: please open issues and pull requests in [usezn/zn](https://github.com/usezn/zn).

## Install it today

Until then, install the plugin from the marketplace in usezn/zn. You need Node.js 20.12 or later and Git. In a terminal:

```
claude plugin marketplace add usezn/zn
claude plugin install zn-gate@usezn
```

Then start a new Claude Code session. Documentation: https://usezn.com/docs

## License

MIT
