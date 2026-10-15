'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

/*
 * Config formats (verified against each agent's official docs, 2026-10-11):
 *
 *  - 'mcpServers-json' : JSON object { mcpServers: { name: { command, args } } }
 *                        (Claude Desktop, Claude Code, Cursor, Antigravity, Hermes)
 *  - 'opencode-json'   : ~/.config/opencode/opencode.json
 *                        { mcp: { name: { type: "local", command: ["npx", ...] } } }
 *                        https://opencode.ai/docs/mcp-servers/ , https://opencode.ai/docs/config/
 *  - 'codex-toml'      : ~/.codex/config.toml (or $CODEX_HOME/config.toml)
 *                        [mcp_servers.name]  command = "npx"  args = ["-y", ...]
 *                        https://developers.openai.com/codex/mcp
 *
 * We never rewrite a file we cannot round-trip safely: JSONC with comments and
 * TOML entries with multi-line arrays are reported as 'manual_required'.
 */

function getKnownEnvironments() {
  const home = os.homedir();
  const isWin = process.platform === 'win32';
  const isMac = process.platform === 'darwin';
  const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, '.config');

  const claudeDesktopPath = isWin
    ? path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
    : isMac
    ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    : path.join(xdgConfig, 'Claude', 'claude_desktop_config.json');

  const opencodeDir = path.join(xdgConfig, 'opencode');
  const opencodeJson = path.join(opencodeDir, 'opencode.json');
  const opencodeJsonc = path.join(opencodeDir, 'opencode.jsonc');
  const opencodePath = !fs.existsSync(opencodeJson) && fs.existsSync(opencodeJsonc) ? opencodeJsonc : opencodeJson;

  const codexHome = process.env.CODEX_HOME || path.join(home, '.codex');

  // Antigravity: Google's MCP guides use ~/.gemini/antigravity/mcp_config.json;
  // other setup guides use a shared ~/.gemini/config/mcp_config.json. Both are
  // checked (each only if it exists), so servers in either file are covered.

  return [
    { name: 'Claude Desktop', id: 'claude-desktop', filePath: claudeDesktopPath, key: 'mcpServers', format: 'mcpServers-json' },
    { name: 'Claude Code', id: 'claude-code', filePath: path.join(home, '.claude.json'), key: 'mcpServers', format: 'mcpServers-json' },
    { name: 'Cursor', id: 'cursor', filePath: path.join(home, '.cursor', 'mcp.json'), key: 'mcpServers', format: 'mcpServers-json' },
    { name: 'Antigravity (AGY)', id: 'antigravity', filePath: path.join(home, '.gemini', 'antigravity', 'mcp_config.json'), key: 'mcpServers', format: 'mcpServers-json' },
    { name: 'Antigravity (shared settings)', id: 'antigravity-shared', filePath: path.join(home, '.gemini', 'config', 'mcp_config.json'), key: 'mcpServers', format: 'mcpServers-json' },
    { name: 'Codex', id: 'codex', filePath: path.join(codexHome, 'config.toml'), key: 'mcp_servers', format: 'codex-toml' },
    { name: 'OpenCode', id: 'opencode', filePath: opencodePath, key: 'mcp', format: 'opencode-json' },
    { name: 'Hermes / PiAgent', id: 'hermes-piagent', filePath: path.join(home, '.hermes', 'mcp.json'), key: 'mcpServers', format: 'mcpServers-json' },
  ];
}

function isShieldedCommand(cmd, args) {
  const joined = [cmd || '', ...(args || [])].join(' ');
  return /\bzn-gate\b|\bzn-mcp\b/.test(joined) || (args || []).includes('shield');
}

function shieldArgv(originalArgv, options) {
  const argv = ['-y', 'zn-gate', 'shield'];
  if (options.shadow) argv.push('--shadow');
  argv.push('--', ...originalArgv);
  return argv;
}

// ---------------------------------------------------------------------------
// Adapter: { mcpServers: { name: { command, args } } }  (and custom `key`)
// ---------------------------------------------------------------------------
const mcpServersJson = {
  list(raw, env) {
    const json = JSON.parse(raw);
    const srvs = json[env.key || 'mcpServers'] || {};
    return Object.entries(srvs).map(([name, cfg]) => {
      const command = (cfg && cfg.command) || '';
      const args = (cfg && cfg.args) || [];
      return { name, command, args, shielded: isShieldedCommand(command, args), remote: !command };
    });
  },
  shield(raw, env, options) {
    const json = JSON.parse(raw);
    const srvs = json[env.key || 'mcpServers'] || {};
    let modified = false;
    for (const cfg of Object.values(srvs)) {
      if (!cfg || !cfg.command) continue; // remote/url servers: nothing to wrap
      const args = cfg.args || [];
      if (isShieldedCommand(cfg.command, args)) continue;
      cfg.args = shieldArgv([cfg.command, ...args], options);
      cfg.command = 'npx';
      modified = true;
    }
    return { modified, content: JSON.stringify(json, null, 2) + '\n', manual: [] };
  },
};

// ---------------------------------------------------------------------------
// Adapter: OpenCode  { mcp: { name: { type: "local", command: [..] } } }
// ---------------------------------------------------------------------------
function parseStrictJson(raw, filePath) {
  try {
    return JSON.parse(raw);
  } catch (e) {
    const err = new Error(`${path.basename(filePath)} is not strict JSON (comments/trailing commas?). Not rewriting it; add zn-gate manually.`);
    err.manual = true;
    throw err;
  }
}

const opencodeJson = {
  list(raw, env) {
    const json = parseStrictJson(raw, env.filePath);
    const srvs = json.mcp || {};
    return Object.entries(srvs).map(([name, cfg]) => {
      const argv = Array.isArray(cfg && cfg.command) ? cfg.command : [];
      const local = cfg && cfg.type === 'local' && argv.length > 0;
      return { name, command: argv[0] || '', args: argv.slice(1), shielded: local && isShieldedCommand(argv[0], argv.slice(1)), remote: !local };
    });
  },
  shield(raw, env, options) {
    const json = parseStrictJson(raw, env.filePath);
    const srvs = json.mcp || {};
    let modified = false;
    for (const cfg of Object.values(srvs)) {
      if (!cfg || cfg.type !== 'local' || !Array.isArray(cfg.command) || cfg.command.length === 0) continue;
      if (isShieldedCommand(cfg.command[0], cfg.command.slice(1))) continue;
      cfg.command = ['npx', ...shieldArgv(cfg.command, options)];
      modified = true;
    }
    return { modified, content: JSON.stringify(json, null, 2) + '\n', manual: [] };
  },
};

// ---------------------------------------------------------------------------
// Adapter: Codex config.toml  [mcp_servers.<name>] command = "..." args = [..]
// Minimal, line-based and conservative (zero dependencies). Only single-line
// `command` strings and single-line `args` arrays of strings are rewritten.
// ---------------------------------------------------------------------------
const TOML_HEADER = /^\s*\[\s*([^\[\]]+?)\s*\]\s*(?:#.*)?$/;

function parseTomlKeyPath(keyPath) {
  // Splits a dotted key like mcp_servers."my server" into parts.
  const parts = [];
  const re = /\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([A-Za-z0-9_-]+))\s*(?:\.|$)/y;
  let m;
  let consumed = 0;
  re.lastIndex = 0;
  while (consumed < keyPath.length && (m = re.exec(keyPath)) !== null) {
    if (m[0].length === 0) break;
    try {
      parts.push(m[1] !== undefined ? JSON.parse(`"${m[1]}"`) : m[2] !== undefined ? m[2] : m[3]);
    } catch (_) {
      return [];
    }
    consumed = re.lastIndex;
  }
  return consumed === keyPath.length ? parts : [];
}

function parseTomlString(src) {
  // Returns [value, rest] for a basic "..." or literal '...' string at the start of src.
  const s = src.trimStart();
  if (s.startsWith('"""') || s.startsWith("'''")) return null; // multi-line strings: unsupported
  let m = /^"((?:[^"\\]|\\.)*)"/.exec(s);
  if (m) {
    try {
      return [JSON.parse(`"${m[1]}"`), s.slice(m[0].length)];
    } catch (_) {
      return null;
    }
  }
  m = /^'([^']*)'/.exec(s);
  if (m) return [m[1], s.slice(m[0].length)];
  return null;
}

function parseTomlStringArray(src) {
  // Parses a single-line ["a", 'b'] array of strings. Returns array or null.
  let s = src.trim();
  if (!s.startsWith('[')) return null;
  s = s.slice(1);
  const out = [];
  for (;;) {
    s = s.trimStart();
    if (s.startsWith(']')) {
      const tail = s.slice(1).trim();
      return tail === '' || tail.startsWith('#') ? out : null;
    }
    const r = parseTomlString(s);
    if (!r) return null;
    out.push(r[0]);
    s = r[1].trimStart();
    if (s.startsWith(',')) s = s.slice(1);
    else if (!s.startsWith(']')) return null;
  }
}

function tomlStr(v) {
  return JSON.stringify(String(v)); // JSON string escapes are valid TOML basic strings
}

function scanCodexToml(raw) {
  const lines = raw.split(/\r?\n/);
  const servers = [];
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    const h = TOML_HEADER.exec(lines[i]);
    if (h && !lines[i].trim().startsWith('[[')) {
      const parts = parseTomlKeyPath(h[1]);
      if (parts.length === 2 && parts[0] === 'mcp_servers') {
        current = { name: parts[1], headerLine: i, commandLine: -1, argsLine: -1, command: null, args: null, unsupported: null, url: false };
        servers.push(current);
      } else {
        current = null; // any other table (including mcp_servers.x.env) ends the section
      }
      continue;
    }
    if (!current) continue;
    const kv = /^\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(lines[i]);
    if (!kv) continue;
    const [, key, value] = kv;
    if (key === 'command') {
      const r = parseTomlString(value);
      const rest = r ? r[1].trim() : '';
      if (r && (rest === '' || rest.startsWith('#'))) {
        current.command = r[0];
        current.commandLine = i;
      } else current.unsupported = 'command is not a single-line string';
    } else if (key === 'args') {
      const arr = parseTomlStringArray(value);
      if (arr) {
        current.args = arr;
        current.argsLine = i;
      } else current.unsupported = 'args is not a single-line array of strings';
    } else if (key === 'url') {
      current.url = true;
    }
  }
  return { lines, servers };
}

const codexToml = {
  list(raw) {
    return scanCodexToml(raw).servers.map((s) => ({
      name: s.name,
      command: s.command || '',
      args: s.args || [],
      shielded: Boolean(s.command) && isShieldedCommand(s.command, s.args || []),
      remote: !s.command,
    }));
  },
  shield(raw, env, options) {
    const eol = raw.includes('\r\n') ? '\r\n' : '\n';
    const { lines, servers } = scanCodexToml(raw);
    const manual = [];
    let modified = false;
    // Process bottom-up so inserted lines don't shift later indices.
    for (const s of [...servers].sort((a, b) => b.headerLine - a.headerLine)) {
      if (!s.command) continue; // streamable-HTTP (url) servers: nothing to wrap
      if (s.unsupported) {
        manual.push(`${s.name}: ${s.unsupported}`);
        continue;
      }
      const args = s.args || [];
      if (isShieldedCommand(s.command, args)) continue;
      const newArgs = shieldArgv([s.command, ...args], options);
      lines[s.commandLine] = `command = ${tomlStr('npx')}`;
      const argsLine = `args = [${newArgs.map(tomlStr).join(', ')}]`;
      if (s.argsLine >= 0) lines[s.argsLine] = argsLine;
      else lines.splice(s.commandLine + 1, 0, argsLine);
      modified = true;
    }
    return { modified, content: lines.join(eol), manual };
  },
};

const ADAPTERS = {
  'mcpServers-json': mcpServersJson,
  'opencode-json': opencodeJson,
  'codex-toml': codexToml,
};

function adapterFor(env) {
  return ADAPTERS[env.format || 'mcpServers-json'] || mcpServersJson;
}

/**
 * Scans the filesystem for the supported agent environments.
 */
function scanEnvironments(customEnvList = null) {
  const envs = customEnvList || getKnownEnvironments();
  const results = [];

  for (const env of envs) {
    const exists = fs.existsSync(env.filePath);
    let servers = [];

    if (exists) {
      try {
        const raw = fs.readFileSync(env.filePath, 'utf8');
        servers = adapterFor(env).list(raw, env);
      } catch (e) {
        servers = [{ name: 'error', error: e.message }];
      }
    }

    const valid = servers.filter((s) => !s.error);
    results.push({
      ...env,
      exists,
      servers,
      serverCount: valid.length,
      allShielded: valid.length > 0 && valid.filter((s) => !s.remote).every((s) => s.shielded),
    });
  }

  return results;
}

/**
 * Protects (or reverts) the detected environments.
 *
 * @param {object} options - { shadow: boolean, dryRun: boolean, revert: boolean, envList: array }
 */
function configureEnvironments(options = {}) {
  const envs = scanEnvironments(options.envList);
  const actions = [];

  for (const env of envs) {
    if (!env.exists) continue;

    if (options.revert) {
      const dir = path.dirname(env.filePath);
      const base = path.basename(env.filePath);
      const baks = fs.readdirSync(dir)
        .filter((f) => f.startsWith(base + '.bak.'))
        .sort()
        .reverse();

      if (baks.length > 0) {
        const latestBak = path.join(dir, baks[0]);
        if (!options.dryRun) {
          fs.copyFileSync(latestBak, env.filePath);
        }
        actions.push({ env: env.name, status: 'reverted', from: latestBak });
      } else if (env.serverCount > 0) {
        actions.push({ env: env.name, status: 'no_backup_found' });
      }
      continue;
    }

    if (env.serverCount === 0) {
      const err = env.servers.find((s) => s.error);
      if (err) actions.push({ env: env.name, status: 'manual_required', error: err.error, file: env.filePath });
      continue;
    }

    try {
      const raw = fs.readFileSync(env.filePath, 'utf8');
      const { modified, content, manual } = adapterFor(env).shield(raw, env, options);

      let backup;
      if (modified && !options.dryRun) {
        backup = `${env.filePath}.bak.${Date.now()}`;
        fs.writeFileSync(backup, raw, 'utf8');
        fs.writeFileSync(env.filePath, content, 'utf8');
      }

      if (modified) {
        actions.push({
          env: env.name,
          status: options.dryRun ? 'would_shield' : 'shielded',
          serversCount: env.serverCount,
          shadow: Boolean(options.shadow),
          ...(backup ? { backup } : {}),
          ...(manual.length ? { manual } : {}),
        });
      } else if (manual.length) {
        actions.push({ env: env.name, status: 'manual_required', manual, file: env.filePath });
      } else {
        actions.push({ env: env.name, status: 'already_shielded' });
      }
    } catch (err) {
      actions.push({ env: env.name, status: err.manual ? 'manual_required' : 'error', error: err.message, file: env.filePath });
    }
  }

  return { scanned: envs, actions };
}

module.exports = {
  getKnownEnvironments,
  scanEnvironments,
  configureEnvironments,
  // exported for tests
  _internal: { scanCodexToml, parseTomlStringArray, parseTomlKeyPath },
};
