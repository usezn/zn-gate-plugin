'use strict';
/** Report formats of `zn audit`: text, JSON (version 1) and SARIF 2.1.0. */

const crypto = require('crypto');
const { RULES, BY_ID, RANK, SECURITY_SEVERITY } = require('./rules');
const { AGENT_PLACES } = require('./index');

const DOCS_URL = 'https://github.com/usezn/zn/blob/main/docs/audit.md';

function summarize(result, failOn) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of result.findings) bySeverity[f.severity]++;
  const failed = failOn !== 'none' && result.findings.some((f) => RANK[f.severity] >= RANK[failOn]);
  return {
    files: result.files,
    findings: result.findings.length,
    bySeverity,
    failOn,
    failed,
    agents: result.agents,
    agentStatus: (result.agents || []).map((a) => {
      const n = (result.agentFiles || {})[a] || 0;
      return { agent: a, files: n, checked: n > 0 };
    }),
    truncated: Boolean(result.truncated),
    skippedDirs: (result.skippedDirs || []).length,
  };
}

function toJson(result, meta) {
  return JSON.stringify({
    version: 1,
    tool: 'zn-gate',
    toolVersion: meta.toolVersion,
    root: result.root,
    findings: result.findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      agent: f.agent,
      file: f.file,
      line: f.line,
      title: f.title,
      detail: f.detail,
      evidence: f.evidence,
      fix: f.fix,
      references: f.references,
    })),
    skippedDirs: (result.skippedDirs || []).map((d) => ({ dir: d.dir, reason: d.reason })),
    summary: summarize(result, meta.failOn),
  }, null, 2) + '\n';
}

// Control characters (C0, DEL, C1) and bidirectional controls from a
// repository must never reach the terminal: an ESC or OSC sequence could
// erase or rewrite the lines above it. They are shown as \xNN / \u{NNNN}.
const UNSAFE_CHARS = /[\u{0}-\u{1f}\u{7f}-\u{9f}\u{202a}-\u{202e}\u{2066}-\u{2069}\u{200e}\u{200f}\u{61c}]/gu;

function safeText(s) {
  return String(s == null ? '' : s).replace(UNSAFE_CHARS, (c) => {
    const cp = c.codePointAt(0);
    return cp <= 0xff ? '\\x' + cp.toString(16).padStart(2, '0') : '\\u{' + cp.toString(16) + '}';
  });
}

function toText(result, meta) {
  const color = Boolean(meta.color);
  const paint = (code, s) => (color ? '\x1b[' + code + 'm' + safeText(s) + '\x1b[0m' : safeText(s));
  const SEV = { critical: '35;1', high: '31;1', medium: '33', low: '36' };
  const lines = [];
  lines.push('zn audit  ' + safeText(meta.displayRoot) + '  (zn-gate ' + meta.toolVersion + ')');
  lines.push('');
  for (const f of result.findings) {
    lines.push(paint(SEV[f.severity], f.severity.toUpperCase().padEnd(9)) + ' ' + f.id + '  ' + safeText(f.file) + ':' + f.line + '  [' + safeText(f.agent) + ']');
    const pad = '          ';
    lines.push(pad + safeText(f.title));
    lines.push(pad + safeText(f.detail));
    if (f.evidence) lines.push(pad + paint('90', 'evidence: ' + f.evidence));
    lines.push(pad + paint('90', 'fix: ' + f.fix));
    if (f.references && f.references.length) lines.push(pad + paint('90', 'refs: ' + f.references.join(', ')));
    lines.push('');
  }
  const s = summarize(result, meta.failOn);
  const counts = s.bySeverity;
  const total = s.findings === 1 ? '1 finding' : s.findings + ' findings';
  let tail = total + ' (' + counts.critical + ' critical, ' + counts.high + ' high, ' + counts.medium + ' medium, ' + counts.low + ' low) in ' + s.files + ' file' + (s.files === 1 ? '' : 's') + '.';
  if (meta.failOn === 'none') tail += ' Not failing (--fail-on none).';
  else tail += s.failed ? ' Failing: severity >= ' + meta.failOn + '.' : ' Nothing at or above ' + meta.failOn + '.';
  // An agent that was asked for but had nothing to read is said so out loud:
  // "no findings" would read as "checked and clean".
  const missed = result.explicitAgents ? s.agentStatus.filter((a) => !a.checked).map((a) => a.agent) : [];
  if (s.findings === 0) {
    tail = s.files === 0
      ? 'Nothing was checked: no agent instruction or config files were found.'
      : (missed.length ? 'No findings in the ' + s.files + ' file' + (s.files === 1 ? '' : 's') + ' that ' + (s.files === 1 ? 'was' : 'were') + ' read.' : 'No findings in ' + s.files + ' agent file' + (s.files === 1 ? '' : 's') + '.');
  }
  lines.push(s.failed ? paint('31;1', tail) : tail);
  for (const a of missed) {
    lines.push(a + ': not checked (no instruction or config files found where zn looks: ' + (AGENT_PLACES[a] || 'its usual places') + ')');
  }
  if (result.truncated) lines.push('Note: the scan stopped early (see ZNA020); some files were not checked.');
  const dirs = result.skippedDirs || [];
  if (dirs.length) {
    lines.push('');
    lines.push('Directories not read (' + dirs.length + '):');
    for (const d of dirs.slice(0, 20)) lines.push('  ' + safeText(d.dir) + ' (' + d.reason + ')');
    if (dirs.length > 20) lines.push('  ... and ' + (dirs.length - 20) + ' more');
  }
  return lines.join('\n') + '\n';
}

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

function encodePath(p) {
  return String(p).split('/').map((seg) => encodeURIComponent(seg)).join('/');
}

function toSarif(result, meta) {
  const rules = RULES.map((r) => ({
    id: r.id,
    name: r.name.replace(/(^|-)([a-z])/g, (m, d, c) => c.toUpperCase()),
    shortDescription: { text: r.title },
    fullDescription: { text: r.help },
    help: {
      text: r.help + '\n\nFix: ' + r.fix + (r.references.length ? '\n\nReferences: ' + r.references.join(', ') : ''),
      markdown: '**' + r.title + '**\n\n' + r.help + '\n\n**Fix:** ' + r.fix + (r.references.length ? '\n\n**References:** ' + r.references.join(', ') : '') + '\n\n[Documentation](' + DOCS_URL + ')',
    },
    helpUri: DOCS_URL + '#rules',
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: {
      'security-severity': SECURITY_SEVERITY[r.severity],
      precision: 'medium',
      tags: ['security'].concat(r.references),
    },
  }));
  const index = Object.fromEntries(RULES.map((r, i) => [r.id, i]));
  // Fingerprint: rule, file and evidence (stable when lines move), plus the
  // ordinal among identical findings so that each one stays unique.
  const ordinals = new Map();
  const results = result.findings.map((f) => {
    const home = f.file.startsWith('~/');
    const base = [f.id, f.file, f.evidence].join('\u0000');
    const n = (ordinals.get(base) || 0) + 1;
    ordinals.set(base, n);
    const fp = crypto.createHash('sha256').update(base + '\u0000' + n).digest('hex');
    return {
      ruleId: f.id,
      ruleIndex: index[f.id],
      level: LEVEL[f.severity],
      message: { text: f.title + ': ' + f.detail },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: encodePath(home ? f.file.slice(2) : f.file), uriBaseId: home ? 'HOME' : '%SRCROOT%' },
          region: { startLine: f.line },
        },
      }],
      partialFingerprints: { 'znAudit/v1': fp },
      properties: { severity: f.severity, agent: f.agent, evidence: f.evidence, fix: f.fix, references: f.references },
    };
  });
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'zn-gate audit',
          informationUri: DOCS_URL,
          version: meta.toolVersion,
          semanticVersion: meta.toolVersion,
          rules,
        },
      },
      originalUriBaseIds: {
        '%SRCROOT%': { description: { text: 'The audited directory (repository root).' } },
        HOME: { description: { text: 'The user home directory (--include-home).' } },
      },
      columnKind: 'utf16CodeUnits',
      results,
    }],
  }, null, 2) + '\n';
}

module.exports = { toJson, toText, toSarif, summarize, safeText, BY_ID };
