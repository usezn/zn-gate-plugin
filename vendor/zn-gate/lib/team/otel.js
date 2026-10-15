'use strict';
/**
 * OpenTelemetry export of the local audit log (~/.zn/audit.jsonl), as OTLP/JSON
 * log records. Local and free: no network, no team needed.
 *
 * Each audit record becomes one `zn.gate.decision` log event.
 *
 * Format: OTLP/JSON (the protobuf JSON mapping: 64-bit integers as decimal
 * strings, severity as numbers). The file is JSON Lines with one
 * ExportLogsServiceRequest per line. The OpenTelemetry Collector reads it with
 * the `otlpjsonfile` receiver, and each line can be POSTed unchanged to an
 * OTLP/HTTP `/v1/logs` endpoint.
 *
 * Output matches the zn cloud export for the same records, so a file made here
 * and one made by the cloud can be compared byte for byte.
 *
 * Privacy: attributes come from a fixed list and every value is checked against
 * the same patterns the audit format uses. A value that does not match is
 * dropped, never passed through. The two markers "[redacted]" and "[invalid]"
 * are kept as they are, as the cloud mapper does. The audit log holds no secret
 * values, no hashes of values, no tool output and no full command lines.
 *
 * Determinism: the output depends only on the records. The event time is the
 * record time and the attribute order is fixed, so the same records always give
 * the same bytes and the same SHA-256.
 */

const fs = require('fs');
const crypto = require('crypto');

const SCOPE_NAME = 'usezn.evidence';
const SCOPE_VERSION = '1';
const EVENT_GATE = 'zn.gate.decision';
const SERVICE_GATE = 'zn-gate';
/** Log records per line; keeps lines well under collector limits. */
const RECORDS_PER_LINE = 500;

/* OTel severity numbers (logs data model). */
const SEVERITY = { INFO: 9, WARN: 13, ERROR: 17 };

/* Same value patterns as lib/vault/audit.js FORMATS, plus the id and hash shapes. */
const MASKED = new Set(['[redacted]', '[invalid]']);
const RE = {
  secret: /^[A-Z0-9_]{1,80}$/,
  name: /^[A-Za-z0-9_.:/-]{1,64}$/,
  argv0: /^[A-Za-z0-9_.+-]{1,64}$/,
  host: /^([a-z0-9.-]{1,253})(?::(\d{1,5}))?$/,
  reason: /^[A-Za-z0-9_:.-]{1,64}$/,
  hex64: /^[0-9a-f]{64}$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  orgId: /^[A-Za-z0-9_-]{1,64}$/,
};
const GATE_MODES = new Set(['proxy', 'env', 'file', 'named', 'detected', 'resolve', 'set', 'remove', 'unlock', 'lock', 'expire', 'other', '[redacted]']);
const GATE_DECISIONS = new Set(['allow', 'deny', 'ask', 'ask:yes', 'ask:no', 'restore', 'withhold', 'error', 'other', '[redacted]']);

function ok(re, v, masked) {
  return typeof v === 'string' && (re.test(v) || (masked && MASKED.has(v))) ? v : null;
}
function inSet(set, v) {
  return typeof v === 'string' && set.has(v) ? v : null;
}
function nonNegInt(v) {
  return Number.isSafeInteger(v) && v >= 0 ? v : null;
}

/** ISO 8601 time to OTLP nanoseconds, as a decimal string. Throws if the time is invalid. */
function unixNano(isoTime) {
  const ms = typeof isoTime === 'string' ? Date.parse(isoTime) : NaN;
  if (!Number.isFinite(ms)) throw new TypeError('audit record without a valid timestamp');
  return (BigInt(ms) * 1000000n).toString();
}

/** Attribute list builder: a null or empty value adds nothing. */
class Attrs {
  constructor() { this.list = []; }
  str(key, v) {
    if (typeof v === 'string' && v) this.list.push({ key, value: { stringValue: v } });
    return this;
  }
  int(key, v) {
    if (Number.isSafeInteger(v)) this.list.push({ key, value: { intValue: String(v) } });
    return this;
  }
}

function gateSeverity(decision) {
  if (decision === 'error') return 'ERROR';
  if (decision === 'deny' || decision === 'withhold' || decision === 'ask:no') return 'WARN';
  return 'INFO';
}

/** One audit record to one OTLP log record. */
function gateRecordToLog(r) {
  const decision = inSet(GATE_DECISIONS, r.decision);
  const agent = ok(RE.name, r.agent, true);
  const tool = ok(RE.name, r.tool, true);
  const secret = ok(RE.secret, r.secret, true);
  const hostMatch = typeof r.host === 'string' ? RE.host.exec(r.host) : null;
  const hostMarker = typeof r.host === 'string' && MASKED.has(r.host) ? r.host : null;
  const port = hostMatch && hostMatch[2] !== undefined ? Number(hostMatch[2]) : null;
  const a = new Attrs()
    .str('zn.decision', decision)
    .str('zn.decision.reason', ok(RE.reason, r.reason, true))
    .str('gen_ai.agent.name', agent)
    .str('gen_ai.tool.name', tool)
    .str('process.executable.name', ok(RE.argv0, r.argv0, true))
    .str('server.address', hostMatch ? hostMatch[1] : hostMarker)
    .int('server.port', port !== null && port <= 65535 ? port : null)
    .str('zn.secret.name', secret)
    .str('zn.secret.mode', inSet(GATE_MODES, r.mode))
    .int('zn.audit.version', nonNegInt(r.v === undefined || r.v === null ? 1 : r.v))
    .int('zn.audit.seq', nonNegInt(r.seq))
    .str('zn.audit.prev', ok(RE.hex64, r.prev, false))
    .str('zn.audit.mac', ok(RE.hex64, r.mac, false));
  const body = [
    decision || 'event',
    agent && `agent=${agent}`,
    tool && `tool=${tool}`,
    secret && `secret=${secret}`,
  ].filter(Boolean).join(' ');
  const t = unixNano(r.ts);
  return {
    timeUnixNano: t,
    observedTimeUnixNano: t,
    severityNumber: SEVERITY[gateSeverity(decision)],
    severityText: gateSeverity(decision),
    eventName: EVENT_GATE,
    body: { stringValue: body },
    // event.name also as an attribute, for backends that predate the eventName field.
    attributes: [{ key: 'event.name', value: { stringValue: EVENT_GATE } }, ...a.list],
  };
}

/** Resource for one zn-gate installation. Both ids are optional: a missing or malformed one is left out. */
function gateResource(ctx) {
  const a = new Attrs()
    .str('service.name', SERVICE_GATE)
    .str('service.instance.id', ok(RE.uuid, ctx.installId, false))
    .str('zn.org.id', ok(RE.orgId, ctx.orgId, false));
  return { attributes: a.list };
}

/**
 * Audit records (one installation) to OTLP/JSON Lines. Records are ordered by
 * seq (stable), so each prev is the previous mac. Empty input gives ''.
 */
function auditToOtlpJsonLines(records, opts) {
  const o = opts || {};
  const list = Array.isArray(records) ? records.filter((r) => r && typeof r === 'object') : [];
  if (!list.length) return '';
  const seq = (r) => (Number.isSafeInteger(r.seq) ? r.seq : 0);
  const sorted = [...list].sort((a, b) => seq(a) - seq(b));
  const logRecords = sorted.map(gateRecordToLog);
  const resource = gateResource({ installId: o.installId, orgId: o.orgId });
  const lines = [];
  for (let i = 0; i < logRecords.length; i += RECORDS_PER_LINE) {
    const req = {
      resourceLogs: [{
        resource,
        scopeLogs: [{
          scope: { name: SCOPE_NAME, version: SCOPE_VERSION },
          logRecords: logRecords.slice(i, i + RECORDS_PER_LINE),
        }],
      }],
    };
    lines.push(JSON.stringify(req));
  }
  return lines.join('\n') + '\n';
}

/* Same duration and date parsing as lib/vault/audit.js read(). */
function parseSince(since) {
  if (since === undefined || since === null || since === '') return null;
  if (since instanceof Date) return since.getTime();
  if (typeof since === 'number') return since;
  const m = /^(\d+)\s*(s|m|h|d)$/.exec(String(since));
  if (m) return Date.now() - Number(m[1]) * { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]];
  const t = Date.parse(String(since));
  if (Number.isNaN(t)) throw new Error('invalid since: ' + since);
  return t;
}

/**
 * exportAuditFile({auditFile, since, installId, orgId}) -> {content, records, sha256}
 * Reads the local log (missing file = no records). Lines that do not parse, or
 * have no valid timestamp, are skipped. `records` is the number of records
 * exported. `since` is an ISO date or a duration such as '7d' or '12h'.
 */
function exportAuditFile(opts) {
  const o = opts || {};
  const file = o.auditFile || require('../vault/store').paths(o).auditFile;
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (err) {
    if (err.code === 'ENOENT') text = ''; else throw err;
  }
  const from = parseSince(o.since);
  const records = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let rec;
    try { rec = JSON.parse(line); } catch (err) { continue; }
    if (!rec || typeof rec !== 'object') continue;
    const t = Date.parse(rec.ts);
    if (!Number.isFinite(t)) continue;
    if (from !== null && t < from) continue;
    records.push(rec);
  }
  const content = auditToOtlpJsonLines(records, { installId: o.installId, orgId: o.orgId });
  const sha256 = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  return { content, records: records.length, sha256 };
}

module.exports = { auditToOtlpJsonLines, exportAuditFile };
