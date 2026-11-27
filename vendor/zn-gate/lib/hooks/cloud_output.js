'use strict';

/*
 * The one hook-side file that can reach the zn cloud: it asks the cloud check about a sample of tool output (see
 * cloudOutputNote in runner.js, which decides whether to ask and what to send). Kept apart so the rule "no other hook,
 * shield or scrubber module reads the stored key or the cloud settings" stays easy to test (test/connect.test.js).
 *
 * Personal data (email, phone, IBAN, card number) is replaced with [EMAIL], [PHONE], [IBAN], [CARD] after the secrets.
 * It sends nothing unless the person ran zn-gate connect (the saved key; no
 * environment variable counts) and ZN_LOCAL_ONLY is not set. analyze() applies the prompt check's own steps: the local rules first, the secret
 * redaction before the request, the same timeouts and the same fallback to the local rules when the call fails.
 * pinOrigin keeps the key and the text on the fixed zn origin: an environment variable of the agent (a project can set
 * it) cannot point them elsewhere, and a TLS setting that weakens the check stops the request.
 */

// The cap on what is sent, in UTF-8 bytes (not characters): the first CLOUD_HEAD bytes, a marker, and the last bytes
// that fit under CLOUD_MAX. A cut never splits a multi-byte character: a partial one at a cut is dropped. The word
// cut at each edge is dropped too (back to the nearest space or line break, if one is within EDGE_WORD bytes), so a
// placeholder is never sent half cut.
const CLOUD_MAX = 16 * 1024;
const CLOUD_HEAD = 12 * 1024;
const CLOUD_TAIL = CLOUD_MAX - CLOUD_HEAD;
const CUT_MARK = '\n[...]\n';
const EDGE_WORD = 64;
// Redaction runs before any cut. A long output is not redacted whole (that costs hundreds of milliseconds on a few
// MB): the head and the tail are redacted in windows WINDOW_MARGIN characters wider than what is kept from them. A
// window's inner edge can split a value, which the detectors then miss; the margin keeps that edge far from the cut.
// It is longer than any value the detectors match in practice (a JWT is at most about 13,000 characters, a phone
// number, IBAN, card number or e-mail address far less).
const WINDOW_MARGIN = 64 * 1024;

const isSpace = (b) => b === 0x20 || b === 0x0A || b === 0x09 || b === 0x0D;

function trimToBytes(text) {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= CLOUD_MAX) return text;
  const mark = Buffer.byteLength(CUT_MARK);
  let headEnd = CLOUD_HEAD;
  while (headEnd > 0 && (buf[headEnd] & 0xC0) === 0x80) headEnd--;
  for (let i = headEnd; i > 0 && i > headEnd - EDGE_WORD; i--) {
    if (isSpace(buf[i])) { headEnd = i; break; }
  }
  let tailStart = buf.length - (CLOUD_TAIL - mark);
  while (tailStart < buf.length && (buf[tailStart] & 0xC0) === 0x80) tailStart++;
  for (let i = tailStart - 1; i < buf.length && i < tailStart + EDGE_WORD; i++) {
    if (isSpace(buf[i])) { tailStart = i + 1; break; }
  }
  return buf.subarray(0, headEnd).toString('utf8') + CUT_MARK + buf.subarray(tailStart).toString('utf8');
}

/*
 * The text sent for `text`: secrets and personal data replaced first, then the cap. Returns null when that cannot be
 * done safely (the caller then sends nothing). Throws when the redaction fails (the caller sends nothing).
 */
function cloudSample(text) {
  const headLen = CLOUD_HEAD + WINDOW_MARGIN;
  const tailLen = CLOUD_TAIL + WINDOW_MARGIN;
  // Placeholders can be longer than what they replace, so the cap is applied to the redacted text.
  if (text.length <= headLen + tailLen) return trimToBytes(redactForCloud(text));
  const head = redactForCloud(text.slice(0, headLen));
  const tail = redactForCloud(text.slice(text.length - tailLen));
  // The cut keeps at most CLOUD_HEAD bytes (so characters) of the head and CLOUD_TAIL of the tail. When redaction
  // shortened a window so much that less than half the margin is left past the cut, the window's raw edge could come
  // within reach of it: nothing is sent.
  if (head.length < CLOUD_HEAD + WINDOW_MARGIN / 2 || tail.length < CLOUD_TAIL + WINDOW_MARGIN / 2) return null;
  return trimToBytes(head + '\n' + tail);
}

// Personal data kinds removed from the sample before it leaves the machine (the scrubber's own detectors, so the
// checks that already decide what counts as an email, a phone number, an IBAN or a card number are the ones used here).
// National ID numbers (Spanish DNI and NIE, US SSN) are replaced too. IPv4 addresses, names, postal addresses and usernames are not
// (docs/connect.md says so).
const PII_ONLY = { email: true, phone: true, iban: true, card: true, dni: true, ssn: true, ipv4: false, name: false, address: false, username: false };
const PII_PLACEHOLDER = { EMAIL: '[EMAIL]', PHONE: '[PHONE]', IBAN: '[IBAN]', CARD: '[CARD]', DNI: '[ID]', NIE: '[ID]', SSN: '[ID]' };

/* The text with secrets and then personal data replaced. Throws when it cannot: the caller then sends nothing. */
function redactForCloud(sample) {
  const secrets = require('../rules').redactSecrets(sample);
  if (!secrets || typeof secrets.sanitized !== 'string') throw new Error('redaction failed');
  let text = secrets.sanitized;
  const spans = require('../scrub/patterns').findPii(text, { pii: PII_ONLY })
    .filter((s) => PII_PLACEHOLDER[s.type])
    .sort((a, b) => a.start - b.start || b.end - a.end);
  let out = '';
  let last = 0;
  for (const s of spans) {
    if (s.start < last) continue;
    out += text.slice(last, s.start) + PII_PLACEHOLDER[s.type];
    last = s.end;
  }
  return out + text.slice(last);
}

/** The analyze() result for the sample, or null when the cloud check is off or nothing could be asked. */
async function ask(sample, timeoutMs) {
  // Cheap test before the client is loaded: nothing of it runs unless the person ran `zn-gate connect`. isConnectedAtUserHome is
  // the only thing this file takes from cloud-key (test/connect.test.js holds it to that): it never reads the key.
  // The environment never turns this path on (no variable does): a project can put variables in the agent's
  // environment, and every tool result would then go out under a key it chose.
  // Judged from the operating-system account's home folder only (os.userInfo()), never from a folder the agent's
  // environment names (HOME, USERPROFILE or the zn folder override).
  const { isConnectedAtUserHome } = require('../cloud-key');
  if (!isConnectedAtUserHome()) return null;
  const client = require('../client');
  if (!client.isCloudEnabled({ storedOnly: true })) return null;
  // Secrets, then personal data, are replaced before the text is cut and before the request is built; if that fails
  // nothing is sent. A cut made before the redaction could split a value so that the detectors miss the part sent.
  const clean = cloudSample(sample);
  if (typeof clean !== 'string' || clean.length < 16) return null;
  return client.analyze(clean, { pinOrigin: true, storedOnly: true, timeout: timeoutMs });
}

module.exports = { ask, cloudSample, redactForCloud, trimToBytes };
