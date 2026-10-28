'use strict';
/**
 * Did a `teamSync` result do its job? A sync is complete only when a valid
 * policy is applied (downloaded now, or confirmed still current) and the
 * pending audit records were uploaded or there was nothing to upload.
 *
 * Shared by `zn team join`, `zn team sync` (exit codes) and the vault daemon
 * (the last sync result shown by `zn team status`).
 *
 *   syncOutcome(result) -> { ok, policyOk, problems: [plain-English strings] }
 */

const POLICY_OK = new Set(['updated', 'current']);
const UPLOAD_FAILED = new Set(['offline', 'revoked', 'inactive', 'rejected', 'diverged', 'local_gap', 'error', 'tampered']);

const short = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n);

function policyProblem(pol) {
  switch (pol.status) {
    case 'none': return 'the organization has not published a policy yet';
    case 'rejected': return 'the downloaded policy was refused' + (pol.error ? ' (' + short(pol.error, 120) + ')' : '');
    case 'revoked': return 'this machine was removed from the organization';
    case 'offline': return 'could not reach the server' + (pol.error ? ' (' + short(pol.error, 60) + ')' : '');
    case 'stopped': return 'the vault was locked before the sync finished';
    case 'stale': return 'this machine left or changed its organization while the sync was running; nothing was applied';
    default: return 'the policy state is unknown (' + short(pol.status, 40) + ')';
  }
}

function syncOutcome(result) {
  const r = result && typeof result === 'object' ? result : {};
  const problems = [];
  const pol = r.policy && typeof r.policy === 'object' ? r.policy : null;
  const policyOk = Boolean(pol) && POLICY_OK.has(pol.status);
  if (!pol) problems.push('the sync did not report a policy state');
  else if (!policyOk) problems.push(policyProblem(pol));
  const up = r.upload && typeof r.upload === 'object' ? r.upload : null;
  if (up && up.status === 'stale') {
    problems.push('audit upload stopped: this machine left or changed its organization while it was running');
  } else if (up && UPLOAD_FAILED.has(up.status)) {
    problems.push('audit upload failed (' + short(up.status, 20) + (up.pending > 0 ? ', ' + up.pending + ' records pending' : '') + ')');
  }
  return { ok: problems.length === 0, policyOk, problems };
}

module.exports = { syncOutcome };
