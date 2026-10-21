// DNS TXT ownership challenge: issue a random per-domain record, then resolve + constant-time
// compare to confirm. Scoped to exactly the host whose _php2shell-verify.<host> was checked.
import { nowMs } from '../db/index.js';
import { resolveTxt } from '../lib/dnsResolver.js';
import { constantTimeEqual } from '../lib/tokens.js';
import * as verifications from './verificationService.js';

export function start({ domain, ipHash }) {
  const v = verifications.createDns({ domain, ipHash });
  return {
    verificationId: v.id,
    claimSecret: v.claimSecret,
    method: 'dns',
    record: { name: v.recordName, type: 'TXT', value: v.value },
    ttlHint: 300,
    expiresAt: v.expiresAt,
  };
}

// Returns { status, found, attempts }.
export async function check(verificationId) {
  const row = verifications.getById(verificationId);
  if (!row || row.method !== 'dns') return { status: 'not_found', found: false, attempts: 0 };
  if (row.status === 'verified' || row.status === 'consumed') {
    return { status: 'verified', found: true, attempts: row.attempts };
  }
  if (row.status !== 'pending') return { status: row.status, found: false, attempts: row.attempts };
  if (row.expires_at < nowMs()) return { status: 'expired', found: false, attempts: row.attempts };

  verifications.incAttempts(verificationId);

  const expected = `php2shell-verify=${row.dns_token}`;
  let values = [];
  try {
    values = await resolveTxt(row.dns_record_name);
  } catch {
    return { status: 'pending', found: false, attempts: row.attempts + 1, error: 'dns_error' };
  }

  // Compare every returned string in constant time; ignore wildcard noise by exact match only.
  let found = false;
  for (const val of values) {
    if (constantTimeEqual(val.trim(), expected)) { found = true; break; }
  }

  if (found) {
    verifications.markVerifiedDns(verificationId);
    return { status: 'verified', found: true, attempts: row.attempts + 1 };
  }
  return { status: 'pending', found: false, attempts: row.attempts + 1 };
}
