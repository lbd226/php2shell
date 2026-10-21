import { tokens, resolveTxt } from '../core.js';
import * as verification from './verification.js';

export async function start({ domain }) {
  const v = await verification.createDns({ domain });
  return {
    verificationId: v.id,
    claimSecret: v.claimSecret,
    method: 'dns',
    record: { name: v.recordName, type: 'TXT', value: v.value },
    ttlHint: 300,
    expiresAt: v.expiresAt,
  };
}

export async function check(verificationId) {
  const v = await verification.getById(verificationId);
  if (!v || v.method !== 'dns') return { status: 'not_found', found: false };
  if (v.status === 'verified' || v.status === 'consumed') return { status: 'verified', found: true };
  if (v.status !== 'pending') return { status: v.status, found: false };

  const expected = `php2shell-verify=${v.dnsToken}`;
  let values = [];
  try { values = await resolveTxt(v.recordName); }
  catch { return { status: 'pending', found: false, error: 'dns_error' }; }

  let found = false;
  for (const val of values) {
    if (tokens.constantTimeEqual(String(val).trim(), expected)) { found = true; break; }
  }
  if (found) {
    await verification.markVerifiedDns(verificationId);
    return { status: 'verified', found: true };
  }
  return { status: 'pending', found: false };
}
