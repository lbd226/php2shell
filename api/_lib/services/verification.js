// Verification lifecycle in Redis. TTL handles expiry (no sweep needed); verified rows are
// re-set with the grant TTL so they cannot linger. Claim is made atomic with a SET NX lock.
import { config, tokens } from '../core.js';
import { redis, hex, fromHex, toSec } from '../redis.js';
import * as grant from './grant.js';

export async function createEmail({ domain, emailAddress }) {
  const id = tokens.randomId();
  const { selector, verifier, token, verifierHash } = tokens.makeSplitToken();
  const claimSecret = tokens.randomSecret();
  const rec = {
    domain, method: 'email', emailAddress, selector,
    verifierHash: hex(verifierHash), claimHash: hex(tokens.sha256(claimSecret)),
    status: 'pending', createdAt: Date.now(),
  };
  const ttl = toSec(config.ttl.emailMs);
  await redis.set(`v:${id}`, rec, { ex: ttl });
  await redis.set(`vsel:${selector}`, id, { ex: ttl });
  return { id, claimSecret, token, expiresAt: Date.now() + config.ttl.emailMs };
}

export async function createDns({ domain }) {
  const id = tokens.randomId();
  const dnsToken = tokens.randomSecret();
  const claimSecret = tokens.randomSecret();
  const recordName = `_php2shell-verify.${domain}`;
  const rec = {
    domain, method: 'dns', dnsToken, recordName,
    claimHash: hex(tokens.sha256(claimSecret)), status: 'pending', createdAt: Date.now(),
  };
  await redis.set(`v:${id}`, rec, { ex: toSec(config.ttl.dnsMs) });
  return { id, claimSecret, recordName, value: `php2shell-verify=${dnsToken}`, expiresAt: Date.now() + config.ttl.dnsMs };
}

export async function getById(id) {
  return redis.get(`v:${id}`);
}

export async function statusFor(id, claimSecret) {
  const v = await redis.get(`v:${id}`);
  if (!v) return null;
  if (!tokens.matchesHash(claimSecret, fromHex(v.claimHash))) return null;
  return { status: v.status, method: v.method, verifiedAt: v.verifiedAt || null };
}

export async function markVerifiedByEmail(selector, verifier) {
  const id = await redis.get(`vsel:${selector}`);
  if (!id) return { ok: false, reason: 'invalid' };
  // Serialize confirm so a replay cannot double-process the same selector.
  const lock = await redis.set(`vcl:${selector}`, 1, { nx: true, ex: 30 });
  if (!lock) return { ok: false, reason: 'used' };
  const v = await redis.get(`v:${id}`);
  if (!v || v.method !== 'email') return { ok: false, reason: 'invalid' };
  if (v.status !== 'pending') return { ok: false, reason: 'used' };
  if (!v.verifierHash || !tokens.matchesHash(verifier, fromHex(v.verifierHash))) return { ok: false, reason: 'invalid' };
  const confirmSecret = tokens.randomSecret();
  v.status = 'verified';
  v.verifiedAt = Date.now();
  v.verifierHash = null;
  v.confirmHash = hex(tokens.sha256(confirmSecret));
  await redis.set(`v:${id}`, v, { ex: toSec(config.ttl.grantMs) }); // verified rows expire after grant TTL
  await redis.del(`vsel:${selector}`); // single-use
  return { ok: true, id, domain: v.domain, confirmSecret };
}

export async function markVerifiedDns(id) {
  const v = await redis.get(`v:${id}`);
  if (!v || v.method !== 'dns' || v.status !== 'pending') return false;
  v.status = 'verified';
  v.verifiedAt = Date.now();
  await redis.set(`v:${id}`, v, { ex: toSec(config.ttl.grantMs) });
  return true;
}

// Exchange a verified verification for exactly one grant. Atomic via a SET NX lock.
export async function claim(id, secret) {
  const v = await redis.get(`v:${id}`);
  if (!v) return { error: 'not_found', status: 404 };
  // Email is claimed with the confirm-time secret (held by the clicker); DNS with the
  // start-time claimSecret (held by the prover, who is the same party).
  const expected = v.method === 'email' ? v.confirmHash : v.claimHash;
  if (!expected || !tokens.matchesHash(secret, fromHex(expected))) return { error: 'not_found', status: 404 };
  if (v.status === 'consumed') return { error: 'already_claimed', status: 409 };
  if (v.status !== 'verified') return { error: 'not_verified', status: 409 };
  const lock = await redis.set(`grantlock:${id}`, 1, { nx: true, ex: toSec(config.ttl.grantMs) });
  if (!lock) return { error: 'already_claimed', status: 409 };
  v.status = 'consumed';
  await redis.set(`v:${id}`, v, { ex: toSec(config.ttl.grantMs) });
  const g = await grant.mint({ verificationId: id, domain: v.domain });
  return { grant: g };
}
