// Scan grants in Redis: one per proven ownership, short-lived (TTL), use-capped. The grant
// carries the bound domain; the scan target is read from the grant, never client input.
import { config, tokens } from '../core.js';
import { redis, hex, fromHex, toSec } from '../redis.js';

export async function mint({ verificationId, domain }) {
  const { selector, verifier, token, verifierHash } = tokens.makeSplitToken();
  const id = tokens.randomId();
  const rec = { id, verificationId, domain, tokenHash: hex(verifierHash), maxUses: config.GRANT_MAX_USES, createdAt: Date.now() };
  await redis.set(`g:${selector}`, rec, { ex: toSec(config.ttl.grantMs) });
  return { token, domain, maxUses: config.GRANT_MAX_USES, expiresAt: Date.now() + config.ttl.grantMs };
}

function err(message, status, code) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

export async function validateBearer(token) {
  const p = tokens.parseSplitToken(token);
  if (!p) throw err('malformed grant', 401, 'invalid_grant');
  const g = await redis.get(`g:${p.selector}`);
  if (!g || !tokens.matchesHash(p.verifier, fromHex(g.tokenHash))) throw err('unknown grant', 401, 'invalid_grant');
  const used = Number(await redis.get(`guses:${g.id}`)) || 0;
  if (used >= g.maxUses) throw err('grant exhausted', 410, 'grant_exhausted');
  return g;
}

// Read-only resolve (any state), for fetching a stored result.
export async function resolveGrant(token) {
  const p = tokens.parseSplitToken(token);
  if (!p) return null;
  const g = await redis.get(`g:${p.selector}`);
  if (!g) return null;
  if (!tokens.matchesHash(p.verifier, fromHex(g.tokenHash))) return null;
  return g;
}

// Atomic use count via INCR; returns false once the cap is exceeded.
export async function consumeUse(grantId, maxUses) {
  const n = await redis.incr(`guses:${grantId}`);
  if (n === 1) await redis.expire(`guses:${grantId}`, toSec(config.ttl.grantMs));
  return n <= maxUses;
}
