// Scan grants: one per proven ownership, short-lived, use-capped, revocable. A grant is the
// ONLY thing that authorizes a scan, and it carries the bound domain — the scan target is
// read from the grant, never from client input.
import { db, nowMs } from '../db/index.js';
import { config } from '../config.js';
import { randomId, makeSplitToken, parseSplitToken, matchesHash } from '../lib/tokens.js';

const insStmt = db.prepare(`
  INSERT INTO scan_grant(id, verification_id, domain, selector, token_hash, status, max_uses, used_count, created_at, expires_at)
  VALUES(@id, @verification_id, @domain, @selector, @token_hash, 'active', @max_uses, 0, @created_at, @expires_at)
`);
const getBySelector = db.prepare('SELECT * FROM scan_grant WHERE selector = ?');
const incUse = db.prepare("UPDATE scan_grant SET used_count = used_count + 1 WHERE id = ? AND status = 'active' AND used_count < max_uses");
const exhaust = db.prepare("UPDATE scan_grant SET status = 'exhausted' WHERE id = ? AND used_count >= max_uses");
const expireStmt = db.prepare("UPDATE scan_grant SET status = 'expired' WHERE status = 'active' AND expires_at < ?");

export class GrantError extends Error {
  constructor(message, status = 401, code = 'invalid_grant') {
    super(message);
    this.name = 'GrantError';
    this.status = status;
    this.code = code;
  }
}

// Synchronous — intended to run inside the claim transaction.
export function mintSync({ verificationId, domain }) {
  const now = nowMs();
  const { selector, verifier, token, verifierHash } = makeSplitToken();
  insStmt.run({
    id: randomId(),
    verification_id: verificationId,
    domain,
    selector,
    token_hash: verifierHash,
    max_uses: config.GRANT_MAX_USES,
    created_at: now,
    expires_at: now + config.ttl.grantMs,
  });
  return { token, selector, expiresAt: now + config.ttl.grantMs, maxUses: config.GRANT_MAX_USES, domain };
}

// Validate a Bearer grant token. Returns the grant row or throws GrantError.
export function validateBearer(token) {
  const parsed = parseSplitToken(token);
  if (!parsed) throw new GrantError('malformed grant', 401);
  const row = getBySelector.get(parsed.selector);
  if (!row) throw new GrantError('unknown grant', 401);
  if (!matchesHash(parsed.verifier, row.token_hash)) throw new GrantError('unknown grant', 401);
  if (row.status !== 'active') throw new GrantError('grant no longer usable', 410, 'grant_inactive');
  if (row.expires_at < nowMs()) throw new GrantError('grant expired', 410, 'grant_expired');
  if (row.used_count >= row.max_uses) throw new GrantError('grant exhausted', 410, 'grant_exhausted');
  return row;
}

// Resolve a grant by token for READ-ONLY access (any status), to fetch a stored result.
export function resolveGrant(token) {
  const parsed = parseSplitToken(token);
  if (!parsed) return null;
  const row = getBySelector.get(parsed.selector);
  if (!row) return null;
  if (!matchesHash(parsed.verifier, row.token_hash)) return null;
  return row;
}

// Atomically consume one use; marks exhausted when the cap is reached.
export function consumeUse(grantId) {
  const txn = db.transaction(() => {
    const r = incUse.run(grantId);
    if (r.changes !== 1) return false;
    exhaust.run(grantId);
    return true;
  });
  return txn();
}

export function expireStale() {
  return expireStmt.run(nowMs()).changes;
}
