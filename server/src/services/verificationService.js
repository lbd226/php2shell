// Verification lifecycle: create (email/dns), look up status, mark verified (single-use,
// atomic compare-and-set), and claim -> mint a single scan grant.
import { db, nowMs } from '../db/index.js';
import { config } from '../config.js';
import { randomId, randomSecret, makeSplitToken, sha256, matchesHash } from '../lib/tokens.js';
import { mintSync as mintGrant } from './grantService.js';

const ATTEMPT_CAP = 8;

const insStmt = db.prepare(`
  INSERT INTO verification(
    id, domain, method, email_address, selector, verifier_hash, dns_record_name, dns_token,
    claim_secret_hash, status, attempts, client_ip_hash, created_at, expires_at, send_count)
  VALUES(@id, @domain, @method, @email_address, @selector, @verifier_hash, @dns_record_name, @dns_token,
    @claim_secret_hash, 'pending', 0, @client_ip_hash, @created_at, @expires_at, @send_count)
`);
const byId = db.prepare('SELECT * FROM verification WHERE id = ?');
const bySelector = db.prepare('SELECT * FROM verification WHERE selector = ?');
const incAttemptsStmt = db.prepare('UPDATE verification SET attempts = attempts + 1 WHERE id = ?');
const verifyEmailStmt = db.prepare(
  "UPDATE verification SET status = 'verified', verified_at = ?, verifier_hash = NULL WHERE id = ? AND status = 'pending'"
);
const verifyDnsStmt = db.prepare(
  "UPDATE verification SET status = 'verified', verified_at = ? WHERE id = ? AND status = 'pending'"
);
const consumeStmt = db.prepare("UPDATE verification SET status = 'consumed' WHERE id = ? AND status = 'verified'");
const markSent = db.prepare('UPDATE verification SET last_sent_at = ?, send_count = send_count + 1 WHERE id = ?');
const expireStmt = db.prepare("UPDATE verification SET status = 'expired' WHERE status = 'pending' AND expires_at < ?");

export function getById(id) {
  return byId.get(id);
}

export function createEmail({ domain, emailAddress, ipHash }) {
  const now = nowMs();
  const claimSecret = randomSecret();
  const { selector, verifier, token, verifierHash } = makeSplitToken();
  const id = randomId();
  insStmt.run({
    id, domain, method: 'email', email_address: emailAddress,
    selector, verifier_hash: verifierHash, dns_record_name: null, dns_token: null,
    claim_secret_hash: sha256(claimSecret), client_ip_hash: ipHash,
    created_at: now, expires_at: now + config.ttl.emailMs, send_count: 0,
  });
  return { id, claimSecret, token, expiresAt: now + config.ttl.emailMs };
}

export function createDns({ domain, ipHash }) {
  const now = nowMs();
  const claimSecret = randomSecret();
  const dnsToken = randomSecret();
  const id = randomId();
  const recordName = `_php2shell-verify.${domain}`;
  insStmt.run({
    id, domain, method: 'dns', email_address: null,
    selector: null, verifier_hash: null, dns_record_name: recordName, dns_token: dnsToken,
    claim_secret_hash: sha256(claimSecret), client_ip_hash: ipHash,
    created_at: now, expires_at: now + config.ttl.dnsMs, send_count: 0,
  });
  return { id, claimSecret, recordName, value: `php2shell-verify=${dnsToken}`, expiresAt: now + config.ttl.dnsMs };
}

export function recordSent(id) {
  markSent.run(nowMs(), id);
}

export function getBySelector(selector) {
  return bySelector.get(selector);
}

export function incAttempts(id) {
  incAttemptsStmt.run(id);
}

// Email confirm: look up by selector, timing-safe verify, single-use consume.
export function markVerifiedByEmail(selector, verifier) {
  const row = bySelector.get(selector);
  if (!row || row.method !== 'email') return { ok: false, reason: 'invalid' };
  if (row.status !== 'pending') return { ok: false, reason: row.status === 'pending' ? 'invalid' : 'used' };
  if (row.expires_at < nowMs()) return { ok: false, reason: 'expired' };
  if (row.attempts >= ATTEMPT_CAP) return { ok: false, reason: 'locked' };
  if (!matchesHash(verifier, row.verifier_hash)) {
    incAttemptsStmt.run(row.id);
    return { ok: false, reason: 'invalid' };
  }
  const r = verifyEmailStmt.run(nowMs(), row.id);
  if (r.changes !== 1) return { ok: false, reason: 'used' };
  return { ok: true, id: row.id, domain: row.domain };
}

export function markVerifiedDns(id) {
  return verifyDnsStmt.run(nowMs(), id).changes === 1;
}

// Status lookup gated by the claimSecret bound to the originating session.
export function statusFor(id, claimSecret) {
  const row = byId.get(id);
  if (!row) return null;
  if (!matchesHash(claimSecret, row.claim_secret_hash)) return null;
  return { status: row.status, method: row.method, verifiedAt: row.verified_at };
}

// Exchange a verified verification for exactly one scan grant. Atomic.
export function claim(id, claimSecret) {
  const txn = db.transaction(() => {
    const v = byId.get(id);
    if (!v) return { error: 'not_found', status: 404 };
    // Uniform response for a wrong secret: do not reveal existence/state.
    if (!matchesHash(claimSecret, v.claim_secret_hash)) return { error: 'not_found', status: 404 };
    if (v.status === 'consumed') return { error: 'already_claimed', status: 409 };
    if (v.status !== 'verified') return { error: 'not_verified', status: 409 };
    const flip = consumeStmt.run(id);
    if (flip.changes !== 1) return { error: 'already_claimed', status: 409 };
    const grant = mintGrant({ verificationId: id, domain: v.domain });
    return { grant };
  });
  return txn();
}

export function expireStale() {
  return expireStmt.run(nowMs()).changes;
}
