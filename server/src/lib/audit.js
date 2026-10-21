// Append-only audit log. No raw IPs or secrets — only hashes and outcomes.
import { db, nowMs } from '../db/index.js';
import { randomId } from './tokens.js';

const ins = db.prepare(
  'INSERT INTO audit_log(id, ts, event, verification_id, domain, ip_hash, outcome, meta_json) VALUES(?,?,?,?,?,?,?,?)'
);

export function audit(event, { verificationId = null, domain = null, ipHash = null, outcome = null, meta = null } = {}) {
  try {
    ins.run(randomId(), nowMs(), event, verificationId, domain, ipHash, outcome, meta ? JSON.stringify(meta) : null);
  } catch {
    // Auditing must never break the request path.
  }
}
