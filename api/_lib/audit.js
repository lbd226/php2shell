// Append-only audit list (capped). No raw IPs or secrets — only hashes and outcomes.
import { redis } from './redis.js';

export async function audit(event, { verificationId = null, domain = null, ipHash = null, outcome = null, meta = null } = {}) {
  try {
    await redis.lpush('audit', JSON.stringify({ event, ts: Date.now(), verificationId, domain, ipHash, outcome, meta }));
    await redis.ltrim('audit', 0, 9999);
  } catch {
    // Auditing must never break the request path.
  }
}
