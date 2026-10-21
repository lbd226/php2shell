// SQLite-backed fixed-window rate limiter. Survives restarts and works across workers that
// share the DB file. All limits fail-closed (a DB error throws and the caller rejects).
import { db, nowMs } from '../db/index.js';

const getStmt = db.prepare('SELECT window_start AS windowStart, count, prev_count AS prevCount FROM rate_bucket WHERE key = ?');
const setStmt = db.prepare('INSERT OR REPLACE INTO rate_bucket(key, window_start, count, prev_count) VALUES(?, ?, ?, ?)');
const incStmt = db.prepare('UPDATE rate_bucket SET count = count + 1 WHERE key = ?');

// Sliding-window counter: estimate = prevWindowCount * overlapFraction + currentWindowCount.
// This closes the ~2x burst a plain fixed window permits across the window boundary.
// Returns { allowed, remaining, resetMs }. Counts this call when allowed.
export function hit(key, limit, windowMs) {
  const now = nowMs();
  const windowStart = Math.floor(now / windowMs) * windowMs;
  const overlap = (windowMs - (now - windowStart)) / windowMs; // share of previous window still in view
  const txn = db.transaction(() => {
    const row = getStmt.get(key);
    let prevCount = 0;
    let curCount = 0;
    let where = 'new';
    if (row && row.windowStart === windowStart) { prevCount = row.prevCount; curCount = row.count; where = 'same'; }
    else if (row && row.windowStart === windowStart - windowMs) { prevCount = row.count; where = 'adjacent'; }

    const estimate = prevCount * overlap + curCount;
    if (estimate >= limit) {
      return { allowed: false, remaining: 0 };
    }
    if (where === 'same') incStmt.run(key);
    else if (where === 'adjacent') setStmt.run(key, windowStart, 1, prevCount);
    else setStmt.run(key, windowStart, 1, 0);
    return { allowed: true, remaining: Math.max(0, Math.floor(limit - estimate - 1)) };
  });
  const r = txn();
  return { ...r, resetMs: windowStart + windowMs };
}

// Convenience: throw a typed 429 when over budget.
export class RateLimitError extends Error {
  constructor(resetMs) {
    super('rate limit exceeded');
    this.name = 'RateLimitError';
    this.status = 429;
    this.code = 'rate_limited';
    this.resetMs = resetMs;
  }
}

export function enforce(key, limit, windowMs) {
  const r = hit(key, limit, windowMs);
  if (!r.allowed) throw new RateLimitError(r.resetMs);
  return r;
}
