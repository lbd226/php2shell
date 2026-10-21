// SQLite-backed fixed-window rate limiter. Survives restarts and works across workers that
// share the DB file. All limits fail-closed (a DB error throws and the caller rejects).
import { db, nowMs } from '../db/index.js';

const getStmt = db.prepare('SELECT window_start AS windowStart, count FROM rate_bucket WHERE key = ?');
const insStmt = db.prepare('INSERT OR REPLACE INTO rate_bucket(key, window_start, count) VALUES(?, ?, ?)');
const incStmt = db.prepare('UPDATE rate_bucket SET count = count + 1 WHERE key = ?');

// Returns { allowed, remaining, resetMs }. Counts this call when allowed.
export function hit(key, limit, windowMs) {
  const now = nowMs();
  const windowStart = Math.floor(now / windowMs) * windowMs;
  const txn = db.transaction(() => {
    const row = getStmt.get(key);
    if (!row || row.windowStart !== windowStart) {
      insStmt.run(key, windowStart, 1);
      return { allowed: true, remaining: limit - 1 };
    }
    if (row.count >= limit) {
      return { allowed: false, remaining: 0 };
    }
    incStmt.run(key);
    return { allowed: true, remaining: limit - row.count - 1 };
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
