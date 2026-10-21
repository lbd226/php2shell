// Sliding-window rate limits backed by Upstash (atomic, serverless-safe).
import { Ratelimit } from '@upstash/ratelimit';
import { redis } from './redis.js';

const mk = (tokens, window) =>
  new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(tokens, window), prefix: 'p2s_rl', analytics: false });

export const limiters = {
  ipVerify: mk(10, '10 m'),   // verification starts per client IP
  domainEmail: mk(5, '60 m'), // emails per domain
  rcptEmail: mk(3, '60 m'),   // emails per recipient
  domainDns: mk(10, '60 m'),  // dns starts per domain
  dnsCheck: mk(1, '5 s'),     // dns checks per verification
  domainScan: mk(10, '60 m'), // scans per domain
  ipScan: mk(20, '60 m'),     // scans per client IP
};

export async function enforce(limiter, key) {
  const r = await limiter.limit(key);
  if (!r.success) {
    const e = new Error('rate limit exceeded');
    e.status = 429;
    e.code = 'rate_limited';
    e.resetMs = r.reset;
    throw e;
  }
}
