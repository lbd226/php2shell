// Upstash Redis over HTTP — ideal for serverless (no TCP pooling). Reads
// UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN from the environment.
import { Redis } from '@upstash/redis';

// The Vercel "Upstash for Redis" marketplace integration injects KV_REST_API_URL /
// KV_REST_API_TOKEN; a raw Upstash store uses UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN.
// Support both so the same code runs regardless of how the store was connected.
const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

export const redis = new Redis({ url, token });

export const hex = (buf) => Buffer.from(buf).toString('hex');
export const fromHex = (h) => Buffer.from(h, 'hex');
export const toSec = (ms) => Math.max(1, Math.ceil(ms / 1000));
