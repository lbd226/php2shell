// Upstash Redis over HTTP — ideal for serverless (no TCP pooling). Reads
// UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN from the environment.
import { Redis } from '@upstash/redis';

export const redis = Redis.fromEnv();

export const hex = (buf) => Buffer.from(buf).toString('hex');
export const fromHex = (h) => Buffer.from(h, 'hex');
export const toSec = (ms) => Math.max(1, Math.ceil(ms / 1000));
