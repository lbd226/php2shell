// Cryptographic token helpers. Every secret comes from a CSPRNG and is compared in constant time.
import crypto from 'node:crypto';
import { config } from '../config.js';

// 128-bit random capability id (verification id).
export function randomId() {
  return crypto.randomBytes(16).toString('base64url');
}

// 256-bit secret, url-safe.
export function randomSecret() {
  return crypto.randomBytes(32).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

// Constant-time compare of a presented value against a stored SHA-256 digest (Buffer).
export function matchesHash(presented, storedHashBuf) {
  if (!storedHashBuf) return false;
  const a = sha256(presented);
  const b = Buffer.isBuffer(storedHashBuf) ? storedHashBuf : Buffer.from(storedHashBuf);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Split token: `<selector>.<verifier>`. Selector is a public 128-bit lookup key;
// verifier is a 256-bit secret whose SHA-256 is stored. Enables O(1) lookup without
// scanning, while the DB never holds a usable secret.
export function makeSplitToken() {
  const selector = crypto.randomBytes(16).toString('base64url');
  const verifier = crypto.randomBytes(32).toString('base64url');
  return { selector, verifier, token: `${selector}.${verifier}`, verifierHash: sha256(verifier) };
}

export function parseSplitToken(token) {
  if (typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;
  const selector = token.slice(0, dot);
  const verifier = token.slice(dot + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(selector) || !/^[A-Za-z0-9_-]+$/.test(verifier)) return null;
  return { selector, verifier };
}

// HMAC a client IP before storing, so no raw IPs live at rest.
export function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHmac('sha256', config.IP_HASH_KEY).update(String(ip)).digest('base64url').slice(0, 24);
}

// Constant-time string equality (for DNS TXT value comparison).
export function constantTimeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // Compare against self to keep timing uniform, then fail.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}
