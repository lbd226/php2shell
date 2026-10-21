// Bounded DNS resolution over an optionally-trusted resolver, with timeouts.
import { Resolver } from 'node:dns/promises';
import { config } from '../config.js';

const RESOLVE_TIMEOUT_MS = 4000;

function withTimeout(promise, ms, label) {
  let t;
  const timeout = new Promise((_, reject) => {
    t = setTimeout(() => reject(new Error(`${label} lookup timed out`)), ms);
    if (t.unref) t.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

function makeResolver() {
  const r = new Resolver({ timeout: RESOLVE_TIMEOUT_MS, tries: 2 });
  if (config.resolverIps.length) r.setServers(config.resolverIps);
  return r;
}

// Resolve all A (and, unless disabled, AAAA) addresses for a host.
export async function resolveAll(domain) {
  const r = makeResolver();
  const out = [];
  const [v4, v6] = await Promise.allSettled([
    withTimeout(r.resolve4(domain), RESOLVE_TIMEOUT_MS, 'A'),
    config.SCAN_DISABLE_IPV6
      ? Promise.resolve([])
      : withTimeout(r.resolve6(domain), RESOLVE_TIMEOUT_MS, 'AAAA'),
  ]);
  if (v4.status === 'fulfilled') for (const ip of v4.value) out.push({ ip, family: 4 });
  if (v6.status === 'fulfilled') for (const ip of v6.value) out.push({ ip, family: 6 });
  return out;
}

// Resolve TXT for a name; returns an array of joined strings. Missing record => [].
export async function resolveTxt(name) {
  const r = makeResolver();
  try {
    const records = await withTimeout(r.resolveTxt(name), RESOLVE_TIMEOUT_MS, 'TXT');
    return records.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
  } catch (e) {
    if (e && (e.code === 'ENOTFOUND' || e.code === 'ENODATA')) return [];
    throw e;
  }
}
