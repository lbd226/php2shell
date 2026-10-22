// Link-preview helper: resolves an allowlisted article URL to its Open Graph
// image, Vercel-side (these hosts are reachable from the serverless runtime),
// caches the result in Redis, and 302-redirects the browser to the image.
// Returns 404 when the page has no usable image, so the client can fall back
// to a monogram tile. Only reputable, hardcoded security/tech/news domains are
// fetchable — this is not an open proxy.
import { Router } from 'express';
import crypto from 'node:crypto';
import { redis } from '../redis.js';

const r = Router();

// Registrable domains we will fetch a preview for (host must equal one or be a subdomain).
const ALLOWED = [
  'watchtowr.com', 'huntress.com', 'jfrog.com', 'crowdstrike.com', 'tenable.com',
  'cloudflare.com', 'wiz.io', 'securityweek.com', 'bleepingcomputer.com', 'thehackernews.com',
  'helpnetsecurity.com', 'heise.de', 'cybernews.com', 'cyberkendra.com', 'php.net',
  'nist.gov', 'github.com', 'csa.gov.sg', 'rapid7.com', 'sansec.io', 'socradar.io',
  'imunify360.com', 'plesk.com', 'paloaltonetworks.com', 'cloud.google.com', 'theregister.com',
  'arstechnica.com', 'zdnet.com', 'darkreading.com', 'cybersecuritynews.com', 'abstract.security',
  'brandefense.io', 'upwind.io', 'patchmon.net', 'pentestit.com', 'safeguard.sh',
  'secureinseconds.com', 'qualys.com', 'sucuri.net', 'wordfence.com', 'cisa.gov',
];

const hostAllowed = (h) => {
  h = String(h).toLowerCase();
  return ALLOWED.some((d) => h === d || h.endsWith('.' + d));
};

function extractOg(html, baseUrl) {
  const head = html.slice(0, 250000);
  const metas = head.match(/<meta[^>]+>/gi) || [];
  for (const m of metas) {
    if (/(?:property|name)\s*=\s*["'](?:og:image(?::secure_url)?|twitter:image(?::src)?)["']/i.test(m)) {
      const c = m.match(/content\s*=\s*["']([^"']+)["']/i);
      if (c && c[1]) {
        try {
          const abs = new URL(c[1].trim(), baseUrl);
          if (abs.protocol === 'https:' || abs.protocol === 'http:') return abs.href;
        } catch {
          /* ignore malformed */
        }
      }
    }
  }
  return null;
}

r.get('/og', async (req, res) => {
  let parsed;
  try {
    parsed = new URL(String(req.query.u || ''));
  } catch {
    return res.status(400).json({ error: 'bad_url' });
  }
  if (parsed.protocol !== 'https:' || !hostAllowed(parsed.hostname)) {
    return res.status(400).json({ error: 'not_allowed' });
  }

  // Cache on the CDN for a day, in Redis for a week.
  res.set('Cache-Control', 'public, max-age=86400, s-maxage=604800');
  const key = 'og:v1:' + crypto.createHash('sha256').update(parsed.href).digest('hex').slice(0, 32);

  let cached;
  try {
    cached = await redis.get(key);
  } catch {
    /* cache miss */
  }
  if (cached) return cached === '∅' ? res.status(404).end() : res.redirect(302, cached);

  let img = null;
  try {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 6000);
    const resp = await fetch(parsed.href, {
      signal: ctrl.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'Mozilla/5.0 (+https://php2shell.ai link-preview)', accept: 'text/html' },
    });
    clearTimeout(to);
    if (resp.ok) img = extractOg(await resp.text(), parsed.href);
  } catch {
    /* unreachable / timed out */
  }

  try {
    await redis.set(key, img || '∅', { ex: img ? 604800 : 86400 });
  } catch {
    /* non-fatal */
  }
  return img ? res.redirect(302, img) : res.status(404).end();
});

export default r;
