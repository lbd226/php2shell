import { Router } from 'express';
import { tokens } from '../core.js';
import { limiters, enforce } from '../ratelimit.js';
import { audit } from '../audit.js';
import * as grant from '../services/grant.js';
import * as scanService from '../services/scan.js';

const r = Router();

function bearer(req) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}
function clientIp(req) {
  return req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown';
}

r.post('/', async (req, res, next) => {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ error: 'missing_grant' });
    const g = await grant.validateBearer(token); // throws 401/410
    await enforce(limiters.domainScan, g.domain);
    await enforce(limiters.ipScan, tokens.hashIp(clientIp(req)));
    const ok = await grant.consumeUse(g.id, g.maxUses);
    if (!ok) return res.status(410).json({ error: 'grant_exhausted' });
    const result = await scanService.scan(g);
    await audit('scan', { verificationId: g.verificationId, domain: g.domain, outcome: result.verdict });
    res.json(result);
  } catch (e) { next(e); }
});

r.get('/:id', async (req, res, next) => {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ error: 'missing_grant' });
    const g = await grant.resolveGrant(token);
    if (!g) return res.status(401).json({ error: 'invalid_grant' });
    const row = await scanService.getStoredResult(req.params.id, g.id);
    if (!row) return res.status(404).json({ error: 'not_found' });
    res.json(row);
  } catch (e) { next(e); }
});

export default r;
