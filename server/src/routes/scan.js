import { Router } from 'express';
import { validateBearer, resolveGrant, consumeUse } from '../services/grantService.js';
import { scan, getStoredResult } from '../services/scanService.js';
import { enforce } from '../lib/rateLimit.js';
import { audit } from '../lib/audit.js';
import { hashIp } from '../lib/tokens.js';

const r = Router();
const HOUR = 60 * 60_000;

function bearer(req) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

// Run the passive scan. Target host comes from the grant, never the request body.
r.post('/', async (req, res, next) => {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ error: 'missing_grant' });
    const grant = validateBearer(token); // throws GrantError (401/410)
    enforce(`domain:${grant.domain}:scan`, 10, HOUR);
    enforce(`ip:${hashIp(req.ip)}:scan`, 20, HOUR);
    const ok = consumeUse(grant.id);
    if (!ok) return res.status(410).json({ error: 'grant_exhausted' });
    const result = await scan(grant);
    audit('scan', { verificationId: grant.verification_id, domain: grant.domain, outcome: result.verdict });
    res.json(result);
  } catch (e) { next(e); }
});

// Read a stored result (read-only; works for the lifetime of the grant token).
r.get('/:id', (req, res, next) => {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ error: 'missing_grant' });
    const grant = resolveGrant(token);
    if (!grant) return res.status(401).json({ error: 'invalid_grant' });
    const row = getStoredResult(req.params.id, grant.id);
    if (!row) return res.status(404).json({ error: 'not_found' });
    res.json(row);
  } catch (e) { next(e); }
});

export default r;
