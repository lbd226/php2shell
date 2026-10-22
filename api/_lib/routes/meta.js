import { Router } from 'express';
import { constants } from '../core.js';
import { redis } from '../redis.js';

const r = Router();

r.get('/healthz', async (_req, res) => {
  let db = false;
  try {
    await redis.set('p2s:healthz', Date.now(), { ex: 30 });
    db = (await redis.get('p2s:healthz')) != null;
  } catch {
    db = false;
  }
  res.json({ ok: true, db, time: new Date().toISOString() });
});

r.get('/version-table', (_req, res) =>
  res.json({
    patched: constants.PATCHED,
    eolRange: constants.EOL_RANGE,
    cves: constants.CVES,
    disclaimer: constants.DISCLAIMER_HE,
  })
);

export default r;
