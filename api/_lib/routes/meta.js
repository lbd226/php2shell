import { Router } from 'express';
import { constants } from '../core.js';

const r = Router();

r.get('/healthz', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

r.get('/version-table', (_req, res) =>
  res.json({
    patched: constants.PATCHED,
    eolRange: constants.EOL_RANGE,
    cves: constants.CVES,
    disclaimer: constants.DISCLAIMER_HE,
  })
);

export default r;
