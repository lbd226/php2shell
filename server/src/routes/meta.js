import { Router } from 'express';
import { PATCHED, EOL_RANGE, CVES, DISCLAIMER_HE } from '../constants.js';

const r = Router();

r.get('/healthz', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// Single source of truth so the hub's client-side table stays in sync with the backend.
r.get('/version-table', (_req, res) =>
  res.json({ patched: PATCHED, eolRange: EOL_RANGE, cves: CVES, disclaimer: DISCLAIMER_HE })
);

export default r;
