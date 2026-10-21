import express from 'express';
import helmet from 'helmet';
import { ZodError } from 'zod';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { config } from './config.js';
import { logger } from './lib/logger.js';
import verifyRoutes from './routes/verify.js';
import scanRoutes from './routes/scan.js';
import metaRoutes from './routes/meta.js';

export function createApp() {
  const app = express();
  // Resolve req.ip from the real peer, not a client-forged X-Forwarded-For.
  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');

  // JSON-only API; CSP matters for the static hub, handled there. Keep other hardening.
  app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
  app.use(express.json({ limit: '16kb' }));

  // CORS allowlist (exact-origin match against configured hub origin[s]).
  app.use((req, res, next) => {
    const origin = req.get('origin');
    if (origin && config.corsOrigins.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization');
      res.set('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  app.use('/api/verify', verifyRoutes);
  app.use('/api/scan', scanRoutes);
  app.use('/api', metaRoutes);

  if (config.SERVE_STATIC) {
    // Serve ONLY the two public hub files by explicit route — never the repo tree,
    // the server source, or the SQLite database.
    const hubDir = fileURLToPath(new URL('../../', import.meta.url));
    const sendHub = (file) => (_req, res) => res.sendFile(path.join(hubDir, file));
    app.get('/', sendHub('index.html'));
    app.get('/index.html', sendHub('index.html'));
    app.get('/scan.html', sendHub('scan.html'));
  }

  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

  // Central error handler: typed errors -> HTTP status; never leak internals on 500.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err instanceof ZodError) {
      return res.status(400).json({ error: 'invalid_request', details: err.issues.map((i) => i.message) });
    }
    const status = err.status || 500;
    const body = { error: err.code || 'server_error' };
    if (err.message && status < 500) body.message = err.message;
    if (err.resetMs) body.retryAfterMs = Math.max(0, err.resetMs - Date.now());
    if (status >= 500) logger.error({ err: { message: err.message, stack: err.stack } }, 'unhandled error');
    res.status(status).json(body);
  });

  return app;
}
