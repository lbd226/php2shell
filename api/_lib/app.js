import express from 'express';
import helmet from 'helmet';
import { ZodError } from 'zod';
import { config } from './core.js';
import verifyRoutes from './routes/verify.js';
import scanRoutes from './routes/scan.js';
import metaRoutes from './routes/meta.js';

export function createApp() {
  const app = express();
  // Vercel terminates TLS and sets x-forwarded-for / x-real-ip from the real connection.
  // We derive the client IP from x-real-ip (see routes), which clients cannot forge.
  app.set('trust proxy', true);
  app.disable('x-powered-by');

  app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
  app.use(express.json({ limit: '16kb' }));

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

  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err instanceof ZodError) {
      return res.status(400).json({ error: 'invalid_request', details: err.issues.map((i) => i.message) });
    }
    const status = err.status || 500;
    const body = { error: err.code || 'server_error' };
    if (err.message && status < 500) body.message = err.message;
    if (err.resetMs) body.retryAfterMs = Math.max(0, err.resetMs - Date.now());
    res.status(status).json(body);
  });

  return app;
}
