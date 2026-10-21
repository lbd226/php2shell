// Bootstrap: migrate DB, start HTTP server, periodic expiry sweep, graceful shutdown.
import { createApp } from './app.js';
import { config } from './config.js';
import { migrate } from './db/index.js';
import { logger } from './lib/logger.js';
import { expireStale as expireVerifications } from './services/verificationService.js';
import { expireStale as expireGrants } from './services/grantService.js';

migrate();

const app = createApp();
const server = app.listen(config.PORT, () => {
  logger.info({ port: config.PORT, emailProvider: config.emailProvider, env: config.NODE_ENV }, 'php2shell ownership-scan API listening');
});

const sweep = setInterval(() => {
  try {
    const v = expireVerifications();
    const g = expireGrants();
    if (v || g) logger.debug({ verifications: v, grants: g }, 'expiry sweep');
  } catch (e) {
    logger.error({ err: e.message }, 'sweep failed');
  }
}, 5 * 60_000);
if (sweep.unref) sweep.unref();

function shutdown(sig) {
  logger.info({ sig }, 'shutting down');
  clearInterval(sweep);
  server.close(() => process.exit(0));
  const t = setTimeout(() => process.exit(0), 8000);
  if (t.unref) t.unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
