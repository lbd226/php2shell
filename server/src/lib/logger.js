import pino from 'pino';

// Redacted structured logging. Never log tokens, secrets, or raw IPs.
export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: {
    paths: ['req.headers.authorization', 'token', 'claimSecret', 'grant', '*.token', '*.claimSecret'],
    remove: true,
  },
});
