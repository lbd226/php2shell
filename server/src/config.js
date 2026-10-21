// Env-driven, zod-validated configuration with fail-fast on boot.
import 'dotenv/config';
import { z } from 'zod';

const bool = (def) =>
  z.preprocess((v) => {
    if (v === undefined || v === '') return def;
    if (typeof v === 'boolean') return v;
    return String(v).toLowerCase() === 'true' || String(v) === '1';
  }, z.boolean());

const int = (def, min, max) =>
  z.preprocess((v) => (v === undefined || v === '' ? def : Number(v)),
    z.number().int().min(min).max(max));

const noTrailingSlash = (s) => s.replace(/\/+$/, '');

const schema = z.object({
  NODE_ENV: z.string().default('production'),
  PORT: int(8080, 1, 65535),

  PUBLIC_BASE_URL: z.string().url().transform(noTrailingSlash),
  HUB_URL: z.string().url().transform(noTrailingSlash),
  CORS_ORIGINS: z.string().default(''),

  DB_PATH: z.string().min(1).default('./data/php2shell.db'),

  // Required secret: used to HMAC client IPs before persistence.
  IP_HASH_KEY: z.string().min(16, 'IP_HASH_KEY must be at least 16 chars of random data'),

  EMAIL_TTL_MIN: int(30, 1, 1440),
  DNS_TTL_HOURS: int(24, 1, 168),
  GRANT_TTL_MIN: int(30, 1, 1440),
  GRANT_MAX_USES: int(3, 1, 50),

  HUB_ALLOW_HTTP: bool(false),
  RESOLVER_IPS: z.string().default(''),
  SCAN_DISABLE_IPV6: bool(false),

  SMTP_HOST: z.string().default(''),
  SMTP_PORT: int(587, 1, 65535),
  SMTP_SECURE: bool(false),
  SMTP_USER: z.string().default(''),
  SMTP_PASS: z.string().default(''),
  MAIL_FROM: z.string().default('PHP2Shell Verify <verify@example.com>'),

  // Resend (https://resend.com) — preferred email provider. Set to enable the email challenge.
  RESEND_API_KEY: z.string().default(''),

  SERVE_STATIC: bool(false),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error('[config] Invalid configuration:\n' + parsed.error.issues
    .map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n'));
  process.exit(1);
}

const cfg = parsed.data;

export const config = {
  ...cfg,
  emailEnabled: cfg.RESEND_API_KEY.length > 0 || cfg.SMTP_HOST.length > 0,
  emailProvider: cfg.RESEND_API_KEY.length > 0 ? 'resend' : (cfg.SMTP_HOST.length > 0 ? 'smtp' : 'none'),
  corsOrigins: [cfg.HUB_URL, ...cfg.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)],
  resolverIps: cfg.RESOLVER_IPS.split(',').map((s) => s.trim()).filter(Boolean),
  ttl: {
    emailMs: cfg.EMAIL_TTL_MIN * 60_000,
    dnsMs: cfg.DNS_TTL_HOURS * 3_600_000,
    grantMs: cfg.GRANT_TTL_MIN * 60_000,
  },
};
