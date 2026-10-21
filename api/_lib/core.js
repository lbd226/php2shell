// Re-export the storage-FREE, security-critical primitives from the Node implementation, so the
// SSRF guard, IP-pinned fetch, token logic, domain rules and version inference are IDENTICAL
// across the Node (SQLite) and Vercel (Redis) deployments — no divergence, one source of truth.
// None of these modules import better-sqlite3, so nothing native gets bundled into the function.
export { config } from '../../server/src/config.js';
export * as tokens from '../../server/src/lib/tokens.js';
export { normalizeDomain, emailHostMatchesDomain, DomainError } from '../../server/src/lib/domain.js';
export { assertAllSafe, isPublicIp, SsrfError } from '../../server/src/lib/ssrfGuard.js';
export { fetchHead } from '../../server/src/lib/safeFetch.js';
export { resolveAll, resolveTxt } from '../../server/src/lib/dnsResolver.js';
export { inferFromHeaders } from '../../server/src/services/phpVersion.js';
export * as constants from '../../server/src/constants.js';
export { sendMail, emailEnabled, emailProvider } from '../../server/src/lib/mailer.js';
