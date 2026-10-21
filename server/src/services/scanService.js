// Strictly passive scan: resolve -> SSRF guard (all addresses) -> IP-pinned headers fetch ->
// version inference -> persist. Never sends a payload, never follows a cross-host redirect,
// never contacts a non-public IP. The target host comes from the grant, not the client.
import { db, nowMs } from '../db/index.js';
import { config } from '../config.js';
import { randomId } from '../lib/tokens.js';
import { resolveAll } from '../lib/dnsResolver.js';
import { assertAllSafe, SsrfError } from '../lib/ssrfGuard.js';
import { fetchHead } from '../lib/safeFetch.js';
import { inferFromHeaders } from './phpVersion.js';
import { CVES, DISCLAIMER_HE, REMEDIATION_URL } from '../constants.js';

const insResult = db.prepare(`
  INSERT INTO scan_result(
    id, grant_id, verification_id, domain, resolved_ip, final_url, http_status,
    server_header, x_powered_by, inferred_version, branch, verdict, patched_version,
    is_inference, detail_json, error_code, duration_ms, created_at)
  VALUES(@id, @grant_id, @verification_id, @domain, @resolved_ip, @final_url, @http_status,
    @server_header, @x_powered_by, @inferred_version, @branch, @verdict, @patched_version,
    1, @detail_json, @error_code, @duration_ms, @created_at)
`);
const getResult = db.prepare('SELECT * FROM scan_result WHERE id = ? AND grant_id = ?');

// grant: the validated scan_grant row.
export async function scan(grant) {
  const started = nowMs();
  const domain = grant.domain;
  const resultId = randomId();

  const persist = (fields) => {
    insResult.run({
      id: resultId,
      grant_id: grant.id,
      verification_id: grant.verification_id,
      domain,
      resolved_ip: fields.resolvedIp ?? null,
      final_url: fields.finalUrl ?? null,
      http_status: fields.httpStatus ?? null,
      server_header: fields.server ?? null,
      x_powered_by: fields.xPoweredBy ?? null,
      inferred_version: fields.inferredVersion ?? null,
      branch: fields.branch ?? null,
      verdict: fields.verdict,
      patched_version: fields.patchedVersion ?? null,
      detail_json: fields.detail ? JSON.stringify(fields.detail) : null,
      error_code: fields.errorCode ?? null,
      duration_ms: nowMs() - started,
      created_at: nowMs(),
    });
  };

  // 1) Resolve all addresses and require every one to be public (fail-closed).
  let addrs;
  try {
    addrs = await resolveAll(domain);
    assertAllSafe(addrs.map((a) => a.ip));
  } catch (e) {
    const errorCode = e instanceof SsrfError ? 'ssrf_block' : 'dns_error';
    persist({ verdict: 'error', errorCode });
    return { resultId, domain, verdict: 'error', errorCode, isInference: true, message: errorMessage(errorCode), cves: CVES, disclaimer: DISCLAIMER_HE };
  }

  // 2) Prefer IPv4; it is the single pinned target for the whole request.
  const target = addrs.find((a) => a.family === 4) || addrs[0];

  // 3) Headers-only fetch: https first, optional http fallback. No cross-host redirects.
  const schemes = config.HUB_ALLOW_HTTP ? ['https', 'http'] : ['https'];
  let resp = null;
  let lastErr = null;
  for (const scheme of schemes) {
    try {
      resp = await fetchHead({ domain, ip: target.ip, scheme });
      break;
    } catch (e) {
      lastErr = e;
    }
  }

  if (!resp) {
    persist({ verdict: 'error', errorCode: 'fetch_failed', resolvedIp: target.ip, detail: { error: String(lastErr && lastErr.message || lastErr) } });
    return { resultId, domain, verdict: 'error', errorCode: 'fetch_failed', isInference: true, message: errorMessage('fetch_failed'), resolvedIp: target.ip, cves: CVES, disclaimer: DISCLAIMER_HE };
  }

  // 4) Infer version from volunteered banners.
  const inf = inferFromHeaders(resp.headers);
  const finalUrl = `${resp.scheme}://${domain}/`;

  persist({
    resolvedIp: target.ip,
    finalUrl,
    httpStatus: resp.status,
    server: resp.headers.server,
    xPoweredBy: resp.headers.xPoweredBy,
    inferredVersion: inf.inferredVersion,
    branch: inf.branch,
    verdict: inf.verdict,
    patchedVersion: inf.patchedVersion,
    detail: { matchedHeader: inf.matchedHeader },
  });

  return {
    resultId,
    domain,
    verdict: inf.verdict,
    inferredVersion: inf.inferredVersion,
    branch: inf.branch,
    patchedVersion: inf.patchedVersion,
    isInference: true,
    message: inf.message,
    headers: { server: resp.headers.server, xPoweredBy: resp.headers.xPoweredBy },
    httpStatus: resp.status,
    resolvedIp: target.ip,
    finalUrl,
    matchedHeader: inf.matchedHeader,
    cves: CVES,
    disclaimer: DISCLAIMER_HE,
    remediation: REMEDIATION_URL,
  };
}

export function getStoredResult(resultId, grantId) {
  return getResult.get(resultId, grantId);
}

function errorMessage(code) {
  switch (code) {
    case 'ssrf_block':
      return 'הדומיין מצביע לכתובת פנימית/לא-ציבורית — הבדיקה סורבה מטעמי אבטחה.';
    case 'dns_error':
      return 'לא ניתן היה לפענח את כתובת הדומיין.';
    case 'fetch_failed':
      return 'לא ניתן היה להגיע לשרת (ייתכן שאין HTTPS, או שהחיבור נכשל).';
    default:
      return 'הבדיקה נכשלה.';
  }
}
