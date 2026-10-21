// Strictly passive scan (Redis-persisted). Reuses the identical SSRF guard, IP-pinned fetch,
// and version inference from the Node implementation. Target host comes from the grant only.
import { config, constants, tokens, resolveAll, assertAllSafe, SsrfError, fetchHead, inferFromHeaders } from '../core.js';
import { redis } from '../redis.js';

const RESULT_TTL_SEC = 3600;

function errorMessage(code) {
  switch (code) {
    case 'ssrf_block': return 'הדומיין מצביע לכתובת פנימית/לא-ציבורית — הבדיקה סורבה מטעמי אבטחה.';
    case 'dns_error': return 'לא ניתן היה לפענח את כתובת הדומיין.';
    case 'fetch_failed': return 'לא ניתן היה להגיע לשרת (ייתכן שאין HTTPS, או שהחיבור נכשל).';
    default: return 'הבדיקה נכשלה.';
  }
}

export async function scan(grant) {
  const started = Date.now();
  const domain = grant.domain;
  const resultId = tokens.randomId();
  const save = (f) => redis.set(`r:${resultId}`, {
    ...f, id: resultId, grantId: grant.id, verificationId: grant.verificationId, domain,
    isInference: true, durationMs: Date.now() - started, createdAt: Date.now(),
  }, { ex: RESULT_TTL_SEC });

  let addrs;
  try {
    addrs = await resolveAll(domain);
    assertAllSafe(addrs.map((a) => a.ip));
  } catch (e) {
    const code = e instanceof SsrfError ? 'ssrf_block' : 'dns_error';
    await save({ verdict: 'error', errorCode: code });
    return { resultId, domain, verdict: 'error', errorCode: code, isInference: true, message: errorMessage(code), cves: constants.CVES, disclaimer: constants.DISCLAIMER_HE };
  }

  const target = addrs.find((a) => a.family === 4) || addrs[0];
  const schemes = config.HUB_ALLOW_HTTP ? ['https', 'http'] : ['https'];
  let resp = null;
  let lastErr = null;
  for (const scheme of schemes) {
    try { resp = await fetchHead({ domain, ip: target.ip, scheme }); break; }
    catch (e) { lastErr = e; }
  }

  if (!resp) {
    await save({ verdict: 'error', errorCode: 'fetch_failed', resolvedIp: target.ip, detail: { error: String((lastErr && lastErr.message) || lastErr) } });
    return { resultId, domain, verdict: 'error', errorCode: 'fetch_failed', isInference: true, message: errorMessage('fetch_failed'), resolvedIp: target.ip, cves: constants.CVES, disclaimer: constants.DISCLAIMER_HE };
  }

  const inf = inferFromHeaders(resp.headers);
  const finalUrl = `${resp.scheme}://${domain}/`;
  await save({
    resolvedIp: target.ip, finalUrl, httpStatus: resp.status,
    serverHeader: resp.headers.server, xPoweredBy: resp.headers.xPoweredBy,
    inferredVersion: inf.inferredVersion, branch: inf.branch, verdict: inf.verdict,
    patchedVersion: inf.patchedVersion, detail: { matchedHeader: inf.matchedHeader },
  });

  return {
    resultId, domain, verdict: inf.verdict, inferredVersion: inf.inferredVersion, branch: inf.branch,
    patchedVersion: inf.patchedVersion, isInference: true, message: inf.message,
    headers: { server: resp.headers.server, xPoweredBy: resp.headers.xPoweredBy },
    httpStatus: resp.status, resolvedIp: target.ip, finalUrl, matchedHeader: inf.matchedHeader,
    cves: constants.CVES, disclaimer: constants.DISCLAIMER_HE, remediation: constants.REMEDIATION_URL,
  };
}

export async function getStoredResult(resultId, grantId) {
  const r = await redis.get(`r:${resultId}`);
  if (!r || r.grantId !== grantId) return null;
  return r;
}
