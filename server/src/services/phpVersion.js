// Version inference from volunteered banners, and verdict vs the PATCHED/EOL table.
// STRICTLY inference — never proof. When the version is hidden, we refuse to guess.
import { PATCHED, CVES, DISCLAIMER_HE, REMEDIATION_URL, verdictMessage } from '../constants.js';

const PHP_VERSION_RE = /PHP\/(\d+)\.(\d+)\.(\d+)/i;

// headers: { server, xPoweredBy }
export function inferFromHeaders(headers = {}) {
  const server = headers.server || null;
  const xPoweredBy = headers.xPoweredBy || null;
  const haystack = [xPoweredBy, server].filter(Boolean).join('  ;  ');
  const m = haystack.match(PHP_VERSION_RE);

  if (!m) {
    // expose_php=Off, header stripped by a proxy, or not a PHP host. Good hygiene; we don't guess.
    return base('unknown_hidden', {
      inferredVersion: null, branch: null, patchedVersion: null, matchedHeader: null,
    });
  }

  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  const branch = `${major}.${minor}`;
  const inferredVersion = `${major}.${minor}.${patch}`;
  const matchedHeader = xPoweredBy && PHP_VERSION_RE.test(xPoweredBy)
    ? `X-Powered-By: ${xPoweredBy}`
    : `Server: ${server}`;

  let verdict;
  let patchedVersion = null;
  if (Object.prototype.hasOwnProperty.call(PATCHED, branch)) {
    const fixed = PATCHED[branch];
    if (patch < fixed) { verdict = 'vulnerable'; patchedVersion = `${branch}.${fixed}`; }
    else { verdict = 'patched'; }
  } else if (major < 8 || (major === 8 && minor < 2)) {
    verdict = 'eol';
  } else {
    verdict = 'unknown_branch';
  }

  return base(verdict, { inferredVersion, branch, patchedVersion, matchedHeader });
}

function base(verdict, extra) {
  return {
    verdict,
    isInference: true,
    inferredVersion: extra.inferredVersion,
    branch: extra.branch,
    patchedVersion: extra.patchedVersion,
    matchedHeader: extra.matchedHeader,
    message: verdictMessage(verdict, extra),
    cves: CVES,
    disclaimer: DISCLAIMER_HE,
    remediation: REMEDIATION_URL,
  };
}
