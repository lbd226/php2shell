// IP-pinned, headers-only fetch. Connects to a pre-validated IP and never re-resolves
// (anti-DNS-rebinding). Reads response headers only; the body is discarded. Redirects are
// NOT followed here — scanService decides, re-validating each hop.
import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import { assertSafeIp } from './ssrfGuard.js';

const UA = 'PHP2Shell-Posture-Check/1.0 (+https://php2shell.com; passive version check, headers only)';
const CONNECT_TIMEOUT_MS = 5000;
const TOTAL_TIMEOUT_MS = 8000;
const MAX_HEADER_BYTES = 32 * 1024;

function trunc(v) {
  return v == null ? null : String(v).slice(0, 512);
}

// scheme: 'https' | 'http'. Returns { status, headers:{server,xPoweredBy,location}, scheme }.
export function fetchHead({ domain, ip, scheme }) {
  // Re-assert at connect time (belt-and-braces against any earlier logic gap).
  assertSafeIp(ip);
  const mod = scheme === 'http' ? http : https;
  const family = net.isIPv6(ip) ? 6 : 4;

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn, arg) => { if (!settled) { settled = true; fn(arg); } };

    const req = mod.request(
      {
        protocol: `${scheme}:`,
        hostname: domain,
        path: '/',
        method: 'GET', // GET, aborted right after headers (more compatible than HEAD)
        servername: scheme === 'https' ? domain : undefined, // correct SNI; TLS verification stays ON
        headers: { Host: domain, 'User-Agent': UA, Accept: '*/*', Connection: 'close' },
        // Pin to the validated IP; the kernel never performs a second, attacker-controllable lookup.
        // Node >=20 (autoSelectFamily) calls lookup with {all:true} and expects an array form.
        lookup: (_host, opts, cb) =>
          (opts && opts.all ? cb(null, [{ address: ip, family }]) : cb(null, ip, family)),
        maxHeaderSize: MAX_HEADER_BYTES,
        setHost: false, // we set Host ourselves
      },
      (res) => {
        const out = {
          status: res.statusCode,
          headers: {
            server: trunc(res.headers['server']),
            xPoweredBy: trunc(res.headers['x-powered-by']),
            location: res.headers['location'] ? String(res.headers['location']).slice(0, 2048) : null,
          },
          scheme,
        };
        res.destroy(); // discard body — headers suffice
        clearTimeout(total);
        done(resolve, out);
      }
    );

    const total = setTimeout(() => req.destroy(new Error('total request timeout')), TOTAL_TIMEOUT_MS);
    if (total.unref) total.unref();

    req.setTimeout(CONNECT_TIMEOUT_MS, () => req.destroy(new Error('connect/read timeout')));
    req.on('error', (e) => { clearTimeout(total); done(reject, e); });
    req.end();
  });
}
