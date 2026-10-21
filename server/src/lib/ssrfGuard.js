// SSRF guard — the #1 control. Fail-closed IP classification: only public global-unicast
// addresses are allowed. Uses ipaddr.js so IPv6 special ranges and IPv4-mapped forms are
// handled correctly rather than by hand-rolled regex.
import ipaddr from 'ipaddr.js';
import { config } from '../config.js';

export class SsrfError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SsrfError';
    this.status = 422;
    this.code = 'ssrf_block';
  }
}

// True only for a public, routable, global-unicast address.
// Everything else — loopback, private, link-local (incl. 169.254.169.254 cloud metadata),
// unique-local, CGNAT, 6to4/Teredo/NAT64 embeddings, reserved, multicast — is rejected.
export function isPublicIp(ip) {
  let addr;
  try {
    addr = ipaddr.parse(ip);
  } catch {
    return false;
  }

  if (addr.kind() === 'ipv6') {
    if (config.SCAN_DISABLE_IPV6) return false;
    // Unwrap ::ffff:a.b.c.d to the underlying IPv4 and classify that.
    if (addr.isIPv4MappedAddress()) {
      return isPublicIp(addr.toIPv4Address().toString());
    }
    // ipaddr.js returns 'unicast' only for global unicast; 6to4/teredo/rfc6052/rfc6145/
    // uniqueLocal/linkLocal/loopback/reserved/multicast all return their own labels.
    return addr.range() === 'unicast';
  }

  // IPv4: 'unicast' excludes loopback/private/linkLocal/carrierGradeNat/reserved/
  // broadcast/multicast/unspecified.
  return addr.range() === 'unicast';
}

export function assertSafeIp(ip) {
  if (!isPublicIp(ip)) {
    throw new SsrfError(`refusing to connect to non-public address: ${ip}`);
  }
}

// Every resolved address must be public, or the whole scan is refused. This defeats a
// split record set where one address is public and another points inward.
export function assertAllSafe(ips) {
  if (!Array.isArray(ips) || ips.length === 0) {
    throw new SsrfError('host did not resolve to any address');
  }
  for (const ip of ips) assertSafeIp(ip);
}
