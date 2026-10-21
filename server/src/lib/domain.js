// Domain normalization + validation. We accept only a registrable domain name as a scan
// target — never a URL, IP literal, port, userinfo, or scheme.
import { domainToASCII } from 'node:url';
import net from 'node:net';
import psl from 'psl';

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export class DomainError extends Error {
  constructor(message) { super(message); this.name = 'DomainError'; this.status = 400; this.code = 'invalid_domain'; }
}

// Returns the normalized ASCII (punycode) host, or throws DomainError.
export function normalizeDomain(input) {
  if (typeof input !== 'string') throw new DomainError('domain must be a string');
  let s = input.trim().toLowerCase();
  if (!s) throw new DomainError('domain is empty');

  // Reject anything that looks like a URL/scheme/userinfo/path/port up front.
  if (/[/\\@\s]/.test(s)) throw new DomainError('enter a bare domain, with no scheme, path, or “@”');
  if (s.includes(':')) throw new DomainError('ports are not allowed');
  if (s.startsWith('.') || s.endsWith('.')) s = s.replace(/^\.+|\.+$/g, '');

  // IDNA2008 -> punycode.
  const ascii = domainToASCII(s);
  if (!ascii) throw new DomainError('not a valid domain name');

  // Reject IP literals outright — the scanner never accepts IPs.
  if (net.isIP(ascii) !== 0) throw new DomainError('IP addresses are not allowed; verify a domain name');

  const labels = ascii.split('.');
  if (labels.length < 2) throw new DomainError('enter a fully-qualified domain (e.g. example.com)');
  for (const label of labels) {
    if (!LABEL.test(label)) throw new DomainError(`invalid label: “${label}”`);
  }

  // Public-suffix validation: must be a registrable name, not a bare TLD/suffix.
  const parsed = psl.parse(ascii);
  if (parsed.error || !parsed.domain) throw new DomainError('not a registrable domain name');
  if (ascii === parsed.tld) throw new DomainError('that is a public suffix, not a domain you can own');

  return ascii;
}

// The email challenge requires the address host to equal the verified domain exactly.
export function emailHostMatchesDomain(email, domain) {
  if (typeof email !== 'string') return false;
  // Strict single-address, no control chars (header-injection guard).
  if (/[\r\n\t]/.test(email) || email.includes(',')) return false;
  const at = email.lastIndexOf('@');
  if (at <= 0) return false;
  const local = email.slice(0, at);
  const host = email.slice(at + 1);
  if (!/^[A-Za-z0-9._%+-]+$/.test(local)) return false;
  let hostAscii;
  try { hostAscii = domainToASCII(host.trim().toLowerCase()); } catch { return false; }
  return hostAscii === domain;
}
