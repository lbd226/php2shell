// Unit tests for the SSRF classifier — the #1 control. Run: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';

// config.js reads env at import time and fail-fasts; satisfy the required vars first.
process.env.PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://api.test';
process.env.HUB_URL = process.env.HUB_URL || 'https://hub.test';
process.env.IP_HASH_KEY = process.env.IP_HASH_KEY || 'test-key-0123456789abcdef0123456789';

const { isPublicIp } = await import('../src/lib/ssrfGuard.js');

const PUBLIC = [
  '1.1.1.1',
  '8.8.8.8',
  '93.184.216.34',
  '2606:4700:4700::1111', // public IPv6 (Cloudflare)
  '2001:4860:4860::8888', // public IPv6 (Google)
  '::ffff:8.8.8.8', // IPv4-mapped public -> allowed
];

const BLOCKED = [
  '127.0.0.1', // loopback
  '10.0.0.5', // private
  '172.16.0.1', // private
  '192.168.1.1', // private
  '169.254.169.254', // cloud metadata (link-local)
  '169.254.0.1', // link-local
  '100.64.0.1', // CGNAT
  '0.0.0.0', // unspecified
  '255.255.255.255', // broadcast
  '224.0.0.1', // multicast
  '::1', // IPv6 loopback
  '::', // IPv6 unspecified
  'fe80::1', // IPv6 link-local
  'fc00::1', // IPv6 unique-local
  'fd00::1', // IPv6 unique-local
  '::ffff:127.0.0.1', // IPv4-mapped loopback
  '::ffff:169.254.169.254', // IPv4-mapped metadata
  '::ffff:10.0.0.1', // IPv4-mapped private
  '2002:a9fe:a9fe::', // 6to4 wrapping 169.254.169.254
  '64:ff9b::a9fe:a9fe', // NAT64 embedding
  'not-an-ip',
  '',
];

test('public global-unicast addresses are allowed', () => {
  for (const ip of PUBLIC) assert.equal(isPublicIp(ip), true, `${ip} should be public`);
});

test('internal / special / metadata addresses are blocked', () => {
  for (const ip of BLOCKED) assert.equal(isPublicIp(ip), false, `${ip} should be blocked`);
});

test('cloud metadata endpoint is blocked in every form', () => {
  assert.equal(isPublicIp('169.254.169.254'), false);
  assert.equal(isPublicIp('::ffff:169.254.169.254'), false);
  assert.equal(isPublicIp('2002:a9fe:a9fe::'), false);
});
