// Unit tests for version inference and verdict boundaries. Run: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inferFromHeaders } from '../src/services/phpVersion.js';

test('vulnerable: patch below the fixed version', () => {
  const r = inferFromHeaders({ xPoweredBy: 'PHP/8.3.20' });
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.inferredVersion, '8.3.20');
  assert.equal(r.branch, '8.3');
  assert.equal(r.patchedVersion, '8.3.36');
  assert.equal(r.isInference, true);
});

test('patched: at or above the fixed version', () => {
  assert.equal(inferFromHeaders({ xPoweredBy: 'PHP/8.3.36' }).verdict, 'patched');
  assert.equal(inferFromHeaders({ xPoweredBy: 'PHP/8.2.40' }).verdict, 'patched');
});

test('boundary: exactly the fixed patch is patched, one below is vulnerable', () => {
  assert.equal(inferFromHeaders({ xPoweredBy: 'PHP/8.4.27' }).verdict, 'patched');
  assert.equal(inferFromHeaders({ xPoweredBy: 'PHP/8.4.26' }).verdict, 'vulnerable');
});

test('eol: 7.4 .. 8.1 have no official fix', () => {
  assert.equal(inferFromHeaders({ xPoweredBy: 'PHP/8.1.10' }).verdict, 'eol');
  assert.equal(inferFromHeaders({ server: 'Apache PHP/7.4.33' }).verdict, 'eol');
});

test('unknown_branch: newer branch not in the table', () => {
  assert.equal(inferFromHeaders({ xPoweredBy: 'PHP/8.6.0' }).verdict, 'unknown_branch');
});

test('unknown_hidden: no PHP token in any header -> refuse to guess', () => {
  assert.equal(inferFromHeaders({ server: 'nginx' }).verdict, 'unknown_hidden');
  assert.equal(inferFromHeaders({}).verdict, 'unknown_hidden');
});

test('parses PHP version embedded in the Server header', () => {
  const r = inferFromHeaders({ server: 'Apache/2.4.58 (Unix) PHP/8.2.10' });
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.inferredVersion, '8.2.10');
  assert.equal(r.patchedVersion, '8.2.35');
});
