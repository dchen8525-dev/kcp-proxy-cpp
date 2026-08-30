'use strict';

const { test } = require('node:test');
const assert = require('node:assert');

const {
  getBeijingDate,
  generateKey,
  formatBytes,
  isValidPort,
  validateLaunchConfig
} = require('../utils.js');

test('getBeijingDate formats Beijing date as YYYYMMDD', () => {
  // 2026-08-20T00:30:00Z == 2026-08-20T08:30+08:00 (same day, before midnight)
  const fixed = new Date(Date.UTC(2026, 7, 20, 0, 30));
  assert.strictEqual(getBeijingDate(fixed), '20260820');
});

test('getBeijingDate rolls over at UTC 16:00 (Beijing midnight)', () => {
  // 2026-08-20T16:00:00Z == 2026-08-21T00:00+08:00 → next Beijing day
  const fixed = new Date(Date.UTC(2026, 7, 20, 16, 0));
  assert.strictEqual(getBeijingDate(fixed), '20260821');
});

test('generateKey daily mode = date + suffix', () => {
  assert.strictEqual(
    generateKey('daily', { date: '20260820', suffix: 'Abcd1234' }),
    '20260820Abcd1234'
  );
});

test('generateKey daily mode falls back to today-UTC+8 when date omitted', () => {
  assert.strictEqual(
    generateKey('daily', { suffix: 'Abcd1234' }),
    getBeijingDate() + 'Abcd1234'
  );
});

test('generateKey fixed mode returns the fixed key verbatim', () => {
  assert.strictEqual(
    generateKey('fixed', { fixedKey: 'my-secret-key-1234567890' }),
    'my-secret-key-1234567890'
  );
});

test('generateKey empty modes produce empty string', () => {
  assert.strictEqual(generateKey('fixed', {}), '');
  assert.strictEqual(generateKey('daily', { date: '20260820', suffix: '' }), '20260820');
});

test('formatBytes humanizes byte counts', () => {
  assert.strictEqual(formatBytes(0), '0 B');
  assert.strictEqual(formatBytes(512), '512 B');
  assert.strictEqual(formatBytes(1024), '1.0 KB');
  assert.strictEqual(formatBytes(5 * 1024 * 1024), '5.0 MB');
  assert.strictEqual(formatBytes(3.5 * 1024 * 1024 * 1024), '3.5 GB');
  assert.strictEqual(formatBytes(undefined), '0 B');
});

test('isValidPort accepts 1..65535 only', () => {
  assert.strictEqual(isValidPort('8388'), true);
  assert.strictEqual(isValidPort('1'), true);
  assert.strictEqual(isValidPort('65535'), true);
  assert.strictEqual(isValidPort('0'), false);
  assert.strictEqual(isValidPort('65536'), false);
  assert.strictEqual(isValidPort('abc'), false);
  assert.strictEqual(isValidPort(''), false);
  assert.strictEqual(isValidPort(' 1080 '), true); // trimmed
});

test('validateLaunchConfig accepts a valid daily-mode config', () => {
  assert.strictEqual(
    validateLaunchConfig({
      serverHost: 'example.com',
      serverPort: '8388',
      localPort: '1080',
      keyMode: 'daily',
      keySuffix: 'Abcd1234',
      keyDate: '20260820'
    }),
    null
  );
});

test('validateLaunchConfig accepts a valid fixed-mode config', () => {
  assert.strictEqual(
    validateLaunchConfig({
      serverHost: '1.2.3.4',
      serverPort: '8388',
      localPort: '1080',
      keyMode: 'fixed',
      fixedKey: 'abcdefghijklmnopqrstuvwxyz123456'
    }),
    null
  );
});

test('validateLaunchConfig rejects missing host', () => {
  const err = validateLaunchConfig({
    serverHost: '',
    serverPort: '8388',
    localPort: '1080',
    keyMode: 'daily',
    keySuffix: 'Abcd1234'
  });
  assert.ok(err && err.includes('服务器地址'));
});

test('validateLaunchConfig rejects out-of-range ports', () => {
  assert.ok(validateLaunchConfig({
    serverHost: 'h', serverPort: '99999', localPort: '1080',
    keyMode: 'fixed', fixedKey: 'x'.repeat(20)
  }));
  assert.ok(validateLaunchConfig({
    serverHost: 'h', serverPort: '8388', localPort: '0',
    keyMode: 'fixed', fixedKey: 'x'.repeat(20)
  }));
});

test('validateLaunchConfig rejects short keys in both modes', () => {
  assert.ok(validateLaunchConfig({
    serverHost: 'h', serverPort: '8388', localPort: '1080',
    keyMode: 'daily', keySuffix: '1234567' // 7 chars
  }));
  assert.ok(validateLaunchConfig({
    serverHost: 'h', serverPort: '8388', localPort: '1080',
    keyMode: 'fixed', fixedKey: 'short-key'
  }));
});

test('validateLaunchConfig rejects invalid suffix characters in daily mode', () => {
  assert.ok(validateLaunchConfig({
    serverHost: 'h', serverPort: '8388', localPort: '1080',
    keyMode: 'daily', keySuffix: 'bad suffix!!'
  }));
});