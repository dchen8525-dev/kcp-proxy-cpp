'use strict';

const { test } = require('node:test');
const assert = require('node:assert');

const {
  getBeijingDate,
  generateKey,
  formatBytes,
  formatBytesPerSec,
  isValidPort,
  validateLaunchConfig,
  buildClientArgs,
  resolveAppIconPath
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
  assert.strictEqual(formatBytes(1024), '1.00 KB');
  assert.strictEqual(formatBytes(5 * 1024 * 1024), '5.00 MB');
  assert.strictEqual(formatBytes(3.5 * 1024 * 1024 * 1024), '3.50 GB');
  assert.strictEqual(formatBytes(undefined), '0 B');
});

test('formatBytesPerSec humanizes rates and never goes negative', () => {
  assert.strictEqual(formatBytesPerSec(0), '0 B/s');
  assert.strictEqual(formatBytesPerSec(undefined), '0 B/s');
  assert.strictEqual(formatBytesPerSec(-5), '0 B/s');
  assert.strictEqual(formatBytesPerSec(1024), '1.00 KB/s');
  assert.strictEqual(formatBytesPerSec(3.5 * 1024 * 1024), '3.50 MB/s');
});

test('buildClientArgs omits -fec entirely when FEC is disabled', () => {
  // The absent flag IS the disabled form: argv (and wire) stay byte-identical
  // to pre-FEC launches, which is what keeps old pairs compatible.
  const args = buildClientArgs({
    serverHost: 'example.com', serverPort: '8388', localPort: '1080',
    allowLan: false
  });
  assert.strictEqual(args.includes('-fec'), false);
});

test('buildClientArgs appends -fec DATA:PARITY when FEC is enabled', () => {
  const args = buildClientArgs({
    serverHost: 'example.com', serverPort: '8388', localPort: '1080',
    allowLan: false, fecEnabled: true, fecPair: '10:3'
  });
  const i = args.indexOf('-fec');
  assert.notStrictEqual(i, -1, '-fec flag must be present');
  assert.strictEqual(args[i + 1], '10:3');
  // The flag must come after the fixed connect parameters, at the tail.
  assert.ok(i > args.indexOf('-L'));
});

test('buildClientArgs canonicalizes the pair it emits', () => {
  // Leading zeros parse on the C++ side, but the argv carries the canonical
  // numeric form so logs on both ends read identically.
  const args = buildClientArgs({
    serverHost: 'h', serverPort: 8388, localPort: 1080,
    allowLan: true, fecEnabled: true, fecPair: '010:003'
  });
  assert.deepStrictEqual(args.slice(-2), ['-fec', '10:3']);
});

test('validateLaunchConfig rejects bad FEC pairs only while FEC is enabled', () => {
  const base = {
    serverHost: 'example.com', serverPort: '8388', localPort: '1080',
    keyMode: 'daily', keySuffix: 'Abcd1234', keyDate: '20260820'
  };
  // Disabled: the pair field is ignored entirely (stale garbage must not
  // block a launch whose FEC is off).
  assert.strictEqual(
    validateLaunchConfig({ ...base, fecEnabled: false, fecPair: '0:99' }),
    null);
  // Enabled: the pair must satisfy 1 <= PARITY <= DATA <= 255.
  for (const pair of ['10:3', '4:2', '128:128']) {
    assert.strictEqual(
      validateLaunchConfig({ ...base, fecEnabled: true, fecPair: pair }),
      null, `fec ${pair} must be accepted`);
  }
  for (const pair of ['3:10', '0:3', '10:0', '10:-3', '10:abc', '10:0x3',
                      'abc:3', '', '10', '10:3:1', ':3', '10:', '10 :3']) {
    assert.match(
      validateLaunchConfig({ ...base, fecEnabled: true, fecPair: pair }),
      /FEC 参数/,
      `fec ${JSON.stringify(pair)} must be rejected with the parameter message`);
  }
});

test('buildClientArgs never emits a malformed pair for a bad FEC form', () => {
  // Regression: a malformed pair used to reach the argv verbatim (formerly as
  // "-fec NaN:NaN"). The client's parser is fail-closed, so that is not a
  // degraded tunnel -- it is a client that refuses to start at all. Every
  // unusable value must fall back to the default pair instead.
  const cases = [
    [undefined, '10:3'],
    ['', '10:3'],
    ['abc', '10:3'],
    ['0:0', '10:3'],
    ['10', '10:3'],      // missing colon — a half-typed pair
    ['10:', '10:3'],
    ['4:0', '10:3']
  ];
  for (const [fecPair, want] of cases) {
    const args = buildClientArgs({
      serverHost: 'h', serverPort: '8388', localPort: '1080',
      allowLan: false, fecEnabled: true, fecPair
    });
    assert.strictEqual(args[args.indexOf('-fec') + 1], want,
      `FEC form ${JSON.stringify(fecPair)} must fall back to ${want}`);
    assert.ok(!args.some((a) => a.includes('NaN')), 'no argv token may contain NaN');
  }
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

// ---------------------------------------------------------------------------
// resolveAppIconPath — the window/tray icon lookup used by main.js.
// The tray regression this pins: the icon must come from the packaged asset
// (assets/icon.png preferred, icon.ico as the Windows fallback), never from a
// programmatic substitute that hides the brand icon.
// ---------------------------------------------------------------------------

// Fake filesystem: only the listed paths exist. Returns the exists() callback.
function fakeExists(paths) {
  const set = new Set(paths.map((p) => p.replaceAll('\\', '/')));
  return (p) => set.has(p.replaceAll('\\', '/'));
}

// path.join emits the platform separator (backslash on Windows), so compare
// the resolved path through a normalizer instead of literal strings.
const norm = (p) => (p === null ? null : p.replaceAll('\\', '/'));

test('resolveAppIconPath prefers the app dir PNG over the ICO', () => {
  const exists = fakeExists([
    '/app/assets/icon.png',
    '/app/assets/icon.ico'
  ]);
  assert.strictEqual(
    norm(resolveAppIconPath('/app', null, exists)),
    '/app/assets/icon.png'
  );
});

test('resolveAppIconPath falls back to the ICO when the PNG is absent', () => {
  const exists = fakeExists(['/app/assets/icon.ico']);
  assert.strictEqual(
    norm(resolveAppIconPath('/app', null, exists)),
    '/app/assets/icon.ico'
  );
});

test('resolveAppIconPath falls back to resourcesPath after the app dir', () => {
  // Nothing under the app dir; the packaged layout keeps assets in resources.
  const exists = fakeExists(['/resources/assets/icon.png']);
  assert.strictEqual(
    norm(resolveAppIconPath('/app', '/resources', exists)),
    '/resources/assets/icon.png'
  );
});

test('resolveAppIconPath returns null when no icon asset exists', () => {
  // A null result must make the caller degrade loudly (skip the tray), not
  // silently substitute a different-looking icon.
  assert.strictEqual(
    resolveAppIconPath('/app', '/resources', fakeExists([])),
    null
  );
});

test('resolveAppIconPath tolerates a missing resourcesDir (dev mode)', () => {
  const exists = fakeExists(['/app/assets/icon.png']);
  assert.strictEqual(
    norm(resolveAppIconPath('/app', undefined, exists)),
    '/app/assets/icon.png'
  );
});