'use strict';

// Launch-contract tests for the GUI's client spawn path.
//
// Static part: the argv/env builders. The key must NEVER appear in argv (a
// command line is readable by every local user); it must ride in
// KCP_PROXY_KEY inside the environment.
//
// Runtime part: spawn the real client binary with exactly the parameters the
// GUI passes (buildClientArgs + buildClientEnv) and prove the env-only key
// channel actually works at startup — the client binds its SOCKS listener —
// and that removing the key channel fails fast with a clear error instead of
// half-starting a proxy. The runtime tests skip when the binary has not
// been built.

const { test } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const { buildClientArgs, buildClientEnv } = require('../utils.js');

const GUI_KEY = 'gui_runtime_test_key_123456'; // >= 16 chars

// --------------------------------------------------------------------------- //
// static: argv/env contract
// --------------------------------------------------------------------------- //

test('buildClientArgs emits exactly the connect parameters', () => {
  const args = buildClientArgs({
    serverHost: 'example.com', serverPort: 8388, localPort: 1080
  });
  assert.deepStrictEqual(args, [
    '-s', 'example.com',
    '-p', '8388',
    '-H', '127.0.0.1',
    '-l', '1080',
    '-L', 'info'
  ]);
});

test('buildClientArgs never carries the key on the command line', () => {
  const args = buildClientArgs({
    serverHost: 'h', serverPort: '8388', localPort: '1080'
  });
  assert.ok(!args.includes('-k'), "'-k' must not be in the client argv");
  assert.ok(!args.includes('--key'), "'--key' must not be in the client argv");
  for (const arg of args) {
    assert.ok(!arg.includes(GUI_KEY),
      `the key value must never leak into argv (saw it in ${JSON.stringify(arg)})`);
  }
});

test('buildClientEnv carries the key via KCP_PROXY_KEY and preserves the rest', () => {
  const base = { PATH: '/bin', LANG: 'C' };
  const env = buildClientEnv(GUI_KEY, base);
  assert.strictEqual(env.KCP_PROXY_KEY, GUI_KEY);
  assert.strictEqual(env.PATH, '/bin');
  assert.strictEqual(env.LANG, 'C');
  // The parent environment object must not be mutated.
  assert.ok(!('KCP_PROXY_KEY' in base));
});

// --------------------------------------------------------------------------- //
// runtime: spawn the real binary with the GUI's exact launch parameters
// --------------------------------------------------------------------------- //

function findClientBinary() {
  const executable = process.platform === 'win32'
    ? 'kcp-proxy-client.exe' : 'kcp-proxy-client';
  // Same layout as main.js getClientPath(), minus the packaged-resource path
  // that only exists inside an Electron ASAR.
  const candidates = [
    path.join(__dirname, '../../../bin',
      process.platform === 'win32' ? 'windows' : process.platform, executable),
    path.join(__dirname, '../../../build/Release', executable),
    path.join(__dirname, executable)
  ];
  return candidates.find((c) => fs.existsSync(c)) || null;
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function envWithoutKey() {
  const env = { ...process.env };
  delete env.KCP_PROXY_KEY;
  return env;
}

function waitForPort(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => {
        sock.destroy();
        resolve();
      });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) {
          reject(new Error(`port ${port} never came up within ${timeoutMs}ms`));
        } else {
          setTimeout(attempt, 100);
        }
      });
    };
    attempt();
  });
}

class ClientProc {
  constructor(bin, args, env) {
    this.stderr = '';
    this.child = spawn(bin, args, {
      cwd: path.dirname(bin),
      stdio: ['ignore', 'ignore', 'pipe'],
      env
    });
    this.child.stderr.on('data', (d) => {
      this.stderr += d.toString('utf8', 'replace');
    });
    this.exited = new Promise((resolve) => {
      this.child.once('close', (code) => resolve({ code, stderr: this.stderr }));
      this.child.once('error', (err) => resolve({ code: null, stderr: String(err) }));
    });
  }

  alive() {
    return this.child.exitCode === null && this.child.signalCode === null;
  }

  async stop() {
    if (this.alive()) {
      this.child.kill();
      await this.exited;
    }
    return this.exited;
  }
}

const clientBinary = findClientBinary();
const skipReason = clientBinary
  ? false
  : 'kcp-proxy-client binary not built yet (bin/ or build/Release)';

test('runtime: env-only key channel works — SOCKS listener comes up and stays up',
  { skip: skipReason }, async () => {
    const socksPort = await getFreePort();
    const serverPort = await getFreePort(); // unreachable server is fine: the
    // client binds its SOCKS listener before any KCP handshake is attempted.

    const proc = new ClientProc(
      clientBinary,
      buildClientArgs({
        serverHost: '127.0.0.1', serverPort, localPort: socksPort
      }),
      buildClientEnv(GUI_KEY, envWithoutKey()));

    try {
      await waitForPort(socksPort, 15000);
      assert.ok(proc.alive(),
        'client exited although its SOCKS listener was still expected '
        + `(stderr: ${JSON.stringify(proc.stderr)})`);
      // A key-less or broken launch dies within milliseconds; a brief settle
      // proves the env key passed startup validation, not a lucky race.
      await new Promise((r) => setTimeout(r, 700));
      assert.ok(proc.alive(),
        'client did not stay up with the env-only key channel');
    } finally {
      await proc.stop();
    }
  });

test('runtime: no key channel anywhere fails fast with a clear error',
  { skip: skipReason }, async () => {
    const socksPort = await getFreePort();
    const serverPort = await getFreePort();
    const proc = new ClientProc(
      clientBinary,
      buildClientArgs({
        serverHost: '127.0.0.1', serverPort, localPort: socksPort
      }),
      envWithoutKey());
    const { code, stderr } = await proc.exited;
    assert.notStrictEqual(code, 0,
      'client without any key channel must exit non-zero, not half-start');
    assert.ok(stderr.includes('--key is required'),
      `expected the "--key is required" diagnostic, got: ${JSON.stringify(stderr)}`);
  });
