'use strict';
// Regression test for the CONNECT-in-progress window: send the SOCKS5 CONNECT
// request and immediately pipeline the HTTP payload WITHOUT waiting for the
// reply. The pipelined data message reaches the server while its upstream TCP
// connect is still in flight; the server must forward it to the target once
// connected, not misparse it as a second SOCKS5 request and kill the session.
//
// This is a MANUAL probe against a live tunnel (default 127.0.0.1:11080, or the
// PORT env var). `node --test` collects this file along with the rest of the
// suite, so it reports itself as SKIPPED when nothing is listening. It used to
// print "SKIP" and process.exit(0) instead, which node --test counted as a
// PASSING test -- a fully green suite in exactly the situation this regression
// would hide in. It also needs outbound access to 1.1.1.1:80, so a live tunnel
// behind a firewall fails rather than skips; that is intentional for a manual
// probe and it is not part of CI.

const net = require('node:net');
const { test } = require('node:test');
const assert = require('node:assert');

const PORT = Number(process.env.PORT || 11080);

// True when something accepts TCP on the probe port. A bare ECONNREFUSED must
// read as "not running", not as a regression.
function isListening(port) {
  return new Promise((resolve) => {
    const probe = net.connect(port, '127.0.0.1');
    probe.once('connect', () => {
      probe.destroy();
      resolve(true);
    });
    probe.once('error', () => resolve(false));
  });
}

// Drives the probe: SOCKS5 greeting, then CONNECT pipelined with the payload
// before any reply arrives. Resolves with everything received.
function runProbe(port) {
  return new Promise((resolve, reject) => {
    let buf = '';
    let stage = 0;
    let settled = false;

    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(Buffer.from([5, 1, 0])); // greeting: 1 method, no-auth
    });

    const timer = setTimeout(() => {
      finish(() => reject(new Error('timeout, buf=' + JSON.stringify(buf.slice(0, 160)))));
    }, 20000);

    function finish(settle) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      settle();
    }

    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (stage === 0 && buf.length >= 2) {
        stage = 1;
        // CONNECT 1.1.1.1:80 ...
        sock.write(Buffer.from([5, 1, 0, 1, 1, 1, 1, 1, 0, 80]));
        // ... and the payload pipelined right behind it, before any reply.
        sock.write('HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n');
      } else if (stage === 1 && buf.length >= 12) {
        // [VER] of the method reply (2B) + [VER REP] of the request reply.
        const rep = buf.charCodeAt(3);
        if (rep !== 0) {
          finish(() => reject(new Error(`socks reply code=${rep}`)));
          return;
        }
        stage = 2;
      }
      if (buf.includes('HTTP/1.')) {
        finish(() => resolve(buf));
      }
    });

    sock.on('error', (e) => finish(() => reject(e)));
    sock.on('close', () => {
      if (!buf.includes('HTTP/1.')) {
        finish(() => reject(
          new Error('closed early, buf=' + JSON.stringify(buf.slice(0, 160)))));
      }
    });
  });
}

test('pipelined CONNECT payload is not misparsed as a second SOCKS5 request', async (t) => {
  if (!(await isListening(PORT))) {
    t.skip(`no live tunnel on 127.0.0.1:${PORT} (start the GUI proxy first)`);
    return;
  }

  const buf = await runProbe(PORT);
  const statusLine = buf.slice(buf.indexOf('HTTP/1.')).split('\r\n')[0];
  assert.ok(statusLine.startsWith('HTTP/1.'),
    `expected the target's HTTP status line back through the tunnel, got ${statusLine}`);
});
