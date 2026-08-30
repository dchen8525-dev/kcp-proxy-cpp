'use strict';
// Regression test for the CONNECT-in-progress window: send the SOCKS5 CONNECT
// request and immediately pipeline the HTTP payload WITHOUT waiting for the
// reply. The pipelined data message reaches the server while its upstream TCP
// connect is still in flight; the server must forward it to the target once
// connected, not misparse it as a second SOCKS5 request and kill the session.

const net = require('net');

let stage = 0;
let buf = '';
const sock = net.connect(11080, '127.0.0.1', () => {
  // SOCKS5 greeting: 1 method, no-auth
  sock.write(Buffer.from([5, 1, 0]));
});

sock.on('data', (d) => {
  buf += d.toString('latin1');
  if (stage === 0 && buf.length >= 2) {
    stage = 1;
    // CONNECT 1.1.1.1:80 ...
    sock.write(Buffer.from([5, 1, 0, 1, 1, 1, 1, 1, 0, 80]));
    // ... and the payload pipelined right behind it, before any reply.
    sock.write('HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n');
  } else if (stage === 1 && buf.length >= 12) {
    const rep = buf.charCodeAt(3); // [VER] of method reply(2B) + [VER REP] of request reply
    if (rep !== 0) {
      console.log(`FAIL socks reply code=${rep}`);
      process.exit(1);
    }
    stage = 2;
  }
  if (buf.includes('HTTP/1.')) {
    console.log('PASS: ' + buf.slice(buf.indexOf('HTTP/1.')).split('\r\n')[0]);
    process.exit(0);
  }
});

setTimeout(() => {
  console.log('TIMEOUT buf=' + JSON.stringify(buf.slice(0, 160)));
  process.exit(1);
}, 20000);

sock.on('error', (e) => {
  console.log('SOCKET ERROR: ' + e.message);
  process.exit(1);
});
sock.on('close', () => {
  if (!buf.includes('HTTP/1.')) {
    console.log('CLOSED EARLY buf=' + JSON.stringify(buf.slice(0, 160)));
    process.exit(1);
  }
});
