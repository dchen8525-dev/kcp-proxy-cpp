#!/usr/bin/env python3
"""Manual load generator: N concurrent SOCKS5 + TLS connections through the proxy.

Not a ctest. The registered suites (``tunnel_e2e.py``, ``robustness_e2e.py``)
run offline on loopback and assert on the binaries they spawn themselves. This
one needs a *running* client and real internet reachability, because what it
reproduces is a burst shape, not a protocol behaviour.

Why it exists: it is how the 2026-09-23 `ERR_CONNECTION_CLOSED` incident was
reproduced and how the fix was verified. Chrome opens dozens of connections at
once, and the client gives each one its own UDP socket, so a page load turns
into a simultaneous burst from ~40 KCP flows in fastest mode. Against a server
whose UDP receive buffer had been silently clamped to 208 KiB, that burst
overflowed the socket buffer, the kernel dropped the ClientHello and every
retransmission of it, and the server tore the sessions down at
`KCP_TIMEOUT_SEC` -- which Chrome reports as an active close. All N threads are
started before any is joined, so the burst is genuinely simultaneous; that is
the property under test, and it is why this cannot be a serial loop.

Usage:
    # terminal 1: kcp-proxy-client -s <server> -k <key> -l 1080 -L info
    # terminal 2:
    tests/e2e/chrome_sim.py 1080 www.google.com 443 100

Verify the server side at the same time -- the counter that must not move is
RcvbufErrors (see docs/TROUBLESHOOTING.md):

    awk '/^Udp:/{getline; print}' /proc/net/snmp
"""
import argparse
import socket
import ssl
import struct
import sys
import threading
import time


def socks5_connect(sock, host, port):
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
        raise RuntimeError("greeting failed: %r" % (resp,))
    h = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack("!H", port))
    head = sock.recv(4)
    if len(head) < 4:
        raise RuntimeError("short reply: %r" % (head,))
    if head[1] != 0:
        raise RuntimeError("socks rep=0x%02x" % head[1])
    atyp = head[3]
    if atyp == 1:
        sock.recv(4)
    elif atyp == 4:
        sock.recv(16)
    elif atyp == 3:
        n = sock.recv(1)[0]
        sock.recv(n)
    sock.recv(2)


def one(i, proxy_port, host, port, timeout, results, lock):
    t0 = time.time()
    out = {"i": i}
    try:
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
        s.settimeout(timeout)
        socks5_connect(s, host, port)
        out["socks_ms"] = int((time.time() - t0) * 1000)
        # The target certificate is never the point here -- reachability and
        # burst survival are. Verification would only add a CA dependency.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=host)
        out["tls_ms"] = int((time.time() - t0) * 1000)
        out["ok"] = True
        ss.close()
    except Exception as exc:
        out["ok"] = False
        out["err"] = "%s: %s" % (type(exc).__name__, exc)
        out["ms"] = int((time.time() - t0) * 1000)
    with lock:
        results.append(out)


def main():
    ap = argparse.ArgumentParser(
        description="Fire N simultaneous SOCKS5+TLS connections at a running "
                    "kcp-proxy-client and report per-connection latency.")
    ap.add_argument("proxy_port", type=int, help="SOCKS5 port of the local client")
    ap.add_argument("host", help="target hostname the proxy should reach")
    ap.add_argument("port", type=int, help="target port")
    ap.add_argument("count", type=int, help="number of simultaneous connections")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="per-connection socket timeout in seconds (default 20)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print only the summary line and failures")
    args = ap.parse_args()

    results = []
    lock = threading.Lock()
    threads = [threading.Thread(target=one,
                                args=(i, args.proxy_port, args.host, args.port,
                                      args.timeout, results, lock))
               for i in range(args.count)]

    # Start every thread before joining any, so the connections overlap. A
    # serial loop would not overflow anything and would verify nothing.
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok = [r for r in results if r.get("ok")]
    bad = [r for r in results if not r.get("ok")]
    print("=== %d/%d OK in %.1fs ===" % (len(ok), args.count, time.time() - start))
    if not args.quiet:
        for r in ok:
            print("  ok   #%d  socks=%sms tls=%sms"
                  % (r["i"], r.get("socks_ms"), r.get("tls_ms")))
    for r in bad:
        print("  FAIL #%d  %s  (%sms)" % (r["i"], r["err"], r.get("ms")))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
