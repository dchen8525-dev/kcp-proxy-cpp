#!/usr/bin/env python3
"""Adversarial end-to-end suite for the SOCKS5-over-KCP proxy.

``tunnel_e2e.py`` proves the golden path; ``robustness_e2e.py`` proves the
proxy survives wrong keys, garbage floods, concurrency, half-close and big
responses. This suite closes the remaining gaps in that coverage -- the attack
surface a hostile LOCAL APPLICATION or a hostile UDP NEIGHBOUR can reach that
neither of the other two suites touches:

  A. SOCKS5 protocol abuse - the client's listener is the one port every local
     process can reach, so it is the most attacked surface in practice: bad
     versions, no-auth-less greetings, non-zero RSV, bogus ATYPs, zero-length
     and 255-byte domains, BIND / UDP ASSOCIATE, IPv6 loopback (SSRF on the
     v6 path), requests dribbled one byte at a time, and requests pipelined
     with payload. Every one of these must be answered correctly or refused
     cleanly, and the client + server must both survive the whole set.
  B. Many-source UDP flood - robustness phase B can only flood from ONE
     loopback address, so only the per-address failure gate is ever exercised
     there. Binding 800 distinct 127/8 sources is the only way to reach the
     GLOBAL auth-attempt budget (MAX_AUTH_ATTEMPTS_PER_SEC = 5000) and prove
     that (a) it engages, and (b) legitimate new sessions are served again
     once the 1s window resets. The flood is sized so the outcome does not
     depend on where the window boundaries fall (see the phase body).
     macOS: only 127.0.0.1 is configured on lo0, so distinct 127/8 sources are
     unavailable and the per-address gate (20/s) caps any single-source blast
     far below the 5000/s budget -- the phase skips there, and the single-source
     per-address-gate coverage runs on every platform in robustness phase B.
  C. Client session cap - 520 simultaneous local connections against a client
     whose MAX_CLIENT_SESSIONS is 512: the excess must be refused, the cap
     tickets must be released when the connections close (a leak here would
     permanently shrink the client's capacity), and a fresh connection must
     work afterwards.
  D. Stalled target - a CONNECT whose upstream TCP handshake can never
     complete (the target's accept backlog is full, so the SYN is dropped)
     must hit the server's CONNECT_TIMEOUT_SEC deadline, produce a clean
     HOST_UNREACHABLE reply, and leave no session behind -- not a hang.
  E. Restart / key rotation - the server being killed and restarted under the
     SAME key must not disturb the client process (new tunnels just work),
     and a restart under a DIFFERENT key must fail the handshake fast and
     loudly without killing the client or spamming its log.

Every phase runs fully offline on loopback. Assertions are made against real
process behaviour plus the structured logs (captured to files), never against
mocks: server logs go to stderr, so each process gets its own log file.

Note on the allowlist: the server's SSRF guard refuses loopback targets by
default, so the phases that need a local target pass ``--allow-target`` (the
lab affordance documented in main_server.cpp). Phase A allowlists ONLY the one
IPv4 loopback echo endpoint its success cases need; the *default* protection is
still asserted there, by an IPv6 loopback CONNECT -- which also proves an IPv4
allowlist entry does not leak to a v6 target.

Exit code 0 on success, non-zero with a diagnostic on failure.
"""

import argparse
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tunnel_e2e import (  # noqa: E402  (path tweak must precede the import)
    KEY,
    EchoServer,
    augment_dll_path,
    free_port,
    free_udp_port,
    normalize_binary_path,
    recv_exact,
    run_case,
    socks5_connect,
    wait_for_port,
)

# Phase C: the client's compile-time cap (config.hpp MAX_CLIENT_SESSIONS).
MAX_CLIENT_SESSIONS = 512

# macOS only configures 127.0.0.1 on lo0; the rest of 127/8 is NOT routable,
# so datagrams cannot be sourced from 127.0.0.2..127.0.3.200 the way Linux and
# Windows allow. With a single usable source address the per-address failure
# gate (20/s) caps counted attempts and the GLOBAL auth budget (5000/s) can
# never be reached -- phase B's global-budget half is structurally untestable
# there. macOS also paces loopback UDP bursts to a trickle (see the robustness
# suite's phase B), so even the per-address gate is only provable with the
# OS-pacing-aware fallback that suite already implements. Phase B therefore
# skips on macOS; every assertion it could make there already has a home:
#   * global budget via many distinct sources -> this phase (Linux/Windows)
#   * single-source flood, per-address gate, recovery  -> robustness phase B
IS_MACOS = sys.platform == "darwin"

# Phase B: distinct loopback sources. 127/8 is entirely loopback, so
# 127.0.0.2..127.0.0.201, 127.0.1.1..127.0.1.200, 127.0.2.1..127.0.2.200 and
# 127.0.3.1..127.0.3.200 give 800 addresses (Linux/Windows only).
FLOOD_ADDRS = (
    ["127.0.0.%d" % i for i in range(2, 202)] +
    ["127.0.1.%d" % i for i in range(1, 201)] +
    ["127.0.2.%d" % i for i in range(1, 201)] +
    ["127.0.3.%d" % i for i in range(1, 201)]
)
FLOOD_PER_ADDR = 25          # datagrams per source: 20 counted + 5 gate-dropped
# The blast must CLEAR MAX_AUTH_ATTEMPTS_PER_SEC inside a single 1s window, so
# what matters is the achieved send RATE, not the packet count.
#
# Two things dominate that rate, and both were once charged to the measured
# window, which is why an earlier version of this phase sat at ~4.9k/s -- right
# ON the 5000/s budget, so it passed or failed on host speed instead of on the
# server's behaviour:
#   * socket()+bind() for 800 distinct loopback addresses costs seconds on
#     Windows. Those sockets are now created before the clock starts (below).
#   * one Python thread cannot drive 800 sockets fast enough; sendto() releases
#     the GIL, so slicing the address space across threads really does scale.
# Measured on this host with sockets pre-created: 1 thread = 8.4k/s,
# 8 threads = 10.5k/s, against 12.5k/s for the same blast aimed at a dead port.
FLOOD_SENDER_THREADS = 8
# Mirrors of the server's two-level auth throttle (config.hpp).
MAX_AUTH_ATTEMPTS_PER_SEC = 5000
MAX_AUTH_FAILURES_PER_ADDR_PER_SEC = 20
# Phase D: the server's upstream connect deadline (config.hpp).
CONNECT_TIMEOUT_SEC = 15


# --------------------------------------------------------------------------- #
# process + log helpers (same discipline as robustness_e2e: logs to FILES)
# --------------------------------------------------------------------------- #
class Proc:
    """A spawned binary whose combined stdout/stderr goes to its own log file."""

    def __init__(self, cmd, log_path, extra_env=None):
        self.cmd = cmd
        self.log_path = log_path
        env = None
        if extra_env:
            env = dict(os.environ)
            env.update(extra_env)
        self._fh = open(log_path, "wb")
        self.proc = subprocess.Popen(cmd, stdout=self._fh,
                                     stderr=subprocess.STDOUT, env=env)

    def alive(self):
        return self.proc.poll() is None

    def exit_code(self):
        return self.proc.poll()

    def stop(self):
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
        except Exception:
            pass
        time.sleep(0.2)
        try:
            if self.proc.poll() is None:
                self.proc.kill()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass
        try:
            self._fh.close()
        except Exception:
            pass


def log_text(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def count_in(path, needle):
    return log_text(path).count(needle)


def wait_for_log(path, needle, timeout):
    """Poll a log file until ``needle`` appears; return whether it did."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in log_text(path):
            return True
        time.sleep(0.1)
    return needle in log_text(path)


def wait_log_quiescent(path, quiet=1.2, timeout=30):
    """Wait until the log file stops growing for ``quiet`` seconds.

    Used after the phase B flood: the server counts auth attempts at its own
    pace, so the last counted attempt can land well after the last datagram
    was sent -- and the 1s auth window only resets from THAT point. A fixed
    sleep after the last send would race the server's drain tail.
    """
    deadline = time.time() + timeout
    last_size = -1
    last_change = time.time()
    while time.time() < deadline:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        now = time.time()
        if size != last_size:
            last_size = size
            last_change = now
        elif now - last_change >= quiet:
            return True
        time.sleep(0.1)
    return False


def dump_logs(log_paths, lines=12):
    for path in log_paths:
        text = log_text(path).strip().splitlines()
        print("  --- tail %s ---" % os.path.basename(path), file=sys.stderr)
        for line in text[-lines:]:
            print("      " + line, file=sys.stderr)


def start_pair(server_exe, client_exe, udp_port, socks_port, key, log_dir, tag,
               allow_target=None, log_level="INFO"):
    """Server + client on loopback. ``allow_target`` is one "HOST:PORT" string
    (repeatable by calling with a list) for the phases that need a local
    target despite the SSRF guard."""
    server_cmd = [server_exe, "-H", "127.0.0.1", "-p", str(udp_port),
                  "-k", key, "-L", log_level]
    if allow_target:
        for target in ([allow_target] if isinstance(allow_target, str) else allow_target):
            server_cmd += ["--allow-target", target]
    server = Proc(server_cmd, os.path.join(log_dir, tag + "-server.log"))
    client_cmd = [client_exe, "-s", "127.0.0.1", "-p", str(udp_port),
                  "-H", "127.0.0.1", "-l", str(socks_port), "-k", key,
                  "-L", log_level]
    client = Proc(client_cmd, os.path.join(log_dir, tag + "-client.log"))
    return server, client


def require_pair_ready(server, client, socks_port, timeout=20):
    if not wait_for_port("127.0.0.1", socks_port, timeout):
        raise RuntimeError("client SOCKS port never came up on 127.0.0.1:%d" % socks_port)
    time.sleep(0.3)
    if not server.alive():
        raise RuntimeError("server exited early with code %s" % server.exit_code())
    if not client.alive():
        raise RuntimeError("client exited early with code %s" % client.exit_code())


# --------------------------------------------------------------------------- #
# raw SOCKS5 exchange helpers (full control, unlike socks5_connect)
# --------------------------------------------------------------------------- #
def open_client(socks_port, timeout=10):
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.settimeout(timeout)
    return s


def read_method_selection(s):
    """Read the 2-byte greeting reply; return (ver, method)."""
    ver, method = recv_exact(s, 2, 10)
    return ver, method


def read_request_reply(s, timeout=15):
    """Read a full SOCKS5 CONNECT reply; return the REP byte."""
    header = recv_exact(s, 4, timeout)
    if header[0] != 0x05:
        raise AssertionError("bad SOCKS5 reply version: %d" % header[0])
    atyp = header[3]
    if atyp == 0x01:
        recv_exact(s, 6, timeout)
    elif atyp == 0x04:
        recv_exact(s, 18, timeout)
    elif atyp == 0x03:
        dlen = recv_exact(s, 1, timeout)[0]
        recv_exact(s, dlen + 2, timeout)
    else:
        raise AssertionError("bad SOCKS5 reply ATYP=0x%02x" % atyp)
    return header[1]


def expect_eof(s, timeout=8, what="connection"):
    """The peer must close without sending anything more."""
    s.settimeout(timeout)
    try:
        data = s.recv(64)
    except socket.timeout:
        raise AssertionError("%s stayed open; expected a clean close" % what)
    if data:
        raise AssertionError("%s sent unexpected data before close: %r"
                             % (what, data[:16]))


def greeting_ok(s):
    s.sendall(bytes([0x05, 0x01, 0x00]))
    ver, method = read_method_selection(s)
    if ver != 0x05 or method != 0x00:
        raise AssertionError("greeting not accepted: ver=%d method=%d" % (ver, method))


def ipv4_request(cmd, host, port):
    req = bytes([0x05, cmd, 0x00, 0x01])
    req += bytes(int(o) for o in host.split("."))
    req += bytes([(port >> 8) & 0xFF, port & 0xFF])
    return req


# How many times check_malformed_openings() repeats each exchange. The bug it
# guards against is an arrival-order race: with the RST-emitting close(), a
# malformed greeting that pipelines one extra byte lost its 0x05 0xFF reply
# ~25% of the time (the app saw connection_reset instead of the method
# selection), so a single exchange caught it only one run in four. Five
# rounds over fresh connections catch a regression with >99.6% probability,
# and with the fix (drain + FIN, see KCPProxyClient::close_local_socket) every
# round must pass deterministically.
RST_ROUNDS = 5


def check_malformed_openings(socks_port, echo_port):
    """Malformed openings: answered (or cleanly closed), never RST, never wedged.

    Cases 1-3 carry a reply plus pipelined leftover bytes -- exactly the
    precondition of the RST-discard race. Cases 4-6 write no reply but must
    still close cleanly (an RST surfaces to the app as connection_reset,
    which expect_eof rejects). Repeated RST_ROUNDS times.
    """
    for round_no in range(RST_ROUNDS):
        # 1. Wrong SOCKS version: not a greeting at all -> 0xFF, then close.
        s = open_client(socks_port)
        s.sendall(bytes([0x04, 0x01, 0x00]))
        ver, method = read_method_selection(s)
        assert (ver, method) == (0x05, 0xFF), \
            "bad version must be answered 0x05 0xFF, got %r" % ((ver, method),)
        expect_eof(s, what="bad-version connection")
        s.close()

        # 2. Zero methods offered -> 0xFF, then close.
        s = open_client(socks_port)
        s.sendall(bytes([0x05, 0x00]))
        ver, method = read_method_selection(s)
        assert (ver, method) == (0x05, 0xFF), \
            "nmethods=0 must be answered 0xFF, got %r" % ((ver, method),)
        expect_eof(s, what="nmethods=0 connection")
        s.close()

        # 3. Methods offered, but no-auth NOT among them -> 0xFF, then close.
        s = open_client(socks_port)
        s.sendall(bytes([0x05, 0x01, 0x02]))  # only user/pass auth
        ver, method = read_method_selection(s)
        assert (ver, method) == (0x05, 0xFF), \
            "no-auth-less greeting must be answered 0xFF, got %r" % ((ver, method),)
        expect_eof(s, what="no-auth-less connection")
        s.close()

        # 4. Non-zero RSV in the request: RFC 1928 says it MUST be 0x00.
        s = open_client(socks_port)
        greeting_ok(s)
        s.sendall(bytes([0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1,
                         (echo_port >> 8) & 0xFF, echo_port & 0xFF]))
        expect_eof(s, what="RSV!=0 request")
        s.close()

        # 5. Unknown ATYP (0x02): refuse before any target work.
        s = open_client(socks_port)
        greeting_ok(s)
        s.sendall(bytes([0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4, 0, 80]))
        expect_eof(s, what="unknown-ATYP request")
        s.close()

        # 6. Zero-length domain name.
        s = open_client(socks_port)
        greeting_ok(s)
        s.sendall(bytes([0x05, 0x01, 0x00, 0x03, 0x00, 0, 80]))
        expect_eof(s, what="empty-domain request")
        s.close()
    print("  [ok] malformed openings x%d (bad version / nmethods=0 / "
          "no-auth / RSV!=0 / bad ATYP / empty domain) -> always answered, "
          "always FIN" % RST_ROUNDS)


# --------------------------------------------------------------------------- #
# phase A: SOCKS5 protocol abuse against the client's listener
# --------------------------------------------------------------------------- #
def phase_protocol_abuse(server_exe, client_exe, log_dir, echo_port):
    print("[A] SOCKS5 protocol abuse: malformed local traffic must be refused "
          "cleanly, never crash or wedge the proxy")
    udp_port = free_udp_port()
    socks_port = free_port()
    # The ONLY allowlist entry is the IPv4 loopback echo endpoint that the
    # success cases (split request / pipelined payload / post-abuse baseline)
    # need. Everything else stays under the DEFAULT SSRF guard: the IPv6
    # loopback case below still proves v6 classification, and that an IPv4
    # allowlist entry does not leak to a v6 target.
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "abuse",
                                allow_target="127.0.0.1:%d" % echo_port)
    try:
        require_pair_ready(server, client, socks_port)

        # 1-6. Malformed openings (bad version / nmethods=0 / no-auth-less /
        #      RSV!=0 / bad ATYP / empty domain). Delegated and repeated: the
        #      failure mode is an arrival-order race, so one pass catches a
        #      regression only ~25% of the time -- see check_malformed_openings.
        check_malformed_openings(socks_port, echo_port)

        # 7. BIND: unsupported command -> COMMAND_NOT_SUPPORTED reply, close.
        s = open_client(socks_port)
        greeting_ok(s)
        s.sendall(ipv4_request(0x02, "127.0.0.1", echo_port))
        rep = read_request_reply(s)
        assert rep == 0x07, "BIND must be refused with 0x07, got 0x%02x" % rep
        expect_eof(s, what="BIND connection")
        s.close()
        print("  [ok] BIND -> command-not-supported reply + close")

        # 8. UDP ASSOCIATE: same treatment (udp_associate=unsupported).
        s = open_client(socks_port)
        greeting_ok(s)
        s.sendall(ipv4_request(0x03, "127.0.0.1", echo_port))
        rep = read_request_reply(s)
        assert rep == 0x07, "UDP ASSOCIATE must be refused with 0x07, got 0x%02x" % rep
        expect_eof(s, what="UDP ASSOCIATE connection")
        s.close()
        print("  [ok] UDP ASSOCIATE -> command-not-supported reply + close")

        # 9. IPv6 loopback target with an EMPTY allowlist: the SSRF guard must
        #    refuse it (v6 classification path, no allowlist override).
        s = open_client(socks_port)
        greeting_ok(s)
        v6 = bytes([0] * 15 + [1])  # ::1
        req = bytes([0x05, 0x01, 0x00, 0x04]) + v6 + \
            bytes([(echo_port >> 8) & 0xFF, echo_port & 0xFF])
        s.sendall(req)
        rep = read_request_reply(s)
        assert rep == 0x04, \
            "IPv6 loopback must be SSRF-blocked with 0x04, got 0x%02x" % rep
        expect_eof(s, what="IPv6-loopback connection")
        s.close()
        print("  [ok] IPv6 loopback CONNECT -> SSRF guard blocks (0x04)")

        # 10. Maximum-length (255) bogus domain: must fail as host-unreachable,
        #     not crash the resolver or the client.
        s = open_client(socks_port)
        greeting_ok(s)
        domain = (b"a" * 247) + b".invalid"  # RFC 6761: never resolvable
        req = bytes([0x05, 0x01, 0x00, 0x03, len(domain)]) + domain + \
            bytes([(echo_port >> 8) & 0xFF, echo_port & 0xFF])
        s.sendall(req)
        rep = read_request_reply(s, timeout=25)
        assert rep == 0x04, \
            "unresolvable 255-byte domain must yield 0x04, got 0x%02x" % rep
        expect_eof(s, what="bogus-domain connection")
        s.close()
        print("  [ok] 255-byte unresolvable domain -> host-unreachable + close")

        # 11. A request dribbled one byte at a time must still complete.
        s = open_client(socks_port)
        greeting_ok(s)
        req = ipv4_request(0x01, "127.0.0.1", echo_port)
        for b in req:
            s.sendall(bytes([b]))
            time.sleep(0.01)
        rep = read_request_reply(s)
        assert rep == 0x00, "split request must succeed, got 0x%02x" % rep
        payload = b"split-request-payload"
        s.sendall(payload)
        got = recv_exact(s, len(payload), 10)
        assert got == payload, "split request payload mismatch"
        s.close()
        print("  [ok] byte-by-byte split request -> full round-trip")

        # 12. Greeting + request + payload pipelined into ONE write: the
        #     trailing payload must survive the handshake, not be dropped.
        s = open_client(socks_port)
        payload = b"pipelined-early-data"
        blob = bytes([0x05, 0x01, 0x00]) + \
            ipv4_request(0x01, "127.0.0.1", echo_port) + payload
        s.sendall(blob)
        ver, method = read_method_selection(s)
        assert (ver, method) == (0x05, 0x00), "pipelined greeting rejected"
        rep = read_request_reply(s)
        assert rep == 0x00, "pipelined request must succeed, got 0x%02x" % rep
        got = recv_exact(s, len(payload), 10)
        assert got == payload, "pipelined payload mismatch: %r" % got
        s.close()
        print("  [ok] pipelined greeting+request+payload -> nothing dropped")

        # 13. Greeting then immediate close: a cleanup path, must not wedge.
        s = open_client(socks_port)
        greeting_ok(s)
        s.close()
        time.sleep(0.2)

        # 14. After the whole abuse set, the proxy must still work normally.
        run_case("post-abuse baseline", socks_port, echo_port,
                 b"still alive after abuse", 20)
        if not server.alive():
            raise AssertionError("server died during protocol abuse")
        if not client.alive():
            raise AssertionError("client died during protocol abuse")
        print("  [ok] both processes alive; service fully functional")
    finally:
        client.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# phase B: many-source flood -> global auth budget, then recovery
# --------------------------------------------------------------------------- #
def phase_multi_source_flood(server_exe, client_exe, log_dir, echo_port):
    if IS_MACOS:
        # See IS_MACOS above for the full argument. Skipped BEFORE starting any
        # process: nothing this phase can assert on macOS is not already
        # asserted by the robustness suite's phase B, which runs here too.
        print("[B] SKIP on macOS: the global-budget flood needs 800 distinct "
              "127/8 source addresses; macOS only configures 127.0.0.1, so "
              "the per-address gate caps counted attempts at %d/s and the "
              "%d/s global budget is unreachable. Single-source per-address "
              "coverage lives in robustness phase B, which runs on this "
              "platform." % (MAX_AUTH_FAILURES_PER_ADDR_PER_SEC,
                             MAX_AUTH_ATTEMPTS_PER_SEC))
        return
    print("[B] many-source UDP flood: the GLOBAL auth budget must engage and "
          "legitimate sessions must be served again afterwards")
    udp_port = free_udp_port()
    socks_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "multiflood",
                                allow_target="127.0.0.1:%d" % echo_port)
    try:
        require_pair_ready(server, client, socks_port)
        run_case("pre-flood baseline", socks_port, echo_port,
                 b"baseline before the multi-source flood", 20)

        # 800 distinct loopback source addresses. The per-address failure gate
        # (20/s per address) caps each source's counted attempts, so the flood
        # yields 800 * 20 = 16000 counted attempts -- the only way to reach the
        # GLOBAL 5000/s budget, the path robustness phase B structurally cannot
        # reach (all its senders share 127.0.0.1).
        #
        # Why this many: the budget engages only when some 1s WINDOW contains
        # >= 5001 counted attempts. An earlier version of this phase sent 9000
        # datagrams (6000 counted) and measured the failure directly -- the
        # blast itself spans >1s, so a window boundary split the attempts
        # 3831 + 2170 and the budget never engaged: "6000 in one window" is
        # not something a >1s flood can promise. 16000 counted attempts make
        # the outcome independent of where the boundaries fall -- any split of
        # 16000 leaves a half >= 8000, and a counted span over ~2s always
        # contains at least one full window.
        random.seed(1)
        packets = [bytes(random.getrandbits(8) for _ in range(60))
                   for _ in range(FLOOD_PER_ADDR)]
        # One sender thread per slice of the address space -- see
        # FLOOD_SENDER_THREADS for why, and for the measured rates.
        #
        # The sockets are created and bound ONCE, before the clock starts:
        # 800 socket()+bind() calls cost seconds on Windows and would other-
        # wise be charged to the blast, understating the achieved rate.
        senders = []
        for addr in FLOOD_ADDRS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((addr, 0))
            senders.append(sock)
        slices = [senders[i::FLOOD_SENDER_THREADS]
                  for i in range(FLOOD_SENDER_THREADS)]
        slices = [s for s in slices if s]
        sent = [0]
        sent_lock = threading.Lock()
        target = ("127.0.0.1", udp_port)

        def blast(sock_slice):
            local = 0
            try:
                for sock in sock_slice:
                    for pkt in packets:
                        sock.sendto(pkt, target)
                        local += 1
            finally:
                with sent_lock:
                    sent[0] += local

        try:
            started = time.time()
            threads = [threading.Thread(target=blast, args=(s,))
                       for s in slices]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            elapsed = time.time() - started
        finally:
            for sock in senders:
                try:
                    sock.close()
                except OSError:
                    pass
        achieved_rate = sent[0] / elapsed if elapsed > 0 else 0.0
        print("  [ok] blasted %d datagrams from %d distinct sources via %d "
              "threads in %.2fs (%.0f/s)"
              % (sent[0], len(FLOOD_ADDRS), len(slices), elapsed,
                 achieved_rate))
        # Only ~80% of these are ever counted (each address is gate-dropped
        # after 20 failures), so the send rate has to clear the budget by a
        # margin. Saying so here turns a slow host into a diagnosable failure
        # instead of the misleading "budget never engaged".
        if achieved_rate * 0.8 <= MAX_AUTH_ATTEMPTS_PER_SEC:
            raise AssertionError(
                "the blast reached only %.0f datagrams/s (~%.0f/s counted "
                "after the per-address gate), which cannot exceed the %d/s "
                "budget -- raise FLOOD_SENDER_THREADS or the host is too slow"
                % (achieved_rate, achieved_rate * 0.8,
                   MAX_AUTH_ATTEMPTS_PER_SEC))

        if not server.alive():
            raise AssertionError("server died under the multi-source flood")
        if not client.alive():
            raise AssertionError("client died during the multi-source flood")
        print("  [ok] both processes survived the flood")

        # The global budget line is the whole point of this phase: it is the
        # only defense left once every source address is distinct.
        if not wait_for_log(server.log_path,
                            "auth attempt rate limit reached", 10):
            raise AssertionError(
                "global auth budget never engaged: %d attempts from %d "
                "sources at %.0f/s should exceed %d/s"
                % (sent[0], len(FLOOD_ADDRS), achieved_rate,
                   MAX_AUTH_ATTEMPTS_PER_SEC))
        print("  [ok] global auth-attempt budget engaged under the flood")

        # The budget is a 1-second window: once it resets, legitimate NEW
        # sessions must be served again. A flood that permanently locked out
        # new sessions would be a worse DoS than the one it prevents.
        #
        # The window resets 1s after the LAST counted attempt, and the server
        # counts at its own pace -- the counted attempts can outlast the blast
        # itself. Waiting for the log to go quiet (not a fixed sleep after the
        # last send) is what makes the recovery probe land in a fresh window
        # regardless of the machine's throughput.
        if not wait_log_quiescent(server.log_path, quiet=1.2, timeout=30):
            raise AssertionError("server log never went quiet after the flood")
        time.sleep(1.2)  # the reset window itself, plus a margin
        run_case("post-flood recovery", socks_port, echo_port,
                 b"recovered after the flood", 20)
        print("  [ok] legitimate new session served after the window reset")
    finally:
        client.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# phase C: client session cap (MAX_CLIENT_SESSIONS) and ticket release
# --------------------------------------------------------------------------- #
def phase_client_session_cap(server_exe, client_exe, log_dir, echo_port):
    print("[C] client session cap: %d simultaneous local connections must be "
          "capped, and the cap must be released when they close"
          % MAX_CLIENT_SESSIONS)
    udp_port = free_udp_port()
    socks_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "clientcap",
                                allow_target="127.0.0.1:%d" % echo_port)
    conns = []
    refused = []
    accepted = []
    try:
        require_pair_ready(server, client, socks_port)

        # MAX_CLIENT_SESSIONS + 8: the excess must be refused outright.
        total = MAX_CLIENT_SESSIONS + 8
        for _ in range(total):
            s = socket.create_connection(("127.0.0.1", socks_port), timeout=10)
            s.setblocking(False)
            conns.append(s)
        # A refused connection is closed by the client, so recv() returns
        # b'' (EOF); an accepted one is idle and raises BlockingIOError.
        # NOT select(): its fd_set is capped at FD_SETSIZE=64 entries on
        # Windows, and this phase holds MAX_CLIENT_SESSIONS+8 sockets.
        # Poll instead, until the expected number of refusals shows up or
        # the deadline hits -- the client refuses asynchronously, so a
        # single immediate pass can race its own cap enforcement.
        expected_refused = total - MAX_CLIENT_SESSIONS
        pending = list(conns)
        deadline = time.time() + 10
        while time.time() < deadline and len(refused) < expected_refused:
            still_pending = []
            for s in pending:
                try:
                    data = s.recv(1)
                except (BlockingIOError, InterruptedError):
                    still_pending.append(s)
                    continue
                except OSError:
                    data = b""
                if data == b"":
                    refused.append(s)
                else:
                    # An idle accepted socket never receives data; anything
                    # else stays unclassified rather than misread as EOF.
                    still_pending.append(s)
            pending = still_pending
            if pending and len(refused) < expected_refused:
                time.sleep(0.2)
        accepted = pending
        for s in refused:
            s.close()
        print("  [ok] %d/%d connections accepted, %d refused at the cap"
              % (len(accepted), total, len(refused)))

        if len(accepted) > MAX_CLIENT_SESSIONS:
            raise AssertionError(
                "client accepted %d connections, over its %d cap"
                % (len(accepted), MAX_CLIENT_SESSIONS))
        if len(refused) < total - MAX_CLIENT_SESSIONS:
            raise AssertionError(
                "client refused only %d of the %d over-cap connections"
                % (len(refused), total - MAX_CLIENT_SESSIONS))
        if not client.alive():
            raise AssertionError("client died under the connection burst")
        if not server.alive():
            raise AssertionError("server died under the connection burst")
        print("  [ok] cap enforced exactly; both processes alive")

        # Release path: close everything and prove the tickets come back. A
        # leaked ticket here would permanently shrink the client's capacity.
        for s in accepted:
            try:
                s.close()
            except OSError:
                pass
        accepted = []
        deadline = time.time() + 10
        recovered = False
        while time.time() < deadline:
            try:
                probe = socks5_connect("127.0.0.1", socks_port, "127.0.0.1",
                                       echo_port, 10)
                probe.sendall(b"cap-released")
                got = recv_exact(probe, len(b"cap-released"), 10)
                probe.close()
                if got == b"cap-released":
                    recovered = True
                    break
            except (RuntimeError, OSError):
                time.sleep(0.3)
        if not recovered:
            raise AssertionError(
                "no capacity came back after closing all %d connections: "
                "session-cap tickets are leaking" % MAX_CLIENT_SESSIONS)
        print("  [ok] full capacity restored after the connections closed")
    finally:
        for s in accepted:
            try:
                s.close()
            except OSError:
                pass
        client.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# phase D: stalled target -> connect timeout, clean failure, no leak
# --------------------------------------------------------------------------- #
class StalledTarget:
    """A TCP listener whose accept backlog is permanently full.

    Connections queue into the backlog; what happens to the NEXT connect is
    kernel-specific and was measured on Windows 11 (all variants: backlog 0/1,
    1..8 established fillers): the connect hangs ~2.0s and then fails with
    WSAECONNREFUSED -- Windows RSTs the overflow connection instead of
    dropping the SYN. Linux drops the overflow SYN, so connect() hangs until
    the peer gives up. macOS/BSD also drops the overflow SYN, but its own SYN
    retransmissions (1s + 2s + 4s) run out at ~7.8s and the connect fails
    with ETIMEDOUT -- well before the server's 15s deadline. The suite
    therefore probes the platform at runtime (see phase_stalled_target)
    instead of assuming one behavior; this class only guarantees the backlog
    is full.
    """

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(1)
        self.fillers = []

    def start(self):
        # Queue a couple of connections (they complete the handshake into the
        # backlog) so the accept queue is definitively full afterwards.
        for _ in range(4):
            f = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            f.setblocking(False)
            try:
                f.connect_ex(("127.0.0.1", self.port))
            except OSError:
                pass
            self.fillers.append(f)
        time.sleep(0.3)

    def stop(self):
        for f in self.fillers:
            try:
                f.close()
            except OSError:
                pass
        try:
            self.sock.close()
        except OSError:
            pass


def phase_stalled_target(server_exe, client_exe, log_dir, echo_port):
    print("[D] un-completable upstream connect: the client must get a clean "
          "SOCKS5 error, the session must be reaped, and the service must "
          "survive")
    udp_port = free_udp_port()
    socks_port = free_port()
    stalled_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "stalled",
                                allow_target=["127.0.0.1:%d" % echo_port,
                                              "127.0.0.1:%d" % stalled_port])
    stalled = StalledTarget(stalled_port)
    stalled.start()
    try:
        require_pair_ready(server, client, socks_port)

        # What does THIS kernel do when the accept queue is full? Linux drops
        # the overflow SYN and retries it for minutes, so connect() hangs
        # until the server's CONNECT_TIMEOUT_SEC deadline fires (reply 0x04
        # HOST_UNREACHABLE, reason connect_timeout). Windows RSTs the overflow
        # connection after ~2s, so connect() fails with ECONNREFUSED (reply
        # 0x05 CONNECTION_REFUSED, reason tcp_connect_failed). macOS/BSD also
        # drops the overflow SYN, but its own SYN retransmissions run out at
        # ~7.8s and the connect fails with ETIMEDOUT (reply 0x04 --
        # get_error_reply_code maps timed_out to HOST_UNREACHABLE -- reason
        # tcp_connect_failed), BEFORE the 15s deadline. All three outcomes
        # are clean and correctly mapped by the server; probe once and then
        # branch on the close reason the server actually logged, keeping a
        # timing sanity check per branch. The shared contract -- a clean
        # SOCKS5 error reply, the session reaped via close_connection, and a
        # functional service afterwards -- is asserted either way.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(3.0)
        try:
            probe.connect(("127.0.0.1", stalled_port))
            mode = "accepted"
        except socket.timeout:  # before OSError: it is an OSError subclass
            mode = "blackhole"
        except OSError:
            mode = "refused"
        finally:
            probe.close()
        if mode == "accepted":
            raise AssertionError(
                "stalled-target construction broken: the probe connect "
                "succeeded, so the accept queue was not full and this phase "
                "cannot force an un-completable connect")
        print("  [ok] full-backlog connect behavior on this kernel: %s" % mode)

        s = open_client(socks_port, timeout=30)
        greeting_ok(s)
        s.sendall(ipv4_request(0x01, "127.0.0.1", stalled_port))
        started = time.time()
        rep = read_request_reply(s, timeout=2 * CONNECT_TIMEOUT_SEC + 10)
        elapsed = time.time() - started
        if mode == "blackhole":
            # Branch on the close reason the server actually logged, not on
            # the platform name: Linux can only exit via the server's 15s
            # deadline, while macOS/BSD's own SYN retransmissions give up
            # first (~7.8s, ETIMEDOUT -> 0x04). Both are the clean outcome
            # this phase exists to prove; each branch carries its own timing
            # sanity check.
            assert rep in (0x04, 0x05), \
                "stalled connect must fail with a clean SOCKS5 error, got 0x%02x" % rep
            if wait_for_log(server.log_path,
                            "close_connection from connect_timeout", 5):
                # Deadline-driven path (Linux): the reply must come from the
                # server's timer, not from an early kernel decision.
                assert rep == 0x04, \
                    "connect timeout must reply HOST_UNREACHABLE (0x04), got 0x%02x" % rep
                assert elapsed >= CONNECT_TIMEOUT_SEC - 2, \
                    "deadline-driven reply arrived after only %.1fs" % elapsed
                print("  [ok] connect timeout replied 0x04 after %.1fs" % elapsed)
                reap_reason = "connect_timeout"
            elif wait_for_log(server.log_path,
                              "close_connection from tcp_connect_failed", 5):
                # Kernel-gave-up path (macOS/BSD): the connect error beat the
                # deadline, so the reply may legitimately arrive early.
                assert elapsed < CONNECT_TIMEOUT_SEC, \
                    "kernel error arrived at %.1fs, past the %ds deadline" % (
                        elapsed, CONNECT_TIMEOUT_SEC)
                print("  [ok] kernel SYN retries exhausted before the %ds "
                      "deadline: replied 0x%02x after %.1fs"
                      % (CONNECT_TIMEOUT_SEC, rep, elapsed))
                reap_reason = "tcp_connect_failed"
            else:
                raise AssertionError(
                    "stalled-connect session was never reaped: neither "
                    "connect_timeout nor tcp_connect_failed close in the log")
            expect_eof(s, what="stalled-target connection")
            s.close()
            print("  [ok] session reaped via close_connection(%s)" % reap_reason)
        else:
            assert rep == 0x05, \
                "refused connect must fail with CONNECTION_REFUSED (0x05), got 0x%02x" % rep
            # A refused connect must fail fast, not ride out the 15s deadline.
            assert elapsed < CONNECT_TIMEOUT_SEC, \
                "refused connect took %.1fs, suspiciously close to the %ds deadline" % (
                    elapsed, CONNECT_TIMEOUT_SEC)
            print("  [ok] refused connect replied 0x05 after %.1fs" % elapsed)
            expect_eof(s, what="stalled-target connection")
            s.close()
            if not wait_for_log(server.log_path, "tcp_connect_failed", 5):
                raise AssertionError("server never logged the connect failure")
            if not wait_for_log(server.log_path,
                                "close_connection from tcp_connect_failed", 5):
                raise AssertionError("refused-connect session was never closed")
            print("  [ok] session reaped via close_connection(tcp_connect_failed)")

        if not server.alive():
            raise AssertionError("server died during the stalled connect")
        if not client.alive():
            raise AssertionError("client died during the stalled connect")
        run_case("post-timeout baseline", socks_port, echo_port,
                 b"still alive after the stalled connect", 20)
        print("  [ok] service fully functional afterwards")
    finally:
        stalled.stop()
        client.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# phase E: server restart under the same key / under a different key
# --------------------------------------------------------------------------- #
def phase_restart_and_key_rotation(server_exe, client_exe, log_dir, echo_port):
    print("[E] restart / key rotation: the client must survive a server "
          "restart, recover under the same key, and fail fast under a new one")
    udp_port = free_udp_port()
    socks_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "restart",
                                allow_target="127.0.0.1:%d" % echo_port)
    try:
        require_pair_ready(server, client, socks_port)
        run_case("pre-restart baseline", socks_port, echo_port,
                 b"before the restart", 20)

        # Kill the server outright (no graceful shutdown available to a
        # SIGKILL-equivalent) and bring it back under the SAME key.
        server.stop()
        time.sleep(0.5)
        if not client.alive():
            raise AssertionError("client died when the server was killed")
        print("  [ok] client survived the server being killed")
        server = start_pair(server_exe, client_exe, udp_port, socks_port,
                            KEY, log_dir, "restart",
                            allow_target="127.0.0.1:%d" % echo_port)[0]
        time.sleep(1.0)
        if not server.alive():
            raise AssertionError("restarted server exited early")
        # The client process is untouched; each new local connection builds a
        # fresh KCP session, so the tunnel must simply work again.
        run_case("post-restart recovery (same key)", socks_port, echo_port,
                 b"recovered after the restart", 20)
        print("  [ok] new tunnels work against the restarted server")

        # Now restart under a DIFFERENT key: every new handshake must fail
        # fast (3s KCP handshake timeout), the local app must be told "no"
        # (socket closed), and the client must stay alive and quiet.
        server.stop()
        time.sleep(0.5)
        rotated_key = "rotated_server_key_9999"
        assert rotated_key != KEY
        server = Proc([server_exe, "-H", "127.0.0.1", "-p", str(udp_port),
                       "-k", rotated_key, "-L", "INFO",
                       "--allow-target", "127.0.0.1:%d" % echo_port],
                      os.path.join(log_dir, "restart-rotated-server.log"))
        time.sleep(1.0)
        if not server.alive():
            raise AssertionError("key-rotated server exited early")

        s = open_client(socks_port, timeout=15)
        # No greeting response is possible: the client reads the SOCKS5
        # greeting only AFTER the KCP handshake, which can never complete
        # against a wrong-key server (3s deadline), so it closes the local
        # socket instead. Send the bytes anyway -- a real app would -- and
        # expect the clean close. These 12 bytes sit unread in the client's
        # receive queue when it aborts; close_local_socket drains them first,
        # so the app sees EOF, not RST.
        s.sendall(bytes([0x05, 0x01, 0x00]))
        s.sendall(ipv4_request(0x01, "127.0.0.1", echo_port))
        # No SOCKS5 reply is possible: the KCP handshake below it never
        # completes, so the client closes the local socket instead.
        expect_eof(s, timeout=15, what="wrong-key connection")
        s.close()
        print("  [ok] wrong server key -> fast clean refusal, no half-tunnel")

        if not client.alive():
            raise AssertionError("client died under key rotation")
        if not server.alive():
            raise AssertionError("server died under key rotation")
        # No error storm: the client must not spin on the dead handshake.
        client_lines = log_text(client.log_path).count("\n")
        if client_lines > 400:
            raise AssertionError(
                "client log exploded under key rotation (%d lines): "
                "unthrottled retries?" % client_lines)
        print("  [ok] both processes alive, client log bounded (%d lines)"
              % client_lines)

        # And the client is still fully functional once a matching server
        # comes back -- a key rotation must not wedge the proxy itself.
        server.stop()
        server = start_pair(server_exe, client_exe, udp_port, socks_port,
                            KEY, log_dir, "restart",
                            allow_target="127.0.0.1:%d" % echo_port)[0]
        time.sleep(1.0)
        if not server.alive():
            raise AssertionError("final server restart exited early")
        run_case("final recovery (key restored)", socks_port, echo_port,
                 b"recovered after the key was restored", 20)
        print("  [ok] proxy fully functional after the full cycle")
    finally:
        client.stop()
        server.stop()


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="kcp-proxy adversarial end-to-end suite")
    ap.add_argument("--server", required=True, help="path to kcp-proxy-server binary")
    ap.add_argument("--client", required=True, help="path to kcp-proxy-client binary")
    ap.add_argument("--keep-logs", action="store_true",
                    help="keep the per-process log files for inspection")
    args = ap.parse_args()

    for path in (args.server, args.client):
        if not os.path.exists(path):
            print("E2E ADVERSARIAL FAILED: binary not found: %s" % path,
                  file=sys.stderr)
            return 1
    # Normalize before spawning: a relative path with forward slashes is not
    # resolvable by CreateProcess on Windows (see normalize_binary_path).
    args.server = normalize_binary_path(args.server)
    args.client = normalize_binary_path(args.client)
    augment_dll_path(args.server)
    augment_dll_path(args.client)

    log_dir = tempfile.mkdtemp(prefix="kcp_adv_logs_")
    echo_port = free_port()
    echo = EchoServer(echo_port)
    echo.start()

    print("E2E adversarial suite: server=%s" % args.server)
    log_paths = []
    try:
        # Register each phase's logs BEFORE running the phase: a phase that
        # raises must leave its own evidence in the dump below (and the
        # cleanup in ``finally`` must still find the files). Registering
        # after the call silently drops the failing phase's logs.
        log_paths += [os.path.join(log_dir, "abuse-server.log"),
                      os.path.join(log_dir, "abuse-client.log")]
        phase_protocol_abuse(args.server, args.client, log_dir, echo_port)
        log_paths += [os.path.join(log_dir, "multiflood-server.log"),
                      os.path.join(log_dir, "multiflood-client.log")]
        phase_multi_source_flood(args.server, args.client, log_dir, echo_port)
        log_paths += [os.path.join(log_dir, "clientcap-server.log"),
                      os.path.join(log_dir, "clientcap-client.log")]
        phase_client_session_cap(args.server, args.client, log_dir, echo_port)
        log_paths += [os.path.join(log_dir, "stalled-server.log"),
                      os.path.join(log_dir, "stalled-client.log")]
        phase_stalled_target(args.server, args.client, log_dir, echo_port)
        log_paths += [os.path.join(log_dir, "restart-server.log"),
                      os.path.join(log_dir, "restart-client.log"),
                      os.path.join(log_dir, "restart-rotated-server.log")]
        phase_restart_and_key_rotation(args.server, args.client, log_dir,
                                       echo_port)

        print("E2E ADVERSARIAL TEST PASSED")
        return 0
    except Exception as exc:  # noqa: BLE001 - surface any failure as a test failure
        print("E2E ADVERSARIAL TEST FAILED: %s" % exc, file=sys.stderr)
        dump_logs(log_paths)
        return 1
    finally:
        echo.stop()
        if not args.keep_logs:
            for path in log_paths:
                try:
                    os.remove(path)
                except OSError:
                    pass
        else:
            print("logs kept in %s" % log_dir)


if __name__ == "__main__":
    random.seed(0)
    sys.exit(main())
