#!/usr/bin/env python3
"""Negative / robustness end-to-end suite for the SOCKS5-over-KCP proxy.

The golden happy path is covered by ``tunnel_e2e.py``. This suite covers what a
security-sensitive proxy must *survive* but never be *seen* to succeed at:

  A. Wrong key      - a client started with a mismatched key must be silently
                      dropped by the server (no session is ever created), and
                      the local app must be told "no" (socket closed/reset)
                      rather than be handed a tunnel that looks alive.
  B. Garbage flood  - random, hostile, truncated and oversize datagrams aimed
                      at the server's UDP port must not crash it, must be
                      rejected at the auth boundary before any KCP work, must
                      trip the global auth rate limiter, and must leave the
                      service working normally afterwards.
  C. Concurrency    - N simultaneous tunnels must each carry their own bytes
                      with no cross-session bleed, and every session must be
                      reclaimed once its target closes (created == closed); an
                      abrupt RST must not wedge the server either.
  D. Half-close     - a local app that stops sending half-closes the tunnel so
                      an in-flight response is not truncated, but that grace
                      must be bounded: a slow response spread past the grace
                      must still arrive byte-exact, while a stalled one whose
                      target never closes must be reclaimed (session + UDP
                      socket released) instead of leaking one upstream
                      connection per abandoned app.

Every phase runs fully offline on loopback. Assertions are made against real
process behaviour plus the structured logs (captured to files), never against
mocks: server logs go to stderr, so each process gets its own log file, which
also keeps the flood from filling (and blocking on) a pipe buffer.

Note on the allowlist: the server's SSRF guard refuses loopback targets by
default, so the phases that need a local target pass ``--allow-target``. Phase B
also asserts the *opposite* default in ``tunnel_e2e.py``; here the flag is only
a lab affordance so the offline suite can reach its own echo server.

Exit code 0 on success, non-zero with a diagnostic on failure.
"""

import argparse
import os
import random
import socket
import struct
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
    recv_exact,
    run_case,
    socks5_connect,
    wait_for_port,
)

# A well-formed-length but wrong key: the server must never accept it.
WRONG_KEY = "totally_wrong_key_0000000"

N_CONCURRENT = 100      # phase C: simultaneous tunnels
N_RST = 10              # phase C: abrupt-reset connections
FLOOD_PACKETS = 1500    # phase B: must exceed MAX_AUTH_ATTEMPTS_PER_SEC (500)


# --------------------------------------------------------------------------- #
# process + log helpers
# --------------------------------------------------------------------------- #
class Proc:
    """A spawned binary whose combined stdout/stderr goes to its own log file."""

    def __init__(self, cmd, log_path):
        self.cmd = cmd
        self.log_path = log_path
        # Binary mode: log lines are ASCII, and this avoids any text-layer
        # buffering surprises when we read the file back while the child writes.
        self._fh = open(log_path, "wb")
        self.proc = subprocess.Popen(cmd, stdout=self._fh, stderr=subprocess.STDOUT)

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
    """Read a log file written by another process (tolerates partial writes)."""
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def count_in(path, needle):
    return log_text(path).count(needle)


def wait_for_count(path, needle, target, timeout):
    """Poll a log file until ``needle`` appears at least ``target`` times."""
    deadline = time.time() + timeout
    seen = 0
    while time.time() < deadline:
        seen = count_in(path, needle)
        if seen >= target:
            return seen
        time.sleep(0.2)
    return seen


def wait_until(predicate, timeout, interval=0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def dump_logs(log_paths, lines=12):
    for path in log_paths:
        text = log_text(path).strip().splitlines()
        print("  --- tail %s ---" % os.path.basename(path), file=sys.stderr)
        for line in text[-lines:]:
            print("      " + line, file=sys.stderr)


def start_pair(server_exe, client_exe, udp_port, socks_port, key, log_dir, tag,
               allow_target=None, log_level="INFO", client_key=None,
               half_close_grace=None):
    """Start a server/client pair. ``client_key`` defaults to ``key``; passing a
    different one is how the wrong-key phase provokes an auth failure.
    ``half_close_grace`` overrides the client's half-close grace so the
    reclamation phase does not have to wait out the production value."""
    server_cmd = [server_exe, "-H", "127.0.0.1", "-p", str(udp_port),
                  "-k", key, "-L", log_level]
    if allow_target:
        server_cmd += ["--allow-target", allow_target]
    server = Proc(server_cmd, os.path.join(log_dir, tag + "-server.log"))
    client_cmd = [client_exe, "-s", "127.0.0.1", "-p", str(udp_port),
                  "-H", "127.0.0.1", "-l", str(socks_port),
                  "-k", client_key or key, "-L", log_level]
    if half_close_grace is not None:
        client_cmd += ["--half-close-grace", str(half_close_grace)]
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
# fase C target: echo every chunk, then close after a short quiet period
# --------------------------------------------------------------------------- #
class CloseAfterEchoServer:
    """Echoes each received chunk, then closes once the stream goes quiet.

    Used by phase C so the tunnel's upstream really terminates: the server then
    takes its ``target_drained`` path and must evict the session from its table.
    """

    QUIET = 0.3

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(128)
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.3)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(self.QUIET)
            while True:
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    break  # request complete: nothing more is coming
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# phase A: wrong key must be dropped, not half-accepted
# --------------------------------------------------------------------------- #
def phase_wrong_key(server_exe, client_exe, log_dir):
    print("[A] wrong key: server must drop the client, app must be told no")
    udp_port = free_port()
    socks_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "wrongkey", log_level="INFO",
                                client_key=WRONG_KEY)
    try:
        # The server needs a moment to bind its UDP socket before we can judge
        # the client's failure, but the client's SOCKS listener is the readiness
        # signal we can actually observe.
        if not wait_for_port("127.0.0.1", socks_port, 20):
            raise RuntimeError("client SOCKS port never came up (wrong-key phase)")

        # A local app asks for a tunnel. With a wrong key the client can never
        # complete the KCP handshake, so it must close the app socket (or have
        # it reset) instead of answering SOCKS5 and pretending to work.
        app = socket.create_connection(("127.0.0.1", socks_port), timeout=10)
        try:
            app.settimeout(12)
            app.sendall(bytes([0x05, 0x01, 0x00]))  # greeting: no-auth
            try:
                data = app.recv(2)
                outcome = "closed" if data == b"" else "replied:%r" % data
            except socket.timeout:
                outcome = "hang"
            except ConnectionResetError:
                outcome = "reset"
        finally:
            try:
                app.close()
            except OSError:
                pass

        if outcome == "hang":
            raise AssertionError(
                "wrong-key client left the local app hanging: no reply and no close")
        if outcome.startswith("replied"):
            raise AssertionError(
                "wrong-key client answered SOCKS5 (%s) instead of refusing" % outcome)
        print("  [ok] local app was told no (%s), not handed a dead tunnel" % outcome)

        # Give the client time to hit its 3s handshake timeout and log it.
        if not wait_until(lambda: "handshake timeout" in log_text(client.log_path), 10):
            raise AssertionError(
                "client never logged a KCP handshake timeout; it may have "
                "falsely reported a connection")

        client_log = log_text(client.log_path)
        if "handshake confirmed" in client_log:
            raise AssertionError(
                "client reported 'handshake confirmed' for a wrong key "
                "(remote state is misleading)")
        print("  [ok] client logged the timeout, never claimed a confirmed handshake")

        # The server must not have allocated any session for the bad client:
        # the packet has to die at the auth boundary.
        srv_log = log_text(server.log_path)
        if "new session" in srv_log:
            raise AssertionError("server created a session for an unauthenticated client")
        if "DECRYPT_FAILED" not in srv_log:
            raise AssertionError("server did not reject the wrong-key packet at auth")
        print("  [ok] server created no session; packet rejected (DECRYPT_FAILED)")

        if not server.alive() or not client.alive():
            raise AssertionError("a process died during the wrong-key phase")
        print("  [ok] both processes alive")
    finally:
        client.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# phase B: garbage flood must be absorbed, throttled, and survivable
# --------------------------------------------------------------------------- #
def _fake_kcp_header():
    """A structurally plausible ikcp header: conv cmd frg wnd ts sn una len."""
    return struct.pack("<IBB H III I",
                       random.getrandbits(32),      # conv
                       random.choice([81, 82, 83, 84]),  # cmd (PUSH/ACK/...)
                       random.randint(0, 1),        # frg
                       random.randint(0, 65535),    # wnd
                       random.getrandbits(32),      # ts
                       random.getrandbits(32),      # sn
                       random.getrandbits(32),      # una
                       random.randint(0, 1400))     # len


def phase_garbage_flood(server_exe, client_exe, log_dir, echo_port):
    print("[B] garbage flood: hostile UDP datagrams must not crash or degrade the server")
    udp_port = free_port()
    socks_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "flood",
                                allow_target="127.0.0.1:%d" % echo_port,
                                log_level="INFO")
    try:
        require_pair_ready(server, client, socks_port)
        run_case("pre-flood baseline", socks_port, echo_port,
                 b"baseline before the flood", 20)

        # Snapshot the session count so we can prove the flood allocates *zero*
        # server state (a garbage packet must never get as far as a session).
        sessions_before = count_in(server.log_path, "new session:")

        # Edge cases first: zero length, header-sized, truncation boundaries,
        # oversize, and the IPv4 UDP maximum.
        edge_sizes = [0, 1, 2, 4, 12, 23, 24, 25, 64, 1400, 1401, 2000, 8192, 65507]
        sent = 0
        skipped = 0
        # Several source sockets exercise the per-endpoint session path with
        # distinct session ids, not one shared hot sid.
        senders = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(4)]
        try:
            for i in range(FLOOD_PACKETS):
                sock = senders[i % len(senders)]
                if i < len(edge_sizes):
                    size = edge_sizes[i]
                else:
                    size = random.randint(1, 1400)
                # Mix pure noise with packets that look like a real encrypted
                # frame (KCP header + payload) so the parser is hit with
                # structured input too, not just random bytes.
                if size >= 24 and random.random() < 0.4:
                    packet = _fake_kcp_header() + os.urandom(max(0, size - 24))
                else:
                    packet = os.urandom(size)
                try:
                    sock.sendto(packet, ("127.0.0.1", udp_port))
                    sent += 1
                except OSError:
                    skipped += 1  # e.g. EMSGSIZE for the 64KB probe
        finally:
            for sock in senders:
                try:
                    sock.close()
                except OSError:
                    pass
        print("  [ok] blasted %d datagrams (sizes 0..65507, %d skipped by the OS)"
              % (sent, skipped))

        if not server.alive():
            raise AssertionError("server died under the garbage flood")
        if not client.alive():
            raise AssertionError("client died during the garbage flood")
        print("  [ok] server survived the flood")

        srv_log = log_text(server.log_path)
        if "DECRYPT_FAILED" not in srv_log:
            raise AssertionError("garbage was not rejected at the auth boundary")
        print("  [ok] garbage rejected at auth (DECRYPT_FAILED), never reached KCP")

        sessions_after = count_in(server.log_path, "new session:")
        if sessions_after != sessions_before:
            raise AssertionError(
                "garbage created %d server session(s); hostile packets must not "
                "allocate any state" % (sessions_after - sessions_before))
        print("  [ok] garbage allocated no session on the server")

        if "auth attempt rate limit reached" not in srv_log:
            raise AssertionError(
                "auth throttle never engaged under a %d-packet flood "
                "(a flood could pin the CPU on AEAD decrypts)" % FLOOD_PACKETS)
        print("  [ok] auth rate limiter engaged under the flood")

        # The throttle is a global per-second budget. A legitimate handshake in
        # the same window would be dropped, so wait for the window to roll over
        # before proving the service is intact.
        time.sleep(1.5)
        run_case("post-flood tunnel", socks_port, echo_port,
                 os.urandom(4096), 20)
        if not server.alive() or not client.alive():
            raise AssertionError("a process died after the flood")
        print("  [ok] service intact after the flood")
    finally:
        client.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# phase C: concurrency + session reclamation
# --------------------------------------------------------------------------- #
def _concurrent_tunnel(index, socks_port, target_port, results, timeout):
    """One worker: unique payload in, identical payload out (or an error)."""
    payload = ("tunnel-%03d-" % index).encode() + bytes([index % 256]) * 480
    try:
        with socks5_connect("127.0.0.1", socks_port, "127.0.0.1", target_port, timeout) as s:
            s.sendall(payload)
            got = recv_exact(s, len(payload), timeout)
        results[index] = (got == payload, len(got))
    except Exception as exc:  # noqa: BLE001 - reported as a per-tunnel failure
        results[index] = (False, str(exc))


def phase_concurrency(server_exe, client_exe, log_dir):
    print("[C] concurrency: %d simultaneous tunnels, then session reclamation"
          % N_CONCURRENT)
    target_port = free_port()
    target = CloseAfterEchoServer(target_port)
    target.start()

    udp_port = free_port()
    socks_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "concurrency",
                                allow_target="127.0.0.1:%d" % target_port,
                                log_level="INFO")
    try:
        require_pair_ready(server, client, socks_port)

        # The readiness probe opens (and abandons) one connection of its own, so
        # measure the burst as a delta from a post-readiness baseline.
        base_created = count_in(server.log_path, "new session:")
        base_drained = count_in(server.log_path, "close_connection from target_drained")

        results = {}
        threads = [threading.Thread(target=_concurrent_tunnel,
                                    args=(i, socks_port, target_port, results, 30))
                   for i in range(N_CONCURRENT)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        failed = {i: r for i, r in results.items() if not r[0]}
        if failed:
            sample = list(failed.items())[:3]
            raise AssertionError("%d/%d tunnels failed: %s"
                                 % (len(failed), N_CONCURRENT, sample))
        print("  [ok] %d concurrent tunnels each got their own bytes back "
              "(no cross-session bleed)" % N_CONCURRENT)

        if not server.alive() or not client.alive():
            raise AssertionError("a process died under concurrent load")

        # Every tunnel must be registered...
        created = count_in(server.log_path, "new session:") - base_created
        if created < N_CONCURRENT:
            raise AssertionError("server logged only %d new sessions for %d "
                                 "concurrent tunnels" % (created, N_CONCURRENT))
        print("  [ok] server registered %d/%d burst sessions"
              % (created, N_CONCURRENT))

        # ...and reclaimed once its target closed (the session is erased from
        # sessions_/connections_ inside close_connection, so this proves the
        # cleanup actually happened rather than merely being scheduled).
        drained_total = wait_for_count(server.log_path,
                                       "close_connection from target_drained",
                                       base_drained + N_CONCURRENT, 25)
        drained = drained_total - base_drained
        if drained < N_CONCURRENT:
            raise AssertionError(
                "only %d/%d sessions were reclaimed after their target closed "
                "(session/table leak)" % (drained, N_CONCURRENT))
        print("  [ok] all %d burst sessions reclaimed (no session/table leak)"
              % drained)

        # An abrupt reset (SO_LINGER 0 => RST, not FIN) must not wedge anything.
        for _ in range(N_RST):
            try:
                s = socks5_connect("127.0.0.1", socks_port, "127.0.0.1", target_port, 20)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.close()
            except (OSError, RuntimeError):
                pass
        time.sleep(0.5)
        if not server.alive() or not client.alive():
            raise AssertionError("a process died after abrupt resets")
        run_case("post-RST tunnel", socks_port, target_port,
                 b"still alive after resets", 20)
        print("  [ok] %d abrupt resets absorbed; service still works" % N_RST)
    finally:
        client.stop()
        server.stop()
        target.stop()


# --------------------------------------------------------------------------- #
# phase D: the half-close must be bounded without truncating a slow response
# --------------------------------------------------------------------------- #
class HalfCloseTarget:
    """A target that answers with delayed chunks and then NEVER closes.

    The first byte of the request picks the behaviour:

      ``C`` - send ``chunks`` payloads ``gap`` apart, then stay silent with the
              connection still open (a slow but progressing response).
      ``I`` - send nothing at all, connection open forever (a stalled long-poll
              or an abandoned keep-alive connection).
      ``E`` - echo everything back (a health check for the tunnel).

    Never closing is the point: it is what makes the client-side half-close
    unreclaimable without a grace, because the server never reaches its
    target-closed drain path and the keepalives keep both idle clocks fresh.
    """

    def __init__(self, port, chunks=3, gap=1.2):
        self.port = port
        self.chunks = chunks
        self.gap = gap
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.3)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(15)
            request = conn.recv(1)
            if not request:
                return
            if request == b"E":
                conn.sendall(request)
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
                return
            if request == b"C":
                for i in range(self.chunks):
                    time.sleep(self.gap)
                    conn.sendall(b"chunk-%02d:" % i + bytes([65 + i]) * 64)
            # Modes C and I then hold the connection open without ever sending
            # FIN, so only the client's own grace can end the tunnel.
            while not self._stop:
                time.sleep(0.2)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def phase_half_close(server_exe, client_exe, log_dir):
    """A local app that stops sending must not pin a tunnel forever.

    The client deliberately half-closes when the app's read side reports EOF:
    the response may still be in flight, and closing would truncate it. But the
    application keepalives keep BOTH peers' idle clocks fresh, so if the target
    never closes either, nothing ever reclaims the tunnel: it leaks the local
    socket, the UDP socket and one upstream connection per abandoned app until
    the client hits MAX_CLIENT_SESSIONS and refuses everything. This phase pins
    both halves of the fix -- a progressing response survives the grace, a
    stalled one is reclaimed.
    """
    print("[D] half-close: a slow response must survive, a stalled one must be reclaimed")
    grace = 3          # seconds; short so the phase stays fast
    chunks = 3
    gap = 1.2          # chunks land over ~3.6s, i.e. past the 3s grace

    target_port = free_port()
    target = HalfCloseTarget(target_port, chunks=chunks, gap=gap)
    target.start()

    udp_port = free_port()
    socks_port = free_port()
    server, client = start_pair(server_exe, client_exe, udp_port, socks_port,
                                KEY, log_dir, "halfclose",
                                allow_target="127.0.0.1:%d" % target_port,
                                log_level="INFO",
                                half_close_grace=grace)
    try:
        require_pair_ready(server, client, socks_port)
        # wait_for_port() probes the listener with a connect/close, which the
        # client turns into a session of its own. Let it settle so the counters
        # below measure only this phase's tunnels.
        time.sleep(1.0)

        # on_close() emits a stats line, so this is a precise count of client
        # sessions actually released (not merely of tunnels that logged).
        base_closed = count_in(client.log_path, "stats tx_pkt=")
        base_expired = count_in(client.log_path, "half-close grace expired")

        # --- D1: the grace must not truncate a response still in flight -----
        # The app half-closes its write side, then reads a response the target
        # delivers in chunks spread across (and past) the grace window. Every
        # byte must arrive: reclaiming at the deadline without checking for
        # progress would cut the response.
        app = socks5_connect("127.0.0.1", socks_port, "127.0.0.1", target_port, 20)
        app.sendall(b"C")
        app.shutdown(socket.SHUT_WR)
        expected = b"".join(b"chunk-%02d:" % i + bytes([65 + i]) * 64
                            for i in range(chunks))
        try:
            got = recv_exact(app, len(expected), 30)
        except RuntimeError as exc:
            raise AssertionError(
                "half-closed tunnel truncated the slow response (%s): the grace "
                "may only reclaim a tunnel that stopped making progress" % exc)
        finally:
            app.close()
        if got != expected:
            raise AssertionError(
                "half-closed tunnel corrupted the slow response: expected %d "
                "bytes, got %d" % (len(expected), len(got)))
        print("  [ok] %d-byte response delivered in %d chunks over %.1fs (> grace=%ds): "
              "no truncation" % (len(expected), chunks, gap * chunks, grace))

        # D1's target never closes either, so its own tunnel must be reclaimed
        # by the same grace. Waiting for that also gives D2 a clean baseline.
        if not wait_until(
                lambda: count_in(client.log_path, "stats tx_pkt=") > base_closed,
                grace + 20):
            raise AssertionError(
                "the half-closed tunnel was never reclaimed after its target "
                "went quiet (session leak)")
        print("  [ok] it was reclaimed once the chunks stopped, not left pinned")

        # --- D2: a stalled half-close must be reclaimed --------------------
        base_closed = count_in(client.log_path, "stats tx_pkt=")
        base_expired = count_in(client.log_path, "half-close grace expired")

        app = socks5_connect("127.0.0.1", socks_port, "127.0.0.1", target_port, 20)
        app.sendall(b"I")           # target will never answer and never close
        time.sleep(0.5)
        app.close()                 # local app abandons the tunnel (read EOF)

        # Control: nothing may be reclaimed before the grace elapses, otherwise
        # the fix would be a truncation hazard rather than a bound.
        time.sleep(1.0)
        if count_in(client.log_path, "half-close grace expired") > base_expired:
            raise AssertionError(
                "half-closed tunnel was reclaimed before the grace elapsed")

        if not wait_until(
                lambda: count_in(client.log_path, "half-close grace expired") > base_expired,
                grace + 20):
            raise AssertionError(
                "client never reclaimed a half-closed tunnel whose target never "
                "closes: the tunnel (and one upstream connection) leaks forever")

        if not wait_until(
                lambda: count_in(client.log_path, "stats tx_pkt=") > base_closed, 15):
            raise AssertionError(
                "client logged the half-close expiry but never tore the session "
                "down (the KCP session and its UDP socket leaked)")
        print("  [ok] stalled half-closed tunnel reclaimed after ~%ds; its KCP "
              "session and UDP socket were released" % grace)

        if not server.alive() or not client.alive():
            raise AssertionError("a process died during the half-close phase")

        # The client must still be fully functional: open a fresh tunnel.
        run_case("post-half-close tunnel", socks_port, target_port,
                 b"E" + b"still healthy after the grace", 20)
        print("  [ok] the client still tunnels normally afterwards")
    finally:
        client.stop()
        server.stop()
        target.stop()


def main():
    ap = argparse.ArgumentParser(
        description="kcp-proxy negative / robustness end-to-end suite")
    ap.add_argument("--server", required=True, help="path to kcp-proxy-server binary")
    ap.add_argument("--client", required=True, help="path to kcp-proxy-client binary")
    ap.add_argument("--keep-logs", action="store_true",
                    help="keep the per-process log files for inspection")
    args = ap.parse_args()

    for path in (args.server, args.client):
        if not os.path.exists(path):
            print("E2E ROBUSTNESS FAILED: binary not found: %s" % path, file=sys.stderr)
            return 1
    augment_dll_path(args.server)
    augment_dll_path(args.client)

    log_dir = tempfile.mkdtemp(prefix="kcp_e2e_logs_")
    echo_port = free_port()
    echo = EchoServer(echo_port)
    echo.start()

    print("E2E robustness suite: server=%s" % args.server)
    log_paths = []
    try:
        phase_wrong_key(args.server, args.client, log_dir)
        log_paths += [os.path.join(log_dir, "wrongkey-server.log"),
                      os.path.join(log_dir, "wrongkey-client.log")]
        phase_garbage_flood(args.server, args.client, log_dir, echo_port)
        log_paths += [os.path.join(log_dir, "flood-server.log"),
                      os.path.join(log_dir, "flood-client.log")]
        phase_concurrency(args.server, args.client, log_dir)
        log_paths += [os.path.join(log_dir, "concurrency-server.log"),
                      os.path.join(log_dir, "concurrency-client.log")]
        phase_half_close(args.server, args.client, log_dir)
        log_paths += [os.path.join(log_dir, "halfclose-server.log"),
                      os.path.join(log_dir, "halfclose-client.log")]

        print("E2E ROBUSTNESS TEST PASSED")
        return 0
    except Exception as exc:  # noqa: BLE001 - surface any failure as a test failure
        print("E2E ROBUSTNESS TEST FAILED: %s" % exc, file=sys.stderr)
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
