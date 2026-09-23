#!/usr/bin/env python3
"""End-to-end tunnel test: server <-> client <-> echo target.

Spawns the built ``kcp-proxy-server`` and ``kcp-proxy-client`` binaries, a
local TCP echo server and a minimal dependency-free SOCKS5 client, then drives
real payloads through the full SOCKS5-over-KCP path and asserts they come back
byte-for-byte.

The test is fully offline: every endpoint is loopback. Because the server's
SSRF guard refuses loopback/private targets by default, the server is launched
with ``--allow-target 127.0.0.1:<echo_port>`` so the local echo target is
explicitly whitelisted. That allowlist is empty unless an operator passes
``--allow-target``, so production traffic stays fully protected.

Exit code 0 on success, non-zero with a diagnostic on failure.
"""

import argparse
import os
import random
import socket
import subprocess
import sys
import threading
import time

KEY = "e2e_tunnel_test_key_123456"  # >= 16 chars, required by the server


def free_port():
    """Grab an ephemeral TCP port the OS just handed out."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class EchoServer:
    """Trivial TCP echo server: every byte received is echoed back in order."""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.5)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _handle(conn):
        try:
            while True:
                data = conn.recv(65536)
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


class OneShotTarget:
    """Accepts connections, sends a fixed payload, then hangs up.

    Models a target that answers and closes -- HTTP/1.0 without
    Content-Length, a one-shot daemon, a shell command that exits. This is the
    case where the server side of the tunnel reaches EOF while the local app is
    still reading, so the app can only finish when the server's half-close
    reaches it.
    """

    def __init__(self, port, payload):
        self.port = port
        self.payload = payload
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.5)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.sendall(self.payload)
        except OSError:
            pass
        finally:
            # close() is what actually emits the FIN the server observes as
            # its target-EOF; nothing was read, so the receive queue is empty
            # and the close is clean.
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


class EofWatcher:
    """Accepts one connection, reads until EOF, and records when it arrived.

    The mirror image of OneShotTarget: it answers the question "did the local
    app's half-close actually reach the target, and how long did it take?".
    """

    def __init__(self, port, ack=b""):
        self.port = port
        self.ack = ack
        self.received = bytearray()
        self.eof_event = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.5)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                self.received += data
        except OSError:
            pass
        self.eof_event.set()
        try:
            if self.ack:
                conn.sendall(self.ack)
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


def recv_exact(sock, n, timeout):
    """Read exactly n bytes or raise."""
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("connection closed after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return bytes(buf)


def socks5_connect(socks_host, socks_port, target_host, target_port, timeout):
    """Minimal SOCKS5 CONNECT (no-auth). Returns the established socket."""
    s = socket.create_connection((socks_host, socks_port), timeout=timeout)
    s.settimeout(timeout)

    # Greeting: VER=5, NMETHODS=1, METHODS=[0x00 no-auth].
    s.sendall(bytes([0x05, 0x01, 0x00]))
    ver, method = recv_exact(s, 2, timeout)
    if ver != 0x05 or method != 0x00:
        raise RuntimeError("bad SOCKS5 method selection: ver=%d method=%d" % (ver, method))

    # Request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=1 (IPv4) + addr + port.
    req = bytes([0x05, 0x01, 0x00, 0x01])
    req += bytes(int(o) for o in target_host.split("."))
    req += bytes([(target_port >> 8) & 0xFF, target_port & 0xFF])
    s.sendall(req)

    # Reply: VER REP RSV ATYP BND.ADDR BND.PORT (variable length by ATYP).
    header = recv_exact(s, 4, timeout)
    if header[0] != 0x05:
        raise RuntimeError("bad SOCKS5 reply version: %d" % header[0])
    if header[1] != 0x00:
        raise RuntimeError("SOCKS5 CONNECT refused, REP=0x%02x" % header[1])
    atyp = header[3]
    if atyp == 0x01:
        recv_exact(s, 6, timeout)
    elif atyp == 0x04:
        recv_exact(s, 18, timeout)
    elif atyp == 0x03:
        dlen = recv_exact(s, 1, timeout)[0]
        recv_exact(s, dlen + 2, timeout)
    else:
        raise RuntimeError("bad SOCKS5 reply ATYP=0x%02x" % atyp)
    return s


def wait_for_eof(sock, timeout):
    """Read until EOF; return how many seconds that took.

    Raises rather than returning on timeout so a caller can never mistake
    "still blocked" for "closed promptly".
    """
    sock.settimeout(timeout)
    start = time.time()
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            raise AssertionError("no EOF within %.1fs" % timeout)
        if not chunk:
            return time.time() - start
        raise AssertionError("expected EOF, got %d unexpected bytes" % len(chunk))


def wait_for_port(host, port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def normalize_binary_path(path):
    """Return an absolute path with native separators.

    Windows' CreateProcess does not resolve a *relative* path written with
    forward slashes: ``subprocess.Popen(["build/Release/kcp-proxy-server.exe"])``
    fails with ``[WinError 2] The system cannot find the file specified`` even
    though the file exists and ``os.path.exists`` agrees. That is exactly the
    form the documented invocation uses, so the failure was a confusing
    "binary not found" against a binary that is right there. Normalizing once,
    here, makes every downstream Popen call work on all platforms.
    """
    return os.path.abspath(os.path.normpath(path))


def augment_dll_path(exe_path):
    """On Windows, add the vcpkg runtime dir next to the built binary to PATH.

    The binaries are dynamically linked against vcpkg (OpenSSL/fmt); CTest runs
    from the build tree where those DLLs live in vcpkg_installed. Prepending the
    candidate dirs lets the spawned process find them without a manual setup.
    """
    if os.name != "nt":
        return
    exe_dir = os.path.dirname(os.path.abspath(exe_path))
    candidates = []
    cur = exe_dir
    for _ in range(4):
        candidates.append(os.path.join(cur, "vcpkg_installed", "x64-windows", "bin"))
        candidates.append(os.path.join(cur, "vcpkg_installed", "x64-windows", "debug", "bin"))
        cur = os.path.dirname(cur)
    existing = [c for c in candidates if os.path.isdir(c)]
    if existing:
        os.environ["PATH"] = os.pathsep.join(existing + [os.environ.get("PATH", "")])


def start_pair(server_exe, client_exe, udp_port, socks_port, allow_target=None):
    """Start a server+client pair on loopback; return the two Popen handles.

    `allow_target` is one "HOST:PORT" string or a list of them (the server's
    --allow-target is repeatable).
    """
    server_cmd = [server_exe, "-H", "127.0.0.1", "-p", str(udp_port), "-k", KEY, "-L", "WARNING"]
    if allow_target:
        for target in ([allow_target] if isinstance(allow_target, str) else allow_target):
            server_cmd += ["--allow-target", target]
    server_proc = subprocess.Popen(
        server_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    client_proc = subprocess.Popen(
        [client_exe, "-s", "127.0.0.1", "-p", str(udp_port), "-H", "127.0.0.1",
         "-l", str(socks_port), "-k", KEY, "-L", "WARNING"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return server_proc, client_proc


def wait_pair_ready(server_proc, client_proc, socks_port, timeout=15):
    if not wait_for_port("127.0.0.1", socks_port, timeout):
        raise RuntimeError("client SOCKS port never came up on 127.0.0.1:%d" % socks_port)
    time.sleep(0.3)
    if server_proc.poll() is not None:
        raise RuntimeError("server exited early with code %s" % server_proc.returncode)
    if client_proc.poll() is not None:
        raise RuntimeError("client exited early with code %s" % client_proc.returncode)


def run_case(label, socks_port, echo_port, payload, timeout):
    with socks5_connect("127.0.0.1", socks_port, "127.0.0.1", echo_port, timeout) as s:
        s.sendall(payload)
        got = recv_exact(s, len(payload), timeout)
    if got != payload:
        raise AssertionError(
            "%s: payload mismatch (sent %d bytes, got %d bytes)" % (label, len(payload), len(got))
        )
    print("  [ok] %s: %d bytes round-tripped byte-exact" % (label, len(payload)))


def target_is_refused(socks_port, echo_port, timeout):
    """Return True if a SOCKS5 CONNECT to the local target is refused."""
    try:
        s = socks5_connect("127.0.0.1", socks_port, "127.0.0.1", echo_port, timeout)
    except RuntimeError as exc:
        return ("refused" in str(exc)) or ("closed" in str(exc))
    except OSError:
        return True
    s.close()
    return False


def main():
    ap = argparse.ArgumentParser(description="kcp-proxy end-to-end tunnel test")
    ap.add_argument("--server", required=True, help="path to kcp-proxy-server binary")
    ap.add_argument("--client", required=True, help="path to kcp-proxy-client binary")
    args = ap.parse_args()

    for path in (args.server, args.client):
        if not os.path.exists(path):
            print("E2E FAILED: binary not found: %s" % path, file=sys.stderr)
            return 1
    # Normalize before spawning: a relative path with forward slashes is not
    # resolvable by CreateProcess on Windows (see normalize_binary_path).
    args.server = normalize_binary_path(args.server)
    args.client = normalize_binary_path(args.client)
    augment_dll_path(args.server)
    augment_dll_path(args.client)

    echo_port = free_port()
    echo = EchoServer(echo_port)
    echo.start()

    procs = []
    extra_servers = []
    try:
        # --- Phase 1: allowlisted local target -> data survives the tunnel ---
        udp1 = free_port()
        socks1 = free_port()
        sp1, cp1 = start_pair(args.server, args.client, udp1, socks1,
                              "127.0.0.1:%d" % echo_port)
        procs += [sp1, cp1]
        wait_pair_ready(sp1, cp1, socks1)
        print("E2E tunnel test: server=127.0.0.1:%d client_socks=127.0.0.1:%d echo=127.0.0.1:%d"
              % (udp1, socks1, echo_port))

        run_case("small payload", socks1, echo_port,
                 b"KCP tunnel E2E golden test\n" + bytes(range(256)), 20)
        run_case("large payload (>64KB)", socks1, echo_port,
                 os.urandom(256 * 1024), 40)
        run_case("binary payload (all byte values)", socks1, echo_port,
                 bytes(range(256)) * 4, 20)

        # Streaming: several ordered messages on one connection.
        with socks5_connect("127.0.0.1", socks1, "127.0.0.1", echo_port, 20) as s:
            for i in range(10):
                msg = ("seq-%03d-" % i).encode() + os.urandom(1000)
                s.sendall(msg)
                got = recv_exact(s, len(msg), 20)
                if got != msg:
                    raise AssertionError("streaming message %d corrupted" % i)
        print("  [ok] streaming: 10 ordered messages byte-exact")

        # --- Phase 2: default guard (no allowlist) must refuse the same target ---
        udp2 = free_port()
        socks2 = free_port()
        sp2, cp2 = start_pair(args.server, args.client, udp2, socks2, allow_target=None)
        procs += [sp2, cp2]
        wait_pair_ready(sp2, cp2, socks2)
        if not target_is_refused(socks2, echo_port, 20):
            raise AssertionError(
                "SSRF guard did NOT refuse loopback target without --allow-target")
        print("  [ok] default SSRF guard refuses loopback target (no allowlist)")

        # --- Phase 3: half-close (FIN) reaches the far end promptly ----------
        # Both directions used to end only when the peer's KCP_TIMEOUT_SEC idle
        # sweep fired, so an app whose target hung up sat blocked for up to a
        # minute (and a target waiting on the app's half-close for up to three,
        # via the client's half-close grace). These cases assert the half-close
        # arrives in seconds; the budget is well under KCP_TIMEOUT_SEC, so both
        # fail on the old behavior and pass on the FIN path.
        fin_budget = 10.0

        oneshot_port = free_port()
        oneshot = OneShotTarget(oneshot_port, b"one-shot answer\n")
        oneshot.start()
        watcher_port = free_port()
        watcher = EofWatcher(watcher_port, ack=b"ack-after-half-close\n")
        watcher.start()
        extra_servers = [oneshot, watcher]

        udp3 = free_port()
        socks3 = free_port()
        sp3, cp3 = start_pair(
            args.server, args.client, udp3, socks3,
            ["127.0.0.1:%d" % oneshot_port, "127.0.0.1:%d" % watcher_port])
        procs += [sp3, cp3]
        wait_pair_ready(sp3, cp3, socks3)

        # 3a: target -> client. The target answers and hangs up; the local app
        # must be told, instead of blocking until the client's idle sweep.
        with socks5_connect("127.0.0.1", socks3, "127.0.0.1", oneshot_port, 20) as s:
            got = recv_exact(s, len(oneshot.payload), 20)
            if got != oneshot.payload:
                raise AssertionError("one-shot target payload mismatch: %r" % got)
            waited = wait_for_eof(s, fin_budget)
        print("  [ok] target hang-up surfaced to the local app as EOF in %.2fs" % waited)

        # 3b: client -> target. The local app half-closes after its request; the
        # target must see EOF (not wait for the tunnel to time out), and the
        # response it sends back afterwards must still arrive.
        half_close_payload = b"request-body\n"
        with socks5_connect("127.0.0.1", socks3, "127.0.0.1", watcher_port, 20) as s:
            s.sendall(half_close_payload)
            s.shutdown(socket.SHUT_WR)
            if not watcher.eof_event.wait(fin_budget):
                raise AssertionError(
                    "target did not see the local app's half-close within %.1fs" % fin_budget)
            got = recv_exact(s, len(watcher.ack), 20)
            if got != watcher.ack:
                raise AssertionError("post-half-close response mismatch: %r" % got)
            wait_for_eof(s, fin_budget)
        if bytes(watcher.received) != half_close_payload:
            raise AssertionError("target received %r, expected %r"
                                 % (bytes(watcher.received), half_close_payload))
        print("  [ok] local half-close reached the target promptly; response survived")

        print("E2E TUNNEL TEST PASSED")
        return 0
    except Exception as exc:  # noqa: BLE001 - surface any failure as a test failure
        print("E2E TUNNEL TEST FAILED: %s" % exc, file=sys.stderr)
        return 1
    finally:
        for proc in procs:
            try:
                proc.terminate()
            except Exception:
                pass
        time.sleep(0.3)
        for proc in procs:
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        for server in extra_servers:
            server.stop()
        echo.stop()


if __name__ == "__main__":
    random.seed(0)
    sys.exit(main())
