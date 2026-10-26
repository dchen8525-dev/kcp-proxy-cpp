#!/usr/bin/env python3
"""FEC end-to-end suite: forward error correction under real datagram loss.

``tunnel_e2e.py`` proves the golden path with zero loss. This suite adds the
one thing FEC exists for: a lossy hop BETWEEN the client and the server, in
the shape of a userspace UDP relay that silently drops a fixed percentage of
datagrams in BOTH directions (the loss profile of a real WAN, minus the
latency). Nothing else about the stack changes -- the relay is transparent,
so the pair negotiates and carries traffic exactly as it would over a
lossy link.

Phase 1 (FEC on, 8% loss both ways): server and client run -fec 10:3, so
  roughly 3 lost datagrams per shard set are repaired instead of retransmitted.
  The payload must round-trip byte-exact, and the client's stats line must
  report fec_repaired > 0 -- the codec's repairs must be observable, not
  assumed (a broken wiring could pass the payload assertion via plain KCP
  retransmission alone).
Phase 2 (FEC off, 8% loss both ways): the default configuration must be
  regression-free through the same relay -- same payload byte-exact, and the
  stats line must report fec_repaired == 0 (no codec is running).

The stats lines are DEBUG-level and the first one fires ~10ms into a session,
so each phase runs the transfer, waits one 30s stats interval, and asserts on
the LAST stats line in the log -- the one that covers the traffic.

Every phase runs fully offline on loopback. Exit code 0 on success, non-zero
with a diagnostic on failure.
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
    socks5_connect,
    wait_for_port,
)

# Per-direction datagram drop probability. At 8% over a 256KB transfer
# (~190 KCP datagrams per direction, ~19 shard sets of 10:3), the expected
# number of repaired datagrams per direction is ~15 -- the phase-1 assertion
# (fec_repaired > 0) cannot flake on the low side, and phase 2's control
# assertion (== 0) is exact by construction.
DROP_RATE = 0.08

# WSAIOW(IOC_VENDOR, 12): the SIO_UDP_CONNRESET ioctl the C++ server and
# client apply to their own UDP sockets. Python's socket module does not
# export the constant, so it is defined here by value. Setting it to FALSE
# stops Windows from reporting WSAECONNRESET on the receive after a send to
# a dead peer port -- without it this relay dies on the first stale-port
# forward (the client rebinds its UDP port per tunnel).
SIO_UDP_CONNRESET = 0x9800000C

# The transfer payload: large enough to span many FEC shard sets, small enough
# to keep the whole suite under a minute on loopback even with loss.
PAYLOAD_BYTES = 256 * 1024

# Stats lines repeat every 30s (KcpTunnel::maybe_log_stats). Waiting one full
# interval after the transfer guarantees a stats line that covers it.
STATS_INTERVAL_SEC = 30

# One retry per phase. Tunnel establishment is a one-shot per phase: the KCP
# HELLO handshake has a hard 3s budget (KCP_HANDSHAKE_TIMEOUT_SEC) with no
# session-level retry, and the phase makes exactly one SOCKS5 connect. A
# single scheduler stall on a shared CI runner (test harness + two
# DEBUG-logging processes + this Python relay sharing 2 vCPUs) can therefore
# kill the whole phase -- observed in CI as "connection closed after 0/4
# bytes" with the SAME binary passing the identical phase minutes earlier.
# A data-path regression fails every attempt, so the retry cannot mask one.
PHASE_ATTEMPTS = 2


def log_tail(path, limit=2500):
    """Tail of a process log, attached to a phase failure for diagnosis."""
    try:
        with open(path, "rb") as f:
            return f.read()[-limit:].decode("utf-8", "replace")
    except OSError:
        return "<log unavailable>"


class LossyUdpRelay(threading.Thread):
    """A transparent UDP relay that silently drops a fraction of datagrams.

    The client sends to the relay's port as if it were the server; the relay
    forwards to the real server from its own socket, so the server's replies
    come back to that same socket and are forwarded to the one client address
    observed so far. Dropping is per-datagram and direction-independent.
    """

    def __init__(self, relay_port, server_addr, drop_c2s, drop_s2c):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", relay_port))
        # Windows: a sendto to a closed UDP port draws an ICMP port
        # unreachable, and the NEXT recvfrom then raises WSAECONNRESET
        # (10054). The stale-port sends are routine here (the client rebinds
        # per tunnel, and dropped-late replies outlive a tunnel), so disable
        # the conn-reset reporting exactly like the server does for its own
        # UDP socket. Python's socket.ioctl rejects this command code, so it
        # goes through ws2_32.WSAIoctl directly -- the same call the C++
        # server issues at startup.
        if os.name == "nt":
            import ctypes

            try:
                flag = ctypes.c_ubyte(0)  # BOOLEAN FALSE = disable reporting
                ret_len = ctypes.c_uint32(0)
                rc = ctypes.windll.ws2_32.WSAIoctl(
                    self.sock.fileno(), SIO_UDP_CONNRESET,
                    ctypes.byref(flag), ctypes.sizeof(flag),
                    None, 0, ctypes.byref(ret_len), None, None)
                if rc != 0:
                    raise OSError("WSAIoctl rc=%d" % rc)
            except OSError:
                pass  # the loop's tolerant handler covers it
        self.sock.settimeout(0.2)
        self.server_addr = server_addr
        self.drop_c2s = drop_c2s
        self.drop_s2c = drop_s2c
        self.client_addr = None
        self.stop_event = threading.Event()
        self.dropped_c2s = 0
        self.dropped_s2c = 0
        self.forwarded = 0

    def run(self):
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                # ICMP-driven transient (connection_reset/refused): skip the
                # packet and keep relaying, like the server's receive loop.
                # The ioctl above disables the Windows reporting; this is the
                # cross-platform safety net. Micro-sleep guards against a
                # pathological always-error busy loop.
                time.sleep(0.01)
                continue
            if addr == self.server_addr:
                dst, rate = self.client_addr, self.drop_s2c
            else:
                # Track the LATEST client address on every packet: the client
                # opens a fresh UDP socket per KCP tunnel (the port probe from
                # wait_for_port creates one tunnel, the real SOCKS connect
                # another), so a one-shot lock would pin the relay to the
                # first, soon-dead port and starve every later tunnel. This
                # mirrors a NAT rebinding, which is exactly the WAN profile
                # this relay models.
                self.client_addr = addr
                dst, rate = self.server_addr, self.drop_c2s
            if dst is None:
                continue
            if random.random() < rate:
                if addr == self.server_addr:
                    self.dropped_s2c += 1
                else:
                    self.dropped_c2s += 1
                continue
            try:
                self.sock.sendto(data, dst)
                self.forwarded += 1
            except OSError:
                # A dead destination port must never stop the relay: the next
                # tunnel may already be live on a fresh port.
                continue

    def stop(self):
        self.stop_event.set()


def read_log(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def extract_fec_repaired(log_text):
    """All fec_repaired values from the stats lines in `log_text`."""
    import re

    return [int(m) for m in re.findall(r"fec_repaired=(\d+)", log_text)]


def run_loss_phase(label, server_exe, client_exe, echo_port, fec_args):
    """One relayed phase: start pair (with/without -fec), transfer, assert.

    Returns the client log text (the caller asserts on the counters).
    """
    udp_port = free_udp_port()
    relay_port = free_udp_port()
    socks_port = free_port()
    server_log = os.path.join(tempfile.mkdtemp(prefix="fec_e2e_"), "server.log")
    client_log = os.path.join(tempfile.mkdtemp(prefix="fec_e2e_"), "client.log")

    server_cmd = [server_exe, "-H", "127.0.0.1", "-p", str(udp_port), "-k", KEY,
                  "-L", "DEBUG"] + fec_args + [
                  "--allow-target", "127.0.0.1:%d" % echo_port]
    client_cmd = [client_exe, "-s", "127.0.0.1", "-p", str(relay_port),
                  "-H", "127.0.0.1", "-l", str(socks_port), "-k", KEY,
                  "-L", "DEBUG"] + fec_args

    # stdout=DEBUG volume: redirect to files instead of PIPE, which would fill
    # the OS pipe buffer and block the child mid-transfer.
    try:
        with open(server_log, "wb") as sf, open(client_log, "wb") as cf:
            server_proc = subprocess.Popen(server_cmd, stdout=sf, stderr=subprocess.STDOUT)
            client_proc = subprocess.Popen(client_cmd, stdout=cf, stderr=subprocess.STDOUT)

            relay = LossyUdpRelay(relay_port, ("127.0.0.1", udp_port), DROP_RATE, DROP_RATE)
            relay.start()
            try:
                if not wait_for_port("127.0.0.1", socks_port, 20):
                    raise RuntimeError("%s: client SOCKS port never came up" % label)
                time.sleep(0.3)
                if server_proc.poll() is not None or client_proc.poll() is not None:
                    raise RuntimeError(
                        "%s: a process exited early (server=%s client=%s)"
                        % (label, server_proc.returncode, client_proc.returncode))

                with socks5_connect("127.0.0.1", socks_port, "127.0.0.1", echo_port, 30) as s:
                    payload = os.urandom(PAYLOAD_BYTES)
                    s.sendall(payload)
                    got = recv_exact(s, len(payload), 60)
                if got != payload:
                    raise AssertionError(
                        "%s: payload mismatch through %d%% loss (sent %d, got %d bytes)"
                        % (label, DROP_RATE * 100, len(payload), len(got)))
                print("  [ok] %s: %d bytes round-tripped byte-exact through %.0f%% loss "
                      "(relay dropped c2s=%d s2c=%d)"
                      % (label, PAYLOAD_BYTES, DROP_RATE * 100,
                         relay.dropped_c2s, relay.dropped_s2c))

                # Keep every process ALIVE for one full stats interval: the
                # counters this suite asserts on are only visible in stats lines
                # (session close + the periodic line), and a terminated process
                # stops logging. The transfer session either drains its FIN and
                # logs its close stats, or the periodic line fires -- either way
                # the post-transfer totals reach the log.
                time.sleep(STATS_INTERVAL_SEC + 2)
            finally:
                relay.stop()
                time.sleep(0.2)
                client_proc.terminate()
                server_proc.terminate()
                try:
                    client_proc.wait(timeout=5)
                    server_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client_proc.kill()
                    server_proc.kill()
    except Exception as exc:
        # A bare failure is undiagnosable in CI: the DEBUG logs live in a temp
        # dir nobody ever sees. Attach both tails so a failure names the stall
        # (KCP handshake timeout vs SOCKS5 handshake timeout vs early exit).
        raise RuntimeError(
            "%s: %s\n--- client log tail ---\n%s--- server log tail ---\n%s"
            % (label, exc, log_tail(client_log), log_tail(server_log))) from exc

    return read_log(client_log), read_log(server_log)


def run_loss_phase_with_retry(label, server_exe, client_exe, echo_port, fec_args,
                              attempts=PHASE_ATTEMPTS):
    """run_loss_phase with a fresh-ports retry; see PHASE_ATTEMPTS for why."""
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            return run_loss_phase(label, server_exe, client_exe, echo_port, fec_args)
        except Exception as exc:  # noqa: BLE001 - retried below, re-raised at the end
            last_error = exc
            print("  [warn] %s: attempt %d/%d failed (%s)"
                  % (label, attempt, attempts, exc))
    raise AssertionError(
        "%s: still failing after %d attempts (a data-path regression fails every "
        "attempt; a host stall should not); last error: %s"
        % (label, attempts, last_error))


def main():
    ap = argparse.ArgumentParser(description="kcp-proxy FEC loss e2e test")
    ap.add_argument("--server", required=True, help="path to kcp-proxy-server binary")
    ap.add_argument("--client", required=True, help="path to kcp-proxy-client binary")
    args = ap.parse_args()

    for path in (args.server, args.client):
        if not os.path.exists(path):
            print("E2E FAILED: binary not found: %s" % path, file=sys.stderr)
            return 1
    args.server = normalize_binary_path(args.server)
    args.client = normalize_binary_path(args.client)
    augment_dll_path(args.server)
    augment_dll_path(args.client)

    echo_port = free_port()
    echo = EchoServer(echo_port)
    echo.start()

    try:
        # --- Phase 1: FEC 10:3 through 8% loss: transfer + observable repairs ---
        client_log, server_log = run_loss_phase_with_retry(
            "fec=10:3 under loss", args.server, args.client, echo_port,
            ["-fec", "10:3"])
        if "FEC config shards=10:3" not in client_log:
            raise AssertionError("client startup log lacks the FEC config line")
        if "FEC config shards=10:3" not in server_log:
            raise AssertionError("server startup log lacks the FEC config line")
        repaired = extract_fec_repaired(client_log)
        if not repaired or max(repaired) <= 0:
            raise AssertionError(
                "no stats line reports fec_repaired > 0 (values seen: %r); "
                "the codec either never ran or its repairs are invisible"
                % repaired[-5:])
        print("  [ok] fec_repaired counters observed: max=%d across %d stats lines"
              % (max(repaired), len(repaired)))

        # --- Phase 2: FEC off through the same loss: default must not regress ---
        client_log2, _ = run_loss_phase_with_retry(
            "fec=off under loss", args.server, args.client, echo_port, [])
        if "FEC config shards=off" not in client_log2:
            raise AssertionError("client startup log lacks the disabled FEC line")
        repaired2 = extract_fec_repaired(client_log2)
        if repaired2 and max(repaired2) != 0:
            raise AssertionError(
                "fec_repaired must stay 0 with FEC disabled (values seen: %r)"
                % repaired2[-5:])
        print("  [ok] fec disabled: transfer clean and fec_repaired stays 0")
    except Exception as exc:  # noqa: BLE001 - a suite must diagnose, not traceback
        print("E2E FAILED: %s" % exc, file=sys.stderr)
        return 1
    finally:
        echo.stop()

    print("E2E FEC loss test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
