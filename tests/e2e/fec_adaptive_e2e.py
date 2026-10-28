#!/usr/bin/env python3
"""Adaptive FEC parity end-to-end suite (on by default when FEC is enabled).

``fec_loss_e2e.py`` proves that parity repairs losses. This suite proves the
opposite half: that a CLEAN path stops paying for parity, and that a lossy one
does not.

Phase 1 (0% loss, --fec 10:3, probe=6s): a sustained transfer
  must drive the controller to "economy" -- the client logs the transition and
  keeps sending data shards with no parity behind them. The peer keeps decoding:
  a skipped set is a complete set of 10 data shards, and nothing else on the wire
  changes. Measured at the end: far fewer parity datagrams than 3-per-10.

Phase 2 (8% loss, same flags): every 2s sample window carries real losses, so
  the controller must never drop parity. This is the property that makes the
  design safe -- the downgrade is only ever taken on evidence of a clean path,
  and the evidence here (snmp_fast_retrans, i.e. the peer reporting an ACK gap)
  survives FEC repair even though it is much weaker than without FEC.

Both phases assert byte-exact payload delivery: adaptive parity must never
change what the tunnel carries, only how much redundancy rides with it.

Exit code 0 on success, non-zero with a diagnostic on failure.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fec_loss_e2e import LossyUdpRelay, log_tail, read_log  # noqa: E402
from tunnel_e2e import (  # noqa: E402
    KEY,
    EchoServer,
    augment_dll_path,
    free_port,
    free_udp_port,
    normalize_binary_path,
    socks5_connect,
    wait_for_port,
)

# Probe window used by both phases. Small so the suite stays fast; the shipped
# default is 60s (FEC_PARITY_PROBE_SEC).
PROBE_SEC = 6
# How long to keep the transfer running. Phase 1 needs comfortably more than
# PROBE_SEC of traffic to switch and then still send a good stretch unprotected;
# phase 2 needs several sample windows to prove it does NOT switch.
CLEAN_SECONDS = 20
LOSSY_SECONDS = 10
# Paced sender rate. Well above FEC_PARITY_MIN_SEG_RATE (50 segs/s) so every
# sample window counts as traffic, and low enough that the loopback kernel
# buffers never become the bottleneck (which would inject spurious RTO resends).
RATE_BPS = 2 * 1024 * 1024

DROP_RATE = 0.08

STATS_RE = re.compile(
    r"stats tx_pkt=\d+ .*?fec_repaired=(\d+) fec_data_tx=(\d+) fec_parity_tx=(\d+) "
    r"fec_parity=(\w+)"
)
TRANSITION_OFF = "FEC adaptive: parity off"
TRANSITION_ON = "FEC adaptive: parity on"


def paced_roundtrip(sock, payload, rate_bps):
    """Send `payload` at ~rate_bps while a reader drains the echoed reply.

    Reading has to happen concurrently: the target is an echo server, so a
    sender that never reads would fill the client's receive buffer, block the
    echo path, and stall the transfer (backpressure all the way to the sender).
    """
    received = bytearray()
    errors = []

    def reader():
        try:
            while len(received) < len(payload):
                chunk = sock.recv(min(65536, len(payload) - len(received)))
                if not chunk:
                    break
                received.extend(chunk)
        except OSError as exc:  # noqa: BLE001 - reported through errors
            errors.append(exc)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    started = time.time()
    sent = 0
    chunk_size = 32 * 1024
    for off in range(0, len(payload), chunk_size):
        part = payload[off:off + chunk_size]
        sock.sendall(part)
        sent += len(part)
        ahead = sent / float(rate_bps) - (time.time() - started)
        if ahead > 0:
            time.sleep(ahead)
    thread.join(timeout=120)
    if errors:
        raise RuntimeError("reader failed: %r" % (errors[0],))
    return bytes(received)


def last_stats(log_text):
    """(repaired, data_tx, parity_tx, mode) of the LAST stats line, or None."""
    matches = STATS_RE.findall(log_text)
    if not matches:
        return None
    repaired, data_tx, parity_tx, mode = matches[-1]
    return int(repaired), int(data_tx), int(parity_tx), mode


def run_phase(label, server_exe, client_exe, echo_port, fec_args, drop_rate, seconds):
    """One phase: start the pair, run a paced transfer, return both logs."""
    udp_port = free_udp_port()
    relay_port = free_udp_port()
    socks_port = free_port()
    client_udp_port = relay_port if drop_rate else udp_port

    tmpdir = tempfile.mkdtemp(prefix="fec_adaptive_e2e_")
    server_log = os.path.join(tmpdir, "server.log")
    client_log = os.path.join(tmpdir, "client.log")

    server_cmd = [server_exe, "-H", "127.0.0.1", "-p", str(udp_port), "-k", KEY,
                  "-L", "INFO", "--allow-target", "127.0.0.1:%d" % echo_port] + fec_args
    client_cmd = [client_exe, "-s", "127.0.0.1", "-p", str(client_udp_port),
                  "-H", "127.0.0.1", "-l", str(socks_port), "-k", KEY,
                  "-L", "INFO"] + fec_args

    relay = None
    try:
        with open(server_log, "wb") as sf, open(client_log, "wb") as cf:
            server_proc = subprocess.Popen(server_cmd, stdout=sf, stderr=subprocess.STDOUT)
            client_proc = subprocess.Popen(client_cmd, stdout=cf, stderr=subprocess.STDOUT)
            if drop_rate:
                relay = LossyUdpRelay(relay_port, ("127.0.0.1", udp_port), drop_rate, drop_rate)
                relay.start()
            try:
                if not wait_for_port("127.0.0.1", socks_port, 20):
                    raise RuntimeError("%s: client SOCKS port never came up" % label)
                time.sleep(0.3)
                payload = os.urandom(int(RATE_BPS * seconds))
                with socks5_connect("127.0.0.1", socks_port, "127.0.0.1", echo_port, 30) as s:
                    got = paced_roundtrip(s, payload, RATE_BPS)
                if got != payload:
                    raise AssertionError(
                        "%s: payload mismatch (sent %d, got %d bytes)"
                        % (label, len(payload), len(got)))
                # Let the session tear down so it logs its final stats line.
                time.sleep(1.5)
            finally:
                client_proc.terminate()
                server_proc.terminate()
                try:
                    client_proc.wait(timeout=5)
                    server_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client_proc.kill()
                    server_proc.kill()
    except Exception as exc:
        raise RuntimeError(
            "%s: %s\n--- client log tail ---\n%s--- server log tail ---\n%s"
            % (label, exc, log_tail(client_log), log_tail(server_log))) from exc
    finally:
        if relay:
            relay.stop()

    return read_log(client_log), read_log(server_log), relay


def check_clean_phase(client_log, server_log):
    """A clean path must end in economy, with far less parity than 3-per-10."""
    stats = last_stats(client_log)
    if stats is None:
        raise AssertionError("no stats line in the client log "
                             "(session never closed cleanly?)")
    repaired, data_tx, parity_tx, mode = stats
    if TRANSITION_OFF not in client_log:
        raise AssertionError(
            "the client never reported dropping parity on a clean path "
            "(no %r line); stats=%r" % (TRANSITION_OFF, stats))
    if mode != "econ":
        raise AssertionError("the final session state must be economy, got %r" % mode)
    if data_tx <= 0:
        raise AssertionError("no FEC data shards were counted (data_tx=%d)" % data_tx)
    # Full protection costs 3 parity per 10 data (30%). Stopping for the last
    # two-thirds of the transfer must land well under that; a regression that
    # kept emitting would sit at ~30%.
    ratio = parity_tx / float(data_tx)
    if ratio >= 0.20:
        raise AssertionError(
            "parity ratio %.3f is too high for a clean path (data=%d parity=%d); "
            "adaptive mode did not remove the redundancy" % (ratio, data_tx, parity_tx))
    if repaired != 0:
        raise AssertionError("a clean path repaired %d shards; the relay was idle" % repaired)
    # The server drives its controller from the update tick (a different
    # sampling site from the client's traffic reporter): prove that path works
    # too, or a server-side regression would go unnoticed.
    if TRANSITION_OFF not in server_log:
        raise AssertionError(
            "the server never dropped parity on a clean download path "
            "(its update-tick sampling may be broken)")
    print("  [ok] clean path: parity off on both ends, client ratio=%.3f "
          "(data=%d parity=%d), payload byte-exact" % (ratio, data_tx, parity_tx))


def check_lossy_phase(client_log, relay):
    """A lossy path must stay protected and keep repairing."""
    stats = last_stats(client_log)
    if stats is None:
        raise AssertionError("no stats line in the client log "
                             "(session never closed cleanly?)")
    repaired, data_tx, parity_tx, mode = stats
    if TRANSITION_OFF in client_log:
        # Never fatal per se -- the policy may probe -- but on a path losing 8%
        # of every datagram the probe must have been corrected, i.e. parity must
        # be back on before the session ended.
        if TRANSITION_ON not in client_log.split(TRANSITION_OFF)[-1]:
            raise AssertionError(
                "parity was dropped on a lossy path and never restored")
    if mode != "full":
        raise AssertionError("the final state on a lossy path must be full "
                             "protection, got %r" % mode)
    if repaired <= 0:
        raise AssertionError(
            "FEC repaired nothing at %.0f%% loss (repaired=%d); the lossy "
            "relay was not effective or parity was not emitted"
            % (DROP_RATE * 100, repaired))
    if parity_tx <= 0:
        raise AssertionError("no parity was emitted on a lossy path")
    dropped = relay.dropped_c2s + relay.dropped_s2c if relay else 0
    if dropped <= 0:
        raise AssertionError("the lossy relay dropped nothing; the phase proves nothing")
    print("  [ok] lossy path: parity stayed on (mode=%s, repaired=%d, dropped=%d), "
          "payload byte-exact" % (mode, repaired, dropped))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="build/Release/kcp-proxy-server.exe")
    parser.add_argument("--client", default="build/Release/kcp-proxy-client.exe")
    args = parser.parse_args()

    server_exe = normalize_binary_path(args.server)
    client_exe = normalize_binary_path(args.client)
    for exe in (server_exe, client_exe):
        if not os.path.exists(exe):
            print("missing binary: %s" % exe)
            return 1
    augment_dll_path(server_exe)

    echo_port = free_port()
    echo = EchoServer(echo_port)
    echo.start()

    # Adaptive parity is on by default, so the flags here only shorten its
    # windows (the shipped defaults are 60s/300s).
    fec_args = ["--fec", "10:3",
                "--fec-adaptive-probe", str(PROBE_SEC),
                "--fec-adaptive-hold", "30"]
    try:
        client_log, server_log, _ = run_phase(
            "clean", server_exe, client_exe, echo_port, fec_args, 0.0, CLEAN_SECONDS)
        check_clean_phase(client_log, server_log)

        client_log, _server_log, relay = run_phase(
            "lossy", server_exe, client_exe, echo_port, fec_args, DROP_RATE, LOSSY_SECONDS)
        check_lossy_phase(client_log, relay)
    finally:
        echo.stop()

    print("adaptive FEC e2e: all phases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
