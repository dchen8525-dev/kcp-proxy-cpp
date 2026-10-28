#!/usr/bin/env python3
"""Adaptive RTO floor end-to-end suite (--rto-adaptive-clean).

Answering the other half of the retransmission problem. A KCP send window of
1024 segments is ~1.4 MB; on a fast path that takes tens of milliseconds to
drain through the socket, but kcp's nodelay mode fires its retransmission timer
after 30ms. Segments that were merely queued therefore get resent -- on loopback
this measured 1355 retransmissions out of 15001 segments, of which the peer
received 1172 as duplicates.

The fix is a floor that follows the path: keep the fast 30ms while the path is
losing packets, relax to 100ms only after a sustained clean window.

Phase 1 (clean path): the client must log the relaxation to 100ms and finish the
  session with nodelay=0, payload byte-exact.
Phase 2 (8% loss): the floor must NOT stay relaxed -- every sample window has
  fast retransmits, so the session must end at nodelay=1 (the pre-adaptive
  behaviour for a lossy link).

Exit code 0 on success, non-zero with a diagnostic on failure.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# The phases share the paced-transfer harness and the stats-line shape with the
# adaptive-FEC suite; only the policy under test differs.
from fec_adaptive_e2e import (  # noqa: E402
    LOSSY_SECONDS,
    RATE_BPS,
    run_phase,
)
from tunnel_e2e import KEY, EchoServer, augment_dll_path, free_port, normalize_binary_path  # noqa: E402

# Short relax window so the suite stays fast; the shipped default is 15s.
RELAX_SEC = 5
CLEAN_SECONDS = 16

DROP_RATE = 0.08

RELAXED_LINE = "RTO adaptive: floor 30ms -> 100ms"
FAST_LINE = "RTO adaptive: floor 100ms -> 30ms"
STATS_RE = re.compile(r"stats .*?nodelay=(\d+)")


def final_nodelay(log_text):
    """nodelay= of the LAST stats line (the session's closing totals)."""
    matches = STATS_RE.findall(log_text)
    return int(matches[-1]) if matches else None


def check_clean_phase(client_log):
    if RELAXED_LINE not in client_log:
        raise AssertionError(
            "the client never reported relaxing the RTO floor on a clean path "
            "(no %r line)" % RELAXED_LINE)
    nodelay = final_nodelay(client_log)
    if nodelay != 0:
        raise AssertionError(
            "the session must end with nodelay=0 (100ms floor) on a clean path, "
            "got %r" % nodelay)
    print("  [ok] clean path: RTO floor relaxed to 100ms, payload byte-exact")


def check_lossy_phase(client_log, relay):
    tail = client_log
    if RELAXED_LINE in client_log:
        # A probe that fires is fine as long as the loss put the fast floor
        # back before the session ended.
        tail = client_log.split(RELAXED_LINE)[-1]
        if FAST_LINE not in tail:
            raise AssertionError(
                "the RTO floor relaxed on a lossy path and never went back to 30ms")
    nodelay = final_nodelay(client_log)
    if nodelay != 1:
        raise AssertionError(
            "the session must end with nodelay=1 (30ms floor) on a lossy path, "
            "got %r" % nodelay)
    dropped = relay.dropped_c2s + relay.dropped_s2c if relay else 0
    if dropped <= 0:
        raise AssertionError("the lossy relay dropped nothing; the phase proves nothing")
    print("  [ok] lossy path: RTO floor stayed at 30ms (dropped=%d), payload byte-exact"
          % dropped)


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

    # Deliberately no --fec: the floor policy must stand on its own.
    rto_args = ["--rto-adaptive-clean", str(RELAX_SEC)]

    echo_port = free_port()
    echo = EchoServer(echo_port)
    echo.start()
    try:
        client_log, _server_log, _ = run_phase(
            "rto-clean", server_exe, client_exe, echo_port, rto_args, 0.0, CLEAN_SECONDS)
        check_clean_phase(client_log)

        client_log, _server_log, relay = run_phase(
            "rto-lossy", server_exe, client_exe, echo_port, rto_args, DROP_RATE,
            LOSSY_SECONDS)
        check_lossy_phase(client_log, relay)
    finally:
        echo.stop()

    print("adaptive RTO floor e2e: all phases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
