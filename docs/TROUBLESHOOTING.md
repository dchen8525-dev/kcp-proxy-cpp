# Troubleshooting

## Client Does Not Connect

The client now waits for an authenticated `HELLO_ACK` from the server for every KCP session. If the server
is down, UDP is blocked, or the key is wrong, the session fails instead of being marked connected.

The client sends `KCP_PROXY_HELLO_V2` and accepts either `KCP_PROXY_HELLO_ACK_V2` (half-close enabled) or
the older `KCP_PROXY_HELLO_ACK_V1` (half-close disabled, everything else unchanged), so it still works
against a server that predates V2. A server that answers anything else fails the handshake outright.

Check:

- Server is listening on the expected UDP host and port.
- Client `-s` and `-p` match the server address and port.
- Both sides use the same key and the key is at least 16 characters.
- Firewalls allow UDP in both directions.

## SOCKS5 Works for HTTP but Not QUIC

This proxy supports SOCKS5 CONNECT for TCP only. It does not support `UDP ASSOCIATE`, QUIC/HTTP3, or UDP
DNS. Disable QUIC/HTTP3 in clients that otherwise prefer UDP.

## Domain Connect Fails Intermittently

The server resolves all A/AAAA results and uses Asio `async_connect` over the endpoint sequence. A failure
should only be returned after all resolved endpoints fail or the connect timeout fires.

Use `-L DEBUG` to inspect endpoint-level diagnostics when adding deeper logging.

## Connections Stall or Close Under Load (`ERR_CONNECTION_CLOSED`)

Symptom: browsing through the proxy works when idle, but opening a page with many parallel connections
(Chrome opens ~40) makes several of them hang and then fail with `ERR_CONNECTION_CLOSED`. Per-session
server logs show a suspiciously uniform, very small `rx_pkt=` — often the same number for every stalled
session.

That uniformity is the tell. It means only the first few datagrams of each session were ever drained
from the socket, and the rest were dropped by the kernel before the server saw them.

Cause: the server requests 4 MiB UDP socket buffers, but the kernel silently clamps the request to
`net.core.rmem_max` / `net.core.wmem_max` (208 KiB on a stock Debian host) and `setsockopt` still
reports success. The smaller buffer overflows during a simultaneous burst from many sessions in KCP's
fastest mode (`nc=1`, 10 ms interval, no congestion control), the kernel drops datagrams, and KCP
misreads those drops as network loss and retransmits whole windows.

Check:

1. The startup log prints the effective sizes. A clamp also emits its own WARNING:

   ```
   UDP socket buffers so_rcvbuf=212992 so_sndbuf=212992
   UDP socket buffer clamped by the kernel: so_rcvbuf requested=4194304 effective=212992 ...
   ```

   `so_rcvbuf` should read 4194304 (or higher — Linux reports a doubled value).

2. Compare the kernel's UDP drop counters against its total input. `InErrors == RcvbufErrors` with
   `InCsumErrors=0` means buffer overflow, not corruption or a bad link:

   ```bash
   # The Udp: line in /proc/net/snmp is a header row followed by a value row.
   # Map the header to column indices instead of hardcoding them: kernels append
   # columns over time (IgnoredMulti, InCsumErrors), so fixed indices silently
   # report the wrong counter.
   awk '/^Udp:/ { if (h++) { for (i = 2; i <= NF; i++) printf "%s=%s ", hdr[i], $i; print ""; exit }
                   for (i = 2; i <= NF; i++) hdr[i] = $i }' /proc/net/snmp
   ```

   Sample it before and after a burst: a nonzero delta on `RcvbufErrors` is the confirmation.

3. Confirm the ceiling is actually raised: `sysctl net.core.rmem_max net.core.wmem_max`.

Fix: raise the ceiling on the server and restart the service. Both installers do this automatically
(`/etc/sysctl.d/99-kcp-proxy.conf`, written only when the host's value is lower — see the README's
deployment section). To do it by hand:

```bash
printf 'net.core.rmem_max=4194304\nnet.core.wmem_max=4194304\n' | sudo tee /etc/sysctl.d/99-kcp-proxy.conf
sudo sysctl -p /etc/sysctl.d/99-kcp-proxy.conf
sudo systemctl restart kcp-proxy-server   # the server reads the clamp at startup
```

A kernel drop is not the only way to lose a burst, but it is the one that is invisible from inside the
process — which is why the server compares the requested and effective sizes instead of trusting
`setsockopt` to have failed loudly.

## Log Volume

`INFO` is intended for lifecycle events: server/client start, session creation/close, SOCKS5 target,
connect success/failure, and fatal errors. Packet-level UDP/KCP/TCP forwarding details are logged at
`DEBUG`.

Do not log keys or payload bytes.

## Common Failure Stages

This is the complete list of stages the binaries emit (grep `FAIL_STAGE=` in `src/` to verify):

- `DECRYPT_FAILED`: packet decryption or tag verification failed — in practice a wrong key, an
  unauthenticated packet, or a session-salt mismatch.
- `KCP_HANDSHAKE_FAILED`: the protocol handshake read failed before SOCKS5 started.
- `KCP_INPUT_FAILED`: `ikcp_input()` rejected a segment (`ret_<n>`).
- `KCP_NO_RECV`: the downstream KCP read failed or returned zero bytes.
- `SOCKS5_PARSE_FAILED`: SOCKS5 request was invalid or too large.
- `SOCKS5_UNSUPPORTED_COMMAND`: command was `BIND`, `UDP ASSOCIATE`, or unknown.
- `SSRF_BLOCKED`: the requested target is a restricted address (loopback, private, link-local, …)
  and the server refuses to connect to it. Use `--allow-target` only in a lab.
- `DNS_RESOLVE_FAILED`: domain resolution failed.
- `TCP_CONNECT_FAILED`: all outbound TCP connect attempts failed, or the connect timeout fired.
- `TCP_READ_FAILED` / `TCP_WRITE_FAILED`: remote TCP stream failed during forwarding.
- `UDP_SEND_FAILED`: UDP send failed.
- `SESSION_TIMEOUT`: session idle/KCP timeout cleanup.

A failure to reach `CPP_REMOTE_REACHABLE` on the Android side (server stopped, wrong key, UDP blocked)
does not surface as a stage on the server at all — there is no session to log one from, because the
server never authenticates a packet. Look for the absence of `new session:` instead.
