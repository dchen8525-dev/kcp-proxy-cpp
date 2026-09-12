# Testing

## Automated

Build and run tests from the repository root:

```powershell
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python tests/smoke/smoke_test.py
```

`ctest` runs three tests:

- `kcp_proxy_test` — the unit suite below.
- `kcp_proxy_e2e_tunnel` — an offline end-to-end tunnel test (see below).
- `kcp_proxy_e2e_robustness` — the negative/robustness suite (see below).

## End-to-end tunnel test

`tests/e2e/tunnel_e2e.py` spawns the built server and client binaries plus a
local TCP echo server and a dependency-free SOCKS5 client, then drives real
payloads through the full SOCKS5-over-KCP path and asserts they return
byte-for-byte (small, >64 KB, all-byte-values, and a streamed sequence). It is
fully offline — every endpoint is loopback.

Because the server's SSRF guard refuses loopback/private targets by default, the
test starts the server with an explicit lab allowlist entry:

```powershell
python tests/e2e/tunnel_e2e.py `
  --server build/Release/kcp-proxy-server.exe `
  --client build/Release/kcp-proxy-client.exe
```

The second phase of the test starts a server *without* `--allow-target` and
asserts the same loopback target is still refused, pinning the security default.

### `--allow-target` (lab/test only)

```powershell
kcp-proxy-server.exe -H 127.0.0.1 -p 8388 -k <key> --allow-target 127.0.0.1:9000
```

`--allow-target HOST[:PORT]` (repeatable) lets a specific target bypass the SSRF
guard even when it is loopback/private. It is **off by default** — production
traffic has an empty allowlist and stays fully protected. Never expose a server
started with `--allow-target` on an untrusted network.

## Negative / robustness suite

`tests/e2e/robustness_e2e.py` covers what the happy-path test cannot: hostile
input and teardown. It is the automated form of the manual negative checks
listed further down.

```powershell
python tests/e2e/robustness_e2e.py `
  --server build/Release/kcp-proxy-server.exe `
  --client build/Release/kcp-proxy-client.exe
```

Add `--keep-logs` to keep the per-process server/client log files for
inspection (they are printed on failure either way).

Five phases, all offline:

- **A. Wrong key** — a client started with a mismatched key must be dropped by
  the server at the auth boundary: no session is created, the packet is rejected
  with `DECRYPT_FAILED`, and the local SOCKS5 app is told *no* (socket closed or
  reset) instead of being handed a tunnel that is silently dead. The client must
  log a handshake timeout and never claim a confirmed handshake.
- **B. Garbage flood** — 1500 hostile datagrams (zero-length, header-sized,
  oversize, and the 64 KB UDP maximum; pure noise plus KCP-shaped frames) are
  blasted at the server's UDP port from several source ports. The server must
  survive, reject every packet at auth, allocate **no** session, trip the global
  auth rate limiter (`MAX_AUTH_ATTEMPTS_PER_SEC`), and still carry real traffic
  byte-exact once the one-second window rolls over.
- **C. Concurrency and reclamation** — 100 simultaneous tunnels must each carry
  their own payload with no cross-session bleed, every one of the 100 sessions
  must be registered *and* reclaimed once its target closes (verified by
  counting `new session` against `close_connection from target_drained`), and 10
  abrupt `SO_LINGER`-reset connections must not wedge the server.
- **D. Half-close** — the local app stops sending while its target never closes.
  A response still in flight must arrive byte-exact even when it is spread across
  (and past) the grace window, while a stalled tunnel must be reclaimed — the
  KCP session and its UDP socket are released rather than held forever. Also
  checks the control case: nothing is reclaimed *before* the grace elapses, so
  the bound can never truncate a response.
- **E. Big response, target closes** — a target that sends a 1 MB response and
  closes immediately after the last byte must not have it truncated: the local
  app has to receive every byte, byte-exact, and the session must be torn down
  through the **drained** path (`close_connection from target_drained`), which
  only runs once `wait_send() == 0` — i.e. after the whole tail was delivered —
  rather than by closing on the FIN.

The phases use `--allow-target` only to reach their own local echo servers; the
regression that the guard stays on by default is pinned by `tunnel_e2e.py`.

### Half-closed tunnels: bounded by a grace

When the local app's read side reports EOF the client half-closes the tunnel
instead of tearing it down, so a response still in flight is not truncated. That
half-close cannot be unbounded: the application-layer keepalives keep refresh
**both** peers' idle clocks, so if the target never closes either, nothing would
ever reclaim the tunnel — each abandoned app (a closed browser tab, a client
timeout, `curl --max-time`) would leak a local socket, a UDP socket, KCP buffers
and one upstream connection until the client hit `MAX_CLIENT_SESSIONS` (512) and
refused *all* new connections.

The client therefore arms a grace (`CLIENT_HALF_CLOSE_GRACE_SEC`, 2× the idle
timeout) when the app's read side reports EOF, and is refreshed **only** by
payload actually written to the app — application keepalives are dropped inside
the session and never reach the forwarding loop, so they cannot extend it. A
response that keeps making progress is therefore never cut off, while a tunnel
that goes quiet for the whole window is closed. Once the client closes its
session it stops sending, so the server's own idle sweep reaps its half of the
tunnel shortly after.

Override the grace for lab use (phase D of the robustness suite uses this to
avoid waiting out the production value):

```powershell
kcp-proxy-client.exe -s 127.0.0.1 -k <key> --half-close-grace 3
```

A grace of `0` reclaims the tunnel immediately at EOF, which is only safe when
the target is known to answer within the same packet exchange.

Current unit coverage includes:

- Crypto client-to-server and server-to-client round trips
- Wrong key failure
- Tamper detection
- Replay rejection
- Old counter rejection
- Packet older than the 64-packet replay window rejection
- SOCKS5 IPv4, IPv6, and domain parsing
- SOCKS5 byte-by-byte partial request handling
- Extra payload preservation after CONNECT
- Unsupported command parsing
- UDP ASSOCIATE parse-before-reject behavior
- Invalid SOCKS5 version rejection
- SOCKS5 reply bind-address encoding
- Restricted-target classification (loopback, private, link-local, CGN, and
  IPv6 transition forms such as 6to4/Teredo/NAT64)
- Stacked `async_read_some` rejection with `already_started`
- KCP config line rendering and live `ikcp` state matching the `KCP_*` constants
- Stopped-session inertness (`stop()` idempotent, `on_update_tick` no-op) and
  the target-drained teardown contract: the callback fires exactly once when the
  target closed and the send buffer is empty, and — the anti-truncation half — is
  **withheld** while bytes are still queued in KCP. That deferral is pinned
  deterministically here; phase E of the robustness suite covers the same
  guarantee end-to-end (a 1 MB response whose target closes must arrive whole).
- Client-side teardown contract, the counterpart of the above:
  `KCPClientSession::close()` — the primitive every `abort_handshake()` runs — is
  safe before `connect()` and idempotent, leaves a mid-handshake session inert
  (a later read aborts instead of parking), and **releases the handler the
  handshake parked** (asserted through a `weak_ptr`, which is the session +
  UDP-socket leak the funnel exists to prevent). The keepalive/ticket attached
  via `set_keepalive()` is released with the session. An in-process test then
  drives a real `KCPProxyClient` against an unreachable server and asserts
  `abort_handshake()` closes the local app socket once the handshake fails,
  while the client keeps accepting new connections.

## Manual

Start a server:

```powershell
.\build\Release\kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L INFO
```

Start a client:

```powershell
.\build\Release\kcp-proxy-client.exe -H 127.0.0.1 -l 1080 -s 127.0.0.1 -p 8388 -k remote_test_key_123456 -L INFO
```

Verify through the local SOCKS5 proxy:

```powershell
curl -x socks5h://127.0.0.1:1080 http://neverssl.com
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x socks5h://127.0.0.1:1080 https://www.cloudflare.com
```

Negative checks (automated by `tests/e2e/robustness_e2e.py`, kept here for
manual poking):

- Start the client with a wrong key; the KCP handshake should fail or time out.
- Stop the server and open a new proxy connection; the client must not report KCP connected for that session.
- Send SOCKS5 `UDP ASSOCIATE`; the server should return command-not-supported.
- Run several concurrent curl requests and confirm session count returns near zero after traffic stops.

## Stress

Run concurrent requests through the local SOCKS5 proxy (server and client started as above):

```bash
for i in $(seq 1 100); do
    curl -x socks5h://127.0.0.1:1080 --max-time 30 -fsS -o /dev/null https://example.com &
done
wait
```

Watch INFO logs for lifecycle-level output only. Packet byte counts should remain at DEBUG.
After the test, stop the server and client; the session count should return near zero.
