# Testing

## Automated

Build and run tests from the repository root:

```powershell
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python tests/smoke/smoke_test.py
```

`ctest` runs two tests:

- `kcp_proxy_test` — the unit suite below.
- `kcp_proxy_e2e_tunnel` — an offline end-to-end tunnel test (see below).

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
  the target-drained teardown callback firing exactly once

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

Negative checks:

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
