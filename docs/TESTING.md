# Testing

## Automated

Build and run tests from the repository root:

```powershell
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python tests/smoke/smoke_test.py
```

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
- Stacked `async_read_some` rejection with `already_started`

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
