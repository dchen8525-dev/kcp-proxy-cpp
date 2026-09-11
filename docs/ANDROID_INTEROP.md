# Android Interop Testing

How to validate the C++ SOCKS5-over-KCP server against the Android `CPP_REMOTE`
peer end-to-end. This document is copy-paste driven; every command is real.

## Topology

```text
Android App (Chrome / WebView)
  -> CPP_REMOTE  (one TCP conn = one UDP socket = one KCP session)
    -> KCP over UDP -> C++ kcp-proxy-server (Windows)
      -> raw TCP to the real target
```

Both ends must use the **same KCP parameters** or `ikcp` silently discards the
peer's packets. The C++ server and client both print the canonical line at
startup, rendered from `config.hpp`:

```text
KCP config conv=1 mtu=1400 nodelay=1 interval=10 resend=5 nc=1 sndWnd=256 rcvWnd=512 timeout=60s
```

When you start the C++ server, confirm this line appears before any traffic.

## 1. Start the C++ server (Windows)

From the repository root, after a successful build (see `TESTING.md`):

```powershell
.\build\Release\kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L INFO
```

- `-k` must be **at least 16 characters**, or the server refuses to start.
- `-H 0.0.0.0` binds all interfaces so the Android emulator (which reaches the
  host via `10.0.2.2`) can connect.
- `-p 8388` is the UDP listen port. Both peers must agree on it.

## 2. Windows Firewall — allow UDP 8388

The tunnel is UDP, so the firewall must allow **inbound UDP 8388** on the
Windows host. Quick check before testing:

```powershell
# Does anything already listen on UDP 8388?
netstat -an -p UDP | findstr 8388
```

If you need to open it (run PowerShell as Administrator):

```powershell
New-NetFirewallRule -DisplayName "KCP Proxy UDP 8388" `
  -Direction Inbound -Protocol UDP -LocalPort 8388 -Action Allow
```

Without this rule, the Android side sees `AUTH_FAILED` / handshake timeouts
even though the server process is running.

## 3. Android Emulator endpoint

From inside the emulator, the host machine is reached at the well-known
loopback alias `10.0.2.2`. Point `CPP_REMOTE` at:

```text
10.0.2.2:8388
```

Not `127.0.0.1` (that is the emulator itself) and not the host's LAN IP.

## 4. Expected C++ server logs (when Android connects)

Captured from a real run. The lifecycle stays at `INFO`; packet-level detail is
`DEBUG` only.

```text
[INFO] server: listening on 0.0.0.0:8388
[INFO] server: KCP config conv=1 mtu=1400 nodelay=1 interval=10 resend=5 nc=1 sndWnd=256 rcvWnd=512 timeout=60s
[INFO] kcp_session: <peer-ip>:<port>: started
[INFO] server: new session: <peer-ip>:<port> (total: 1)
[INFO] server: <peer-ip>:<port>: KCP handshake confirmed
[INFO] server: <peer-ip>:<port>: SOCKS5 connect target cmd=1 atyp=3 host=<dst> port=80
[INFO] server: <peer-ip>:<port>: connecting to <dst>:80
[INFO] server: <peer-ip>:<port>: resolved <dst> to N endpoints, connecting...
[INFO] server: <peer-ip>:<port>: connected to target <dst>:80
[INFO] kcp_session: <peer-ip>:<port>: handshake done
```

On disconnect / idle timeout:

```text
[INFO] kcp_session: <peer-ip>:<port>: closed
[INFO] server: session closed: <peer-ip>:<port> (total: 0)
```

## 5. Expected Android CPP_REMOTE logs

`CPP_REMOTE` should distinguish clearly between *local VPN started* and *remote
reachable*. Only mark the remote reachable after a valid SOCKS5 response with
`rep=0x00` (or another valid server packet). Example lines:

```text
LOCAL_VPN_STARTED
CPP_REMOTE_STARTED
CPP_REMOTE SOCKS5 CONNECT connectionId=123 dst=93.184.216.34:80
CPP_REMOTE SOCKS5 response rep=0x00 connectionId=123
SOCKS5 CONNECT dst=93.184.216.34:80 cmd=1
connected to target 93.184.216.34:80
CPP_REMOTE_REACHABLE
```

Failure states to surface distinctly:

```text
CPP_REMOTE_FAILED   # server stopped / wrong key / Windows firewall blocks UDP
```

## 6. Chrome test URLs

Open these in Chrome on the emulator (routed through `CPP_REMOTE`):

```text
http://93.184.216.34
http://neverssl.com
http://example.org
https://example.com
https://www.cloudflare.com
https://www.wikipedia.org
https://httpbin.org/get
```

Concurrent tabs (to exercise session cleanup):

```text
https://www.google.com
https://www.github.com
https://www.wikipedia.org
https://www.cloudflare.com
```

Expected: pages load, C++ `INFO` logs show one session per tab, and after
closing the tabs the active session count returns near zero.

## 7. Failure stage mapping

If a request fails, match the symptom to a stage:

| Symptom | Stage | Where to look |
| --- | --- | --- |
| Client never reaches `CPP_REMOTE_REACHABLE` | `AUTH_FAILED` / handshake timeout | Wrong key, or UDP 8388 blocked by firewall |
| `rep != 0x00` in SOCKS5 response | `TCP_CONNECT_FAILED` / `DNS_RESOLVE_FAILED` | Server cannot reach the target |
| Connection drops mid-transfer | `TCP_READ_FAILED` / `TCP_WRITE_FAILED` / `SESSION_TIMEOUT` | Server↔target TCP issue or idle timeout |
| Garbage bytes in tunnel | KCP param mismatch | Confirm both ends print the same `KCP config` line |
| `UDP ASSOCIATE` rejected | `SOCKS5_UNSUPPORTED_COMMAND` | Expected — only CONNECT is supported |

Full stage list: see `TROUBLESHOOTING.md` → "Common Failure Stages".

## 8. Quick verification checklist

- [ ] C++ server prints the `KCP config ...` line at startup.
- [ ] Windows Firewall allows inbound UDP 8388.
- [ ] Android `CPP_REMOTE` endpoint is `10.0.2.2:8388`.
- [ ] Android logs show `CPP_REMOTE_REACHABLE`, not just `CPP_REMOTE_STARTED`.
- [ ] `http://neverssl.com` loads in emulator Chrome.
- [ ] Closing all Chrome tabs drives the C++ server session count back to 0.
- [ ] INFO logs stay lifecycle-only (no packet spam); use `-L DEBUG` only for deep dives.
