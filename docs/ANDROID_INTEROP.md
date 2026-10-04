# Android Interop Testing

How to validate the C++ SOCKS5-over-KCP server against the Android `CPP_REMOTE`
peer end-to-end. This document is copy-paste driven; every command is real.

## Topology

```text
Android App (Chrome / WebView)
  -> CPP_REMOTE  (one TCP conn = one UDP socket = one KCP session)
    -> KCP over UDP -> C++ kcp-proxy-server (Windows host, or a Linux host -- see §9)
      -> raw TCP to the real target
```

Both ends must use the **same KCP parameters** or `ikcp` silently discards the
peer's packets. The C++ server and client both print the canonical line at
startup, rendered from `config.hpp`, and the Android peer prints the same values:

```text
KCP config conv=1 mtu=1400 nodelay=1 interval=10 resend=5 nc=1 sndWnd=256 rcvWnd=512 timeout=60s
```

When you start the C++ server, confirm this line appears before any traffic.

## 1. Start the C++ server (Windows)

From the repository root, after a successful build (see `TESTING.md`):

```powershell
.\build\Release\kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L INFO
```

`build_vs.bat` also copies the binaries (and the OpenSSL DLLs they need) to
`bin\windows\`, so `.\bin\windows\kcp-proxy-server.exe ...` works the same way.
Either path is fine — just stay in the directory that has the two OpenSSL DLLs
next to the `.exe`.

To run the server on a remote Linux host instead (so a physical device or a
non-host emulator can reach it), see §9.

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

Without this rule, the Android side sees handshake timeouts even though the
server process is running. The server logs no `new session:` line at all in
that case — no packet ever reaches it, so there is nothing for it to reject.

## 3. Android Emulator endpoint

From inside the emulator, the host machine is reached at the well-known
loopback alias `10.0.2.2`. Point `CPP_REMOTE` at:

```text
10.0.2.2:8388
```

Not `127.0.0.1` (that is the emulator itself) and not the host's LAN IP.

## 4. Expected C++ server logs (when Android connects)

Captured from a real run (Android emulator -> Linux server, port 8389). The
lifecycle stays at `INFO`; packet-level detail is `DEBUG` only.

```text
[INFO] server: listening on 0.0.0.0:8388
[INFO] server: KCP config conv=1 mtu=1400 nodelay=1 interval=10 resend=5 nc=1 sndWnd=256 rcvWnd=512 timeout=60s
[INFO] server: new session: <peer-ip>:<port> (total: 1)
[INFO] server: <peer-ip>:<port>: KCP handshake confirmed (V2, half-close enabled)
[INFO] server: <peer-ip>:<port>: SOCKS5 connect target cmd=1 atyp=1 host=<dst> port=80
[INFO] server: <peer-ip>:<port>: connecting to <dst>:80
[INFO] server: <peer-ip>:<port>: resolved <dst> to N endpoints, connecting...
[INFO] server: <peer-ip>:<port>: connected to target <dst>:80
```

`CPP_REMOTE` sends `KCP_PROXY_HELLO_V2` as its first payload, so the server
answers `KCP_PROXY_HELLO_ACK_V2` and enables half-close both ways — the
`KCP handshake confirmed (V2, half-close enabled)` line above is expected for an
Android session. (An older note here claimed the opposite, from before
`CPP_REMOTE` implemented V2; it has been verified against a device.)

The V1 / compatibility paths still exist and log differently:

```text
# A peer that sends KCP_PROXY_HELLO_V1 (V1 client, or the Android local-mode tunnel):
[INFO] server: <peer-ip>:<port>: KCP handshake confirmed
# A peer that sends no HELLO at all (first KCP payload is the SOCKS5 CONNECT):
[INFO] server: <peer-ip>:<port>: no HELLO control frame; treating first KCP payload as SOCKS5 compatibility handshake
```

Both of those keep half-close disabled (a FIN would be forwarded into the tunnel
as stream data by a peer that does not understand it), so the server never sends
`KCP_PROXY_FIN_V1` on those paths.

On disconnect (FIN/RST, error, or the 60s idle sweep):

```text
[INFO] server: <peer-ip>:<port>: close_connection from <reason>
[INFO] kcp_session: <peer-ip>:<port>: stopped
[INFO] kcp_session: <peer-ip>:<port>: stats tx_pkt=... tx_bytes=... rx_pkt=... rx_bytes=... replay_dropped=0 decrypt_err=0 encrypt_err=0
```

When the target closes first, the half-close path is visible too (V2 peers):

```text
[INFO] server: <peer-ip>:<port>: target connection closed, draining queued data to client (wait_send=N)
[INFO] kcp_session: <peer-ip>:<port>: FIN sent (half-close)
```

Every 30s the server also emits the count your §8 checklist depends on:

```text
[INFO] server: metrics sweep: sessions=N pkts_sent=... pkts_recv=... bytes_sent=... bytes_recv=...
```

`sessions` is the number of live KCP sessions; after closing all Chrome tabs it
must fall back to `0` within the idle timeout (60s).

## 5. Expected Android CPP_REMOTE logs

`CPP_REMOTE` distinguishes *local VPN started* from *remote reachable*. The
remote is marked reachable only after a valid SOCKS5 response with `rep=0x00`
(or another valid server packet). Captured from a real device run:

```text
[INFO] CPP_REMOTE KCP UDP socket protected=true connectionId=<id>
[INFO] CPP_REMOTE HELLO_V2 connectionId=<id> salt=<4 hex bytes>..
[INFO] CPP_REMOTE handshake confirmed (V2, half-close enabled) connectionId=<id>
[INFO] CPP_REMOTE SOCKS5 CONNECT connectionId=<id> dst=<dst-ip>:<port> atyp=IPV4|IPV6
[INFO] CPP_REMOTE SOCKS5 response rep=0x00 connectionId=<id>
[INFO] CPP_REMOTE state=CPP_REMOTE_REACHABLE detail=valid SOCKS5 response received
```

Then the data path (application traffic through the VPN):

```text
[DEBUG] PacketRouter parse protocol=6 src=<tun-ip> dst=<dst-ip> len=<n>
[INFO]  TCP SYN connectionId=<id> mode=CPP_REMOTE dst=<dst-ip>:<port>
[DEBUG] CPP_REMOTE TCP payload -> KCP raw len=<n> connectionId=<id>
[DEBUG] CPP_REMOTE KCP raw -> TCP payload len=<n> connectionId=<id>
```

Failure states surface distinctly, and the close reason names the real stage:

```text
[ERROR] CPP_REMOTE HELLO/SOCKS5 response timeout ... timeoutSec=20   # server silent (down, wrong key, UDP blocked)
[WARN]  CPP_REMOTE connection closed reason=CPP_SERVER_NO_RESPONSE
[INFO]  CPP_REMOTE SOCKS5 response rep=0x04 ...                      # server reached the peer, target unreachable
[INFO]  CPP_REMOTE connection closed reason=SOCKS5_CONNECT_FAILED
[ERROR] CPP_REMOTE CRYPTO_MISMATCH (auth failed)                     # wrong key
```

The client's HELLO/SOCKS5 deadline (20s) is deliberately longer than the
server's `CONNECT_TIMEOUT_SEC` (15s): the server answers an unreachable target
with a real error code at 15s, and the client must still be waiting to relay it.
When the deadline was shorter, every unreachable target surfaced as a generic
`CPP_SERVER_NO_RESPONSE` instead of the server's actual verdict.

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
| Client never reaches `CPP_REMOTE_REACHABLE` | no stage — nothing logged | Wrong key or blocked UDP: the server never logs `new session:`/`FAIL_STAGE=DECRYPT_FAILED` for the packet |
| Android logs `SOCKS5 reply failed: <code>` | none (client side) | Server could not reach the target; the C++ log carries the real stage |
| `rep != 0x00` in the SOCKS5 response | `TCP_CONNECT_FAILED` / `DNS_RESOLVE_FAILED` / `SSRF_BLOCKED` | Server cannot reach the target, or it is a restricted address |
| `rep=0x04` for every IPv6 target | `TCP_CONNECT_FAILED` `ERROR=Network is unreachable` | The **server** has no IPv6 egress. See the IPv6 note below |
| Connection drops mid-transfer | `TCP_READ_FAILED` / `TCP_WRITE_FAILED` / `SESSION_TIMEOUT` | Server↔target TCP issue or idle timeout |
| Session dies before SOCKS5 starts | `KCP_HANDSHAKE_FAILED` / `KCP_INPUT_FAILED` | Handshake read failed or `ikcp_input()` rejected a segment |
| Garbage bytes in tunnel | KCP param mismatch | Confirm both ends print the same `KCP config` line |
| `UDP ASSOCIATE` rejected | `SOCKS5_UNSUPPORTED_COMMAND` | Expected — only CONNECT is supported |

Full stage list: see `TROUBLESHOOTING.md` → "Common Failure Stages".

### IPv6 targets need IPv6 on the server

The Android VPN advertises `::/0`, so IPv6 traffic enters the tunnel. If the
**server** has no IPv6 egress, every IPv6 target fails — the server logs
`FAIL_STAGE=TCP_CONNECT_FAILED ERROR=Network is unreachable` and the client
reports `SOCKS5_CONNECT_FAILED`.

This is usually harmless: DNS returns both A and AAAA, and applications
(Chrome, Android) use Happy Eyeballs to try IPv4 in parallel, so dual-stack
hostnames still work. It only breaks IPv6-only targets. Check the server with
`ip -6 addr show scope global` — an empty result means no IPv6.

Adding IPv6 via a 6in4 tunnel (Hurricane Electric) works even when the provider
does not offer IPv6, provided it allows protocol 41; verify the kernel supports
it with `modprobe sit && ip tunnel help`. Note the tunnel routes IPv6 through
the broker, which adds latency, so it is a compatibility fix rather than a speed
up — leave it out unless you actually need IPv6-only targets.

## 8. Quick verification checklist

- [ ] C++ server prints the `KCP config ...` line at startup.
- [ ] Windows Firewall allows inbound UDP 8388 (or the Linux host's firewall does).
- [ ] Android `CPP_REMOTE` endpoint is `10.0.2.2:8388` (or the host's public IP).
- [ ] Android logs show `CPP_REMOTE_REACHABLE`, not just `CPP_REMOTE_STARTED`.
- [ ] Android logs show `handshake confirmed (V2, half-close enabled)`.
- [ ] `http://neverssl.com` loads in emulator Chrome.
- [ ] Closing all Chrome tabs drives `metrics sweep: sessions=N` back to 0.
- [ ] INFO logs stay lifecycle-only (no packet spam); use `-L DEBUG` only for deep dives.

Two flags are worth knowing while debugging:

- `--allow-target <host[:port]>` (server) bypasses the SSRF guard. Needed only if
  a test target lives on the host's own LAN; it is a lab-only escape hatch.
- `-T <n>` (server) sets io_context worker threads (1–64, default 1). Useful
  when driving many concurrent tabs.

## 9. Deploying the server on a remote Linux host

Use this when the emulator cannot reach the Windows host (a physical device, a
remote emulator, or CI). Verified on Ubuntu 22.04.

```bash
# 1. Build deps (no vcpkg needed: the distro packages satisfy find_package)
apt-get update && apt-get install -y build-essential cmake ninja-build \
  libssl-dev libasio-dev libfmt-dev git curl zip unzip tar pkg-config

# 2. vcpkg only for the `kcp` package (no distro equivalent)
git clone --depth 1 https://github.com/microsoft/vcpkg.git /root/vcpkg
/root/vcpkg/bootstrap-vcpkg.sh
/root/vcpkg/vcpkg install kcp --triplet x64-linux

# 3. Build (ship the source with `git archive`, not a checkout)
git archive --format=tar.gz -o src.tar.gz HEAD
#   ... copy src.tar.gz to the host, extract, then:
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/root/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_MANIFEST_INSTALL=OFF \
  -DCMAKE_PREFIX_PATH=/root/vcpkg/installed/x64-linux
cmake --build build --parallel
./build/kcp_proxy_test          # the unit suite runs on Linux too

# 4. Run as a service (separate port so it cannot disturb an existing instance)
cat > /etc/systemd/system/kcp-proxy-test.service <<'UNIT'
[Unit]
Description=KCP Proxy Server (test instance)
After=network.target
[Service]
ExecStart=/root/kcp-test/src/build/kcp-proxy-server -H 0.0.0.0 -p 8389 -k remote_test_key_123456 -L INFO
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now kcp-proxy-test
journalctl -u kcp-proxy-test -f          # watch the logs
```

`-DCMAKE_PREFIX_PATH` matters: with `VCPKG_MANIFEST_INSTALL=OFF` and a classic
vcpkg install, the `asio` config file is not found without it.

Cleanup: `systemctl disable --now kcp-proxy-test && rm /etc/systemd/system/kcp-proxy-test.service && systemctl daemon-reload`.

## 10. Automated live interop test

The Android repo carries `app/src/androidTest/.../CppRemoteLiveInteropTest`,
which runs the real `CPP_REMOTE` protocol stack (crypto, KCP, session) on a
device against a deployed server and asserts a real byte round-trip. It needs no
VPN consent (the socket protector is stubbed, since no VPN is active), so it runs
unattended:

```bash
# from the Android repo; the server must be reachable from the device
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w \
  -e class com.dchen.kcpvpn.vpn.cppremote.CppRemoteLiveInteropTest \
  com.dchen.kcpvpn.debug.test/androidx.test.runner.AndroidJUnitRunner
```

It targets a **literal IP**, not a hostname: emulator DNS in restricted networks
can resolve names to `127.0.0.1`/`0.0.0.0`, which makes a hostname-based test
connect to the wrong address and fail spuriously.

Unlike the GUI path, this test does not cover the TUN/`PacketRouter` layer or the
VPN service — for that, drive the app as in §3–§6 (accepting the system VPN
consent dialog once).
