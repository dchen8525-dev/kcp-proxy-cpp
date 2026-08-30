# AGENTS.md

> **Status Update (2026-08-19)**
>
> This file documents interop testing between Android CPP_REMOTE and C++ server.
>
> **C++ Project Status**:
> - ✅ KCP dependency migrated to vcpkg (no longer a Git submodule)
> - ✅ Version unified to 0.0.1 across all config files
> - ✅ CI configuration updated (removed submodule references)
> - ✅ Build scripts updated (removed submodule initialization)
> - ✅ Documentation updated and sanitized
>
> **Current Focus**: Android interop testing and validation

## Scope

Fix remaining maintainability, test, and interop issues across:

```text
D:\work\kcp-proxy-andriod
D:\work\kcp-proxy-cpp
```

Do NOT redesign the protocol.

Current architecture is correct:

```text
Android CPP_REMOTE
-> one TCP connection = one UDP socket = one KCP session
-> first KCP payload = SOCKS5 CONNECT
-> raw TCP stream after CONNECT
-> C++ SOCKS5-over-KCP server
```

Focus only on:

```text
source formatting
documentation formatting
test coverage
interop verification
runtime diagnostics
```

---

## 0. Baseline

Android:

```bat
cd /d D:\work\kcp-proxy-andriod
git status --short
.\gradlew clean assembleDebug test lintDebug
git diff --check
```

C++:

```bat
cd /d D:\work\kcp-proxy-cpp
git status --short
.\build_vs.bat
ctest --test-dir build --output-on-failure
git diff --check
```

Record all results before changing code.

---

## 1. Reformat Source and Docs

### Problem

Many files are still compressed into very long single lines.

Known examples:

```text
kcp-proxy-andriod/README.md
kcp-proxy-andriod/app/src/main/java/com/dchen/kcpvpn/vpn/cppremote/CppRemoteKcpSession.java
kcp-proxy-andriod/app/src/main/java/com/dchen/kcpvpn/vpn/cppremote/CppRemoteTunnelManager.java
kcp-proxy-cpp/CMakeLists.txt
kcp-proxy-cpp/src/kcp_proxy/*.cpp
kcp-proxy-cpp/docs/*.md
```

This makes review, diff, debugging, and future maintenance difficult.

### Fix

Reformat into readable multi-line style.

Do not change behavior while formatting unless required.

### Verify

```bat
git diff --check
.\gradlew clean assembleDebug test lintDebug
.\build_vs.bat
ctest --test-dir build --output-on-failure
```

---

## 2. Android: Add/Verify SOCKS5 Response Buffer Tests

### Problem

`CppRemoteKcpSession` uses `CppSocks5ResponseBuffer`, but tests must prove partial SOCKS5 responses work.

### Required Tests

Add or verify tests for:

```text
complete IPv4 SOCKS5 response
response split byte-by-byte
response with extra payload
REP != 0
invalid VER
invalid ATYP
truncated response
```

### Verify

```bat
.\gradlew test
```

---

## 3. Android: Verify CPP_REMOTE Session Cleanup

### Problem

CPP_REMOTE creates one session per TCP connection and schedules periodic KCP work. Need proof that sessions/tasks/sockets are cleaned up.

### Fix

Audit:

```text
CppRemoteTunnelManager
CppRemoteKcpSession
PacketRouter
KcpVpnService
```

Ensure:

```text
scheduled tasks cancel on close
sessions removed on FIN/RST/error
VPN stop closes all sessions
UDP channel closes safely
active session count returns near zero after browsing
```

Add DEBUG logs for active session count if useful.

### Verify

Open many Chrome tabs, close them, then stop VPN.

Expected:

```text
no CPU spin
no thread leak
no socket leak
active CPP_REMOTE sessions return near zero
```

---

## 4. Android: Remote State Must Not Be Misleading

### Problem

Remote Test can start locally even if the C++ server is unavailable.

### Fix

Ensure logs/UI distinguish:

```text
LOCAL_VPN_STARTED
CPP_REMOTE_STARTED
CPP_REMOTE_REACHABLE
CPP_REMOTE_FAILED
```

Only mark remote reachable after:

```text
valid SOCKS5 response rep=0x00
or another valid server packet proving the remote server is alive
```

### Verify

Test:

```text
server stopped
wrong key
Windows firewall blocks UDP
server running normally
```

---

## 5. C++: Improve Android Interop Docs

### Problem

`docs/ANDROID_INTEROP.md` exists but should be readable and copy-paste useful.

### Fix

Update docs with:

```text
Windows server start command
Windows Firewall UDP 8388 check
Android Emulator endpoint 10.0.2.2:8388
expected Android logs
expected C++ logs
Chrome test URLs
failure stage mapping
```

Use concrete examples:

```text
CPP_REMOTE SOCKS5 CONNECT connectionId=123 dst=93.184.216.34:80
CPP_REMOTE SOCKS5 response rep=0x00 connectionId=123
SOCKS5 CONNECT dst=93.184.216.34:80 cmd=1
connected to target 93.184.216.34:80
```

---

## 6. C++: Reformat and Improve Interop Script

### Problem

Interop server helper is not part of this repository; use the documented server command in `docs/TESTING.md`.

### Fix

It should print:

```text
server executable path
bind host/port
Android emulator endpoint
Windows Firewall reminder
current netstat UDP 8388 status
expected startup log lines
```

### Verify

```powershell
Use the server command from `docs/TESTING.md`; no repository script is required for this step.
```

---

## 7. KCP Parameter Consistency

### Problem

Both sides must log the same real KCP settings.

Expected baseline:

```text
conv=1
mtu=1400
nodelay=1
interval=10
resend=5
nc=1
sndWnd=256
rcvWnd=512
timeout=60s
```

### Fix

Ensure Android CPP_REMOTE and C++ startup logs print actual values.

If values differ, align them or document why the difference is safe.

### Verify

Start C++ server and Android Remote Test, compare logs.

---

## 8. INFO Log Volume

### Problem

INFO logs must not be packet spam.

### Fix

Keep INFO for lifecycle:

```text
started/stopped
session created/closed
SOCKS5 target
SOCKS5 response
remote reachable/failed
connect success/failure
fatal errors
```

DEBUG only:

```text
UDP send/recv
KCP input/output
TCP byte forwarding
TUN packet details
SOCKS5 hex dumps
```

### Verify

Browse several sites at INFO.

Logs remain readable.

---

## 9. End-to-End Verification

### C++ local curl

```bat
bin\windows\kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L INFO
bin\windows\kcp-proxy-client.exe -s 127.0.0.1 -p 8388 -H 127.0.0.1 -l 1080 -k remote_test_key_123456 -L INFO

curl -x socks5h://127.0.0.1:1080 http://neverssl.com
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x socks5h://127.0.0.1:1080 https://www.cloudflare.com
```

### Android Remote Test

C++ server:

```bat
bin\windows\kcp-proxy-server.exe -H 0.0.0.0 -p 8388 -k remote_test_key_123456 -L INFO
```

Android emulator endpoint:

```text
10.0.2.2:8388
```

Chrome tests:

```text
http://93.184.216.34
http://neverssl.com
http://example.org
https://example.com
https://www.cloudflare.com
https://www.wikipedia.org
https://httpbin.org/get
```

Concurrent tabs:

```text
https://www.google.com
https://www.github.com
https://www.wikipedia.org
https://www.cloudflare.com
```

---

## 10. Acceptance Criteria

Complete only when:

```text
both repos build
Android tests pass
Android lintDebug checked
C++ CTest passes
git diff --check passes
source/docs are readable
SOCKS5 response buffer tests exist
CPP_REMOTE session cleanup verified
remote state is not misleading
C++ Android interop docs are useful
interop script is readable
KCP config logs match
INFO logs are not packet spam
C++ local curl tests pass
Android Chrome remote tests pass or clear failure stages are reported
```

---

## 11. Final Report

Report:

```text
1. Problems found
2. Android files changed
3. C++ files changed
4. Fixes implemented
5. Tests added/updated
6. Android build/test/lint result
7. C++ build/CTest result
8. C++ local curl result
9. Android emulator interop result
10. Remaining risks
```

Do not stop at analysis. Apply fixes directly.