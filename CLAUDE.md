# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KCP proxy: a SOCKS5 proxy that tunnels TCP traffic over an encrypted KCP (UDP) channel. Two components:
- **kcp-proxy-client**: runs locally, accepts SOCKS5 connections, encrypts and forwards over KCP/UDP to server
- **kcp-proxy-server**: runs remotely, decrypts KCP/UDP traffic, connects to actual targets on behalf of client

```
Local App  --TCP-->  Client SOCKS5  --[encrypt/KCP/UDP]-->  Server --TCP--> Target
```

## Build Commands

```bash
# One-command build (Linux/macOS) — auto-bootstraps vcpkg if needed
./build.sh

# One-command build (Windows MSVC) — auto-detects VS version, bootstraps vcpkg
build_vs.bat

# CLion: set VCPKG_ROOT env var to your vcpkg installation, then open project

# Manual build with CMake presets
cmake --preset default           # Configure (uses vcpkg from VCPKG_ROOT)
cmake --build --preset release   # Build Release
cmake --build --preset debug     # Build Debug
```

Build targets: `kcp-proxy-server`, `kcp-proxy-client`

Build outputs live under `build/` (multi-config: `build/Release/`, `build/Debug/`).

## Runtime

```bash
kcp-proxy-server -k <key> [-H 0.0.0.0] [-p 8388] [-L info]
kcp-proxy-client -s <server-host> -k <key> [-p 8388] [-H 127.0.0.1] [-l 1080] [-L info]
```

Key is derived via HKDF-SHA256 into AES-128-GCM keys (see README 协议与加密 / docs/PROTOCOL.md). Both sides must use the same key (min 16 chars).

## Deployment

- Deploy/build implementations are grouped under `scripts/runtime/`, `scripts/deploy/`, `scripts/package/`, and `scripts/templates/`.
- **Local-side tooling is Python 3.12 (stdlib only, cross-platform)**; anything that runs *on the target Linux server* stays POSIX sh, because minimal Debian hosts do not guarantee `python3`.
  - Python: `scripts/deploy/deploy.py` (deploy) and `scripts/package/package.py` (packaging: standalone tar.gz/zip + deb).
  - POSIX sh: `scripts/deploy/install-service.sh`, `scripts/deploy/uninstall-service.sh`, plus the wrapper/postinst/prerm/postrm payloads embedded in packages.
- Packaging: `python3 scripts/package/package.py standalone` (tar.gz on linux/macos, zip on windows) and `python3 scripts/package/package.py deb`. Archive permissions come from an explicit table in `package.py`, never from `stat()` — Windows has no Unix mode bits.
- `scripts/runtime/common.sh` is the single source of truth for ports and suffix validation — `start.sh` and `install-service.sh` source it, `deploy.py` parses it.
- One-command deploy: `./deploy.sh user@host` (thin forwarder to `scripts/deploy/deploy.py`, Python3 stdlib + system ssh/scp, cross-platform).
- Server side: fixed unit name `kcp-proxy-server.service` (no @template), suffix stored in `/etc/kcp-proxy/server.env` (mode 600), runs as `kcpproxy` system user.
- Key = Beijing date (YYYYMMDD) + suffix, re-derived on each service (re)start. A root crontab entry (`0 */6 * * *`, marker `# kcp-proxy-server`) restarts the service every 6 hours so the key rolls over shortly after midnight; clients must restart after the key changes. Uninstall removes the cron entry.

## Architecture

### Data Flow

- **KcpWrapper** wraps vendored `ikcp`. Output callback pattern: when KCP produces output, callback fires to encrypt and send via UDP.
- **Crypto** provides AES-128-GCM encryption with monotonic counter nonce. Direction byte (0x01 client, 0x02 server) prevents cross-direction replay.
- **Server side**: single UDP socket, `KCPSession` per client endpoint (keyed by `ip:port`), multiplexed by `KCPServer`.
- **Client side**: one UDP socket + one `KCPClientSession` per TCP connection (N connections = N sockets).
- **KCPProxyClient**: TCP acceptor for local SOCKS5. Per-connection inline SOCKS5 handshake, then bidirectional forwarding via Crypto + KCPClientSession.

### Key Patterns

- All major classes use `enable_shared_from_this` — lambdas capture `shared_ptr` to prevent premature destruction during async ops.
- Asio proactor pattern throughout: recursive async loops (`do_receive -> handle_receive -> do_receive`).
- "Pending read" pattern bridges KCP's pull-based recv with Asio: `async_read_some` stores handler, fulfilled later by `try_fulfill_read()` when data arrives.
- `forward_read_pending` atomic flag prevents concurrent KCP reads — must stay true through the entire read→write→re-arm cycle.

### Config and Tuning

All tuning is compile-time constants in `config.hpp` (KCP interval, window sizes, MTU, timeouts, crypto params). KCP runs in fastest mode: nodelay, 10ms interval, fast resend after 5 skips, no congestion control.

## Dependencies

| Dependency | Source |
|------------|--------|
| OpenSSL | vcpkg |
| Asio | vcpkg (standalone, no Boost) |
| KCP | vcpkg |

All dependencies are managed by vcpkg. Build scripts automatically install them during the build process.

## Platform

CMake supports Ubuntu x64 and Windows x64 (GCC, MinGW, MSVC). `ASIO_STANDALONE` is set globally — no Boost dependency.