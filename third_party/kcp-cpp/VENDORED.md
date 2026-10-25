# Vendored: kcp-cpp

C++17 port of the xtaci/kcp-go v5 protocol state machine
(https://github.com/xtaci/kcp-go), vendored from the kcp-cpp repository
(https://github.com/dchen8525-dev/kcp-cpp).

- Provenance: kcp-cpp @ `0538725` (2026-10-25, master)
- License: MIT (see `LICENSE`; upstream kcp-go is MIT, Copyright (c) 2015 xtaci)
- Previous sync: `584c46f` (2026-10-24). The delta is porting rounds 36-45
  (upstream PORTING-PLAN.md v5.17, risks R32-R38): in the compiled subset it
  changes `Kcp::Flush` to return the `nextUpdate` interval (callers may ignore
  it — the proxy's own driver is a fixed 10 ms shared tick with an
  unconditional flush after every `Update()`, so retransmit granularity stays
  bounded by that tick by design) and makes `PeekSize` hold fragments whose
  head carries `frg == 255` instead of assembling across the uint8 wrap
  (upstream deviation D21, hostile-input-only). The session-layer fixes
  (close-path races, EINTR, poll-based wait, cancellable rate limiter) live in
  files this vendor does not compile; they are vendored for provenance.

## Why vendored

`kcp-proxy` previously used the C `ikcp` implementation (vcpkg `kcp` port).
It now uses this C++ port instead: same wire format and algorithm lineage
(kcp-go), pure C++17, injectable clock, no global mutable state. Vendoring
keeps the repository self-contained — `vcpkg.json` no longer lists a `kcp`
dependency.

Compared to the first-generation vendor in the experimental tree
(kcp-proxy-cpp2, kcp-cpp @ `8a104bb`), this copy is 35 porting rounds newer
and is the first one to compile the FEC layer (`fec.cc` + `rs.cc` +
`galois.cc`): kcp-proxy applies Reed-Solomon forward error correction between
the KCP state machine and the crypto layer.

## Build scope

`CMakeLists.txt` here compiles the KCP state machine core (`src/kcp.cc`,
`src/internal/clock.cc`), the SNMP counters (`src/snmp.cc`), and the FEC
codec (`src/internal/fec.cc`, `rs.cc`, `galois.cc`). The rest of the upstream
source tree (`udp_session.cc`, `crypt.cc`, `frame.cc`, its own crypto and
platform layers, ...) is vendored unmodified for provenance and future use
but is deliberately not compiled: the proxy implements its own transport
(asio) and crypto (OpenSSL AEAD).

## Local patches (documented deviations from upstream)

Both patches are confined to testability/const-correctness; neither changes
the wire format nor the protocol behavior. They are kept minimal so the
vendored copy stays easy to diff against upstream.

1. `include/kcp/kcp.h` + `src/kcp.cc` — `Kcp::PeekSize()` is now `const`.
   It only reads `rcv_queue_` (`RingBuffer::Peek() const` already exists),
   and the proxy exposes `peek_size()` through a const accessor.
2. `include/kcp/kcp.h` — added four read-only accessors
   (`nodelay()`, `interval()`, `fastresend()`, `nocwnd()`) over the tuning
   state applied by `NoDelay()`, so embedders can verify that configured
   constants reached the live protocol state (mirrors the existing
   `conv()`/`mtu()`/`snd_wnd()`/`rcv_wnd()` accessor set).
