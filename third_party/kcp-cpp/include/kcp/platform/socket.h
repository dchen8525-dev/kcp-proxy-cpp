// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_PLATFORM_SOCKET_H_
#define KCP_PLATFORM_SOCKET_H_

#include <cstddef>
#include <cstdint>
#include <string>

namespace kcp {
namespace platform {

// Portable socket handle. On Windows this is the 64-bit SOCKET (UINT_PTR); on POSIX a file
// descriptor.
#if defined(_WIN32)
using SocketHandle = std::uintptr_t;
constexpr SocketHandle kInvalidSocket = static_cast<SocketHandle>(~static_cast<std::uintptr_t>(0));
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

// Opaque socket address (holds sockaddr_storage so IPv4 and IPv6 both fit).
//
// System headers are deliberately not part of the public interface: everything that needs
// <winsock2.h> / <sys/socket.h> stays inside src/platform/socket.cc.
class SocketAddress {
 public:
  SocketAddress();

  // Parses a numeric address ("127.0.0.1", "::1") plus port. No DNS resolution: the session layer
  // never needs it for the loopback test matrix, and getaddrinfo() would drag in another
  // platform-specific failure mode.
  static bool Parse(const std::string& ip, std::uint16_t port, SocketAddress* out);

  // Parses "1.2.3.4:9000", "[::1]:9000" or ":9000" (wildcard bind). No DNS resolution, same
  // reason as Parse().
  static bool ParseHostPort(const std::string& host_port, SocketAddress* out);

  // Returns "ip:port"; used for Listener session keys (PORTING-PLAN.md §3.1: the key is the
  // source address string, not conv).
  std::string ToString() const;

  bool valid() const { return len_ != 0; }
  const void* data() const;
  int size() const { return len_; }

  // Mutable access for sys_recvfrom, which fills the address in place.
  void* mutable_data();
  int mutable_size() const;
  void set_size(int len) { len_ = len; }

  bool operator==(const SocketAddress& other) const;
  bool operator!=(const SocketAddress& other) const { return !(*this == other); }

 private:
  static constexpr int kStorageSize = 128;
  alignas(8) unsigned char storage_[kStorageSize];
  int len_ = 0;
};

// One-time socket layer initialisation (WSAStartup on Windows, no-op on POSIX). Safe to call
// repeatedly; the first call wins.
bool InitSockets();
void ShutdownSockets();

// Last socket error for the calling thread (WSAGetLastError / errno).
int LastError();
std::string ErrorMessage(int err);

// True for a recvfrom error that must not stop the read loop: the datagram it belonged to is lost,
// the socket is still usable.
//
// This matters most on Windows, where an ICMP port-unreachable raised by an earlier sendto is
// reported to the *next* recvfrom as WSAECONNRESET (10054). A UDP peer that closes while the other
// side is echoing is the normal end of a transfer, so treating 10054 as fatal stops the listener's
// monitor thread and starves every session it owns - kcp-go never returns from its read loops for
// exactly this reason (readloop.go:47-70, listener.go:1229).
bool IsIgnorableRecvError(int err);

// Thin syscall wrappers. Named with a sys_ prefix so no member function of the session classes
// (read/write/close) can ever shadow them (PORTING-PLAN.md §3.3).
SocketHandle SysSocketUdp();
int SysBind(SocketHandle fd, const SocketAddress& addr);
// Resolves the address a socket is bound to (useful after binding to port 0 in tests).
int SysGetSockName(SocketHandle fd, SocketAddress* addr);
int SysSendTo(SocketHandle fd, const void* buf, std::size_t len, const SocketAddress& to);
int SysRecvFrom(SocketHandle fd, void* buf, std::size_t len, SocketAddress* from);
int SysClose(SocketHandle fd);
int SysShutdown(SocketHandle fd);
int SysSetNonBlocking(SocketHandle fd, bool non_blocking);
// Enables SO_REUSEADDR. The listener relies on it in the interop matrix so a fast restart does not
// hit TIME_WAIT-style bind failures.
int SysSetReuseAddr(SocketHandle fd);
// SO_RCVBUF / SO_SNDBUF, in bytes.
int SysSetRecvBuffer(SocketHandle fd, int bytes);
int SysSetSendBuffer(SocketHandle fd, int bytes);
// SO_RCVTIMEO. Used by tests so a lost packet fails the test instead of hanging ctest.
int SysSetRecvTimeout(SocketHandle fd, int timeout_ms);

// Waits until the socket is readable. Returns 1 when readable, 0 on timeout, -1 on error.
//
// The read loops use this instead of blocking forever inside recvfrom: shutdown() does not
// reliably wake a blocked recvfrom on POSIX, and closing a descriptor that another thread is
// polling is undefined, so a bounded wait plus a closed_ flag is the portable way to stop them.
int SysWaitReadable(SocketHandle fd, int timeout_ms);

// Writes the DSCP byte (IPv4 TOS = dscp << 2, IPv6 traffic class = dscp). Returns 0 on success
// and -1 when the platform rejects it; on Windows an unconnected UDP socket commonly refuses
// IP_TOS, which is why the support matrix in README.md records the difference (issue #48).
int SysSetDscp(SocketHandle fd, int dscp);

}  // namespace platform
}  // namespace kcp

#endif  // KCP_PLATFORM_SOCKET_H_
