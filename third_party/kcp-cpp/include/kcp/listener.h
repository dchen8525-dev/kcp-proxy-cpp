// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_LISTENER_H_
#define KCP_LISTENER_H_

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

#include "kcp/error.h"
#include "kcp/platform/socket.h"
#include "kcp/udp_session.h"

namespace kcp {

// Server-side session multiplexer (sess.go:1163-1420). One UDP socket, one read thread, and a map
// from peer address to session: a packet from an unknown address with a valid conv creates a
// session, which is then handed to Accept().
//
// The Listener owns the socket and the sessions' shared state, so it must outlive every session it
// created. Closing it stops the read thread; the sessions report a socket error afterwards, which
// is what the reference does too.
class Listener {
 public:
  ~Listener();

  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;

  // Waits for the next incoming session. Blocks until one arrives, the deadline expires, the
  // socket fails, or the listener is closed.
  std::shared_ptr<UdpSession> Accept(std::error_code* ec = nullptr);

  // Go name for the same operation.
  std::shared_ptr<UdpSession> AcceptKcp(std::error_code* ec = nullptr) { return Accept(ec); }

  void close(std::error_code* ec = nullptr);

  bool is_closed() const { return closed_.load(std::memory_order_acquire); }
  std::string addr() const { return addr_text_; }

  void SetDeadline(Deadline deadline);
  void SetReadDeadline(Deadline deadline);

  // Go returns errInvalidOperation here; kept for API parity (sess.go:1401).
  ErrorCode SetWriteDeadline(Deadline deadline);

  ErrorCode SetReadBuffer(int bytes);
  ErrorCode SetWriteBuffer(int bytes);
  ErrorCode SetDscp(int dscp);

  // Runs `fn` against the underlying descriptor while holding the session map lock.
  int Control(const std::function<int(platform::SocketHandle)>& fn, std::error_code* ec = nullptr);

  // Number of live sessions. Not exported by the reference; used by tests and diagnostics.
  std::size_t session_count() const;

  // Diagnostic tap for the datagrams the monitor pulls off the socket, in the format the session
  // uses (PORTING-PLAN.md §6.1). Only the incoming direction exists here: a listener never sends.
  // Fires before decryption, so the bytes are exactly what came off the wire - which is the whole
  // point, and why it cannot be folded into UdpSession::SetPacketTrace: OpenInPlace decrypts in
  // place, destroying the original bytes before the session sees them.
  void SetPacketTrace(UdpSession::PacketTrace trace);

 private:
  friend class UdpSession;
  friend std::unique_ptr<Listener> ListenWithOptions(const std::string&, const Crypt&, int, int,
                                                     std::error_code*);
  friend std::unique_ptr<Listener> ServeConn(const Crypt&, int, int, platform::SocketHandle,
                                             std::error_code*);

  Listener(Crypt crypt, int data_shards, int parity_shards, platform::SocketHandle fd,
           bool own_conn);

  // Binds `laddr` (or adopts `fd` when it is valid) and starts the monitor thread.
  static std::unique_ptr<Listener> Create(const std::string& laddr, Crypt crypt, int data_shards,
                                          int parity_shards, platform::SocketHandle fd,
                                          bool own_conn, std::error_code* ec);

  void Start();
  void Monitor();
  void PacketInput(std::uint8_t* data, std::size_t len, const platform::SocketAddress& from);
  void CloseSession(const platform::SocketAddress& remote, const UdpSession* session);
  void NotifyReadError(int socket_errno);

  Crypt crypt_;
  int data_shards_ = 0;
  int parity_shards_ = 0;
  platform::SocketHandle fd_ = platform::kInvalidSocket;
  bool own_conn_ = false;
  std::string addr_text_;

  std::atomic<bool> closed_{false};
  mutable std::mutex mu_;  // L3: the session map and the accept backlog
  std::condition_variable accept_cv_;
  std::map<std::string, std::shared_ptr<UdpSession>> sessions_;
  std::deque<std::shared_ptr<UdpSession>> accepts_;
  Deadline read_deadline_{};
  ErrorCode read_error_ = ErrorCode::kOk;
  std::atomic<int> socket_error_code_{0};

  std::thread monitor_thread_;

  std::shared_ptr<const UdpSession::PacketTrace> packet_trace_;
};

// ---- package-level constructors (sess.go:1430-1478) -------------------------------------------

std::unique_ptr<Listener> Listen(const std::string& laddr, std::error_code* ec = nullptr);
std::unique_ptr<Listener> ListenWithOptions(const std::string& laddr, const Crypt& crypt,
                                            int data_shards, int parity_shards,
                                            std::error_code* ec = nullptr);
inline std::unique_ptr<Listener> ListenWithOptions(const std::string& laddr,
                                                   std::shared_ptr<BlockCrypt> block,
                                                   int data_shards, int parity_shards,
                                                   std::error_code* ec = nullptr) {
  return ListenWithOptions(laddr, Crypt{std::move(block), nullptr}, data_shards, parity_shards, ec);
}
inline std::unique_ptr<Listener> ListenWithOptions(const std::string& laddr,
                                                   std::shared_ptr<AeadCrypt> aead, int data_shards,
                                                   int parity_shards,
                                                   std::error_code* ec = nullptr) {
  return ListenWithOptions(laddr, Crypt{nullptr, std::move(aead)}, data_shards, parity_shards, ec);
}

// Adopts an existing bound descriptor (Go's ServeConn).
std::unique_ptr<Listener> ServeConn(const Crypt& crypt, int data_shards, int parity_shards,
                                    platform::SocketHandle fd, std::error_code* ec = nullptr);

}  // namespace kcp

#endif  // KCP_LISTENER_H_
