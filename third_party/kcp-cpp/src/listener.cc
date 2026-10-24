// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/listener.h"

#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

#include "kcp/internal/byteorder.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/frame.h"
#include "kcp/snmp.h"

namespace kcp {
namespace {

std::shared_ptr<UdpSession> FailNull(std::error_code* ec, ErrorCode code) {
  if (ec != nullptr) {
    *ec = MakeErrorCode(code);
  }
  return nullptr;
}

void Succeed(std::error_code* ec) {
  if (ec != nullptr) {
    ec->clear();
  }
}

}  // namespace

Listener::Listener(Crypt crypt, int data_shards, int parity_shards, platform::SocketHandle fd,
                   bool own_conn)
    : crypt_(std::move(crypt)),
      data_shards_(data_shards),
      parity_shards_(parity_shards),
      fd_(fd),
      own_conn_(own_conn) {}

Listener::~Listener() {
  if (!closed_.load(std::memory_order_acquire)) {
    close(nullptr);
  }
  if (monitor_thread_.joinable()) {
    monitor_thread_.join();
  }
  if (own_conn_ && fd_ != platform::kInvalidSocket) {
    platform::SysClose(fd_);
    fd_ = platform::kInvalidSocket;
  }
}

std::unique_ptr<Listener> Listener::Create(const std::string& laddr, Crypt crypt, int data_shards,
                                           int parity_shards, platform::SocketHandle fd,
                                           bool own_conn, std::error_code* ec) {
  platform::SocketHandle handle = fd;
  bool owns = own_conn;

  if (handle == platform::kInvalidSocket) {
    platform::SocketAddress bind_addr;
    if (!platform::SocketAddress::ParseHostPort(laddr, &bind_addr)) {
      if (ec != nullptr) {
        *ec = MakeErrorCode(ErrorCode::kInvalidArgument);
      }
      return nullptr;
    }
    handle = platform::SysSocketUdp();
    if (handle == platform::kInvalidSocket) {
      if (ec != nullptr) {
        *ec = MakeErrorCode(ErrorCode::kSocketError);
      }
      return nullptr;
    }
    if (platform::SysBind(handle, bind_addr) != 0) {
      platform::SysClose(handle);
      if (ec != nullptr) {
        *ec = MakeErrorCode(ErrorCode::kSocketError);
      }
      return nullptr;
    }
    owns = true;
  }

  std::unique_ptr<Listener> listener(
      new Listener(std::move(crypt), data_shards, parity_shards, handle, owns));
  platform::SocketAddress local;
  if (platform::SysGetSockName(handle, &local) == 0) {
    listener->addr_text_ = local.ToString();
  }
  listener->Start();
  Succeed(ec);
  return listener;
}

void Listener::Start() {
  monitor_thread_ = std::thread([this] { Monitor(); });
}

void Listener::Monitor() {
  std::vector<std::uint8_t> buffer(kMtuLimit);
  while (!closed_.load(std::memory_order_acquire)) {
    const int ready = platform::SysWaitReadable(fd_, 50);
    if (ready < 0) {
      NotifyReadError(platform::LastError());
      return;
    }
    if (ready == 0) {
      continue;
    }

    // Same burst read as UdpSession::ReadLoop: the monitor is the hot path for every server-side
    // datagram, and a wake costs far more than the demultiplexing it does.
    for (std::size_t i = 0; i < kMaxBatchSize; ++i) {
      platform::SocketAddress from;
      const int got = platform::SysRecvFrom(fd_, buffer.data(), buffer.size(), &from);
      if (got < 0) {
        if (closed_.load(std::memory_order_acquire)) {
          return;
        }
        const int err = platform::LastError();
        if (!platform::IsIgnorableRecvError(err)) {
          NotifyReadError(err);
          return;
        }
        // One datagram is lost; the socket is not. Returning here would silence the monitor and
        // starve every session this listener owns, which is what kcp-go avoids by counting the
        // error and continuing (listener.go:1229). A peer that closes while the server is still
        // echoing produces exactly this (Windows reports the resulting ICMP port-unreachable as
        // WSAECONNRESET on the next recvfrom), so it is part of the normal end of a transfer.
        DefaultSnmp().in_errs.fetch_add(1, std::memory_order_relaxed);
        break;
      }
      if (closed_.load(std::memory_order_acquire)) {
        return;
      }
      // Before PacketInput: OpenInPlace decrypts in place, so this is the last point where the
      // datagram is still byte-identical to what the peer sent.
      if (const auto trace = std::atomic_load(&packet_trace_)) {
        (*trace)(false, buffer.data(), static_cast<std::size_t>(got));
      }
      PacketInput(buffer.data(), static_cast<std::size_t>(got), from);
      if (platform::SysWaitReadable(fd_, 0) != 1) {
        break;
      }
    }
  }
}

void Listener::PacketInput(std::uint8_t* data, std::size_t len,
                           const platform::SocketAddress& from) {
  switch (internal::OpenInPlace(crypt_.block.get(), crypt_.aead.get(), &data, &len)) {
    case internal::OpenResult::kDropped:
      return;
    case internal::OpenResult::kIntegrityFailed:
      DefaultSnmp().in_csum_errors.fetch_add(1, std::memory_order_relaxed);
      return;
    case internal::OpenResult::kOk:
      break;
  }

  // sess.go:1222 - anything shorter cannot even carry a conv, so it is dropped silently here (the
  // session path counts it, the listener does not).
  if (len < std::min(kOverhead, kFecHeaderSizePlus2 + kConvSize)) {
    return;
  }

  // Demultiplex by source address first, exactly like sess.go:1228: the map key is the peer
  // address string, never the conv.
  const std::string key = from.ToString();
  std::shared_ptr<UdpSession> session;
  {
    std::lock_guard<std::mutex> lock(mu_);
    const auto it = sessions_.find(key);
    if (it != sessions_.end()) {
      session = it->second;
    }
  }

  std::uint32_t conv = 0;
  std::uint32_t sn = 0;
  bool has_conv = false;

  const std::uint16_t fec_flag = internal::ReadLe16(data + 4);
  switch (fec_flag) {
    case kTypeData:
      if (len < kFecHeaderSizePlus2 + kOverhead) {
        break;
      }
      has_conv = true;
      conv = internal::ReadLe32(data + kFecHeaderSizePlus2);
      sn = internal::ReadLe32(data + kFecHeaderSizePlus2 + kSnOffset);
      break;
    case kTypeParity:
      // A parity shard carries no conv: it belongs to whatever session already exists for this
      // address. Without one there is nothing to attach it to.
      break;
    case kTypeOob:
      has_conv = true;
      conv = internal::ReadLe32(data + kFecHeaderSizePlus2);
      break;
    default:
      if (len < kOverhead) {
        return;
      }
      has_conv = true;
      conv = internal::ReadLe32(data);
      sn = internal::ReadLe32(data + kSnOffset);
      break;
  }

  if (session != nullptr) {
    if (!has_conv || conv == session->conv()) {
      session->KcpInput(data, len);
      return;
    }
    // A different conv on a live address is only accepted as a reset (sn == 0); anything else is
    // a stray packet from an earlier incarnation of the peer.
    if (sn != 0) {
      return;
    }
    session->close(nullptr);
  }

  if (!has_conv) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(mu_);
    if (accepts_.size() >= kAcceptBacklog) {
      return;
    }
  }

  std::shared_ptr<UdpSession> created =
      UdpSession::Create(conv, crypt_, data_shards_, parity_shards_, this, fd_, false, from);
  created->KcpInput(data, len);

  {
    std::lock_guard<std::mutex> lock(mu_);
    sessions_[key] = created;
    accepts_.push_back(created);
  }
  accept_cv_.notify_one();
}

std::shared_ptr<UdpSession> Listener::Accept(std::error_code* ec) {
  std::unique_lock<std::mutex> lock(mu_);
  for (;;) {
    if (!accepts_.empty()) {
      std::shared_ptr<UdpSession> session = accepts_.front();
      accepts_.pop_front();
      Succeed(ec);
      return session;
    }
    if (read_error_ != ErrorCode::kOk) {
      return FailNull(ec, read_error_);
    }
    if (closed_.load(std::memory_order_acquire)) {
      return FailNull(ec, ErrorCode::kClosedPipe);
    }
    if (read_deadline_ != Deadline{} && std::chrono::steady_clock::now() >= read_deadline_) {
      return FailNull(ec, ErrorCode::kTimeout);
    }

    if (read_deadline_ == Deadline{}) {
      accept_cv_.wait(lock);
    } else {
      accept_cv_.wait_until(lock, read_deadline_);
    }
  }
}

void Listener::close(std::error_code* ec) {
  std::vector<std::shared_ptr<UdpSession>> owned;
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_.load(std::memory_order_acquire)) {
      if (ec != nullptr) {
        *ec = MakeErrorCode(ErrorCode::kClosedPipe);
      }
      return;
    }
    closed_.store(true, std::memory_order_release);
  }
  accept_cv_.notify_all();

  if (monitor_thread_.joinable() && monitor_thread_.get_id() != std::this_thread::get_id()) {
    monitor_thread_.join();
  }

  // Listener.Close closes every child (listener.go:1158-1176) before the shared socket goes away.
  // Dropping the references without closing them would be wrong twice over: the sessions would keep
  // using an fd that is about to be closed, and their destructors would call back into
  // CloseSession() on a Listener that no longer has a sessions_ map to erase from.
  {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& entry : sessions_) {
      owned.push_back(entry.second);
    }
    sessions_.clear();
    accepts_.clear();
  }
  for (auto& session : owned) {
    session->close(nullptr);
  }

  if (own_conn_ && fd_ != platform::kInvalidSocket) {
    platform::SysClose(fd_);
    fd_ = platform::kInvalidSocket;
  }
  Succeed(ec);
}

void Listener::SetDeadline(Deadline deadline) { SetReadDeadline(deadline); }

void Listener::SetReadDeadline(Deadline deadline) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    read_deadline_ = deadline;
  }
  accept_cv_.notify_all();
}

ErrorCode Listener::SetWriteDeadline(Deadline deadline) {
  static_cast<void>(deadline);
  return ErrorCode::kInvalidOperation;
}

ErrorCode Listener::SetReadBuffer(int bytes) {
  return platform::SysSetRecvBuffer(fd_, bytes) == 0 ? ErrorCode::kOk : ErrorCode::kSocketError;
}

ErrorCode Listener::SetWriteBuffer(int bytes) {
  return platform::SysSetSendBuffer(fd_, bytes) == 0 ? ErrorCode::kOk : ErrorCode::kSocketError;
}

ErrorCode Listener::SetDscp(int dscp) {
  return platform::SysSetDscp(fd_, dscp) == 0 ? ErrorCode::kOk : ErrorCode::kInvalidOperation;
}

int Listener::Control(const std::function<int(platform::SocketHandle)>& fn, std::error_code* ec) {
  std::lock_guard<std::mutex> lock(mu_);
  const int rc = fn(fd_);
  Succeed(ec);
  return rc;
}

std::size_t Listener::session_count() const {
  std::lock_guard<std::mutex> lock(mu_);
  return sessions_.size();
}

void Listener::SetPacketTrace(UdpSession::PacketTrace trace) {
  if (!trace) {
    std::atomic_store(&packet_trace_, std::shared_ptr<const UdpSession::PacketTrace>());
    return;
  }
  std::atomic_store(&packet_trace_,
                    std::make_shared<const UdpSession::PacketTrace>(std::move(trace)));
}

void Listener::CloseSession(const platform::SocketAddress& remote) {
  std::lock_guard<std::mutex> lock(mu_);
  sessions_.erase(remote.ToString());
}

void Listener::NotifyReadError(int socket_errno) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (read_error_ != ErrorCode::kOk) {
      return;
    }
    read_error_ = ErrorCode::kSocketError;
    socket_error_code_.store(socket_errno, std::memory_order_relaxed);
  }
  accept_cv_.notify_all();

  // sess.go:1300-1312 - a dead listening socket is dead for every session on it.
  std::vector<std::shared_ptr<UdpSession>> sessions;
  {
    std::lock_guard<std::mutex> lock(mu_);
    sessions.reserve(sessions_.size());
    for (const auto& entry : sessions_) {
      sessions.push_back(entry.second);
    }
  }
  for (const auto& session : sessions) {
    session->NotifyReadError(socket_errno);
  }
}

// ---------------------------------------------------------------------------------------------
// Package-level constructors
// ---------------------------------------------------------------------------------------------

std::unique_ptr<Listener> Listen(const std::string& laddr, std::error_code* ec) {
  return ListenWithOptions(laddr, Crypt{}, 0, 0, ec);
}

std::unique_ptr<Listener> ListenWithOptions(const std::string& laddr, const Crypt& crypt,
                                            int data_shards, int parity_shards,
                                            std::error_code* ec) {
  return Listener::Create(laddr, crypt, data_shards, parity_shards, platform::kInvalidSocket, true,
                          ec);
}

std::unique_ptr<Listener> ServeConn(const Crypt& crypt, int data_shards, int parity_shards,
                                    platform::SocketHandle fd, std::error_code* ec) {
  return Listener::Create(std::string(), crypt, data_shards, parity_shards, fd, false, ec);
}

}  // namespace kcp
