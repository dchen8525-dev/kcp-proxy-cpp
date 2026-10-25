// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/udp_session.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#include "kcp/internal/byteorder.h"
#include "kcp/internal/clock.h"
#include "kcp/internal/frame.h"
#include "kcp/internal/primitives.h"
#include "kcp/internal/timedsched.h"
#include "kcp/listener.h"
#include "kcp/platform/entropy_backend.h"
#include "kcp/snmp.h"

namespace kcp {
namespace {

int Fail(std::error_code* ec, ErrorCode code) {
  if (ec != nullptr) {
    *ec = MakeErrorCode(code);
  }
  return -1;
}

void Succeed(std::error_code* ec) {
  if (ec != nullptr) {
    ec->clear();
  }
}

void Bump(std::atomic<std::uint64_t>& counter, std::uint64_t delta) {
  counter.fetch_add(delta, std::memory_order_relaxed);
}

std::uint32_t RandomConv() {
  std::uint32_t conv = 0;
  platform::FillRand(&conv, sizeof(conv));
  return conv;
}

}  // namespace

UdpSession::UdpSession(std::uint32_t conv, Crypt crypt, int data_shards, int parity_shards,
                       Listener* listener, platform::SocketHandle fd, bool own_conn,
                       const platform::SocketAddress& remote)
    : block_(std::move(crypt.block)),
      aead_(std::move(crypt.aead)),
      listener_(listener),
      fd_(fd),
      own_conn_(own_conn),
      remote_(remote),
      remote_text_(remote.ToString()) {
  enc_header_size_ = internal::CipherHeaderSize(block_.get(), aead_.get());
  aead_overhead_ = aead_ != nullptr ? aead_->overhead() : 0;

  // FEC encoder gets the *cipher* header size as its offset, so the layout is
  // [cipher header][FEC header 8][segment] (sess.go:220-226).
  fec_encoder_ =
      internal::FecEncoder::New(data_shards, parity_shards, static_cast<int>(enc_header_size_));
  fec_decoder_ = internal::FecDecoder::New(data_shards, parity_shards);
  header_size_ = enc_header_size_ + (fec_encoder_ != nullptr ? kFecHeaderSizePlus2 : 0);

  recv_buf_.assign(kMtuLimit, 0);

  kcp_ = std::make_unique<Kcp>(
      conv, [this](const std::uint8_t* buf, std::size_t size) { OnKcpOutput(buf, size); });

  // sess.go:248 - the construction path runs the same SetMtu contract as user code.
  SetMtu(kMtuDef);

  platform::SocketAddress local;
  if (platform::SysGetSockName(fd_, &local) == 0) {
    local_text_ = local.ToString();
  }
}

UdpSession::~UdpSession() {
  if (!closed_.load(std::memory_order_acquire)) {
    close(nullptr);
  }
  if (post_thread_.joinable()) {
    post_thread_.join();
  }
  if (read_thread_.joinable()) {
    read_thread_.join();
  }
}

std::shared_ptr<UdpSession> UdpSession::Create(std::uint32_t conv, Crypt crypt, int data_shards,
                                               int parity_shards, Listener* listener,
                                               platform::SocketHandle fd, bool own_conn,
                                               const platform::SocketAddress& remote) {
  std::shared_ptr<UdpSession> session(new UdpSession(
      conv, std::move(crypt), data_shards, parity_shards, listener, fd, own_conn, remote));
  session->Start();
  return session;
}

void UdpSession::Start() {
  post_thread_ = std::thread([this] { PostProcess(); });

  if (listener_ == nullptr) {
    read_thread_ = std::thread([this] { ReadLoop(); });
    Bump(DefaultSnmp().active_opens, 1);
  } else {
    Bump(DefaultSnmp().passive_opens, 1);
  }

  const std::uint64_t current = DefaultSnmp().curr_estab.fetch_add(1) + 1;
  std::uint64_t max_conn = DefaultSnmp().max_conn.load();
  while (current > max_conn && !DefaultSnmp().max_conn.compare_exchange_weak(max_conn, current)) {
  }

  ScheduleUpdate();
}

void UdpSession::ScheduleUpdate() {
  std::weak_ptr<UdpSession> weak = weak_from_this();
  if (weak.expired()) {
    return;
  }
  internal::TimedSched::Default().Put(
      [weak] {
        if (auto self = weak.lock()) {
          self->Update();
        }
      },
      std::chrono::steady_clock::now());
}

// ---------------------------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------------------------

void UdpSession::Update() {
  if (closed_.load(std::memory_order_acquire)) {
    return;
  }
  // TimedSched is one shared thread, so this session's share is charged per callback rather than
  // by measuring the thread (P8.0). The flush that Update triggers on this session's behalf counts
  // as this session's cost, which is exactly what the decomposition needs.
  platform::CpuScope cpu(profiling_.load(std::memory_order_relaxed) ? &update_cpu_us_ : nullptr);

  std::chrono::steady_clock::time_point when;
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_.load(std::memory_order_acquire)) {
      return;
    }
    // sess.go:803-816: the reference's update loop calls flush(FULL) unconditionally on every
    // callback and re-arms itself with the returned nextUpdate = min(resendts - now, interval).
    // Going through Update()+Check() instead quantizes every timer-driven event (RTO retransmit,
    // dead_link, probes) to the next ts_flush tick: Check() wakes at resendts, Update() no-ops
    // because ts_flush is not due, and the loop spins at 1 ms until the tick boundary.
    const std::uint32_t interval = kcp_->Flush(kFlushFull);
    if (kcp_->wait_snd() < static_cast<int>(kcp_->snd_wnd())) {
      write_cv_.notify_one();
    }
    // Clamp to 1 ms: flush returns at least 1 here (interval >= 10, resend diffs are > 0 when
    // they lower it), but a zero delay must never turn the scheduler into a spin loop.
    when =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(interval > 0 ? interval : 1);
  }

  if (closed_.load(std::memory_order_acquire)) {
    return;
  }
  std::weak_ptr<UdpSession> weak = weak_from_this();
  internal::TimedSched::Default().Put(
      [weak] {
        if (auto self = weak.lock()) {
          self->Update();
        }
      },
      when);
}

// ---------------------------------------------------------------------------------------------
// Outgoing pipeline: Kcp output -> FEC -> encrypt -> socket
// ---------------------------------------------------------------------------------------------

void UdpSession::OnKcpOutput(const std::uint8_t* buf, std::size_t size) {
  // sess.go:230 - datagrams below one segment are impossible and would corrupt the FEC seqid
  // stream, so they are dropped here rather than downstream.
  if (size < kOverhead) {
    return;
  }

  SendRequest request;
  const std::size_t total = header_size_ + size;
  // Sized for the tag up front: Seal writes it past the end of the plaintext, and a later
  // resize() that grew the vector would zero those bytes back out.
  request.buffer.assign(total + internal::kMaxAeadOverhead, 0);
  request.size = total;
  std::memcpy(request.buffer.data() + header_size_, buf, size);
  request.oob = false;

  // Full queue means drop, never block: the caller holds the session mutex and KCP will
  // retransmit (#38).
  post_processing_.TryPush(std::move(request));
}

void UdpSession::PostProcess() {
  platform::SetThreadCounters(&io_);
  std::vector<std::vector<std::uint8_t>> txqueue;
  txqueue.reserve(kMaxBatchSize + 16);
  std::size_t bytes_to_send = 0;
  SendRequest request;

  while (post_processing_.Pop(&request)) {
    // One scope per dequeued datagram. The pop itself blocks, but CPU time does not count a
    // blocked thread, so what lands here is the pipeline work: FEC, CRC, encrypt, Tx (P8.0).
    platform::CpuScope cpu(profiling_.load(std::memory_order_relaxed) ? &post_thread_cpu_us_
                                                                      : nullptr);
    std::vector<internal::FecPacket> parity;
    if (fec_encoder_ != nullptr) {
      if (request.oob) {
        fec_encoder_->EncodeOob(request.buffer.data(), request.size);
      } else {
        fec_encoder_->Encode(request.buffer.data(), request.size, kMaxFecEncodeLatencyMs, &parity);
      }
    }

    const std::size_t wire =
        internal::EncryptInPlace(block_.get(), aead_.get(), request.buffer.data(), request.size,
                                 request.buffer.size(), nullptr);
    if (wire == 0) {
      continue;
    }
    request.buffer.resize(wire);  // shrink only: the tag already sits in the allocation
    bytes_to_send += wire;
    txqueue.push_back(std::move(request.buffer));
    const std::size_t data_index = txqueue.size() - 1;

    // sess.go:752-758 - duplicated copies are of the sealed packet, so the peer sees identical
    // datagrams and KCP deduplicates them by sn.
    const int dup = dup_.load(std::memory_order_relaxed);
    for (int i = 0; i < dup; ++i) {
      txqueue.push_back(txqueue[data_index]);
      bytes_to_send += wire;
    }

    for (auto& packet : parity) {
      const std::size_t plain_size = packet.size();
      packet.resize(plain_size + aead_overhead_);
      const std::size_t sealed = internal::EncryptInPlace(block_.get(), aead_.get(), packet.data(),
                                                          plain_size, packet.size(), nullptr);
      packet.resize(sealed);
      bytes_to_send += sealed;
      txqueue.push_back(std::move(packet));
    }

    if (post_processing_.size() == 0 || txqueue.size() >= kMaxBatchSize) {
      std::shared_ptr<internal::RateLimiter> limiter;
      {
        std::lock_guard<std::mutex> lock(rate_mutex_);
        limiter = rate_limiter_;
      }
      if (limiter != nullptr) {
        limiter->Acquire(bytes_to_send);
      }
      Tx(txqueue);
      txqueue.clear();
      bytes_to_send = 0;
    }
  }

  // Drained by close(): anything still batched must still hit the wire.
  if (!txqueue.empty()) {
    Tx(txqueue);
  }
}

void UdpSession::Tx(const std::vector<std::vector<std::uint8_t>>& packets) {
  const std::shared_ptr<const PacketTrace> trace = std::atomic_load(&packet_trace_);
  std::uint64_t bytes = 0;
  std::uint64_t count = 0;
  for (const auto& packet : packets) {
    if (trace != nullptr) {
      (*trace)(true, packet.data(), packet.size());
    }
    const int sent = platform::SysSendTo(fd_, packet.data(), packet.size(), remote_);
    if (sent < 0) {
      NotifyWriteError(platform::LastError());
      break;
    }
    bytes += static_cast<std::uint64_t>(sent);
    ++count;
  }
  Bump(DefaultSnmp().out_pkts, count);
  Bump(DefaultSnmp().out_bytes, bytes);
}

// ---------------------------------------------------------------------------------------------
// Incoming pipeline: socket -> decrypt -> CRC/tag -> FEC -> Kcp
// ---------------------------------------------------------------------------------------------

void UdpSession::ReadLoop() {
  platform::SetThreadCounters(&io_);
  std::vector<std::uint8_t> buffer(kMtuLimit);
  while (!closed_.load(std::memory_order_acquire)) {
    // One scope per burst: the bounded wait inside is idle time and does not count as CPU, so this
    // ends up being the receive pipeline itself - recvfrom, decrypt, CRC, FEC, Kcp::Input.
    platform::CpuScope cpu(profiling_.load(std::memory_order_relaxed) ? &read_thread_cpu_us_
                                                                      : nullptr);
    // Bounded wait instead of an unbounded recvfrom: shutdown() does not reliably wake a blocked
    // reader on POSIX and closing a descriptor under a blocked reader is undefined.
    const int ready = platform::SysWaitReadable(fd_, 50);
    if (ready < 0) {
      NotifyReadError(platform::LastError());
      return;
    }
    if (ready == 0) {
      continue;
    }

    // Drain what the kernel already queued before waiting again. A wake costs an OS scheduling
    // round trip (~100us on Windows), which dwarfs the per-datagram work, so one select per burst
    // instead of one per datagram is the difference between 12 MB/s and the socket's capacity.
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
        // Same policy as the listener's monitor: a lost datagram is not a dead socket, and KCP
        // retransmits anything that mattered (readloop.go:47-70).
        Bump(DefaultSnmp().in_errs, 1);
        break;
      }
      if (closed_.load(std::memory_order_acquire)) {
        return;
      }

      // A client socket only talks to the address it dialled (readloop.go:47-70).
      if (from != remote_) {
        Bump(DefaultSnmp().in_errs, 1);
      } else {
        if (const auto trace = std::atomic_load(&packet_trace_)) {
          (*trace)(false, buffer.data(), static_cast<std::size_t>(got));
        }
        PacketInput(buffer.data(), static_cast<std::size_t>(got));
      }

      // Nothing else pending: go back to the blocking wait instead of spinning on select(0).
      if (platform::SysWaitReadable(fd_, 0) != 1) {
        break;
      }
    }
  }
}

void UdpSession::PacketInput(std::uint8_t* data, std::size_t len) {
  switch (internal::OpenInPlace(block_.get(), aead_.get(), &data, &len)) {
    case internal::OpenResult::kDropped:
      return;
    case internal::OpenResult::kIntegrityFailed:
      Bump(DefaultSnmp().in_csum_errors, 1);
      return;
    case internal::OpenResult::kOk:
      break;
  }

  // sess.go:1016 - min(IKCP_OVERHEAD, fecHeaderSizePlus2 + convSize) = 12: an OOB packet may be
  // much shorter than a KCP segment.
  if (len < std::min(kOverhead, kFecHeaderSizePlus2 + kConvSize)) {
    Bump(DefaultSnmp().kcp_in_errors, 1);
    return;
  }

  KcpInput(data, len);
}

void UdpSession::KcpInput(std::uint8_t* data, std::size_t len) {
  Bump(DefaultSnmp().in_pkts, 1);
  Bump(DefaultSnmp().in_bytes, len);

  // 16-bit demultiplexing field: KCP commands are 81..84 and frg is a byte, so neither can collide
  // with 0x00f1/0x00f2/0x00f3 (sess.go:1049-1052).
  const std::uint16_t fec_flag = internal::ReadLe16(data + 4);
  switch (fec_flag) {
    case kTypeData:
    case kTypeParity: {
      if (len < kFecHeaderSizePlus2) {
        Bump(DefaultSnmp().in_errs, 1);
        return;
      }

      std::uint64_t kcp_in_errors = 0;
      std::lock_guard<std::mutex> lock(mu_);

      // Lazy default: a peer that started using FEC after the handshake gets a 1/1 decoder.
      if (fec_decoder_ == nullptr) {
        fec_decoder_ = internal::FecDecoder::New(1, 1);
      }

      if (fec_flag == kTypeData) {
        if (kcp_->Input(data + kFecHeaderSizePlus2, len - kFecHeaderSizePlus2, PacketType::kRegular,
                        ack_nodelay_) != 0) {
          ++kcp_in_errors;
        }
      }

      const std::vector<internal::FecPacket> recovered = fec_decoder_->Decode(data, len);
      for (const auto& shard : recovered) {
        if (shard.size() >= 2) {
          const std::uint16_t size = internal::ReadLe16(shard.data());
          if (size >= 2 && size <= shard.size()) {
            if (kcp_->Input(shard.data() + 2, size - 2, PacketType::kFec, ack_nodelay_) != 0) {
              ++kcp_in_errors;
            }
          }
        }
      }

      if (kcp_->PeekSize() > 0) {
        read_cv_.notify_one();
      }
      if (kcp_->wait_snd() < static_cast<int>(kcp_->snd_wnd())) {
        write_cv_.notify_one();
      }
      if (kcp_in_errors > 0) {
        Bump(DefaultSnmp().kcp_in_errors, kcp_in_errors);
      }
      return;
    }
    case kTypeOob: {
      Bump(DefaultSnmp().oob_packets, 1);
      OobCallback callback;
      {
        std::lock_guard<std::mutex> lock(oob_mutex_);
        callback = oob_callback_;
      }
      // Layout: [FEC header 8][conv 4][payload]. No session lock is held here, so a handler may
      // read session state - but it still must not block or call close() (sess.go:845-848).
      if (callback) {
        callback(data + kFecHeaderSizePlus2 + kConvSize, len - kFecHeaderSizePlus2 - kConvSize);
      }
      return;
    }
    default: {
      std::lock_guard<std::mutex> lock(mu_);
      if (kcp_->Input(data, len, PacketType::kRegular, ack_nodelay_) != 0) {
        Bump(DefaultSnmp().kcp_in_errors, 1);
      }
      if (kcp_->PeekSize() > 0) {
        read_cv_.notify_one();
      }
      if (kcp_->wait_snd() < static_cast<int>(kcp_->snd_wnd())) {
        write_cv_.notify_one();
      }
      return;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Read / write
// ---------------------------------------------------------------------------------------------

int UdpSession::read(void* buf, std::size_t len, std::error_code* ec) {
  const bool profiling = profiling_.load(std::memory_order_relaxed);
  platform::CpuScope cpu(profiling ? &read_cpu_us_ : nullptr);
  if (profiling) {
    read_calls_.fetch_add(1, std::memory_order_relaxed);
  }
  auto* out = static_cast<std::uint8_t*>(buf);
  std::unique_lock<std::mutex> lock(mu_);

  for (;;) {
    // 1. Leftover from a previous short read: hand it out before touching KCP again (§3.6).
    if (buf_ptr_len_ > 0) {
      const std::size_t n = std::min(len, buf_ptr_len_);
      std::memcpy(out, recv_buf_.data() + buf_ptr_offset_, n);
      buf_ptr_offset_ += n;
      buf_ptr_len_ -= n;
      Bump(DefaultSnmp().bytes_received, n);
      Succeed(ec);
      return static_cast<int>(n);
    }

    // 2. A whole message is ready.
    const int size = kcp_->PeekSize();
    if (size > 0) {
      if (len >= static_cast<std::size_t>(size)) {
        // The caller's buffer holds the message: read straight into it (the DMA path).
        kcp_->Recv(out, len);
        Bump(DefaultSnmp().bytes_received, static_cast<std::uint64_t>(size));
        Succeed(ec);
        return size;
      }

      // Buffer too small: park the message in recv_buf_ and copy what fits.
      if (recv_buf_.size() < static_cast<std::size_t>(size)) {
        recv_buf_.resize(static_cast<std::size_t>(size));
      }
      kcp_->Recv(recv_buf_.data(), recv_buf_.size());
      const std::size_t n = std::min(len, static_cast<std::size_t>(size));
      std::memcpy(out, recv_buf_.data(), n);
      buf_ptr_offset_ = n;
      buf_ptr_len_ = static_cast<std::size_t>(size) - n;
      Bump(DefaultSnmp().bytes_received, n);
      Succeed(ec);
      return static_cast<int>(n);
    }

    if (read_error_ != ErrorCode::kOk) {
      return Fail(ec, read_error_);
    }
    if (closed_.load(std::memory_order_acquire)) {
      return Fail(ec, ErrorCode::kClosedPipe);
    }
    if (Expired(read_deadline_)) {
      return Fail(ec, ErrorCode::kTimeout);
    }

    if (read_deadline_ == Deadline{}) {
      read_cv_.wait(lock);
    } else {
      read_cv_.wait_until(lock, read_deadline_);
    }
  }
}

int UdpSession::write(const void* data, std::size_t len, std::error_code* ec) {
  return write_buffers({ConstBuffer{data, len}}, ec);
}

int UdpSession::write_buffers(const std::vector<ConstBuffer>& bufs, std::error_code* ec) {
  const bool profiling = profiling_.load(std::memory_order_relaxed);
  platform::CpuScope cpu(profiling ? &write_cpu_us_ : nullptr);
  if (profiling) {
    write_calls_.fetch_add(1, std::memory_order_relaxed);
  }
  // The return type is int, so a batch larger than INT_MAX can never be reported back to the
  // caller. Refuse it up front instead of summing into an int: signed overflow is UB, and the
  // wrapped-negative total would masquerade as a successful byte count (upstream kcp-go writes
  // with a 64-bit int and would accept the batch, but no KCP message of that size is deliverable
  // over UDP anyway, so the deterministic refusal is the safe port). The check touches lengths
  // only - no buffer is dereferenced - so nothing is queued and the session stays usable.
  std::size_t total = 0;
  for (const auto& view : bufs) {
    total += view.len;
    if (total > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
      return Fail(ec, ErrorCode::kInvalidArgument);
    }
  }
  std::unique_lock<std::mutex> lock(mu_);

  for (;;) {
    if (write_error_ != ErrorCode::kOk) {
      return Fail(ec, write_error_);
    }
    if (closed_.load(std::memory_order_acquire)) {
      return Fail(ec, ErrorCode::kClosedPipe);
    }

    // The send window is the flow-control valve: block until the peer acknowledges enough
    // (sess.go:390-425).
    if (kcp_->wait_snd() < static_cast<int>(kcp_->snd_wnd())) {
      const std::size_t mss = kcp_->mss();
      // `total` was summed (and range-checked) before the lock; the send loop only consumes.
      for (const auto& view : bufs) {
        const auto* cursor = static_cast<const std::uint8_t*>(view.data);
        std::size_t left = view.len;
        while (left > 0) {
          const std::size_t chunk = std::min(left, mss);
          kcp_->Send(cursor, chunk);
          cursor += chunk;
          left -= chunk;
        }
      }

      const int after = kcp_->wait_snd();
      if (after >= static_cast<int>(kcp_->snd_wnd()) || !write_delay_) {
        // Flush immediately unless the caller asked for tick-level batching (#39).
        kcp_->Flush(kFlushFull);
      }
      Bump(DefaultSnmp().bytes_sent, static_cast<std::uint64_t>(total));
      Succeed(ec);
      return static_cast<int>(total);
    }

    if (Expired(write_deadline_)) {
      return Fail(ec, ErrorCode::kTimeout);
    }

    if (write_deadline_ == Deadline{}) {
      write_cv_.wait(lock);
    } else {
      write_cv_.wait_until(lock, write_deadline_);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------------

void UdpSession::close(std::error_code* ec) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_.load(std::memory_order_acquire)) {
      if (ec != nullptr) {
        *ec = MakeErrorCode(ErrorCode::kClosedPipe);
      }
      return;
    }
    closed_.store(true, std::memory_order_release);
    read_cv_.notify_all();
    write_cv_.notify_all();
  }

  DefaultSnmp().curr_estab.fetch_sub(1);
  // Cancel the token bucket before anything else can sleep in it: the post thread may already be
  // parked inside Acquire waiting for up to burst/rate seconds, and close() joins that thread -
  // as does the listener's single monitor thread on the stale-conv reset path.
  {
    std::shared_ptr<internal::RateLimiter> limiter;
    {
      std::lock_guard<std::mutex> lock(rate_mutex_);
      limiter = std::move(rate_limiter_);
    }
    if (limiter != nullptr) {
      limiter->Close();
    }
  }
  // Best effort: push whatever KCP still holds. The queue is still open, so the tail is encoded
  // and sent instead of being lost (§3.1 item 2).
  {
    std::lock_guard<std::mutex> lock(mu_);
    kcp_->Flush(kFlushFull);
  }
  post_processing_.Close();

  const auto self = std::this_thread::get_id();
  if (post_thread_.joinable() && post_thread_.get_id() != self) {
    post_thread_.join();
  }
  if (read_thread_.joinable() && read_thread_.get_id() != self) {
    read_thread_.join();
  }

  // mu_ pairs with Control()/SetDscp()/Set{Read,Write}Buffer(), which read fd_ under the same
  // mutex; writing it here without the lock is a data race and lets a concurrent callback run on
  // a closed (possibly reused) handle.
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (own_conn_ && fd_ != platform::kInvalidSocket) {
      platform::SysClose(fd_);
      fd_ = platform::kInvalidSocket;
    }
  }

  if (listener_ != nullptr) {
    listener_->CloseSession(remote_, this);
  }

  Succeed(ec);
}

// ---------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------

void UdpSession::SetDeadline(Deadline deadline) {
  SetReadDeadline(deadline);
  SetWriteDeadline(deadline);
}

void UdpSession::SetReadDeadline(Deadline deadline) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    read_deadline_ = deadline;
  }
  read_cv_.notify_all();
}

void UdpSession::SetWriteDeadline(Deadline deadline) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    write_deadline_ = deadline;
  }
  write_cv_.notify_all();
}

void UdpSession::SetWriteDelay(bool delay) {
  std::lock_guard<std::mutex> lock(mu_);
  write_delay_ = delay;
}

void UdpSession::SetWindowSize(int sndwnd, int rcvwnd) {
  std::lock_guard<std::mutex> lock(mu_);
  kcp_->WndSize(sndwnd, rcvwnd);
}

bool UdpSession::SetMtu(int mtu) {
  // §3.7: clamp to the ethernet limit, then subtract everything the session prepends - the cipher
  // header, the FEC header, and (for AEAD) the tag that is appended.
  int value = std::min(static_cast<int>(kMtuLimit), mtu);
  value -= static_cast<int>(header_size_);
  value -= static_cast<int>(aead_overhead_);

  std::lock_guard<std::mutex> lock(mu_);
  return kcp_->SetMtu(value) == 0;
}

void UdpSession::SetStreamMode(bool enable) {
  std::lock_guard<std::mutex> lock(mu_);
  kcp_->SetStreamMode(enable);
}

void UdpSession::SetAckNoDelay(bool nodelay) {
  std::lock_guard<std::mutex> lock(mu_);
  ack_nodelay_ = nodelay;
}

void UdpSession::SetDup(int dup) { dup_.store(dup, std::memory_order_relaxed); }

void UdpSession::SetNoDelay(int nodelay, int interval, int resend, int nc) {
  std::lock_guard<std::mutex> lock(mu_);
  kcp_->NoDelay(nodelay, interval, resend, nc);
}

ErrorCode UdpSession::SetDscp(int dscp) {
  std::lock_guard<std::mutex> lock(mu_);
  if (listener_ != nullptr) {
    return ErrorCode::kInvalidOperation;
  }
  return platform::SysSetDscp(fd_, dscp) == 0 ? ErrorCode::kOk : ErrorCode::kInvalidOperation;
}

ErrorCode UdpSession::SetReadBuffer(int bytes) {
  std::lock_guard<std::mutex> lock(mu_);
  if (listener_ != nullptr) {
    return ErrorCode::kInvalidOperation;
  }
  return platform::SysSetRecvBuffer(fd_, bytes) == 0 ? ErrorCode::kOk : ErrorCode::kSocketError;
}

ErrorCode UdpSession::SetWriteBuffer(int bytes) {
  std::lock_guard<std::mutex> lock(mu_);
  if (listener_ != nullptr) {
    return ErrorCode::kInvalidOperation;
  }
  return platform::SysSetSendBuffer(fd_, bytes) == 0 ? ErrorCode::kOk : ErrorCode::kSocketError;
}

void UdpSession::SetRateLimit(std::uint32_t bytes_per_second) {
  auto limiter = std::make_shared<internal::RateLimiter>(bytes_per_second);
  std::lock_guard<std::mutex> lock(rate_mutex_);
  rate_limiter_ = std::move(limiter);
}

void UdpSession::SetLogger(std::uint32_t mask, LogCallback logger) {
  std::lock_guard<std::mutex> lock(mu_);
  kcp_->SetLogger(mask, std::move(logger));
}

void UdpSession::SetPacketTrace(PacketTrace trace) {
  // atomic_load/atomic_store rather than mu_: the two I/O loops must be able to snapshot the
  // callback without serialising on a mutex the caller may be holding.
  if (!trace) {
    std::atomic_store(&packet_trace_, std::shared_ptr<const PacketTrace>());
    return;
  }
  std::atomic_store(&packet_trace_, std::make_shared<const PacketTrace>(std::move(trace)));
}

void UdpSession::EnableProfiling() {
  io_.enabled.store(true, std::memory_order_relaxed);
  profiling_.store(true, std::memory_order_relaxed);
}

SessionProfile UdpSession::profile() const {
  SessionProfile out;
  out.read_thread_cpu_us = read_thread_cpu_us_.load(std::memory_order_relaxed);
  out.post_thread_cpu_us = post_thread_cpu_us_.load(std::memory_order_relaxed);
  out.update_cpu_us = update_cpu_us_.load(std::memory_order_relaxed);
  out.write_cpu_us = write_cpu_us_.load(std::memory_order_relaxed);
  out.write_calls = write_calls_.load(std::memory_order_relaxed);
  out.read_cpu_us = read_cpu_us_.load(std::memory_order_relaxed);
  out.read_calls = read_calls_.load(std::memory_order_relaxed);
  out.tx_n = io_.send_n.load(std::memory_order_relaxed);
  out.tx_us = io_.send_us.load(std::memory_order_relaxed);
  out.tx_err = io_.send_err.load(std::memory_order_relaxed);
  out.rx_n = io_.recv_n.load(std::memory_order_relaxed);
  out.rx_us = io_.recv_us.load(std::memory_order_relaxed);
  out.rx_err = io_.recv_err.load(std::memory_order_relaxed);
  out.probe_n = io_.probe_n.load(std::memory_order_relaxed);
  out.probe_us = io_.probe_us.load(std::memory_order_relaxed);
  out.wait_n = io_.wait_n.load(std::memory_order_relaxed);
  out.wait_us = io_.wait_us.load(std::memory_order_relaxed);
  return out;
}

std::uint32_t UdpSession::conv() const {
  std::lock_guard<std::mutex> lock(mu_);
  return kcp_->conv();
}

std::uint32_t UdpSession::rto() const {
  std::lock_guard<std::mutex> lock(mu_);
  return kcp_->rto();
}

std::int32_t UdpSession::srtt() const {
  std::lock_guard<std::mutex> lock(mu_);
  return kcp_->srtt();
}

bool UdpSession::IsDead() const {
  std::lock_guard<std::mutex> lock(mu_);
  return kcp_->IsDead();
}

std::int32_t UdpSession::srtt_var() const {
  std::lock_guard<std::mutex> lock(mu_);
  return kcp_->srtt_var();
}

// ---------------------------------------------------------------------------------------------
// Out-of-band data
// ---------------------------------------------------------------------------------------------

ErrorCode UdpSession::SetOobHandler(OobCallback callback) {
  if (fec_encoder_ == nullptr) {
    return ErrorCode::kOobRequiresFec;
  }
  std::lock_guard<std::mutex> lock(oob_mutex_);
  oob_callback_ = std::move(callback);
  return ErrorCode::kOk;
}

int UdpSession::oob_max_size() const {
  if (fec_encoder_ == nullptr) {
    return 0;
  }
  std::lock_guard<std::mutex> lock(mu_);
  return static_cast<int>(kcp_->mtu()) - static_cast<int>(kConvSize);
}

ErrorCode UdpSession::SendOob(const std::uint8_t* data, std::size_t len) {
  if (fec_encoder_ == nullptr) {
    return ErrorCode::kOobRequiresFec;
  }

  std::lock_guard<std::mutex> lock(mu_);
  const std::size_t size = kConvSize + len;
  if (size > kcp_->mtu()) {
    return ErrorCode::kOobTooLarge;
  }

  SendRequest request;
  const std::size_t total = header_size_ + size;
  request.buffer.assign(total + internal::kMaxAeadOverhead, 0);
  request.size = total;
  internal::WriteLe32(request.buffer.data() + header_size_, kcp_->conv());
  if (len > 0) {
    std::memcpy(request.buffer.data() + header_size_ + kConvSize, data, len);
  }
  request.oob = true;

  if (post_processing_.TryPush(std::move(request))) {
    return ErrorCode::kOk;
  }
  if (closed_.load(std::memory_order_acquire)) {
    return ErrorCode::kClosedPipe;
  }
  // Queue full: OOB is best effort by design, so the packet is dropped without an error.
  return ErrorCode::kOk;
}

int UdpSession::Control(const std::function<int(platform::SocketHandle)>& fn, std::error_code* ec) {
  if (!own_conn_) {
    return Fail(ec, ErrorCode::kInvalidOperation);
  }
  std::lock_guard<std::mutex> lock(mu_);
  // The callback receives a raw handle, not a wrapped conn like Go's net.PacketConn; once close()
  // has run, the handle value may already be reused by the OS for another socket, so it must not
  // be handed out. Go surfaces this as "use of closed network connection" from the conn method.
  if (closed_.load(std::memory_order_acquire) || fd_ == platform::kInvalidSocket) {
    return Fail(ec, ErrorCode::kClosedPipe);
  }
  const int rc = fn(fd_);
  Succeed(ec);
  return rc;
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

void UdpSession::NotifyReadError(int socket_errno) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (read_error_ != ErrorCode::kOk) {
      return;
    }
    read_error_ = ErrorCode::kSocketError;
    socket_error_code_.store(socket_errno, std::memory_order_relaxed);
  }
  read_cv_.notify_all();
}

void UdpSession::NotifyWriteError(int socket_errno) {
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (write_error_ != ErrorCode::kOk) {
      return;
    }
    write_error_ = ErrorCode::kSocketError;
    socket_error_code_.store(socket_errno, std::memory_order_relaxed);
  }
  write_cv_.notify_all();
}

bool UdpSession::Expired(Deadline deadline) {
  return deadline != Deadline{} && std::chrono::steady_clock::now() >= deadline;
}

// ---------------------------------------------------------------------------------------------
// Package-level constructors
// ---------------------------------------------------------------------------------------------

namespace {

bool OpenClientSocket(platform::SocketHandle* fd, std::error_code* ec) {
  const platform::SocketHandle handle = platform::SysSocketUdp();
  if (handle == platform::kInvalidSocket) {
    if (ec != nullptr) {
      *ec = MakeErrorCode(ErrorCode::kSocketError);
    }
    return false;
  }
  platform::SocketAddress any;
  platform::SocketAddress::Parse("0.0.0.0", 0, &any);
  if (platform::SysBind(handle, any) != 0) {
    platform::SysClose(handle);
    if (ec != nullptr) {
      *ec = MakeErrorCode(ErrorCode::kSocketError);
    }
    return false;
  }
  *fd = handle;
  return true;
}

bool ResolveRemote(const std::string& raddr, platform::SocketAddress* out, std::error_code* ec) {
  if (!platform::SocketAddress::ParseHostPort(raddr, out)) {
    if (ec != nullptr) {
      *ec = MakeErrorCode(ErrorCode::kInvalidArgument);
    }
    return false;
  }
  return true;
}

}  // namespace

std::shared_ptr<UdpSession> Dial(const std::string& raddr, std::error_code* ec) {
  return DialWithOptions(raddr, Crypt{}, 0, 0, ec);
}

std::shared_ptr<UdpSession> DialWithOptions(const std::string& raddr, const Crypt& crypt,
                                            int data_shards, int parity_shards,
                                            std::error_code* ec) {
  platform::SocketAddress remote;
  if (!ResolveRemote(raddr, &remote, ec)) {
    return nullptr;
  }
  platform::SocketHandle fd = platform::kInvalidSocket;
  if (!OpenClientSocket(&fd, ec)) {
    return nullptr;
  }
  if (ec != nullptr) {
    ec->clear();
  }
  return UdpSession::Create(RandomConv(), crypt, data_shards, parity_shards, nullptr, fd, true,
                            remote);
}

std::shared_ptr<UdpSession> NewConn4(std::uint32_t conv, const std::string& raddr,
                                     const Crypt& crypt, int data_shards, int parity_shards,
                                     bool own_conn, platform::SocketHandle fd,
                                     std::error_code* ec) {
  platform::SocketAddress remote;
  if (!ResolveRemote(raddr, &remote, ec)) {
    return nullptr;
  }
  if (ec != nullptr) {
    ec->clear();
  }
  return UdpSession::Create(conv, crypt, data_shards, parity_shards, nullptr, fd, own_conn, remote);
}

std::shared_ptr<UdpSession> NewConn3(std::uint32_t conv, const std::string& raddr,
                                     const Crypt& crypt, int data_shards, int parity_shards,
                                     platform::SocketHandle fd, std::error_code* ec) {
  return NewConn4(conv, raddr, crypt, data_shards, parity_shards, false, fd, ec);
}

std::shared_ptr<UdpSession> NewConn2(const std::string& raddr, const Crypt& crypt, int data_shards,
                                     int parity_shards, platform::SocketHandle fd,
                                     std::error_code* ec) {
  return NewConn3(RandomConv(), raddr, crypt, data_shards, parity_shards, fd, ec);
}

std::shared_ptr<UdpSession> NewConn(const std::string& raddr, const Crypt& crypt, int data_shards,
                                    int parity_shards, platform::SocketHandle fd,
                                    std::error_code* ec) {
  return NewConn2(raddr, crypt, data_shards, parity_shards, fd, ec);
}

}  // namespace kcp
