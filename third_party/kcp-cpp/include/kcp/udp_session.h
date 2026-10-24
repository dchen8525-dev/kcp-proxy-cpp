// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_UDP_SESSION_H_
#define KCP_UDP_SESSION_H_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "kcp/crypt.h"
#include "kcp/error.h"
#include "kcp/internal/blocking_queue.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/fec.h"
#include "kcp/internal/rate_limiter.h"
#include "kcp/kcp.h"
#include "kcp/platform/profile.h"
#include "kcp/platform/socket.h"

namespace kcp {

class Listener;
class UdpSession;

// Non-owning view of one buffer for write_buffers(), mirroring Go's [][]byte.
struct ConstBuffer {
  const void* data = nullptr;
  std::size_t len = 0;
};

// Cumulative cost accounting for one session (PORTING-PLAN.md P8.0). Two different clocks are kept
// apart on purpose:
//
//   *_cpu_us       CPU time, from GetThreadTimes / CLOCK_THREAD_CPUTIME_ID
//   tx_us/rx_us    wall time spent inside the syscall, from two clock reads around it
//
// The split is what makes the difference between "burned a core" and "waited" visible: sendto()
// spends only half of its 44 us on CPU on Windows, and no CPU-time meter would ever show that.
//
// Thread attribution: the read and post threads are owned by the session, so their buckets are
// whole-thread totals. Update() runs on the shared TimedSched thread, so it is charged per call
// instead. A session owned by a Listener reads on the listener's monitor thread, which this object
// cannot see: read_thread_cpu_us stays 0 there, and so do the rx counters.
struct SessionProfile {
  std::uint64_t read_thread_cpu_us = 0;  // ReadLoop: wait + recvfrom + decrypt + Kcp::Input
  std::uint64_t post_thread_cpu_us = 0;  // PostProcess: FEC + CRC + encrypt + Tx
  std::uint64_t update_cpu_us = 0;       // Update() callbacks, including the flush they trigger
  std::uint64_t write_cpu_us = 0;        // inside write()/write_buffers(), on the calling thread
  std::uint64_t write_calls = 0;
  std::uint64_t read_cpu_us = 0;  // inside read(), on the calling thread
  std::uint64_t read_calls = 0;

  std::uint64_t tx_n = 0;  // SysSendTo calls (one per datagram, including duplicates and parity)
  std::uint64_t tx_us = 0;
  std::uint64_t tx_err = 0;
  std::uint64_t rx_n = 0;  // SysRecvFrom calls (including the ones that found nothing)
  std::uint64_t rx_us = 0;
  std::uint64_t rx_err = 0;
  std::uint64_t probe_n = 0;  // SysWaitReadable(fd, 0): the per-datagram readiness probe
  std::uint64_t probe_us = 0;
  std::uint64_t wait_n = 0;  // SysWaitReadable(fd, 50 ms): idle unless the loop is saturated
  std::uint64_t wait_us = 0;
};

// Deadlines are monotonic, because a wall-clock jump would otherwise turn a 100 ms timeout into an
// immediate failure or an indefinite wait. A default-constructed value means "no deadline", the
// same convention as Go's zero time.Time (sess.go:497).
using Deadline = std::chrono::steady_clock::time_point;

// A session's cipher: exactly one field is set. Go has a single BlockCrypt interface whose
// Encrypt/Decrypt panic for AEAD instances; splitting it makes that mistake a compile error.
struct Crypt {
  std::shared_ptr<BlockCrypt> block;
  std::shared_ptr<AeadCrypt> aead;
};

// One KCP session over UDP: reliable stream framing (Kcp) plus the packet pipeline from sess.go.
//
//   out: Kcp output -> FEC -> CRC/nonce -> encrypt -> tx queue -> socket
//   in : socket -> decrypt -> CRC/tag -> FEC -> Kcp input
//
// Threading: read()/write() block, every setter may be called concurrently, and close() may be
// called from any thread except a session callback (OOB handler). See PORTING-PLAN.md §3.2 for the
// lock order (L3 Listener -> L2 session).
class UdpSession : public std::enable_shared_from_this<UdpSession> {
 public:
  // OOB payload delivery. Invoked synchronously from the read thread with the session mutex
  // released; it must return quickly and must not block (sess.go:845-848).
  using OobCallback = std::function<void(const std::uint8_t* data, std::size_t len)>;

  ~UdpSession();

  UdpSession(const UdpSession&) = delete;
  UdpSession& operator=(const UdpSession&) = delete;

  // ---- I/O -----------------------------------------------------------------------------------

  // Reads one KCP message, or the remainder of one. Returns the number of bytes copied, which may
  // be less than `len` (message bounds are preserved, §3.6), or -1 with *ec set.
  int read(void* buf, std::size_t len, std::error_code* ec = nullptr);

  // Queues `len` bytes and flushes unless write delay is enabled. Returns the accepted byte count
  // or -1 with *ec set. A request over INT_MAX bytes is refused with kInvalidArgument: the int
  // return type cannot report it, and nothing is queued when it happens.
  int write(const void* data, std::size_t len, std::error_code* ec = nullptr);

  // Vector form of write(); sizes are split by mss exactly like a single buffer. The batch total
  // is validated against INT_MAX before anything is queued.
  int write_buffers(const std::vector<ConstBuffer>& bufs, std::error_code* ec = nullptr);

  // Idempotent, but a second call reports kClosedPipe (sess.go:470-472). Flushes the tail before
  // stopping the pipeline, then joins both worker threads.
  void close(std::error_code* ec = nullptr);

  bool is_closed() const { return closed_.load(std::memory_order_acquire); }

  std::string local_addr() const { return local_text_; }
  std::string remote_addr() const { return remote_text_; }

  // ---- deadlines -----------------------------------------------------------------------------

  void SetDeadline(Deadline deadline);
  void SetReadDeadline(Deadline deadline);
  void SetWriteDeadline(Deadline deadline);

  // ---- tuning --------------------------------------------------------------------------------

  void SetWriteDelay(bool delay);
  void SetWindowSize(int sndwnd, int rcvwnd);
  bool SetMtu(int mtu);
  void SetStreamMode(bool enable);
  void SetAckNoDelay(bool nodelay);
  void SetDup(int dup);
  void SetNoDelay(int nodelay, int interval, int resend, int nc);
  ErrorCode SetDscp(int dscp);
  ErrorCode SetReadBuffer(int bytes);
  ErrorCode SetWriteBuffer(int bytes);
  void SetRateLimit(std::uint32_t bytes_per_second);
  void SetLogger(std::uint32_t mask, LogCallback logger);

  // Diagnostic tap on the raw datagrams, for PORTING-PLAN.md §6.1 (locating a cross-language
  // mismatch by dumping the first packet and diffing it field by field). `outgoing` tells the
  // direction; `data`/`len` are the bytes exactly as they crossed the socket - already sealed when
  // outgoing, still sealed when incoming. Not part of the kcp-go API.
  //
  // The callback runs on the read and transmit threads, so it must be thread-safe. Pass an empty
  // function to remove it. Held behind atomic_load/atomic_store so setting it after the session
  // started is well defined, at the cost of one atomic load per datagram when it is set.
  using PacketTrace = std::function<void(bool outgoing, const std::uint8_t* data, std::size_t len)>;
  void SetPacketTrace(PacketTrace trace);

  // ---- introspection -------------------------------------------------------------------------

  // Turns on the accounting described by SessionProfile (PORTING-PLAN.md P8.0). Off by default:
  // while it is off the syscall wrappers pay one relaxed atomic load per datagram; while it is on
  // they pay two wall-clock reads (~21 ns each) and the worker loops pay two thread-clock reads
  // (~102 ns each, `bench/syscall_cost` CLOCK line).
  //
  // Enable before the traffic starts - the totals only cover the window it was on for. Read
  // profile() after close(), when both worker threads have been joined, for a snapshot that
  // is stable across all fields at once; a mid-flight read is race-free (every counter is
  // atomic) but the fields are sampled one at a time, so they need not describe the same
  // instant.
  void EnableProfiling();
  SessionProfile profile() const;

  std::uint32_t conv() const;
  std::uint32_t rto() const;
  std::int32_t srtt() const;
  std::int32_t srtt_var() const;
  int socket_error_code() const { return socket_error_code_; }

  // True once the underlying KCP connection hit dead_link (kcp.go:943). Go writes that state but
  // never reads it; the lossy-relay gate needs it to assert a 30% link does not kill the session.
  bool IsDead() const;

  // ---- out-of-band data (requires FEC) -------------------------------------------------------

  ErrorCode SetOobHandler(OobCallback callback);
  int oob_max_size() const;
  ErrorCode SendOob(const std::uint8_t* data, std::size_t len);

  // Runs `fn` against the underlying descriptor. Only valid for sockets the session owns.
  int Control(const std::function<int(platform::SocketHandle)>& fn, std::error_code* ec = nullptr);

 private:
  friend class Listener;
  // Package-level constructors are the only callers of Create(); they live in udp_session.cc and
  // exist so the session's private layout never leaks into the header's factory surface.
  friend std::shared_ptr<UdpSession> DialWithOptions(const std::string&, const Crypt&, int, int,
                                                     std::error_code*);
  friend std::shared_ptr<UdpSession> NewConn4(std::uint32_t, const std::string&, const Crypt&, int,
                                              int, bool, platform::SocketHandle, std::error_code*);

  // One datagram on its way into the pipeline: header space reserved at the front, payload already
  // copied in. `size` is the logical length and `buffer.size()` is the allocation, which is larger
  // by kMaxAeadOverhead so the AEAD tag can be written in place. Growing a vector after the tag
  // is written would zero it again, so the pipeline only ever shrinks `buffer`.
  struct SendRequest {
    std::vector<std::uint8_t> buffer;
    std::size_t size = 0;
    bool oob = false;
  };

  UdpSession(std::uint32_t conv, Crypt crypt, int data_shards, int parity_shards,
             Listener* listener, platform::SocketHandle fd, bool own_conn,
             const platform::SocketAddress& remote);

  // Wires the session up: starts PostProcess, the read loop for client sockets, and schedules the
  // first Update. Separate from the constructor because the timer needs a weak_ptr, which only
  // exists once the shared_ptr is built.
  void Start();

  static std::shared_ptr<UdpSession> Create(std::uint32_t conv, Crypt crypt, int data_shards,
                                            int parity_shards, Listener* listener,
                                            platform::SocketHandle fd, bool own_conn,
                                            const platform::SocketAddress& remote);

  // Kcp output callback. Runs with the session mutex held, so it never blocks: a full queue drops
  // the datagram and KCP retransmits it (#38).
  void OnKcpOutput(const std::uint8_t* buf, std::size_t size);

  void PostProcess();
  void ReadLoop();
  void Update();
  void PacketInput(std::uint8_t* data, std::size_t len);
  void KcpInput(std::uint8_t* data, std::size_t len);
  void Tx(const std::vector<std::vector<std::uint8_t>>& packets);

  void ScheduleUpdate();
  void NotifyReadError(int socket_errno);
  void NotifyWriteError(int socket_errno);
  static bool Expired(Deadline deadline);

  std::shared_ptr<BlockCrypt> block_;
  std::shared_ptr<AeadCrypt> aead_;
  std::unique_ptr<Kcp> kcp_;
  Listener* listener_ = nullptr;  // non-owning: the listener outlives its sessions
  platform::SocketHandle fd_ = platform::kInvalidSocket;
  bool own_conn_ = false;
  platform::SocketAddress remote_;
  std::string remote_text_;
  std::string local_text_;

  // Header accounting (§3.7): enc_header_size_ is what the cipher adds, header_size_ also counts
  // the 8-byte FEC header. SetMtu subtracts header_size_ and, for AEAD, the tag overhead.
  std::size_t enc_header_size_ = 0;
  std::size_t header_size_ = 0;
  std::size_t aead_overhead_ = 0;

  std::unique_ptr<internal::FecEncoder> fec_encoder_;
  std::unique_ptr<internal::FecDecoder> fec_decoder_;

  std::vector<std::uint8_t> recv_buf_;
  std::size_t buf_ptr_offset_ = 0;
  std::size_t buf_ptr_len_ = 0;

  std::atomic<bool> closed_{false};
  mutable std::mutex mu_;
  std::condition_variable read_cv_;
  std::condition_variable write_cv_;
  Deadline read_deadline_{};
  Deadline write_deadline_{};

  bool ack_nodelay_ = false;
  bool write_delay_ = false;
  std::atomic<int> dup_{0};

  ErrorCode read_error_ = ErrorCode::kOk;
  ErrorCode write_error_ = ErrorCode::kOk;
  std::atomic<int> socket_error_code_{0};

  internal::BlockingQueue<SendRequest> post_processing_{kDevBacklog};
  std::thread post_thread_;
  std::thread read_thread_;

  std::mutex rate_mutex_;
  std::shared_ptr<internal::RateLimiter> rate_limiter_;

  std::mutex oob_mutex_;
  OobCallback oob_callback_;

  // Read with atomic_load in the two I/O loops; see SetPacketTrace.
  std::shared_ptr<const PacketTrace> packet_trace_;

  // P8.0 accounting. `io_` is installed on both worker threads; each writes only its own half (the
  // post thread the send counters, the read thread the recv/probe/wait ones), so no two threads
  // touch the same field.
  platform::IoCounters io_;
  std::atomic<bool> profiling_{false};
  std::atomic<std::uint64_t> read_thread_cpu_us_{0};
  std::atomic<std::uint64_t> post_thread_cpu_us_{0};
  std::atomic<std::uint64_t> update_cpu_us_{0};
  std::atomic<std::uint64_t> write_cpu_us_{0};
  std::atomic<std::uint64_t> write_calls_{0};
  std::atomic<std::uint64_t> read_cpu_us_{0};
  std::atomic<std::uint64_t> read_calls_{0};
};

// ---- package-level constructors (sess.go:1430-1528) -------------------------------------------

std::shared_ptr<UdpSession> Dial(const std::string& raddr, std::error_code* ec = nullptr);
std::shared_ptr<UdpSession> DialWithOptions(const std::string& raddr, const Crypt& crypt,
                                            int data_shards, int parity_shards,
                                            std::error_code* ec = nullptr);
inline std::shared_ptr<UdpSession> DialWithOptions(const std::string& raddr,
                                                   std::shared_ptr<BlockCrypt> block,
                                                   int data_shards, int parity_shards,
                                                   std::error_code* ec = nullptr) {
  return DialWithOptions(raddr, Crypt{std::move(block), nullptr}, data_shards, parity_shards, ec);
}
inline std::shared_ptr<UdpSession> DialWithOptions(const std::string& raddr,
                                                   std::shared_ptr<AeadCrypt> aead, int data_shards,
                                                   int parity_shards,
                                                   std::error_code* ec = nullptr) {
  return DialWithOptions(raddr, Crypt{nullptr, std::move(aead)}, data_shards, parity_shards, ec);
}

// Adopts an existing descriptor instead of creating one (Go's net.PacketConn parameter).
std::shared_ptr<UdpSession> NewConn3(std::uint32_t conv, const std::string& raddr,
                                     const Crypt& crypt, int data_shards, int parity_shards,
                                     platform::SocketHandle fd, std::error_code* ec = nullptr);
std::shared_ptr<UdpSession> NewConn4(std::uint32_t conv, const std::string& raddr,
                                     const Crypt& crypt, int data_shards, int parity_shards,
                                     bool own_conn, platform::SocketHandle fd,
                                     std::error_code* ec = nullptr);
std::shared_ptr<UdpSession> NewConn2(const std::string& raddr, const Crypt& crypt, int data_shards,
                                     int parity_shards, platform::SocketHandle fd,
                                     std::error_code* ec = nullptr);
std::shared_ptr<UdpSession> NewConn(const std::string& raddr, const Crypt& crypt, int data_shards,
                                    int parity_shards, platform::SocketHandle fd,
                                    std::error_code* ec = nullptr);

}  // namespace kcp

#endif  // KCP_UDP_SESSION_H_
