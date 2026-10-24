// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_KCP_H_
#define KCP_KCP_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "kcp/internal/kcp_segment.h"
#include "kcp/internal/ringbuffer.h"

namespace kcp {

// Which side of the FEC split a received packet came from (kcp.go:66-70). Only regular packets
// are trusted for the remote window: a parity shard carries a stale wnd snapshot, so honouring it
// would throttle the sender with an out-of-date value.
enum class PacketType : std::int8_t { kRegular = 0, kFec = 1 };

// Flush scopes (kcp.go:72-77). kFlushAckOnly writes pending ACKs and nothing else, which is what
// the low-latency clocking path in Input uses; kFlushFull runs the whole scheduler.
enum FlushType : std::uint8_t { kFlushAckOnly = 1, kFlushFull = 2 };

// Trace categories (kcp.go:80-93). The reference compiles these calls away unless the `debug`
// build tag is set; here the mask is checked at run time and the message is only built when a
// category is enabled, so an unconfigured logger costs one branch per call site.
enum LogType : std::uint32_t {
  kLogOutput = 1u << 0,
  kLogInput = 1u << 1,
  kLogSend = 1u << 2,
  kLogRecv = 1u << 3,
  kLogOutAck = 1u << 4,
  kLogOutPush = 1u << 5,
  kLogOutWask = 1u << 6,
  kLogOutWins = 1u << 7,
  kLogInAck = 1u << 8,
  kLogInPush = 1u << 9,
  kLogInWask = 1u << 10,
  kLogInWins = 1u << 11,
};

// One datagram's worth of encoded segments, handed to the transport. `buf` is only valid for the
// duration of the call - the caller must copy it, exactly like the Go callback contract.
using OutputCallback = std::function<void(const std::uint8_t* buf, std::size_t size)>;

// Trace sink. The message is already formatted; return quickly and do not block (the KCP lock is
// held while this runs).
using LogCallback = std::function<void(const std::string& line)>;

// Milliseconds from a monotonic origin. Injectable so tests can drive the timers deterministically
// instead of sleeping; the default is internal::CurrentMs().
using Clock = std::function<std::uint32_t()>;

// A single KCP connection's protocol state machine: pure ARQ, no I/O (kcp.go:203-249). Everything
// the reference keeps in unexported fields is a member here; the public surface mirrors its
// exported methods plus the accessor set the session layer needs.
class Kcp {
 public:
  // kcp.go:251-281 - 'conv' must match at both peers or every segment is rejected, and 'output'
  // is invoked from Flush/Input with the datagram to send.
  Kcp(std::uint32_t conv, OutputCallback output, Clock clock = nullptr);

  Kcp(const Kcp&) = delete;
  Kcp& operator=(const Kcp&) = delete;
  Kcp(Kcp&&) = delete;
  Kcp& operator=(Kcp&&) = delete;

  // Size of the next complete message, -1 when nothing is readable (kcp.go:298-321).
  // [kcp-proxy local patch] const: it only reads rcv_queue_, and the proxy
  // exposes peek_size() through a const accessor (see VENDORED.md).
  int PeekSize() const;

  // Copies the next message into 'buffer'. Returns the byte count, -1 when no message is ready,
  // -2 when the message does not fit (kcp.go:329-379).
  int Recv(void* buffer, std::size_t len);

  // Queues 'len' bytes for transmission. Returns 0, -1 for an empty write, -2 when the message
  // needs more than 255 fragments (kcp.go:382-444).
  int Send(const void* buffer, std::size_t len);

  // Feeds one received datagram through the state machine. Returns 0, or -1/-2/-3 for a conv
  // mismatch, a truncated segment, or an unknown command (kcp.go:588-750).
  int Input(const std::uint8_t* data, std::size_t len, PacketType pkt_type = PacketType::kRegular,
            bool ack_no_delay = false);

  // Advances the timers; call every few milliseconds (kcp.go:1003-1025).
  void Update();

  // Absolute time at which Update should next be called (kcp.go:1034-1077).
  std::uint32_t Check();

  // Runs the scheduler. Public because the session flushes the tail on close (kcp.go:757-985).
  void Flush(FlushType flush_type);

  // Sets the MTU. Returns -1 when it cannot even hold a header (kcp.go:1080-1088).
  int SetMtu(int mtu);

  // nodelay/interval/resend/nc, negatives leave the current value alone (kcp.go:1096-1119).
  int NoDelay(int nodelay, int interval, int resend, int nc);

  // Send and receive window sizes in packets; non-positive values are ignored (kcp.go:1122-1130).
  int WndSize(int sndwnd, int rcvwnd);

  // Stream mode merges adjacent writes into the last queued segment instead of preserving message
  // boundaries (kcp.go:392-410). The reference sets the field directly from the session.
  void SetStreamMode(bool enable);

  // Trace categories and sink; a null sink disables tracing (kcp.go:1139-1146).
  void SetLogger(std::uint32_t mask, LogCallback logger);

  // Packets queued or still in flight (kcp.go:1133-1136).
  int wait_snd() const;

  // True once a segment has hit dead_link retransmits (kcp.go:943).
  bool IsDead() const { return state_ == kDeadState; }

  std::uint32_t conv() const { return conv_; }
  std::uint32_t mtu() const { return mtu_; }
  // Largest payload one segment can carry (kcp.go:198, mtu - kOverhead).
  std::uint32_t mss() const { return mss_; }
  // Send/remote window bounds, read by the session's write path to decide whether to block.
  std::uint32_t snd_wnd() const { return snd_wnd_; }
  std::uint32_t rcv_wnd() const { return rcv_wnd_; }

  // [kcp-proxy local patch] Read-only accessors over the tuning state applied by
  // NoDelay(), so embedders can verify that configured constants reached the
  // live protocol state (mirrors the conv()/mtu()/snd_wnd()/rcv_wnd() set).
  std::uint32_t nodelay() const { return nodelay_; }
  std::uint32_t interval() const { return interval_; }
  std::int32_t fastresend() const { return fastresend_; }
  std::int32_t nocwnd() const { return nocwnd_; }

  // Smoothed RTT and its variance in milliseconds, and the current retransmission timeout.
  std::int32_t srtt() const { return rx_srtt_; }
  std::int32_t srtt_var() const { return rx_rttvar_; }
  std::uint32_t rto() const { return rx_rto_; }

 private:
  struct AckItem {
    std::uint32_t sn = 0;
    std::uint32_t ts = 0;
  };

  template <typename Fn>
  void DebugLog(std::uint32_t type, Fn&& format) {
    if (log_ == nullptr || (log_mask_ & type) == 0) {
      return;
    }
    log_(format());
  }

  void UpdateAck(std::int32_t rtt);
  void ShrinkBuf();
  void ParseAck(std::uint32_t sn);
  int ParseFastack(std::uint32_t sn, std::uint32_t ts);
  int ParseUna(std::uint32_t una);
  void AckPush(std::uint32_t sn, std::uint32_t ts);

  // 'header' supplies cmd/frg/wnd/ts/sn/una; the payload is copied only when the segment is new,
  // so a duplicate costs no allocation (kcp.go:556-584).
  bool ParseData(const internal::Segment& header, const std::uint8_t* payload, std::size_t len);

  void DrainRecvBuffer();
  std::uint16_t WndUnused() const;
  std::uint32_t Now() const { return clock_(); }

  // Identity and framing
  std::uint32_t conv_ = 0;
  std::uint32_t mtu_ = 0;
  std::uint32_t mss_ = 0;
  std::uint32_t state_ = 0;  // 0 while alive, kDeadState once dead

  // Sequence numbers
  std::uint32_t snd_una_ = 0;
  std::uint32_t snd_nxt_ = 0;
  std::uint32_t rcv_nxt_ = 0;

  // Congestion control
  std::uint32_t ssthresh_ = 0;
  std::int32_t rx_rttvar_ = 0;
  std::int32_t rx_srtt_ = 0;
  std::uint32_t rx_rto_ = 0;
  std::uint32_t rx_minrto_ = 0;
  std::uint32_t snd_wnd_ = 0;
  std::uint32_t rcv_wnd_ = 0;
  std::uint32_t rmt_wnd_ = 0;
  std::uint32_t cwnd_ = 0;
  std::uint32_t incr_ = 0;

  // Window probing
  std::uint32_t probe_ = 0;
  std::uint32_t ts_probe_ = 0;
  std::uint32_t probe_wait_ = 0;

  // Timers
  std::uint32_t interval_ = 0;
  std::uint32_t ts_flush_ = 0;
  std::uint32_t nodelay_ = 0;
  std::uint32_t updated_ = 0;

  // Reliability
  std::uint32_t dead_link_ = 0;
  std::int32_t fastresend_ = 0;
  std::int32_t nocwnd_ = 0;
  std::int32_t stream_ = 0;

  // Logging
  std::uint32_t log_mask_ = 0;
  LogCallback log_;

  internal::RingBuffer<internal::Segment> snd_queue_;
  internal::RingBuffer<internal::Segment> rcv_queue_;
  internal::RingBuffer<internal::Segment> snd_buf_;
  internal::SegmentHeap rcv_buf_;

  std::vector<AckItem> acklist_;
  std::vector<std::uint8_t> buffer_;
  OutputCallback output_;
  Clock clock_;
};

}  // namespace kcp

#endif  // KCP_KCP_H_
