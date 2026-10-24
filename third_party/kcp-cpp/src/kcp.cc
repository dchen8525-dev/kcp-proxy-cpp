// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/kcp.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>

#include "kcp/internal/byteorder.h"
#include "kcp/internal/clock.h"
#include "kcp/internal/constants.h"
#include "kcp/snmp.h"

namespace kcp {
namespace {

using internal::Segment;
using internal::TimeDiff;

void Bump(std::atomic<std::uint64_t>& counter, std::uint64_t delta) {
  counter.fetch_add(delta, std::memory_order_relaxed);
}

void Store(std::atomic<std::uint64_t>& counter, std::uint64_t value) {
  counter.store(value, std::memory_order_relaxed);
}

std::string Field(const char* name, std::uint64_t value) {
  std::string out;
  out.reserve(std::strlen(name) + 24);
  out += name;
  out += '=';
  out += std::to_string(value);
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Segment / SegmentHeap
// ---------------------------------------------------------------------------

std::uint8_t* internal::Segment::Encode(std::uint8_t* ptr) const {
  internal::WriteLe32(ptr, conv);
  ptr[4] = cmd;
  ptr[5] = frg;
  internal::WriteLe16(ptr + 6, wnd);
  internal::WriteLe32(ptr + 8, ts);
  internal::WriteLe32(ptr + 12, sn);
  internal::WriteLe32(ptr + 16, una);
  internal::WriteLe32(ptr + 20, static_cast<std::uint32_t>(data.size()));
  Bump(DefaultSnmp().out_segs, 1);
  return ptr + kOverhead;
}

bool internal::SegmentHeap::Less(const Segment& a, const Segment& b) {
  // kcp.go:176-178: j sorts after i while the wrapping distance is positive, so the heap pops the
  // lowest sequence number even across the 32-bit wrap.
  return TimeDiff(b.sn, a.sn) > 0;
}

void internal::SegmentHeap::Push(Segment seg) {
  segments_.push_back(std::move(seg));
  marks_.insert(segments_.back().sn);
  SiftUp(segments_.size() - 1);
}

void internal::SegmentHeap::SiftUp(std::size_t i) {
  while (i > 0) {
    const std::size_t parent = (i - 1) / 2;
    if (!Less(segments_[i], segments_[parent])) {
      break;
    }
    std::swap(segments_[i], segments_[parent]);
    i = parent;
  }
}

void internal::SegmentHeap::SiftDown(std::size_t i) {
  const std::size_t n = segments_.size();
  for (;;) {
    const std::size_t left = 2 * i + 1;
    if (left >= n) {
      break;
    }
    std::size_t smallest = left;
    const std::size_t right = left + 1;
    if (right < n && Less(segments_[right], segments_[left])) {
      smallest = right;
    }
    if (!Less(segments_[smallest], segments_[i])) {
      break;
    }
    std::swap(segments_[i], segments_[smallest]);
    i = smallest;
  }
}

bool internal::SegmentHeap::Pop(Segment* out) {
  const std::size_t n = segments_.size();
  if (n == 0) {
    return false;
  }
  *out = std::move(segments_[0]);
  marks_.erase(out->sn);
  if (n == 1) {
    segments_.pop_back();
    return true;
  }
  segments_[0] = std::move(segments_[n - 1]);
  segments_.pop_back();
  SiftDown(0);
  return true;
}

// ---------------------------------------------------------------------------
// Kcp
// ---------------------------------------------------------------------------

Kcp::Kcp(std::uint32_t conv, OutputCallback output, Clock clock)
    : snd_queue_(kWndSnd * 2),
      rcv_queue_(kWndRcv * 2),
      snd_buf_(kWndSnd * 2),
      output_(std::move(output)),
      clock_(clock != nullptr ? std::move(clock) : Clock(&internal::CurrentMs)) {
  conv_ = conv;
  snd_wnd_ = kWndSnd;
  rcv_wnd_ = kWndRcv;
  rmt_wnd_ = kWndRcv;
  mtu_ = static_cast<std::uint32_t>(kMtuDef);
  mss_ = mtu_ - static_cast<std::uint32_t>(kOverhead);
  buffer_.assign(static_cast<std::size_t>(mtu_ + kOverhead) * 3, 0);
  rx_rto_ = kRtoDef;
  rx_minrto_ = kRtoMin;
  interval_ = kInterval;
  ts_flush_ = kInterval;
  ssthresh_ = kThreshInit;
  dead_link_ = kDeadLink;
}

// kcp.go:298-321 — [kcp-proxy local patch] const (only reads rcv_queue_).
int Kcp::PeekSize() const {
  const Segment* head = rcv_queue_.Peek();
  if (head == nullptr) {
    return -1;
  }
  if (head->frg == 0) {
    return static_cast<int>(head->data.size());
  }
  // A fragmented message is only readable once every fragment has arrived.
  if (rcv_queue_.Len() < static_cast<std::size_t>(head->frg) + 1) {
    return -1;
  }
  std::size_t length = 0;
  rcv_queue_.ForEach([&length](const Segment& seg) {
    length += seg.data.size();
    return seg.frg != 0;
  });
  return static_cast<int>(length);
}

// kcp.go:329-379
int Kcp::Recv(void* buffer, std::size_t len) {
  const int peeksize = PeekSize();
  if (peeksize < 0) {
    return -1;
  }
  if (static_cast<std::size_t>(peeksize) > len) {
    return -2;
  }

  // If the queue is at the window edge before this read, draining it makes room and the peer has
  // to be told immediately, otherwise it stalls until the next probe.
  const bool fast_recover = rcv_queue_.Len() >= static_cast<std::size_t>(rcv_wnd_);

  auto* out = static_cast<std::uint8_t*>(buffer);
  int n = 0;
  for (;;) {
    Segment seg;
    if (!rcv_queue_.Pop(&seg)) {
      break;
    }
    if (!seg.data.empty()) {
      std::memcpy(out, seg.data.data(), seg.data.size());
      out += seg.data.size();
    }
    n += static_cast<int>(seg.data.size());
    if (seg.frg == 0) {
      DebugLog(kLogRecv, [this, n]() {
        return std::string("[KCP RECV] stream=") + std::to_string(stream_) + Field(" conv", conv_) +
               Field(" datalen", static_cast<std::uint64_t>(n));
      });
      break;
    }
  }

  DrainRecvBuffer();

  if (rcv_queue_.Len() < static_cast<std::size_t>(rcv_wnd_) && fast_recover) {
    // Tell the remote the window opened up (kcp.go:520-527).
    probe_ |= kAskTell;
  }
  return n;
}

// kcp.go:382-444
int Kcp::Send(const void* buffer, std::size_t len) {
  if (len == 0) {
    return -1;
  }
  const auto* data = static_cast<const std::uint8_t*>(buffer);

  if (stream_ != 0) {
    // Only the last queued segment can absorb more bytes: message boundaries do not exist in
    // stream mode, so a partial tail is not a boundary (kcp.go:392-410).
    if (snd_queue_.Len() > 0) {
      snd_queue_.ForEachReverse([&](Segment& seg) {
        if (seg.data.size() < static_cast<std::size_t>(mss_)) {
          const std::size_t capacity = static_cast<std::size_t>(mss_) - seg.data.size();
          const std::size_t extend = std::min(len, capacity);
          seg.data.insert(seg.data.end(), data, data + extend);
          data += extend;
          len -= extend;
        }
        return false;
      });
      if (len == 0) {
        return 0;
      }
    }
  }

  int count = 0;
  if (len <= static_cast<std::size_t>(mss_)) {
    count = 1;
  } else {
    count = static_cast<int>((len + static_cast<std::size_t>(mss_) - 1) /
                             static_cast<std::size_t>(mss_));
  }
  if (count > 255) {
    return -2;
  }
  if (count == 0) {
    count = 1;
  }

  for (int i = 0; i < count; ++i) {
    const std::size_t size = std::min(len, static_cast<std::size_t>(mss_));
    Segment seg;
    seg.data.assign(data, data + size);
    seg.frg = stream_ == 0 ? static_cast<std::uint8_t>(count - i - 1) : 0;
    snd_queue_.Push(std::move(seg));
    data += size;
    len -= size;
  }
  return 0;
}

// kcp.go:466-483
void Kcp::UpdateAck(std::int32_t rtt) {
  if (rx_srtt_ == 0) {
    rx_srtt_ = rtt;
    rx_rttvar_ = rtt >> 1;
  } else {
    std::int32_t delta = rtt - rx_srtt_;
    rx_srtt_ += delta >> 3;
    if (delta < 0) {
      delta = -delta;
    }
    if (rtt < rx_srtt_ - rx_rttvar_) {
      // A sample below the expected band gets 1/8 of the normal weight (RFC 6298).
      rx_rttvar_ += (delta - rx_rttvar_) >> 5;
    } else {
      rx_rttvar_ += (delta - rx_rttvar_) >> 2;
    }
  }
  const std::uint32_t rto =
      static_cast<std::uint32_t>(rx_srtt_) +
      std::max<std::uint32_t>(interval_, static_cast<std::uint32_t>(rx_rttvar_) << 2);
  rx_rto_ = std::min<std::uint32_t>(std::max<std::uint32_t>(rx_minrto_, rto), kRtoMax);
}

// kcp.go:486-493
void Kcp::ShrinkBuf() {
  const Segment* head = snd_buf_.Peek();
  snd_una_ = head != nullptr ? head->sn : snd_nxt_;
}

// kcp.go:499-516
void Kcp::ParseAck(std::uint32_t sn) {
  if (TimeDiff(sn, snd_una_) < 0 || TimeDiff(sn, snd_nxt_) >= 0) {
    return;
  }
  snd_buf_.ForEach([&](Segment& seg) {
    if (sn == seg.sn) {
      // Marked, not removed: the segment stays until una passes it so nothing behind it has to
      // shift. The payload is released right away.
      seg.acked = 1;
      std::vector<std::uint8_t>().swap(seg.data);
      return false;
    }
    return TimeDiff(sn, seg.sn) >= 0;
  });
}

// kcp.go:521-544
int Kcp::ParseFastack(std::uint32_t sn, std::uint32_t ts) {
  int should_fast_ack = 0;
  if (TimeDiff(sn, snd_una_) < 0 || TimeDiff(sn, snd_nxt_) >= 0) {
    return 0;
  }
  snd_buf_.ForEach([&](Segment& seg) {
    if (TimeDiff(sn, seg.sn) < 0) {
      return false;
    }
    if (sn != seg.sn && TimeDiff(seg.ts, ts) <= 0) {
      if (seg.fastack != 0xFFFFFFFFu) {
        ++seg.fastack;
        if (seg.fastack >= static_cast<std::uint32_t>(fastresend_)) {
          should_fast_ack = 1;
        }
      }
    }
    return true;
  });
  return should_fast_ack;
}

// kcp.go:549-560
int Kcp::ParseUna(std::uint32_t una) {
  int count = 0;
  snd_buf_.ForEach([&](const Segment& seg) {
    if (TimeDiff(una, seg.sn) > 0) {
      ++count;
      return true;
    }
    return false;
  });
  snd_buf_.Discard(static_cast<std::size_t>(count));
  return count;
}

// kcp.go:563-565
void Kcp::AckPush(std::uint32_t sn, std::uint32_t ts) { acklist_.push_back(AckItem{sn, ts}); }

// Moves whatever is now contiguous from rcv_buf into rcv_queue (kcp.go:356-368, 575-583).
void Kcp::DrainRecvBuffer() {
  while (rcv_buf_.Len() > 0) {
    Segment seg;
    if (!rcv_buf_.Pop(&seg)) {
      break;
    }
    if (seg.sn == rcv_nxt_ && rcv_queue_.Len() < static_cast<std::size_t>(rcv_wnd_)) {
      rcv_queue_.Push(std::move(seg));
      ++rcv_nxt_;
    } else {
      rcv_buf_.Push(std::move(seg));
      break;
    }
  }
}

// kcp.go:568-586
bool Kcp::ParseData(const Segment& header, const std::uint8_t* payload, std::size_t len) {
  if (TimeDiff(header.sn, rcv_nxt_ + rcv_wnd_) >= 0 || TimeDiff(header.sn, rcv_nxt_) < 0) {
    return true;
  }

  bool repeat = false;
  if (!rcv_buf_.Has(header.sn)) {
    Segment seg = header;
    seg.data.assign(payload, payload + len);
    rcv_buf_.Push(std::move(seg));
  } else {
    repeat = true;
  }

  DrainRecvBuffer();
  return repeat;
}

// kcp.go:594-750
int Kcp::Input(const std::uint8_t* data, std::size_t len, PacketType pkt_type, bool ack_no_delay) {
  const std::uint32_t snd_una = snd_una_;
  if (len < kOverhead) {
    return -1;
  }

  std::uint32_t latest = 0;  // ts of the last ACK in this datagram
  bool update_rtt = false;
  std::uint64_t in_segs = 0;
  int flush_segments = 0;
  std::size_t offset = 0;

  for (;;) {
    if (len - offset < kOverhead) {
      break;
    }

    const std::uint8_t* p = data + offset;
    const std::uint32_t conv = internal::ReadLe32(p);
    const std::uint8_t cmd = p[4];
    const std::uint8_t frg = p[5];
    const std::uint16_t wnd = internal::ReadLe16(p + 6);
    const std::uint32_t ts = internal::ReadLe32(p + 8);
    const std::uint32_t sn = internal::ReadLe32(p + kSnOffset);
    const std::uint32_t una = internal::ReadLe32(p + 16);
    const std::size_t length = internal::ReadLe32(p + 20);
    offset += kOverhead;

    if (conv != conv_) {
      return -1;
    }

    DebugLog(kLogInput, [&]() {
      return std::string("[KCP INPUT]") + Field(" conv", conv) + Field(" cmd", cmd) +
             Field(" frg", frg) + Field(" wnd", wnd) + Field(" ts", ts) + Field(" sn", sn) +
             Field(" una", una) + Field(" len", length);
    });

    if (len - offset < length) {
      return -2;
    }

    if (cmd != kCmdPush && cmd != kCmdAck && cmd != kCmdWask && cmd != kCmdWins) {
      return -3;
    }

    // Only regular packets carry a trustworthy window: a parity shard's wnd is a snapshot.
    if (pkt_type == PacketType::kRegular) {
      rmt_wnd_ = wnd;
    }
    if (ParseUna(una) > 0) {
      flush_segments |= 1;
    }
    ShrinkBuf();

    switch (cmd) {
      case kCmdAck:
        DebugLog(kLogInAck, [&]() {
          return std::string("[KCP INPUT ACK]") + Field(" conv", conv) + Field(" sn", sn) +
                 Field(" una", una) + Field(" ts", ts) + Field(" rto", rx_rto_);
        });
        ParseAck(sn);
        flush_segments |= ParseFastack(sn, ts);
        update_rtt = true;
        latest = ts;
        break;

      case kCmdPush: {
        bool repeat = true;
        if (TimeDiff(sn, rcv_nxt_ + rcv_wnd_) < 0) {
          AckPush(sn, ts);
          if (TimeDiff(sn, rcv_nxt_) >= 0) {
            Segment header;
            header.conv = conv;
            header.cmd = cmd;
            header.frg = frg;
            header.wnd = wnd;
            header.ts = ts;
            header.sn = sn;
            header.una = una;
            repeat = ParseData(header, data + offset, length);
          }
        }
        if (pkt_type == PacketType::kRegular && repeat) {
          Bump(DefaultSnmp().repeat_segs, 1);
        }
        DebugLog(kLogInPush, [&]() {
          return std::string("[KCP INPUT PUSH]") + Field(" conv", conv) + Field(" sn", sn) +
                 Field(" una", una) + Field(" ts", ts) +
                 Field(" packettype", static_cast<std::uint64_t>(pkt_type)) +
                 Field(" repeat", repeat ? 1 : 0);
        });
        break;
      }

      case kCmdWask:
        // The peer is asking: schedule a WINS in the next flush (kcp.go:690-695).
        probe_ |= kAskTell;
        DebugLog(kLogInWask, [&]() {
          return std::string("[KCP INPUT WASK]") + Field(" conv", conv) + Field(" wnd", wnd) +
                 Field(" ts", ts);
        });
        break;

      case kCmdWins:
        DebugLog(kLogInWins, [&]() {
          return std::string("[KCP INPUT WINS]") + Field(" conv", conv) + Field(" wnd", wnd) +
                 Field(" ts", ts);
        });
        break;

      default:
        return -3;
    }

    ++in_segs;
    offset += length;
  }
  Bump(DefaultSnmp().in_segs, in_segs);

  // One RTT sample per datagram, from the last ACK it carried (kcp.go:713-721).
  if (update_rtt && pkt_type == PacketType::kRegular) {
    const std::uint32_t current = Now();
    if (TimeDiff(current, latest) >= 0) {
      UpdateAck(TimeDiff(current, latest));
    }
  }

  // Reno-style congestion control (kcp.go:723-752).
  if (nocwnd_ == 0) {
    if (TimeDiff(snd_una_, snd_una) > 0) {
      if (cwnd_ < rmt_wnd_) {
        const std::uint32_t mss = mss_;
        if (cwnd_ < ssthresh_) {
          ++cwnd_;
          incr_ += mss;
        } else {
          if (incr_ < mss) {
            incr_ = mss;
          }
          incr_ += (mss * mss) / incr_ + (mss / 16);
          if ((cwnd_ + 1) * mss <= incr_) {
            if (mss > 0) {
              cwnd_ = (incr_ + mss - 1) / mss;
            } else {
              cwnd_ = incr_ + mss - 1;
            }
          }
        }
        if (cwnd_ > rmt_wnd_) {
          cwnd_ = rmt_wnd_;
          incr_ = rmt_wnd_ * mss;
        }
      }
    }
  }

  if (flush_segments != 0) {
    // The window slid or a fast retransmit is due: send now instead of waiting for the tick.
    Flush(kFlushFull);
  } else if (acklist_.size() >= static_cast<std::size_t>(mtu_ / kOverhead)) {
    // Clocking: on a low-latency link the interval is longer than the RTT, so a full ACK batch is
    // flushed on its own (kcp.go:735-741).
    Flush(kFlushAckOnly);
  } else if (ack_no_delay && !acklist_.empty()) {
    Flush(kFlushAckOnly);
  }
  return 0;
}

// kcp.go:752-754
std::uint16_t Kcp::WndUnused() const {
  if (rcv_queue_.Len() < static_cast<std::size_t>(rcv_wnd_)) {
    return static_cast<std::uint16_t>(rcv_wnd_ - rcv_queue_.Len());
  }
  return 0;
}

// kcp.go:757-985
void Kcp::Flush(FlushType flush_type) {
  Segment seg;
  seg.conv = conv_;
  seg.cmd = kCmdAck;
  seg.wnd = WndUnused();
  seg.una = rcv_nxt_;

  std::uint8_t* buffer = buffer_.data();
  std::size_t capacity = buffer_.size();
  std::size_t ptr = 0;  // bytes written into buffer

  // Flush at the MTU boundary: every output() call becomes exactly one datagram.
  auto flush_buffer = [&]() {
    if (ptr > 0 && output_ != nullptr) {
      output_(buffer, ptr);
    }
    ptr = 0;
  };

  auto make_space = [&](std::size_t space) {
    if (ptr + space > mtu_) {
      flush_buffer();
    }
  };

  // A segment queued before a shrinking SetMtu can be larger than the buffer the new MTU
  // implies. Go would slice out of range here; grow instead so the segment still goes out intact.
  auto ensure_capacity = [&](std::size_t need) {
    if (need <= capacity) {
      return;
    }
    buffer_.resize(need);
    buffer = buffer_.data();
    capacity = buffer_.size();
  };

  // --- Phase 1: pending ACKs ---
  if (flush_type == kFlushAckOnly || flush_type == kFlushFull) {
    const std::size_t ack_count = acklist_.size();
    for (std::size_t i = 0; i < ack_count; ++i) {
      const AckItem ack = acklist_[i];
      make_space(kOverhead);
      // Drop ACKs the peer already covered, except the last one: it carries the freshest una and
      // is what closes the sender's window (kcp.go:791-797).
      if (TimeDiff(ack.sn, rcv_nxt_) >= 0 || ack_count - 1 == i) {
        seg.sn = ack.sn;
        seg.ts = ack.ts;
        ensure_capacity(ptr + kOverhead);
        ptr = static_cast<std::size_t>(seg.Encode(buffer + ptr) - buffer);
        DebugLog(kLogOutAck, [&]() {
          return std::string("[KCP OUTPUT ACK]") + Field(" conv", seg.conv) + Field(" sn", seg.sn) +
                 Field(" una", seg.una) + Field(" ts", seg.ts);
        });
      }
    }
    acklist_.clear();
  }

  // --- Phase 2: window probing schedule ---
  if (rmt_wnd_ == 0) {
    const std::uint32_t current = Now();
    if (probe_wait_ == 0) {
      probe_wait_ = kProbeInit;
      ts_probe_ = current + probe_wait_;
    } else if (TimeDiff(current, ts_probe_) >= 0) {
      if (probe_wait_ < kProbeInit) {
        probe_wait_ = kProbeInit;
      }
      probe_wait_ += probe_wait_ / 2;
      if (probe_wait_ > kProbeLimit) {
        probe_wait_ = kProbeLimit;
      }
      ts_probe_ = current + probe_wait_;
      probe_ |= kAskSend;
    }
  } else {
    ts_probe_ = 0;
    probe_wait_ = 0;
  }

  // --- Phase 3: probe commands ---
  if ((probe_ & kAskSend) != 0) {
    seg.cmd = kCmdWask;
    make_space(kOverhead);
    ensure_capacity(ptr + kOverhead);
    ptr = static_cast<std::size_t>(seg.Encode(buffer + ptr) - buffer);
    DebugLog(kLogOutWask, [&]() {
      return std::string("[KCP OUTPUT WASK]") + Field(" conv", seg.conv) + Field(" wnd", seg.wnd) +
             Field(" ts", seg.ts);
    });
  }
  if ((probe_ & kAskTell) != 0) {
    seg.cmd = kCmdWins;
    make_space(kOverhead);
    ensure_capacity(ptr + kOverhead);
    ptr = static_cast<std::size_t>(seg.Encode(buffer + ptr) - buffer);
    DebugLog(kLogOutWins, [&]() {
      return std::string("[KCP OUTPUT WINS]") + Field(" conv", seg.conv) + Field(" wnd", seg.wnd) +
             Field(" ts", seg.ts);
    });
  }
  probe_ = 0;

  // --- Phase 4: snd_queue -> snd_buf ---
  std::uint32_t cwnd = std::min(snd_wnd_, rmt_wnd_);
  if (nocwnd_ == 0) {
    cwnd = std::min(cwnd_, cwnd);
  }

  int new_segs_count = 0;
  for (;;) {
    if (TimeDiff(snd_nxt_, snd_una_ + cwnd) >= 0) {
      break;
    }
    Segment newseg;
    if (!snd_queue_.Pop(&newseg)) {
      break;
    }
    newseg.conv = conv_;
    newseg.cmd = kCmdPush;
    newseg.sn = snd_nxt_;
    snd_buf_.Push(std::move(newseg));
    ++snd_nxt_;
    ++new_segs_count;
  }

  // A disabled fast retransmit must never fire: 0xffffffff can only be reached by the sentinel the
  // fast-retransmit path writes back, and that path is guarded by the same value.
  std::uint32_t resent = static_cast<std::uint32_t>(fastresend_);
  if (fastresend_ <= 0) {
    resent = 0xFFFFFFFFu;
  }

  // --- Phase 5: (re)transmission ---
  std::uint32_t current = Now();
  std::uint64_t change = 0;
  std::uint64_t lost_segs = 0;
  std::uint64_t fast_retrans_segs = 0;
  std::uint64_t early_retrans_segs = 0;
  std::uint32_t next_update = interval_;

  if (flush_type == kFlushFull) {
    snd_buf_.ForEach([&](Segment& segment) {
      bool needsend = false;
      if (segment.acked == 1) {
        return true;
      }
      if (segment.xmit == 0) {
        needsend = true;
        segment.rto = rx_rto_;
        segment.resendts = current + segment.rto;
      } else if (segment.fastack >= resent && segment.fastack != 0xFFFFFFFFu) {
        needsend = true;
        // Stay latched until the RTO path resets it, so one loss does not trigger a resend storm.
        segment.fastack = 0xFFFFFFFFu;
        segment.rto = rx_rto_;
        segment.resendts = current + segment.rto;
        ++change;
        ++fast_retrans_segs;
      } else if (segment.fastack > 0 && segment.fastack != 0xFFFFFFFFu && new_segs_count == 0) {
        // No new data to fill the pipe: resend on the first duplicate ACK instead of waiting.
        needsend = true;
        segment.fastack = 0xFFFFFFFFu;
        segment.rto = rx_rto_;
        segment.resendts = current + segment.rto;
        ++change;
        ++early_retrans_segs;
      } else if (TimeDiff(current, segment.resendts) >= 0) {
        needsend = true;
        if (nodelay_ == 0) {
          segment.rto += rx_rto_;
        } else {
          segment.rto += rx_rto_ / 2;
        }
        segment.fastack = 0;
        segment.resendts = current + segment.rto;
        ++lost_segs;
      }

      if (needsend) {
        current = Now();
        ++segment.xmit;
        segment.ts = current;
        segment.wnd = seg.wnd;
        segment.una = seg.una;

        const std::size_t need = kOverhead + segment.data.size();
        make_space(need);
        ensure_capacity(ptr + need);
        ptr = static_cast<std::size_t>(segment.Encode(buffer + ptr) - buffer);
        if (!segment.data.empty()) {
          std::memcpy(buffer + ptr, segment.data.data(), segment.data.size());
          ptr += segment.data.size();
        }

        DebugLog(kLogOutPush, [&]() {
          return std::string("[KCP OUTPUT PUSH]") + Field(" conv", segment.conv) +
                 Field(" sn", segment.sn) + Field(" frg", segment.frg) +
                 Field(" una", segment.una) + Field(" ts", segment.ts) +
                 Field(" xmit", segment.xmit) + Field(" datalen", segment.data.size());
        });

        if (segment.xmit >= dead_link_) {
          state_ = kDeadState;  // kcp.go:942-944
        }
      }

      const std::int32_t rto = TimeDiff(segment.resendts, current);
      if (rto > 0 && static_cast<std::uint32_t>(rto) < next_update) {
        next_update = static_cast<std::uint32_t>(rto);
      }
      return true;
    });
  }

  // --- Phase 6: counters and congestion window ---
  std::uint64_t sum = lost_segs;
  if (lost_segs > 0) {
    Bump(DefaultSnmp().lost_segs, lost_segs);
  }
  if (fast_retrans_segs > 0) {
    Bump(DefaultSnmp().fast_retrans_segs, fast_retrans_segs);
    sum += fast_retrans_segs;
  }
  if (early_retrans_segs > 0) {
    Bump(DefaultSnmp().early_retrans_segs, early_retrans_segs);
    sum += early_retrans_segs;
  }
  if (sum > 0) {
    Bump(DefaultSnmp().retrans_segs, sum);
  }

  if (nocwnd_ == 0) {
    if (change > 0) {
      // Rate halving: ssthresh = inflight / 2, then cwnd = ssthresh + fastresend (RFC 6937).
      const std::uint32_t inflight = snd_nxt_ - snd_una_;
      ssthresh_ = std::max<std::uint32_t>(inflight / 2, kThreshMin);
      cwnd_ = ssthresh_ + resent;
      incr_ = cwnd_ * mss_;
    }
    if (lost_segs > 0) {
      // RTO: collapse to one segment and re-enter slow start (RFC 5681).
      ssthresh_ = std::max<std::uint32_t>(cwnd / 2, kThreshMin);
      cwnd_ = 1;
      incr_ = mss_;
    }
    if (cwnd_ < 1) {
      cwnd_ = 1;
      incr_ = mss_;
    }
  }

  flush_buffer();
  Store(DefaultSnmp().ring_buffer_snd_queue, snd_queue_.Len());
  Store(DefaultSnmp().ring_buffer_rcv_queue, rcv_queue_.Len());
  Store(DefaultSnmp().ring_buffer_snd_buffer, snd_buf_.Len());
}

// kcp.go:1003-1025
void Kcp::Update() {
  const std::uint32_t current = Now();
  if (updated_ == 0) {
    updated_ = 1;
    ts_flush_ = current;
  }

  std::int32_t slap = TimeDiff(current, ts_flush_);
  if (slap >= 10000 || slap < -10000) {
    // A clock jump this large is a suspend or a bogus timestamp: resync instead of firing a burst.
    ts_flush_ = current;
    slap = 0;
  }

  if (slap >= 0) {
    ts_flush_ += interval_;
    if (TimeDiff(current, ts_flush_) >= 0) {
      ts_flush_ = current + interval_;
    }
    Flush(kFlushFull);
  }
}

// kcp.go:1034-1077
std::uint32_t Kcp::Check() {
  const std::uint32_t current = Now();
  std::uint32_t ts_flush = ts_flush_;
  std::int32_t tm_flush = 0x7fffffff;
  std::int32_t tm_packet = 0x7fffffff;
  std::uint32_t minimal = 0;

  if (updated_ == 0) {
    return current;
  }

  if (TimeDiff(current, ts_flush) >= 10000 || TimeDiff(current, ts_flush) < -10000) {
    ts_flush = current;
  }
  if (TimeDiff(current, ts_flush) >= 0) {
    return current;
  }

  tm_flush = TimeDiff(ts_flush, current);
  bool due = false;
  snd_buf_.ForEach([&](const Segment& seg) {
    const std::int32_t diff = TimeDiff(seg.resendts, current);
    if (diff <= 0) {
      due = true;
      return false;
    }
    if (diff < tm_packet) {
      tm_packet = diff;
    }
    return true;
  });
  if (due) {
    return current;
  }

  minimal = static_cast<std::uint32_t>(tm_packet);
  if (tm_packet >= tm_flush) {
    minimal = static_cast<std::uint32_t>(tm_flush);
  }
  if (minimal >= interval_) {
    minimal = interval_;
  }
  return current + minimal;
}

// kcp.go:1080-1088
int Kcp::SetMtu(int mtu) {
  if (mtu <= static_cast<int>(kOverhead)) {
    return -1;
  }
  mtu_ = static_cast<std::uint32_t>(mtu);
  mss_ = mtu_ - static_cast<std::uint32_t>(kOverhead);
  buffer_.assign(static_cast<std::size_t>(mtu_ + kOverhead) * 3, 0);
  return 0;
}

// kcp.go:1096-1119
int Kcp::NoDelay(int nodelay, int interval, int resend, int nc) {
  if (nodelay >= 0) {
    nodelay_ = static_cast<std::uint32_t>(nodelay);
    rx_minrto_ = nodelay != 0 ? kRtoNdl : kRtoMin;
  }
  if (interval >= 0) {
    if (interval > 5000) {
      interval = 5000;
    } else if (interval < 10) {
      interval = 10;
    }
    interval_ = static_cast<std::uint32_t>(interval);
  }
  if (resend >= 0) {
    fastresend_ = resend;
  }
  if (nc >= 0) {
    nocwnd_ = nc;
  }
  return 0;
}

// kcp.go:1122-1130
int Kcp::WndSize(int sndwnd, int rcvwnd) {
  if (sndwnd > 0) {
    snd_wnd_ = static_cast<std::uint32_t>(sndwnd);
  }
  if (rcvwnd > 0) {
    rcv_wnd_ = static_cast<std::uint32_t>(rcvwnd);
  }
  return 0;
}

void Kcp::SetStreamMode(bool enable) { stream_ = enable ? 1 : 0; }

// kcp.go:1133-1136
int Kcp::wait_snd() const { return static_cast<int>(snd_buf_.Len() + snd_queue_.Len()); }

// kcp.go:1139-1146
void Kcp::SetLogger(std::uint32_t mask, LogCallback logger) {
  if (logger == nullptr) {
    log_mask_ = 0;
    log_ = nullptr;
    return;
  }
  log_mask_ = mask;
  log_ = std::move(logger);
}

}  // namespace kcp
