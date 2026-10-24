// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_KCP_SEGMENT_H_
#define KCP_INTERNAL_KCP_SEGMENT_H_

#include <cstddef>
#include <cstdint>
#include <unordered_set>
#include <vector>

namespace kcp {

namespace internal {

// One KCP segment (kcp.go:120-136). The wire fields keep their protocol names because they are
// laid out by Segment::Encode; the bookkeeping fields below them are KCP's own.
//
// The payload is an owning vector rather than a pooled buffer (deviation D12): the reference
// hands out fixed 1500-byte blocks and returns them by hand in recycleSegment, which means every
// path that drops a segment - ack'd, discarded, recv-queue popped, heap popped - has to remember
// to give the block back. Owning storage makes the release implicit, and the per-segment
// allocation is ~1 malloc per MSS-sized chunk on a path that already does a memcpy.
struct Segment {
  std::uint32_t conv = 0;
  std::uint8_t cmd = 0;
  std::uint8_t frg = 0;
  std::uint16_t wnd = 0;
  std::uint32_t ts = 0;
  std::uint32_t sn = 0;
  std::uint32_t una = 0;

  std::uint32_t rto = 0;
  std::uint32_t xmit = 0;
  std::uint32_t resendts = 0;
  std::uint32_t fastack = 0;
  std::uint32_t acked = 0;  // 1 once an ACK covered this segment

  std::vector<std::uint8_t> data;

  // Writes the 24-byte header and returns the first byte after it (kcp.go:145-159). The length
  // field is the payload size, so the caller must have sized data correctly.
  std::uint8_t* Encode(std::uint8_t* ptr) const;
};

// Min-heap of out-of-order received segments plus a membership set, so duplicate suppression is
// O(1) instead of a scan (kcp.go:162-198). Ordering is by sequence number with wraparound, which
// is why the comparator goes through TimeDiff rather than operator<.
class SegmentHeap {
 public:
  std::size_t Len() const { return segments_.size(); }

  bool Has(std::uint32_t sn) const { return marks_.find(sn) != marks_.end(); }

  void Push(Segment seg);

  // Removes and returns the smallest segment; false when empty.
  bool Pop(Segment* out);

 private:
  // kcp.go:176-178 - Less(i, j) is "segment i sorts before segment j".
  static bool Less(const Segment& a, const Segment& b);

  void SiftUp(std::size_t i);
  void SiftDown(std::size_t i);

  std::vector<Segment> segments_;
  std::unordered_set<std::uint32_t> marks_;
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_KCP_SEGMENT_H_
