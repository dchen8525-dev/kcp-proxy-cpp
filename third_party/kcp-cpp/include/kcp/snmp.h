// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_SNMP_H_
#define KCP_SNMP_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace kcp {

// Point-in-time copy of the counters. Plain values so it can be copied and logged; take one with
// Snmp::Snapshot() instead of reading the atomics one by one.
struct SnmpSnapshot {
  std::uint64_t bytes_sent = 0;
  std::uint64_t bytes_received = 0;
  std::uint64_t max_conn = 0;
  std::uint64_t active_opens = 0;
  std::uint64_t passive_opens = 0;
  std::uint64_t curr_estab = 0;
  std::uint64_t in_errs = 0;
  std::uint64_t in_csum_errors = 0;
  std::uint64_t kcp_in_errors = 0;
  std::uint64_t in_pkts = 0;
  std::uint64_t out_pkts = 0;
  std::uint64_t in_segs = 0;
  std::uint64_t out_segs = 0;
  std::uint64_t in_bytes = 0;
  std::uint64_t out_bytes = 0;
  std::uint64_t retrans_segs = 0;
  std::uint64_t fast_retrans_segs = 0;
  std::uint64_t early_retrans_segs = 0;
  std::uint64_t lost_segs = 0;
  std::uint64_t repeat_segs = 0;
  std::uint64_t fec_full_shard_set = 0;
  std::uint64_t fec_recovered = 0;
  std::uint64_t fec_errs = 0;
  std::uint64_t fec_parity_shards = 0;
  std::uint64_t fec_shard_set = 0;
  std::uint64_t fec_shard_min = 0;
  std::uint64_t ring_buffer_snd_queue = 0;
  std::uint64_t ring_buffer_rcv_queue = 0;
  std::uint64_t ring_buffer_snd_buffer = 0;
  std::uint64_t oob_packets = 0;
};

// Network statistics, field for field with kcp-go's Snmp (snmp.go:31-62).
//
// The counters are public atomics rather than accessor pairs: this is a data aggregate with no
// invariants, the reference implementation updates it from every hot path, and a getter per
// counter would be noise. They sit at lock level L0 (PORTING-PLAN.md §3.2) - relaxed ordering is
// enough because no counter orders other memory.
class Snmp {
 public:
  std::atomic<std::uint64_t> bytes_sent{0};
  std::atomic<std::uint64_t> bytes_received{0};
  std::atomic<std::uint64_t> max_conn{0};
  std::atomic<std::uint64_t> active_opens{0};
  std::atomic<std::uint64_t> passive_opens{0};
  std::atomic<std::uint64_t> curr_estab{0};
  std::atomic<std::uint64_t> in_errs{0};
  std::atomic<std::uint64_t> in_csum_errors{0};
  std::atomic<std::uint64_t> kcp_in_errors{0};
  std::atomic<std::uint64_t> in_pkts{0};
  std::atomic<std::uint64_t> out_pkts{0};
  std::atomic<std::uint64_t> in_segs{0};
  std::atomic<std::uint64_t> out_segs{0};
  std::atomic<std::uint64_t> in_bytes{0};
  std::atomic<std::uint64_t> out_bytes{0};
  std::atomic<std::uint64_t> retrans_segs{0};
  std::atomic<std::uint64_t> fast_retrans_segs{0};
  std::atomic<std::uint64_t> early_retrans_segs{0};
  std::atomic<std::uint64_t> lost_segs{0};
  std::atomic<std::uint64_t> repeat_segs{0};
  std::atomic<std::uint64_t> fec_full_shard_set{0};
  std::atomic<std::uint64_t> fec_recovered{0};
  std::atomic<std::uint64_t> fec_errs{0};
  std::atomic<std::uint64_t> fec_parity_shards{0};
  std::atomic<std::uint64_t> fec_shard_set{0};
  std::atomic<std::uint64_t> fec_shard_min{0};
  std::atomic<std::uint64_t> ring_buffer_snd_queue{0};
  std::atomic<std::uint64_t> ring_buffer_rcv_queue{0};
  std::atomic<std::uint64_t> ring_buffer_snd_buffer{0};
  std::atomic<std::uint64_t> oob_packets{0};

  static constexpr std::size_t kFieldCount = 30;

  SnmpSnapshot Snapshot() const;
  void Reset();

  // Column names in counter order, for metric export. Strings match the reference implementation
  // verbatim, including its "FECFullShards" label for fec_full_shard_set (snmp.go:91).
  static const char* const* HeaderNames();

  // Counter values in the same order as HeaderNames().
  std::array<std::uint64_t, kFieldCount> ToArray() const;
};

// Process-wide statistics collector. Function-local static and intentionally never destroyed:
// sessions may still be updating counters during static destruction (PORTING-PLAN.md §3.5).
Snmp& DefaultSnmp();

}  // namespace kcp

#endif  // KCP_SNMP_H_
