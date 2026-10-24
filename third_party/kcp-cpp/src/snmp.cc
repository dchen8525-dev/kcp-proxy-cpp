// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/snmp.h"

namespace kcp {
namespace {

constexpr std::memory_order kRelaxed = std::memory_order_relaxed;

// Same strings and order as Snmp.Header() in snmp.go:70-101.
const char* const kHeaderNames[Snmp::kFieldCount] = {
    "BytesSent",
    "BytesReceived",
    "MaxConn",
    "ActiveOpens",
    "PassiveOpens",
    "CurrEstab",
    "InErrs",
    "InCsumErrors",
    "KCPInErrors",
    "InPkts",
    "OutPkts",
    "InSegs",
    "OutSegs",
    "InBytes",
    "OutBytes",
    "RetransSegs",
    "FastRetransSegs",
    "EarlyRetransSegs",
    "LostSegs",
    "RepeatSegs",
    "FECFullShards",
    "FECParityShards",
    "FECErrs",
    "FECRecovered",
    "FECShardSet",
    "FECShardMin",
    "RingBufferSndQueue",
    "RingBufferRcvQueue",
    "RingBufferSndBuffer",
    "OOBPackets",
};

}  // namespace

SnmpSnapshot Snmp::Snapshot() const {
  SnmpSnapshot s;
  s.bytes_sent = bytes_sent.load(kRelaxed);
  s.bytes_received = bytes_received.load(kRelaxed);
  s.max_conn = max_conn.load(kRelaxed);
  s.active_opens = active_opens.load(kRelaxed);
  s.passive_opens = passive_opens.load(kRelaxed);
  s.curr_estab = curr_estab.load(kRelaxed);
  s.in_errs = in_errs.load(kRelaxed);
  s.in_csum_errors = in_csum_errors.load(kRelaxed);
  s.kcp_in_errors = kcp_in_errors.load(kRelaxed);
  s.in_pkts = in_pkts.load(kRelaxed);
  s.out_pkts = out_pkts.load(kRelaxed);
  s.in_segs = in_segs.load(kRelaxed);
  s.out_segs = out_segs.load(kRelaxed);
  s.in_bytes = in_bytes.load(kRelaxed);
  s.out_bytes = out_bytes.load(kRelaxed);
  s.retrans_segs = retrans_segs.load(kRelaxed);
  s.fast_retrans_segs = fast_retrans_segs.load(kRelaxed);
  s.early_retrans_segs = early_retrans_segs.load(kRelaxed);
  s.lost_segs = lost_segs.load(kRelaxed);
  s.repeat_segs = repeat_segs.load(kRelaxed);
  s.fec_full_shard_set = fec_full_shard_set.load(kRelaxed);
  s.fec_recovered = fec_recovered.load(kRelaxed);
  s.fec_errs = fec_errs.load(kRelaxed);
  s.fec_parity_shards = fec_parity_shards.load(kRelaxed);
  s.fec_shard_set = fec_shard_set.load(kRelaxed);
  s.fec_shard_min = fec_shard_min.load(kRelaxed);
  s.ring_buffer_snd_queue = ring_buffer_snd_queue.load(kRelaxed);
  s.ring_buffer_rcv_queue = ring_buffer_rcv_queue.load(kRelaxed);
  s.ring_buffer_snd_buffer = ring_buffer_snd_buffer.load(kRelaxed);
  s.oob_packets = oob_packets.load(kRelaxed);
  return s;
}

void Snmp::Reset() {
  bytes_sent.store(0, kRelaxed);
  bytes_received.store(0, kRelaxed);
  max_conn.store(0, kRelaxed);
  active_opens.store(0, kRelaxed);
  passive_opens.store(0, kRelaxed);
  curr_estab.store(0, kRelaxed);
  in_errs.store(0, kRelaxed);
  in_csum_errors.store(0, kRelaxed);
  kcp_in_errors.store(0, kRelaxed);
  in_pkts.store(0, kRelaxed);
  out_pkts.store(0, kRelaxed);
  in_segs.store(0, kRelaxed);
  out_segs.store(0, kRelaxed);
  in_bytes.store(0, kRelaxed);
  out_bytes.store(0, kRelaxed);
  retrans_segs.store(0, kRelaxed);
  fast_retrans_segs.store(0, kRelaxed);
  early_retrans_segs.store(0, kRelaxed);
  lost_segs.store(0, kRelaxed);
  repeat_segs.store(0, kRelaxed);
  fec_full_shard_set.store(0, kRelaxed);
  fec_recovered.store(0, kRelaxed);
  fec_errs.store(0, kRelaxed);
  fec_parity_shards.store(0, kRelaxed);
  fec_shard_set.store(0, kRelaxed);
  fec_shard_min.store(0, kRelaxed);
  ring_buffer_snd_queue.store(0, kRelaxed);
  ring_buffer_rcv_queue.store(0, kRelaxed);
  ring_buffer_snd_buffer.store(0, kRelaxed);
  oob_packets.store(0, kRelaxed);
}

const char* const* Snmp::HeaderNames() { return kHeaderNames; }

std::array<std::uint64_t, Snmp::kFieldCount> Snmp::ToArray() const {
  const SnmpSnapshot s = Snapshot();
  return {
      s.bytes_sent,
      s.bytes_received,
      s.max_conn,
      s.active_opens,
      s.passive_opens,
      s.curr_estab,
      s.in_errs,
      s.in_csum_errors,
      s.kcp_in_errors,
      s.in_pkts,
      s.out_pkts,
      s.in_segs,
      s.out_segs,
      s.in_bytes,
      s.out_bytes,
      s.retrans_segs,
      s.fast_retrans_segs,
      s.early_retrans_segs,
      s.lost_segs,
      s.repeat_segs,
      s.fec_full_shard_set,
      s.fec_parity_shards,
      s.fec_errs,
      s.fec_recovered,
      s.fec_shard_set,
      s.fec_shard_min,
      s.ring_buffer_snd_queue,
      s.ring_buffer_rcv_queue,
      s.ring_buffer_snd_buffer,
      s.oob_packets,
  };
}

Snmp& DefaultSnmp() {
  static Snmp* snmp = new Snmp();
  return *snmp;
}

}  // namespace kcp
