// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go
//
// Forward error correction layer: fecEncoder / fecDecoder / shardHeap from fec.go. The encoder
// groups data_shards consecutive outgoing packets into one shard set and emits parity_shards
// packets for it; the decoder groups incoming packets by shard set and reconstructs whatever is
// missing once at least data_shards packets of that set have arrived.

#ifndef KCP_INTERNAL_FEC_H_
#define KCP_INTERNAL_FEC_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "kcp/internal/rs.h"

namespace kcp {
namespace internal {

// One wire-level FEC packet: the 6-byte header (seqid(4) + type(2)) followed by the protected
// payload. The payload itself begins with the 2-byte length field the encoder writes, so the
// codec sees length_field + data exactly as Go's `fecPacket.data()` = bts[6:] does.
using FecPacket = std::vector<std::uint8_t>;

// Packets of one shard set, keyed by seqid. Holds at most shard_size entries, so the sorted
// vector is cheaper than a heap and makes the pop order explicit (ascending seqid, like
// container/heap with fec.go's Less).
class ShardHeap {
 public:
  bool Has(std::uint32_t seqid) const;
  void Push(FecPacket packet);

  std::size_t size() const { return elements_.size(); }
  bool Empty() const { return elements_.empty(); }

  // Removes and returns the lowest-seqid packet.
  FecPacket Pop();

  // Removes every packet, in ascending seqid order.
  std::vector<FecPacket> TakeAll();

  // Observability for tests; Go keeps `elements` unexported and reads only Len().
  const std::vector<FecPacket>& elements() const { return elements_; }

 private:
  std::vector<FecPacket> elements_;
  std::unordered_set<std::uint32_t> marks_;
};

// Builds the parity packets for outgoing data. Thread-compatible with Go: one instance per
// session, called from the single post-processing path, so it carries no lock.
class FecEncoder {
 public:
  // header_offset is the number of bytes reserved in front of the FEC header for the encryption
  // layer (sess.go:220 passes sess.headerSize). Returns nullptr for data_shards < 1,
  // parity_shards < 1 or a rejected Reed-Solomon configuration.
  static std::unique_ptr<FecEncoder> New(int data_shards, int parity_shards, int header_offset);

  int data_shards() const { return data_shards_; }
  int parity_shards() const { return parity_shards_; }
  int shard_size() const { return shard_size_; }
  int header_offset() const { return header_offset_; }
  int payload_offset() const { return payload_offset_; }

  // Next seqid to be written (fec.go's `enc.next`). Monotonic modulo paws.
  std::uint32_t next() const { return next_; }

  // Seals one packet in place: writes the seqid/type header and the 2-byte length field, buffers
  // the payload, and on every data_shards-th call appends the parity packets to *parity.
  //
  // rto is the continuity window in milliseconds (fec.go:427): if the previous data packet is
  // older than that, the shard set is not considered a burst and parity is skipped - but the
  // seqid still advances by parity_shards so the peer keeps seeing a monotonic stream. That
  // branch is not an optimisation to skip; a receiver relies on the gap to notice the loss.
  //
  // `length` must be at least payload_offset + 2; a shorter buffer is rejected without writing.
  void Encode(std::uint8_t* buffer, std::size_t length, std::uint32_t rto,
              std::vector<FecPacket>* parity);

  // Seals an out-of-band packet: fixed seqid 0xffffffff, typeOob, and no seqid advance
  // (fec.go:544-556). OOB packets are demultiplexed with the FEC header layout but never enter
  // the Reed-Solomon code.
  void EncodeOob(std::uint8_t* buffer, std::size_t length);

 private:
  FecEncoder(int data_shards, int parity_shards, int header_offset);

  // Emits the parity_shards parity packets for the buffered shard set. Byte-exact port of the
  // fec.go:432-465 branch: zero-extend every data shard to max_size, run RS over
  // [payload_offset, max_size), seal the parity headers, hand out max_size-long packets.
  void GenerateParity(std::vector<FecPacket>* parity);

  void SealData(std::uint8_t* header);
  void SealParity(std::uint8_t* header);
  void SealOob(std::uint8_t* header);
  void SkipParity();

  const int data_shards_;
  const int parity_shards_;
  const int shard_size_;
  const int header_offset_;
  const int payload_offset_;
  const std::uint32_t paws_;

  std::uint32_t next_ = 0;
  int shard_count_ = 0;
  std::size_t max_size_ = 0;
  std::int64_t ts_latest_packet_ = 0;

  // One full-MTU buffer per shard. The first payload_offset bytes of each are dead weight kept
  // only so a parity packet can be handed out as a single contiguous slice, exactly like
  // fec.go:398's shardCache.
  std::vector<std::vector<std::uint8_t>> shard_cache_;
  std::vector<std::size_t> shard_length_;

  std::unique_ptr<ReedSolomon> codec_;
  ShardSet codec_shards_;
};

// Reassembles shard sets from incoming packets and reconstructs the missing ones.
class FecDecoder {
 public:
  // Mirrors newFECDecoder (fec.go:144): rejects data_shards < 1, parity_shards < 1 and
  // data_shards + parity_shards > 256.
  static std::unique_ptr<FecDecoder> New(int data_shards, int parity_shards);

  int data_shards() const { return data_shards_; }
  int parity_shards() const { return parity_shards_; }
  int shard_size() const { return shard_size_; }

  // Feeds one packet (header included) and returns whichever data shards had to be rebuilt. The
  // returned buffers are the shard payloads, i.e. packet[6:], ready to be decrypted and passed to
  // the KCP input. Empty result for duplicates, for packets beyond paws_ and for sets that are
  // still short of data_shards packets.
  std::vector<FecPacket> Decode(const std::uint8_t* packet, std::size_t length);

  // Gauge: number of shard sets currently held. Go stores the same value into FECShardSet.
  std::size_t shard_set_count() const { return shard_set_.size(); }
  std::uint32_t newest_shard_id() const { return newest_shard_id_; }

 private:
  FecDecoder(int data_shards, int parity_shards);

  std::uint32_t GetShardId(std::uint32_t seqid) const;
  void DiscardShards();

  const int data_shards_;
  const int parity_shards_;
  const int shard_size_;
  const std::uint32_t paws_;

  std::unordered_map<std::uint32_t, ShardHeap> shard_set_;
  std::uint32_t newest_shard_id_ = 0;

  std::unique_ptr<ReedSolomon> codec_;
  ShardSet shards_;                // reused decode scratch space
  std::vector<bool> shard_flags_;  // true when the slot came from the wire
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_FEC_H_
