// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/fec.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <utility>

#include "kcp/internal/byteorder.h"
#include "kcp/internal/constants.h"
#include "kcp/snmp.h"

namespace kcp {
namespace internal {
namespace {

// Monotonic milliseconds. Go reads time.Now().UnixMilli() (fec.go:426); the only use is the
// continuity window between two data packets, so a monotonic source is strictly better - a wall
// clock jump must not be able to fake (or hide) a burst.
std::int64_t NowMillis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

std::uint32_t PawsFor(int shard_size) {
  return 0xffffffffu / static_cast<std::uint32_t>(shard_size) *
         static_cast<std::uint32_t>(shard_size);
}

}  // namespace

// ---------------------------------------------------------------------------
// ShardHeap
// ---------------------------------------------------------------------------

bool ShardHeap::Has(std::uint32_t seqid) const { return marks_.find(seqid) != marks_.end(); }

void ShardHeap::Push(FecPacket packet) {
  if (packet.size() < kFecHeaderSize) {
    return;
  }
  const std::uint32_t seqid = ReadLe32(packet.data());
  marks_.insert(seqid);
  // Ascending seqid, matching container/heap with fec.go:96's Less. A shard set holds at most
  // shard_size entries, so the linear insertion beats a heap's bookkeeping.
  auto pos = elements_.begin();
  while (pos != elements_.end() && TimeDiff(ReadLe32(pos->data()), seqid) < 0) {
    ++pos;
  }
  elements_.insert(pos, std::move(packet));
}

FecPacket ShardHeap::Pop() {
  if (elements_.empty()) {
    return {};
  }
  FecPacket packet = std::move(elements_.front());
  elements_.erase(elements_.begin());
  marks_.erase(ReadLe32(packet.data()));
  return packet;
}

std::vector<FecPacket> ShardHeap::TakeAll() {
  std::vector<FecPacket> packets = std::move(elements_);
  elements_.clear();
  marks_.clear();
  return packets;
}

// ---------------------------------------------------------------------------
// FecEncoder
// ---------------------------------------------------------------------------

std::unique_ptr<FecEncoder> FecEncoder::New(int data_shards, int parity_shards, int header_offset) {
  if (data_shards <= 0 || parity_shards <= 0 || header_offset < 0) {
    return nullptr;
  }
  auto codec = ReedSolomon::New(data_shards, parity_shards);
  if (codec == nullptr) {
    return nullptr;
  }
  std::unique_ptr<FecEncoder> encoder(new FecEncoder(data_shards, parity_shards, header_offset));
  encoder->codec_ = std::move(codec);
  encoder->codec_shards_.resize(static_cast<std::size_t>(encoder->shard_size_));
  return encoder;
}

FecEncoder::FecEncoder(int data_shards, int parity_shards, int header_offset)
    : data_shards_(data_shards),
      parity_shards_(parity_shards),
      shard_size_(data_shards + parity_shards),
      header_offset_(header_offset),
      payload_offset_(header_offset + static_cast<int>(kFecHeaderSize)),
      paws_(PawsFor(data_shards + parity_shards)) {
  shard_cache_.assign(static_cast<std::size_t>(shard_size_),
                      std::vector<std::uint8_t>(kMtuLimit, 0));
  shard_length_.assign(static_cast<std::size_t>(shard_size_), 0);
}

void FecEncoder::Encode(std::uint8_t* buffer, std::size_t length, std::uint32_t rto,
                        std::vector<FecPacket>* parity) {
  if (buffer == nullptr || parity == nullptr) {
    return;
  }
  const std::size_t payload_offset = static_cast<std::size_t>(payload_offset_);
  if (length < payload_offset + 2) {
    return;
  }

  SealData(buffer + header_offset_);
  // fec.go:406: the length field counts itself, so it is the size of everything from
  // payload_offset up to the end of the packet.
  WriteLe16(buffer + payload_offset, static_cast<std::uint16_t>(length - payload_offset));

  const std::size_t index = static_cast<std::size_t>(shard_count_);
  shard_length_[index] = length;
  if (shard_cache_[index].size() < length) {
    shard_cache_[index].resize(length, 0);
  }
  // Only the payload is buffered; the FEC header of a data shard is the caller's buffer.
  std::memcpy(shard_cache_[index].data() + payload_offset, buffer + payload_offset,
              length - payload_offset);
  ++shard_count_;
  max_size_ = std::max(max_size_, length);

  const std::int64_t now = NowMillis();
  if (shard_count_ == data_shards_) {
    if (now - ts_latest_packet_ < static_cast<std::int64_t>(rto)) {
      GenerateParity(parity);
    } else {
      // Non-continuous burst (fec.go:460): skip the parity but keep the seqid advancing, since
      // the receiver detects losses from the seqid gap.
      SkipParity();
    }
    shard_count_ = 0;
    max_size_ = 0;
  }
  ts_latest_packet_ = now;
}

void FecEncoder::GenerateParity(std::vector<FecPacket>* parity) {
  const std::size_t payload_offset = static_cast<std::size_t>(payload_offset_);
  const std::size_t span = max_size_ - payload_offset;

  for (std::vector<std::uint8_t>& cache : shard_cache_) {
    if (cache.size() < max_size_) {
      cache.resize(max_size_, 0);
    }
  }
  // Zero the tail of each data shard so every shard is exactly max_size long (fec.go:437).
  for (int i = 0; i < data_shards_; ++i) {
    const std::size_t shard_length = shard_length_[static_cast<std::size_t>(i)];
    std::memset(shard_cache_[static_cast<std::size_t>(i)].data() + shard_length, 0,
                max_size_ - shard_length);
  }

  for (int k = 0; k < shard_size_; ++k) {
    std::vector<std::uint8_t>& shard = codec_shards_[static_cast<std::size_t>(k)];
    shard.assign(span, 0);
    if (k < data_shards_) {
      std::memcpy(shard.data(), shard_cache_[static_cast<std::size_t>(k)].data() + payload_offset,
                  span);
    }
  }

  if (codec_->Encode(&codec_shards_) != ErrorCode::kOk) {
    DefaultSnmp().fec_errs.fetch_add(1);
    SkipParity();
    return;
  }

  for (int k = 0; k < parity_shards_; ++k) {
    std::vector<std::uint8_t>& shard = shard_cache_[static_cast<std::size_t>(data_shards_ + k)];
    std::memcpy(shard.data() + payload_offset,
                codec_shards_[static_cast<std::size_t>(data_shards_ + k)].data(), span);
    SealParity(shard.data() + header_offset_);
    // The parity packet is max_size long, header space included, exactly like fec.go:463's
    // `ps[k] = ps[k][:enc.maxSize]`. Bytes below header_offset_ belong to the encryption layer
    // and are overwritten there before the packet hits the wire.
    parity->emplace_back(shard.begin(), shard.begin() + static_cast<std::ptrdiff_t>(max_size_));
  }
}

void FecEncoder::EncodeOob(std::uint8_t* buffer, std::size_t length) {
  const std::size_t payload_offset = static_cast<std::size_t>(payload_offset_);
  if (buffer == nullptr || length < payload_offset + 2) {
    return;
  }
  SealOob(buffer + header_offset_);
  WriteLe16(buffer + payload_offset, static_cast<std::uint16_t>(length - payload_offset));
}

void FecEncoder::SealData(std::uint8_t* header) {
  WriteLe32(header, next_);
  WriteLe16(header + 4, kTypeData);
  next_ = (next_ + 1) % paws_;
}

void FecEncoder::SealParity(std::uint8_t* header) {
  WriteLe32(header, next_);
  WriteLe16(header + 4, kTypeParity);
  next_ = (next_ + 1) % paws_;
}

void FecEncoder::SealOob(std::uint8_t* header) {
  WriteLe32(header, 0xffffffff);
  WriteLe16(header + 4, kTypeOob);
}

void FecEncoder::SkipParity() {
  next_ = (next_ + static_cast<std::uint32_t>(parity_shards_)) % paws_;
}

// ---------------------------------------------------------------------------
// FecDecoder
// ---------------------------------------------------------------------------

std::unique_ptr<FecDecoder> FecDecoder::New(int data_shards, int parity_shards) {
  if (data_shards <= 0 || parity_shards <= 0) {
    return nullptr;
  }
  auto codec = ReedSolomon::New(data_shards, parity_shards);
  if (codec == nullptr) {
    return nullptr;
  }
  std::unique_ptr<FecDecoder> decoder(new FecDecoder(data_shards, parity_shards));
  decoder->codec_ = std::move(codec);
  return decoder;
}

FecDecoder::FecDecoder(int data_shards, int parity_shards)
    : data_shards_(data_shards),
      parity_shards_(parity_shards),
      shard_size_(data_shards + parity_shards),
      paws_(PawsFor(data_shards + parity_shards)) {
  shards_.resize(static_cast<std::size_t>(shard_size_));
  shard_flags_.assign(static_cast<std::size_t>(shard_size_), false);
}

std::uint32_t FecDecoder::GetShardId(std::uint32_t seqid) const {
  return seqid / static_cast<std::uint32_t>(shard_size_);
}

std::vector<FecPacket> FecDecoder::Decode(const std::uint8_t* packet, std::size_t length) {
  std::vector<FecPacket> recovered;
  if (packet == nullptr || length < kFecHeaderSize) {
    return recovered;
  }

  const std::uint32_t seqid = ReadLe32(packet);
  const std::uint16_t flag = ReadLe16(packet + 4);
  if (seqid >= paws_) {
    return recovered;
  }

  // Auto-tuning is P8 (PORTING-PLAN.md P4): Go compares the observed type against the type its
  // current parameters imply and, on a mismatch, drops the packet while it infers new
  // parameters (fec.go:279-320). We deliberately keep shouldTune false, so a mismatched packet
  // still joins its shard set; the peer then simply cannot recover from it and retransmits.
  // Silently discarding packets from the decode path would be a data-loss bug, not a feature.

  const std::uint32_t shard_id = GetShardId(seqid);
  auto slot = shard_set_.try_emplace(shard_id);
  if (slot.second) {
    DefaultSnmp().fec_shard_set.fetch_add(1);
  }
  ShardHeap& shard = slot.first->second;

  if (shard.Has(seqid)) {
    return recovered;
  }
  if (flag == kTypeParity) {
    DefaultSnmp().fec_parity_shards.fetch_add(1);
  }
  shard.Push(FecPacket(packet, packet + length));

  if (shard.size() >= static_cast<std::size_t>(data_shards_)) {
    for (std::size_t k = 0; k < shards_.size(); ++k) {
      shards_[k].clear();
      shard_flags_[k] = false;
    }

    std::size_t maxlen = 0;
    int num_data_shard = 0;
    const std::vector<FecPacket> packets = shard.TakeAll();
    for (const FecPacket& pkt : packets) {
      const std::uint32_t packet_seqid = ReadLe32(pkt.data());
      const std::uint16_t packet_flag = ReadLe16(pkt.data() + 4);
      const std::size_t index = packet_seqid % static_cast<std::uint32_t>(shard_size_);
      shards_[index].assign(pkt.begin() + static_cast<std::ptrdiff_t>(kFecHeaderSize), pkt.end());
      shard_flags_[index] = true;
      if (packet_flag == kTypeData) {
        ++num_data_shard;
      }
      maxlen = std::max(maxlen, pkt.size() - kFecHeaderSize);
    }

    if (num_data_shard == data_shards_) {
      DefaultSnmp().fec_full_shard_set.fetch_add(1);
    } else {
      // Equalise lengths: the wire carries the true length in each shard's 2-byte field, so the
      // short shards are zero-extended, never truncated (fec.go:470-480).
      for (int k = 0; k < shard_size_; ++k) {
        std::vector<std::uint8_t>& current = shards_[static_cast<std::size_t>(k)];
        if (!current.empty()) {
          current.resize(maxlen, 0);
        }
      }
      if (codec_->ReconstructData(&shards_) == ErrorCode::kOk) {
        for (int k = 0; k < data_shards_; ++k) {
          if (!shard_flags_[static_cast<std::size_t>(k)]) {
            recovered.push_back(std::move(shards_[static_cast<std::size_t>(k)]));
          }
        }
      } else {
        // Unreachable for an MDS matrix, but a silent partial recovery would be worse.
        DefaultSnmp().fec_errs.fetch_add(1);
      }
      DefaultSnmp().fec_recovered.fetch_add(static_cast<std::uint64_t>(recovered.size()));
    }
  }

  const std::uint32_t set_span = static_cast<std::uint32_t>(shard_size_);
  if (TimeDiff(shard_id * set_span, newest_shard_id_ * set_span) > 0) {
    newest_shard_id_ = shard_id;
    DefaultSnmp().fec_shard_min.store(newest_shard_id_);
  }
  DiscardShards();
  return recovered;
}

void FecDecoder::DiscardShards() {
  const std::uint32_t set_span = static_cast<std::uint32_t>(shard_size_);
  const std::uint32_t newest = newest_shard_id_ * set_span;
  for (auto it = shard_set_.begin(); it != shard_set_.end();) {
    const std::uint32_t id = it->first * set_span;
    if (TimeDiff(newest, id) > kMaxShardSets * shard_size_) {
      it = shard_set_.erase(it);
    } else {
      ++it;
    }
  }
  // Gauge, not a counter: Go stores len(shardSet) after every decode (fec.go:341).
  DefaultSnmp().fec_shard_set.store(static_cast<std::uint64_t>(shard_set_.size()));
}

}  // namespace internal
}  // namespace kcp
