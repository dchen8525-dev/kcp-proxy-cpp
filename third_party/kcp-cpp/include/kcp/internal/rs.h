// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go
//
// Reed-Solomon erasure code over GF(2^8), matching the matrix that
// github.com/klauspost/reedsolomon v1.12.0 builds through its default
// buildMatrix() path: start from the Vandermonde matrix vm[r][c] = r^c, then right-multiply by
// the inverse of the top data_shards x data_shards square so the data shards pass through
// unchanged (reedsolomon.go:220-244). The parity bytes are wire-visible in the FEC packets, so
// the construction is part of the interop contract, not an implementation detail.

#ifndef KCP_INTERNAL_RS_H_
#define KCP_INTERNAL_RS_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "kcp/error.h"

namespace kcp {
namespace internal {

// One entry per shard. An empty vector means "missing"; see the Reconstruct() contract below.
using ShardSet = std::vector<std::vector<std::uint8_t>>;

class ReedSolomon {
 public:
  // Mirrors reedsolomon.New: data_shards >= 1, parity_shards >= 0 and
  // data_shards + parity_shards <= 256 (ErrInvShardNum / ErrMaxShardNum). Returns nullptr for
  // any rejected combination, including a matrix that fails to invert.
  static std::unique_ptr<ReedSolomon> New(int data_shards, int parity_shards);

  int data_shards() const { return data_shards_; }
  int parity_shards() const { return parity_shards_; }
  int total_shards() const { return data_shards_ + parity_shards_; }

  // Row-major encoding matrix, total_shards x data_shards. The first data_shards rows are the
  // identity matrix; the remaining rows generate the parity shards.
  std::uint8_t MatrixAt(int row, int col) const {
    return matrix_[static_cast<std::size_t>(row) * static_cast<std::size_t>(data_shards_) +
                   static_cast<std::size_t>(col)];
  }

  // Recomputes every parity shard from the data shards. All total_shards entries must be present
  // and of equal non-zero length; only the parity entries are written.
  ErrorCode Encode(ShardSet* shards) const;

  // Rebuilds the missing data shards. Missing entries are empty vectors on input and are sized
  // to the common shard length on success. At least data_shards entries must be present overall,
  // otherwise kFecRecoverFailed is returned and nothing is allocated.
  //
  // Unequal shard lengths are a caller error: the FEC layer zero-pads to maxlen before calling
  // in (PORTING-PLAN.md #41), so absorbing that here would hide a padding bug.
  ErrorCode ReconstructData(ShardSet* shards) const;

  // Same as ReconstructData, but also rebuilds any missing parity shards.
  ErrorCode Reconstruct(ShardSet* shards) const;

 private:
  ReedSolomon(int data_shards, int parity_shards);

  bool BuildMatrix();

  ErrorCode ReconstructImpl(ShardSet* shards, bool data_only) const;

  int data_shards_;
  int parity_shards_;
  std::vector<std::uint8_t> matrix_;  // total_shards * data_shards, row-major
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_RS_H_
