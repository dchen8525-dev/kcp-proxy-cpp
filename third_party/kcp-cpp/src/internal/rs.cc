// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/rs.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "kcp/internal/galois.h"

namespace kcp {
namespace internal {
namespace {

// Minimal dense GF(2^8) matrix. Only the operations the codec construction needs: the inverse
// of the Vandermonde top square and a single multiply. Kept out of the header because nothing
// outside this file should be building matrices by hand.
class Matrix {
 public:
  Matrix() = default;
  Matrix(int rows, int cols)
      : rows_(rows), cols_(cols), data_(static_cast<std::size_t>(rows * cols), 0) {}

  int rows() const { return rows_; }
  int cols() const { return cols_; }

  std::uint8_t At(int row, int col) const {
    return data_[static_cast<std::size_t>(row * cols_ + col)];
  }
  void Set(int row, int col, std::uint8_t value) {
    data_[static_cast<std::size_t>(row * cols_ + col)] = value;
  }
  std::uint8_t* Row(int row) { return data_.data() + static_cast<std::size_t>(row * cols_); }
  const std::uint8_t* Row(int row) const {
    return data_.data() + static_cast<std::size_t>(row * cols_);
  }

  const std::vector<std::uint8_t>& data() const { return data_; }

  // vm[r][c] = r^c, with r taken as a field element (reedsolomon.go:270-281 vandermonde()).
  static Matrix Vandermonde(int rows, int cols) {
    Matrix m(rows, cols);
    for (int r = 0; r < rows; ++r) {
      for (int c = 0; c < cols; ++c) {
        m.Set(r, c, GaloisExp(static_cast<std::uint8_t>(r), c));
      }
    }
    return m;
  }

  Matrix SubMatrix(int row0, int col0, int rows, int cols) const {
    Matrix m(rows, cols);
    for (int r = 0; r < rows; ++r) {
      for (int c = 0; c < cols; ++c) {
        m.Set(r, c, At(row0 + r, col0 + c));
      }
    }
    return m;
  }

  // Gauss-Jordan on [this | I]. Returns false for a singular matrix (no pivot in some column).
  bool Invert(Matrix* out) const {
    if (rows_ != cols_) {
      return false;
    }
    const int n = rows_;
    const int wide = n * 2;
    Matrix work(n, wide);
    for (int r = 0; r < n; ++r) {
      for (int c = 0; c < n; ++c) {
        work.Set(r, c, At(r, c));
      }
      work.Set(r, n + r, 1);
    }

    const GaloisMulTable& mul = MulTable();
    for (int r = 0; r < n; ++r) {
      if (work.At(r, r) == 0) {
        int swap_with = -1;
        for (int below = r + 1; below < n; ++below) {
          if (work.At(below, r) != 0) {
            swap_with = below;
            break;
          }
        }
        if (swap_with < 0) {
          return false;
        }
        std::uint8_t* a = work.Row(r);
        std::uint8_t* b = work.Row(swap_with);
        for (int c = 0; c < wide; ++c) {
          std::swap(a[c], b[c]);
        }
      }

      // Scale the pivot row so the pivot becomes 1.
      if (work.At(r, r) != 1) {
        std::uint8_t* row = work.Row(r);
        const std::uint8_t* scale = mul[GaloisInv(row[r])];
        for (int c = 0; c < wide; ++c) {
          row[c] = scale[row[c]];
        }
      }

      // Eliminate the column everywhere else.
      const std::uint8_t* pivot = work.Row(r);
      for (int other = 0; other < n; ++other) {
        if (other == r) {
          continue;
        }
        std::uint8_t* row = work.Row(other);
        const std::uint8_t factor = row[r];
        if (factor == 0) {
          continue;
        }
        const std::uint8_t* factor_row = mul[factor];
        for (int c = 0; c < wide; ++c) {
          row[c] ^= factor_row[pivot[c]];
        }
      }
    }

    Matrix result(n, n);
    for (int r = 0; r < n; ++r) {
      for (int c = 0; c < n; ++c) {
        result.Set(r, c, work.At(r, n + c));
      }
    }
    *out = result;
    return true;
  }

  Matrix Multiply(const Matrix& right) const {
    Matrix result(rows_, right.cols_);
    const GaloisMulTable& mul = MulTable();
    for (int r = 0; r < rows_; ++r) {
      const std::uint8_t* lhs = Row(r);
      std::uint8_t* dst = result.Row(r);
      for (int i = 0; i < cols_; ++i) {
        if (lhs[i] == 0) {
          continue;
        }
        const std::uint8_t* scaled = mul[lhs[i]];
        const std::uint8_t* rhs = right.Row(i);
        for (int c = 0; c < right.cols_; ++c) {
          dst[c] ^= scaled[rhs[c]];
        }
      }
    }
    return result;
  }

 private:
  int rows_;
  int cols_;
  std::vector<std::uint8_t> data_;
};

// out = sum(coefs[i] * inputs[i]) over GF(2^8), which is exactly what every shard computation in
// the codec reduces to.
void Combine(const std::uint8_t* coefs, const std::vector<const std::uint8_t*>& inputs,
             std::uint8_t* out, std::size_t bytes) {
  const GaloisMulTable& mul = MulTable();
  std::memset(out, 0, bytes);
  for (std::size_t i = 0; i < inputs.size(); ++i) {
    const std::uint8_t* in = inputs[i];
    if (in == nullptr || coefs[i] == 0) {
      continue;
    }
    const std::uint8_t* scaled = mul[coefs[i]];
    for (std::size_t b = 0; b < bytes; ++b) {
      out[b] ^= scaled[in[b]];
    }
  }
}

}  // namespace

std::unique_ptr<ReedSolomon> ReedSolomon::New(int data_shards, int parity_shards) {
  if (data_shards < 1 || parity_shards < 0) {
    return nullptr;
  }
  if (data_shards + parity_shards > kGaloisMaxShards) {
    return nullptr;
  }
  std::unique_ptr<ReedSolomon> codec(new ReedSolomon(data_shards, parity_shards));
  if (!codec->BuildMatrix()) {
    return nullptr;
  }
  return codec;
}

ReedSolomon::ReedSolomon(int data_shards, int parity_shards)
    : data_shards_(data_shards), parity_shards_(parity_shards) {}

bool ReedSolomon::BuildMatrix() {
  Matrix vm = Matrix::Vandermonde(total_shards(), data_shards_);
  Matrix top = vm.SubMatrix(0, 0, data_shards_, data_shards_);
  Matrix top_inv;
  if (!top.Invert(&top_inv)) {
    return false;
  }
  Matrix result = vm.Multiply(top_inv);
  matrix_ = result.data();
  return true;
}

ErrorCode ReedSolomon::Encode(ShardSet* shards) const {
  if (shards == nullptr || shards->size() != static_cast<std::size_t>(total_shards())) {
    return ErrorCode::kInvalidArgument;
  }
  std::size_t shard_size = 0;
  for (int i = 0; i < total_shards(); ++i) {
    const std::vector<std::uint8_t>& shard = (*shards)[static_cast<std::size_t>(i)];
    if (shard.empty()) {
      return ErrorCode::kInvalidArgument;
    }
    if (shard_size == 0) {
      shard_size = shard.size();
    } else if (shard.size() != shard_size) {
      return ErrorCode::kInvalidArgument;
    }
  }
  if (shard_size == 0) {
    return ErrorCode::kInvalidArgument;
  }

  std::vector<const std::uint8_t*> inputs(static_cast<std::size_t>(data_shards_));
  for (int i = 0; i < data_shards_; ++i) {
    inputs[static_cast<std::size_t>(i)] = (*shards)[static_cast<std::size_t>(i)].data();
  }
  for (int j = 0; j < parity_shards_; ++j) {
    const std::uint8_t* coefs =
        matrix_.data() + static_cast<std::size_t>(data_shards_ + j) * data_shards_;
    Combine(coefs, inputs, (*shards)[static_cast<std::size_t>(data_shards_ + j)].data(),
            shard_size);
  }
  return ErrorCode::kOk;
}

ErrorCode ReedSolomon::ReconstructData(ShardSet* shards) const {
  return ReconstructImpl(shards, /*data_only=*/true);
}

ErrorCode ReedSolomon::Reconstruct(ShardSet* shards) const {
  return ReconstructImpl(shards, /*data_only=*/false);
}

ErrorCode ReedSolomon::ReconstructImpl(ShardSet* shards, bool data_only) const {
  if (shards == nullptr || shards->size() != static_cast<std::size_t>(total_shards())) {
    return ErrorCode::kInvalidArgument;
  }

  std::size_t shard_size = 0;
  int present = 0;
  int data_present = 0;
  for (int i = 0; i < total_shards(); ++i) {
    const std::vector<std::uint8_t>& shard = (*shards)[static_cast<std::size_t>(i)];
    if (shard.empty()) {
      continue;
    }
    if (shard_size == 0) {
      shard_size = shard.size();
    } else if (shard.size() != shard_size) {
      return ErrorCode::kInvalidArgument;
    }
    ++present;
    if (i < data_shards_) {
      ++data_present;
    }
  }

  // Same early-outs as reedsolomon.go:1186-1197: nothing to do when the requested shards are all
  // present.
  if (data_only && data_present == data_shards_) {
    return ErrorCode::kOk;
  }
  if (!data_only && present == total_shards()) {
    return ErrorCode::kOk;
  }
  if (present < data_shards_ || shard_size == 0) {
    return ErrorCode::kFecRecoverFailed;
  }

  // Collect the first data_shards present rows; they form an invertible square submatrix of the
  // encoding matrix because it is MDS.
  std::vector<const std::uint8_t*> sub_shards;
  sub_shards.reserve(static_cast<std::size_t>(data_shards_));
  std::vector<int> valid_indices;
  valid_indices.reserve(static_cast<std::size_t>(data_shards_));
  for (int row = 0; row < total_shards() && static_cast<int>(valid_indices.size()) < data_shards_;
       ++row) {
    const std::vector<std::uint8_t>& shard = (*shards)[static_cast<std::size_t>(row)];
    if (shard.empty()) {
      continue;
    }
    sub_shards.push_back(shard.data());
    valid_indices.push_back(row);
  }

  Matrix sub(static_cast<int>(valid_indices.size()), data_shards_);
  for (int r = 0; r < static_cast<int>(valid_indices.size()); ++r) {
    for (int c = 0; c < data_shards_; ++c) {
      sub.Set(r, c, MatrixAt(valid_indices[static_cast<std::size_t>(r)], c));
    }
  }
  Matrix decode_matrix;
  if (!sub.Invert(&decode_matrix)) {
    // Unreachable for an MDS matrix, but a silent wrong answer would be far worse than a drop.
    return ErrorCode::kFecRecoverFailed;
  }

  for (int i = 0; i < data_shards_; ++i) {
    std::vector<std::uint8_t>& shard = (*shards)[static_cast<std::size_t>(i)];
    if (!shard.empty()) {
      continue;
    }
    shard.assign(shard_size, 0);
    Combine(decode_matrix.Row(i), sub_shards, shard.data(), shard_size);
  }

  if (data_only) {
    return ErrorCode::kOk;
  }

  // With the data shards whole again, the missing parity shards are a plain re-encode.
  std::vector<const std::uint8_t*> data_shards(static_cast<std::size_t>(data_shards_));
  for (int i = 0; i < data_shards_; ++i) {
    data_shards[static_cast<std::size_t>(i)] = (*shards)[static_cast<std::size_t>(i)].data();
  }
  for (int j = 0; j < parity_shards_; ++j) {
    const std::size_t index = static_cast<std::size_t>(data_shards_ + j);
    if (!(*shards)[index].empty()) {
      continue;
    }
    (*shards)[index].assign(shard_size, 0);
    const std::uint8_t* coefs = matrix_.data() + index * static_cast<std::size_t>(data_shards_);
    Combine(coefs, data_shards, (*shards)[index].data(), shard_size);
  }
  return ErrorCode::kOk;
}

}  // namespace internal
}  // namespace kcp
