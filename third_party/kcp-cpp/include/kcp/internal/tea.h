// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_TEA_H_
#define KCP_INTERNAL_TEA_H_

#include <cstddef>
#include <cstdint>

#include "kcp/internal/block_cipher.h"

namespace kcp {
namespace internal {

// Key schedule constant shared by TEA and XTEA.
constexpr std::uint32_t kTeaDelta = 0x9e3779b9u;

// TEA as instantiated by kcp-go. Note the round count: x/crypto/tea defaults to 64, but
// crypt.go:246 calls tea.NewCipherWithRounds(key, 16), so 16 is what the wire format uses.
class Tea final : public BlockCipher {
 public:
  static constexpr std::size_t kBlockSize = 8;
  static constexpr std::size_t kKeySize = 16;
  static constexpr int kKcpRounds = 16;

  explicit Tea(const std::uint8_t* key, int rounds = kKcpRounds);

  std::size_t block_size() const override { return kBlockSize; }
  void EncryptBlock(std::uint8_t* dst, const std::uint8_t* src) const override;

 private:
  std::uint32_t k_[4];
  int rounds_;
};

// XTEA (Needham-Wheeler 1997), 64 rounds with the table of precalculated round sums that
// x/crypto/xtea builds in initCipher.
class Xtea final : public BlockCipher {
 public:
  static constexpr std::size_t kBlockSize = 8;
  static constexpr std::size_t kKeySize = 16;
  static constexpr int kRounds = 64;

  explicit Xtea(const std::uint8_t* key);

  std::size_t block_size() const override { return kBlockSize; }
  void EncryptBlock(std::uint8_t* dst, const std::uint8_t* src) const override;

 private:
  std::uint32_t table_[kRounds];
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_TEA_H_
