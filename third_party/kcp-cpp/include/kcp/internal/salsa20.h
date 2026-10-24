// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_SALSA20_H_
#define KCP_INTERNAL_SALSA20_H_

#include <cstddef>
#include <cstdint>

namespace kcp {
namespace internal {

// Salsa20 (snuffle 2005) shaped exactly like golang.org/x/crypto/salsa20 when handed an 8-byte
// nonce: the 16-byte input block is nonce(8) || counter(8), the counter starts at zero and lives
// in the high half, incrementing little-endian (salsa20_ref.go:207-216).
class Salsa20 {
 public:
  static constexpr std::size_t kKeySize = 32;
  static constexpr std::size_t kNonceSize = 8;
  static constexpr std::size_t kBlockSize = 64;

  // Keys shorter than 32 bytes are zero padded, longer ones truncated - the same effect as
  // copy(c.key[:], key) at crypt.go:169.
  explicit Salsa20(const std::uint8_t* key, std::size_t key_len);

  // dst = src XOR keystream over len bytes; dst may alias src.
  void XorKeyStream(std::uint8_t* dst, const std::uint8_t* src, std::size_t len,
                    const std::uint8_t nonce[kNonceSize]) const;

 private:
  void Core(std::uint8_t out[kBlockSize], const std::uint32_t input[16]) const;

  std::uint32_t key_[8];
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_SALSA20_H_
