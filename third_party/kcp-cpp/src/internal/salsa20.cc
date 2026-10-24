// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/salsa20.h"

#include <cstring>

namespace kcp {
namespace internal {
namespace {

// "expand 32-byte k" as four little-endian words (salsa20_ref.go:12, salsa/salsa.go Sigma).
constexpr std::uint32_t kSigma[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
constexpr int kRounds = 20;

inline std::uint32_t Rotl32(std::uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

inline std::uint32_t LoadLe32(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void StoreLe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v);
  p[1] = static_cast<std::uint8_t>(v >> 8);
  p[2] = static_cast<std::uint8_t>(v >> 16);
  p[3] = static_cast<std::uint8_t>(v >> 24);
}

}  // namespace

Salsa20::Salsa20(const std::uint8_t* key, std::size_t key_len) {
  std::uint8_t buf[kKeySize] = {};
  std::memcpy(buf, key, key_len < kKeySize ? key_len : kKeySize);
  for (int i = 0; i < 8; ++i) {
    key_[i] = LoadLe32(buf + 4 * i);
  }
}

void Salsa20::Core(std::uint8_t out[kBlockSize], const std::uint32_t input[16]) const {
  std::uint32_t x0 = input[0];
  std::uint32_t x1 = input[1];
  std::uint32_t x2 = input[2];
  std::uint32_t x3 = input[3];
  std::uint32_t x4 = input[4];
  std::uint32_t x5 = input[5];
  std::uint32_t x6 = input[6];
  std::uint32_t x7 = input[7];
  std::uint32_t x8 = input[8];
  std::uint32_t x9 = input[9];
  std::uint32_t x10 = input[10];
  std::uint32_t x11 = input[11];
  std::uint32_t x12 = input[12];
  std::uint32_t x13 = input[13];
  std::uint32_t x14 = input[14];
  std::uint32_t x15 = input[15];

  for (int i = 0; i < kRounds; i += 2) {
    x4 ^= Rotl32(x0 + x12, 7);
    x8 ^= Rotl32(x4 + x0, 9);
    x12 ^= Rotl32(x8 + x4, 13);
    x0 ^= Rotl32(x12 + x8, 18);
    x9 ^= Rotl32(x5 + x1, 7);
    x13 ^= Rotl32(x9 + x5, 9);
    x1 ^= Rotl32(x13 + x9, 13);
    x5 ^= Rotl32(x1 + x13, 18);
    x14 ^= Rotl32(x10 + x6, 7);
    x2 ^= Rotl32(x14 + x10, 9);
    x6 ^= Rotl32(x2 + x14, 13);
    x10 ^= Rotl32(x6 + x2, 18);
    x3 ^= Rotl32(x15 + x11, 7);
    x7 ^= Rotl32(x3 + x15, 9);
    x11 ^= Rotl32(x7 + x3, 13);
    x15 ^= Rotl32(x11 + x7, 18);

    x1 ^= Rotl32(x0 + x3, 7);
    x2 ^= Rotl32(x1 + x0, 9);
    x3 ^= Rotl32(x2 + x1, 13);
    x0 ^= Rotl32(x3 + x2, 18);
    x6 ^= Rotl32(x5 + x4, 7);
    x7 ^= Rotl32(x6 + x5, 9);
    x4 ^= Rotl32(x7 + x6, 13);
    x5 ^= Rotl32(x4 + x7, 18);
    x11 ^= Rotl32(x10 + x9, 7);
    x8 ^= Rotl32(x11 + x10, 9);
    x9 ^= Rotl32(x8 + x11, 13);
    x10 ^= Rotl32(x9 + x8, 18);
    x12 ^= Rotl32(x15 + x14, 7);
    x13 ^= Rotl32(x12 + x15, 9);
    x14 ^= Rotl32(x13 + x12, 13);
    x15 ^= Rotl32(x14 + x13, 18);
  }

  const std::uint32_t sum[16] = {
      x0 + input[0],   x1 + input[1],   x2 + input[2],   x3 + input[3],
      x4 + input[4],   x5 + input[5],   x6 + input[6],   x7 + input[7],
      x8 + input[8],   x9 + input[9],   x10 + input[10], x11 + input[11],
      x12 + input[12], x13 + input[13], x14 + input[14], x15 + input[15]};
  for (int i = 0; i < 16; ++i) {
    StoreLe32(out + 4 * i, sum[i]);
  }
}

void Salsa20::XorKeyStream(std::uint8_t* dst, const std::uint8_t* src, std::size_t len,
                           const std::uint8_t nonce[kNonceSize]) const {
  std::uint32_t input[16];
  input[0] = kSigma[0];
  input[5] = kSigma[1];
  input[10] = kSigma[2];
  input[15] = kSigma[3];
  for (int i = 0; i < 4; ++i) {
    input[1 + i] = key_[i];
    input[11 + i] = key_[4 + i];
  }
  // Bytes 4..11 of the input block are the nonce; 12..15 are the low half of the counter and stay
  // zero, which is what an 8-byte nonce means for Salsa20 (salsa20.go:56-57).
  std::uint8_t nonce_block[16] = {};
  std::memcpy(nonce_block, nonce, kNonceSize);
  for (int i = 0; i < 4; ++i) {
    input[6 + i] = LoadLe32(nonce_block + 4 * i);
  }
  input[8] = 0;
  input[9] = 0;

  std::uint8_t block[kBlockSize];
  std::size_t offset = 0;
  while (offset < len) {
    Core(block, input);
    const std::size_t n = len - offset < kBlockSize ? len - offset : kBlockSize;
    for (std::size_t i = 0; i < n; ++i) {
      dst[offset + i] = static_cast<std::uint8_t>(src[offset + i] ^ block[i]);
    }
    // 64-bit counter increments little-endian over input[8], input[9].
    if (++input[8] == 0) {
      ++input[9];
    }
    offset += n;
  }
}

}  // namespace internal
}  // namespace kcp
