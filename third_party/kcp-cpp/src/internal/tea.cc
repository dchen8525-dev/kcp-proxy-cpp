// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/tea.h"

#include <cstring>

namespace kcp {
namespace internal {
namespace {

inline std::uint32_t LoadBe32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline void StoreBe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}

}  // namespace

Tea::Tea(const std::uint8_t* key, int rounds) : rounds_(rounds) {
  std::uint8_t buf[kKeySize] = {};
  std::memcpy(buf, key, kKeySize);
  for (int i = 0; i < 4; ++i) {
    k_[i] = LoadBe32(buf + 4 * i);
  }
}

void Tea::EncryptBlock(std::uint8_t* dst, const std::uint8_t* src) const {
  // x/crypto/tea is big-endian throughout (tea/cipher.go:83-101).
  std::uint32_t v0 = LoadBe32(src);
  std::uint32_t v1 = LoadBe32(src + 4);
  std::uint32_t sum = 0;
  for (int i = 0; i < rounds_ / 2; ++i) {
    sum += kTeaDelta;
    v0 += ((v1 << 4) + k_[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k_[1]);
    v1 += ((v0 << 4) + k_[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k_[3]);
  }
  StoreBe32(dst, v0);
  StoreBe32(dst + 4, v1);
}

Xtea::Xtea(const std::uint8_t* key) {
  std::uint8_t buf[kKeySize] = {};
  std::memcpy(buf, key, kKeySize);
  std::uint32_t k[4];
  for (int i = 0; i < 4; ++i) {
    k[i] = LoadBe32(buf + 4 * i);
  }
  // xtea/cipher.go:85-93: two rounds share one sum. The even entry is built from the running sum
  // and steps it by delta; the odd entry reuses that same sum with a different key index (bits
  // 11..12 rather than 0..1). Stepping again after the odd entry would desynchronise every later
  // round, which is why the loop below advances once per pair, not twice.
  std::uint32_t sum = 0;
  for (int i = 0; i < kRounds; i += 2) {
    table_[i] = sum + k[sum & 3];
    sum += kTeaDelta;
    table_[i + 1] = sum + k[(sum >> 11) & 3];
  }
}

void Xtea::EncryptBlock(std::uint8_t* dst, const std::uint8_t* src) const {
  std::uint32_t v0 = LoadBe32(src);
  std::uint32_t v1 = LoadBe32(src + 4);
  for (int i = 0; i < kRounds; i += 2) {
    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ table_[i];
    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ table_[i + 1];
  }
  StoreBe32(dst, v0);
  StoreBe32(dst + 4, v1);
}

}  // namespace internal
}  // namespace kcp
