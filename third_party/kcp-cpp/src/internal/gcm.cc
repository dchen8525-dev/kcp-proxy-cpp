// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/gcm.h"

#include <cstring>

namespace kcp {
namespace internal {
namespace {

// Reduction polynomial for GHASH: x^128 + x^7 + x^2 + x + 1 (SP 800-38D 6.3).
//
// Coefficient layout: the most significant bit of byte 0 is the coefficient of x^0, so bit index k
// of the block is the coefficient of x^k. Walking the block as a 128-bit string, multiplying by x
// therefore shifts it toward byte 15 and reduction happens when the last bit leaves the far end.
// x^128 = x^7 + x^2 + x + 1 lands on bit indices 7, 2, 1, 0, i.e. masks 0x01|0x20|0x40|0x80 of
// byte 0 = 0xE1 - the constant every GCM implementation carries around.
constexpr std::uint8_t kReductionByte = 0xe1;

inline void Xor16(std::uint8_t* dst, const std::uint8_t* src) {
  for (int i = 0; i < 16; ++i) {
    dst[i] ^= src[i];
  }
}

// Multiply the value by x inside GF(2^128).
void MulX(std::uint8_t v[16]) {
  const std::uint8_t carry = static_cast<std::uint8_t>(v[15] & 1);
  for (int j = 15; j > 0; --j) {
    v[j] = static_cast<std::uint8_t>((v[j] >> 1) | (v[j - 1] << 7));
  }
  v[0] = static_cast<std::uint8_t>(v[0] >> 1);
  if (carry != 0) {
    v[0] ^= kReductionByte;
  }
}

void StoreBe64(std::uint8_t* p, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    p[i] = static_cast<std::uint8_t>(v >> (56 - 8 * i));
  }
}

// Increments the low 32 bits of a GCM counter block, big-endian, wrapping.
void IncrementCounter(std::uint8_t* counter) {
  for (int i = 15; i >= 12; --i) {
    counter[i] = static_cast<std::uint8_t>(counter[i] + 1);
    if (counter[i] != 0) {
      break;
    }
  }
}

bool ConstantTimeEqual(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) {
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < len; ++i) {
    diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
  }
  return diff == 0;
}

}  // namespace

AesGcm::AesGcm(const std::uint8_t* key, std::size_t key_len, AesBackend backend)
    : aes_(key, key_len, backend) {
  if (!aes_.valid()) {
    return;
  }
  const std::uint8_t zero[kBlockSize] = {};
  std::uint8_t h[kBlockSize];
  aes_.EncryptBlock(h, zero);
  BuildTable(h);
}

void AesGcm::BuildTable(const std::uint8_t h[kBlockSize]) {
  // table_[t][n] = n * H * x^(4t), where nibble t covers block bits 4t..4t+3 and the nibble's most
  // significant bit is the coefficient of x^(4t). One whole-block multiply is then 32 lookups.
  std::uint8_t base[kBlockSize];
  std::memcpy(base, h, kBlockSize);
  for (int t = 0; t < 32; ++t) {
    std::uint8_t power[4][kBlockSize];
    std::memcpy(power[0], base, kBlockSize);
    for (int b = 1; b < 4; ++b) {
      std::memcpy(power[b], power[b - 1], kBlockSize);
      MulX(power[b]);
    }
    for (int n = 1; n < 16; ++n) {
      std::uint8_t acc[kBlockSize] = {};
      for (int b = 0; b < 4; ++b) {
        // Nibble bit b (0x8 is x^(4t), 0x1 is x^(4t+3)) selects power[3 - b].
        if (((n >> b) & 1) != 0) {
          Xor16(acc, power[3 - b]);
        }
      }
      std::memcpy(table_[t][n], acc, kBlockSize);
    }
    for (int i = 0; i < 4; ++i) {
      MulX(base);
    }
  }
}

void AesGcm::Multiply(std::uint8_t z[kBlockSize], const std::uint8_t x[kBlockSize]) const {
  std::uint8_t acc[kBlockSize] = {};
  for (int t = 0; t < 32; ++t) {
    const std::uint8_t byte = x[t >> 1];
    const int nibble = (t & 1) == 0 ? (byte >> 4) : (byte & 0x0f);
    Xor16(acc, table_[t][nibble]);
  }
  std::memcpy(z, acc, kBlockSize);
}

void AesGcm::GHashUpdate(std::uint8_t y[kBlockSize], const std::uint8_t* data,
                         std::size_t len) const {
  std::size_t offset = 0;
  while (len - offset >= kBlockSize) {
    Xor16(y, data + offset);
    Multiply(y, y);
    offset += kBlockSize;
  }
  if (offset < len) {
    std::uint8_t last[kBlockSize] = {};
    std::memcpy(last, data + offset, len - offset);
    Xor16(y, last);
    Multiply(y, y);
  }
}

void AesGcm::GHashFinal(std::uint8_t y[kBlockSize], std::size_t ciphertext_len) const {
  std::uint8_t lengths[kBlockSize] = {};
  // len(A) == 0, so the first eight bytes stay zero.
  StoreBe64(lengths + 8, static_cast<std::uint64_t>(ciphertext_len) * 8);
  Xor16(y, lengths);
  Multiply(y, y);
}

void AesGcm::CtrXor(std::uint8_t* dst, const std::uint8_t* src, std::size_t len,
                    const std::uint8_t counter[kBlockSize]) const {
  std::uint8_t block[kBlockSize];
  std::uint8_t ctr[kBlockSize];
  std::memcpy(ctr, counter, kBlockSize);
  std::size_t offset = 0;
  while (offset < len) {
    aes_.EncryptBlock(block, ctr);
    const std::size_t n = len - offset < kBlockSize ? len - offset : kBlockSize;
    for (std::size_t i = 0; i < n; ++i) {
      dst[offset + i] = static_cast<std::uint8_t>(src[offset + i] ^ block[i]);
    }
    IncrementCounter(ctr);
    offset += n;
  }
}

void AesGcm::Seal(std::uint8_t* dst, const std::uint8_t* nonce, const std::uint8_t* plaintext,
                  std::size_t len) const {
  // J0 = nonce || 0x00000001; payload encryption starts at J0 + 1.
  std::uint8_t j0[kBlockSize];
  std::memcpy(j0, nonce, kNonceSize);
  j0[12] = 0;
  j0[13] = 0;
  j0[14] = 0;
  j0[15] = 1;

  std::uint8_t counter[kBlockSize];
  std::memcpy(counter, j0, kBlockSize);
  IncrementCounter(counter);
  CtrXor(dst, plaintext, len, counter);

  std::uint8_t y[kBlockSize] = {};
  GHashUpdate(y, dst, len);
  GHashFinal(y, len);

  std::uint8_t mask[kBlockSize];
  aes_.EncryptBlock(mask, j0);
  for (int i = 0; i < 16; ++i) {
    dst[len + i] = static_cast<std::uint8_t>(y[i] ^ mask[i]);
  }
}

bool AesGcm::Open(std::uint8_t* dst, const std::uint8_t* nonce, const std::uint8_t* ciphertext,
                  std::size_t len) const {
  if (len < kTagSize) {
    return false;
  }
  const std::size_t body = len - kTagSize;

  std::uint8_t j0[kBlockSize];
  std::memcpy(j0, nonce, kNonceSize);
  j0[12] = 0;
  j0[13] = 0;
  j0[14] = 0;
  j0[15] = 1;

  std::uint8_t y[kBlockSize] = {};
  GHashUpdate(y, ciphertext, body);
  GHashFinal(y, body);
  std::uint8_t mask[kBlockSize];
  aes_.EncryptBlock(mask, j0);
  std::uint8_t expected[kTagSize];
  for (int i = 0; i < 16; ++i) {
    expected[i] = static_cast<std::uint8_t>(y[i] ^ mask[i]);
  }
  if (!ConstantTimeEqual(expected, ciphertext + body, kTagSize)) {
    return false;
  }

  std::uint8_t counter[kBlockSize];
  std::memcpy(counter, j0, kBlockSize);
  IncrementCounter(counter);
  CtrXor(dst, ciphertext, body, counter);
  return true;
}

}  // namespace internal
}  // namespace kcp
