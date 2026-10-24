// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/primitives.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace kcp {
namespace internal {
namespace {

constexpr std::uint32_t RotateLeft(std::uint32_t value, int bits) {
  return (value << bits) | (value >> (32 - bits));
}

const std::array<std::uint32_t, 256>& Crc32Table() {
  // Reflected CRC-32 table; identical to Go's crc32.MakeTable(crc32.IEEE).
  static const std::array<std::uint32_t, 256> table = [] {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t c = i;
      for (int bit = 0; bit < 8; ++bit) {
        c = (c & 1u) != 0 ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
      }
      t[i] = c;
    }
    return t;
  }();
  return table;
}

}  // namespace

std::uint32_t Crc32Update(std::uint32_t seed, const void* data, std::size_t len) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  const auto& table = Crc32Table();
  std::uint32_t crc = ~seed;
  for (std::size_t i = 0; i < len; ++i) {
    crc = table[(crc ^ bytes[i]) & 0xffu] ^ (crc >> 8);
  }
  return ~crc;
}

std::uint32_t Crc32(const void* data, std::size_t len) { return Crc32Update(0, data, len); }

Sha1::Sha1() {
  h_[0] = 0x67452301u;
  h_[1] = 0xefcdab89u;
  h_[2] = 0x98badcfeu;
  h_[3] = 0x10325476u;
  h_[4] = 0xc3d2e1f0u;
}

void Sha1::ProcessBlock(const std::uint8_t block[kBlockSize]) {
  std::uint32_t w[80];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (int i = 16; i < 80; ++i) {
    w[i] = RotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }

  std::uint32_t a = h_[0];
  std::uint32_t b = h_[1];
  std::uint32_t c = h_[2];
  std::uint32_t d = h_[3];
  std::uint32_t e = h_[4];

  for (int i = 0; i < 80; ++i) {
    std::uint32_t f = 0;
    std::uint32_t k = 0;
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5a827999u;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ed9eba1u;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8f1bbcdcu;
    } else {
      f = b ^ c ^ d;
      k = 0xca62c1d6u;
    }
    const std::uint32_t tmp = RotateLeft(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = RotateLeft(b, 30);
    b = a;
    a = tmp;
  }

  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
}

void Sha1::Update(const void* data, std::size_t len) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  total_len_ += len;

  if (buffer_len_ > 0) {
    const std::size_t take = std::min(kBlockSize - buffer_len_, len);
    std::memcpy(buffer_ + buffer_len_, bytes, take);
    buffer_len_ += take;
    bytes += take;
    len -= take;
    if (buffer_len_ == kBlockSize) {
      ProcessBlock(buffer_);
      buffer_len_ = 0;
    }
  }

  while (len >= kBlockSize) {
    ProcessBlock(bytes);
    bytes += kBlockSize;
    len -= kBlockSize;
  }

  if (len > 0) {
    std::memcpy(buffer_, bytes, len);
    buffer_len_ = len;
  }
}

void Sha1::Final(std::uint8_t digest[kDigestSize]) {
  // Length in bits must be captured before padding mutates total_len_.
  const std::uint64_t bit_len = total_len_ * 8;

  const std::uint8_t pad = 0x80;
  Update(&pad, 1);
  const std::uint8_t zero = 0;
  while (buffer_len_ != kBlockSize - 8) {
    Update(&zero, 1);
  }

  std::uint8_t length_bytes[8];
  for (int i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>(bit_len >> (56 - i * 8));
  }
  Update(length_bytes, sizeof(length_bytes));

  for (int i = 0; i < 5; ++i) {
    digest[i * 4] = static_cast<std::uint8_t>(h_[i] >> 24);
    digest[i * 4 + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
    digest[i * 4 + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
    digest[i * 4 + 3] = static_cast<std::uint8_t>(h_[i]);
  }

  *this = Sha1();
}

void Sha1::Compute(const void* data, std::size_t len, std::uint8_t digest[kDigestSize]) {
  Sha1 sha;
  sha.Update(data, len);
  sha.Final(digest);
}

void HmacSha1(const void* key, std::size_t key_len, const void* data, std::size_t data_len,
              std::uint8_t digest[Sha1::kDigestSize]) {
  std::uint8_t key_block[Sha1::kBlockSize] = {0};
  if (key_len > Sha1::kBlockSize) {
    // Long keys are hashed down to kDigestSize bytes, zero-padded to a block.
    Sha1::Compute(key, key_len, key_block);
  } else {
    std::memcpy(key_block, key, key_len);
  }

  std::uint8_t inner_pad[Sha1::kBlockSize];
  std::uint8_t outer_pad[Sha1::kBlockSize];
  for (std::size_t i = 0; i < Sha1::kBlockSize; ++i) {
    inner_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36);
    outer_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5c);
  }

  std::uint8_t inner_digest[Sha1::kDigestSize];
  Sha1 inner;
  inner.Update(inner_pad, sizeof(inner_pad));
  inner.Update(data, data_len);
  inner.Final(inner_digest);

  Sha1 outer;
  outer.Update(outer_pad, sizeof(outer_pad));
  outer.Update(inner_digest, sizeof(inner_digest));
  outer.Final(digest);
}

bool Pbkdf2HmacSha1(const void* password, std::size_t password_len, const void* salt,
                    std::size_t salt_len, int iterations, std::uint8_t* out, std::size_t out_len) {
  if (iterations < 1) {
    // golang.org/x/crypto/pbkdf2 clamps to 1; a caller passing 0 is a bug, so report it instead.
    return false;
  }

  constexpr std::size_t kDigestLen = Sha1::kDigestSize;
  const auto* salt_bytes = static_cast<const std::uint8_t*>(salt);

  // salt || INT32BE(block_index), built once and reused across blocks.
  std::vector<std::uint8_t> message(salt_len + 4);
  if (salt_len > 0) {
    std::memcpy(message.data(), salt_bytes, salt_len);
  }

  std::uint8_t u[kDigestLen];
  std::uint8_t t[kDigestLen];
  for (std::uint32_t block = 1; out_len > 0; ++block) {
    message[salt_len] = static_cast<std::uint8_t>(block >> 24);
    message[salt_len + 1] = static_cast<std::uint8_t>(block >> 16);
    message[salt_len + 2] = static_cast<std::uint8_t>(block >> 8);
    message[salt_len + 3] = static_cast<std::uint8_t>(block);

    HmacSha1(password, password_len, message.data(), message.size(), u);
    std::memcpy(t, u, kDigestLen);

    for (int iter = 1; iter < iterations; ++iter) {
      std::uint8_t next[kDigestLen];
      HmacSha1(password, password_len, u, kDigestLen, next);
      std::memcpy(u, next, kDigestLen);
      for (std::size_t i = 0; i < kDigestLen; ++i) {
        t[i] ^= u[i];
      }
    }

    const std::size_t take = std::min(kDigestLen, out_len);
    std::memcpy(out, t, take);
    out += take;
    out_len -= take;
  }
  return true;
}

}  // namespace internal
}  // namespace kcp
