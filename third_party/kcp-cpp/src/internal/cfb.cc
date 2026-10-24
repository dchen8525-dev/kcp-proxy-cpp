// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/cfb.h"

#include <cstring>

#include "kcp/internal/constants.h"

namespace kcp {
namespace internal {
namespace {

// Largest supported block is 16 bytes (AES); the feedback register never needs more.
constexpr std::size_t kMaxBlockSize = 16;

}  // namespace

void CfbEncrypt(const BlockCipher& cipher, std::uint8_t* dst, const std::uint8_t* src,
                std::size_t len) {
  if (len == 0) {
    return;
  }
  const std::size_t block = cipher.block_size();
  std::uint8_t tbl[kMaxBlockSize];
  // Block ciphers shorter than 16 bytes read only their own block size from the IV, exactly like
  // block.Encrypt(tbl, initialVector) on an 8-byte cipher (crypt.go:349).
  cipher.EncryptBlock(tbl, kInitialVector);

  const std::size_t full = len / block;
  for (std::size_t i = 0; i < full; ++i) {
    std::uint8_t* out = dst + i * block;
    const std::uint8_t* in = src + i * block;
    for (std::size_t j = 0; j < block; ++j) {
      out[j] = static_cast<std::uint8_t>(in[j] ^ tbl[j]);
    }
    cipher.EncryptBlock(tbl, out);
  }

  // Tail: pure XOR against the current feedback, no further encryption (#43).
  const std::size_t tail = len - full * block;
  for (std::size_t j = 0; j < tail; ++j) {
    dst[full * block + j] = static_cast<std::uint8_t>(src[full * block + j] ^ tbl[j]);
  }
}

void CfbDecrypt(const BlockCipher& cipher, std::uint8_t* dst, const std::uint8_t* src,
                std::size_t len) {
  if (len == 0) {
    return;
  }
  const std::size_t block = cipher.block_size();
  std::uint8_t tbl[kMaxBlockSize];
  cipher.EncryptBlock(tbl, kInitialVector);

  const std::size_t full = len / block;
  for (std::size_t i = 0; i < full; ++i) {
    std::uint8_t* out = dst + i * block;
    const std::uint8_t* in = src + i * block;
    // Feedback is the ciphertext (the input), so it must be captured before dst overwrites src
    // when the two alias.
    std::uint8_t ciphertext[kMaxBlockSize];
    std::memcpy(ciphertext, in, block);
    for (std::size_t j = 0; j < block; ++j) {
      out[j] = static_cast<std::uint8_t>(ciphertext[j] ^ tbl[j]);
    }
    cipher.EncryptBlock(tbl, ciphertext);
  }

  const std::size_t tail = len - full * block;
  for (std::size_t j = 0; j < tail; ++j) {
    dst[full * block + j] = static_cast<std::uint8_t>(src[full * block + j] ^ tbl[j]);
  }
}

}  // namespace internal
}  // namespace kcp
