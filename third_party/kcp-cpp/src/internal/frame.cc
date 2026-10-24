// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/frame.h"

#include <cstring>

#include "kcp/internal/byteorder.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/primitives.h"
#include "kcp/platform/entropy_backend.h"

namespace kcp {
namespace internal {

std::size_t CipherHeaderSize(BlockCrypt* block, AeadCrypt* aead) {
  if (aead != nullptr) {
    return aead->nonce_size();
  }
  if (block != nullptr) {
    return kCryptHeaderSize;
  }
  return 0;
}

std::size_t EncryptInPlace(BlockCrypt* block, AeadCrypt* aead, std::uint8_t* buf, std::size_t size,
                           std::size_t capacity, const std::uint8_t* fixed_nonce) {
  if (aead != nullptr) {
    const std::size_t nonce_size = aead->nonce_size();
    const std::size_t overhead = aead->overhead();
    if (size < nonce_size || capacity < size + overhead) {
      return 0;
    }
    if (fixed_nonce != nullptr) {
      std::memcpy(buf, fixed_nonce, nonce_size);
    } else {
      platform::FillRand(buf, nonce_size);
    }
    // Seal writes at dst, not "appends to dst": the ciphertext starts after the nonce, exactly
    // where the plaintext was. Go expresses this as Seal(dst=buf[:nonceSize], ...), which appends
    // to that slice's length.
    const ErrorCode rc = aead->Seal(buf + nonce_size, capacity - nonce_size, buf, buf + nonce_size,
                                    size - nonce_size);
    return rc == ErrorCode::kOk ? size + overhead : 0;
  }

  if (block != nullptr) {
    if (size < kCryptHeaderSize) {
      return 0;
    }
    if (fixed_nonce != nullptr) {
      std::memcpy(buf, fixed_nonce, kNonceSize);
    } else {
      platform::FillRand(buf, kNonceSize);
    }
    // sess.go:735 - checksum covers everything after the nonce+CRC pair, i.e. the FEC header and
    // the KCP segment, and is stored little-endian at [16, 20).
    const std::uint32_t checksum = Crc32(buf + kCryptHeaderSize, size - kCryptHeaderSize);
    WriteLe32(buf + kNonceSize, checksum);
    block->Encrypt(buf, buf, size);
    return size;
  }

  return size;
}

OpenResult OpenInPlace(BlockCrypt* block, AeadCrypt* aead, std::uint8_t** data, std::size_t* len) {
  std::uint8_t* buf = *data;
  std::size_t size = *len;

  if (aead != nullptr) {
    const std::size_t nonce_size = aead->nonce_size();
    const std::size_t overhead = aead->overhead();
    if (size < nonce_size + overhead) {
      return OpenResult::kDropped;
    }
    // sess.go:976-988 - plaintext overwrites the ciphertext, nonce stays at the front.
    std::uint8_t* plain = buf + nonce_size;
    const std::size_t cipher_len = size - nonce_size;
    if (aead->Open(plain, cipher_len - overhead, buf, plain, cipher_len) != ErrorCode::kOk) {
      return OpenResult::kIntegrityFailed;
    }
    *data = plain;
    *len = cipher_len - overhead;
    return OpenResult::kOk;
  }

  if (block != nullptr) {
    if (size < kCryptHeaderSize) {
      return OpenResult::kDropped;
    }
    block->Decrypt(buf, buf, size);
    // sess.go:992-1004 - drop the nonce, then the 4-byte checksum in front of the payload.
    std::uint8_t* body = buf + kNonceSize;
    const std::size_t body_len = size - kNonceSize;
    const std::uint32_t checksum = Crc32(body + kCrcSize, body_len - kCrcSize);
    if (checksum != ReadLe32(body)) {
      return OpenResult::kIntegrityFailed;
    }
    *data = body + kCrcSize;
    *len = body_len - kCrcSize;
    return OpenResult::kOk;
  }

  return OpenResult::kOk;
}

}  // namespace internal
}  // namespace kcp
