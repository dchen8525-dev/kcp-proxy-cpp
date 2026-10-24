// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_CRYPT_H_
#define KCP_CRYPT_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "kcp/error.h"

namespace kcp {

// The two encryption interfaces of PORTING-PLAN.md §3.8 (#44).
//
// Go declares a single BlockCrypt interface whose Encrypt/Decrypt panic for AEAD instances; C++
// splits it so the mistake is a compile error instead of a runtime panic.
//
// Deviation D9: Go keeps a per-instance working buffer behind a mutex (crypt.go:130-158). This
// port keeps the CFB feedback register on the stack instead, so implementations hold no mutable
// state, Encrypt/Decrypt are const, and the L1 lock of §3.5 disappears.

class BlockCrypt {
 public:
  virtual ~BlockCrypt() = default;

  // Encrypts len bytes. The first kCryptHeaderSize bytes of src are the random nonce header and
  // are encrypted like any other plaintext (whole-packet CFB, §4.2). dst may alias src exactly.
  virtual void Encrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const = 0;

  // Inverse of Encrypt; same aliasing rules.
  virtual void Decrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const = 0;
};

class AeadCrypt {
 public:
  virtual ~AeadCrypt() = default;

  // Cheap accessors, hence snake_case.
  virtual std::size_t nonce_size() const = 0;
  virtual std::size_t overhead() const = 0;

  // Writes len + overhead() bytes to dst. Returns kBufferTooSmall when dst_capacity cannot hold
  // the result - Go panics there (crypt.go:83), deviation D1.
  virtual ErrorCode Seal(std::uint8_t* dst, std::size_t dst_capacity, const std::uint8_t* nonce,
                         const std::uint8_t* plaintext, std::size_t len) const = 0;

  // len is the full ciphertext length including the tag. Returns kIntegrityFailed when the tag
  // does not verify, kBufferTooSmall when dst_capacity is short.
  virtual ErrorCode Open(std::uint8_t* dst, std::size_t dst_capacity, const std::uint8_t* nonce,
                         const std::uint8_t* ciphertext, std::size_t len) const = 0;
};

// Factories mirroring crypt.go. Each returns nullptr when the key length is wrong (16/24/32 for
// AES, 16 for TEA/XTEA; Salsa20 and SimpleXOR accept any length and pad or truncate, exactly like
// the Go constructors do with copy()).

std::shared_ptr<BlockCrypt> NewNoneBlockCrypt(const std::uint8_t* key, std::size_t key_len);
std::shared_ptr<BlockCrypt> NewSimpleXorBlockCrypt(const std::uint8_t* key, std::size_t key_len);
std::shared_ptr<BlockCrypt> NewTeaBlockCrypt(const std::uint8_t* key, std::size_t key_len);
std::shared_ptr<BlockCrypt> NewXteaBlockCrypt(const std::uint8_t* key, std::size_t key_len);
std::shared_ptr<BlockCrypt> NewSalsa20BlockCrypt(const std::uint8_t* key, std::size_t key_len);
std::shared_ptr<BlockCrypt> NewAesBlockCrypt(const std::uint8_t* key, std::size_t key_len);

std::shared_ptr<AeadCrypt> NewAesGcmCrypt(const std::uint8_t* key, std::size_t key_len);

// crypt.go:103 - adapts an externally supplied AEAD. In C++ AeadCrypt *is* the interface, so this
// is the identity; it exists so Go call sites map one to one.
std::shared_ptr<AeadCrypt> NewAeadCrypt(std::shared_ptr<AeadCrypt> aead);

}  // namespace kcp

#endif  // KCP_CRYPT_H_
