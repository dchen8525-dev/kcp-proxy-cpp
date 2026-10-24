// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/crypt.h"

#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "kcp/internal/aes.h"
#include "kcp/internal/cfb.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/gcm.h"
#include "kcp/internal/primitives.h"
#include "kcp/internal/salsa20.h"
#include "kcp/internal/tea.h"

namespace kcp {
namespace {

// Every block cipher plugs into the same CFB implementation; only block_size() differs.
class CfbBlockCrypt final : public BlockCrypt {
 public:
  explicit CfbBlockCrypt(std::unique_ptr<internal::BlockCipher> cipher)
      : cipher_(std::move(cipher)) {}

  void Encrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    internal::CfbEncrypt(*cipher_, dst, src, len);
  }

  void Decrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    internal::CfbDecrypt(*cipher_, dst, src, len);
  }

 private:
  std::unique_ptr<internal::BlockCipher> cipher_;
};

// crypt.go:289-303 - plain copy, but it must tolerate dst == src like the Go version.
class NoneBlockCrypt final : public BlockCrypt {
 public:
  void Encrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    if (len == 0 || dst == src) {
      return;
    }
    std::memmove(dst, src, len);
  }

  void Decrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    Encrypt(dst, src, len);
  }
};

// crypt.go:262-287 - a PBKDF2-expanded one-time pad of mtuLimit bytes.
class SimpleXorBlockCrypt final : public BlockCrypt {
 public:
  SimpleXorBlockCrypt(const std::uint8_t* key, std::size_t key_len) : xortbl_(kMtuLimit) {
    internal::Pbkdf2HmacSha1(key, key_len, kSaltXor, sizeof(kSaltXor) - 1, kSimpleXorIterations,
                             xortbl_.data(), xortbl_.size());
  }

  void Encrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    if (len == 0) {
      return;
    }
    // subtle.XORBytes stops at the shorter operand, so bytes beyond mtuLimit are left untouched,
    // exactly as in Go. Packets never exceed the MTU, so the cap is unreachable in practice.
    const std::size_t n = len < xortbl_.size() ? len : xortbl_.size();
    for (std::size_t i = 0; i < n; ++i) {
      dst[i] = static_cast<std::uint8_t>(src[i] ^ xortbl_[i]);
    }
  }

  void Decrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    Encrypt(dst, src, len);
  }

 private:
  std::vector<std::uint8_t> xortbl_;
};

// crypt.go:161-186 - not a chaining mode: the first 8 bytes ride along in cleartext and become the
// Salsa20 nonce for the remaining bytes.
class Salsa20BlockCrypt final : public BlockCrypt {
 public:
  Salsa20BlockCrypt(const std::uint8_t* key, std::size_t key_len) : cipher_(key, key_len) {}

  void Encrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    Xor(dst, src, len);
  }

  void Decrypt(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const override {
    Xor(dst, src, len);
  }

 private:
  void Xor(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) const {
    if (len < internal::Salsa20::kNonceSize) {
      return;
    }
    cipher_.XorKeyStream(dst + internal::Salsa20::kNonceSize, src + internal::Salsa20::kNonceSize,
                         len - internal::Salsa20::kNonceSize, src);
    if (dst != src) {
      std::memcpy(dst, src, internal::Salsa20::kNonceSize);
    }
  }

  internal::Salsa20 cipher_;
};

class AeadBlockCrypt final : public AeadCrypt {
 public:
  AeadBlockCrypt(const std::uint8_t* key, std::size_t key_len) : gcm_(key, key_len) {}

  bool valid() const { return gcm_.valid(); }

  std::size_t nonce_size() const override { return gcm_.nonce_size(); }
  std::size_t overhead() const override { return gcm_.overhead(); }

  ErrorCode Seal(std::uint8_t* dst, std::size_t dst_capacity, const std::uint8_t* nonce,
                 const std::uint8_t* plaintext, std::size_t len) const override {
    if (dst == nullptr || dst_capacity < len + gcm_.overhead()) {
      return ErrorCode::kBufferTooSmall;
    }
    gcm_.Seal(dst, nonce, plaintext, len);
    return ErrorCode::kOk;
  }

  ErrorCode Open(std::uint8_t* dst, std::size_t dst_capacity, const std::uint8_t* nonce,
                 const std::uint8_t* ciphertext, std::size_t len) const override {
    if (len < gcm_.overhead()) {
      return ErrorCode::kIntegrityFailed;
    }
    if (dst == nullptr || dst_capacity < len - gcm_.overhead()) {
      return ErrorCode::kBufferTooSmall;
    }
    return gcm_.Open(dst, nonce, ciphertext, len) ? ErrorCode::kOk : ErrorCode::kIntegrityFailed;
  }

 private:
  internal::AesGcm gcm_;
};

bool IsValidBlockKey(std::size_t len) { return len == 16 || len == 24 || len == 32; }

}  // namespace

std::shared_ptr<BlockCrypt> NewNoneBlockCrypt(const std::uint8_t* key, std::size_t key_len) {
  static_cast<void>(key);
  static_cast<void>(key_len);
  return std::make_shared<NoneBlockCrypt>();
}

std::shared_ptr<BlockCrypt> NewSimpleXorBlockCrypt(const std::uint8_t* key, std::size_t key_len) {
  return std::make_shared<SimpleXorBlockCrypt>(key, key_len);
}

std::shared_ptr<BlockCrypt> NewTeaBlockCrypt(const std::uint8_t* key, std::size_t key_len) {
  if (key_len != internal::Tea::kKeySize) {
    return nullptr;
  }
  return std::make_shared<CfbBlockCrypt>(
      std::make_unique<internal::Tea>(key, internal::Tea::kKcpRounds));
}

std::shared_ptr<BlockCrypt> NewXteaBlockCrypt(const std::uint8_t* key, std::size_t key_len) {
  if (key_len != internal::Xtea::kKeySize) {
    return nullptr;
  }
  return std::make_shared<CfbBlockCrypt>(std::make_unique<internal::Xtea>(key));
}

std::shared_ptr<BlockCrypt> NewSalsa20BlockCrypt(const std::uint8_t* key, std::size_t key_len) {
  return std::make_shared<Salsa20BlockCrypt>(key, key_len);
}

std::shared_ptr<BlockCrypt> NewAesBlockCrypt(const std::uint8_t* key, std::size_t key_len) {
  if (!IsValidBlockKey(key_len)) {
    return nullptr;
  }
  auto aes = std::make_unique<internal::Aes>(key, key_len);
  if (!aes->valid()) {
    return nullptr;
  }
  return std::make_shared<CfbBlockCrypt>(std::move(aes));
}

std::shared_ptr<AeadCrypt> NewAesGcmCrypt(const std::uint8_t* key, std::size_t key_len) {
  if (!IsValidBlockKey(key_len)) {
    return nullptr;
  }
  auto crypt = std::make_shared<AeadBlockCrypt>(key, key_len);
  if (!crypt->valid()) {
    return nullptr;
  }
  return crypt;
}

std::shared_ptr<AeadCrypt> NewAeadCrypt(std::shared_ptr<AeadCrypt> aead) { return aead; }

}  // namespace kcp
