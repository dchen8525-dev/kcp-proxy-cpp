// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_GCM_H_
#define KCP_INTERNAL_GCM_H_

#include <cstddef>
#include <cstdint>

#include "kcp/internal/aes.h"

namespace kcp {
namespace internal {

// AES-GCM as configured by cipher.NewGCM(aes): 12-byte nonce, 16-byte tag, no additional data
// (kcp-go passes nil at sess.go:718,726).
//
// GHASH runs off a 32x16 nibble table of H*x^(4k) so one 128-bit multiply costs 32 table lookups
// instead of 128 conditional reductions - the same trick OpenSSL's gcm_init_4bit uses, just with
// the table indexed per position instead of per nibble value.
class AesGcm {
 public:
  static constexpr std::size_t kNonceSize = 12;
  static constexpr std::size_t kTagSize = 16;
  static constexpr std::size_t kBlockSize = 16;

  // key_len must be 16, 24 or 32; valid() reports whether construction succeeded. `backend` selects
  // the AES path (decision 6); it mirrors Aes's constructor so the test suite and bench/ can drive
  // both backends on one machine and prove they agree.
  explicit AesGcm(const std::uint8_t* key, std::size_t key_len,
                  AesBackend backend = AesBackend::kAuto);

  bool valid() const { return aes_.valid(); }
  bool using_ni() const { return aes_.using_ni(); }
  std::size_t nonce_size() const { return kNonceSize; }
  std::size_t overhead() const { return kTagSize; }

  // Writes len + kTagSize bytes to dst. dst may alias plaintext exactly; partial overlap is not
  // supported. Caller must ensure the output capacity, see AeadCrypt::Seal in kcp/crypt.h.
  void Seal(std::uint8_t* dst, const std::uint8_t* nonce, const std::uint8_t* plaintext,
            std::size_t len) const;

  // Returns false when the tag does not verify, in which case dst holds unspecified bytes.
  bool Open(std::uint8_t* dst, const std::uint8_t* nonce, const std::uint8_t* ciphertext,
            std::size_t len) const;

 private:
  void BuildTable(const std::uint8_t h[kBlockSize]);
  void Multiply(std::uint8_t z[kBlockSize], const std::uint8_t x[kBlockSize]) const;
  // Feeds len bytes (any length) through GHASH, zero-padding the final partial block.
  void GHashUpdate(std::uint8_t y[kBlockSize], const std::uint8_t* data, std::size_t len) const;
  void GHashFinal(std::uint8_t y[kBlockSize], std::size_t ciphertext_len) const;
  void CtrXor(std::uint8_t* dst, const std::uint8_t* src, std::size_t len,
              const std::uint8_t counter[kBlockSize]) const;

  Aes aes_;
  std::uint8_t table_[32][16][kBlockSize] = {};
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_GCM_H_
