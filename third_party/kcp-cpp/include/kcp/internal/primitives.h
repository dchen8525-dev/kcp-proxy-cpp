// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_PRIMITIVES_H_
#define KCP_INTERNAL_PRIMITIVES_H_

#include <cstddef>
#include <cstdint>

namespace kcp {
namespace internal {

// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320) - matches Go's crc32.ChecksumIEEE, which the
// CFB header checksum uses (sess.go:730).
std::uint32_t Crc32(const void* data, std::size_t len);
std::uint32_t Crc32Update(std::uint32_t seed, const void* data, std::size_t len);

// SHA-1 (FIPS 180-1). Streaming interface, since PBKDF2 hashes many messages.
class Sha1 {
 public:
  static constexpr std::size_t kDigestSize = 20;
  static constexpr std::size_t kBlockSize = 64;

  Sha1();
  void Update(const void* data, std::size_t len);
  // Writes the digest and leaves the object in a usable state for a new message.
  void Final(std::uint8_t digest[kDigestSize]);

  static void Compute(const void* data, std::size_t len, std::uint8_t digest[kDigestSize]);

 private:
  void ProcessBlock(const std::uint8_t block[kBlockSize]);

  std::uint32_t h_[5];
  std::uint8_t buffer_[kBlockSize];
  std::size_t buffer_len_ = 0;
  std::uint64_t total_len_ = 0;
};

// HMAC-SHA1 (RFC 2104).
void HmacSha1(const void* key, std::size_t key_len, const void* data, std::size_t data_len,
              std::uint8_t digest[Sha1::kDigestSize]);

// PBKDF2-HMAC-SHA1 (RFC 8018). Matches golang.org/x/crypto/pbkdf2.Key with sha1.New.
// Returns false only when iterations < 1; callers pass a compile-time constant.
bool Pbkdf2HmacSha1(const void* password, std::size_t password_len, const void* salt,
                    std::size_t salt_len, int iterations, std::uint8_t* out, std::size_t out_len);

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_PRIMITIVES_H_
