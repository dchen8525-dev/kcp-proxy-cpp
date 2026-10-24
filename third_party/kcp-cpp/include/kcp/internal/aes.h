// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_AES_H_
#define KCP_INTERNAL_AES_H_

#include <cstddef>
#include <cstdint>

#include "kcp/internal/block_cipher.h"

namespace kcp {
namespace internal {

// Which implementation EncryptBlock() dispatches to. kAuto picks AES-NI when the CPU reports it
// and the T-table path otherwise; the other two exist so the test suite can drive both paths on
// any machine and prove they agree (PORTING-PLAN.md P2 gate, decision 6).
enum class AesBackend {
  kAuto,
  kNin,
  kTable,
};

// AES-128/192/256 block encryption (FIPS-197). Purely a key schedule plus EncryptBlock(); the
// chaining mode lives in cfb.h / gcm.h so both can share one schedule.
class Aes final : public BlockCipher {
 public:
  static constexpr std::size_t kBlockSize = 16;
  static constexpr std::size_t kMaxRoundKeys = 15;  // AES-256: Nr = 14, so 15 round keys.

  // key_len must be 16, 24 or 32. Any other length leaves valid() false instead of throwing,
  // mirroring the KeySizeError that crypto/aes.NewCipher returns (crypt.go:270-272).
  Aes(const std::uint8_t* key, std::size_t key_len);
  Aes(const std::uint8_t* key, std::size_t key_len, AesBackend backend);

  bool valid() const { return rounds_ != 0; }
  std::size_t key_len() const { return key_len_; }
  bool using_ni() const { return use_ni_; }

  std::size_t block_size() const override { return kBlockSize; }
  void EncryptBlock(std::uint8_t* dst, const std::uint8_t* src) const override;

 private:
  void ExpandKey(const std::uint8_t* key);

  std::uint8_t round_keys_[kMaxRoundKeys * kBlockSize] = {};
  std::size_t key_len_ = 0;
  int rounds_ = 0;
  bool use_ni_ = false;
};

// True when the host CPU implements AES-NI. Cached after the first call.
bool AesNiAvailable();

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_AES_H_
