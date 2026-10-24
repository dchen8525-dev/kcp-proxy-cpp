// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_BLOCK_CIPHER_H_
#define KCP_INTERNAL_BLOCK_CIPHER_H_

#include <cstddef>
#include <cstdint>

namespace kcp {
namespace internal {

// Single-block forward transform. CFB (crypt.go:302-660) and GCM (crypt.go:113-124) both consume
// the block cipher in the forward direction only, so that is the only direction offered here -
// adding an unused virtual would be dead weight.
class BlockCipher {
 public:
  virtual ~BlockCipher() = default;

  // Cheap accessor, hence snake_case (Google: Naming, accessors may match the data member).
  virtual std::size_t block_size() const = 0;

  // dst and src must each address block_size() readable/writable bytes. May alias.
  virtual void EncryptBlock(std::uint8_t* dst, const std::uint8_t* src) const = 0;
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_BLOCK_CIPHER_H_
