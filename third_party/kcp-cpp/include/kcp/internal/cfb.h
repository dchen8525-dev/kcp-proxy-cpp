// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_CFB_H_
#define KCP_INTERNAL_CFB_H_

#include <cstddef>
#include <cstdint>

#include "kcp/internal/block_cipher.h"

namespace kcp {
namespace internal {

// The local CFB variant of crypt.go:302-660, shared by every block cipher (8-byte and 16-byte
// blocks alike). Semantics that matter for the wire format:
//
//   tbl = E_K(initialVector)                       // feedback starts from the fixed IV
//   for each full block: dst = src ^ tbl; tbl = E_K(dst)      (encrypt)
//                        dst = src ^ tbl; tbl = E_K(src)      (decrypt)
//   trailing bytes (len % blockSize): dst = src ^ tbl, feedback NOT advanced  (#43)
//
// The 8x unrolling in the Go source is a throughput trick with no semantic effect, so this
// implementation keeps the plain block-at-a-time loop. dst may alias src exactly; partial overlap
// is unsupported.

void CfbEncrypt(const BlockCipher& cipher, std::uint8_t* dst, const std::uint8_t* src,
                std::size_t len);

void CfbDecrypt(const BlockCipher& cipher, std::uint8_t* dst, const std::uint8_t* src,
                std::size_t len);

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_CFB_H_
