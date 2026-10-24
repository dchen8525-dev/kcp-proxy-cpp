// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_BYTEORDER_H_
#define KCP_INTERNAL_BYTEORDER_H_

#include <cstddef>
#include <cstdint>

namespace kcp {
namespace internal {

// Little-endian accessors for the wire formats (KCP segment headers, FEC headers, AEAD nonce
// counters). Hand-rolled byte shifts rather than memcpy+byteswap: the layouts are unaligned by
// construction (§4.1), and the shifts are what Go's encoding/binary does.

inline std::uint16_t ReadLe16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(p[0]) |
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8));
}

inline std::uint32_t ReadLe32(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void WriteLe16(std::uint8_t* p, std::uint16_t value) {
  p[0] = static_cast<std::uint8_t>(value & 0xff);
  p[1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
}

inline void WriteLe32(std::uint8_t* p, std::uint32_t value) {
  p[0] = static_cast<std::uint8_t>(value & 0xff);
  p[1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
  p[2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
  p[3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

// Serial-number comparison from kcp.go:220: the difference is taken in 32-bit wrapping
// arithmetic and read back as a signed distance, so numbers on either side of the wrap point
// still order correctly.
inline std::int32_t TimeDiff(std::uint32_t later, std::uint32_t earlier) {
  return static_cast<std::int32_t>(later - earlier);
}

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_BYTEORDER_H_
