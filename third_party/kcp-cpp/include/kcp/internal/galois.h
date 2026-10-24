// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go
//
// GF(2^8) arithmetic backing the Reed-Solomon codec. kcp-go reaches this through
// github.com/klauspost/reedsolomon v1.12.0, whose field parameters are fixed: the reduction
// polynomial is 29 = 0x11D and the generator is 2 (galois.go:24 generatingPolynomial). Both are
// wire-visible through the parity bytes, so they are not free choices.

#ifndef KCP_INTERNAL_GALOIS_H_
#define KCP_INTERNAL_GALOIS_H_

#include <cstdint>

namespace kcp {
namespace internal {

// A single byte addresses every element of the field, so a code cannot have more than 256
// shards in total (= d + p). reedsolomon.New rejects anything above this (ErrMaxShardNum).
constexpr int kGaloisMaxShards = 256;

// Reduction polynomial x^8 + x^4 + x^3 + x^2 + 1, i.e. 0x11D (galois.go:24).
constexpr std::uint16_t kGaloisPoly = 0x11d;

// Dense 256x256 product table. The data path keeps a reference to this for the whole encode, so
// the cost is one indirection per call rather than one per byte.
using GaloisMulTable = std::uint8_t[256][256];

// Thread-safe one-time construction. Layout of the returned table is [a][b] = a * b.
const GaloisMulTable& MulTable();

// Convenience wrappers for setup code (matrix construction, inversion), where the per-byte cost
// is irrelevant.
std::uint8_t GaloisMul(std::uint8_t a, std::uint8_t b);

// a / b. Returns 0 when a == 0; b must be non-zero (a zero divisor is a caller bug, and the RS
// code never asks for it).
std::uint8_t GaloisDiv(std::uint8_t a, std::uint8_t b);

// Multiplicative inverse. Returns 0 for input 0 so a singular matrix shows up as a failed
// Invert() instead of undefined behaviour.
std::uint8_t GaloisInv(std::uint8_t a);

// a ** n in the field, with the reedsolomon edge cases kept verbatim (galois.go:897):
// n == 0 yields 1 even for a == 0, and a == 0 with n != 0 yields 0.
std::uint8_t GaloisExp(std::uint8_t a, int n);

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_GALOIS_H_
