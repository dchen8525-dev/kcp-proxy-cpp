// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_PLATFORM_ENTROPY_BACKEND_H_
#define KCP_PLATFORM_ENTROPY_BACKEND_H_

#include <cstddef>

namespace kcp {
namespace platform {

// Fills buf with cryptographically secure random bytes.
//
// Windows: BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG).
// POSIX:   getrandom(2), falling back to /dev/urandom when the syscall is unavailable.
//
// Returns false when no system source could be read. The buffer is still filled in that case, via
// a splitmix64 fallback seeded from the clock and stack address, so a session never sends an
// all-zero nonce; the degraded condition is reported once on stderr. Callers treat false as
// "entropy degraded", not as a per-packet error.
bool FillRand(void* buf, std::size_t len);

}  // namespace platform
}  // namespace kcp

#endif  // KCP_PLATFORM_ENTROPY_BACKEND_H_
