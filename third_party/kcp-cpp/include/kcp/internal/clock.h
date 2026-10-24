// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_CLOCK_H_
#define KCP_INTERNAL_CLOCK_H_

#include <cstdint>

namespace kcp {
namespace internal {

// Milliseconds on a monotonic clock, measured from an arbitrary fixed origin (kcp.go:110-113).
// Only differences are meaningful: KCP keeps all of its timers as wrapping 32-bit values and
// compares them with TimeDiff, so the origin cancels out.
std::uint32_t CurrentMs();

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_CLOCK_H_
