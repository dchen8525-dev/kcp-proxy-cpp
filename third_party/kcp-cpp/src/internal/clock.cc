// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/clock.h"

#include <chrono>

namespace kcp {
namespace internal {

std::uint32_t CurrentMs() {
  // kcp.go:112-113 - a fixed origin plus a monotonic delta. steady_clock never jumps backwards,
  // so the wrapping 32-bit counter advances at a constant rate and TimeDiff stays meaningful for
  // the ~49 days it takes to wrap.
  static const std::chrono::steady_clock::time_point origin = std::chrono::steady_clock::now();
  const auto elapsed = std::chrono::steady_clock::now() - origin;
  return static_cast<std::uint32_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
}

}  // namespace internal
}  // namespace kcp
