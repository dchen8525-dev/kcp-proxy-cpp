// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/rate_limiter.h"

#include <algorithm>

#include "kcp/internal/constants.h"

namespace kcp {
namespace internal {

RateLimiter::RateLimiter(std::uint32_t bytes_per_second)
    : rate_(static_cast<double>(bytes_per_second)),
      burst_(static_cast<double>(kMaxBatchSize * kMtuLimit)),
      tokens_(static_cast<double>(kMaxBatchSize * kMtuLimit)),
      last_(std::chrono::steady_clock::now()) {}

void RateLimiter::Refill(std::chrono::steady_clock::time_point now) {
  const std::chrono::duration<double> elapsed = now - last_;
  last_ = now;
  tokens_ = std::min(burst_, tokens_ + elapsed.count() * rate_);
}

void RateLimiter::Acquire(std::size_t n) {
  if (unlimited() || n == 0) {
    return;
  }
  // x/time/rate.WaitN rejects a request larger than the burst outright: it returns an error without
  // reserving a single token, and sess.go discards that error and transmits anyway. So an oversized
  // batch goes out immediately - it must not block waiting for a whole burst to accrue, which would
  // add up to burst/rate of latency the reference never pays (reachable when a FEC-parity-heavy
  // post-processing batch exceeds maxBatchSize packets).
  if (static_cast<double>(n) > burst_) {
    return;
  }
  const double want = static_cast<double>(n);

  std::unique_lock<std::mutex> lock(mu_);
  for (;;) {
    const auto now = std::chrono::steady_clock::now();
    Refill(now);
    if (tokens_ >= want) {
      tokens_ -= want;
      return;
    }
    const double missing = want - tokens_;
    const std::chrono::duration<double> wait(missing / rate_);
    cv_.wait_for(lock, std::chrono::duration_cast<std::chrono::microseconds>(wait) +
                           std::chrono::microseconds(100));
  }
}

}  // namespace internal
}  // namespace kcp
