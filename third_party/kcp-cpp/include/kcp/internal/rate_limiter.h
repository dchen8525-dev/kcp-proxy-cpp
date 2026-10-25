// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_RATE_LIMITER_H_
#define KCP_INTERNAL_RATE_LIMITER_H_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace kcp {
namespace internal {

// Token bucket standing in for golang.org/x/time/rate (sess.go:648-658). kcp-go builds a limiter
// with `rate.NewLimiter(rate.Limit(bytesPerSecond), maxBatchSize*mtuLimit)` and calls WaitN before
// each transmit; a non-positive rate is rate.Inf, i.e. unlimited.
//
// WaitN's error is discarded in the reference ("only returns error if the limiter is
// misconfigured"), and a request larger than the burst is exactly such a case: WaitN returns
// without reserving a token, so the oversized batch is transmitted immediately. This implementation
// mirrors that early-out rather than blocking for a full burst.
class RateLimiter {
 public:
  // bytes_per_second == 0 means unlimited.
  explicit RateLimiter(std::uint32_t bytes_per_second);

  // Blocks until `n` bytes may be sent. No-op when unlimited.
  void Acquire(std::size_t n);

  // Wakes every sleeper in Acquire and makes all future calls return immediately. Without this,
  // a session close would block for up to burst/rate seconds inside the post thread's token wait
  // (at 1 kB/s that is ~96 s), and whoever joins that thread - including the listener's single
  // monitor thread on the stale-conv reset path - freezes every other session on the listener.
  void Close();

  bool unlimited() const { return rate_ <= 0.0; }

 private:
  void Refill(std::chrono::steady_clock::time_point now);

  std::mutex mu_;
  std::condition_variable cv_;
  std::atomic<bool> closed_{false};
  const double rate_;   // bytes per second; <= 0 means unlimited
  const double burst_;  // bytes
  double tokens_ = 0.0;
  std::chrono::steady_clock::time_point last_;
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_RATE_LIMITER_H_
