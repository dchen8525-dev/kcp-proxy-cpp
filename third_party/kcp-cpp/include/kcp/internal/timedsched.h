// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_TIMEDSCHED_H_
#define KCP_INTERNAL_TIMEDSCHED_H_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace kcp {
namespace internal {

// Drives the per-session KCP timer (timedsched.go). One instance is process-wide, so N sessions
// cost one thread instead of N.
//
// Deviation from the reference (PORTING-PLAN.md §3.2, issue #22): timedsched.go runs a two-stage
// scheduler with max(NumCPU, 2) workers that may execute the same session's Update concurrently.
// Serialising on the session mutex makes that safe but not free. This port keeps a single worker,
// so callbacks never run concurrently at all; Update is an idempotent state-machine step, so the
// observable behaviour is the same and interop is unaffected.
class TimedSched {
 public:
  using TimePoint = std::chrono::steady_clock::time_point;

  // Process-wide instance. Allocated with new and never destroyed: sessions may still be
  // scheduling during static destruction (§3.5).
  static TimedSched& Default();

  TimedSched();
  ~TimedSched();

  TimedSched(const TimedSched&) = delete;
  TimedSched& operator=(const TimedSched&) = delete;

  // Queues `fn` for `deadline`. Ignored once Shutdown() has run. A task that reschedules itself
  // (the session Update loop) costs one heap push per tick and no extra thread.
  void Put(std::function<void()> fn, TimePoint deadline);

  // Stops the worker and joins it. Called by tests that need to prove the thread is reclaimable;
  // normal process exit deliberately does not call it (§3.5).
  void Shutdown();

  // Tasks still queued. Used by tests; not part of the session hot path.
  std::size_t size() const;

 private:
  struct Task {
    TimePoint due;
    std::uint64_t seq;
    std::function<void()> fn;
  };

  struct Later {
    bool operator()(const Task& a, const Task& b) const {
      if (a.due != b.due) {
        return a.due > b.due;
      }
      return a.seq > b.seq;
    }
  };

  void Run();

  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::priority_queue<Task, std::vector<Task>, Later> tasks_;
  std::uint64_t next_seq_ = 0;
  bool stopped_ = false;
  std::thread worker_;
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_TIMEDSCHED_H_
