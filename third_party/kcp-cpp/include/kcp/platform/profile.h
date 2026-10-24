// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_PLATFORM_PROFILE_H_
#define KCP_PLATFORM_PROFILE_H_

#include <atomic>
#include <cstdint>

namespace kcp {
namespace platform {

// Monotonic wall clock in microseconds. Two calls around a syscall cost ~50 ns together, which is
// noise next to the 2.6 us WSASendTo that P8.1 is about (PORTING-PLAN.md §6.3.1).
std::uint64_t WallMicros();

// CPU time consumed by the calling thread / by the whole process, in microseconds. Returns 0 when
// the platform cannot report it. Granularity is the OS clock tick (15.6 ms on Windows), so these
// are only meaningful as totals over a run of seconds - never as a per-call figure.
std::uint64_t ThreadCpuMicros();
std::uint64_t ProcessCpuMicros();

// Syscall accounting for one thread. A session installs one on each of its I/O threads, so the
// cost of sendto/recvfrom/select is attributed to the code that issued it instead of to the
// process as a whole.
//
// The times are wall clock, not CPU: sendto() on Windows spends roughly half of its 44 us off-CPU,
// and that gap is exactly what P8.1 is about. `enabled` is checked on every call, so a session that
// never asks for a profile pays one atomic load per datagram and nothing else.
//
// Every counter is atomic (relaxed): the I/O threads write them while profile() reads them from
// the caller's thread. Reading after close() gives a coherent snapshot because the join provides
// the happens-before, but a mid-flight read is still legal C++ rather than a data race - each
// field is a torn-free, individually monotonic total. The cost is a locked RMW per syscall, noise
// next to the 2.6 us the syscall itself costs (P8.1).
struct IoCounters {
  std::atomic<bool> enabled{false};

  std::atomic<std::uint64_t> send_n{0};
  std::atomic<std::uint64_t> send_us{0};
  std::atomic<std::uint64_t> send_err{0};
  std::atomic<std::uint64_t> recv_n{0};
  std::atomic<std::uint64_t> recv_us{0};
  std::atomic<std::uint64_t> recv_err{0};
  // Non-blocking readiness probe (SysWaitReadable with a zero timeout).
  std::atomic<std::uint64_t> probe_n{0};
  std::atomic<std::uint64_t> probe_us{0};
  // Bounded blocking wait. Dominated by idle time rather than by work, so it is reported apart
  // from the probe: it says how much of the loop was waiting, not how much it cost.
  std::atomic<std::uint64_t> wait_n{0};
  std::atomic<std::uint64_t> wait_us{0};
};

// Binds `counters` to the calling thread. Only one profile per thread; nullptr detaches. Threads
// spawned later start detached - each worker has to install its own.
void SetThreadCounters(IoCounters* counters);
IoCounters* ThreadCounters();

// Adds the CPU time this scope consumed on the calling thread to `target`. Used to charge a whole
// worker loop (read/post) and single public calls (write/read) without having to touch every
// return path.
class CpuScope {
 public:
  explicit CpuScope(std::atomic<std::uint64_t>* target);
  ~CpuScope();

  CpuScope(const CpuScope&) = delete;
  CpuScope& operator=(const CpuScope&) = delete;

 private:
  std::atomic<std::uint64_t>* target_;
  std::uint64_t start_us_;
};

}  // namespace platform
}  // namespace kcp

#endif  // KCP_PLATFORM_PROFILE_H_
