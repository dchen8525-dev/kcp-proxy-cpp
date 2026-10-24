// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/platform/profile.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>

#include <cerrno>
#endif

namespace kcp {
namespace platform {
namespace {

#if defined(_WIN32)

// FILETIME is 100 ns since 1601. Only differences are ever used, so the epoch is irrelevant.
std::uint64_t FileTimeMicros(const FILETIME& ft) {
  ULARGE_INTEGER value;
  value.LowPart = ft.dwLowDateTime;
  value.HighPart = ft.dwHighDateTime;
  return value.QuadPart / 10;
}

#else

std::uint64_t TimespecMicros(const timespec& ts) {
  return static_cast<std::uint64_t>(ts.tv_sec) * 1000000ULL +
         static_cast<std::uint64_t>(ts.tv_nsec) / 1000ULL;
}

#endif

}  // namespace

std::uint64_t WallMicros() {
#if defined(_WIN32)
  static const std::uint64_t kFrequency = [] {
    LARGE_INTEGER frequency;
    ::QueryPerformanceFrequency(&frequency);
    return static_cast<std::uint64_t>(frequency.QuadPart);
  }();
  LARGE_INTEGER counter;
  ::QueryPerformanceCounter(&counter);
  const std::uint64_t ticks = static_cast<std::uint64_t>(counter.QuadPart);
  // Split the multiply so a long-running process cannot overflow: seconds first, remainder second.
  return (ticks / kFrequency) * 1000000ULL + ((ticks % kFrequency) * 1000000ULL) / kFrequency;
#else
  timespec ts;
  ::clock_gettime(CLOCK_MONOTONIC, &ts);
  return TimespecMicros(ts);
#endif
}

std::uint64_t ThreadCpuMicros() {
#if defined(_WIN32)
  FILETIME creation;
  FILETIME exit;
  FILETIME kernel;
  FILETIME user;
  // GetCurrentThread() is a pseudo handle: nothing to close. Kernel time is CPU time spent in
  // kernel mode, which is where most of a syscall's cycles land, so it belongs in the sum.
  if (::GetThreadTimes(::GetCurrentThread(), &creation, &exit, &kernel, &user) == 0) {
    return 0;
  }
  return FileTimeMicros(kernel) + FileTimeMicros(user);
#else
  timespec ts;
  if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
    return 0;
  }
  return TimespecMicros(ts);
#endif
}

std::uint64_t ProcessCpuMicros() {
#if defined(_WIN32)
  FILETIME creation;
  FILETIME exit;
  FILETIME kernel;
  FILETIME user;
  if (::GetProcessTimes(::GetCurrentProcess(), &creation, &exit, &kernel, &user) == 0) {
    return 0;
  }
  return FileTimeMicros(kernel) + FileTimeMicros(user);
#else
  timespec ts;
  if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0) {
    return 0;
  }
  return TimespecMicros(ts);
#endif
}

namespace {

thread_local IoCounters* g_thread_counters = nullptr;

}  // namespace

void SetThreadCounters(IoCounters* counters) { g_thread_counters = counters; }

IoCounters* ThreadCounters() { return g_thread_counters; }

CpuScope::CpuScope(std::atomic<std::uint64_t>* target)
    : target_(target), start_us_(target != nullptr ? ThreadCpuMicros() : 0) {}

CpuScope::~CpuScope() {
  if (target_ == nullptr) {
    return;
  }
  const std::uint64_t end = ThreadCpuMicros();
  if (end >= start_us_) {
    target_->fetch_add(end - start_us_, std::memory_order_relaxed);
  }
}

}  // namespace platform
}  // namespace kcp
