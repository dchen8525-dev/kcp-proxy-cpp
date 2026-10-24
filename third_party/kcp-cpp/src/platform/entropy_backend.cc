// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/platform/entropy_backend.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>

#if defined(_WIN32)
#include <windows.h>

#include <bcrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

namespace kcp {
namespace platform {
namespace {

// splitmix64: only used when the OS source fails. It is not a cryptographic RNG on its own; it
// exists so a degraded source cannot produce a constant nonce.
std::uint64_t SplitMix64(std::uint64_t* state) {
  *state += 0x9e3779b97f4a7c15ull;
  std::uint64_t z = *state;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

void FillFallback(void* buf, std::size_t len) {
  static std::atomic<std::uint64_t> calls{0};
  const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::uint64_t state = static_cast<std::uint64_t>(now) ^
                        (static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(buf)) << 1) ^
                        calls.fetch_add(1, std::memory_order_relaxed);
  auto* out = static_cast<std::uint8_t*>(buf);
  std::size_t offset = 0;
  while (offset < len) {
    const std::uint64_t word = SplitMix64(&state);
    const std::size_t take = (len - offset) < 8 ? (len - offset) : 8;
    for (std::size_t i = 0; i < take; ++i) {
      out[offset + i] = static_cast<std::uint8_t>(word >> (i * 8));
    }
    offset += take;
  }
}

bool ReadSystemRandom(void* buf, std::size_t len) {
#if defined(_WIN32)
  NTSTATUS status = BCryptGenRandom(nullptr, static_cast<PUCHAR>(buf), static_cast<ULONG>(len),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return status == 0;
#else
  auto* out = static_cast<std::uint8_t*>(buf);
  std::size_t offset = 0;
#if defined(__linux__)
  while (offset < len) {
    const ssize_t got = ::getrandom(out + offset, len - offset, 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    offset += static_cast<std::size_t>(got);
  }
  if (offset == len) {
    return true;
  }
#endif
  // Portable fallback: /dev/urandom (also covers non-Linux POSIX). Resumes at `offset`, so a
  // partially served getrandom() is topped up rather than restarted.
  const int fd = ::open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    return false;
  }
  while (offset < len) {
    const ssize_t got = ::read(fd, out + offset, len - offset);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      ::close(fd);
      return false;
    }
    if (got == 0) {
      break;
    }
    offset += static_cast<std::size_t>(got);
  }
  ::close(fd);
  return offset == len;
#endif
}

}  // namespace

bool FillRand(void* buf, std::size_t len) {
  if (len == 0) {
    return true;
  }
  if (ReadSystemRandom(buf, len)) {
    return true;
  }
  static std::atomic<bool> warned{false};
  if (!warned.exchange(true)) {
    std::fprintf(stderr, "kcp: system entropy source unavailable, using degraded fallback\n");
  }
  FillFallback(buf, len);
  return false;
}

}  // namespace platform
}  // namespace kcp
