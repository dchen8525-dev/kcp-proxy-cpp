// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/galois.h"

#include <cstddef>

namespace kcp {
namespace internal {
namespace {

// exp[] doubles as the antilog table and the product table's leaf. The second half repeats the
// first so a lookup never needs a modulo after an addition of two logs (galois.go:63).
constexpr int kExpSize = 512;

struct Tables {
  std::uint8_t exp[kExpSize];
  std::uint8_t log[256];
  std::uint8_t mul[256][256];

  Tables() {
    for (int i = 0; i < kExpSize; ++i) {
      exp[i] = 0;
    }
    for (int i = 0; i < 256; ++i) {
      log[i] = 0;
    }
    std::uint16_t x = 1;
    for (int i = 0; i < 255; ++i) {
      exp[i] = static_cast<std::uint8_t>(x);
      log[x] = static_cast<std::uint8_t>(i);
      x = static_cast<std::uint16_t>(x << 1);
      if ((x & 0x100) != 0) {
        x = static_cast<std::uint16_t>(x ^ kGaloisPoly);
      }
    }
    for (int i = 255; i < kExpSize; ++i) {
      exp[i] = exp[i - 255];
    }
    // 0 has no logarithm; galois.go:36 leaves logTable[0] = 0. Every caller tests for a zero
    // operand before looking at the log, so the value is inert.
    log[0] = 0;

    for (int a = 0; a < 256; ++a) {
      for (int b = 0; b < 256; ++b) {
        mul[a][b] = 0;
      }
    }
    for (int a = 1; a < 256; ++a) {
      for (int b = 1; b < 256; ++b) {
        int s = static_cast<int>(log[a]) + static_cast<int>(log[b]);
        if (s >= 255) {
          s -= 255;
        }
        mul[a][b] = exp[s];
      }
    }
  }
};

const Tables& Get() {
  // Function-local static: thread-safe initialisation since C++11, one 64 KiB table for the
  // process, never destroyed (monotonic lifetime, PORTING-PLAN.md §3.5).
  static const Tables* tables = new Tables();
  return *tables;
}

}  // namespace

const GaloisMulTable& MulTable() { return Get().mul; }

std::uint8_t GaloisMul(std::uint8_t a, std::uint8_t b) { return Get().mul[a][b]; }

std::uint8_t GaloisDiv(std::uint8_t a, std::uint8_t b) {
  if (a == 0) {
    return 0;
  }
  const Tables& t = Get();
  int s = static_cast<int>(t.log[a]) - static_cast<int>(t.log[b]);
  if (s < 0) {
    s += 255;
  }
  return t.exp[s];
}

std::uint8_t GaloisInv(std::uint8_t a) {
  if (a == 0) {
    return 0;
  }
  const Tables& t = Get();
  return t.exp[255 - static_cast<int>(t.log[a])];
}

std::uint8_t GaloisExp(std::uint8_t a, int n) {
  if (n == 0) {
    return 1;
  }
  if (a == 0) {
    return 0;
  }
  const Tables& t = Get();
  int s = static_cast<int>(t.log[a]) * n;
  s %= 255;
  return t.exp[s];
}

}  // namespace internal
}  // namespace kcp
