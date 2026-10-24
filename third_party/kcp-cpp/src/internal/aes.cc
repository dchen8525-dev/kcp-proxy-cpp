// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/aes.h"

#include <cstring>

#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#define KCP_HAVE_X86_AES 1
#endif

#if defined(KCP_HAVE_X86_AES)
#if defined(_MSC_VER)
#include <intrin.h>
#include <wmmintrin.h>
#else
#include <cpuid.h>
#include <wmmintrin.h>
#endif
#endif

// GCC/Clang need a per-function target attribute to accept AES intrinsics without compiling the
// whole translation unit for AES-capable CPUs; MSVC enables them for x64 unconditionally.
#if defined(KCP_HAVE_X86_AES) && !defined(_MSC_VER)
#define KCP_AES_NI_TARGET __attribute__((target("aes,sse2")))
#else
#define KCP_AES_NI_TARGET
#endif

namespace kcp {
namespace internal {
namespace {

constexpr std::uint8_t kPolynomial = 0x1b;

std::uint8_t GfMul2(std::uint8_t a) {
  const std::uint8_t carry = static_cast<std::uint8_t>(a & 0x80);
  a = static_cast<std::uint8_t>(a << 1);
  return carry != 0 ? static_cast<std::uint8_t>(a ^ kPolynomial) : a;
}

std::uint8_t GfMul(std::uint8_t a, std::uint8_t b) {
  std::uint8_t result = 0;
  while (b != 0) {
    if ((b & 1) != 0) {
      result ^= a;
    }
    a = GfMul2(a);
    b = static_cast<std::uint8_t>(b >> 1);
  }
  return result;
}

// x^254 is the multiplicative inverse of x in GF(2^8) for x != 0, since x^255 == 1.
std::uint8_t GfInverse(std::uint8_t x) {
  if (x == 0) {
    return 0;
  }
  std::uint8_t result = 1;
  std::uint8_t base = x;
  unsigned exponent = 254;
  while (exponent != 0) {
    if ((exponent & 1) != 0) {
      result = GfMul(result, base);
    }
    base = GfMul(base, base);
    exponent >>= 1;
  }
  return result;
}

std::uint8_t Rotate8(std::uint8_t v, int n) {
  return static_cast<std::uint8_t>((v << n) | (v >> (8 - n)));
}

std::uint32_t Pack(std::uint8_t b0, std::uint8_t b1, std::uint8_t b2, std::uint8_t b3) {
  return (static_cast<std::uint32_t>(b0) << 24) | (static_cast<std::uint32_t>(b1) << 16) |
         (static_cast<std::uint32_t>(b2) << 8) | static_cast<std::uint32_t>(b3);
}

std::uint32_t LoadBe32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void StoreBe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}

// S-box plus the four MixColumns tables. Generated once instead of carrying 4 KiB of literals that
// nobody can review; Table() is the single source of truth for both encrypt paths.
struct AesTables {
  std::uint8_t sbox[256];
  std::uint32_t te0[256];
  std::uint32_t te1[256];
  std::uint32_t te2[256];
  std::uint32_t te3[256];
};

const AesTables& Table() {
  static const AesTables kTables = [] {
    AesTables t{};
    for (int x = 0; x < 256; ++x) {
      const std::uint8_t inv = GfInverse(static_cast<std::uint8_t>(x));
      // FIPS-197 5.1.1: affine transform over the multiplicative inverse.
      const std::uint8_t s = static_cast<std::uint8_t>(inv ^ Rotate8(inv, 1) ^ Rotate8(inv, 2) ^
                                                       Rotate8(inv, 3) ^ Rotate8(inv, 4) ^ 0x63);
      t.sbox[x] = s;
      const std::uint8_t s2 = GfMul(s, 2);
      const std::uint8_t s3 = GfMul(s, 3);
      t.te0[x] = Pack(s2, s, s, s3);
      t.te1[x] = Pack(s3, s2, s, s);
      t.te2[x] = Pack(s, s3, s2, s);
      t.te3[x] = Pack(s, s, s3, s2);
    }
    return t;
  }();
  return kTables;
}

std::uint32_t SubWord(std::uint32_t w) {
  const AesTables& t = Table();
  return (static_cast<std::uint32_t>(t.sbox[w >> 24]) << 24) |
         (static_cast<std::uint32_t>(t.sbox[(w >> 16) & 0xff]) << 16) |
         (static_cast<std::uint32_t>(t.sbox[(w >> 8) & 0xff]) << 8) |
         static_cast<std::uint32_t>(t.sbox[w & 0xff]);
}

std::uint32_t RotWord(std::uint32_t w) { return (w << 8) | (w >> 24); }

void EncryptBlockTable(const std::uint8_t* round_keys, int rounds, const std::uint8_t* src,
                       std::uint8_t* dst) {
  const AesTables& t = Table();
  std::uint32_t s0 = LoadBe32(src) ^ LoadBe32(round_keys);
  std::uint32_t s1 = LoadBe32(src + 4) ^ LoadBe32(round_keys + 4);
  std::uint32_t s2 = LoadBe32(src + 8) ^ LoadBe32(round_keys + 8);
  std::uint32_t s3 = LoadBe32(src + 12) ^ LoadBe32(round_keys + 12);

  for (int r = 1; r < rounds; ++r) {
    const std::uint8_t* rk = round_keys + 16 * r;
    const std::uint32_t t0 = t.te0[s0 >> 24] ^ t.te1[(s1 >> 16) & 0xff] ^ t.te2[(s2 >> 8) & 0xff] ^
                             t.te3[s3 & 0xff] ^ LoadBe32(rk);
    const std::uint32_t t1 = t.te0[s1 >> 24] ^ t.te1[(s2 >> 16) & 0xff] ^ t.te2[(s3 >> 8) & 0xff] ^
                             t.te3[s0 & 0xff] ^ LoadBe32(rk + 4);
    const std::uint32_t t2 = t.te0[s2 >> 24] ^ t.te1[(s3 >> 16) & 0xff] ^ t.te2[(s0 >> 8) & 0xff] ^
                             t.te3[s1 & 0xff] ^ LoadBe32(rk + 8);
    const std::uint32_t t3 = t.te0[s3 >> 24] ^ t.te1[(s0 >> 16) & 0xff] ^ t.te2[(s1 >> 8) & 0xff] ^
                             t.te3[s2 & 0xff] ^ LoadBe32(rk + 12);
    s0 = t0;
    s1 = t1;
    s2 = t2;
    s3 = t3;
  }

  // Final round drops MixColumns: SubBytes + ShiftRows + AddRoundKey only.
  const std::uint8_t* rk = round_keys + 16 * rounds;
  const std::uint8_t* s = t.sbox;
  StoreBe32(dst, Pack(s[s0 >> 24], s[(s1 >> 16) & 0xff], s[(s2 >> 8) & 0xff], s[s3 & 0xff]) ^
                     LoadBe32(rk));
  StoreBe32(dst + 4, Pack(s[s1 >> 24], s[(s2 >> 16) & 0xff], s[(s3 >> 8) & 0xff], s[s0 & 0xff]) ^
                         LoadBe32(rk + 4));
  StoreBe32(dst + 8, Pack(s[s2 >> 24], s[(s3 >> 16) & 0xff], s[(s0 >> 8) & 0xff], s[s1 & 0xff]) ^
                         LoadBe32(rk + 8));
  StoreBe32(dst + 12, Pack(s[s3 >> 24], s[(s0 >> 16) & 0xff], s[(s1 >> 8) & 0xff], s[s2 & 0xff]) ^
                          LoadBe32(rk + 12));
}

#if defined(KCP_HAVE_X86_AES)
KCP_AES_NI_TARGET
void EncryptBlockNi(const std::uint8_t* round_keys, int rounds, const std::uint8_t* src,
                    std::uint8_t* dst) {
  __m128i m = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(src)),
                            _mm_loadu_si128(reinterpret_cast<const __m128i*>(round_keys)));
  for (int r = 1; r < rounds; ++r) {
    m = _mm_aesenc_si128(m, _mm_loadu_si128(reinterpret_cast<const __m128i*>(round_keys + 16 * r)));
  }
  m = _mm_aesenclast_si128(
      m, _mm_loadu_si128(reinterpret_cast<const __m128i*>(round_keys + 16 * rounds)));
  _mm_storeu_si128(reinterpret_cast<__m128i*>(dst), m);
}
#endif

}  // namespace

bool AesNiAvailable() {
#if defined(KCP_HAVE_X86_AES)
  static const bool kAvailable = [] {
#if defined(_MSC_VER)
    int regs[4] = {};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 25)) != 0;
#else
    unsigned eax = 0;
    unsigned ebx = 0;
    unsigned ecx = 0;
    unsigned edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
      return false;
    }
    return (ecx & (1u << 25)) != 0;
#endif
  }();
  return kAvailable;
#else
  return false;
#endif
}

Aes::Aes(const std::uint8_t* key, std::size_t key_len) : Aes(key, key_len, AesBackend::kAuto) {}

Aes::Aes(const std::uint8_t* key, std::size_t key_len, AesBackend backend) {
  if (key_len != 16 && key_len != 24 && key_len != 32) {
    return;
  }
  switch (backend) {
    case AesBackend::kNin:
      use_ni_ = true;
#if !defined(KCP_HAVE_X86_AES)
      use_ni_ = false;
#endif
      break;
    case AesBackend::kTable:
      use_ni_ = false;
      break;
    case AesBackend::kAuto:
      use_ni_ = AesNiAvailable();
      break;
  }
  key_len_ = key_len;
  rounds_ = static_cast<int>(key_len / 4) + 6;
  ExpandKey(key);
}

void Aes::ExpandKey(const std::uint8_t* key) {
  const std::size_t nk = key_len_ / 4;
  const std::size_t total = 4 * (static_cast<std::size_t>(rounds_) + 1);
  std::uint32_t w[60] = {};
  for (std::size_t i = 0; i < nk; ++i) {
    w[i] = LoadBe32(key + 4 * i);
  }
  std::uint8_t rcon = 1;
  for (std::size_t i = nk; i < total; ++i) {
    std::uint32_t temp = w[i - 1];
    if (i % nk == 0) {
      temp = SubWord(RotWord(temp)) ^ (static_cast<std::uint32_t>(rcon) << 24);
      rcon = GfMul2(rcon);
    } else if (nk > 6 && i % nk == 4) {
      temp = SubWord(temp);
    }
    w[i] = w[i - nk] ^ temp;
  }
  for (std::size_t i = 0; i < total; ++i) {
    StoreBe32(round_keys_ + 4 * i, w[i]);
  }
}

void Aes::EncryptBlock(std::uint8_t* dst, const std::uint8_t* src) const {
  if (rounds_ == 0) {
    return;
  }
#if defined(KCP_HAVE_X86_AES)
  if (use_ni_) {
    EncryptBlockNi(round_keys_, rounds_, src, dst);
    return;
  }
#endif
  EncryptBlockTable(round_keys_, rounds_, src, dst);
}

}  // namespace internal
}  // namespace kcp
