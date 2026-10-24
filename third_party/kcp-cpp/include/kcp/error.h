// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_ERROR_H_
#define KCP_ERROR_H_

#include <string>
#include <system_error>

namespace kcp {

// Error contract from PORTING-PLAN.md §3.4. The core never throws: every fallible entry point
// returns one of these, and callers that want the std::error_code interoperability call
// MakeErrorCode().
enum class ErrorCode {
  kOk = 0,
  kTimeout,             // errTimeout                      - deadline expired
  kClosedPipe,          // io.ErrClosedPipe                - session already closed
  kSocketError,         // raw syscall error               - sendto/recvfrom failure
  kConvMismatch,        // Input() == -1                   - conv does not match this session
  kTooShort,            // Input() == -2                   - packet below the minimum size
  kFecRecoverFailed,    // FECErrs++ then drop             - fewer shards than needed
  kIntegrityFailed,     // InCsumErrors++ then drop        - AEAD tag or CRC32 mismatch
  kUnsupportedCipher,   // no Go equivalent                - algorithm not built in
  kInvalidKeySize,      // aes.KeySizeError                - key length not 16/24/32
  kOobRequiresFec,      // errNoFecForOob                  - OOB without FEC enabled
  kOobTooLarge,         // errOobTooLarge                  - payload above oob_max_size()
  kBufferTooSmall,      // panic("increase MTU size")      - deviation D1, never panics here
  kBufferSizeMismatch,  // errBufferSizeMismatch           - pool Put() with a resized buffer
  kInvalidOperation,    // errInvalidOperation             - call not valid for this object
  kInvalidArgument,     // errInvalidArgument              - bad parameter
};

// Stable ASCII spelling, usable in logs and in test failure messages.
const char* ErrorCodeName(ErrorCode code);

// Adapter to std::error_code so callers can compose with <system_error> machinery.
std::error_code MakeErrorCode(ErrorCode code);

// Standard customisation point: std::error_code's converting constructor calls make_error_code()
// through argument-dependent lookup, so this exact spelling (lowercase, mandated by the standard)
// is what lets callers write `ec == ErrorCode::kTimeout` or `std::error_code ec = kTimeout`.
inline std::error_code make_error_code(ErrorCode code) { return MakeErrorCode(code); }

// Convenience: the error_category instance backing MakeErrorCode().
const std::error_category& KcpErrorCategory();

}  // namespace kcp

// Enables the implicit std::error_code construction in MakeErrorCode() and lets user code write
// `ec == kcp::ErrorCode::kTimeout`.
namespace std {
template <>
struct is_error_code_enum<kcp::ErrorCode> : true_type {};
}  // namespace std

#endif  // KCP_ERROR_H_
