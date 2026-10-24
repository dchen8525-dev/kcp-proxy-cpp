// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/error.h"

#include <system_error>

namespace kcp {
namespace {

class KcpErrorCategoryImpl final : public std::error_category {
 public:
  const char* name() const noexcept override { return "kcp"; }

  std::string message(int value) const override {
    return ErrorCodeName(static_cast<ErrorCode>(value));
  }
};

}  // namespace

const char* ErrorCodeName(ErrorCode code) {
  switch (code) {
    case ErrorCode::kOk:
      return "ok";
    case ErrorCode::kTimeout:
      return "timeout";
    case ErrorCode::kClosedPipe:
      return "closed pipe";
    case ErrorCode::kSocketError:
      return "socket error";
    case ErrorCode::kConvMismatch:
      return "conv mismatch";
    case ErrorCode::kTooShort:
      return "packet too short";
    case ErrorCode::kFecRecoverFailed:
      return "fec recover failed";
    case ErrorCode::kIntegrityFailed:
      return "integrity check failed";
    case ErrorCode::kUnsupportedCipher:
      return "unsupported cipher";
    case ErrorCode::kInvalidKeySize:
      return "invalid key size";
    case ErrorCode::kOobRequiresFec:
      return "oob requires fec";
    case ErrorCode::kOobTooLarge:
      return "oob payload too large";
    case ErrorCode::kBufferTooSmall:
      return "buffer too small";
    case ErrorCode::kBufferSizeMismatch:
      return "buffer size mismatch";
    case ErrorCode::kInvalidOperation:
      return "invalid operation";
    case ErrorCode::kInvalidArgument:
      return "invalid argument";
  }
  return "unknown error";
}

const std::error_category& KcpErrorCategory() {
  static const KcpErrorCategoryImpl kInstance;
  return kInstance;
}

std::error_code MakeErrorCode(ErrorCode code) {
  return std::error_code(static_cast<int>(code), KcpErrorCategory());
}

}  // namespace kcp
