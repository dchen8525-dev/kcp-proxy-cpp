#pragma once

#include "config.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace kcp_proxy {

struct SOCKS5Request {
    uint8_t cmd = 0;
    std::string host;
    uint16_t port = 0;
    uint8_t atyp = 0;
    std::vector<uint8_t> initial_payload;
};

struct SOCKS5Response {
    uint8_t reply = SOCKS5_REPLY_GENERAL_FAILURE;
    std::string host;
    uint16_t port = 0;

    std::vector<uint8_t> build() const;
};

enum class SOCKS5ParseStatus {
    NeedMore,
    Complete,
    Invalid
};

struct SOCKS5ParseResult {
    SOCKS5ParseStatus status = SOCKS5ParseStatus::NeedMore;
    // Only engaged when status == Complete.
    std::optional<SOCKS5Request> request;
    std::string error;
    size_t bytes_consumed = 0;
    // True when status == Invalid because the ATYP is unsupported. The caller
    // should reply SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED for that case and
    // SOCKS5_REPLY_GENERAL_FAILURE for every other parse error.
    bool bad_atyp = false;
};

SOCKS5ParseResult parse_socks5_request(const std::vector<uint8_t>& data);

} // namespace kcp_proxy
