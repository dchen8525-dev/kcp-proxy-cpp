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
    // True when status == Invalid because the ATYP is unsupported. The caller
    // should reply SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED for that case and
    // SOCKS5_REPLY_GENERAL_FAILURE for every other parse error.
    bool bad_atyp = false;
};

SOCKS5ParseResult parse_socks5_request(const std::vector<uint8_t>& data);

// A fully validated SOCKS5 reply (RFC 1928 §6).
struct SOCKS5Reply {
    uint8_t reply = SOCKS5_REPLY_GENERAL_FAILURE;
    std::string host;
    uint16_t port = 0;
    // How many bytes of the input the reply occupies. A KCP message can carry
    // target payload right after the reply, so the caller must consume exactly
    // this many bytes and forward the remainder — dropping it truncates the
    // first response the local app sees.
    size_t length = 0;
};

enum class SOCKS5ReplyStatus {
    NeedMore,
    Complete,
    Invalid
};

struct SOCKS5ReplyResult {
    SOCKS5ReplyStatus status = SOCKS5ReplyStatus::NeedMore;
    // Only engaged when status == Complete.
    std::optional<SOCKS5Reply> reply;
    std::string error;
};

// Parse a SOCKS5 CONNECT reply. Unlike the client's old inline check (which
// looked at byte[1] only), this validates VER, RSV, ATYP and the total length
// implied by ATYP, and reports NeedMore so a reply split across several KCP
// messages is accumulated instead of being mistaken for a complete one.
SOCKS5ReplyResult parse_socks5_reply(const std::vector<uint8_t>& data);

} // namespace kcp_proxy
