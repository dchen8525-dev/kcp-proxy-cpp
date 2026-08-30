#include "kcp_proxy/socks5.hpp"
#include "kcp_proxy/address.hpp"

namespace kcp_proxy {

std::vector<uint8_t> SOCKS5Response::build() const {
    std::vector<uint8_t> result;
    result.push_back(SOCKS5_VERSION);
    result.push_back(reply);
    result.push_back(0x00); // RSV

    // RFC 1928 §6: on errors, BND.ADDR/BND.PORT should be a well-formed
    // address (0.0.0.0:0 is the canonical "no bound address" value). Many
    // SOCKS5 clients trip over an ATYP=DOMAIN with an empty name.
    if (host.empty()) {
        result.push_back(SOCKS5_ATYP_IPV4);
        for (int i = 0; i < 4; ++i) result.push_back(0);
        result.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(port & 0xFF));
    } else {
        std::vector<uint8_t> addr = encode_address(host, port);
        result.insert(result.end(), addr.begin(), addr.end());
    }
    return result;
}

SOCKS5ParseResult parse_socks5_request(const std::vector<uint8_t>& data) {
    SOCKS5ParseResult result;
    if (data.size() < 4) {
        return result;
    }

    if (data[0] != SOCKS5_VERSION) {
        result.status = SOCKS5ParseStatus::Invalid;
        result.error = "invalid SOCKS5 version: " + std::to_string(data[0]);
        return result;
    }

    const uint8_t cmd = data[1];
    const uint8_t atyp = data[3];
    size_t need = 0;

    if (atyp == SOCKS5_ATYP_IPV4) {
        need = 4 + 4 + 2;
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        need = 4 + 16 + 2;
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        if (data.size() < 5) {
            return result;
        }
        const size_t domain_len = data[4];
        if (domain_len == 0) {
            result.status = SOCKS5ParseStatus::Invalid;
            result.error = "empty domain";
            return result;
        }
        need = 4 + 1 + domain_len + 2;
    } else {
        result.status = SOCKS5ParseStatus::Invalid;
        result.error = "unsupported address type: " + std::to_string(atyp);
        result.bad_atyp = true;
        return result;
    }

    if (data.size() < need) {
        return result;
    }

    try {
        auto parsed = parse_address(data.data(), need, 3);
        SOCKS5Request req;
        req.cmd = cmd;
        req.host = parsed.host;
        req.port = parsed.port;
        req.atyp = atyp;
        if (data.size() > need) {
            req.initial_payload.assign(data.begin() + static_cast<std::ptrdiff_t>(need),
                                       data.end());
        }
        result.request = std::move(req);
        result.bytes_consumed = need;
        result.status = SOCKS5ParseStatus::Complete;
    } catch (const std::exception& e) {
        result.status = SOCKS5ParseStatus::Invalid;
        result.error = e.what();
        // parse_address can also throw "Unsupported address type" as a safety
        // net; propagate the distinction so the caller picks the right reply.
        result.bad_atyp = std::string(e.what()).find("Unsupported address type") != std::string::npos;
    }
    return result;
}

} // namespace kcp_proxy
