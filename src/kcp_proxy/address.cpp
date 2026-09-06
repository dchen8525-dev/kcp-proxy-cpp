#include "kcp_proxy/address.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/config.hpp"
#include <asio/ip/address.hpp>
#include <asio/ip/address_v6.hpp>
#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace kcp_proxy {

ParsedAddress parse_address(const uint8_t* data, size_t data_size, size_t offset) {
    if (offset >= data_size) {
        throw std::invalid_argument("Insufficient data for address type");
    }

    uint8_t atyp = data[offset];

    if (atyp == SOCKS5_ATYP_IPV4) {
        if (data_size < offset + 7) {
            throw std::invalid_argument("Insufficient data for IPv4 address");
        }
        std::string host = std::to_string(data[offset + 1]) + "." +
                           std::to_string(data[offset + 2]) + "." +
                           std::to_string(data[offset + 3]) + "." +
                           std::to_string(data[offset + 4]);
        uint16_t port = (static_cast<uint16_t>(data[offset + 5]) << 8) |
                        data[offset + 6];
        return {host, port, 7};
    }

    if (atyp == SOCKS5_ATYP_DOMAIN) {
        if (offset + 1 >= data_size) {
            throw std::invalid_argument("Insufficient data for domain length");
        }
        uint8_t domain_len = data[offset + 1];
        if (offset + 2 + domain_len + 2 > data_size) {
            throw std::invalid_argument("Insufficient data for domain address");
        }
        std::string host(reinterpret_cast<const char*>(data + offset + 2),
                         domain_len);
        size_t port_offset = offset + 2 + domain_len;
        uint16_t port = (static_cast<uint16_t>(data[port_offset]) << 8) |
                        data[port_offset + 1];
        // Frame consumed from `offset` (at the ATYP byte):
        // ATYP(1) + LEN(1) + domain + PORT(2) = 4 + domain_len.
        return {host, port, 4 + static_cast<size_t>(domain_len)};
    }

    if (atyp == SOCKS5_ATYP_IPV6) {
        if (data_size < offset + 19) {
            throw std::invalid_argument("Insufficient data for IPv6 address");
        }
        std::array<unsigned char, 16> bytes{};
        std::copy_n(data + offset + 1, bytes.size(), bytes.begin());
        std::string host = asio::ip::address_v6(bytes).to_string();
        uint16_t port = (static_cast<uint16_t>(data[offset + 17]) << 8) |
                        data[offset + 18];
        return {host, port, 19};
    }

    throw std::invalid_argument("Unsupported address type: " + std::to_string(atyp));
}

ParsedAddress parse_address(byte_view data, size_t offset) {
    return parse_address(data.data(), data.size(), offset);
}

std::vector<uint8_t> encode_address(std::string_view host, uint16_t port) {
    std::vector<uint8_t> result;
    const std::string host_str(host);
    std::error_code ec;
    const auto ip = asio::ip::make_address(host_str, ec);

    if (!ec && ip.is_v4()) {
        result.push_back(SOCKS5_ATYP_IPV4);
        const auto bytes = ip.to_v4().to_bytes();
        for (uint8_t byte : bytes) {
            result.push_back(byte);
        }
        result.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(port & 0xFF));
    } else if (!ec && ip.is_v6()) {
        result.push_back(SOCKS5_ATYP_IPV6);
        const auto bytes = ip.to_v6().to_bytes();
        for (uint8_t byte : bytes) {
            result.push_back(byte);
        }
        result.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(port & 0xFF));
    } else {
        if (host.size() > 255) {
            throw std::invalid_argument("Domain name too long");
        }
        result.push_back(SOCKS5_ATYP_DOMAIN);
        result.push_back(static_cast<uint8_t>(host.size()));
        for (char c : host) {
            result.push_back(static_cast<uint8_t>(c));
        }
        result.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(port & 0xFF));
    }

    return result;
}

bool is_restricted_target(const asio::ip::address& addr) {
    if (addr.is_v4()) {
        const auto v4 = addr.to_v4();
        const uint32_t a = v4.to_uint();
        const uint8_t o0 = static_cast<uint8_t>((a >> 24) & 0xFF);
        const uint8_t o1 = static_cast<uint8_t>((a >> 16) & 0xFF);
        const uint8_t o2 = static_cast<uint8_t>((a >> 8) & 0xFF);
        if (v4.is_unspecified() || v4.is_loopback() || v4.is_multicast()) {
            return true;
        }
        if (o0 == 0) return true;                              // 0.0.0.0/8
        if (o0 == 10) return true;                             // 10.0.0.0/8
        if (o0 == 100 && (o1 & 0xC0) == 64) return true;       // 100.64.0.0/10 CGN
        if (o0 == 169 && o1 == 254) return true;               // 169.254.0.0/16
        if (o0 == 172 && (o1 & 0xF0) == 16) return true;       // 172.16.0.0/12
        if (o0 == 192 && o1 == 168) return true;               // 192.168.0.0/16
        // 192.0.0.0/24 (IETF protocol assignments) and 192.0.2.0/24
        // (TEST-NET-1). Note o2 must be exactly 0 or 2 — the previous
        // `o2 <= 2` also swallowed 192.0.1.0/24, which is globally routable.
        if (o0 == 192 && o1 == 0 && (o2 == 0 || o2 == 2)) return true;
        if (o0 == 192 && o1 == 88 && o2 == 99) return true;    // 192.88.99.0/24 6to4 relay anycast (deprecated)
        if (o0 == 198 && (o1 == 18 || o1 == 19)) return true;  // 198.18.0.0/15
        if (o0 == 198 && o1 == 51 && o2 == 100) return true;   // 198.51.100.0/24
        if (o0 == 203 && o1 == 0 && o2 == 113) return true;    // 203.0.113.0/24
        if (o0 >= 240) return true;                            // 240.0.0.0/4 reserved (class E)
        return false;
    }
    if (addr.is_v6()) {
        const auto v6 = addr.to_v6();
        // IPv4-mapped ::ffff:a.b.c.d: inherit the IPv4 classification.
        if (v6.is_v4_mapped()) {
            return is_restricted_target(v6.to_v4());
        }
        const auto bytes = v6.to_bytes();

        // IPv6 transition mechanisms EMBED an IPv4 address, so they can
        // tunnel straight into the IPv4 ranges blocked above (e.g.
        // 2002:7f00:0001::1 carries 127.0.0.1). Classify the embedded IPv4
        // instead of trusting the IPv6 surface, otherwise these prefixes are
        // an SSRF bypass. (Recursion terminates: the embedded address is v4.)
        auto embedded_v4 = [&bytes](size_t i) {
            const asio::ip::address_v4::bytes_type b{
                bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]};
            return asio::ip::address(asio::ip::address_v4(b));
        };
        // 6to4 (2002::/16): the encapsulated IPv4 address lives in bytes 2-5.
        if (bytes[0] == 0x20 && bytes[1] == 0x02 &&
            is_restricted_target(embedded_v4(2))) {
            return true;
        }
        // Teredo (2001:0000::/32): the Teredo server's IPv4 is in bytes 4-7
        // and the client's IPv4 (bit-inverted) in bytes 12-15. Refuse the
        // address if EITHER embeds a restricted IPv4.
        if (bytes[0] == 0x20 && bytes[1] == 0x01 &&
            bytes[2] == 0x00 && bytes[3] == 0x00) {
            if (is_restricted_target(embedded_v4(4))) {
                return true;
            }
            const asio::ip::address_v4::bytes_type client_b{
                static_cast<unsigned char>(~bytes[12]),
                static_cast<unsigned char>(~bytes[13]),
                static_cast<unsigned char>(~bytes[14]),
                static_cast<unsigned char>(~bytes[15])};
            if (is_restricted_target(asio::ip::address_v4(client_b))) {
                return true;
            }
        }
        // IPv4-compatible ::a.b.c.d (deprecated ::/96): tail bytes ARE the
        // IPv4 address. :: and ::1 are already caught by the checks below.
        {
            bool v4_compat = true;
            for (int i = 0; i < 12; ++i) {
                if (bytes[i] != 0) { v4_compat = false; break; }
            }
            if (v4_compat && is_restricted_target(embedded_v4(12))) {
                return true;
            }
        }

        if (v6.is_loopback() || v6.is_unspecified() || v6.is_link_local() ||
            v6.is_multicast() || (bytes[0] & 0xFE) == 0xFC) {  // fc00::/7 unique-local
            return true;
        }
        // 2001:db8::/32 documentation range.
        if (bytes[0] == 0x20 && bytes[1] == 0x01 &&
            bytes[2] == 0x0d && bytes[3] == 0xb8) {
            return true;
        }
        return false;
    }
    return false;
}

} // namespace kcp_proxy
