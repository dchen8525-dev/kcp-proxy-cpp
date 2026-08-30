#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace asio { namespace ip { class address; } }

namespace kcp_proxy {

struct byte_view;

struct ParsedAddress {
    std::string host;
    uint16_t port = 0;
    size_t bytes_consumed = 0;
};

ParsedAddress parse_address(const uint8_t* data, size_t data_size, size_t offset = 0);
ParsedAddress parse_address(byte_view data, size_t offset = 0);
std::vector<uint8_t> encode_address(std::string_view host, uint16_t port);

// True if the address must never be a SOCKS5 CONNECT target: loopback,
// private, link-local, CGN, multicast, unspecified, broadcast, or
// documentation/test ranges. The server rejects such targets so an
// authenticated client cannot use it as a pivot into the server's own network
// (SSRF / internal port scan).
bool is_restricted_target(const asio::ip::address& addr);

} // namespace kcp_proxy
