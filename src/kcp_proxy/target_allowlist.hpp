#pragma once

// --allow-target entry parsing and matching.
//
// The allowlist is the ONLY bypass of the SSRF guard, so its parser is
// deliberately strict and fail-closed: a malformed entry is skipped (or
// rejected at startup by the CLI), never interpreted loosely. Loose parsing
// had two real wrapping bugs here:
//   "host:99999" -> std::stoi gives 99999, static_cast<uint16_t> wraps to
//                   34463, silently allowlisting the wrong port;
//   "host:-1"    -> -1 wraps to 65535.
// Both must fail closed instead.

#include <cstdint>
#include <string>
#include <vector>

namespace kcp_proxy {

// Parse one allowlist entry into (host, has_port, port).
// Accepted forms:
//   "host"            host-only: matches every port on that host
//   "host:port"       host + exact port
//   "[v6]"            bracketed IPv6, host-only
//   "[v6]:port"       bracketed IPv6 + exact port
//   "::1"             bare multi-colon IPv6 literal, host-only
// Rejected (returns false): empty entries, trailing garbage, non-numeric or
// out-of-range ports ("host:", "host:-1", "host:99999", "host:80x",
// "[::1]junk").
inline bool parse_allow_target_entry(const std::string& entry,
                                     std::string& host,
                                     bool& has_port,
                                     uint16_t& port) {
    has_port = false;
    port = 0;

    if (entry.empty()) return false;

    if (entry.front() == '[') {
        auto close = entry.find(']');
        if (close == std::string::npos) return false;
        host = entry.substr(1, close - 1);
        if (host.empty()) return false;
        if (close + 1 == entry.size()) return true;           // "[v6]"
        if (entry[close + 1] != ':') return false;            // "[v6]junk"
        const std::string port_part = entry.substr(close + 2);
        if (port_part.empty()) return false;                  // "[v6]:"
        for (const char c : port_part) {
            if (c < '0' || c > '9') return false;
        }
        const long value = std::stol(port_part);
        if (value < 1 || value > 65535) return false;
        port = static_cast<uint16_t>(value);
        has_port = true;
        return true;
    }

    const auto colon = entry.rfind(':');
    if (colon != std::string::npos && entry.find(':') != colon) {
        // More than one ':': a bare IPv6 literal; the whole entry is the host.
        host = entry;
        return true;
    }
    if (colon != std::string::npos) {
        host = entry.substr(0, colon);
        const std::string port_part = entry.substr(colon + 1);
        if (host.empty() || port_part.empty()) return false;  // ":80" / "host:"
        for (const char c : port_part) {
            if (c < '0' || c > '9') return false;             // "-1" / "80x"
        }
        const long value = std::stol(port_part);
        if (value < 1 || value > 65535) return false;         // "99999"
        port = static_cast<uint16_t>(value);
        has_port = true;
        return true;
    }
    host = entry;
    return true;
}

// True iff (host, port) matches an entry. A host-only entry matches every
// port on that host (documented "HOST[:PORT]" semantics). Malformed entries
// match nothing; there is no wildcard support, so a '*' entry is inert.
inline bool target_matches_allowlist(const std::vector<std::string>& entries,
                                     const std::string& host, uint16_t port) {
    for (const auto& entry : entries) {
        std::string entry_host;
        bool has_port = false;
        uint16_t entry_port = 0;
        if (!parse_allow_target_entry(entry, entry_host, has_port, entry_port)) {
            continue;
        }
        if (entry_host == host && (!has_port || entry_port == port)) {
            return true;
        }
    }
    return false;
}

} // namespace kcp_proxy
