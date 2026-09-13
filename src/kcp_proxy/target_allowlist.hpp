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

namespace detail {

// Convert a decimal port, rejecting anything that is not a plain in-range
// decimal. The length gate is what makes std::stol safe to call: "all digits"
// does NOT imply "fits in a long", and on Windows (32-bit long) a port like
// "3000000000" made std::stol throw std::out_of_range. Because --allow-target
// is parsed in main()'s argv loop -- outside its try block -- that exception
// escaped as an uncaught exception, so the documented clean rejection
// ("Error: invalid --allow-target entry ...") never printed: the process just
// aborted with no diagnostic at all. 5 digits is the widest valid port (65535),
// so anything longer is out of range by construction and needs no conversion.
// A zero-padded port longer than 5 digits ("0065535") is consequently rejected
// as well: deliberate, and consistent with this file's fail-closed contract for
// an SSRF allowlist. Padding that still fits ("00080") parses normally -- the
// value is unambiguous.
inline bool parse_port_digits(const std::string& digits, uint16_t& port) {
    if (digits.empty() || digits.size() > 5) return false;
    for (const char c : digits) {
        if (c < '0' || c > '9') return false;
    }
    const long value = std::stol(digits);
    if (value < 1 || value > 65535) return false;
    port = static_cast<uint16_t>(value);
    return true;
}

} // namespace detail

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
        if (!detail::parse_port_digits(port_part, port)) {    // "[v6]:" / "[v6]:80x"
            return false;
        }
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
        if (host.empty()) return false;                       // ":80"
        const std::string port_part = entry.substr(colon + 1);
        if (!detail::parse_port_digits(port_part, port)) {    // "host:" / "-1" / "80x" / "99999"
            return false;
        }
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
