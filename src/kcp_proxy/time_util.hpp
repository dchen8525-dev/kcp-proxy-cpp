#pragma once

#include <chrono>
#include <cstdint>

namespace kcp_proxy {

inline int64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

inline uint32_t now_kcp_ms() {
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

} // namespace kcp_proxy
