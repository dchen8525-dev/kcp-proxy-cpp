#pragma once

#include <fmt/format.h>
#include <string>
#include <string_view>
#include <chrono>

namespace kcp_proxy {

enum class LogLevel { Debug, Info, Warning, Error };

// Collapses a log line that would otherwise fire once per piece of hostile
// input into at most one line per interval.
//
// Why this exists: the server's packet-rejection paths run once per received
// datagram. Their work is deliberately capped (the auth rate limiter bounds
// AEAD decrypts to MAX_AUTH_ATTEMPTS_PER_SEC), but the logging that reports the
// rejection was not -- so an attacker blasting garbage over UDP got a formatted
// WARNING line per datagram for free. That is strictly worse than the decrypt it
// replaces: a formatting pass, a timestamp, and a write(2) cost far more than
// one small AES-GCM open. Measured: 5000 hostile datagrams produced 10500 log
// lines, with no upper bound under a sustained flood (log spam and disk fill
// were the cheapest DoS on the server).
//
// Usage:
//     uint32_t suppressed = 0;
//     if (throttle.should_log(suppressed)) {
//         LOG_WARNING("server", "..." + fmt::format(" ({} suppressed)", suppressed));
//     }
//
// Not thread-safe: callers must serialize it (the server's UDP receive path is
// serialized by construction -- exactly one async_receive_from is outstanding
// at a time, and the next is only armed as the last statement of the handler).
class LogThrottle {
public:
    explicit LogThrottle(std::chrono::milliseconds interval = std::chrono::seconds(1))
        : interval_(interval) {}

    // Returns true if the caller should emit its line now. On true, `suppressed`
    // receives how many occurrences were folded into this emission (0 for the
    // first line of a window); on false it is left untouched. The first call
    // always emits, so a one-off rejection is never lost.
    bool should_log(uint32_t& suppressed) {
        const auto now = std::chrono::steady_clock::now();
        if (now - window_start_ < interval_) {
            ++suppressed_;
            return false;
        }
        window_start_ = now;
        suppressed = suppressed_;
        suppressed_ = 0;
        return true;
    }

    // How many occurrences this throttle has swallowed since the last emission.
    // Lets a caller surface a final tally on a teardown path.
    uint32_t pending() const { return suppressed_; }

private:
    std::chrono::steady_clock::time_point window_start_{};
    std::chrono::milliseconds interval_;
    uint32_t suppressed_ = 0;
};

void set_log_level(LogLevel level);
LogLevel current_log_level() noexcept;
void set_log_file_path(const char* path);
void log(LogLevel level, std::string_view module, std::string_view message);

// Performance-optimized logging with fmt library
template <typename... Args>
void log_fmt(LogLevel level, std::string_view module, fmt::format_string<Args...> fmt, Args&&... args) {
    if (static_cast<int>(level) >= static_cast<int>(current_log_level())) {
        try {
            log(level, module, fmt::format(fmt, std::forward<Args>(args)...));
        } catch (const std::exception& e) {
            // Fallback to error message if formatting fails
            log(LogLevel::Error, "logger", std::string("Log format error: ") + e.what());
        }
    }
}

// Convenience macros with fmt support. The level check is hoisted to the call site
// so we don't pay for std::string concatenation in the hot path when the level is filtered.
#define LOG_DEBUG(mod, msg)                                                     \
    do {                                                                        \
        if (::kcp_proxy::LogLevel::Debug >= ::kcp_proxy::current_log_level())  \
            ::kcp_proxy::log(::kcp_proxy::LogLevel::Debug, (mod), (msg));      \
    } while (0)

#define LOG_INFO(mod, msg)                                                      \
    do {                                                                        \
        if (::kcp_proxy::LogLevel::Info >= ::kcp_proxy::current_log_level())   \
            ::kcp_proxy::log(::kcp_proxy::LogLevel::Info, (mod), (msg));       \
    } while (0)

#define LOG_WARNING(mod, msg)                                                   \
    do {                                                                        \
        if (::kcp_proxy::LogLevel::Warning >= ::kcp_proxy::current_log_level()) \
            ::kcp_proxy::log(::kcp_proxy::LogLevel::Warning, (mod), (msg));    \
    } while (0)

#define LOG_ERROR(mod, msg)                                                     \
    do {                                                                        \
        if (::kcp_proxy::LogLevel::Error >= ::kcp_proxy::current_log_level())  \
            ::kcp_proxy::log(::kcp_proxy::LogLevel::Error, (mod), (msg));      \
    } while (0)

// Fmt-based logging macros (more efficient than string concatenation)
#define LOG_DEBUG_FMT(mod, fmt, ...) \
    ::kcp_proxy::log_fmt(::kcp_proxy::LogLevel::Debug, mod, fmt, __VA_ARGS__)

#define LOG_INFO_FMT(mod, fmt, ...) \
    ::kcp_proxy::log_fmt(::kcp_proxy::LogLevel::Info, mod, fmt, __VA_ARGS__)

#define LOG_WARNING_FMT(mod, fmt, ...) \
    ::kcp_proxy::log_fmt(::kcp_proxy::LogLevel::Warning, mod, fmt, __VA_ARGS__)

#define LOG_ERROR_FMT(mod, fmt, ...) \
    ::kcp_proxy::log_fmt(::kcp_proxy::LogLevel::Error, mod, fmt, __VA_ARGS__)

} // namespace kcp_proxy