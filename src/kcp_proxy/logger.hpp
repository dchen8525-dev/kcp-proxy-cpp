#pragma once

#include <fmt/format.h>
#include <cstdint>
#include <functional>
#include <limits>
#include <mutex>
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
// The tally saturates at UINT32_MAX instead of wrapping: a sustained flood
// folds occurrences into it for as long as the condition lasts, so an
// unbounded rate eventually exceeds 2^32 and a wrapping counter would report a
// count lower than what was actually dropped -- understating the very signal
// an operator reads to size the attack. 2^32 suppressed datagrams in one
// interval is not reachable in practice; UB is.
//
// Thread-safe: should_log()/pending() are internally synchronized. The original
// contract required callers to serialize (the server's UDP strand did), but
// Crypto::decrypt_impl's rejection paths run on the UDP strand AND every
// session strand, so a shared instance there would race -- and a per-instance
// throttle cannot bound the aggregate. The mutex is uncontended on every
// strand-confined call site and costs orders of magnitude less than the log
// write it guards.
class LogThrottle {
public:
    explicit LogThrottle(std::chrono::milliseconds interval = std::chrono::seconds(1))
        : interval_(interval) {}

    // Returns true if the caller should emit its line now. On true, `suppressed`
    // receives how many occurrences were folded into this emission (0 for the
    // first line of a window); on false it is left untouched. The first call
    // always emits, so a one-off rejection is never lost.
    bool should_log(uint32_t& suppressed) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (now - window_start_ < interval_) {
            note_suppressed_locked(1);
            return false;
        }
        window_start_ = now;
        suppressed = clamp_to_u32(suppressed_);
        suppressed_ = 0;
        return true;
    }

    // How many occurrences this throttle has swallowed since the last emission.
    // Lets a caller surface a final tally on a teardown path.
    uint32_t pending() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return clamp_to_u32(suppressed_);
    }

    // Test-only: fold `n` occurrences into the tally without waiting for real
    // traffic. Reaching the 2^32 saturation point otherwise needs billions of
    // hostile datagrams, so this is what makes the saturating behaviour (and
    // the no-wrap invariant it protects) testable at all.
    void add_suppressed_for_test(uint64_t n) {
        std::lock_guard<std::mutex> lock(mutex_);
        note_suppressed_locked(n);
    }

private:
    // Saturating add: see the class comment.
    void note_suppressed_locked(uint64_t n) {
        constexpr uint64_t kMax = std::numeric_limits<uint64_t>::max();
        if (suppressed_ > kMax - n) {
            suppressed_ = kMax;
        } else {
            suppressed_ += n;
        }
    }
    static uint32_t clamp_to_u32(uint64_t v) {
        constexpr uint64_t kU32Max = std::numeric_limits<uint32_t>::max();
        return v > kU32Max ? kU32Max : static_cast<uint32_t>(v);
    }

    mutable std::mutex mutex_;
    std::chrono::steady_clock::time_point window_start_{};
    std::chrono::milliseconds interval_;
    // Wide enough that it cannot wrap, so saturation is the only clamping the
    // reported count ever needs.
    uint64_t suppressed_ = 0;
};

void set_log_level(LogLevel level);
LogLevel current_log_level() noexcept;
void set_log_file_path(const char* path);
void log(LogLevel level, std::string_view module, std::string_view message);

// Test-only: receive every line the logger actually emits, in addition to the
// normal stderr/file output. Logging is the only observable side effect of the
// server's rejection paths, so counting lines is the only way to assert that a
// per-datagram diagnostic is bounded -- the property every LogThrottle in this
// codebase exists to provide, and the one that silently regressed twice
// (unthrottled WARNINGs, then a shared throttle masking its sibling's line).
// Pass an empty function to uninstall. Not thread-safe against concurrent
// install/uninstall; tests install it before starting traffic.
using LogSink = std::function<void(LogLevel, std::string_view, std::string_view)>;
void set_log_sink_for_test(LogSink sink);

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