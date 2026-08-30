#pragma once

#include <fmt/format.h>
#include <string>
#include <string_view>
#include <chrono>

namespace kcp_proxy {

enum class LogLevel { Debug, Info, Warning, Error };

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