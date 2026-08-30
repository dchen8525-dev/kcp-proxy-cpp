#include "kcp_proxy/logger.hpp"
#include <atomic>
#include <chrono>
#include <ctime>
#include <iostream>
#include <mutex>

#ifdef __ANDROID__
#include <android/log.h>
#include <cstdio>
#endif

namespace kcp_proxy {

namespace {
std::atomic<LogLevel> g_log_level{LogLevel::Info};
std::mutex g_log_mutex;

#ifdef __ANDROID__
FILE* g_log_file = nullptr;
#endif

bool to_local_time(std::time_t t, std::tm& out) {
#if defined(_WIN32)
    return localtime_s(&out, &t) == 0;
#else
    return localtime_r(&t, &out) != nullptr;
#endif
}
} // namespace

void set_log_level(LogLevel level) {
    g_log_level.store(level, std::memory_order_relaxed);
}

LogLevel current_log_level() noexcept {
    return g_log_level.load(std::memory_order_relaxed);
}

void set_log_file_path(const char* path) {
#ifdef __ANDROID__
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file) {
        std::fclose(g_log_file);
        g_log_file = nullptr;
    }
    if (path) {
        g_log_file = std::fopen(path, "a");
    }
#else
    (void)path;
#endif
}

void log(LogLevel level, std::string_view module, std::string_view message) {
    // Re-check level: callers may have skipped the macro short-circuit.
    if (level < current_log_level()) return;

    const char* level_str;
    switch (level) {
    case LogLevel::Debug:   level_str = "DEBUG"; break;
    case LogLevel::Info:    level_str = "INFO"; break;
    case LogLevel::Warning: level_str = "WARNING"; break;
    case LogLevel::Error:   level_str = "ERROR"; break;
    default:                level_str = "UNKNOWN"; break;
    }

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    to_local_time(t, tm);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    // Use fmt for high-performance formatting
    char time_buf[32];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
    auto line = fmt::format("{}.{:03d} [{}] {}: {}", time_buf, ms.count(), level_str, module, message);

#ifdef __ANDROID__
    int prio = ANDROID_LOG_INFO;
    if (level == LogLevel::Debug) prio = ANDROID_LOG_DEBUG;
    else if (level == LogLevel::Warning) prio = ANDROID_LOG_WARN;
    else if (level == LogLevel::Error) prio = ANDROID_LOG_ERROR;
    __android_log_print(prio, "kcp_proxy", "%s", line.c_str());

    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        if (g_log_file) {
            std::fprintf(g_log_file, "%s\n", line.c_str());
            std::fflush(g_log_file);
        }
    }
#else
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        std::cerr << line << '\n';
    }
#endif
}

} // namespace kcp_proxy