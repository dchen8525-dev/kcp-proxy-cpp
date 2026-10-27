#include "kcp_proxy/logger.hpp"

#include <spdlog/details/fmt_helper.h>
#include <spdlog/formatter.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/spdlog.h>

#ifdef __ANDROID__
#include <android/log.h>
#include <spdlog/sinks/android_sink.h>
#else
#include <spdlog/sinks/stdout_sinks.h>
#endif

#include <algorithm>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace kcp_proxy {

namespace {

// The whole logging backend is spdlog: level filtering, timestamping, module
// prefixing and the stderr/file sinks are its job. What stays ours is the
// FORMAT CONTRACT and the test sink:
//
//   YYYY-MM-DD HH:MM:SS.mmm [LEVEL] module: message
//
// tests/e2e/robustness_e2e.py:525 slices line[:23] and parses it with
// "%Y-%m-%d %H:%M:%S.%f" to measure the auth limiter's rate, and the docs
// (docs/ANDROID_INTEROP.md) quote the "[INFO] server: ..." shape. Changing the
// pattern silently breaks both, so it is pinned here rather than left to
// spdlog's default ("[2026-01-01 00:00:00.000] [info] [name] msg").
constexpr const char* kPattern = "%Y-%m-%d %H:%M:%S.%e [%l] %n: %v";

// What the formatter substitutes for spdlog's lowercase %l.
constexpr char kLevelPlaceholder = '\x01';

// kPattern with the whole `[%l]` field swapped for the bracketed placeholder.
// The formatter must derive its pattern from kPattern rather than restate it:
// the previous version carried a second, subtly different literal (the same
// string with [\x01] in place of [%l]) right here in the constructor, so
// editing the constant above -- the documented contract -- silently changed
// nothing. tests/smoke asserts the pattern appears exactly once in this file,
// and tests/e2e asserts the emitted line shape, which is what keeps the two
// from drifting apart again.
//
// The replacement is on "[%l]", not on "%l": kPattern already brackets the
// level, and substituting only the %l doubles them ("[[INFO]]"), which no
// longer matches the GUI's prefix regex or the documented shape.
std::string formatter_pattern() {
    std::string pattern(kPattern);
    const std::string level_field = "[%l]";
    const size_t at = pattern.find(level_field);
    if (at != std::string::npos) {
        pattern.replace(at, level_field.size(), std::string("[") + kLevelPlaceholder + "]");
    }
    return pattern;
}

// spdlog's %l always renders the level in lowercase ("info"), and the pattern
// language has no uppercase variant, so the [LEVEL] field is the one part of
// the line spdlog cannot reproduce on its own. Everything else in kPattern is
// handled by a pattern_formatter; this wrapper renders the whole pattern with
// a unique placeholder standing in for the level, then substitutes the
// uppercase name. Keeping it a formatter (not a hand-rolled sprintf) means the
// timestamp, %e milliseconds and the logger name still come from spdlog.
class UppercaseLevelFormatter final : public spdlog::formatter {
public:
    UppercaseLevelFormatter() : inner_(formatter_pattern(), spdlog::pattern_time_type::local) {}

    void format(const spdlog::details::log_msg& msg, spdlog::memory_buf_t& dest) override {
        // memory_buf_t (fmt's memory_buffer) is append-only, so the pattern is
        // rendered into a scratch buffer, split at the placeholder, and the
        // three pieces are appended in order. The scratch is reused across
        // calls; the formatter itself is owned by one sink and its log() is
        // serialized by the sink's mutex.
        scratch_.clear();
        inner_.format(msg, scratch_);
        // std::string_view for the search (spdlog's fmt::string_view has no
        // find/substr); converted to spdlog's type only for append.
        const std::string_view line(scratch_.data(), scratch_.size());
        const size_t marker = line.find(kLevelPlaceholder);
        auto append = [&dest](std::string_view piece) {
            spdlog::details::fmt_helper::append_string_view(
                spdlog::string_view_t(piece.data(), piece.size()), dest);
        };
        if (marker == std::string_view::npos) {
            append(line);
            return;
        }
        append(line.substr(0, marker));
        append(uppercase_level(msg.level));
        append(line.substr(marker + 1));
    }

    std::unique_ptr<spdlog::formatter> clone() const override {
        return std::make_unique<UppercaseLevelFormatter>();
    }

private:
    static std::string_view uppercase_level(spdlog::level::level_enum level);

    spdlog::pattern_formatter inner_;
    spdlog::memory_buf_t scratch_;
};

// One shared sink plus one logger per module (see module_logger below). Level
// filtering happens in spdlog (it compares against logger->level()), and the
// LOG_* macros keep hoisting the same check to the call site so a filtered
// line never builds its message string.
spdlog::sink_ptr g_sink;
std::unordered_map<std::string, std::shared_ptr<spdlog::logger>> g_module_loggers;
std::mutex g_logger_mutex;

// Test sink (see set_log_sink_for_test in the header). Invoked AFTER the line
// has been written, never while holding g_logger_mutex: a sink that logged
// again (or asserted) would otherwise deadlock on it.
std::mutex g_sink_mutex;
LogSink g_log_sink;

// spdlog levels are not our enum's integers (trace=0 .. critical=5, while ours
// is Debug=0 .. Error=3), so the mapping is explicit and exhaustive.
spdlog::level::level_enum to_spdlog(LogLevel level) {
    switch (level) {
        case LogLevel::Debug:
            return spdlog::level::debug;
        case LogLevel::Info:
            return spdlog::level::info;
        case LogLevel::Warning:
            return spdlog::level::warn;
        case LogLevel::Error:
            return spdlog::level::err;
    }
    return spdlog::level::info;
}

LogLevel from_spdlog(spdlog::level::level_enum level) {
    switch (level) {
        case spdlog::level::trace:
        case spdlog::level::debug:
            return LogLevel::Debug;
        case spdlog::level::warn:
            return LogLevel::Warning;
        case spdlog::level::err:
        case spdlog::level::critical:
            return LogLevel::Error;
        default:
            return LogLevel::Info;
    }
}

// to_spdlog/from_spdlog fold trace into Debug and critical into Error, so the
// spdlog level maps back to our enum and the name comes from the single
// definition in logger.hpp -- the exact four strings the previous
// implementation printed.
std::string_view UppercaseLevelFormatter::uppercase_level(spdlog::level::level_enum level) {
    return log_level_name(from_spdlog(level));
}

// One sink for the life of the process. Deliberately NOT registered as
// spdlog's default logger, and never reached through spdlog::info() and
// friends: third-party code using those keeps its own output, unmixed with
// our format.
spdlog::sink_ptr make_sink() {
#ifdef __ANDROID__
    // Android has no stderr to read; the existing behaviour is logcat only.
    return std::make_shared<spdlog::sinks::android_sink_mt>("kcp_proxy");
#else
    // stderr, NOT stdout: systemd routes StandardOutput/StandardError to
    // LOG_FILE (scripts/deploy/install-service.sh) and scripts/runtime/start.sh
    // relies on both landing in the same stream. A stdout sink would also
    // interleave badly with a foreground run's terminal.
    return std::make_shared<spdlog::sinks::stderr_sink_mt>();
#endif
}

spdlog::sink_ptr shared_sink() {
    std::lock_guard<std::mutex> lock(g_logger_mutex);
    if (!g_sink) {
        g_sink = make_sink();
        g_sink->set_formatter(std::make_unique<UppercaseLevelFormatter>());
    }
    return g_sink;
}

// spdlog's logger carries its name, which is the "%n" field of kPattern -- so
// there is one logger per MODULE ("server", "crypto", "kcp_session", ...), not
// one for the process. They all share one mutex-protected sink, i.e. the same
// serialization the previous global g_log_mutex provided, so a burst on two
// strands still produces whole, unmixed lines.
std::shared_ptr<spdlog::logger> module_logger(std::string_view module) {
    std::shared_ptr<spdlog::logger> lg;
    {
        std::lock_guard<std::mutex> lock(g_logger_mutex);
        for (const auto& entry : g_module_loggers) {
            if (entry.first == module) return entry.second;
        }
    }
    // Built outside the lock: only the registration needs it. A concurrent
    // first call for the same module may build a duplicate that the insert
    // below discards -- harmless, as both wrap the same sink.
    lg = std::make_shared<spdlog::logger>(std::string(module), shared_sink());
    lg->set_level(to_spdlog(current_log_level()));

    std::lock_guard<std::mutex> lock(g_logger_mutex);
    auto it = g_module_loggers.find(std::string(module));
    if (it != g_module_loggers.end()) return it->second;
    // Re-read the level under the registration lock. A set_log_level() that
    // ran between the unlocked build above and this lock walked a map that did
    // not yet contain lg, so without this re-read a logger registered in that
    // window would keep the stale level for the rest of the process (its own
    // filtering, independent of the header atomic the macros check).
    lg->set_level(to_spdlog(current_log_level()));
    g_module_loggers.emplace(std::string(module), lg);
    return lg;
}

// spdlog reports sink/format failures (a full disk, a bad pattern) through its
// error handler instead of throwing into the logging path, which matters here
// because log() is called from crypto and session teardown. Installing it once
// keeps a broken log visible to the operator without taking the process down.
void install_error_handler() {
    static const bool installed = [] {
        spdlog::set_error_handler([](const std::string& msg) {
            std::fprintf(stderr, "logger: spdlog error: %s\n", msg.c_str());
        });
        return true;
    }();
    (void)installed;
}

} // namespace

void set_log_sink_for_test(LogSink sink) {
    std::lock_guard<std::mutex> lock(g_sink_mutex);
    g_log_sink = std::move(sink);
}

void set_log_level(LogLevel level) {
    // Kept in the header's atomic so the LOG_* macros' hot-path check stays
    // lock-free, and mirrored into spdlog for the logging path itself.
    detail::store_log_level(level);
    const auto spd_level = to_spdlog(level);
    std::lock_guard<std::mutex> lock(g_logger_mutex);
    // Only walk the loggers that already exist: module_logger() builds any
    // later one with the current level, so this list cannot go stale.
    for (auto& [name, lg] : g_module_loggers) {
        lg->set_level(spd_level);
    }
}

LogLevel current_log_level() noexcept {
    return detail::load_log_level();
}

void set_log_file_path(const char* path) {
    // Non-Android builds write to stderr and let the service supervisor
    // (systemd StandardOutput/StandardError, or a shell redirect) own the file;
    // that is why LOG_FILE lives in server.env rather than in the logger. Keep
    // the symbol for the callers that pass it, and make the Android file path
    // work through spdlog's android_sink if one is ever needed.
    (void)path;
}

void log(LogLevel level, std::string_view module, std::string_view message) {
    // Re-check level: callers may have skipped the macro short-circuit.
    if (level < current_log_level()) return;

    install_error_handler();
    auto lg = module_logger(module);
    const spdlog::level::level_enum spd_level = to_spdlog(level);
    if (!lg->should_log(spd_level)) return;

    // The message is already formatted by the caller (every LOG_* macro takes
    // a fully built std::string), so it goes through spdlog's pass-through
    // path -- no format string, no braces to interpret.
    lg->log(spd_level, message);

    LogSink sink;
    {
        std::lock_guard<std::mutex> lock(g_sink_mutex);
        sink = g_log_sink;
    }
    if (sink) sink(level, module, message);
}

} // namespace kcp_proxy
