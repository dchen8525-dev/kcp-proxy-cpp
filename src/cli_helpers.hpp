#pragma once

#include "kcp_proxy/logger.hpp"
#include <asio.hpp>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

namespace kcp_proxy {
namespace cli {

inline std::string get_arg(int argc, char* argv[], int& i) {
    if (i + 1 < argc) {
        return argv[++i];
    }
    return "";
}

inline bool get_port_arg(int argc, char* argv[], int& i, uint16_t& out) {
    std::string val = get_arg(argc, argv, i);
    if (val.empty()) return false;
    try {
        unsigned long v = std::stoul(val);
        if (v > 65535) {
            std::cerr << "Error: port out of range\n";
            return false;
        }
        out = static_cast<uint16_t>(v);
        return true;
    } catch (const std::exception&) {
        std::cerr << "Error: invalid port '" << val << "'\n";
        return false;
    }
}

// Read an environment variable ("" when unset). Used as an alternative
// channel for --key: a secret passed as argv is visible to every local user
// (Task Manager / wmic on Windows, /proc/<pid>/cmdline on Linux), while the
// process environment is readable only by the same user (or root). GUIs
// should therefore set KCP_PROXY_KEY instead of spawning with -k <key>.
inline std::string get_env(const char* name) {
#ifdef _WIN32
    // MSVC deprecates getenv (C4996); _dupenv_s is the sanctioned form and is
    // also provided by MinGW-w64.
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, name) != 0 || buf == nullptr) {
        return {};
    }
    std::string value(buf);
    std::free(buf);
    return value;
#else
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
#endif
}

inline void secure_wipe(std::string& s) {
    volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(s.data());
    for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
}

inline void parse_log_level(const std::string& log_level) {
    std::string lower = log_level;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower == "debug") set_log_level(LogLevel::Debug);
    else if (lower == "info") set_log_level(LogLevel::Info);
    else if (lower == "warning") set_log_level(LogLevel::Warning);
    else if (lower == "error") set_log_level(LogLevel::Error);
    else std::cerr << "Warning: unknown log level '" << log_level << "'\n";
}

template <typename StopFn>
inline void setup_signal_handler(asio::io_context& io, StopFn stop_fn) {
    auto signals = std::make_shared<asio::signal_set>(io, SIGINT
#ifdef SIGTERM
        , SIGTERM
#endif
#ifdef SIGBREAK
        , SIGBREAK
#endif
    );
    signals->async_wait([&io, signals, stop = std::move(stop_fn)](const std::error_code&, int) {
        LOG_INFO("main", "Shutting down...");
        stop();
        io.stop();
    });
}

} // namespace cli
} // namespace kcp_proxy
