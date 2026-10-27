#pragma once

#include "kcp_proxy/config.hpp"
#include "kcp_proxy/logger.hpp"

#include <asio.hpp>

#include <CLI/CLI.hpp>
#include <openssl/crypto.h>
#include <cctype>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace kcp_proxy {
namespace cli {

// Overwrite a secret before it leaves scope. The key reaches the process via
// argv or the environment and both outlive the string that holds it here, so
// zeroing only shortens the window -- but it is the window under our control.
//
// OPENSSL_cleanse, not a hand-written volatile loop: it is the same primitive
// Crypto uses for its key material, and it is definitionally resistant to the
// dead-store elimination a plain loop is subject to. Having one cleanse in the
// codebase instead of two also means the "is this wipe real?" question has one
// answer.
inline void secure_wipe(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(s.data(), s.size());
}

// Strict decimal validator for numeric options.
//
// CLI11's default conversion goes through std::stoi, which accepts trailing
// junk ("8388x" -> 8388), a "0x" prefix and leading whitespace. Every one of
// those silently starts the proxy on a different port / thread count than the
// operator typed, with the startup banner confidently reporting the wrong one
// -- a regression this project has already fixed once by hand. The gate makes
// the value provably digits-only, so the conversion behind it cannot truncate.
//
// Chained BEFORE CLI::Range so a typo reports "must be a decimal number"
// rather than a range complaint about a number nobody typed.
inline CLI::Validator positive_decimal(std::string name) {
    return CLI::Validator(
        [](std::string& v) -> std::string {
            if (v.empty() || v.find_first_not_of("0123456789") != std::string::npos) {
                return "must be a non-negative decimal number";
            }
            return {};
        },
        std::move(name));
}

// The key is a secret and has a minimum length; both are checked here so the
// two binaries cannot disagree about what an acceptable key is.
//
// The empty check is not redundant with ->required(): `-k ""` is a PRESENT
// option with an empty value, so CLI11 considers the requirement satisfied and
// -- because the option was given -- never consults KCP_PROXY_KEY. The process
// would then start with a zero-length key. The old hand-rolled parser looked at
// key.empty() after the argv loop, which is why an empty -k used to fall back
// to the environment. Every shipped launcher uses the environment and never
// passes -k at all, so this is a regression guard rather than a live fix.
inline CLI::Validator key_validator() {
    return CLI::Validator(
        [](std::string& v) -> std::string {
            if (v.empty()) {
                return "must not be empty";
            }
            if (v.size() < 16) {
                return "must be at least 16 characters";
            }
            return {};
        },
        "KEY");
}

// Accept any spelling of the four level names, case-insensitively.
//
// The previous hand-rolled parser lowercased before comparing, so "-L WARNING"
// (the spelling this project prints in every log line and in --help) was
// accepted. A plain CLI::IsMember would reject it, which breaks the e2e suite
// and every operator who copied the name from the banner. The declaration
// accepts the canonical lowercase form; this validator decides by lowercasing.
inline CLI::Validator log_level_validator() {
    return CLI::Validator(
        [](std::string& v) -> std::string {
            std::string lower = v;
            for (auto& c : lower) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (lower != "debug" && lower != "info" && lower != "warning" && lower != "error") {
                return "must be one of DEBUG, INFO, WARNING, ERROR";
            }
            return {};
        },
        "LEVEL");
}

// Apply a log level by name, case-insensitively.
//
// Both mains attach log_level_validator() to -L, so by the time control
// reaches here the name is guaranteed to be one of the four -- an unknown
// spelling is rejected at parse time (fail-closed, like --fec), not silently
// mapped to a default. The warning branch below therefore only fires for a
// direct caller that bypasses the validator; it is defense-in-depth, not the
// CLI contract.
inline void parse_log_level(const std::string& log_level) {
    std::string lower = log_level;
    for (auto& c : lower)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower == "debug")
        set_log_level(LogLevel::Debug);
    else if (lower == "info")
        set_log_level(LogLevel::Info);
    else if (lower == "warning")
        set_log_level(LogLevel::Warning);
    else if (lower == "error")
        set_log_level(LogLevel::Error);
    else
        std::cerr << "Warning: unknown log level '" << log_level << "'\n";
}

// 0.2.0 renamed `-fec` to `--fec`; the old single-dash spelling is now an
// unknown argument. CLI11 reports that as "The following arguments were not
// expected: -fec 10:3", which reads like a typo and says nothing about a
// rename -- but a launcher, systemd unit or shell history carrying the old
// spelling is the expected failure right after an upgrade, so the message has
// to name the fix. Returns true when it explained the failure, in which case
// the caller exits without CLI11's own diagnostic.
inline bool explain_legacy_fec(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "-fec" || arg.substr(0, 5) == "-fec=") {
            std::cerr << "Error: -fec was renamed to --fec in KCP-Proxy 0.2.0; "
                         "update the launcher to pass --fec DATA:PARITY\n";
            return true;
        }
    }
    return false;
}

template <typename StopFn>
inline void setup_signal_handler(asio::io_context& io, StopFn stop_fn) {
    auto signals = std::make_shared<asio::signal_set>(io, SIGINT
#ifdef SIGTERM
                                                      ,
                                                      SIGTERM
#endif
#ifdef SIGBREAK
                                                      ,
                                                      SIGBREAK
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
