#include "kcp_proxy/server.hpp"
#include "kcp_proxy/target_allowlist.hpp"
#include "cli_helpers.hpp"
#include <asio.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace kcp_proxy;

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  -p, --port PORT        UDP listen port (default: 8388)\n"
              << "  -H, --host HOST        Bind address (default: 0.0.0.0)\n"
              << "  -k, --key KEY          Encryption key (min 16 chars; alternatively\n"
              << "                         set the KCP_PROXY_KEY environment variable)\n"
              << "  -T, --threads N        io_context worker threads (default: 1).\n"
              << "                         KCP updates run on a single shared 10ms tick;\n"
              << "                         extra threads spread UDP/TCP I/O across cores.\n"
              << "                         Thread safety comes from per-session strands\n"
              << "                         and the shared_mutex-protected session map.\n"
              << "  -L, --log-level LEVEL  Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)\n"
              << "  --allow-target HOST[:PORT]  Allow a specific lab/test target to bypass\n"
              << "                         the SSRF guard (repeatable). Off by default; never\n"
              << "                         expose this in production. e.g. --allow-target 127.0.0.1:9000\n";
}

int main(int argc, char* argv[]) {
    uint16_t port = 8388;
    std::string host = "0.0.0.0";
    std::string key;
    std::string log_level = "INFO";
    unsigned int threads = 1;
    std::vector<std::string> allowed_targets;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            if (!cli::get_port_arg(argc, argv, i, port)) return 1;
        } else if ((arg == "-H" || arg == "--host") && i + 1 < argc) {
            host = cli::get_arg(argc, argv, i);
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            key = cli::get_arg(argc, argv, i);
        } else if ((arg == "-T" || arg == "--threads") && i + 1 < argc) {
            // Strict digits-only parse, deliberately stricter than std::stoul.
            // stoul throws on "-T abc" / an over-long number, and this argv loop
            // runs OUTSIDE main()'s try block, so the exception escaped as an
            // uncaught exception: the process aborted with no diagnostic instead
            // of printing an error. It also accepts trailing junk ("-T 4abc"
            // silently meant 4). The allowlist parser rejects "80x" for exactly
            // that reason, so stay consistent. The length gate (2 digits covers
            // the 1..64 range) keeps the conversion provably in range on every
            // platform, so nothing can throw here.
            const std::string value = cli::get_arg(argc, argv, i);
            if (value.empty() || value.size() > 2 ||
                value.find_first_not_of("0123456789") != std::string::npos) {
                std::cerr << "Error: --threads must be between 1 and 64" << std::endl;
                return 1;
            }
            // Range-check BEFORE narrowing: assigning std::stoul's result
            // straight to `unsigned int` truncated it first, so "-T 4294967297"
            // wrapped to 1 and was accepted as a single-threaded server.
            const unsigned long parsed = std::stoul(value);
            if (parsed == 0 || parsed > 64) {
                std::cerr << "Error: --threads must be between 1 and 64" << std::endl;
                return 1;
            }
            threads = static_cast<unsigned int>(parsed);
        } else if ((arg == "-L" || arg == "--log-level") && i + 1 < argc) {
            log_level = cli::get_arg(argc, argv, i);
        } else if (arg == "--allow-target" && i + 1 < argc) {
            const std::string value = cli::get_arg(argc, argv, i);
            std::string parsed_host;
            bool has_port = false;
            uint16_t parsed_port = 0;
            // Fail loudly: a malformed entry (e.g. "host:99999" or a missing
            // value) is a typo an operator must see, not a silently inert
            // allowlist row. The parser is fail-closed either way.
            if (!kcp_proxy::parse_allow_target_entry(value, parsed_host,
                                                     has_port, parsed_port)) {
                std::cerr << "Error: invalid --allow-target entry '" << value
                          << "' (expected HOST[:PORT] or [IPv6][:PORT])"
                          << std::endl;
                return 1;
            }
            allowed_targets.push_back(value);
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    if (key.empty()) {
        // Fallback channel for tooling: the environment keeps the secret out
        // of the command line, which is visible to every local user.
        key = cli::get_env("KCP_PROXY_KEY");
    }
    if (key.empty()) {
        std::cerr << "Error: --key is required (or set KCP_PROXY_KEY)" << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    if (key.size() < 16) {
        std::cerr << "Error: key must be at least 16 characters" << std::endl;
        return 1;
    }

    cli::parse_log_level(log_level);

    try {
        asio::io_context io;
        asio::executor_work_guard<asio::io_context::executor_type> work_guard(io.get_executor());
        auto server = std::make_shared<KCPServer>(io, port, key, host);
        cli::secure_wipe(key);
        server->set_allowed_targets(allowed_targets);
        server->start();

        LOG_INFO("main", "KCP proxy server started on " + host + ":" + std::to_string(port));

        cli::setup_signal_handler(io, [server]() { server->stop(); });

        std::vector<std::thread> io_threads;
        io_threads.reserve(threads);
        for (unsigned int t = 1; t < threads; ++t) {
            io_threads.emplace_back([&io]() { io.run(); });
        }
        io.run();
        for (auto& t : io_threads) t.join();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
