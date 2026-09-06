#include "kcp_proxy/server.hpp"
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
              << "                         Each session holds a 10ms update timer, so under\n"
              << "                         heavy load 2-4 threads spread that work across\n"
              << "                         cores. Thread safety comes from per-session strands\n"
              << "                         and the shared_mutex-protected session map.\n"
              << "  -L, --log-level LEVEL  Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)\n";
}

int main(int argc, char* argv[]) {
    uint16_t port = 8388;
    std::string host = "0.0.0.0";
    std::string key;
    std::string log_level = "INFO";
    unsigned int threads = 1;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            if (!cli::get_port_arg(argc, argv, i, port)) return 1;
        } else if ((arg == "-H" || arg == "--host") && i + 1 < argc) {
            host = cli::get_arg(argc, argv, i);
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            key = cli::get_arg(argc, argv, i);
        } else if ((arg == "-T" || arg == "--threads") && i + 1 < argc) {
            threads = std::stoul(cli::get_arg(argc, argv, i));
            if (threads == 0 || threads > 64) {
                std::cerr << "Error: --threads must be between 1 and 64" << std::endl;
                return 1;
            }
        } else if ((arg == "-L" || arg == "--log-level") && i + 1 < argc) {
            log_level = cli::get_arg(argc, argv, i);
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
