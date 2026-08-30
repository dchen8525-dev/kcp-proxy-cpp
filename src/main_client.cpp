#include "kcp_proxy/client.hpp"
#include "cli_helpers.hpp"
#include <asio.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using namespace kcp_proxy;

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  -s, --server HOST      Remote KCP server host (required)\n"
              << "  -p, --server-port PORT Remote KCP server port (default: 8388)\n"
              << "  -k, --key KEY          Encryption key (min 16 chars; alternatively\n"
              << "                         set the KCP_PROXY_KEY environment variable)\n"
              << "  -H, --listen-host HOST Local SOCKS5 bind address (default: 127.0.0.1)\n"
              << "  -l, --listen-port PORT Local SOCKS5 listen port (default: 1080)\n"
              << "  -L, --log-level LEVEL  Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)\n";
}

int main(int argc, char* argv[]) {
    std::string server_host;
    uint16_t server_port = 8388;
    std::string key;
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 1080;
    std::string log_level = "INFO";

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-s" || arg == "--server") && i + 1 < argc) {
            server_host = cli::get_arg(argc, argv, i);
        } else if ((arg == "-p" || arg == "--server-port") && i + 1 < argc) {
            if (!cli::get_port_arg(argc, argv, i, server_port)) return 1;
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            key = cli::get_arg(argc, argv, i);
        } else if ((arg == "-H" || arg == "--listen-host") && i + 1 < argc) {
            listen_host = cli::get_arg(argc, argv, i);
        } else if ((arg == "-l" || arg == "--listen-port") && i + 1 < argc) {
            if (!cli::get_port_arg(argc, argv, i, listen_port)) return 1;
        } else if ((arg == "-L" || arg == "--log-level") && i + 1 < argc) {
            log_level = cli::get_arg(argc, argv, i);
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    if (server_host.empty()) {
        std::cerr << "Error: --server is required" << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    if (key.empty()) {
        // Fallback channel for GUIs: the environment keeps the secret out of
        // the command line, which is visible to every local user.
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
        auto client = std::make_shared<KCPProxyClient>(
            io, server_host, server_port, key, listen_host, listen_port);
        cli::secure_wipe(key);
        client->start();

        LOG_INFO("main", "KCP proxy client started, SOCKS5 on " +
                 listen_host + ":" + std::to_string(listen_port));

        cli::setup_signal_handler(io, [client]() { client->stop(); });

        std::thread io_thread([&io]() { io.run(); });
        io_thread.join();
        // If startup failed (e.g. DNS resolve), fail_startup() stopped the io
        // context; exit with a non-zero code instead of silently "succeeding".
        if (!client->startup_ok()) {
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
