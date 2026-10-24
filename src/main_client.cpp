#include "kcp_proxy/client.hpp"
#include "cli_helpers.hpp"
#include <asio.hpp>
#include <atomic>
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
              << "  -fec DATA:PARITY       Reed-Solomon FEC, e.g. -fec 10:3 (default: off).\n"
              << "                         Repairs up to PARITY lost datagrams per group of\n"
              << "                         DATA. MUST match the server's value exactly — the\n"
              << "                         first datagram is already FEC-framed.\n"
              << "  -H, --listen-host HOST Local SOCKS5 bind address (default: 127.0.0.1)\n"
              << "  -l, --listen-port PORT Local SOCKS5 listen port (default: 1080)\n"
              << "  -L, --log-level LEVEL  Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)\n"
              << "      --half-close-grace SEC\n"
              << "                         Seconds a half-closed tunnel may go without target\n"
              << "                         payload before it is reclaimed (default: "
              << CLIENT_HALF_CLOSE_GRACE_SEC << ")\n";
}

int main(int argc, char* argv[]) {
    std::string server_host;
    uint16_t server_port = 8388;
    std::string key;
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 1080;
    int half_close_grace_sec = CLIENT_HALF_CLOSE_GRACE_SEC;
    std::string log_level = "INFO";
    FecConfig fec;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-s" || arg == "--server") && i + 1 < argc) {
            server_host = cli::get_arg(argc, argv, i);
        } else if ((arg == "-p" || arg == "--server-port") && i + 1 < argc) {
            if (!cli::get_port_arg(argc, argv, i, server_port)) return 1;
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            key = cli::get_arg(argc, argv, i);
        } else if ((arg == "-fec" || arg == "--fec") && i + 1 < argc) {
            // Fail-closed parse (see parse_fec_config): anything but 0:0 or a
            // valid shard pair refuses to start, so a typo can never open a
            // tunnel whose framing silently mismatches the server's.
            if (!parse_fec_config(cli::get_arg(argc, argv, i), fec)) {
                std::cerr << "Error: --fec expects DATA:PARITY (e.g. 10:3), "
                          << "with 1 <= PARITY <= DATA <= 255, or 0:0 to disable"
                          << std::endl;
                return 1;
            }
        } else if ((arg == "-H" || arg == "--listen-host") && i + 1 < argc) {
            listen_host = cli::get_arg(argc, argv, i);
        } else if ((arg == "-l" || arg == "--listen-port") && i + 1 < argc) {
            if (!cli::get_port_arg(argc, argv, i, listen_port)) return 1;
        } else if ((arg == "-L" || arg == "--log-level") && i + 1 < argc) {
            log_level = cli::get_arg(argc, argv, i);
        } else if (arg == "--half-close-grace" && i + 1 < argc) {
            // Digits-only gate before stoi: stoi ignores trailing junk
            // ("120s" -> 120), which would silently start the proxy with a
            // grace different from what was typed. (Same rule as the port and
            // --threads arguments.)
            const std::string value = cli::get_arg(argc, argv, i);
            if (value.empty() ||
                value.find_first_not_of("0123456789") != std::string::npos) {
                std::cerr << "Error: --half-close-grace expects a non-negative number of seconds" << std::endl;
                return 1;
            }
            try {
                half_close_grace_sec = std::stoi(value);
            } catch (const std::exception&) {
                std::cerr << "Error: --half-close-grace expects a number of seconds" << std::endl;
                return 1;
            }
            if (half_close_grace_sec < 0) {
                std::cerr << "Error: --half-close-grace must be >= 0" << std::endl;
                return 1;
            }
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
            io, server_host, server_port, key, listen_host, listen_port,
            half_close_grace_sec, fec);
        cli::secure_wipe(key);
        client->start();

        LOG_INFO("main", "KCP proxy client started, SOCKS5 on " +
                 listen_host + ":" + std::to_string(listen_port) +
                 " fec=" + fec.to_string());

        cli::setup_signal_handler(io, [client]() { client->stop(); });

        std::atomic<bool> io_failed{false};
        std::thread io_thread([&io, &io_failed]() {
            // A handler that throws must not escape into std::terminate: this
            // is a bare worker thread with no handler of its own, unlike the
            // server's io.run(), which sits inside main()'s try block. Catch,
            // report, and exit non-zero like any other fatal error.
            try {
                io.run();
            } catch (const std::exception& e) {
                std::cerr << "Fatal error in I/O thread: " << e.what() << std::endl;
                io_failed.store(true);
            } catch (...) {
                // Same reasoning as the server's io.run(): this is a bare
                // worker thread with no handler of its own, so ANY escaping
                // exception -- not just std::exception -- terminates the
                // process before the diagnostic can print. Catching only
                // std::exception left that hole open for e.g. a custom error
                // type thrown by a handler, or a rethrow of something that is
                // not derived from std::exception.
                std::cerr << "Fatal error in I/O thread: unknown exception" << std::endl;
                io_failed.store(true);
            }
        });
        io_thread.join();
        if (io_failed.load()) {
            return 1;
        }
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
