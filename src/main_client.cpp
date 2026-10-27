#include "cli_helpers.hpp"

#include <fmt/format.h>
#include "kcp_proxy/client.hpp"

#include <asio.hpp>

#include <CLI/CLI.hpp>
#include <atomic>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>

using namespace kcp_proxy;

namespace {

struct ClientCliOptions {
    std::string server_host;
    uint16_t server_port = 8388;
    std::string key;
    std::string fec_text;
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 1080;
    int half_close_grace_sec = CLIENT_HALF_CLOSE_GRACE_SEC;
    std::string log_level = "INFO";
};

// Rejects a FEC string the codec would not accept. Mirrors parse_fec_config's
// fail-closed contract: anything but 0:0 or a valid shard pair refuses to
// start, so a typo cannot open a tunnel whose framing silently mismatches the
// server's.
std::string validate_fec(const std::string& v) {
    FecConfig parsed;
    if (!parse_fec_config(v, parsed)) {
        return "must be DATA:PARITY (e.g. 10:3) with 1 <= PARITY <= DATA <= 255, "
               "or 0:0 to disable";
    }
    return {};
}

std::optional<ClientCliOptions> parse_cli(int argc, char* argv[], int& exit_code) {
    ClientCliOptions o;

    CLI::App app{"kcp-proxy-client: local SOCKS5 that tunnels over KCP/UDP", "kcp-proxy-client"};
    app.option_defaults()->configurable(false);

    app.add_option("-s,--server", o.server_host, "Remote KCP server host")->required();
    app.add_option("-p,--server-port", o.server_port, "Remote KCP server port")
        ->check(cli::positive_decimal("PORT"))
        ->check(CLI::Range(1, 65535))
        ->capture_default_str();
    app.add_option("-k,--key", o.key, "Encryption key (min 16 chars)")
        ->envname("KCP_PROXY_KEY")
        ->check(cli::key_validator())
        ->required();
    app.add_option("--fec", o.fec_text,
                   "Reed-Solomon FEC as DATA:PARITY, e.g. 10:3 (0:0 disables). "
                   "Repairs up to PARITY lost datagrams per group of DATA. Keep "
                   "the value equal to the server's --fec (default 10:3) so "
                   "parity repair works in both directions.")
        ->default_str("off")
        ->check(validate_fec);
    app.add_option("-H,--listen-host", o.listen_host, "Local SOCKS5 bind address")
        ->capture_default_str();
    app.add_option("-l,--listen-port", o.listen_port, "Local SOCKS5 listen port")
        ->check(cli::positive_decimal("PORT"))
        ->check(CLI::Range(1, 65535))
        ->capture_default_str();
    app.add_option("-L,--log-level", o.log_level, "Log level: DEBUG, INFO, WARNING, ERROR")
        ->check(cli::log_level_validator())
        ->capture_default_str();
    app.add_option("--half-close-grace", o.half_close_grace_sec,
                   "Seconds a half-closed tunnel may go without target payload "
                   "before it is reclaimed")
        ->check(cli::positive_decimal("SECONDS"))
        ->capture_default_str();

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // A stale GUI or launcher still passing the pre-0.2.0 `-fec` gets a
        // message that names the rename instead of "arguments were not
        // expected".
        if (cli::explain_legacy_fec(argc, argv)) {
            exit_code = 1;
            return std::nullopt;
        }
        // app.exit() prints the diagnostic (to stderr for errors, stdout for
        // --help) and yields CLI11's own exit code, which the caller returns
        // verbatim. CallForHelp derives from Success, so --help is exit 0 --
        // main() must pass it through, not coerce it to 1.
        exit_code = app.exit(e);
        return std::nullopt;
    }
    return o;
}

} // namespace

int main(int argc, char* argv[]) {
    int cli_exit = 0;
    auto parsed_cli = parse_cli(argc, argv, cli_exit);
    if (!parsed_cli) return cli_exit;
    ClientCliOptions opts = std::move(*parsed_cli);

    // parse_fec_config already accepted this text in the validator; parsing it
    // again here is what turns it into the shard pair (fails closed).
    FecConfig fec;
    if (!opts.fec_text.empty() && !parse_fec_config(opts.fec_text, fec)) {
        std::cerr << "Error: --fec " << opts.fec_text << " is invalid" << std::endl;
        return 1;
    }

    std::string& key = opts.key;
    cli::parse_log_level(opts.log_level);

    try {
        asio::io_context io;
        asio::executor_work_guard<asio::io_context::executor_type> work_guard(io.get_executor());
        auto client = std::make_shared<KCPProxyClient>(io, opts.server_host, opts.server_port, key,
                                                       opts.listen_host, opts.listen_port,
                                                       opts.half_close_grace_sec, fec);
        cli::secure_wipe(key);
        client->start();

        LOG_INFO("main", fmt::format("KCP proxy client started, SOCKS5 on {}:{} fec={}",
                                     opts.listen_host, opts.listen_port, fec.to_string()));

        cli::setup_signal_handler(io, [client]() {
            client->stop();
        });

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
