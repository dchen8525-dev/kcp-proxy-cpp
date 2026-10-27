#include "cli_helpers.hpp"
#include "kcp_proxy/server.hpp"
#include "kcp_proxy/target_allowlist.hpp"

#include <asio.hpp>

#include <CLI/CLI.hpp>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace kcp_proxy;

namespace {

struct ServerCliOptions {
    uint16_t port = 8388;
    std::string host = "0.0.0.0";
    std::string key;
    std::string fec_text;
    unsigned int threads = 1;
    std::string log_level = "INFO";
    std::vector<std::string> allowed_targets;
};

std::optional<ServerCliOptions> parse_cli(int argc, char* argv[], int& exit_code) {
    ServerCliOptions o;

    CLI::App app{"kcp-proxy-server: SOCKS5-over-KCP tunnel server", "kcp-proxy-server"};
    app.option_defaults()->configurable(false);

    app.add_option("-p,--port", o.port, "UDP listen port")
        ->check(cli::positive_decimal("PORT"))
        ->check(CLI::Range(1, 65535))
        ->capture_default_str();
    app.add_option("-H,--host", o.host, "Bind address")->capture_default_str();
    app.add_option("-k,--key", o.key, "Encryption key (min 16 chars)")
        ->envname("KCP_PROXY_KEY")
        ->check(cli::key_validator())
        ->required();
    app.add_option("--fec", o.fec_text,
                   "Reed-Solomon FEC as DATA:PARITY, e.g. 10:3 (0:0 disables). "
                   "The server auto-adapts per session: a client that speaks FEC "
                   "gets FEC back, a client that does not gets bare datagrams. "
                   "This value sets the shard parameters used for adapting "
                   "clients (default 10:3 when unset); keep the client's value "
                   "equal to it so parity repair works in both directions.")
        ->default_str("off")
        ->check([](const std::string& v) -> std::string {
            // Fail-closed, exactly as parse_fec_config documents: anything but
            // 0:0 or a valid shard pair refuses to start, so a typo can never
            // open a server whose framing silently mismatches its clients.
            FecConfig parsed;
            if (!parse_fec_config(v, parsed)) {
                return "must be DATA:PARITY (e.g. 10:3) with 1 <= PARITY <= DATA <= 255, "
                       "or 0:0 to disable";
            }
            return {};
        });
    app.add_option("-T,--threads", o.threads, "io_context worker threads")
        ->check(cli::positive_decimal("N"))
        ->check(CLI::Range(1, 64))
        ->capture_default_str();
    app.add_option("-L,--log-level", o.log_level, "Log level: DEBUG, INFO, WARNING, ERROR")
        ->check(cli::log_level_validator())
        ->capture_default_str();
    app.add_option("--allow-target", o.allowed_targets,
                   "Allow a specific lab/test target past the SSRF guard "
                   "(repeatable; never use in production), e.g. 127.0.0.1:9000")
        ->check([](const std::string& v) -> std::string {
            std::string h;
            bool has_port = false;
            uint16_t p = 0;
            if (!parse_allow_target_entry(v, h, has_port, p)) {
                return "must be HOST[:PORT] or [IPv6][:PORT]";
            }
            return {};
        });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
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
    ServerCliOptions opts = std::move(*parsed_cli);

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
        auto server = std::make_shared<KCPServer>(io, opts.port, key, opts.host, fec);
        cli::secure_wipe(key);
        server->set_allowed_targets(opts.allowed_targets);
        server->start();

        LOG_INFO("main", "KCP proxy server started on " + opts.host + ":" +
                             std::to_string(server->bound_port()) + " fec=" + fec.to_string());

        cli::setup_signal_handler(io, [server]() {
            server->stop();
        });

        // An exception escaping an io_context handler is fatal -- the server is
        // left in an unknown state -- but it must not be allowed to unwind
        // straight out of here. Doing so would destroy `io_threads` while its
        // threads are still joinable, and ~thread on a joinable thread calls
        // std::terminate, so the "Fatal error:" diagnostic below could never
        // print. The same is true of an exception escaping a *worker* thread's
        // function, which terminates immediately. So: catch it in every thread,
        // stop the io_context so the others return, and rethrow only after the
        // join, where the stack is safe to unwind.
        std::vector<std::thread> io_threads;
        io_threads.reserve(opts.threads);
        std::exception_ptr handler_error;
        std::mutex handler_error_mutex;
        auto run_io = [&io, &handler_error, &handler_error_mutex]() {
            try {
                io.run();
            } catch (...) {
                {
                    std::lock_guard<std::mutex> lock(handler_error_mutex);
                    if (!handler_error) {
                        handler_error = std::current_exception();
                    }
                }
                io.stop();
            }
        };
        for (unsigned int t = 1; t < opts.threads; ++t) {
            io_threads.emplace_back(run_io);
        }
        run_io();
        for (auto& t : io_threads)
            t.join();
        if (handler_error) {
            std::rethrow_exception(handler_error);
        }
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
