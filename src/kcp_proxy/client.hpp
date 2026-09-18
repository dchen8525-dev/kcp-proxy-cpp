#pragma once

#include "config.hpp"
#include "kcp_client_session.hpp"
#include "byte_view.hpp"
#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace kcp_proxy {

class KCPProxyClient : public std::enable_shared_from_this<KCPProxyClient> {
public:
    KCPProxyClient(asio::io_context& io, std::string server_host,
                   uint16_t server_port, std::string key,
                   std::string listen_host = "127.0.0.1",
                   uint16_t listen_port = 1080,
                   int half_close_grace_sec = CLIENT_HALF_CLOSE_GRACE_SEC);
    ~KCPProxyClient();

    void start();
    void stop();

    // True unless startup failed (DNS resolve / bind / listen error). The main
    // loop checks this after io.run() returns so a failed startup exits with a
    // non-zero code instead of hanging forever on the work guard.
    bool startup_ok() const { return !start_failed_.load(); }

    // Traffic statistics (shared with GUI via periodic log line)
    std::atomic<uint64_t> tx_bytes_{0};
    std::atomic<uint64_t> rx_bytes_{0};

private:
    // Per-tunnel half-close bookkeeping (see forward_client_to_kcp()). Created
    // once the SOCKS5 handshake completes and shared by both forwarding loops;
    // released with them when the tunnel ends.
    //
    // The timer runs on the session strand, so arm/re-arm happen on the same
    // executor as the forwarding completions that refresh last_progress_us.
    struct HalfCloseGuard {
        explicit HalfCloseGuard(asio::steady_timer::executor_type ex)
            : deadline(std::move(ex)) {}

        asio::steady_timer deadline;
        // Set once the local app's read side reported EOF: the tunnel is in
        // drain-only mode. Until then the grace never applies.
        std::atomic<bool> app_eof{false};
        // steady_clock us of the last payload received from the target,
        // recorded as soon as it is consumed from KCP (so a slow write to the
        // app cannot look like a stalled target). Keepalives never touch this:
        // they are dropped inside the session and never reach the forwarding
        // loop, which is what makes the grace a measure of real progress rather
        // than of session liveness.
        std::atomic<int64_t> last_progress_us{0};
    };

    asio::io_context& io_;
    std::string server_host_;
    uint16_t server_port_;
    std::string key_;
    std::string listen_host_;
    uint16_t listen_port_;
    // How long a half-closed tunnel may sit without the target delivering
    // payload before it is reclaimed. See CLIENT_HALF_CLOSE_GRACE_SEC.
    int half_close_grace_sec_;

    void wipe_key();

    asio::ip::tcp::acceptor tcp_acceptor_;
    asio::ip::udp::resolver udp_resolver_;
    asio::ip::udp::endpoint server_endpoint_;
    asio::steady_timer traffic_timer_;
    std::atomic<bool> running_{false};
    std::atomic<bool> start_failed_{false};
    // Live SOCKS5 connections, enforced against MAX_CLIENT_SESSIONS.
    std::atomic<size_t> active_sessions_{0};

    // Last (tx,rx) pair handed to the GUI. The 2s traffic heartbeat only emits
    // an INFO line when these change; an idle tunnel drops to DEBUG instead of
    // repeating the same cumulative numbers forever. The GUI keeps its last
    // values, so the display is unaffected. Only touched from the io thread.
    uint64_t last_reported_tx_ = 0;
    uint64_t last_reported_rx_ = 0;

    // Shared KCP update tick: one 10ms timer for ALL client sessions (same
    // design as KCPServer::do_update_tick). The registry stores weak refs
    // keyed by raw pointer; expired entries are pruned during the tick, so
    // no teardown path needs an explicit deregistration hook. The snapshot
    // buffer is reused every tick (never reallocated in steady state).
    asio::steady_timer update_tick_timer_;
    // Accept-error backoff: on a persistent accept failure (e.g. fd exhaustion)
    // the acceptor re-arms through this short timer instead of busy-spinning
    // with one unthrottled log per iteration (mirrors the server's UDP receive
    // backoff). Cancelled in stop().
    asio::steady_timer accept_retry_timer_;
    std::unordered_map<KCPClientSession*, std::weak_ptr<KCPClientSession>> tick_sessions_;
    std::shared_mutex tick_sessions_mutex_;
    std::vector<std::weak_ptr<KCPClientSession>> tick_snapshot_;

    void do_resolve();
    void do_update_tick(const std::error_code& ec);
    void do_accept();
    // Log a fatal startup error, remember it for startup_ok(), and stop the io
    // context so main() can exit with a non-zero code instead of hanging.
    void fail_startup(const std::string& message);
    void handle_client_connection(asio::ip::tcp::socket client_socket);

    // Tear down a failed SOCKS5 handshake: mark cancelled, cancel the deadline
    // timer, and close BOTH the local TCP socket and the KCP session. Every
    // handshake failure path must go through this — previously the failure
    // paths only cancelled the deadline, whose callback was the sole cleanup
    // owner and returns early on operation_aborted, so the KCP session (plus
    // its UDP socket and update timer) leaked until the idle timeout.
    void abort_handshake(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                         std::shared_ptr<KCPClientSession> session,
                         std::shared_ptr<asio::steady_timer> handshake_deadline,
                         std::shared_ptr<std::atomic<bool>> handshake_cancelled);

    void start_traffic_reporter();
    void report_traffic();

    void read_socks5_request(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                             std::shared_ptr<KCPClientSession> session,
                             std::shared_ptr<asio::steady_timer> handshake_deadline,
                             std::shared_ptr<std::atomic<bool>> handshake_cancelled);

    void handle_sync_request(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                             std::shared_ptr<KCPClientSession> session,
                             uint8_t cmd, const std::string& host, uint16_t port,
                             std::shared_ptr<asio::steady_timer> handshake_deadline,
                             std::shared_ptr<std::atomic<bool>> handshake_cancelled);

    // Read and validate the server's SOCKS5 CONNECT reply. A reply can be split
    // across several KCP messages, and one message can carry target payload
    // after it, so this accumulates into `accum` and re-arms until
    // parse_socks5_reply() reports Complete. Only then is the handshake done:
    // the reply (plus any trailing payload) is written to the local app and the
    // forwarding loops start.
    void read_socks5_reply(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                           std::shared_ptr<KCPClientSession> session,
                           std::shared_ptr<std::vector<uint8_t>> accum,
                           std::chrono::steady_clock::time_point handshake_start,
                           std::shared_ptr<asio::steady_timer> handshake_deadline,
                           std::shared_ptr<std::atomic<bool>> handshake_cancelled,
                           std::shared_ptr<HalfCloseGuard> half_close);

    void forward_client_to_kcp(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                               std::shared_ptr<KCPClientSession> session,
                               std::shared_ptr<std::vector<uint8_t>> buf = {},
                               std::shared_ptr<HalfCloseGuard> guard = {});

    void forward_kcp_to_client(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                               std::shared_ptr<KCPClientSession> session,
                               std::shared_ptr<std::vector<uint8_t>> buf = {},
                               std::shared_ptr<HalfCloseGuard> guard = {});

    // Arm the half-close grace deadline after the local app's read side hit EOF.
    // The tunnel is now drain-only: it exists solely to deliver whatever the
    // target still has to say. See CLIENT_HALF_CLOSE_GRACE_SEC.
    void arm_half_close_grace(const std::shared_ptr<HalfCloseGuard>& guard,
                              std::shared_ptr<asio::ip::tcp::socket> client_socket,
                              std::shared_ptr<KCPClientSession> session);

    // Grace deadline callback. Re-arms itself while the target is still making
    // progress; reclaims the tunnel once the target has been quiet for the
    // whole grace window after the app closed.
    void on_half_close_check(std::shared_ptr<HalfCloseGuard> guard,
                             std::shared_ptr<asio::ip::tcp::socket> client_socket,
                             std::shared_ptr<KCPClientSession> session);

    void send_socks5_error(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                           uint8_t reply,
                           std::function<void()> on_complete = {});
};

} // namespace kcp_proxy
