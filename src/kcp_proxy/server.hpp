#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "kcp_session.hpp"
#include "logger.hpp"
#include "socks5.hpp"
#include "byte_view.hpp"
#include <asio.hpp>
#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace kcp_proxy {

struct ClientConnection {
    std::shared_ptr<asio::ip::tcp::socket> tcp_socket;
};

class KCPServer : public std::enable_shared_from_this<KCPServer> {
public:
    KCPServer(asio::io_context& io, uint16_t port, std::string key,
              std::string host = "0.0.0.0");
    ~KCPServer();

    void start();
    void stop();

    // Lab allowlist: targets explicitly permitted to bypass the SSRF guard.
    // Empty by default, so production traffic is fully protected. Populated
    // only when an operator passes --allow-target (e.g. to test against a
    // local echo server). Each entry is "host" or "host:port"; an IPv6 host
    // may be bracketed as "[addr]:port".
    void set_allowed_targets(std::vector<std::string> targets);

    // Route one received datagram: authenticate it (creating a session for an
    // unknown endpoint on success) and hand the bytes to KCP. Returns the
    // session that accepted the packet, or nullptr when it was rejected (auth
    // failure, auth rate limit, duplicate session salt, session cap).
    // handle_receive() is a thin socket wrapper around this; it is public so
    // tests can drive the create/auth/reject logic without a bound socket.
    std::shared_ptr<KCPSession> route_datagram(const asio::ip::udp::endpoint& addr,
                                               byte_view data);

private:
    asio::io_context& io_;
    uint16_t port_;
    std::string host_;
    std::string key_;

    // Wipe the plaintext key from memory. Called after the key has been
    // fully consumed (sessions are created lazily, so this is invoked by
    // stop() rather than the constructor).
    void wipe_key();

    asio::ip::udp::socket udp_socket_;
    asio::ip::udp::endpoint recv_endpoint_;

    std::unordered_map<std::string, std::shared_ptr<KCPSession>> sessions_;
    std::unordered_map<std::string, ClientConnection> connections_;

    asio::steady_timer cleanup_timer_;
    // Backoff timer for the UDP receive error path: unknown receive errors
    // re-arm do_receive() through this 10ms delay so a persistently failing
    // socket cannot spin the io_context (bounded to ~100 retries/s).
    asio::steady_timer receive_backoff_timer_;
    // Single shared KCP update timer. Drives ikcp_update/flush for EVERY
    // session on a fixed 10ms cadence, replacing one steady_timer per
    // session. With N sessions the old design churned N timer-heap entries
    // every 10ms (O(N log N) heap ops, cache-hostile at N=4096); this
    // collapses that to exactly one timer. The tick re-arms FIRST so the
    // cadence never stretches with the per-tick snapshot work.
    asio::steady_timer update_tick_timer_;
    // Reused snapshot buffer for the tick: weak refs copied out of sessions_
    // under the shared_mutex, then dispatched WITHOUT holding the lock.
    // weak_ptr (not shared_ptr) so a session erased from the map between
    // snapshots is skipped at dispatch time instead of being kept alive;
    // lock() success yields a temporary strong ref valid for this tick only.
    std::vector<std::weak_ptr<KCPSession>> tick_snapshot_;
    std::atomic<bool> running_{false};
    // Read-mostly session table: UDP packet routing does map lookups far more
    // often than it mutates them, so a shared_mutex lets concurrent readers
    // proceed in parallel while writers stay exclusive.
    std::shared_mutex sessions_mutex_;

    // Global throttle on new-session authentication attempts (unknown sources
    // only ever pay a full AEAD decrypt here). Bounds CPU burn from garbage
    // UDP floods. Non-atomic, and safe because the UDP receive path is
    // serialized: exactly one async_receive_from is outstanding at a time and
    // the next is armed only as the last statement of the completion handler,
    // so two handlers never overlap here even with -T > 1. (The receive path is
    // NOT single-threaded -- the -T flag spreads it over N io_context threads --
    // so this invariant, not thread count, is what makes the plain fields safe.)
    uint32_t auth_attempts_window_ = 0;
    std::chrono::steady_clock::time_point auth_window_start_{};

    // Throttles for the per-datagram rejection diagnostics. The auth counters
    // above cap the *work* a flood can force, but these lines each fire once per
    // hostile datagram and so were unbounded -- under a sustained flood the
    // logging cost far more than the capped decrypts it reports on (see
    // LogThrottle). Separate instances because they carry different meanings: a
    // flood that trips the rate limiter must not also swallow the first
    // "packet dropped" or decrypt-failure line, and vice versa. Each one always
    // emits its first occurrence, which is what the robustness suite greps for.
    LogThrottle auth_ratelimit_log_;
    LogThrottle drop_log_;
    LogThrottle decrypt_fail_log_;

    // Targets whitelisted via --allow-target; the SSRF guard refuses a target
    // only if it is restricted AND not in this list. Read-only after start().
    std::vector<std::string> allowed_targets_;

    // True iff (host, port) matches an entry in allowed_targets_.
    bool is_target_allowed(const std::string& host, uint16_t port) const;

    // Fixed-size UDP receive buffer (avoids heap allocation per datagram).
    alignas(64) std::array<uint8_t, UDP_RECV_BUF_SIZE> udp_recv_buf_{};

    void do_receive();
    void handle_receive(const std::error_code& ec, size_t bytes_transferred);

    std::shared_ptr<KCPSession> get_or_create_session(
        const asio::ip::udp::endpoint& addr, byte_view encrypted_packet,
        bool& already_consumed);
    void handle_kcp_data(std::shared_ptr<KCPSession> session,
                         const asio::ip::udp::endpoint& sender);
    void handle_socks5_request(std::shared_ptr<KCPSession> session);
    void handle_socks5_request(std::shared_ptr<KCPSession> session,
                               std::vector<uint8_t> initial_data);
    // Reads the next fragment of an (incomplete) SOCKS5 request; the read
    // handler re-invokes this until the request parses or fails. A member
    // function rather than a self-capturing std::function to avoid the
    // self-referential shared_ptr cycle that would leak per request.
    void read_more_socks5(std::shared_ptr<KCPSession> session,
                          std::shared_ptr<std::vector<uint8_t>> accum,
                          std::shared_ptr<KCPServer> self);
    bool parse_accumulated_socks5(std::shared_ptr<KCPSession> session,
                                  std::vector<uint8_t>& accum,
                                  bool log_details);
    void handle_protocol_handshake(std::shared_ptr<KCPSession> session);
    void handle_connect_command(std::shared_ptr<KCPSession> session,
                                const SOCKS5Request& request);
    void handle_connect_command(std::shared_ptr<KCPSession> session,
                                const SOCKS5Request& request,
                                std::vector<uint8_t> initial_payload);
    void handle_udp_associate(std::shared_ptr<KCPSession> session,
                              const SOCKS5Request& request);
    void send_socks5_reply(std::shared_ptr<KCPSession> session, uint8_t reply);
    void send_socks5_reply(std::shared_ptr<KCPSession> session, uint8_t reply,
                           std::string_view host, uint16_t port);
    void forward_tcp_to_kcp(std::string session_id,
                            std::shared_ptr<KCPSession> session,
                            std::shared_ptr<asio::ip::tcp::socket> tcp_socket,
                            std::shared_ptr<std::vector<uint8_t>> buf = {});
    // Tears down the session + target connection registered under session_id.
    // When `owner` is non-null, the maps are only touched if the current entry
    // IS that session: a teardown queued by a replaced/idle-reaped session must
    // never kill a newer session that reuses the same endpoint (NAT port reuse
    // on client reconnect). owner == nullptr keeps the legacy unconditional
    // behavior for defensive paths that have no session at hand.
    void close_connection(const std::string& session_id, const char* caller,
                          const std::shared_ptr<KCPSession>& owner = nullptr);
    // Graceful teardown of the upstream TCP side: mark the session's target as
    // closed, close the target socket, and stop the client->target loop. The
    // session stays alive until the KCP send buffer drains to the client (see
    // KCPSession::on_update_tick / set_drained_callback), then close_connection runs.
    void handle_target_closed(std::shared_ptr<KCPSession> session,
                              std::shared_ptr<asio::ip::tcp::socket> tcp_socket);
    void do_update_tick(const std::error_code& ec);
    void do_cleanup(const std::error_code& ec);
    // Takes ownership of the (already encrypted) datagram so the UDP send can
    // move it without a second copy.
    void send_to_client(const asio::ip::udp::endpoint& addr, std::vector<uint8_t> data);
    void forward_kcp_to_tcp(std::shared_ptr<KCPSession> session,
                            std::shared_ptr<std::vector<uint8_t>> buf = {});

    static uint8_t get_error_reply_code(const std::error_code& ec);
};

} // namespace kcp_proxy
