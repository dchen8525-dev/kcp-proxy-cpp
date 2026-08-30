#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "kcp_session.hpp"
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

namespace kcp_proxy {

struct ClientConnection {
    std::string session_id;
    std::shared_ptr<asio::ip::tcp::socket> tcp_socket;
    std::chrono::steady_clock::time_point created_at;
};

class KCPServer : public std::enable_shared_from_this<KCPServer> {
public:
    KCPServer(asio::io_context& io, uint16_t port, std::string key,
              std::string host = "0.0.0.0");
    ~KCPServer();

    void start();
    void stop();

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
    std::atomic<bool> running_{false};
    // Read-mostly session table: UDP packet routing does map lookups far more
    // often than it mutates them, so a shared_mutex lets concurrent readers
    // proceed in parallel while writers stay exclusive.
    std::shared_mutex sessions_mutex_;

    // Global throttle on new-session authentication attempts (unknown sources
    // only ever pay a full AEAD decrypt here). Bounds CPU burn from garbage
    // UDP floods. Only touched on the single I/O thread.
    uint32_t auth_attempts_window_ = 0;
    std::chrono::steady_clock::time_point auth_window_start_{};

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
    void close_connection(const std::string& session_id, const char* caller);
    // Graceful teardown of the upstream TCP side: mark the session's target as
    // closed, close the target socket, and stop the client->target loop. The
    // session stays alive until the KCP send buffer drains to the client (see
    // KCPSession::do_update / set_drained_callback), then close_connection runs.
    void handle_target_closed(std::shared_ptr<KCPSession> session,
                              std::shared_ptr<asio::ip::tcp::socket> tcp_socket);
    void do_cleanup(const std::error_code& ec);
    // Takes ownership of the (already encrypted) datagram so the UDP send can
    // move it without a second copy.
    void send_to_client(const asio::ip::udp::endpoint& addr, std::vector<uint8_t> data);
    void forward_kcp_to_tcp(std::shared_ptr<KCPSession> session,
                            std::shared_ptr<std::vector<uint8_t>> buf = {});

    static uint8_t get_error_reply_code(const std::error_code& ec);
};

} // namespace kcp_proxy
