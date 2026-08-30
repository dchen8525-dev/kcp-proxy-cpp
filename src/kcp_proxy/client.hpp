#pragma once

#include "config.hpp"
#include "kcp_client_session.hpp"
#include "byte_view.hpp"
#include <asio.hpp>
#include <atomic>
#include <cstring>
#include <memory>
#include <string>

namespace kcp_proxy {

class KCPProxyClient : public std::enable_shared_from_this<KCPProxyClient> {
public:
    KCPProxyClient(asio::io_context& io, std::string server_host,
                   uint16_t server_port, std::string key,
                   std::string listen_host = "127.0.0.1",
                   uint16_t listen_port = 1080);
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
    asio::io_context& io_;
    std::string server_host_;
    uint16_t server_port_;
    std::string key_;
    std::string listen_host_;
    uint16_t listen_port_;

    void wipe_key();

    asio::ip::tcp::acceptor tcp_acceptor_;
    asio::ip::udp::resolver udp_resolver_;
    asio::ip::udp::endpoint server_endpoint_;
    asio::steady_timer traffic_timer_;
    std::atomic<bool> running_{false};
    std::atomic<bool> start_failed_{false};

    void do_resolve();
    void do_accept();
    // Log a fatal startup error, remember it for startup_ok(), and stop the io
    // context so main() can exit with a non-zero code instead of hanging.
    void fail_startup(const std::string& message);
    void handle_client_connection(asio::ip::tcp::socket client_socket);

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

    void forward_client_to_kcp(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                               std::shared_ptr<KCPClientSession> session,
                               std::shared_ptr<std::vector<uint8_t>> buf = {});

    void forward_kcp_to_client(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                               std::shared_ptr<KCPClientSession> session,
                               std::shared_ptr<std::vector<uint8_t>> buf = {});

    void send_socks5_error(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                           uint8_t reply);
};

} // namespace kcp_proxy
