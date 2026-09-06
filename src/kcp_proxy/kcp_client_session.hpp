#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "kcp_wrapper.hpp"
#include "byte_view.hpp"
#include "logger.hpp"
#include <asio.hpp>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace kcp_proxy {

// UDP packet reordering is normal, especially in high-throughput scenarios.
// When packets arrive out of order beyond the replay window, they are discarded.
// This is expected behavior - KCP will retransmit if needed. We no longer close
// the session on replay errors. Server restart detection is handled by KCP timeout.

class KCPClientSession : public std::enable_shared_from_this<KCPClientSession> {
public:
    KCPClientSession(asio::io_context& io, asio::ip::udp::endpoint server_addr,
                     std::shared_ptr<Crypto> crypto, uint32_t conv = 1);
    ~KCPClientSession();

    // Async-friendly: connect dispatches onto the strand so the upper layer
    // does not have to care which thread it ran on.
    void connect(std::function<void(bool)> handler);
    void close();

    // One KCP update/flush/keepalive/idle-timeout cycle. Runs ONLY inside
    // strand_. Public solely so KCPProxyClient's shared update tick
    // (do_update_tick) can invoke it after dispatching onto the session
    // strand; nothing else should call it -- the tick owns the cadence.
    void on_update_tick();

    void send_data(byte_view data);
    void async_read_some(asio::mutable_buffer buffer,
                         std::function<void(std::error_code, size_t)> handler);

    bool is_connected() const { return connected_.load() && running_.load(); }
    bool is_handshake_done() const { return socks5_handshake_done_.load(); }
    void mark_handshake_done() {
        socks5_handshake_done_.store(true);
        LOG_INFO("kcp_client", "handshake done");
    }

    // KCP send-queue depth, used by the client's upstream backpressure.
    int wait_send() const { return kcp_.wait_send(); }

    // Opaque external keepalive: whatever is assigned here is released
    // together with the session, so owners can attach RAII resources (e.g. a
    // session-cap ticket) without having to track every teardown path.
    void set_keepalive(std::shared_ptr<void> keep) { keepalive_ = std::move(keep); }

    const asio::ip::udp::endpoint& server_addr() const { return server_addr_; }

    // Per-session strand so the client can run forwarding loops / KCP-state
    // reads (peek_size/wait_send) serialized with the strand handlers that
    // mutate KCP.
    asio::strand<asio::io_context::executor_type>& strand() { return strand_; }

private:
    asio::io_context& io_;
    asio::strand<asio::io_context::executor_type> strand_;
    asio::ip::udp::endpoint server_addr_;
    std::shared_ptr<Crypto> crypto_;
    std::optional<asio::ip::udp::socket> udp_socket_;
    KcpWrapper kcp_;

    // NOTE: no per-session update timer. KCP updates are driven by
    // KCPProxyClient's single shared 10ms tick (do_update_tick), collapsing
    // N per-session timer-heap entries into one timer. on_update_tick()
    // below runs inside strand_ only.
    asio::steady_timer connect_timer_;

    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> connect_pending_{false};
    std::atomic<bool> socks5_handshake_done_{false};
    std::atomic<int64_t> last_activity_us_{0};
    // Last time a valid packet was received from the server (steady_clock us).
    // The client has no server-side idle sweep, so a connected session that
    // stops receiving for KCP_TIMEOUT_SEC is considered dead (server crashed or
    // the key rotated) and is closed. Updated ONLY on authentic received data,
    // never on outgoing keepalives, so it cannot be kept alive by our own sends.
    std::atomic<int64_t> last_rx_us_{0};
    // Keepalive send throttle (steady_clock us). Fixed cadence, independent of
    // received activity, so a healthy peer always hears from us every
    // KCP_KEEPALIVE_SEC.
    std::atomic<int64_t> last_keepalive_us_{0};

    asio::mutable_buffer pending_read_buffer_{nullptr, 0};
    std::function<void(std::error_code, size_t)> pending_read_handler_;

    // Reusable buffers to avoid per-packet heap allocation. The socket is
    // connect()ed to server_addr_, so receive() filters out foreign sources.
    // External RAII resources attached via set_keepalive(); destroyed with the
    // session so reference counting stays tied to real session lifetime.
    std::shared_ptr<void> keepalive_;
    std::vector<uint8_t> udp_recv_buf_ = std::vector<uint8_t>(UDP_RECV_BUF_SIZE);
    // Fixed-size KCP recv buffer (avoid heap allocation on the hot path).
    alignas(64) std::array<uint8_t, FWD_BUF_SIZE> kcp_recv_buf_{};
    // Reused decrypt output (safe: kcp_.input copies into KCP's own buffers).
    std::vector<uint8_t> decrypt_buf_;

    void on_connect(std::function<void(bool)> handler);
    void send_connect_hello();
    void on_close();
    void on_send(byte_view data);
    void on_receive(byte_view packet);
    void on_async_read_some(asio::mutable_buffer buffer,
                            std::function<void(std::error_code, size_t)> handler);
    void do_udp_receive();
    void handle_kcp_output(byte_view data);
    void try_fulfill_read();
    void touch_activity();
};

} // namespace kcp_proxy
