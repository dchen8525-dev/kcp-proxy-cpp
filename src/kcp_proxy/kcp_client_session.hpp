#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "kcp_tunnel.hpp"
#include "byte_view.hpp"
#include <asio.hpp>
#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace kcp_proxy {

// Client-side tunnel: one local TCP connection, one UDP socket connected to the
// server endpoint. Unlike the server session it owns that socket and drives its
// own receive loop. See KcpTunnel for the machinery shared with KCPSession.
class KCPClientSession : public KcpTunnel {
public:
    KCPClientSession(asio::io_context& io, asio::ip::udp::endpoint server_addr,
                     std::shared_ptr<Crypto> crypto, uint32_t conv = KCP_CONV);
    ~KCPClientSession() override;

    // Async-friendly: connect dispatches onto the strand so the upper layer
    // does not have to care which thread it ran on.
    void connect(std::function<void(bool)> handler);
    void close();

    // One KCP update/flush/keepalive/idle-timeout cycle. Runs ONLY inside
    // strand_. Public solely so KCPProxyClient's shared update tick
    // (do_update_tick) can invoke it after dispatching onto the session
    // strand; nothing else should call it -- the tick owns the cadence.
    void on_update_tick();

    bool is_connected() const { return connected_.load() && running_.load(); }
    // is_handshake_done() comes from KcpTunnel; this override adds the log line.
    void mark_handshake_done() override;

    // Opaque external keepalive: whatever is assigned here is released
    // together with the session, so owners can attach RAII resources (e.g. a
    // session-cap ticket) without having to track every teardown path.
    void set_keepalive(std::shared_ptr<void> keep) { keepalive_ = std::move(keep); }

    const asio::ip::udp::endpoint& server_addr() const { return server_addr_; }

private:
    asio::ip::udp::endpoint server_addr_;
    std::optional<asio::ip::udp::socket> udp_socket_;
    asio::steady_timer connect_timer_;
    // NOTE: no per-session update timer. KCP updates are driven by
    // KCPProxyClient's single shared 10ms tick (do_update_tick), collapsing
    // N per-session timer-heap entries into one timer. on_update_tick()
    // below runs inside strand_ only.

    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> connect_pending_{false};
    // Last time a valid packet was received from the server (steady_clock us).
    // The client has no server-side idle sweep, so a connected session that
    // stops receiving for KCP_TIMEOUT_SEC is considered dead (server crashed or
    // the key rotated) and is closed. Updated ONLY on authentic received data,
    // never on outgoing keepalives, so it cannot be kept alive by our own sends.
    std::atomic<int64_t> last_rx_us_{0};

    // External RAII resources attached via set_keepalive(); destroyed with the
    // session so reference counting stays tied to real session lifetime.
    std::shared_ptr<void> keepalive_;

    // Reused receive buffer. The socket is connect()ed to server_addr_, so
    // receive() filters out foreign sources.
    std::vector<uint8_t> udp_recv_buf_ = std::vector<uint8_t>(UDP_RECV_BUF_SIZE);

    // --- KcpTunnel hooks ---
    bool can_accept_data() const override { return running_.load() && connected_.load(); }
    bool is_active() const override { return running_.load(); }
    void shut_down() override;
    void handle_kcp_output(byte_view data) override;

    void on_connect(std::function<void(bool)> handler);
    void send_connect_hello();
    void on_close();
    void on_receive(byte_view packet);
    void do_udp_receive();
};

} // namespace kcp_proxy
