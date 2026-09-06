#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "kcp_wrapper.hpp"
#include "byte_view.hpp"
#include <asio.hpp>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <array>

namespace kcp_proxy {

// Performance metrics for monitoring
struct SessionMetrics {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> encrypt_errors{0};
    std::atomic<uint64_t> decrypt_errors{0};

    void reset() {
        packets_sent.store(0);
        packets_received.store(0);
        bytes_sent.store(0);
        bytes_received.store(0);
        encrypt_errors.store(0);
        decrypt_errors.store(0);
    }
};

class KCPSession : public std::enable_shared_from_this<KCPSession> {
public:
    KCPSession(asio::io_context& io, uint32_t conv,
               asio::ip::udp::endpoint remote_addr,
               std::shared_ptr<Crypto> crypto,
               std::string session_id);
    ~KCPSession();

    void start();
    void stop();

    // One KCP update/flush/keepalive cycle. Runs ONLY inside strand_. Public
    // solely so KCPServer's shared update tick (do_update_tick) can invoke
    // it after dispatching onto the session strand; nothing else should call
    // it -- the tick owns the cadence.
    void on_update_tick();

    // Inputs may be called from any io_context thread; the body is dispatched
    // onto the per-session strand so KCP itself never sees concurrent access.
    // `after` (if set) runs on the strand immediately after the packet has been
    // fed into KCP, letting the caller chain follow-up work in the SAME strand
    // dispatch instead of a second one.
    void receive_data(byte_view encrypted_data, std::function<void()> after = {});
    // Inject already-decrypted KCP bytes directly into ikcp_input. Used by the
    // server when the first packet from a new endpoint was decrypted up front
    // (to authenticate before allocating a session) and we don't want to pay
    // the cost twice -- nor have it rejected by the replay window.
    void inject_decrypted(std::vector<uint8_t> decrypted, std::function<void()> after = {});
    void send_data(byte_view data);
    void async_read_some(asio::mutable_buffer buffer,
                         std::function<void(std::error_code, size_t)> handler);

    bool is_alive() const;
    bool is_running() const { return (state_flags_.load() & RUNNING) != 0; }
    bool is_handshake_done() const;
    void mark_handshake_done();
    bool is_protocol_handshake_done() const {
        return (state_flags_.load() & PROTOCOL_HS_DONE) != 0;
    }
    void mark_protocol_handshake_done() { state_flags_.fetch_or(PROTOCOL_HS_DONE); }
    bool is_socks5_read_pending() const {
        return (state_flags_.load() & SOCKS5_READ_PENDING) != 0;
    }
    void set_socks5_read_pending(bool val) {
        if (val) state_flags_.fetch_or(SOCKS5_READ_PENDING);
        else state_flags_.fetch_and(static_cast<uint8_t>(~SOCKS5_READ_PENDING));
    }
    bool is_forward_read_pending() const {
        return (state_flags_.load() & FORWARD_READ_PENDING) != 0;
    }
    // Set from the moment a SOCKS5 CONNECT request has been accepted until the
    // upstream TCP connect finishes (mark_handshake_done clears it) or the
    // session stops. While set, handle_kcp_data must not start another SOCKS5
    // read: an early data message arriving during the DNS/TCP-connect window
    // would otherwise be parsed as a second request and tear the session down.
    bool is_connect_pending() const {
        return (state_flags_.load() & CONNECT_PENDING) != 0;
    }
    void set_connect_pending(bool val) {
        if (val) state_flags_.fetch_or(CONNECT_PENDING);
        else state_flags_.fetch_and(static_cast<uint8_t>(~CONNECT_PENDING));
    }
    void set_forward_read_pending(bool val) {
        if (val) state_flags_.fetch_or(FORWARD_READ_PENDING);
        else state_flags_.fetch_and(static_cast<uint8_t>(~FORWARD_READ_PENDING));
    }
    // Atomically set forward_read_pending to true; returns the OLD value.
    // Used to avoid TOCTOU between checking and setting in handle_kcp_data.
    bool try_set_forward_read_pending() {
        return (state_flags_.fetch_or(FORWARD_READ_PENDING) & FORWARD_READ_PENDING) != 0;
    }

    // Graceful shutdown of the upstream TCP side. When the target connection
    // closes while the server still has data queued in KCP's send buffer, the
    // session must stay alive until that data is delivered to the client
    // (wait_send() == 0); tearing down early would drop it and truncate the
    // stream. mark_target_closed() records the condition and the drained
    // callback (if set) is invoked once by on_update_tick when the buffer drains.
    bool is_target_closed() const { return target_closed_.load(); }
    void mark_target_closed() { target_closed_.store(true); }
    void set_drained_callback(std::function<void()> cb) { drained_cb_ = std::move(cb); }

    const std::string& session_id() const { return session_id_; }
    const asio::ip::udp::endpoint& remote_addr() const { return remote_addr_; }
    int wait_send() const { return kcp_.wait_send(); }
    int peek_size() const { return kcp_.peek_size(); }

    // Exposes the per-session strand so the server can safely perform KCP-state
    // reads (peek_size/wait_send) and run session-driven logic on the strand
    // instead of the raw I/O thread.
    asio::strand<asio::io_context::executor_type>& strand() { return strand_; }

    // True if `packet`'s leading bytes carry this session's salt (i.e. the
    // packet belongs to this session, not to a NEW session that collided on
    // the same source endpoint after a client reconnect).
    bool salt_matches(byte_view packet) const { return crypto_->matches_salt(packet); }

    // Takes ownership of the (already encrypted) datagram so the server's UDP
    // send can move it without an extra copy.
    void set_send_callback(std::function<void(std::vector<uint8_t>)> cb);

    // Performance metrics
    const SessionMetrics& metrics() const { return metrics_; }

private:
    asio::io_context& io_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::string session_id_;
    asio::ip::udp::endpoint remote_addr_;
    std::shared_ptr<Crypto> crypto_;
    std::function<void(std::vector<uint8_t>)> send_callback_;

    KcpWrapper kcp_;
    // NOTE: there is intentionally NO per-session update timer here. KCP
    // updates are driven by KCPServer's single shared 10ms tick (see
    // do_update_tick), which collapses 4096 per-session timer-heap entries
    // into one timer. on_update_tick() below runs inside strand_ only.

    // Packed atomic flags to reduce cache line contention
    std::atomic<uint8_t> state_flags_{0};

    // State flag bits
    static constexpr uint8_t RUNNING = 0x01;
    static constexpr uint8_t PROTOCOL_HS_DONE = 0x02;
    static constexpr uint8_t SOCKS5_HS_DONE = 0x04;
    static constexpr uint8_t SOCKS5_READ_PENDING = 0x08;
    static constexpr uint8_t FORWARD_READ_PENDING = 0x10;
    static constexpr uint8_t CONNECT_PENDING = 0x20;

    std::atomic<int64_t> last_activity_us_{0}; // steady_clock micros since epoch
    // Keepalive send throttle. Distinct from last_activity_us_: sending a
    // keepalive must NOT refresh the activity clock, otherwise a session whose
    // peer has gone away would keep itself alive forever and evade the idle
    // sweep. The cadence is throttled by this clock instead.
    std::atomic<int64_t> last_keepalive_us_{0};

    // Set once the upstream target TCP connection has closed (see
    // is_target_closed()/mark_target_closed()). While it is set, the session
    // keeps flushing queued target data to the client and does not start the
    // client->target forward loop; on_update_tick invokes drained_cb_ once the KCP
    // send buffer empties.
    std::atomic<bool> target_closed_{false};
    std::function<void()> drained_cb_;

    asio::mutable_buffer pending_read_buffer_{nullptr, 0};
    std::function<void(std::error_code, size_t)> pending_read_handler_;

    // Fixed-size buffer for KCP recv (avoid heap allocation). Sized to hold a
    // full forwarding message; KcpWrapper::recv reports KCP_RECV_MSG_TOO_BIG if
    // a larger message ever arrives.
    alignas(64) std::array<uint8_t, FWD_BUF_SIZE> kcp_recv_buf_{};
    // Reused decrypt output (safe: kcp_.input copies into KCP's own buffers).
    std::vector<uint8_t> decrypt_buf_;

    SessionMetrics metrics_;

    // All methods below assume they run on strand_.
    void on_receive(std::vector<uint8_t> encrypted);
    void on_inject_decrypted(std::vector<uint8_t> decrypted);
    void on_send(byte_view data);
    void on_async_read_some(asio::mutable_buffer buffer,
                            std::function<void(std::error_code, size_t)> handler);
    void handle_kcp_output(byte_view data);
    void try_fulfill_read();

    void touch_activity();
};

} // namespace kcp_proxy