#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "kcp_wrapper.hpp"
#include "byte_view.hpp"
#include <asio.hpp>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace kcp_proxy {

// Performance metrics for monitoring
struct SessionMetrics {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> encrypt_errors{0};
    std::atomic<uint64_t> decrypt_errors{0};

    // UDP datagram level (used for peer-to-peer loss localization): every
    // encrypted datagram handed to the peer counts as one TX, every datagram
    // that reaches decrypt counts as one RX. replay_dropped counts decrypted
    // duplicates discarded by the anti-replay window (i.e. peer retransmissions).
    std::atomic<uint64_t> udp_tx_packets{0};
    std::atomic<uint64_t> udp_tx_bytes{0};
    std::atomic<uint64_t> udp_rx_packets{0};
    std::atomic<uint64_t> udp_rx_bytes{0};
    std::atomic<uint64_t> replay_dropped{0};
};

// Shared machinery for the two KCP tunnels: the server-side session (one peer
// endpoint, multiplexed over the server's single UDP socket) and the
// client-side session (one local TCP connection, one UDP socket).
//
// Both own a KCP state machine fed through the same encrypt/decrypt path and
// driven by the same shared 10ms tick, and both must uphold the same invariants
// around a pending read: never hand back a truncated message, complete the
// handler exactly once, never let a stale handler linger, never send an
// application keepalive before the handshake is done. Those invariants had
// already been fixed twice -- once per copy -- which is the whole argument for
// keeping them in one place.
//
// Deliberately NOT shared: the receive path and the send path. The server
// decrypts a datagram from any endpoint (dispatch + copy) and hands the
// encrypted output to a callback that owns the socket; the client reads a
// connected socket into a reused buffer and sends through that socket directly,
// encrypting straight into the buffer that backs the send. Those differ in both
// allocation strategy and ownership and stay in the concrete classes.
class KcpTunnel : public std::enable_shared_from_this<KcpTunnel> {
public:
    virtual ~KcpTunnel();

    KcpTunnel(const KcpTunnel&) = delete;
    KcpTunnel& operator=(const KcpTunnel&) = delete;

    // Per-session strand. Every strand-bound helper below assumes it is on it.
    asio::strand<asio::io_context::executor_type>& strand() { return strand_; }

    // Queue one application message into KCP and flush it.
    void send_data(byte_view data);

    // Register a read. Exactly one may be outstanding: a second one completes
    // with already_started, and a read on a dead tunnel with operation_aborted.
    void async_read_some(asio::mutable_buffer buffer,
                         std::function<void(std::error_code, size_t)> handler);

    int wait_send() const { return kcp_.wait_send(); }
    int peek_size() const { return kcp_.peek_size(); }

    // Performance metrics
    const SessionMetrics& metrics() const { return metrics_; }

    // Single-line UDP/decrypt counters for loss localization.
    std::string stats_summary() const;

    // True once the peer-level handshake completed. Gates the application
    // keepalive: a tunnel that has not finished connecting must not send one.
    bool is_handshake_done() const { return handshake_done_.load(); }
    virtual void mark_handshake_done();

    // Micros since the last packet that authenticated successfully.
    int64_t activity_age_us() const;

protected:
    KcpTunnel(asio::io_context& io, uint32_t conv, std::shared_ptr<Crypto> crypto,
              std::string log_module, std::string log_tag);

    // ------------------------- hooks for the concrete session ---------------
    // May the tunnel accept new application data? Checked off-strand, before a
    // send is queued.
    virtual bool can_accept_data() const = 0;
    // Is the tunnel still live? Checked inside strand-bound work.
    virtual bool is_active() const = 0;
    // Tear the tunnel down after KCP refused a send.
    virtual void shut_down() = 0;
    // Encrypt KCP output and put it on the wire. The two sessions differ in
    // ownership here, so each implements its own.
    virtual void handle_kcp_output(byte_view data) = 0;

    // ------------------------- shared strand-bound helpers ------------------
    void on_send(byte_view data);
    void on_async_read_some(asio::mutable_buffer buffer,
                            std::function<void(std::error_code, size_t)> handler);
    // Move whatever KCP has into the pending read, or complete it with an error.
    void try_fulfill_read();
    // Detach the pending read (if any) and complete it with `ec` on the strand.
    // This is the single owner of that invariant -- exactly one completion, and
    // the handler always explicitly nulled rather than left moved-from -- which
    // is precisely the logic that had to be fixed twice when it lived in both
    // sessions.
    void complete_pending_read(const std::error_code& ec);
    // Emit the throttled 30s DEBUG stats line. Called from the tick.
    void maybe_log_stats();
    // Inject the application-layer keepalive if the cadence is due. Called from
    // the tick, after the handshake is done.
    void maybe_send_keepalive();
    void touch_activity();

    // "tag: text" when a tag is set (server sessions), just "text" otherwise.
    std::string log_msg(const std::string& text) const;
    const std::string& log_module() const { return log_module_; }

    asio::io_context& io_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::shared_ptr<Crypto> crypto_;
    KcpWrapper kcp_;

    asio::mutable_buffer pending_read_buffer_{nullptr, 0};
    std::function<void(std::error_code, size_t)> pending_read_handler_;
    // Fixed-size KCP recv buffer (avoid heap allocation on the hot path). Sized
    // to hold a full forwarding message; KcpWrapper::recv reports
    // KCP_RECV_MSG_TOO_BIG if a larger message ever arrives.
    alignas(64) std::array<uint8_t, FWD_BUF_SIZE> kcp_recv_buf_{};
    // Reused decrypt output (safe: kcp_.input copies into KCP's own buffers).
    std::vector<uint8_t> decrypt_buf_;

    SessionMetrics metrics_;
    std::atomic<bool> handshake_done_{false};

    std::atomic<int64_t> last_activity_us_{0};  // steady_clock micros
    // Throttle for the periodic (DEBUG) UDP stats line, to avoid per-tick spam.
    std::atomic<int64_t> last_stats_us_{0};
    // Keepalive send throttle. Distinct from last_activity_us_: sending a
    // keepalive must NOT refresh the activity clock, otherwise a tunnel whose
    // peer has gone away would keep itself alive forever and evade the server's
    // idle sweep. The cadence is throttled by this clock instead.
    std::atomic<int64_t> last_keepalive_us_{0};

    // Logger module ("kcp_session" / "kcp_client") and line tag (the server's
    // session id, empty for the client). Together they reproduce each side's
    // existing log lines exactly.
    std::string log_module_;
    std::string log_tag_;
};

} // namespace kcp_proxy
