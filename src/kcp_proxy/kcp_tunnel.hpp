#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "fec_parity.hpp"
#include "kcp_wrapper.hpp"
#include "rto_floor.hpp"
#include "byte_view.hpp"
#include "kcp/internal/constants.h"
#include <asio.hpp>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// kcp-cpp's FEC codec (consumed as the `kcp::kcp` vcpkg package; the overlay
// port lives in ports/kcp-cpp and the pinned revision is in CMakeLists.txt).
// Kept as forward declarations: the members are unique_ptrs and KcpTunnel's
// destructor is out-of-line, so the full fec.h is only needed in
// kcp_tunnel.cpp. (The parity-packet member is declared as
// vector<vector<uint8_t>> -- FecPacket is an ALIAS for that type upstream, and
// aliases cannot be forward-declared.)
namespace kcp::internal {
class FecEncoder;
class FecDecoder;
} // namespace kcp::internal

namespace kcp_proxy {

// Per-process adaptive decisions a tunnel obeys. Both are read-only for a
// tunnel and shared by every session, so a decision made once (by the client's
// traffic timer or the server's update tick) applies immediately everywhere.
// A null gate means "this policy is off", which is what keeps the default path
// byte-identical to the pre-adaptive code.
// Operator intent, resolved once at startup from the CLI. A policy is only
// instantiated when it is asked for here, so the defaults reproduce the
// pre-adaptive behaviour exactly.
struct AdaptiveSettings {
    // Drop FEC parity while the sending direction looks clean (on by default
    // when FEC is enabled; --fec-adaptive-probe 0 turns the policy off).
    bool fec_parity = false;
    FecParityTuning fec_parity_tuning;
    // Seconds of clean traffic before the RTO floor relaxes to 100ms
    // (--rto-adaptive-clean); 0 keeps the 30ms floor forever.
    int rto_relax_sec = KCP_RTO_RELAX_SEC;
};

struct AdaptiveHooks {
    // May a tunnel emit FEC parity? (fec_parity.hpp)
    std::shared_ptr<const FecParityGate> parity_gate;
    // May a tunnel keep the aggressive 30ms RTO floor? (rto_floor.hpp)
    std::shared_ptr<const RtoFloorGate> rto_floor_gate;
};

// Is this decrypted plaintext the 6-byte FEC header of a peer whose -fec is
// enabled? [seqid(4)][type(2, little-endian)], type in {0xf1 data, 0xf2 parity,
// 0xf3 oob}. Shared by the server's per-session FEC auto-adaptation (see
// KCPServer::get_or_create_session) and feed_kcp_input's mismatch diagnostic.
// A bare KCP segment can never match: its bytes 4..5 are cmd (0x51..0x54) and
// frg, so a healthy segment cannot land on 0xf1..0xf3.
inline bool looks_like_fec_frame(const uint8_t* data, size_t size) {
    if (data == nullptr || size < 8) return false;
    const uint16_t type = static_cast<uint16_t>(data[4]) | static_cast<uint16_t>(data[5] << 8);
    return type == kcp::kTypeData || type == kcp::kTypeParity || type == kcp::kTypeOob;
}

// Performance metrics for monitoring
struct SessionMetrics {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> encrypt_errors{0};
    std::atomic<uint64_t> decrypt_errors{0};
    // ikcp_send() refusals in on_send (send window full). Kept separate from
    // encrypt_errors so an "encryption failure" alert is never a KCP-layer
    // backpressure event in disguise.
    std::atomic<uint64_t> send_errors{0};

    // FEC: data shards the Reed-Solomon codec had to rebuild from parity (i.e.
    // datagrams the network lost but FEC recovered). Zero forever when FEC is
    // disabled. Counted only when the rebuilt datagram was accepted by KCP.
    std::atomic<uint64_t> fec_repaired{0};

    // FEC accounting, one increment per datagram actually put on the wire:
    // fec_data_sent counts data shards, fec_parity_sent counts parity shards.
    // Together they are the redundancy this tunnel is paying for:
    //   wire overhead   = parity / (data + parity)
    //   shard sets skipped = 1 - (parity / parity_shards)
    //                          / (data / data_shards)
    // The second form matters because the codec ALREADY skips parity for shard
    // sets that are not a burst (FecEncoder::Encode's rto window), so a measured
    // overhead well below parity/(data+parity) means that path is live and doing
    // work. Both stay zero when FEC is disabled.
    //
    // Needed in addition to udp_tx_packets, which also counts the ACK-only
    // datagrams the KCP state machine emits on its own: during a bidirectional
    // transfer those inflate the packet count by ~15% and would understate the
    // parity ratio.
    std::atomic<uint64_t> fec_data_sent{0};
    std::atomic<uint64_t> fec_parity_sent{0};

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
    asio::strand<asio::io_context::executor_type>& strand() {
        return strand_;
    }

    // Queue one application message into KCP and flush it.
    void send_data(byte_view data);

    // Register a read. Exactly one may be outstanding: a second one completes
    // with already_started, and a read on a dead tunnel with operation_aborted.
    void async_read_some(asio::mutable_buffer buffer,
                         std::function<void(std::error_code, size_t)> handler);

    int wait_send() const {
        return kcp_.wait_send();
    }
    int peek_size() const {
        return kcp_.peek_size();
    }

    // ---------------------- write-path backpressure -------------------------
    // KCP's send queue is bounded, so the tcp->kcp forwarding loops must stop
    // reading from their TCP socket once wait_send() reaches
    // KCP_BACKPRESSURE_THRESHOLD. How they wait is what determines throughput:
    // polling on a fixed timer and reading ONE buffer per wakeup caps a tunnel
    // at FWD_BUF_SIZE / timer, independent of the path and of the KCP window.
    // Measured on a 190ms-RTT link: 4*KCP_INTERVAL_MS (40ms) per 16KB read held
    // every tunnel to ~3 Mbps while the same path carried 29 Mbps over plain
    // TCP. So the loop parks here instead and is resumed the moment KCP's queue
    // has actually drained -- i.e. when the peer's ACKs arrive (on_receive) or,
    // at the latest, on the next update tick -- which makes the window, not the
    // timer, the only remaining limiter.
    //
    // `resume` runs on the strand. Registering it replaces any previous one, so
    // a loop that parks twice before being resumed still holds exactly one hook.
    void park_write(std::function<void()> resume);
    // Drop a parked hook without running it. Called from every teardown path:
    // the hook holds the owner's buffers and (on the client) the local socket,
    // and a stale hook must never be able to restart a dead loop. The socket
    // itself is closed by the session's own teardown, not from here.
    void unpark_write();
    bool write_parked() const {
        return static_cast<bool>(write_resume_cb_);
    }

    // Performance metrics
    const SessionMetrics& metrics() const {
        return metrics_;
    }

    // Single-line UDP/decrypt counters for loss localization.
    std::string stats_summary() const;

    // True once the peer-level handshake completed. Gates the application
    // keepalive: a tunnel that has not finished connecting must not send one.
    bool is_handshake_done() const {
        return handshake_done_.load();
    }
    virtual void mark_handshake_done();
    // True when `timeout_sec` has elapsed since this tunnel was created and the
    // SOCKS5 handshake still has not completed. Needed in addition to the
    // idle check: touch_activity() refreshes on EVERY authenticated packet
    // (keepalives and half-parsed SOCKS5 fragments included), so a peer that
    // holds the key and dribbles a few bytes per minute keeps the idle sweep
    // away forever and pins its session slot plus buffers. This clock is set
    // once at creation and never refreshed, so no inbound traffic can reset it.
    bool handshake_stalled(int64_t timeout_sec) const;

    // ------------------------- half-close (FIN) -----------------------------
    // Whether the peer negotiated FIN support (KCP_PROXY_HELLO_V2 / _ACK_V2).
    // Until it is set, send_fin() is a no-op: a peer that did not advertise
    // support would forward the control message into the tunnel as data.
    bool fin_enabled() const {
        return fin_enabled_.load();
    }
    void enable_fin() {
        fin_enabled_.store(true);
    }
    // Tell the peer that this side will send no more stream data, and flush it.
    // Idempotent (at most one FIN per tunnel) and a no-op on a tunnel that has
    // not negotiated support or is no longer active. Must run on the strand.
    // A refusal from a momentarily full KCP send window does NOT consume the
    // once-per-tunnel budget: the request latches and the shared tick re-drives
    // it (see retry_pending_fin) until the segment is actually queued.
    void send_fin();
    // True if the peer's FIN was consumed from KCP (see try_fulfill_read).
    bool peer_fin_received() const {
        return peer_fin_received_.load();
    }

    // Micros since the last packet that authenticated successfully.
    int64_t activity_age_us() const;

protected:
    KcpTunnel(asio::io_context& io, uint32_t conv, std::shared_ptr<Crypto> crypto,
              std::string log_module, std::string log_tag, const FecConfig& fec = FecConfig{},
              AdaptiveHooks hooks = {});

    // May this tunnel emit parity shards for the sets it completes? True unless
    // an adaptive gate says the path has been clean and the operator opted in
    // (see FEC_PARITY_* in config.hpp). Read once per emitted datagram.
    bool parity_enabled() const {
        return !hooks_.parity_gate || hooks_.parity_gate->enabled();
    }

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
    // Consume one flush cycle's worth of framed output datagrams in a single
    // call. `count` entries of `datagrams` are valid; the vector may be longer
    // (its storage is reused across cycles). The default drains through
    // handle_kcp_output one datagram at a time, which is byte-identical to the
    // pre-batching wire. Sessions override this to encrypt the whole burst and
    // hand it to the wire as one batched send.
    virtual void handle_kcp_output_batch(const std::vector<std::vector<uint8_t>>& datagrams,
                                         size_t count);

    // One KCP scheduling cycle: update(now) + flush(), with every framed
    // output datagram the cycle produces collected and delivered to
    // handle_kcp_output_batch() in a single call. This is the ONLY sanctioned
    // way to drive KCP: every former update+flush pair routes through here, so
    // a burst that used to cost one send syscall per KCP segment now costs one
    // per cycle (see the Linux sendmmsg/recvmmsg batching). Must run on the
    // strand.
    void flush_cycle(uint32_t now_ms);

    // ------------------------- shared strand-bound helpers ------------------
    void on_send(byte_view data);
    void on_async_read_some(asio::mutable_buffer buffer,
                            std::function<void(std::error_code, size_t)> handler);
    // FEC inbound gate: feeds ONE decrypted plaintext datagram into the tunnel.
    // With FEC disabled this is kcp_.input() verbatim. With FEC enabled the
    // datagram is a framed packet [fec_hdr(6)|len(2)|payload]: the native data
    // shard goes straight into KCP (after the length field is validated), and
    // every packet (data and parity) also runs through FecDecoder::Decode so
    // shards the codec rebuilds are fed in too. Returns the kcp_.input() result
    // of the native packet (0 or a negative ikcp-style error) so the caller's
    // throttled rejection logging keeps working; rebuilt shards are logged and
    // counted here.
    // Strand-only (KCP and the FEC codec are strand-confined).
    int feed_kcp_input(const uint8_t* data, size_t size);
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
    // Control-message body = magic || session_salt (see is_control).
    std::vector<uint8_t> build_control_payload(const char* magic) const;
    // Keepalive body = magic || session_salt (see is_keepalive).
    std::vector<uint8_t> build_keepalive_payload() const;
    // True if `data[0..size)` is `magic` immediately followed by this session's
    // salt. Scoping the sentinel with the per-session salt means a genuine
    // payload can never collide with it -- only a peer that shares this
    // session's salt can produce a match.
    bool is_control(const uint8_t* data, size_t size, const char* magic) const;
    bool is_keepalive(const uint8_t* data, size_t size) const;
    // True if `data[0..size)` is this session's FIN (see is_control).
    bool is_peer_fin(const uint8_t* data, size_t size) const;
    void touch_activity();

    // Re-drive a FIN requested via send_fin() whose ikcp_send was refused by a
    // full send window. Called from the shared 10ms tick; no-op unless a FIN
    // was requested and none has been queued yet, and gated on the window
    // having room so a drained-but-unACKed window cannot flood the tick.
    void retry_pending_fin();
    // Fire a parked write-loop hook once KCP's send queue has drained below
    // KCP_BACKPRESSURE_RESUME_THRESHOLD. Must run on the strand; called from the
    // receive path right after ikcp_input() (where the peer's ACKs actually
    // land) and from the update tick as the safety net.
    void maybe_resume_write();
    // The actual send/flush of the once-per-tunnel FIN, shared by send_fin()
    // and retry_pending_fin(). Must run on the strand.
    void do_send_fin();

    // "tag: text" when a tag is set (server sessions), just "text" otherwise.
    std::string log_msg(const std::string& text) const;
    const std::string& log_module() const {
        return log_module_;
    }

    // FEC outbound gate: wraps one KCP output datagram. With FEC disabled this
    // forwards to handle_kcp_output unchanged (byte-identical wire to pre-FEC
    // peers). With FEC enabled the datagram is framed as
    // [crypto reserve(28)][fec_hdr(6)][len(2)][payload], FecEncoder::Encode
    // seals the header and buffers the payload, and every emitted packet —
    // the data shard plus any parity shards of its set — goes through
    // handle_kcp_output separately, each becoming its own encrypted datagram.
    // Strand-only.
    void on_kcp_datagram(byte_view data);

    // ------------------------ output batching -------------------------------
    // Collect framed datagrams between begin_output_batch/end_output_batch.
    // Inside a batch the datagrams are copied into out_batch_'s reusable
    // storage instead of reaching handle_kcp_output one at a time; the closing
    // end delivers the whole burst in one virtual call. The depth counter makes
    // nesting safe, and both hooks are exception-safe: a throw from the KCP
    // internals or from a consumer must leave the depth counter and the
    // accumulator consistent, or every later flush would batch into a stuck
    // counter.
    void begin_output_batch() {
        ++batch_depth_;
    }
    void end_output_batch();
    // Route one framed datagram either into the open batch or, outside a
    // batch, straight to handle_kcp_output (the pre-batching behavior).
    void emit_output(byte_view data);

    // Reusable scratch storage for batched output. Inner buffers keep their
    // capacity across flush cycles, so the steady state costs zero
    // allocations per datagram here (the sessions' encrypted buffers are
    // pooled separately).
    std::vector<std::vector<uint8_t>> out_batch_;
    size_t out_batch_used_ = 0;
    int batch_depth_ = 0;

    asio::io_context& io_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::shared_ptr<Crypto> crypto_;
    KcpWrapper kcp_;
    // Creation time in steady_clock micros. Written once by the constructor and
    // only read afterwards, so it needs no atomic; it is deliberately separate
    // from last_activity_us_, which every authenticated packet refreshes (see
    // handshake_stalled()).
    const int64_t created_us_;

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
    // FIN negotiation state: enabled by the V2 handshake, sent at most once.
    // fin_requested_ latches send_fin() calls; fin_sent_ is only set once the
    // segment is actually queued, so a refused send stays retryable.
    std::atomic<bool> fin_enabled_{false};
    std::atomic<bool> fin_requested_{false};
    std::atomic<bool> fin_sent_{false};
    // Set when the peer's FIN has been consumed from KCP. Sticky for the life of
    // the tunnel: once the peer has half-closed it can never un-half-close, and
    // both the forwarding loops and the teardown paths need to consult it.
    std::atomic<bool> peer_fin_received_{false};
    // Set by feed_kcp_input (queued ACKs are invisible to wait_send()) and by
    // maybe_send_keepalive (its heartbeat is queued after the tick's flush).
    // The update tick runs kcp_.update()+flush() only when this is set or
    // wait_send() > 0, so a fully idle session skips the scheduler pass
    // entirely (see the tick guards in KCPSession/KCPClientSession).
    std::atomic<bool> needs_flush_{false};

    std::atomic<int64_t> last_activity_us_{0}; // steady_clock micros
    // Throttle for the periodic (DEBUG) UDP stats line, to avoid per-tick spam.
    std::atomic<int64_t> last_stats_us_{0};
    // Keepalive send throttle. Distinct from last_activity_us_: sending a
    // keepalive must NOT refresh the activity clock, otherwise a tunnel whose
    // peer has gone away would keep itself alive forever and evade the server's
    // idle sweep. The cadence is throttled by this clock instead.
    std::atomic<int64_t> last_keepalive_us_{0};

    // Parked write-loop resume hook (empty when no loop is parked). Strand-only:
    // registered and consumed exclusively from strand-bound code, so it needs no
    // lock -- and it must stay a plain member because it is a std::function, not
    // an atomic-friendly type.
    std::function<void()> write_resume_cb_;

    // Logger module ("kcp_session" / "kcp_client") and line tag (the server's
    // session id, empty for the client). Together they reproduce each side's
    // existing log lines exactly.
    std::string log_module_;
    std::string log_tag_;

    // FEC codec (null when disabled — see FecConfig). One per session,
    // strand-confined, mirroring kcp-go's one fecEncoder/fecDecoder per
    // session. fec_send_buf_ / fec_parity_ are reused per output datagram;
    // both handle_kcp_output implementations copy out of the view they are
    // given (encrypt_into writes a fresh buffer), so the reuse is safe.
    std::unique_ptr<kcp::internal::FecEncoder> fec_encoder_;
    std::unique_ptr<kcp::internal::FecDecoder> fec_decoder_;
    std::vector<uint8_t> fec_send_buf_;
    // Same type as kcp::internal::FecPacket (an alias for vector<uint8_t>).
    std::vector<std::vector<uint8_t>> fec_parity_;
    // Adaptive-parity decision shared with every other tunnel of this process.
    // Null unless the policy is enabled, which is what keeps
    // the default path byte-identical to the pre-adaptive code.
    AdaptiveHooks hooks_;
    // Last nodelay mode pushed into kcp_ (true = 30ms floor). Strand-only: the
    // comparison and the push both happen in flush_cycle.
    bool rto_low_latency_applied_ = true;

    // Push the adaptive RTO floor into the codec if the policy changed. Called
    // from flush_cycle (strand-bound, every tick), so a policy flip reaches a
    // live tunnel within one 10ms tick without any cross-thread wakeup.
    void apply_rto_floor();
};

} // namespace kcp_proxy
