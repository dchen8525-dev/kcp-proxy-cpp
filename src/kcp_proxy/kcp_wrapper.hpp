#pragma once

#include "config.hpp"
#include "byte_view.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "kcp/kcp.h"

namespace kcp_proxy {

// Single, process-wide, throttled diagnostic for a datagram KCP Input()
// refused. Reachable once per hostile (or merely corrupted) datagram by anyone
// holding the session key -- a truncated segment or a wrong conv is enough --
// so an unthrottled line here is exactly the log DoS LogThrottle exists to
// stop: a format pass, a timestamp and a write(2) per datagram, handed over
// for free. Both tunnels route their KCP Input failure through this one
// emitter so:
//   * the aggregate is bounded (a per-session throttle cannot bound N
//     sessions, and every session has its own KcpWrapper), and
//   * the line is emitted ONCE per datagram. Before this, KcpWrapper::input()
//     logged its own WARNING and every caller logged a second one, so a single
//     bad datagram produced two lines -- double the cost of the DoS and double
//     the noise in any grep for one rejection.
// The first occurrence of a burst always prints, so the FAIL_STAGE marker the
// diagnostics and tests grep for is never lost.
// `tag` is the server's session id (empty on the client), matching each side's
// existing line prefix.
void log_kcp_input_rejected(std::string_view log_module, std::string_view tag,
                            int ret, size_t size);

// Adapter between the proxy and the vendored kcp-cpp port (kcp::Kcp, the C++
// port of xtaci/kcp-go v5). Keeps the exact surface the sessions were written
// against when the backend was the C ikcp implementation, so the transport
// layers above carry no trace of which KCP implementation is in use:
//   * send/recv/input keep ikcp-style negative error codes,
//   * update(ms) keeps taking the session tick's timestamp (forwarded to
//     kcp::Kcp through the injected clock), and
//   * flush() keeps an explicit full-flush entry point.
class KcpWrapper {
public:
    using OutputCallback = std::function<void(byte_view)>;

    explicit KcpWrapper(uint32_t conv);
    ~KcpWrapper();

    // Move/copy disabled: the output and clock callbacks handed to kcp::Kcp
    // capture `this`, so the object's address must remain stable for the
    // entire lifetime of the underlying Kcp. Owners that need movability
    // should hold a unique_ptr.
    KcpWrapper(KcpWrapper&&) = delete;
    KcpWrapper& operator=(KcpWrapper&&) = delete;
    KcpWrapper(const KcpWrapper&) = delete;
    KcpWrapper& operator=(const KcpWrapper&) = delete;

    // Returned by recv(data, size) when the next KCP message is larger than the
    // caller's buffer. The message is NOT consumed; the caller can peek_size()
    // and use the vector overload instead. Distinguishable from kcp error codes.
    static constexpr int KCP_RECV_MSG_TOO_BIG = -100;

    void set_output_callback(OutputCallback cb);
    // kcp::Kcp::Send semantics: 0 on success, -1 for an empty write, -2 when
    // the message needs more than 255 fragments. Unlike the C ikcp it never
    // refuses on a full send window -- kcp-go leaves backpressure to the
    // session layer, which is exactly what KCP_BACKPRESSURE_THRESHOLD does.
    [[nodiscard]] int send(byte_view data);
    [[nodiscard]] int recv(std::vector<uint8_t>& buffer);
    // Overload that receives into a caller-provided fixed buffer (avoids heap
    // allocation on the hot path). Returns the number of bytes received, a
    // negative kcp error code, or KCP_RECV_MSG_TOO_BIG if the next message
    // does not fit. Never silently truncates: a truncated KCP message would
    // corrupt the byte stream the proxy is supposed to preserve.
    [[nodiscard]] int recv(uint8_t* data, size_t size);
    // kcp::Kcp::Input semantics: 0 on success, -1 conv mismatch, -2 truncated
    // segment, -3 unknown command.
    [[nodiscard]] int input(byte_view data);
    void update(uint32_t current_ms);
    void flush();
    int peek_size() const;
    int wait_send() const;

    // Read-only handle to the underlying kcp::Kcp. Used by tests and debugging
    // to inspect the live protocol state (e.g. verify configure() applied the
    // KCP_* constants). Returns a valid reference for the lifetime of the
    // object; construction throws instead of leaving it unbound.
    const kcp::Kcp& kcp() const { return *kcp_; }

    // Current retransmission timeout (ms), driven by the live RTT estimate.
    // The FEC layer borrows it as the burst-continuity window (see
    // FecEncoder::Encode): a shard set whose packets are spread wider than
    // this is not a burst, and parity is skipped for it.
    std::uint32_t rto() const { return kcp_->rto(); }

    void configure();

private:
    // Declaration order matters: kcp_ is constructed LAST and destroyed FIRST,
    // so the two members its injected lambdas read are fully constructed before
    // kcp_ exists and still alive while kcp_ is torn down. (kcp::Kcp's ctor does
    // not call either callback today and its dtor does not flush, but the
    // ordering makes teardown safe regardless.) output_cb_ and current_ms_ also
    // have to outlive the "output_cb_ = nullptr" arm in ~KcpWrapper.
    OutputCallback output_cb_;
    // Last timestamp passed to update(); read back through the injected clock.
    // Storing it keeps the wrapper's time source identical to the session tick
    // that drives it -- and deterministic under tests.
    std::uint32_t current_ms_ = 0;
    // Set once update() has run. Mirrors the C ikcp's `updated` flag: before the
    // first update, flush must be a no-op (see flush()), otherwise a datagram
    // would go out stamped ts=0 and inflate the peer's RTT estimate.
    bool updated_ = false;
    std::unique_ptr<kcp::Kcp> kcp_;

    void c_output(const std::uint8_t* buf, std::size_t len);
};

} // namespace kcp_proxy
