#pragma once

#include "config.hpp"
#include "byte_view.hpp"
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

extern "C" {
#include "ikcp.h"
}

namespace kcp_proxy {

// Single, process-wide, throttled diagnostic for a datagram ikcp_input()
// refused. Reachable once per hostile (or merely corrupted) datagram by anyone
// holding the session key -- a truncated segment or a wrong conv is enough --
// so an unthrottled line here is exactly the log DoS LogThrottle exists to
// stop: a format pass, a timestamp and a write(2) per datagram, handed over
// for free. Both tunnels route their ikcp_input failure through this one
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

class KcpWrapper {
public:
    using OutputCallback = std::function<void(byte_view)>;

    explicit KcpWrapper(uint32_t conv);
    ~KcpWrapper();

    // Move/copy disabled: ikcp_create() embeds `this` into kcp_->user, so the
    // object's address must remain stable for the entire lifetime of the
    // underlying ikcpcb. Owners that need movability should hold a unique_ptr.
    KcpWrapper(KcpWrapper&&) = delete;
    KcpWrapper& operator=(KcpWrapper&&) = delete;
    KcpWrapper(const KcpWrapper&) = delete;
    KcpWrapper& operator=(const KcpWrapper&) = delete;

    // Returned by recv(data, size) when the next KCP message is larger than the
    // caller's buffer. The message is NOT consumed; the caller can peek_size()
    // and use the vector overload instead. Distinguishable from ikcp error codes.
    static constexpr int KCP_RECV_MSG_TOO_BIG = -100;

    void set_output_callback(OutputCallback cb);
    [[nodiscard]] int send(byte_view data);
    [[nodiscard]] int recv(std::vector<uint8_t>& buffer);
    // Overload that receives into a caller-provided fixed buffer (avoids heap
    // allocation on the hot path). Returns the number of bytes received, a
    // negative ikcp error code, or KCP_RECV_MSG_TOO_BIG if the next message
    // does not fit. Never silently truncates: a truncated KCP message would
    // corrupt the byte stream the proxy is supposed to preserve.
    [[nodiscard]] int recv(uint8_t* data, size_t size);
    [[nodiscard]] int input(byte_view data);
    void update(uint32_t current_ms);
    void flush();
    int peek_size() const;
    int wait_send() const;

    // Read-only handle to the underlying ikcpcb. Used by tests and debugging to
    // inspect the live KCP state (e.g. verify configure() applied the KCP_*
    // constants). Returns a valid pointer for the lifetime of the object;
    // construction throws instead of leaving it null.
    const ikcpcb* ikcp() const { return kcp_; }

    void configure();

private:
    ikcpcb* kcp_ = nullptr;
    OutputCallback output_cb_;

    static int c_output(const char* buf, int len, ikcpcb* kcp, void* user);
};

} // namespace kcp_proxy
