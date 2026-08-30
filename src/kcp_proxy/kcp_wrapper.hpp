#pragma once

#include "config.hpp"
#include "byte_view.hpp"
#include <functional>
#include <memory>
#include <vector>

extern "C" {
#include "ikcp.h"
}

namespace kcp_proxy {

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

    void configure();

private:
    ikcpcb* kcp_ = nullptr;
    OutputCallback output_cb_;

    static int c_output(const char* buf, int len, ikcpcb* kcp, void* user);
};

} // namespace kcp_proxy
