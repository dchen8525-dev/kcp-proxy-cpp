#include "kcp_proxy/kcp_wrapper.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace kcp_proxy {

KcpWrapper::KcpWrapper(uint32_t conv) {
    kcp_ = ikcp_create(conv, this);
    if (!kcp_) {
        LOG_ERROR("kcp_wrapper", "ikcp_create failed for conv=" + std::to_string(conv));
        throw std::runtime_error("ikcp_create failed");
    }
    configure();
    ikcp_setoutput(kcp_, &KcpWrapper::c_output);
    LOG_DEBUG("kcp_wrapper", "created conv=" + std::to_string(conv));
}

KcpWrapper::~KcpWrapper() {
    if (kcp_) {
        // Neutralize the C++ callback BEFORE release, but keep the output
        // function pointer installed. If this ikcp build flushes during
        // teardown (some forks call ikcp_flush from ikcp_release), a cleared
        // output pointer would trip ikcp's assert(kcp->output)/null-call;
        // the static c_output trampoline with an empty output_cb_ is a safe
        // no-op in every case, so teardown can never re-enter a destroyed
        // std::function nor a null output function.
        output_cb_ = nullptr;
        ikcp_release(kcp_);
        kcp_ = nullptr;
    }
}

void KcpWrapper::set_output_callback(OutputCallback cb) {
    output_cb_ = std::move(cb);
}

int KcpWrapper::send(byte_view data) {
    int ret = ikcp_send(kcp_, reinterpret_cast<const char*>(data.data()),
                        static_cast<int>(data.size()));
    if (ret < 0) {
        LOG_ERROR("kcp_wrapper", "ikcp_send failed: ret=" + std::to_string(ret) +
                  " size=" + std::to_string(data.size()) +
                  " waitsnd=" + std::to_string(wait_send()));
    } else {
        LOG_DEBUG("kcp_wrapper", "ikcp_send ok: " + std::to_string(data.size()) +
                  " bytes, waitsnd=" + std::to_string(wait_send()));
    }
    return ret;
}

int KcpWrapper::recv(std::vector<uint8_t>& buffer) {
    int size = ikcp_peeksize(kcp_);
    if (size <= 0) {
        buffer.clear();
        return 0;
    }
    buffer.resize(static_cast<size_t>(size));
    int got = ikcp_recv(kcp_, reinterpret_cast<char*>(buffer.data()), size);
    if (got < 0) {
        buffer.clear();
        return got;
    }
    if (static_cast<size_t>(got) != buffer.size()) {
        buffer.resize(static_cast<size_t>(got));
    }
    return got;
}

int KcpWrapper::recv(uint8_t* data, size_t size) {
    int msg_size = ikcp_peeksize(kcp_);
    if (msg_size <= 0) {
        return 0;
    }
    if (static_cast<size_t>(msg_size) > size) {
        // Never silently truncate: consuming the whole message but returning
        // only part of it would corrupt the byte stream this proxy exists to
        // preserve. Report the condition and leave the message in the queue so
        // the caller can handle it (peek + vector overload).
        return KCP_RECV_MSG_TOO_BIG;
    }
    // Fast path: the fixed buffer is large enough, no heap allocation.
    return ikcp_recv(kcp_, reinterpret_cast<char*>(data), msg_size);
}

int KcpWrapper::input(byte_view data) {
    int ret = ikcp_input(kcp_, reinterpret_cast<const char*>(data.data()),
                         static_cast<int>(data.size()));
    if (ret < 0) {
        LOG_WARNING("kcp_wrapper", "ikcp_input failed: ret=" + std::to_string(ret) +
                    " size=" + std::to_string(data.size()));
    } else {
        LOG_DEBUG("kcp_wrapper", "ikcp_input ok: " + std::to_string(data.size()) +
                  " bytes, peek=" + std::to_string(peek_size()));
    }
    return ret;
}

void KcpWrapper::update(uint32_t current_ms) {
    ikcp_update(kcp_, current_ms);
}

void KcpWrapper::flush() {
    ikcp_flush(kcp_);
}

int KcpWrapper::peek_size() const {
    return ikcp_peeksize(kcp_);
}

int KcpWrapper::wait_send() const {
    return ikcp_waitsnd(kcp_);
}

void KcpWrapper::configure() {
    ikcp_nodelay(kcp_, 1, KCP_INTERVAL_MS, 5, 1);
    ikcp_wndsize(kcp_, KCP_SNDWND, KCP_RCVWND);
    ikcp_setmtu(kcp_, KCP_MTU);
}

int KcpWrapper::c_output(const char* buf, int len, ikcpcb* /*kcp*/, void* user) {
    auto* self = static_cast<KcpWrapper*>(user);
    if (!self || !self->output_cb_ || len <= 0 || buf == nullptr) {
        return 0;
    }
    // Catch every C++ exception. Letting one escape into ikcp's C call frame
    // is undefined behavior — and a single bad encrypt on the upper layer
    // would otherwise crash the whole io_context.
    try {
        self->output_cb_(byte_view(
            reinterpret_cast<const uint8_t*>(buf),
            static_cast<size_t>(len)));
    } catch (const std::exception& e) {
        LOG_ERROR("kcp_wrapper", "c_output callback threw: " + std::string(e.what()) +
                  " len=" + std::to_string(len));
        return -1;
    } catch (...) {
        LOG_ERROR("kcp_wrapper", "c_output callback threw unknown exception, len=" + std::to_string(len));
        return -1;
    }
    return 0;
}

} // namespace kcp_proxy
