#include "kcp_proxy/kcp_wrapper.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace kcp_proxy {

namespace {

// One throttle for the whole process: a per-session instance cannot bound the
// aggregate across N sessions, and a flood split across reasons must not
// swallow the first line of another. See log_kcp_input_rejected in the header.
LogThrottle& kcp_input_reject_log() {
    static LogThrottle throttle;
    return throttle;
}

} // namespace

void log_kcp_input_rejected(std::string_view log_module, std::string_view tag,
                            int ret, size_t size) {
    uint32_t suppressed = 0;
    if (!kcp_input_reject_log().should_log(suppressed)) return;
    const std::string prefix = tag.empty() ? std::string()
                                           : std::string(tag) + ": ";
    std::string line =
        fmt::format("{}FAIL_STAGE=KCP_INPUT_FAILED ERROR=ret_{} size={}", prefix, ret, size);
    line += throttle_suffix(suppressed);
    LOG_WARNING(std::string(log_module), line);
}

KcpWrapper::KcpWrapper(uint32_t conv)
    : kcp_(std::make_unique<kcp::Kcp>(
          conv,
          // Output trampoline: kcp::Kcp hands us each datagram from
          // Flush/Input; route it to the caller's byte_view callback.
          [this](const std::uint8_t* buf, std::size_t len) { c_output(buf, len); },
          // Clock: kcp::Kcp reads time only through this injection, so the
          // explicit update(ms) below remains the single time source.
          [this]() -> std::uint32_t { return current_ms_; })) {
    configure();
    LOG_DEBUG("kcp_wrapper", fmt::format("created conv={}", conv));
}

KcpWrapper::~KcpWrapper() {
    // Neutralize the C++ callback BEFORE teardown. The kcp::Kcp destructor
    // does not flush today, but clearing first means teardown can never
    // re-enter a destroyed std::function even if that ever changes.
    output_cb_ = nullptr;
}

void KcpWrapper::set_output_callback(OutputCallback cb) {
    output_cb_ = std::move(cb);
}

int KcpWrapper::send(byte_view data) {
    int ret = kcp_->Send(data.data(), data.size());
    if (ret < 0) {
        LOG_ERROR("kcp_wrapper", fmt::format("kcp send failed: ret={} size={} waitsnd={}", ret,
                                             data.size(), wait_send()));
    } else {
        LOG_DEBUG("kcp_wrapper",
                  fmt::format("kcp send ok: {} bytes, waitsnd={}", data.size(), wait_send()));
    }
    return ret;
}

int KcpWrapper::recv(std::vector<uint8_t>& buffer) {
    int size = kcp_->PeekSize();
    if (size <= 0) {
        buffer.clear();
        return 0;
    }
    buffer.resize(static_cast<size_t>(size));
    int got = kcp_->Recv(buffer.data(), buffer.size());
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
    int msg_size = kcp_->PeekSize();
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
    return kcp_->Recv(data, static_cast<size_t>(msg_size));
}

int KcpWrapper::input(byte_view data) {
    int ret = kcp_->Input(data.data(), data.size());
    if (ret < 0) {
        // Detail only, and at DEBUG: the throttled, once-per-datagram line is
        // the caller's (log_kcp_input_rejected), which already carries ret and
        // the size. Logging both made one rejected datagram cost two WARNINGs.
        LOG_DEBUG("kcp_wrapper", fmt::format("kcp input failed: ret={} size={}", ret, data.size()));
    } else {
        LOG_DEBUG("kcp_wrapper",
                  fmt::format("kcp input ok: {} bytes, peek={}", data.size(), peek_size()));
    }
    return ret;
}

void KcpWrapper::update(uint32_t current_ms) {
    // kcp::Kcp::Update() takes no timestamp; it reads the injected clock.
    current_ms_ = current_ms;
    updated_ = true;
    kcp_->Update();
}

void KcpWrapper::flush() {
    // Mirror ikcp_flush's `if (kcp->updated == 0) return;`: a flush before the
    // first update would bypass kcp::Kcp's own updated_ gate (its Flush has
    // none) and emit a datagram stamped ts=0, which the peer would feed into
    // its RTT estimator. Today every caller updates first, so this only hardens
    // the wrapper against a future caller.
    if (!updated_) return;
    kcp_->Flush(kcp::kFlushFull);
}

int KcpWrapper::peek_size() const {
    return kcp_->PeekSize();
}

int KcpWrapper::wait_send() const {
    return kcp_->wait_snd();
}

void KcpWrapper::configure() {
    const KcpTuning& t = kcp_tuning();
    kcp_->NoDelay(KCP_NODELAY, KCP_INTERVAL_MS, KCP_RESEND, KCP_NC);
    kcp_->WndSize(t.sndwnd, t.rcvwnd);
    if (kcp_->SetMtu(t.mtu) < 0) {
        // SetMtu only refuses when the value cannot even hold a wire header,
        // which the CLI clamp (KCP_MTU_MIN) already excludes -- but a silent
        // misconfiguration here would degrade every session, so surface it.
        LOG_ERROR("kcp_wrapper", fmt::format("kcp SetMtu refused mtu={}", t.mtu));
    }
}

void KcpWrapper::c_output(const std::uint8_t* buf, std::size_t len) {
    if (!output_cb_ || len == 0 || buf == nullptr) {
        return;
    }
    // Catch every C++ exception. One bad encrypt on the upper layer must not
    // unwind through kcp::Kcp's flush/input frames into the io_context.
    try {
        output_cb_(byte_view(buf, len));
    } catch (const std::exception& e) {
        LOG_ERROR("kcp_wrapper", fmt::format("output callback threw: {} len={}", e.what(), len));
    } catch (...) {
        LOG_ERROR("kcp_wrapper",
                  fmt::format("output callback threw unknown exception, len={}", len));
    }
}

} // namespace kcp_proxy
