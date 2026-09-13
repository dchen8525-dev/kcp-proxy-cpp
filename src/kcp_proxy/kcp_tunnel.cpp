#include "kcp_proxy/kcp_tunnel.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/time_util.hpp"
#include <fmt/format.h>
#include <cstring>
#include <utility>

namespace kcp_proxy {

KcpTunnel::KcpTunnel(asio::io_context& io, uint32_t conv,
                     std::shared_ptr<Crypto> crypto,
                     std::string log_module, std::string log_tag)
    : io_(io),
      strand_(asio::make_strand(io.get_executor())),
      crypto_(std::move(crypto)),
      kcp_(conv),
      log_module_(std::move(log_module)),
      log_tag_(std::move(log_tag)) {
    const int64_t now = now_us();
    last_activity_us_.store(now);
    last_keepalive_us_.store(now);
    kcp_.set_output_callback([this](byte_view data) {
        // Always invoked from strand_ (KCP only runs there).
        handle_kcp_output(data);
    });
}

KcpTunnel::~KcpTunnel() = default;

std::string KcpTunnel::log_msg(const std::string& text) const {
    if (log_tag_.empty()) return text;
    return log_tag_ + ": " + text;
}

void KcpTunnel::touch_activity() {
    last_activity_us_.store(now_us());
}

int64_t KcpTunnel::activity_age_us() const {
    return now_us() - last_activity_us_.load();
}

void KcpTunnel::mark_handshake_done() {
    handshake_done_.store(true);
}

std::string KcpTunnel::stats_summary() const {
    const auto& m = metrics_;
    return log_msg(fmt::format(
        "stats tx_pkt={} tx_bytes={} rx_pkt={} rx_bytes={} "
        "replay_dropped={} decrypt_err={} encrypt_err={}",
        m.udp_tx_packets.load(std::memory_order_relaxed),
        m.udp_tx_bytes.load(std::memory_order_relaxed),
        m.udp_rx_packets.load(std::memory_order_relaxed),
        m.udp_rx_bytes.load(std::memory_order_relaxed),
        m.replay_dropped.load(std::memory_order_relaxed),
        m.decrypt_errors.load(std::memory_order_relaxed),
        m.encrypt_errors.load(std::memory_order_relaxed)));
}

void KcpTunnel::send_data(byte_view data) {
    if (!can_accept_data()) return;
    if (strand_.running_in_this_thread()) {
        // Already on the session strand (the common case once the forwarding
        // loops are strand-bound): no copy or dispatch needed.
        on_send(data);
        return;
    }
    std::vector<uint8_t> copy(data.begin(), data.end());
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, d = std::move(copy)]() mutable {
        self->on_send(byte_view(d.data(), d.size()));
    });
}

void KcpTunnel::on_send(byte_view data) {
    if (!is_active()) return;
    LOG_DEBUG(log_module_, log_msg("on_send " + std::to_string(data.size()) + " bytes"));
    int send_ret = kcp_.send(data);
    if (send_ret < 0) {
        metrics_.encrypt_errors.fetch_add(1, std::memory_order_relaxed);
        LOG_ERROR(log_module_, log_msg("ikcp_send failed, ret=" + std::to_string(send_ret) +
                  ", closing session"));
        shut_down();
        return;
    }
    metrics_.packets_sent.fetch_add(1, std::memory_order_relaxed);
    metrics_.bytes_sent.fetch_add(data.size(), std::memory_order_relaxed);
    kcp_.update(now_kcp_ms());
    kcp_.flush();
}

void KcpTunnel::async_read_some(asio::mutable_buffer buffer,
                                std::function<void(std::error_code, size_t)> handler) {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, buffer, handler = std::move(handler)]() mutable {
        self->on_async_read_some(buffer, std::move(handler));
    });
}

void KcpTunnel::on_async_read_some(asio::mutable_buffer buffer,
                                   std::function<void(std::error_code, size_t)> handler) {
    if (!is_active()) {
        // Expected during teardown, so this stays at DEBUG: a read registered
        // after close is a race the caller handles, not a fault.
        LOG_DEBUG(log_module_, log_msg("async_read_some while not running -> aborted"));
        auto h = std::move(handler);
        asio::post(io_, [h = std::move(h)]() mutable {
            h(asio::error::operation_aborted, 0);
        });
        return;
    }
    if (pending_read_handler_) {
        // A second outstanding read would silently shadow the first and leak
        // its caller, so reject it loudly.
        LOG_WARNING(log_module_, log_msg("async_read_some stacked (already_started), "
                    "old handler still pending - rejecting new one"));
        auto h = std::move(handler);
        asio::post(io_, [h = std::move(h)]() mutable {
            h(asio::error::already_started, 0);
        });
        return;
    }
    pending_read_buffer_ = buffer;
    pending_read_handler_ = std::move(handler);
    try_fulfill_read();
}

void KcpTunnel::complete_pending_read(const std::error_code& ec) {
    if (!pending_read_handler_) return;
    auto handler = std::move(pending_read_handler_);
    pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
    // Reset explicitly rather than leaning on the standard's "valid but
    // unspecified" moved-from state: every other site that consumes the handler
    // this way nulls it too, and an empty-by-luck std::function must never be
    // the reason a later try_fulfill_read() does or does not fire.
    pending_read_handler_ = nullptr;
    // Post to the session strand (not the raw io_context) so the completion
    // keeps session affinity and avoids a cross-thread hop.
    auto self = shared_from_this();
    asio::post(strand_, [self, handler = std::move(handler), ec]() mutable {
        handler(ec, 0);
    });
}

void KcpTunnel::try_fulfill_read() {
    if (!pending_read_handler_ || pending_read_buffer_.data() == nullptr) {
        return;
    }

    // Use the fixed-size buffer to avoid heap allocation on the hot path.
    int size = kcp_.recv(kcp_recv_buf_.data(), kcp_recv_buf_.size());
    if (size == KcpWrapper::KCP_RECV_MSG_TOO_BIG) {
        // A message larger than FWD_BUF_SIZE is a protocol violation (senders
        // are capped at FWD_BUF_SIZE per message). Consume it so KCP stays
        // consistent, then fail the read: we must never forward a truncated
        // byte stream, and leaving the handler pending would hang the caller.
        std::vector<uint8_t> oversized;
        int oversized_bytes = kcp_.recv(oversized);
        LOG_ERROR(log_module_, log_msg(fmt::format(
            "dropped oversized KCP message ({} bytes > FWD_BUF_SIZE)", oversized_bytes)));
        complete_pending_read(asio::error::message_size);
        return;
    }
    if (size <= 0) {
        return;
    }

    // Drop application-layer keepalive heartbeats: they are not real stream
    // data and must never be forwarded to the downstream TCP socket.
    if (size == static_cast<int>(std::strlen(KCP_CONTROL_KEEPALIVE)) &&
        std::memcmp(kcp_recv_buf_.data(), KCP_CONTROL_KEEPALIVE,
                    static_cast<size_t>(size)) == 0) {
        LOG_DEBUG(log_module_, log_msg("keepalive received, dropping"));
        return;
    }

    // async_read_some delivers one whole KCP message. The message was already
    // consumed into kcp_recv_buf_ above, so if it does not fit the caller's
    // buffer there is no way to hand back the tail. Report the error instead of
    // silently truncating the stream (which would corrupt the tunnel); the
    // caller closes the connection on message_size.
    if (static_cast<size_t>(size) > pending_read_buffer_.size()) {
        LOG_ERROR(log_module_, log_msg(fmt::format(
            "KCP message too big for read buffer ({} > {}), aborting read",
            size, pending_read_buffer_.size())));
        complete_pending_read(asio::error::message_size);
        return;
    }

    LOG_DEBUG(log_module_, log_msg(fmt::format(
        "try_fulfill_read - got {} bytes from KCP, buffer_capacity={}",
        size, pending_read_buffer_.size())));

    const size_t to_copy = static_cast<size_t>(size);
    std::memcpy(pending_read_buffer_.data(), kcp_recv_buf_.data(), to_copy);

    auto handler = std::move(pending_read_handler_);
    pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
    pending_read_handler_ = nullptr;

    // Dispatch the completion via post() so the caller cannot synchronously
    // re-enter async_read_some -> try_fulfill_read on the same stack frame.
    // Post to the session strand (not the raw io_context) so the completion
    // keeps session affinity and avoids a cross-thread hop.
    auto self = shared_from_this();
    asio::post(strand_, [self, handler = std::move(handler), to_copy]() mutable {
        handler(std::error_code{}, to_copy);
    });
}

void KcpTunnel::maybe_log_stats() {
    static constexpr int64_t STATS_INTERVAL_US = 30 * 1000000;
    const int64_t now = now_us();
    int64_t last = last_stats_us_.load();
    if ((now - last) >= STATS_INTERVAL_US &&
        last_stats_us_.compare_exchange_strong(last, now)) {
        LOG_DEBUG(log_module_, stats_summary());
    }
}

void KcpTunnel::maybe_send_keepalive() {
    if (!is_handshake_done()) return;
    const int64_t now = now_us();
    if (now - last_keepalive_us_.load() <
            static_cast<int64_t>(KCP_KEEPALIVE_SEC) * 1000000 ||
        kcp_.peek_size() > 0) {
        return;
    }
    const auto* kb = reinterpret_cast<const uint8_t*>(KCP_CONTROL_KEEPALIVE);
    const size_t klen = std::strlen(KCP_CONTROL_KEEPALIVE);
    // ikcp_send returns the number of bytes queued (>= 0) on success, NOT 0 --
    // compare against < 0 or the throttle never engages and a keepalive is
    // injected on every 10ms tick once the interval passes.
    if (kcp_.send(byte_view(kb, klen)) >= 0) {
        last_keepalive_us_.store(now);
        LOG_DEBUG(log_module_, log_msg("keepalive sent"));
    }
}

} // namespace kcp_proxy
