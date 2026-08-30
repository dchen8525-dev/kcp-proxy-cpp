#include "kcp_proxy/kcp_session.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/time_util.hpp"
#include <fmt/format.h>
#include <algorithm>
#include <cstring>
#include <utility>

namespace kcp_proxy {

KCPSession::KCPSession(asio::io_context& io, uint32_t conv,
                       asio::ip::udp::endpoint remote_addr,
                       std::shared_ptr<Crypto> crypto,
                       std::string session_id)
    : io_(io),
      strand_(asio::make_strand(io.get_executor())),
      session_id_(std::move(session_id)),
      remote_addr_(std::move(remote_addr)),
      crypto_(std::move(crypto)),
      kcp_(conv),
      update_timer_(strand_) {
    // Mark the session running immediately (synchronously). Previously running_
    // was only flipped true inside the strand-dispatched start() lambda, leaving
    // a window where a freshly inserted session looked "not running" to a
    // concurrent get_or_create_session and could be wrongly treated as stale and
    // erased. Setting it here keeps the live session unambiguous from creation.
    state_flags_.fetch_or(RUNNING);
    last_activity_us_.store(now_us());
    last_keepalive_us_.store(now_us());
    kcp_.set_output_callback([this](byte_view data) {
        // Always invoked from strand_ (KCP only runs there).
        handle_kcp_output(data);
    });
    LOG_DEBUG("kcp_session", fmt::format("{}: created conv={} remote={}:{}",
              session_id_, conv, remote_addr_.address().to_string(), remote_addr_.port()));
}

KCPSession::~KCPSession() {
    LOG_DEBUG("kcp_session", session_id_ + ": destroyed");
    // Best-effort sync stop; if we're still running this means the owner
    // forgot to call stop(), which would normally be on the strand.
    state_flags_.fetch_and(static_cast<uint8_t>(~RUNNING));
}

void KCPSession::set_send_callback(std::function<void(std::vector<uint8_t>)> cb) {
    send_callback_ = std::move(cb);
}

void KCPSession::start() {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self]() {
        // running_ is already true (set in the constructor); this lambda just
        // kicks off the per-session KCP update loop and records the start.
        self->touch_activity();
        self->do_update(std::error_code{});
        LOG_INFO("kcp_session", self->session_id_ + ": started");
    });
}

void KCPSession::stop() {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self]() {
        const uint8_t old = self->state_flags_.fetch_and(static_cast<uint8_t>(~RUNNING));
        if ((old & RUNNING) == 0) return;
        std::error_code ignored;
        self->update_timer_.cancel(ignored);

        // Clear send callback FIRST to prevent any further output during flush.
        // This ensures no packets are sent after session closes, avoiding
        // crypto counter mismatch with client's new session.
        self->send_callback_ = nullptr;

        // Clear pending flags to prevent race conditions when session is
        // reused or when checking stale sessions in the map.
        self->state_flags_.fetch_and(static_cast<uint8_t>(
            ~(FORWARD_READ_PENDING | SOCKS5_READ_PENDING | CONNECT_PENDING)));

        // Notify any pending reader so its caller can clean up rather than
        // wait forever for data that will never arrive. Post to the session
        // strand (not the raw io_context) to keep session affinity, matching
        // how every other completion on this session is delivered.
        if (self->pending_read_handler_) {
            auto h = std::move(self->pending_read_handler_);
            self->pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
            asio::post(self->strand_, [h = std::move(h)]() mutable {
                h(asio::error::operation_aborted, 0);
            });
        }
        LOG_INFO("kcp_session", self->session_id_ + ": stopped");
    });
}

void KCPSession::touch_activity() {
    last_activity_us_.store(now_us());
}

void KCPSession::receive_data(byte_view encrypted_data, std::function<void()> after) {
    LOG_DEBUG("kcp_session", fmt::format("{}: receive_data {} encrypted bytes",
              session_id_, encrypted_data.size()));
    // Copy now: the caller's buffer may be reused before the strand picks up.
    std::vector<uint8_t> copy(encrypted_data.begin(), encrypted_data.end());
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, data = std::move(copy), after = std::move(after)]() mutable {
        self->on_receive(std::move(data));
        if (after) after();
    });
}

void KCPSession::on_receive(std::vector<uint8_t> encrypted) {
    if ((state_flags_.load() & RUNNING) == 0) {
        LOG_WARNING("kcp_session", fmt::format("{}: on_receive while not running, dropping {} bytes",
                    session_id_, encrypted.size()));
        return;
    }
    std::error_code ec = crypto_->decrypt_into(byte_view(encrypted.data(), encrypted.size()), decrypt_buf_);
    if (ec == crypto_errors::errc::replay) {
        // Normal UDP reordering / duplicate: drop quietly, never treat as an
        // error and never advance the replay window (already handled in Crypto).
        LOG_DEBUG("kcp_session", fmt::format("{}: replay/stale packet dropped", session_id_));
        return;
    }
    if (ec) {
        metrics_.decrypt_errors.fetch_add(1, std::memory_order_relaxed);
        LOG_ERROR("kcp_session", fmt::format("FAIL_STAGE=DECRYPT_FAILED ERROR={} CLIENT_ENDPOINT={} TARGET=-",
                    ec.message(), session_id_));
        return;
    }
    touch_activity();
    metrics_.packets_received.fetch_add(1, std::memory_order_relaxed);
    metrics_.bytes_received.fetch_add(encrypted.size(), std::memory_order_relaxed);
    LOG_DEBUG("kcp_session", fmt::format("{}: decrypt OK {} -> {} bytes, peek_before={}",
              session_id_, encrypted.size(), decrypt_buf_.size(), kcp_.peek_size()));
    int input_ret = kcp_.input(byte_view(decrypt_buf_.data(), decrypt_buf_.size()));
    if (input_ret < 0) {
        LOG_WARNING("kcp_session", fmt::format("FAIL_STAGE=KCP_INPUT_FAILED ERROR=ret_{} CLIENT_ENDPOINT={} TARGET=-",
                    input_ret, session_id_));
        return;
    }
    LOG_DEBUG("kcp_session", fmt::format("{}: ikcp_input ok, peek_after={} wait_send={}",
              session_id_, kcp_.peek_size(), kcp_.wait_send()));
    try_fulfill_read();
}

void KCPSession::inject_decrypted(std::vector<uint8_t> decrypted, std::function<void()> after) {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, d = std::move(decrypted), after = std::move(after)]() mutable {
        self->on_inject_decrypted(std::move(d));
        if (after) after();
    });
}

void KCPSession::on_inject_decrypted(std::vector<uint8_t> decrypted) {
    if ((state_flags_.load() & RUNNING) == 0) return;
    touch_activity();
    LOG_DEBUG("kcp_session", fmt::format("{}: inject {} decrypted bytes, peek_before={}",
              session_id_, decrypted.size(), kcp_.peek_size()));
    int input_ret = kcp_.input(byte_view(decrypted.data(), decrypted.size()));
    if (input_ret < 0) {
        LOG_WARNING("kcp_session", fmt::format("FAIL_STAGE=KCP_INPUT_FAILED ERROR=ret_{} CLIENT_ENDPOINT={} TARGET=-",
                    input_ret, session_id_));
        return;
    }
    LOG_DEBUG("kcp_session", fmt::format("{}: inject ok, peek_after={}", session_id_, kcp_.peek_size()));
    try_fulfill_read();
}

void KCPSession::send_data(byte_view data) {
    if ((state_flags_.load() & RUNNING) == 0) return;
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

void KCPSession::on_send(byte_view data) {
    if ((state_flags_.load() & RUNNING) == 0) return;
    LOG_DEBUG("kcp_session", fmt::format("{}: on_send {} bytes, wait_send_before={}",
              session_id_, data.size(), kcp_.wait_send()));
    int send_ret = kcp_.send(data);
    if (send_ret < 0) {
        metrics_.encrypt_errors.fetch_add(1, std::memory_order_relaxed);
        LOG_ERROR("kcp_session", fmt::format("{}: ikcp_send failed, ret={}, closing session",
                    session_id_, send_ret));
        stop();
        return;
    }
    metrics_.packets_sent.fetch_add(1, std::memory_order_relaxed);
    metrics_.bytes_sent.fetch_add(data.size(), std::memory_order_relaxed);
    LOG_DEBUG("kcp_session", fmt::format("{}: ikcp_send ok, wait_send_after={}",
              session_id_, kcp_.wait_send()));
    kcp_.update(now_kcp_ms());
    kcp_.flush();
}

void KCPSession::async_read_some(asio::mutable_buffer buffer,
                                 std::function<void(std::error_code, size_t)> handler) {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, buffer, handler = std::move(handler)]() mutable {
        self->on_async_read_some(buffer, std::move(handler));
    });
}

void KCPSession::on_async_read_some(asio::mutable_buffer buffer,
                                    std::function<void(std::error_code, size_t)> handler) {
    if ((state_flags_.load() & RUNNING) == 0) {
        LOG_WARNING("kcp_session", session_id_ + ": async_read_some while not running -> aborted");
        auto h = std::move(handler);
        asio::post(io_, [h = std::move(h)]() mutable {
            h(asio::error::operation_aborted, 0);
        });
        return;
    }
    if (pending_read_handler_) {
        LOG_WARNING("kcp_session", session_id_ + ": async_read_some stacked (already_started), " +
                    "old handler still pending - rejecting new one");
        auto h = std::move(handler);
        asio::post(io_, [h = std::move(h)]() mutable {
            h(asio::error::already_started, 0);
        });
        return;
    }
    LOG_DEBUG("kcp_session", fmt::format("{}: async_read_some registered, buffer_size={} peek={}",
              session_id_, buffer.size(), kcp_.peek_size()));
    pending_read_buffer_ = buffer;
    pending_read_handler_ = std::move(handler);
    try_fulfill_read();
}

bool KCPSession::is_alive() const {
    if ((state_flags_.load() & RUNNING) == 0) return false;
    int64_t age_us = now_us() - last_activity_us_.load();
    return age_us < static_cast<int64_t>(KCP_TIMEOUT_SEC) * 1000000;
}

bool KCPSession::is_handshake_done() const {
    return (state_flags_.load() & SOCKS5_HS_DONE) != 0;
}

void KCPSession::mark_handshake_done() {
    // The upstream connect finished: CONNECT_PENDING has served its purpose.
    state_flags_.fetch_and(static_cast<uint8_t>(~CONNECT_PENDING));
    state_flags_.fetch_or(SOCKS5_HS_DONE);
    LOG_INFO("kcp_session", session_id_ + ": handshake done");
}

void KCPSession::do_update(const std::error_code& ec) {
    if (ec || (state_flags_.load() & RUNNING) == 0) return;

    kcp_.update(now_kcp_ms());
    kcp_.flush();
    if (pending_read_handler_) {
        try_fulfill_read();
    }

    // Application-layer keepalive: a live but idle tunnel would otherwise be
    // reaped by the peer's idle sweep (KCP_TIMEOUT_SEC). Once the tunnel is
    // established, push a tiny KCP heartbeat on a fixed cadence whenever there
    // is no real data to send. The peer's try_fulfill_read recognizes and drops
    // it; merely receiving it counts as activity on the peer side.
    //
    // IMPORTANT: sending a heartbeat must NOT refresh last_activity_us_. If it
    // did, a session whose peer had gone away would keep itself "alive" forever
    // (sending heartbeats every 30s) and the idle sweep could never reap it.
    // The cadence is throttled by last_keepalive_us_ instead, so the activity
    // clock reflects only what we have actually received from the peer.
    if (is_handshake_done()) {
        const int64_t now = now_us();
        if (now - last_keepalive_us_.load() >=
                static_cast<int64_t>(KCP_KEEPALIVE_SEC) * 1000000 &&
            kcp_.peek_size() <= 0) {
            const auto* kb = reinterpret_cast<const uint8_t*>(KCP_CONTROL_KEEPALIVE);
            size_t klen = std::strlen(KCP_CONTROL_KEEPALIVE);
            if (kcp_.send(byte_view(kb, klen)) == 0) {
                last_keepalive_us_.store(now);
                LOG_DEBUG("kcp_session", session_id_ + ": keepalive sent");
            }
        }
    }

    // Graceful shutdown of the upstream target: once the target TCP connection
    // has closed, keep the session alive (flushing the data already queued in
    // KCP's send buffer to the client) until wait_send() reaches 0, then tear
    // down via the drained callback. Tearing down early would drop the
    // undelivered data and truncate the stream the proxy is supposed to
    // preserve. Note the buffer only drains as the client ACKs, so this waits
    // for genuine delivery, not just the local UDP send.
    if (target_closed_.load() && wait_send() == 0 && drained_cb_) {
        auto cb = std::move(drained_cb_);
        drained_cb_ = nullptr;
        LOG_INFO("kcp_session", session_id_ + ": target drained, closing");
        cb();
        return;
    }

    // Fixed 10ms cadence. Note: we intentionally do NOT use ikcp_check() to
    // sleep longer when idle -- with the vendored ikcp, ikcp_update always
    // advances ts_flush to current+interval, so ikcp_check returns ~10ms ahead
    // even when idle; there is no idle-sleep win to be had.
    update_timer_.expires_after(std::chrono::milliseconds(KCP_INTERVAL_MS));
    auto self = shared_from_this();
    update_timer_.async_wait([self](const std::error_code& e) {
        self->do_update(e);
    });
}

void KCPSession::handle_kcp_output(byte_view data) {
    if (!send_callback_) {
        LOG_WARNING("kcp_session", fmt::format("{}: << handle_kcp_output - no callback, dropping {} bytes",
                    session_id_, data.size()));
        return;
    }
    LOG_DEBUG("kcp_session", fmt::format("{}: handle_kcp_output {} bytes -> encrypt",
              session_id_, data.size()));
    std::vector<uint8_t> encrypted;
    std::error_code ec = crypto_->encrypt_into(data, encrypted);
    if (ec) {
        metrics_.encrypt_errors.fetch_add(1, std::memory_order_relaxed);
        LOG_ERROR("kcp_session", fmt::format("{}: encrypt error: {}", session_id_, ec.message()));
        return;
    }
    LOG_DEBUG("kcp_session", fmt::format("{}: encrypted -> {} bytes -> send_callback",
              session_id_, encrypted.size()));
    send_callback_(std::move(encrypted));
}

void KCPSession::try_fulfill_read() {
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
        LOG_ERROR("kcp_session", fmt::format("{}: dropped oversized KCP message ({} bytes > FWD_BUF_SIZE)",
                    session_id_, oversized_bytes));
        auto handler = std::move(pending_read_handler_);
        pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
        pending_read_handler_ = nullptr;
        auto self = shared_from_this();
        asio::post(strand_, [self, handler = std::move(handler)]() mutable {
            handler(asio::error::message_size, 0);
        });
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
        LOG_DEBUG("kcp_session", session_id_ + ": keepalive received, dropping");
        return;
    }

    // async_read_some delivers one whole KCP message. The message was already
    // consumed into kcp_recv_buf_ above, so if it does not fit the caller's
    // buffer there is no way to hand back the tail. Report the error instead of
    // silently truncating the stream (which would corrupt the tunnel); the
    // caller closes the connection on message_size.
    if (static_cast<size_t>(size) > pending_read_buffer_.size()) {
        LOG_ERROR("kcp_session", fmt::format("{}: KCP message too big for read buffer ({} > {}), aborting read",
                    session_id_, size, pending_read_buffer_.size()));
        auto handler = std::move(pending_read_handler_);
        pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
        pending_read_handler_ = nullptr;
        auto self = shared_from_this();
        asio::post(strand_, [self, handler = std::move(handler)]() mutable {
            handler(asio::error::message_size, 0);
        });
        return;
    }

    LOG_DEBUG("kcp_session", fmt::format("{}: try_fulfill_read - got {} bytes from KCP, buffer_capacity={}",
              session_id_, size, pending_read_buffer_.size()));

    size_t to_copy = static_cast<size_t>(size);
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

} // namespace kcp_proxy
