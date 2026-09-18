#include "kcp_proxy/kcp_session.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/time_util.hpp"
#include <fmt/format.h>
#include <cstring>
#include <utility>

namespace kcp_proxy {

KCPSession::KCPSession(asio::io_context& io, uint32_t conv,
                       asio::ip::udp::endpoint remote_addr,
                       std::shared_ptr<Crypto> crypto,
                       std::string session_id)
    : KcpTunnel(io, conv, std::move(crypto), "kcp_session", session_id),
      session_id_(std::move(session_id)),
      remote_addr_(std::move(remote_addr)) {
    // Mark the session running immediately (synchronously). Previously running_
    // was only flipped true inside the strand-dispatched start() lambda, leaving
    // a window where a freshly inserted session looked "not running" to a
    // concurrent get_or_create_session and could be wrongly treated as stale and
    // erased. Setting it here keeps the live session unambiguous from creation.
    state_flags_.fetch_or(RUNNING);
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
    asio::dispatch(strand(), [this, self]() {
        // is_running() is already true (set in the constructor); this lambda
        // just records the start. KCP updates are driven by the server's shared
        // tick timer, not by a per-session loop.
        touch_activity();
        LOG_INFO("kcp_session", session_id_ + ": started");
    });
}

void KCPSession::stop() {
    auto self = shared_from_this();
    asio::dispatch(strand(), [this, self]() {
        const uint8_t old = state_flags_.fetch_and(static_cast<uint8_t>(~RUNNING));
        if ((old & RUNNING) == 0) return;

        // Clear send callback FIRST to prevent any further output during flush.
        // This ensures no packets are sent after session closes, avoiding
        // crypto counter mismatch with client's new session.
        send_callback_ = nullptr;

        // Clear pending flags to prevent race conditions when session is
        // reused or when checking stale sessions in the map.
        state_flags_.fetch_and(static_cast<uint8_t>(
            ~(FORWARD_READ_PENDING | SOCKS5_READ_PENDING | CONNECT_PENDING)));

        // Notify any pending reader so its caller can clean up rather than
        // wait forever for data that will never arrive.
        complete_pending_read(asio::error::operation_aborted);

        LOG_INFO("kcp_session", session_id_ + ": stopped");
        LOG_INFO("kcp_session", stats_summary());
    });
}

void KCPSession::shut_down() {
    stop();
}

void KCPSession::receive_data(byte_view encrypted_data, std::function<void()> after) {
    LOG_DEBUG("kcp_session", fmt::format("{}: receive_data {} encrypted bytes",
              session_id_, encrypted_data.size()));
    // Copy now: the caller's buffer may be reused before the strand picks up.
    std::vector<uint8_t> copy(encrypted_data.begin(), encrypted_data.end());
    auto self = shared_from_this();
    asio::dispatch(strand(), [this, self, data = std::move(copy),
                              after = std::move(after)]() mutable {
        on_receive(std::move(data));
        if (after) after();
    });
}

void KCPSession::on_receive(std::vector<uint8_t> encrypted) {
    if (!is_running()) {
        LOG_WARNING("kcp_session", fmt::format("{}: on_receive while not running, dropping {} bytes",
                    session_id_, encrypted.size()));
        return;
    }
    std::error_code ec = crypto_->decrypt_into(byte_view(encrypted.data(), encrypted.size()), decrypt_buf_);
    metrics_.udp_rx_packets.fetch_add(1, std::memory_order_relaxed);
    metrics_.udp_rx_bytes.fetch_add(encrypted.size(), std::memory_order_relaxed);
    if (ec == crypto_errors::errc::replay) {
        // Normal UDP reordering / duplicate: drop quietly, never treat as an
        // error and never advance the replay window (already handled in Crypto).
        metrics_.replay_dropped.fetch_add(1, std::memory_order_relaxed);
        LOG_DEBUG("kcp_session", fmt::format("{}: replay/stale packet dropped", session_id_));
        return;
    }
    if (ec) {
        metrics_.decrypt_errors.fetch_add(1, std::memory_order_relaxed);
        // Per-packet attacker-controlled noise: the decrypt_errors metric
        // above remains the INFO-visible signal, so keep the log at DEBUG
        // (AGENTS.md §8: no per-packet spam at INFO).
        LOG_DEBUG("kcp_session", fmt::format("FAIL_STAGE=DECRYPT_FAILED ERROR={} CLIENT_ENDPOINT={} TARGET=-",
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
    asio::dispatch(strand(), [this, self, d = std::move(decrypted),
                              after = std::move(after)]() mutable {
        on_inject_decrypted(std::move(d));
        if (after) after();
    });
}

void KCPSession::on_inject_decrypted(std::vector<uint8_t> decrypted) {
    if (!is_running()) return;
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

bool KCPSession::is_alive() const {
    if (!is_running()) return false;
    return activity_age_us() < static_cast<int64_t>(KCP_TIMEOUT_SEC) * 1000000;
}

void KCPSession::mark_handshake_done() {
    // The upstream connect finished: CONNECT_PENDING has served its purpose.
    state_flags_.fetch_and(static_cast<uint8_t>(~CONNECT_PENDING));
    KcpTunnel::mark_handshake_done();
    LOG_INFO("kcp_session", session_id_ + ": handshake done");
}

void KCPSession::on_update_tick() {
    if (!is_running()) return;

    // Periodic (throttled) stats at DEBUG so peer-to-peer loss asymmetry is
    // visible over time without spamming INFO (see AGENTS.md #8).
    maybe_log_stats();

    kcp_.update(now_kcp_ms());
    kcp_.flush();
    if (pending_read_handler_) {
        try_fulfill_read();
    }

    // Application-layer keepalive: a live but idle tunnel would otherwise be
    // reaped by the peer's idle sweep (KCP_TIMEOUT_SEC). Sending a heartbeat
    // must NOT refresh the activity clock -- see KcpTunnel::maybe_send_keepalive.
    maybe_send_keepalive();

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

    // Re-arm is NOT done here. This method is driven by KCPServer's single
    // shared 10ms tick timer (do_update_tick), which collapses N per-session
    // timer-heap entries into one. Fixed 10ms cadence: we intentionally do
    // NOT use ikcp_check() to sleep longer when idle -- with the vendored
    // ikcp, ikcp_update always advances ts_flush to current+interval, so
    // ikcp_check returns ~10ms ahead even when idle; there is no idle-sleep
    // win to be had.
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
    metrics_.udp_tx_packets.fetch_add(1, std::memory_order_relaxed);
    metrics_.udp_tx_bytes.fetch_add(encrypted.size(), std::memory_order_relaxed);
    send_callback_(std::move(encrypted));
}

} // namespace kcp_proxy
