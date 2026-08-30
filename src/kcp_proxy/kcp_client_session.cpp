#include "kcp_proxy/kcp_client_session.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/time_util.hpp"
#include <algorithm>
#include <cstring>
#include <utility>

namespace kcp_proxy {

KCPClientSession::KCPClientSession(asio::io_context& io,
                                   asio::ip::udp::endpoint server_addr,
                                   std::shared_ptr<Crypto> crypto,
                                   uint32_t conv)
    : io_(io),
      strand_(asio::make_strand(io.get_executor())),
      server_addr_(std::move(server_addr)),
      crypto_(std::move(crypto)),
      kcp_(conv),
      update_timer_(strand_),
      connect_timer_(strand_) {
    last_activity_us_.store(now_us());
    last_rx_us_.store(now_us());
    last_keepalive_us_.store(now_us());
    kcp_.set_output_callback([this](byte_view data) {
        handle_kcp_output(data);
    });
    LOG_DEBUG("kcp_client", "created conv=" + std::to_string(conv) +
              " server=" + server_addr_.address().to_string() + ":" +
              std::to_string(server_addr_.port()));
}

KCPClientSession::~KCPClientSession() {
    LOG_DEBUG("kcp_client", "destroyed");
    running_.store(false);
    connected_.store(false);
}

void KCPClientSession::touch_activity() {
    last_activity_us_.store(now_us());
}

void KCPClientSession::connect(std::function<void(bool)> handler) {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, h = std::move(handler)]() mutable {
        self->on_connect(std::move(h));
    });
}

void KCPClientSession::on_connect(std::function<void(bool)> handler) {
    try {
        udp_socket_.emplace(strand_);
        const auto protocol = server_addr_.protocol();
        udp_socket_->open(protocol);
        if (protocol == asio::ip::udp::v6()) {
            udp_socket_->bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), 0));
        } else {
            udp_socket_->bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        }
        // Pin the socket to the server endpoint so the kernel drops any packet
        // from a different source before it ever reaches the decrypt path.
        // (An attacker would need the shared PSK to forge a valid packet, but
        // filtering foreign sources removes a whole class of off-path noise.)
        std::error_code connect_ec;
        udp_socket_->connect(server_addr_, connect_ec);
        if (connect_ec) {
            throw std::runtime_error("UDP connect failed: " + connect_ec.message());
        }

        running_.store(true);
        connected_.store(false);
        connect_pending_.store(true);
        touch_activity();

        do_update(std::error_code{});
        do_udp_receive();

        auto ack_buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);
        auto self = shared_from_this();
        auto completion = std::make_shared<std::function<void(bool)>>(std::move(handler));
        async_read_some(asio::buffer(*ack_buf),
            [self, ack_buf, completion](const std::error_code& ec, size_t bytes) mutable {
                // Timer may have already cancelled the pending read. If the
                // connect already timed out (connect_pending_ == false but
                // connect_timer_ cancelled our read), the handler is gone.
                if (!self->connect_pending_.exchange(false)) return;
                std::error_code ignored;
                self->connect_timer_.cancel(ignored);
                auto h = std::move(*completion);
                *completion = nullptr;
                if (ec || bytes == 0) {
                    self->on_close();
                    if (h) h(false);
                    return;
                }
                const std::string msg(reinterpret_cast<const char*>(ack_buf->data()), bytes);
                if (msg != KCP_CONTROL_HELLO_ACK) {
                    LOG_ERROR("kcp_client", "KCP handshake failed: unexpected response");
                    self->on_close();
                    if (h) h(false);
                    return;
                }
                self->connected_.store(true);
                self->touch_activity();
                LOG_INFO("kcp_client", "KCP handshake confirmed with " +
                         self->server_addr_.address().to_string() + ":" +
                         std::to_string(self->server_addr_.port()));
                if (h) h(true);
            });

        connect_timer_.expires_after(std::chrono::seconds(KCP_HANDSHAKE_TIMEOUT_SEC));
        connect_timer_.async_wait([self, completion](const std::error_code& ec) mutable {
            if (ec == asio::error::operation_aborted) return;
            if (!self->connect_pending_.exchange(false)) return;
            LOG_ERROR("kcp_client", "KCP handshake timeout after " +
                      std::to_string(KCP_HANDSHAKE_TIMEOUT_SEC) + "s");
            self->on_close();
            auto h = std::move(*completion);
            *completion = nullptr;
            if (h) h(false);
        });

        send_connect_hello();

        LOG_INFO("kcp_client", "KCP handshake started with " +
                 server_addr_.address().to_string() + ":" +
                 std::to_string(server_addr_.port()));
    } catch (const std::exception& e) {
        LOG_ERROR("kcp_client", "connect error: " + std::string(e.what()));
        // Tear down cleanly: if running_ was already set (e.g. the failure was
        // in send_connect_hello), on_close() cancels the timers and the update
        // loop; otherwise the socket may still be open and must be closed.
        on_close();
        if (udp_socket_ && udp_socket_->is_open()) {
            std::error_code ignored;
            udp_socket_->close(ignored);
            udp_socket_.reset();
        }
        if (handler) handler(false);
    }
}

void KCPClientSession::send_connect_hello() {
    const auto* msg = reinterpret_cast<const uint8_t*>(KCP_CONTROL_HELLO);
    const size_t len = std::strlen(KCP_CONTROL_HELLO);
    int send_ret = kcp_.send(byte_view(msg, len));
    if (send_ret < 0) {
        LOG_ERROR("kcp_client", "KCP handshake send failed, ret=" + std::to_string(send_ret));
        on_close();
        return;
    }
    kcp_.update(now_kcp_ms());
    kcp_.flush();
}

void KCPClientSession::close() {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self]() { self->on_close(); });
}

void KCPClientSession::on_close() {
    if (!running_.exchange(false)) return;
    connected_.store(false);
    connect_pending_.store(false);

    std::error_code ignored;
    update_timer_.cancel(ignored);
    connect_timer_.cancel(ignored);

    try {
        kcp_.update(now_kcp_ms());
        kcp_.flush();
    } catch (...) {}

    if (udp_socket_ && udp_socket_->is_open()) {
        udp_socket_->close(ignored);
    }

    // Clear pending handler to prevent race conditions. Post to the session
    // strand (not the raw io_context) to keep session affinity, matching how
    // every other completion on this session is delivered.
    if (pending_read_handler_) {
        auto h = std::move(pending_read_handler_);
        pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
        asio::post(strand_, [h = std::move(h)]() mutable {
            h(asio::error::operation_aborted, 0);
        });
    }

    LOG_INFO("kcp_client", "closed");
}

void KCPClientSession::send_data(byte_view data) {
    if (!running_.load() || !connected_.load()) return;
    if (strand_.running_in_this_thread()) {
        // Already on the session strand (common once the forwarding loops are
        // strand-bound): no copy or dispatch needed.
        on_send(data);
        return;
    }
    std::vector<uint8_t> copy(data.begin(), data.end());
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, d = std::move(copy)]() mutable {
        self->on_send(byte_view(d.data(), d.size()));
    });
}

void KCPClientSession::on_send(byte_view data) {
    if (!running_.load()) return;
    LOG_DEBUG("kcp_client", "on_send " + std::to_string(data.size()) + " bytes");
    int send_ret = kcp_.send(data);
    if (send_ret < 0) {
        LOG_ERROR("kcp_client", "ikcp_send failed, ret=" + std::to_string(send_ret) +
                  ", closing session");
        on_close();
        return;
    }
    kcp_.update(now_kcp_ms());
    kcp_.flush();
}

void KCPClientSession::async_read_some(asio::mutable_buffer buffer,
                                       std::function<void(std::error_code, size_t)> handler) {
    auto self = shared_from_this();
    asio::dispatch(strand_, [self, buffer, h = std::move(handler)]() mutable {
        self->on_async_read_some(buffer, std::move(h));
    });
}

void KCPClientSession::on_async_read_some(asio::mutable_buffer buffer,
                                          std::function<void(std::error_code, size_t)> handler) {
    if (!running_.load()) {
        LOG_DEBUG("kcp_client", "async_read_some while not running -> aborted");
        auto h = std::move(handler);
        asio::post(io_, [h = std::move(h)]() mutable {
            h(asio::error::operation_aborted, 0);
        });
        return;
    }
    if (pending_read_handler_) {
        LOG_WARNING("kcp_client",
                    "async_read_some stacked (already_started), "
                    "old handler remains pending - rejecting new one");
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

void KCPClientSession::do_update(const std::error_code& ec) {
    if (ec || !running_.load()) return;

    // Session-level liveness. KCP never times out on the client side: without
    // this, a server crash or a key rotation on the server leaves the local app
    // hanging forever on an established tunnel. A healthy peer sends keepalives
    // every KCP_KEEPALIVE_SEC, so KCP_TIMEOUT_SEC of total silence is a
    // generous margin. Only valid received packets advance last_rx_us_, so our
    // own outgoing keepalives cannot mask a dead server.
    if (is_connected()) {
        const int64_t idle_us = now_us() - last_rx_us_.load();
        if (idle_us > static_cast<int64_t>(KCP_TIMEOUT_SEC) * 1000000) {
            LOG_WARNING("kcp_client", "idle timeout: no valid data from server for " +
                        std::to_string(idle_us / 1000000) + "s, closing session");
            on_close();
            return;
        }
    }

    kcp_.update(now_kcp_ms());
    kcp_.flush();
    if (pending_read_handler_) try_fulfill_read();

    // Application-layer keepalive (see KCPSession::do_update for rationale).
    // Fixed cadence, independent of received activity: a healthy peer must
    // always hear from us every KCP_KEEPALIVE_SEC or its idle sweep would reap
    // our session even though the tunnel is fine.
    if (is_handshake_done()) {
        const int64_t now = now_us();
        if (now - last_keepalive_us_.load() >=
                static_cast<int64_t>(KCP_KEEPALIVE_SEC) * 1000000 &&
            kcp_.peek_size() <= 0) {
            const auto* kb = reinterpret_cast<const uint8_t*>(KCP_CONTROL_KEEPALIVE);
            size_t klen = std::strlen(KCP_CONTROL_KEEPALIVE);
            if (kcp_.send(byte_view(kb, klen)) == 0) {
                last_keepalive_us_.store(now);
                LOG_DEBUG("kcp_client", "keepalive sent");
            }
        }
    }

    // Fixed 10ms cadence (see KCPSession::do_update for why we don't use
    // ikcp_check to sleep longer when idle).
    update_timer_.expires_after(std::chrono::milliseconds(KCP_INTERVAL_MS));
    auto self = shared_from_this();
    update_timer_.async_wait([self](const std::error_code& e) {
        self->do_update(e);
    });
}

void KCPClientSession::do_udp_receive() {
    if (!udp_socket_ || !running_.load()) return;

    auto self = shared_from_this();
    // Connected datagram socket: async_receive (no endpoint) only delivers
    // packets from the pinned server endpoint.
    udp_socket_->async_receive(
        asio::buffer(udp_recv_buf_),
        asio::bind_executor(strand_,
            [self](const std::error_code& ec, size_t bytes) {
                if (ec) {
                    if (ec != asio::error::operation_aborted &&
                        self->running_.load()) {
                        LOG_ERROR("kcp_client", "UDP receive error: " + ec.message());
                        self->do_udp_receive();
                    }
                    return;
                }
                if (!self->running_.load()) return;
                // on_receive runs synchronously on the strand and consumes the
                // buffer (decrypt -> ikcp_input copies into KCP), so we can pass
                // a view into udp_recv_buf_ and re-arm afterwards -- no copy.
                if (bytes > 0) {
                    self->on_receive(byte_view(self->udp_recv_buf_.data(), bytes));
                }
                self->do_udp_receive();
            }));
}

void KCPClientSession::on_receive(byte_view packet) {
    if (!running_.load()) return;
    std::error_code ec = crypto_->decrypt_into(packet, decrypt_buf_);
    if (ec == crypto_errors::errc::replay) {
        // Normal UDP reordering / duplicate: drop quietly.
        LOG_DEBUG("kcp_client", "replay/stale packet discarded (UDP reordering)");
        return;
    }
    if (ec) {
        LOG_ERROR("kcp_client", "UDP receive error: " + ec.message());
        return;
    }
    touch_activity();
    // Authentic data from the server: this is the liveness clock for the
    // session-level timeout in do_update. Only valid decrypted packets advance
    // it, so a dead/stale server cannot keep the tunnel alive.
    last_rx_us_.store(now_us());
    LOG_DEBUG("kcp_client", "UDP recv " + std::to_string(packet.size()) +
              " encrypted -> " + std::to_string(decrypt_buf_.size()) + " decrypted");
    int input_ret = kcp_.input(byte_view(decrypt_buf_.data(), decrypt_buf_.size()));
    if (input_ret < 0) {
        LOG_WARNING("kcp_client", "ikcp_input rejected packet, ret=" +
                    std::to_string(input_ret));
        return;
    }
    LOG_DEBUG("kcp_client", "ikcp_input ok, peek=" + std::to_string(kcp_.peek_size()));
    try_fulfill_read();
}

void KCPClientSession::handle_kcp_output(byte_view data) {
    if (!udp_socket_ || !running_.load()) {
        LOG_DEBUG("kcp_client", "handle_kcp_output - session not running");
        return;
    }
    LOG_DEBUG("kcp_client", "handle_kcp_output " + std::to_string(data.size()) + " bytes -> encrypt");
    // Encrypt straight into the buffer that will back the async UDP send, so a
    // packet costs one allocation instead of two (encrypted + send_buf).
    auto send_buf = std::make_shared<std::vector<uint8_t>>();
    std::error_code ec = crypto_->encrypt_into(data, *send_buf);
    if (ec) {
        LOG_ERROR("kcp_client", "encrypt error: " + ec.message());
        return;
    }
    LOG_DEBUG("kcp_client", "encrypted -> " + std::to_string(send_buf->size()) +
             " bytes, sending UDP to " + server_addr_.address().to_string() + ":" +
             std::to_string(server_addr_.port()));

    auto self = shared_from_this();
    udp_socket_->async_send(
        asio::buffer(*send_buf),
        asio::bind_executor(strand_,
            [self, send_buf](const std::error_code& ec, size_t bytes_sent) {
                if (ec && ec != asio::error::operation_aborted) {
                    LOG_ERROR("kcp_client", "UDP send error: " + ec.message());
                } else if (!ec) {
                    LOG_DEBUG("kcp_client", "UDP sent " + std::to_string(bytes_sent) + " bytes");
                }
            }));
}

void KCPClientSession::try_fulfill_read() {
    if (!pending_read_handler_ || pending_read_buffer_.data() == nullptr) {
        LOG_DEBUG("kcp_client", "try_fulfill_read - no pending handler");
        return;
    }

    int size = kcp_.recv(kcp_recv_buf_.data(), kcp_recv_buf_.size());
    if (size == KcpWrapper::KCP_RECV_MSG_TOO_BIG) {
        // Protocol violation (sender exceeded FWD_BUF_SIZE per message):
        // consume it so KCP stays consistent, then fail the read. Never forward
        // a truncated byte stream, and leaving the handler pending would hang
        // the caller.
        std::vector<uint8_t> oversized;
        int oversized_bytes = kcp_.recv(oversized);
        LOG_ERROR("kcp_client", "dropped oversized KCP message (" +
                  std::to_string(oversized_bytes) + " bytes > FWD_BUF_SIZE)");
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
        LOG_DEBUG("kcp_client", "try_fulfill_read - no data (recv=" + std::to_string(size) + ")");
        return;
    }

    // Drop application-layer keepalive heartbeats (see KCPSession::try_fulfill_read).
    if (size == static_cast<int>(std::strlen(KCP_CONTROL_KEEPALIVE)) &&
        std::memcmp(kcp_recv_buf_.data(), KCP_CONTROL_KEEPALIVE,
                    static_cast<size_t>(size)) == 0) {
        LOG_DEBUG("kcp_client", "keepalive received, dropping");
        return;
    }

    // The message does not fit the caller's buffer (see KCPSession: same
    // rationale). Fail the read with message_size instead of silently
    // truncating the stream.
    if (static_cast<size_t>(size) > pending_read_buffer_.size()) {
        LOG_ERROR("kcp_client", "KCP message too big for read buffer (" +
                  std::to_string(size) + " > " + std::to_string(pending_read_buffer_.size()) +
                  "), aborting read");
        auto handler = std::move(pending_read_handler_);
        pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
        pending_read_handler_ = nullptr;
        auto self = shared_from_this();
        asio::post(strand_, [self, handler = std::move(handler)]() mutable {
            handler(asio::error::message_size, 0);
        });
        return;
    }

    LOG_DEBUG("kcp_client", "try_fulfill_read - got " + std::to_string(size) + " bytes from KCP");

    size_t to_copy = static_cast<size_t>(size);
    std::memcpy(pending_read_buffer_.data(), kcp_recv_buf_.data(), to_copy);

    auto handler = std::move(pending_read_handler_);
    pending_read_buffer_ = asio::mutable_buffer{nullptr, 0};
    pending_read_handler_ = nullptr;

    // Post the completion to the session strand (not the raw io_context) so the
    // caller keeps session affinity.
    auto self = shared_from_this();
    asio::post(strand_, [self, handler = std::move(handler), to_copy]() mutable {
        handler(std::error_code{}, to_copy);
    });
}

} // namespace kcp_proxy
