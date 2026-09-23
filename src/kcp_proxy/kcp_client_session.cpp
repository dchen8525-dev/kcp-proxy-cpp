#include "kcp_proxy/kcp_client_session.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/time_util.hpp"
#if defined(_WIN32)
#include <winsock2.h>
#include <mswsock.h>
// Present in mswsock.h on modern SDKs; defined here so MinGW and older
// toolchains still compile the SIO_UDP_CONNRESET call (same shim as server.cpp).
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#endif
#include <algorithm>
#include <cstring>
#include <utility>

namespace kcp_proxy {

KCPClientSession::KCPClientSession(asio::io_context& io,
                                   asio::ip::udp::endpoint server_addr,
                                   std::shared_ptr<Crypto> crypto,
                                   uint32_t conv)
    : KcpTunnel(io, conv, std::move(crypto), "kcp_client", ""),
      server_addr_(std::move(server_addr)),
      connect_timer_(strand()),
      receive_backoff_timer_(strand()) {
    last_rx_us_.store(now_us());
    LOG_DEBUG("kcp_client", "created conv=" + std::to_string(conv) +
              " server=" + server_addr_.address().to_string() + ":" +
              std::to_string(server_addr_.port()));
}

KCPClientSession::~KCPClientSession() {
    LOG_DEBUG("kcp_client", "destroyed");
    running_.store(false);
    connected_.store(false);
}

void KCPClientSession::connect(std::function<void(bool)> handler) {
    auto self = shared_from_this();
    asio::dispatch(strand(), [this, self, h = std::move(handler)]() mutable {
        on_connect(std::move(h));
    });
}

void KCPClientSession::on_connect(std::function<void(bool)> handler) {
    // Created before the try so the catch can still deliver the callback if an
    // exception escapes after the handler was moved here (a moved-from
    // std::function would silently swallow the notification).
    auto completion = std::make_shared<std::function<void(bool)>>(std::move(handler));
    try {
        udp_socket_.emplace(strand());
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

#if defined(_WIN32)
        // This socket is connect()ed, so Windows delivers WSAECONNRESET on the
        // next receive after every send to a dead peer port -- the client is
        // MORE exposed to this than the server, whose socket is unconnected.
        // Turn the reporting off at the source, exactly as the server does; the
        // tolerant handler in do_udp_receive stays as the cross-platform safety
        // net. Without this, a server that is down or restarting turns every
        // HELLO retransmit and keepalive into an ERROR log line plus an
        // unthrottled re-arm.
        {
            BOOLEAN disable_connreset = FALSE;
            DWORD bytes_returned = 0;
            const int wsa_rc = ::WSAIoctl(
                udp_socket_->native_handle(), SIO_UDP_CONNRESET,
                &disable_connreset, sizeof(disable_connreset),
                nullptr, 0, &bytes_returned, nullptr, nullptr);
            LOG_DEBUG("kcp_client", std::string("SIO_UDP_CONNRESET disabled (wsa_rc=") +
                      std::to_string(wsa_rc) + ")");
        }
#endif

        // Raise the kernel UDP send/receive buffers. Oversized kernel buffers
        // prevent the OS from silently dropping datagrams during bursts (which
        // KCP would otherwise misread as network loss and retransmit a window).
        std::error_code opt_ec;
        udp_socket_->set_option(asio::socket_base::receive_buffer_size(
                                    UDP_SO_RCVBUF_BYTES), opt_ec);
        if (opt_ec) {
            LOG_WARNING("kcp_client", "failed to set SO_RCVBUF: " + opt_ec.message());
        }
        udp_socket_->set_option(asio::socket_base::send_buffer_size(
                                    UDP_SO_SNDBUF_BYTES), opt_ec);
        if (opt_ec) {
            LOG_WARNING("kcp_client", "failed to set SO_SNDBUF: " + opt_ec.message());
        }

        running_.store(true);
        connected_.store(false);
        connect_pending_.store(true);
        touch_activity();

        do_udp_receive();

        auto ack_buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);
        auto self = shared_from_this();
        async_read_some(asio::buffer(*ack_buf),
            [this, self, ack_buf, completion](const std::error_code& ec, size_t bytes) mutable {
                // Timer may have already cancelled the pending read. If the
                // connect already timed out (connect_pending_ == false but
                // connect_timer_ cancelled our read), the handler is gone.
                if (!connect_pending_.exchange(false)) return;
                std::error_code ignored;
                connect_timer_.cancel(ignored);
                auto h = std::move(*completion);
                *completion = nullptr;
                if (ec || bytes == 0) {
                    on_close();
                    if (h) h(false);
                    return;
                }
                const std::string msg(reinterpret_cast<const char*>(ack_buf->data()), bytes);
                const bool ack_v2 = (msg == KCP_CONTROL_HELLO_ACK_V2);
                if (!ack_v2 && msg != KCP_CONTROL_HELLO_ACK) {
                    LOG_ERROR("kcp_client", "KCP handshake failed: unexpected response");
                    on_close();
                    if (h) h(false);
                    return;
                }
                // Only a V2 ACK means the server understands FIN; sending one to
                // a V1 server would inject a control message into the tunnel as
                // stream data. See KCP_CONTROL_FIN.
                if (ack_v2) enable_fin();
                connected_.store(true);
                touch_activity();
                LOG_INFO("kcp_client", "KCP handshake confirmed with " +
                         server_addr_.address().to_string() + ":" +
                         std::to_string(server_addr_.port()) +
                         (ack_v2 ? " (V2, half-close enabled)" : ""));
                if (h) h(true);
            });

        connect_timer_.expires_after(std::chrono::seconds(KCP_HANDSHAKE_TIMEOUT_SEC));
        connect_timer_.async_wait([this, self, completion](const std::error_code& ec) mutable {
            if (ec == asio::error::operation_aborted) return;
            if (!connect_pending_.exchange(false)) return;
            LOG_ERROR("kcp_client", "KCP handshake timeout after " +
                      std::to_string(KCP_HANDSHAKE_TIMEOUT_SEC) + "s");
            on_close();
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
        // Deliver the failure through `completion`: `handler` was moved into
        // it above and may be empty here. connect_pending_ was cleared by
        // on_close(), so the async read/timer handlers cannot fire it twice.
        if (*completion) {
            auto h = std::move(*completion);
            *completion = nullptr;
            h(false);
        }
    }
}

void KCPClientSession::send_connect_hello() {
    // V2 asks the server for FIN (half-close) support; it answers with the
    // matching ACK and this session enables FIN only if it does (see the
    // handshake reply handler). A V1 server still answers V1 and everything
    // works as before, just without half-close.
    const auto* msg = reinterpret_cast<const uint8_t*>(KCP_CONTROL_HELLO_V2);
    const size_t len = std::strlen(KCP_CONTROL_HELLO_V2);
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
    asio::dispatch(strand(), [this, self]() { on_close(); });
}

void KCPClientSession::shut_down() {
    on_close();
}

void KCPClientSession::mark_handshake_done() {
    KcpTunnel::mark_handshake_done();
    LOG_INFO("kcp_client", "handshake done");
}

void KCPClientSession::on_close() {
    if (!running_.load()) return;

    // Best-effort final flush BEFORE clearing running_: handle_kcp_output()
    // drops everything once running_ is false, so flushing after the exchange
    // would be a no-op. This gives queued segments (e.g. the last bytes of a
    // response) one chance to reach the server before the socket closes.
    // It is still best-effort: the UDP socket closes immediately below, so only
    // segments that flush synchronously into async sends actually leave.
    try {
        kcp_.update(now_kcp_ms());
        kcp_.flush();
    } catch (...) {}

    running_.store(false);
    connected_.store(false);
    connect_pending_.store(false);

    std::error_code ignored;
    connect_timer_.cancel(ignored);
    // Cancel the receive backoff too: a pending wait would otherwise hold a
    // strong ref to this session until it fired, and its handler would re-arm
    // do_udp_receive() on a closed session.
    receive_backoff_timer_.cancel(ignored);

    if (udp_socket_ && udp_socket_->is_open()) {
        udp_socket_->close(ignored);
    }

    complete_pending_read(asio::error::operation_aborted);

    LOG_INFO("kcp_client", "closed");
    LOG_INFO("kcp_client", stats_summary());
}

void KCPClientSession::on_update_tick() {
    if (!running_.load()) return;

    // Periodic (throttled) stats at DEBUG so peer-to-peer loss asymmetry is
    // visible over time without spamming INFO (see AGENTS.md #8).
    maybe_log_stats();

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

    // Application-layer keepalive (see KcpTunnel::maybe_send_keepalive).
    maybe_send_keepalive();

    // Re-arm is NOT done here: this method is driven by KCPProxyClient's
    // single shared 10ms tick timer (do_update_tick), which collapses N
    // per-session timer-heap entries into one. Fixed 10ms cadence -- we
    // intentionally do NOT use ikcp_check to sleep longer when idle (see
    // KCPSession::on_update_tick).
}

void KCPClientSession::do_udp_receive() {
    if (!udp_socket_ || !running_.load()) return;

    auto self = shared_from_this();
    // Connected datagram socket: async_receive (no endpoint) only delivers
    // packets from the pinned server endpoint.
    udp_socket_->async_receive(
        asio::buffer(udp_recv_buf_),
        asio::bind_executor(strand(),
            [this, self](const std::error_code& ec, size_t bytes) {
                if (ec) {
                    if (ec != asio::error::operation_aborted &&
                        running_.load()) {
                        // UDP sockets surface ICMP Port Unreachable as an error
                        // on the next receive: connection_refused on Linux/BSD,
                        // connection_reset (WSAECONNRESET) on Windows. This is
                        // the NORMAL signal that the server is down or
                        // restarting, not a fault, so it stays at DEBUG and
                        // re-arms immediately. (Windows reporting is disabled at
                        // the source in on_connect; this covers Linux and any
                        // other error the socket still surfaces.) The server
                        // classifies these identically -- the client used to log
                        // them at ERROR with no pacing at all.
                        if (ec == asio::error::connection_refused ||
                            ec == asio::error::connection_reset) {
                            LOG_DEBUG("kcp_client", "UDP ICMP port unreachable received (ignored)");
                            do_udp_receive();
                        } else {
                            LOG_ERROR("kcp_client", "UDP receive error: " + ec.message());
                            // Unknown errors can complete immediately and
                            // repeatedly with no external pacing, so an
                            // unbounded re-arm here is a busy spin plus an ERROR
                            // line per iteration. Re-arm through a short backoff
                            // instead, bounding the loop to ~100 attempts/s.
                            auto self2 = shared_from_this();
                            receive_backoff_timer_.expires_after(
                                std::chrono::milliseconds(10));
                            receive_backoff_timer_.async_wait(
                                [this, self2](const std::error_code& timer_ec) {
                                    if (!timer_ec) do_udp_receive();
                                });
                        }
                    }
                    return;
                }
                if (!running_.load()) return;
                // on_receive runs synchronously on the strand and consumes the
                // buffer (decrypt -> ikcp_input copies into KCP), so we can pass
                // a view into udp_recv_buf_ and re-arm afterwards -- no copy.
                if (bytes > 0) {
                    on_receive(byte_view(udp_recv_buf_.data(), bytes));
                }
                do_udp_receive();
            }));
}

void KCPClientSession::on_receive(byte_view packet) {
    if (!running_.load()) return;
    metrics_.udp_rx_packets.fetch_add(1, std::memory_order_relaxed);
    metrics_.udp_rx_bytes.fetch_add(packet.size(), std::memory_order_relaxed);
    std::error_code ec = crypto_->decrypt_into(packet, decrypt_buf_);
    if (ec == crypto_errors::errc::replay) {
        // Normal UDP reordering / duplicate: drop quietly.
        metrics_.replay_dropped.fetch_add(1, std::memory_order_relaxed);
        LOG_DEBUG("kcp_client", "replay/stale packet discarded (UDP reordering)");
        return;
    }
    if (ec) {
        metrics_.decrypt_errors.fetch_add(1, std::memory_order_relaxed);
        // Same packet-level noise class as KCPSession::on_receive: keep at
        // DEBUG, the decrypt_errors metric stays the INFO-visible signal.
        LOG_DEBUG("kcp_client", "UDP decrypt failed: " + ec.message());
        return;
    }
    touch_activity();
    // Authentic data from the server: this is the liveness clock for the
    // session-level timeout in on_update_tick. Only valid decrypted packets
    // advance it, so a dead/stale server cannot keep the tunnel alive.
    last_rx_us_.store(now_us());
    metrics_.packets_received.fetch_add(1, std::memory_order_relaxed);
    metrics_.bytes_received.fetch_add(packet.size(), std::memory_order_relaxed);
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
        metrics_.encrypt_errors.fetch_add(1, std::memory_order_relaxed);
        LOG_ERROR("kcp_client", "encrypt error: " + ec.message());
        return;
    }
    LOG_DEBUG("kcp_client", "encrypted -> " + std::to_string(send_buf->size()) +
             " bytes, sending UDP to " + server_addr_.address().to_string() + ":" +
             std::to_string(server_addr_.port()));

    metrics_.udp_tx_packets.fetch_add(1, std::memory_order_relaxed);
    metrics_.udp_tx_bytes.fetch_add(send_buf->size(), std::memory_order_relaxed);

    auto self = shared_from_this();
    udp_socket_->async_send(
        asio::buffer(*send_buf),
        asio::bind_executor(strand(),
            [this, self, send_buf](const std::error_code& ec, size_t bytes_sent) {
                if (ec && ec != asio::error::operation_aborted) {
                    LOG_ERROR("kcp_client", "UDP send error: " + ec.message());
                } else if (!ec) {
                    LOG_DEBUG("kcp_client", "UDP sent " + std::to_string(bytes_sent) + " bytes");
                }
            }));
}

} // namespace kcp_proxy
