#include "kcp_proxy/kcp_client_session.hpp"
#include "kcp_proxy/buffer_pool.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"

#include <fmt/format.h>
#include "kcp_proxy/socket_buffer.hpp"
#include "kcp_proxy/time_util.hpp"
#if defined(_WIN32)
#include <winsock2.h>
#include <mswsock.h>
// SIO_UDP_CONNRESET and the disable_udp_connreset() wrapper live in
// socket_buffer.hpp, which the server includes too.
#endif
#if defined(__linux__)
// sendmmsg / MSG_DONTWAIT / MSG_NOSIGNAL for the batched wire send.
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif
#include <algorithm>
#include <cstring>
#include <mutex>
#include <utility>

namespace kcp_proxy {

namespace {

// Process-wide throttles for the per-datagram UDP diagnostics. The client
// creates one socket (and one KcpWrapper/logger call site) per local TCP
// connection, so a per-session throttle cannot bound the aggregate: 512
// sessions in a persistently failing state would still emit 512 * 100 lines/s.
// "UDP receive error" in particular is re-driven by the 10ms backoff, exactly
// like the server's -- bounded retries, unbounded logging.
LogThrottle& client_udp_recv_error_log() {
    static LogThrottle throttle;
    return throttle;
}

LogThrottle& client_udp_send_error_log() {
    static LogThrottle throttle;
    return throttle;
}

} // namespace

KCPClientSession::KCPClientSession(asio::io_context& io,
                                   asio::ip::udp::endpoint server_addr,
                                   std::shared_ptr<Crypto> crypto,
                                   uint32_t conv,
                                   const FecConfig& fec)
    : KcpTunnel(io, conv, std::move(crypto), "kcp_client", "", fec),
      server_addr_(std::move(server_addr)),
      connect_timer_(strand()),
      receive_backoff_timer_(strand()) {
    last_rx_us_.store(now_us());
    LOG_DEBUG("kcp_client", fmt::format("created conv={} server={}:{}", conv,
                                        server_addr_.address().to_string(), server_addr_.port()));
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
        // Without this, a server that is down or restarting turns every HELLO
        // retransmit and keepalive into an ERROR log line plus an unthrottled
        // re-arm.
        const int wsa_rc = disable_udp_connreset(*udp_socket_);
        LOG_DEBUG("kcp_client", fmt::format("SIO_UDP_CONNRESET disabled (wsa_rc={})", wsa_rc));
#endif

        // Raise the kernel UDP send/receive buffers and report any silent clamp.
        //
        // Once per process: the client creates one UDP socket per local TCP
        // connection, so logging this per session would spam an unbounded number
        // of identical lines about a value that cannot change while the process
        // runs.
        apply_udp_buffer_sizes(*udp_socket_, "kcp_client", /*report_once=*/true);

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
                LOG_INFO("kcp_client",
                         fmt::format("KCP handshake confirmed with {}:{}{}",
                                     server_addr_.address().to_string(), server_addr_.port(),
                                     ack_v2 ? " (V2, half-close enabled)" : ""));
                if (h) h(true);
            });

        connect_timer_.expires_after(std::chrono::seconds(KCP_HANDSHAKE_TIMEOUT_SEC));
        connect_timer_.async_wait([this, self, completion](const std::error_code& ec) mutable {
            if (ec == asio::error::operation_aborted) return;
            if (!connect_pending_.exchange(false)) return;
            LOG_ERROR("kcp_client",
                      fmt::format("KCP handshake timeout after {}s", KCP_HANDSHAKE_TIMEOUT_SEC));
            on_close();
            auto h = std::move(*completion);
            *completion = nullptr;
            if (h) h(false);
        });

        send_connect_hello();

        LOG_INFO("kcp_client",
                 fmt::format("KCP handshake started with {}:{}", server_addr_.address().to_string(),
                             server_addr_.port()));
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
        // Throw rather than on_close()+return: only on_connect's catch block
        // delivers the failure to the connect completion handler. Returning
        // silently here would leave the SOCKS5 handshake hanging until its
        // 30s deadline, because on_close() disarms every path (ACK read,
        // connect timer) that could complete it.
        throw std::runtime_error(fmt::format("KCP handshake send failed, ret={}", send_ret));
    }
    flush_cycle(now_kcp_ms());
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
        flush_cycle(now_kcp_ms());
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

    // Drop a parked client->kcp loop before the pending read is completed below:
    // its hook holds the local TCP socket and the read buffer, and must never be
    // able to restart the loop on a closed session. The local socket is closed
    // by forward_kcp_to_client's aborted-read path.
    unpark_write();

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
            LOG_WARNING("kcp_client",
                        fmt::format("idle timeout: no valid data from server for {}s, "
                                    "closing session",
                                    idle_us / 1000000));
            on_close();
            return;
        }
    }

    // Idle skip, same contract as KCPSession::on_update_tick: wait_send()
    // covers segments in flight, needs_flush_ covers the ACKs and probes only
    // Input can queue, so skipping a fully idle session changes no wire byte.
    if (kcp_.wait_send() > 0 || needs_flush_.exchange(false, std::memory_order_relaxed)) {
        flush_cycle(now_kcp_ms());
    }
    if (pending_read_handler_) try_fulfill_read();

    // Safety net for a parked client->kcp write loop (see
    // KcpTunnel::maybe_resume_write); the receive path normally resumes it
    // immediately when an ACK frees window space.
    maybe_resume_write();

    // Application-layer keepalive (see KcpTunnel::maybe_send_keepalive).
    maybe_send_keepalive();

    // A FIN refused by a full send window is re-driven as the window drains
    // (see KcpTunnel::retry_pending_fin).
    retry_pending_fin();

    // Re-arm is NOT done here: this method is driven by KCPProxyClient's
    // single shared 10ms tick timer (do_update_tick), which collapses N
    // per-session timer-heap entries into one. The cadence stays 10ms; fully
    // idle sessions skip only the update/flush pass (see above, and
    // KCPSession::on_update_tick for why ikcp_check is no help either).
}

void KCPClientSession::do_udp_receive() {
    if (!udp_socket_ || !running_.load()) return;

    auto self = shared_from_this();
    // Connected datagram socket: async_receive (no endpoint) only delivers
    // packets from the pinned server endpoint.
    udp_socket_->async_receive(
        asio::buffer(udp_recv_buf_),
        asio::bind_executor(strand(), [this, self](const std::error_code& ec, size_t bytes) {
            if (ec) {
                if (ec != asio::error::operation_aborted && running_.load()) {
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
                        uint32_t suppressed = 0;
                        if (client_udp_recv_error_log().should_log(suppressed)) {
                            LOG_ERROR("kcp_client",
                                      fmt::format("UDP receive error: {}{}", ec.message(),
                                                  throttle_suffix(suppressed)));
                        }
                        // Unknown errors can complete immediately and
                        // repeatedly with no external pacing, so an
                        // unbounded re-arm here is a busy spin plus an ERROR
                        // line per iteration. Re-arm through a short backoff
                        // instead, bounding the loop to ~100 attempts/s.
                        auto self2 = shared_from_this();
                        receive_backoff_timer_.expires_after(std::chrono::milliseconds(10));
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
    // Plaintext bytes, matching bytes_sent (KCP payload in on_send) -- the
    // encrypted datagram size is already tracked separately as udp_rx_bytes.
    metrics_.bytes_received.fetch_add(decrypt_buf_.size(), std::memory_order_relaxed);
    LOG_DEBUG("kcp_client", fmt::format("UDP recv {} encrypted -> {} decrypted", packet.size(),
                                        decrypt_buf_.size()));
    int input_ret = feed_kcp_input(decrypt_buf_.data(), decrypt_buf_.size());
    if (input_ret < 0) {
        // Throttled for the same reason as the server side: the server holds
        // the session key too, so a hostile (or merely corrupted) datagram can
        // reach this once per packet -- see log_kcp_input_rejected.
        //
        // Do NOT return: with FEC enabled the decoder may have rebuilt other
        // shards of the set and queued them into KCP even when the native
        // shard was refused, and the drain/resume below is what makes them
        // visible.
        log_kcp_input_rejected("kcp_client", std::string_view(), input_ret,
                               decrypt_buf_.size());
    } else {
        LOG_DEBUG("kcp_client", fmt::format("kcp input ok, peek={}", kcp_.peek_size()));
    }
    try_fulfill_read();
    // ACKs consumed by ikcp_input() are what free send-window space; resuming a
    // parked client->kcp loop here keeps the upload window full instead of
    // refilling it on the 10ms tick (see KcpTunnel::park_write).
    maybe_resume_write();
}

bool KCPClientSession::encrypt_for_wire(byte_view data, std::vector<uint8_t>& out) {
    // Encrypt straight into a pooled buffer that backs the UDP send: a
    // steady-state packet costs one fused allocation (the holder), the buffer
    // itself recycles when the send completes.
    out = datagram_pool().acquire();
    std::error_code ec = crypto_->encrypt_into(data, out);
    if (!ec) return true;
    metrics_.encrypt_errors.fetch_add(1, std::memory_order_relaxed);
    datagram_pool().release(std::move(out));
    // An undeliverable segment is a permanent hole in the byte stream, so
    // the session must be torn down rather than left to hang until the
    // idle timeout (e.g. once the nonce counter reaches MAX_COUNTER every
    // encrypt refuses). The shutdown is DEFERRED via post(): this callback
    // runs from inside a kcp flush -- including on_close()'s best-effort
    // final flush, whose own failing segments would re-enter shut_down()
    // and recurse if it ran synchronously. The latched flag keeps one
    // failure to one log line + one teardown request.
    if (!encrypt_teardown_.exchange(true)) {
        LOG_ERROR("kcp_client", "encrypt error (" + ec.message() + "), closing session");
        // shared_from_this() yields shared_ptr<KcpTunnel>; the posted
        // teardown needs the derived type so the protected shut_down()
        // stays accessible through the object expression.
        auto self = std::static_pointer_cast<KCPClientSession>(shared_from_this());
        asio::post(strand(), [self]() {
            self->shut_down();
        });
    }
    return false;
}

void KCPClientSession::handle_kcp_output(byte_view data) {
    if (!udp_socket_ || !running_.load()) {
        LOG_DEBUG("kcp_client", "handle_kcp_output - session not running");
        return;
    }
    LOG_DEBUG("kcp_client", fmt::format("handle_kcp_output {} bytes -> encrypt", data.size()));
    std::vector<uint8_t> encrypted;
    if (!encrypt_for_wire(data, encrypted)) return;
    LOG_DEBUG("kcp_client",
              fmt::format("encrypted -> {} bytes, sending UDP to {}:{}", encrypted.size(),
                          server_addr_.address().to_string(), server_addr_.port()));
    metrics_.udp_tx_packets.fetch_add(1, std::memory_order_relaxed);
    metrics_.udp_tx_bytes.fetch_add(encrypted.size(), std::memory_order_relaxed);
    start_async_send(std::move(encrypted));
}

void KCPClientSession::handle_kcp_output_batch(const std::vector<std::vector<uint8_t>>& datagrams,
                                               size_t count) {
    if (!udp_socket_ || !running_.load()) {
        LOG_DEBUG(
            "kcp_client",
            fmt::format("handle_kcp_output_batch - not running, dropping {} datagrams", count));
        return;
    }
    LOG_DEBUG("kcp_client", fmt::format("handle_kcp_output_batch {} datagrams -> encrypt", count));
    std::vector<std::vector<uint8_t>> encrypted;
    encrypted.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> buf;
        if (!encrypt_for_wire(datagrams[i], buf)) return; // teardown already posted
        metrics_.udp_tx_packets.fetch_add(1, std::memory_order_relaxed);
        metrics_.udp_tx_bytes.fetch_add(buf.size(), std::memory_order_relaxed);
        encrypted.push_back(std::move(buf));
    }
    send_batch_wire(std::move(encrypted));
}

void KCPClientSession::send_batch_wire(std::vector<std::vector<uint8_t>> batch) {
    if (!udp_socket_ || !running_.load()) return;
#if defined(__linux__)
    if (batch.size() > 1 && udp_socket_->is_open()) {
        // One flush cycle can carry a window's worth of segments (plus FEC
        // parity); walk it in UDP_BATCH_MAX-sized sendmmsg chunks. MSG_DONTWAIT
        // keeps the strand non-blocking: whatever the kernel queue refuses
        // right now falls back to the async path below, which parks on socket
        // writability instead of busy-looping.
        int fd = udp_socket_->native_handle();
        size_t idx = 0;
        bool fast_path_ok = true;
        while (idx < batch.size()) {
            const size_t n = std::min(batch.size() - idx, UDP_BATCH_MAX);
            struct mmsghdr msgs[UDP_BATCH_MAX];
            struct iovec iov[UDP_BATCH_MAX];
            for (size_t i = 0; i < n; ++i) {
                iov[i].iov_base = batch[idx + i].data();
                iov[i].iov_len = batch[idx + i].size();
                std::memset(&msgs[i], 0, sizeof(msgs[i]));
                // Connected socket: no msg_name, the kernel uses the peer.
                msgs[i].msg_hdr.msg_iov = &iov[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
            }
            ssize_t sent = ::sendmmsg(fd, msgs, n, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                sent = 0; // nothing accepted this round: remainder goes async
            }
            if (sent < 0) {
                // Unexpected failure (e.g. EMSGSIZE): let the per-datagram async
                // path surface the real error completion for the remainder.
                fast_path_ok = false;
                break;
            }
            for (size_t i = 0; i < static_cast<size_t>(sent); ++i) {
                datagram_pool().release(std::move(batch[idx + i]));
            }
            idx += static_cast<size_t>(sent);
            if (static_cast<size_t>(sent) < n) break;
        }
        LOG_DEBUG("kcp_client", fmt::format("sendmmsg: {} of {} datagrams accepted by the kernel",
                                            idx, batch.size()));
        // Whatever the kernel queue refused (or a failed fast path left over)
        // goes through the per-datagram async path, which parks on writability.
        for (size_t i = idx; i < batch.size(); ++i)
            start_async_send(std::move(batch[i]));
        return;
    }
#endif
    for (auto& d : batch)
        start_async_send(std::move(d));
}

void KCPClientSession::start_async_send(std::vector<uint8_t> data) {
    if (!udp_socket_ || !running_.load()) return;
    auto buf = make_pooled_send(std::move(data));
    auto self = shared_from_this();
    // NOTE: copy-capture, not a move init-capture. `asio::buffer(*buf)`
    // and the lambda below are arguments of the same call, and MSVC evaluates
    // them right-to-left: a `buf = std::move(buf)` capture empties the
    // shared_ptr before buffer() dereferences it (SIGSEGV, caught by ASAN). The
    // holder is refcounted anyway, so a copy costs one atomic increment.
    udp_socket_->async_send(
        asio::buffer(*buf),
        asio::bind_executor(
            strand(), [this, self, buf](const std::error_code& ec, size_t bytes_sent) {
                if (ec && ec != asio::error::operation_aborted) {
                    // One completion per datagram: an unthrottled line here is
                    // one line per packet whenever the path is failing.
                    uint32_t suppressed = 0;
                    if (client_udp_send_error_log().should_log(suppressed)) {
                        std::string line = fmt::format("UDP send error: {}", ec.message());
                        line += throttle_suffix(suppressed);
                        LOG_ERROR("kcp_client", line);
                    }
                } else if (!ec) {
                    LOG_DEBUG("kcp_client", fmt::format("UDP sent {} bytes", bytes_sent));
                }
            }));
}

} // namespace kcp_proxy
