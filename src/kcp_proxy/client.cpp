#include "kcp_proxy/client.hpp"
#include "kcp_proxy/address.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/socks5.hpp"
#include <asio/error.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <array>
#include <chrono>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#endif

namespace kcp_proxy {

namespace {
// Locale-independent socket error tag. std::error_code::message() returns the
// OS-localized string (GBK on zh-CN Windows), which turns to mojibake inside
// the UTF-8 GUI log; the numeric code is stable and documented everywhere.
std::string sock_err(const std::error_code& ec) {
    return "ec=" + std::to_string(ec.value());
}
} // namespace

KCPProxyClient::KCPProxyClient(asio::io_context& io, std::string server_host,
                                uint16_t server_port, std::string key,
                                std::string listen_host, uint16_t listen_port)
    : io_(io), server_host_(std::move(server_host)), server_port_(server_port),
      key_(std::move(key)), listen_host_(std::move(listen_host)),
      listen_port_(listen_port),
      tcp_acceptor_(io_), udp_resolver_(io_), traffic_timer_(io),
      update_tick_timer_(io) {
}

KCPProxyClient::~KCPProxyClient() {
    stop();
}

void KCPProxyClient::start() {
    do_resolve();
}

void KCPProxyClient::stop() {
    if (!running_) return;
    running_ = false;
    std::error_code ec;
    tcp_acceptor_.close(ec);
    update_tick_timer_.cancel(ec);
    LOG_INFO("client", "stopped");
    wipe_key();
}

void KCPProxyClient::wipe_key() {
    std::memset(key_.data(), 0, key_.size());
    key_.clear();
    key_.shrink_to_fit();
}

void KCPProxyClient::fail_startup(const std::string& message) {
    LOG_ERROR("client", message);
    start_failed_.store(true);
    io_.stop();
}

void KCPProxyClient::do_resolve() {
    auto self = shared_from_this();
    udp_resolver_.async_resolve(server_host_, std::to_string(server_port_),
        [this, self](const std::error_code& ec,
                     asio::ip::udp::resolver::results_type results) {
            if (ec) {
                fail_startup("resolve error: " + ec.message());
                return;
            }
            auto selected = results.begin();
            for (auto it = results.begin(); it != results.end(); ++it) {
                if (it->endpoint().address().is_v4()) {
                    selected = it;
                    break;
                }
            }
            server_endpoint_ = selected->endpoint();
            LOG_INFO("client", "resolved " + server_host_ + " -> " +
                     server_endpoint_.address().to_string());

            std::error_code listen_ec;
            const auto listen_addr = asio::ip::make_address(listen_host_, listen_ec);
            if (listen_ec) {
                fail_startup("invalid listen host '" + listen_host_ +
                             "': " + listen_ec.message());
                return;
            }
            if (!listen_addr.is_loopback()) {
                LOG_WARNING("client", "SOCKS5 listener has no authentication and is bound to a "
                            "non-loopback address (" + listen_host_ + ") - this is an unauthenticated "
                            "open proxy. Keep it on 127.0.0.1 unless you explicitly intend to expose it.");
            }

            asio::ip::tcp::endpoint listen_ep(listen_addr, listen_port_);
            tcp_acceptor_.open(listen_ep.protocol(), listen_ec);
            if (listen_ec) {
                fail_startup("acceptor open failed: " + listen_ec.message());
                return;
            }
            tcp_acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), listen_ec);
            if (listen_ec) {
                fail_startup("set reuse_address failed: " + listen_ec.message());
                return;
            }
            tcp_acceptor_.bind(listen_ep, listen_ec);
            if (listen_ec) {
                fail_startup("bind failed on " + listen_host_ + ":" +
                             std::to_string(listen_port_) + ": " + listen_ec.message());
                return;
            }
            tcp_acceptor_.listen(asio::socket_base::max_listen_connections, listen_ec);
            if (listen_ec) {
                fail_startup("listen failed: " + listen_ec.message());
                return;
            }

            running_ = true;
            LOG_INFO("client", "SOCKS5 proxy listening on " +
                     listen_host_ + ":" + std::to_string(listen_port_));

            start_traffic_reporter();
            // Start the shared KCP update tick (one 10ms timer for all
            // client sessions).
            do_update_tick(std::error_code{});
            do_accept();
        });
}

void KCPProxyClient::do_accept() {
    if (!running_) return;

    auto self = shared_from_this();
    tcp_acceptor_.async_accept(
        [this, self](const std::error_code& ec, asio::ip::tcp::socket socket) {
            if (ec) {
                if (running_) {
                    LOG_ERROR("client", "accept error: " + ec.message());
                    do_accept();
                }
                return;
            }
            handle_client_connection(std::move(socket));
            do_accept();
        });
}

void KCPProxyClient::do_update_tick(const std::error_code& ec) {
    if (ec || !running_.load()) return;

    // Re-arm FIRST so the 10ms cadence is independent of the snapshot and
    // dispatch work below. The timer chain also pins the client (via self)
    // in the io_context for as long as it runs.
    update_tick_timer_.expires_after(std::chrono::milliseconds(KCP_INTERVAL_MS));
    auto self = shared_from_this();
    update_tick_timer_.async_wait([this, self](const std::error_code& e) {
        do_update_tick(e);
    });

    // Snapshot + prune: copy weak refs out under the lock and drop entries
    // whose session object is already destroyed. This doubles as the only
    // deregistration mechanism, so no teardown path needs a cleanup hook.
    tick_snapshot_.clear();
    {
        std::unique_lock<std::shared_mutex> lock(tick_sessions_mutex_);
        tick_snapshot_.reserve(tick_sessions_.size());
        for (auto it = tick_sessions_.begin(); it != tick_sessions_.end();) {
            if (it->second.expired()) {
                it = tick_sessions_.erase(it);
            } else {
                tick_snapshot_.push_back(it->second);
                ++it;
            }
        }
    }

    // Dispatch without holding the lock. Each handler re-locks its weak_ptr
    // inside the session strand, so a session destroyed while queued is
    // skipped and never kept alive artificially by the tick.
    for (const auto& w : tick_snapshot_) {
        if (auto session = w.lock()) {
            std::weak_ptr<KCPClientSession> ws = session;
            asio::dispatch(session->strand(), [ws]() mutable {
                if (auto s = ws.lock()) s->on_update_tick();
            });
        }
    }
}

void KCPProxyClient::handle_client_connection(asio::ip::tcp::socket client_socket) {
    auto client = std::make_shared<asio::ip::tcp::socket>(std::move(client_socket));

    // Session-cap guard. The ticket is attached to the KCP session via
    // set_keepalive(), so the counter drops exactly when the session object
    // is destroyed — no matter which teardown path ran (handshake failure,
    // EOF, error, idle timeout).
    if (active_sessions_.fetch_add(1, std::memory_order_relaxed) >=
        MAX_CLIENT_SESSIONS) {
        active_sessions_.fetch_sub(1, std::memory_order_relaxed);
        LOG_WARNING("client", "connection limit reached (" +
                    std::to_string(MAX_CLIENT_SESSIONS) + "), refusing connection");
        std::error_code ignored;
        client->close(ignored);
        return;
    }
    auto session_ticket = std::shared_ptr<void>(
        &active_sessions_, [](std::atomic<size_t>* counter) {
            counter->fetch_sub(1, std::memory_order_relaxed);
        });

    // Non-throwing overload: a local app that connects and immediately resets
    // the connection can make remote_endpoint() fail. The throwing overload
    // would propagate through io.run() and kill the entire proxy (all tunnels)
    // over one racy connection; the endpoint is only used for logging anyway.
    std::error_code peer_ec;
    const auto peer_ep = client->remote_endpoint(peer_ec);
    if (peer_ec) {
        LOG_INFO("client", "new connection (peer endpoint unavailable: " +
                 peer_ec.message() + ")");
    } else {
        LOG_INFO("client", "new connection from " +
                 peer_ep.address().to_string() + ":" +
                 std::to_string(peer_ep.port()));
    }

    // Deadline timer for the entire SOCKS5 handshake.
    auto handshake_deadline = std::make_shared<asio::steady_timer>(io_);
    handshake_deadline->expires_after(std::chrono::seconds(SOCKS5_HANDSHAKE_TIMEOUT_SEC));
    auto handshake_cancelled = std::make_shared<std::atomic<bool>>(false);

    // Generate a fresh per-session salt. It is carried in cleartext on the
    // wire (see crypto.cpp) and used to derive a session-unique AEAD key so
    // counter/nonce values can never collide across sessions. The server
    // learns the salt from our first packet. NOTE: Android CPP_REMOTE must do
    // the same (generate + prepend salt, derive per-session key) for interop.
    auto crypto = std::make_shared<Crypto>(key_, NONCE_DIR_CLIENT,
                                            Crypto::generate_session_salt());
    auto session = std::make_shared<KCPClientSession>(
        io_, server_endpoint_, crypto);
    // Tie the session-cap ticket to the session's lifetime (see above).
    session->set_keepalive(session_ticket);
    // Register for the shared KCP update tick. Weak ref only: the entry
    // expires with the session object and is pruned by the next tick, so
    // every teardown path (handshake failure, EOF, idle timeout, stop) is
    // covered without an explicit deregistration hook.
    {
        std::unique_lock<std::shared_mutex> lock(tick_sessions_mutex_);
        tick_sessions_[session.get()] = session;
    }

    auto self = shared_from_this();

    // Cancel handshake on timeout.
    handshake_deadline->async_wait(
        [client, session, handshake_cancelled](const std::error_code& ec) {
            if (ec == asio::error::operation_aborted) return;
            if (handshake_cancelled->exchange(true)) return;
            LOG_WARNING("client", "SOCKS5 handshake timeout");
            std::error_code ignored;
            client->close(ignored);
            session->close();
        });

    LOG_INFO("client", "connecting KCP session to " +
             server_endpoint_.address().to_string() + ":" +
             std::to_string(server_endpoint_.port()));
    session->connect([this, self, client, session, handshake_deadline, handshake_cancelled](bool ok) {
        if (handshake_cancelled->load()) return;
        if (!ok) {
            LOG_ERROR("client", "KCP connect failed");
            abort_handshake(client, session, handshake_deadline, handshake_cancelled);
            return;
        }
        LOG_INFO("client", "KCP session connected, reading SOCKS5 greeting");

        auto greet_buf = std::make_shared<std::array<uint8_t, 2>>();
        asio::async_read(*client, asio::buffer(*greet_buf),
            [this, client, session, greet_buf, handshake_deadline, handshake_cancelled, self]
            (const std::error_code& ec, size_t) {
                if (handshake_cancelled->load()) return;
                if (ec) {
                    LOG_DEBUG("client", "read greet header error (" + sock_err(ec) + ")");
                    abort_handshake(client, session, handshake_deadline, handshake_cancelled);
                    return;
                }
                uint8_t ver = (*greet_buf)[0];
                uint8_t nmethods = (*greet_buf)[1];
                LOG_INFO("client", "SOCKS5 greeting ver=" + std::to_string(ver) +
                          " nmethods=" + std::to_string(nmethods));

                if (ver != SOCKS5_VERSION) {
                    LOG_ERROR("client", "bad SOCKS5 version: " + std::to_string(ver));
                    auto ver_resp = std::make_shared<std::array<uint8_t, 2>>();
                    (*ver_resp)[0] = 0x00;
                    (*ver_resp)[1] = SOCKS5_AUTH_NO_ACCEPTABLE;
                    asio::async_write(*client, asio::buffer(*ver_resp),
                        [this, client, session, ver_resp, handshake_deadline, handshake_cancelled](const std::error_code&, size_t) {
                            abort_handshake(client, session, handshake_deadline, handshake_cancelled);
                        });
                    return;
                }
                if (nmethods == 0) {
                    LOG_ERROR("client", "SOCKS5 greeting with no methods");
                    auto ver_resp = std::make_shared<std::array<uint8_t, 2>>();
                    (*ver_resp)[0] = SOCKS5_VERSION;
                    (*ver_resp)[1] = SOCKS5_AUTH_NO_ACCEPTABLE;
                    asio::async_write(*client, asio::buffer(*ver_resp),
                        [this, client, session, ver_resp, handshake_deadline, handshake_cancelled](const std::error_code&, size_t) {
                            abort_handshake(client, session, handshake_deadline, handshake_cancelled);
                        });
                    return;
                }

                auto methods_buf = std::make_shared<std::vector<uint8_t>>(nmethods);
                asio::async_read(*client, asio::buffer(*methods_buf),
                    [this, client, session, methods_buf, handshake_deadline, handshake_cancelled, self]
                    (const std::error_code& ec2, size_t) {
                        if (handshake_cancelled->load()) return;
                        if (ec2) {
                            LOG_DEBUG("client", "read methods error (" + sock_err(ec2) + ")");
                            abort_handshake(client, session, handshake_deadline, handshake_cancelled);
                            return;
                        }

                        LOG_INFO("client", "sending SOCKS5 greeting response (no auth)");
                        auto resp_buf = std::make_shared<std::array<uint8_t, 2>>();
                        (*resp_buf)[0] = SOCKS5_VERSION;
                        (*resp_buf)[1] = SOCKS5_AUTH_NONE;
                        asio::async_write(*client, asio::buffer(*resp_buf),
                            [this, client, session, resp_buf, handshake_deadline, handshake_cancelled, self]
                            (const std::error_code& ec3, size_t) {
                                if (handshake_cancelled->load()) return;
                                if (ec3) {
                                    LOG_DEBUG("client", "send greeting error (" + sock_err(ec3) + ")");
                                    abort_handshake(client, session, handshake_deadline, handshake_cancelled);
                                    return;
                                }
                                read_socks5_request(client, session, handshake_deadline, handshake_cancelled);
                            });
                    });
            });
    });
}

void KCPProxyClient::read_socks5_request(
    std::shared_ptr<asio::ip::tcp::socket> client_socket,
    std::shared_ptr<KCPClientSession> session,
    std::shared_ptr<asio::steady_timer> handshake_deadline,
    std::shared_ptr<std::atomic<bool>> handshake_cancelled) {

    auto header = std::make_shared<std::array<uint8_t, 4>>();
    auto self = shared_from_this();
    asio::async_read(*client_socket, asio::buffer(*header),
        [this, client_socket, session, header, handshake_deadline, handshake_cancelled, self](const std::error_code& ec, size_t) {
            if (handshake_cancelled->load()) return;
            if (ec) {
                LOG_DEBUG("client", "read request header error (" + sock_err(ec) + ")");
                abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
                return;
            }

            uint8_t version = (*header)[0];
            uint8_t cmd = (*header)[1];
            uint8_t atyp = (*header)[3];
            LOG_INFO("client", "SOCKS5 request ver=" + std::to_string(version) +
                      " cmd=" + std::to_string(cmd) +
                      " atyp=" + std::to_string(atyp));

            if (version != SOCKS5_VERSION) {
                LOG_ERROR("client", "bad version: " + std::to_string(version));
                abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
                return;
            }

            // For IPv4/IPv6, read address+port bytes; ATYP is prepended below
            // so we can call parse_address() uniformly. For domain, read only
            // the length byte first since the domain name is variable-length.
            size_t addr_bytes = 0;
            if (atyp == SOCKS5_ATYP_IPV4) addr_bytes = 6;
            else if (atyp == SOCKS5_ATYP_DOMAIN) addr_bytes = 1;
            else if (atyp == SOCKS5_ATYP_IPV6) addr_bytes = 18;
            else {
                LOG_ERROR("client", "bad atyp: " + std::to_string(atyp));
                abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
                return;
            }

            auto addr_buf = std::make_shared<std::vector<uint8_t>>(addr_bytes);
            asio::async_read(*client_socket, asio::buffer(*addr_buf),
                [this, client_socket, session, cmd, atyp, addr_buf, handshake_deadline, handshake_cancelled, self]
                (const std::error_code& ec2, size_t) {
                    if (handshake_cancelled->load()) return;
                    if (ec2) {
                        LOG_DEBUG("client", "read addr error (" + sock_err(ec2) + ")");
                        abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
                        return;
                    }

                    if (atyp == SOCKS5_ATYP_IPV4 || atyp == SOCKS5_ATYP_IPV6) {
                        size_t full_len = 1 + addr_buf->size();
                        std::vector<uint8_t> full(full_len);
                        full[0] = atyp;
                        std::memcpy(full.data() + 1, addr_buf->data(), addr_buf->size());
                        auto parsed = parse_address(full.data(), full.size());
                        handle_sync_request(client_socket, session, cmd, parsed.host, parsed.port,
                                            handshake_deadline, handshake_cancelled);
                    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
                        uint8_t dlen = (*addr_buf)[0];
                        if (dlen == 0) {
                            LOG_ERROR("client", "empty domain in SOCKS5 request");
                            abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
                            return;
                        }
                        auto domain_buf = std::make_shared<std::vector<uint8_t>>(dlen + 2);
                        asio::async_read(*client_socket, asio::buffer(*domain_buf),
                            [this, client_socket, session, cmd, domain_buf, dlen, handshake_deadline, handshake_cancelled, self]
                            (const std::error_code& ec3, size_t) {
                                if (handshake_cancelled->load()) return;
                                if (ec3) {
                                    LOG_DEBUG("client", "read domain error (" + sock_err(ec3) + ")");
                                    abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
                                    return;
                                }
                                std::string h(domain_buf->data(), domain_buf->data() + dlen);
                                uint16_t p = (static_cast<uint16_t>((*domain_buf)[dlen]) << 8) |
                                             (*domain_buf)[dlen + 1];
                                handle_sync_request(client_socket, session, cmd, h, p,
                                                    handshake_deadline, handshake_cancelled);
                            });
                    }
                });
        });
}

void KCPProxyClient::handle_sync_request(
    std::shared_ptr<asio::ip::tcp::socket> client_socket,
    std::shared_ptr<KCPClientSession> session,
    uint8_t cmd, const std::string& host, uint16_t port,
    std::shared_ptr<asio::steady_timer> handshake_deadline,
    std::shared_ptr<std::atomic<bool>> handshake_cancelled) {

    if (cmd != SOCKS5_CMD_CONNECT) {
        LOG_WARNING("client", "unsupported SOCKS5 cmd: " + std::to_string(cmd));
        // The deadline stays armed while the error reply is in flight: if the
        // local app stops reading, the reply write can stall forever, and the
        // deadline is what closes the session in that case.
        send_socks5_error(client_socket, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            [this, client_socket, session, handshake_deadline, handshake_cancelled] {
                abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
            });
        return;
    }

    auto handshake_start = std::chrono::steady_clock::now();
    LOG_INFO("client", "handle_sync_request: cmd=" + std::to_string(cmd) +
              " host=" + host + " port=" + std::to_string(port));

    std::vector<uint8_t> req_data;
    req_data.push_back(SOCKS5_VERSION);
    req_data.push_back(SOCKS5_CMD_CONNECT);
    req_data.push_back(0x00);
    auto addr = encode_address(host, port);
    req_data.insert(req_data.end(), addr.begin(), addr.end());

    LOG_INFO("client", "sending " + std::to_string(req_data.size()) +
              " bytes SOCKS5 request via KCP");
    session->send_data(byte_view(req_data.data(), req_data.size()));

    auto self = shared_from_this();
    auto reply_buf = std::make_shared<std::vector<uint8_t>>(SOCKS5_REPLY_BUF_SIZE);
    session->async_read_some(asio::buffer(*reply_buf),
        [this, client_socket, session, reply_buf, handshake_start, handshake_deadline, handshake_cancelled, self]
        (const std::error_code& ec, size_t bytes) {
            if (handshake_cancelled->load()) return;
            // Send the error reply, then release the session once the write
            // settles. The deadline stays armed during the reply write so a
            // stalled write (local app stopped reading) is still cleaned up.
            auto fail_with_reply = [this, client_socket, session, handshake_deadline,
                                    handshake_cancelled](uint8_t reply) {
                send_socks5_error(client_socket, reply,
                    [this, client_socket, session, handshake_deadline, handshake_cancelled] {
                        abort_handshake(client_socket, session, handshake_deadline, handshake_cancelled);
                    });
            };
            if (ec || bytes == 0) {
                LOG_ERROR("client", "recv SOCKS5 reply error: " + ec.message());
                fail_with_reply(SOCKS5_REPLY_GENERAL_FAILURE);
                return;
            }

            if (bytes < 2) {
                LOG_ERROR("client", "SOCKS5 reply too short");
                fail_with_reply(SOCKS5_REPLY_GENERAL_FAILURE);
                return;
            }

            uint8_t reply_code = (*reply_buf)[1];
            LOG_INFO("client", "recv SOCKS5 reply " + std::to_string(bytes) +
                      " bytes, reply_code=" + std::to_string(reply_code));

            if (reply_code != SOCKS5_REPLY_SUCCEEDED) {
                LOG_WARNING("client", "SOCKS5 reply failed: " + std::to_string(reply_code));
                fail_with_reply(reply_code);
                return;
            }

            // Handshake complete - cancel the deadline timer.
            handshake_cancelled->store(true);
            std::error_code ignored;
            handshake_deadline->cancel(ignored);

            session->mark_handshake_done();

            SOCKS5Response resp;
            resp.reply = SOCKS5_REPLY_SUCCEEDED;
            resp.host = "0.0.0.0";
            resp.port = 0;
            auto reply = std::make_shared<std::vector<uint8_t>>(resp.build());

            asio::async_write(*client_socket, asio::buffer(*reply),
                [this, client_socket, session, reply, handshake_start, self]
                (const std::error_code& ec2, size_t) {
                    if (ec2) {
                        LOG_ERROR("client", "send reply error: " + ec2.message());
                        return;
                    }
                    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - handshake_start).count();
                    LOG_INFO("client", "handshake complete in " +
                             std::to_string(elapsed_ms) + "ms, starting forwarding");
                    forward_client_to_kcp(client_socket, session);
                    forward_kcp_to_client(client_socket, session);
                });
        });
}

// Periodically report accumulated traffic as a parseable log line:
//   TRAFFIC tx=<bytes> rx=<bytes>
// The Electron GUI parses this line to display live traffic stats.
void KCPProxyClient::start_traffic_reporter() {
    auto self = shared_from_this();
    traffic_timer_.expires_after(std::chrono::seconds(2));
    traffic_timer_.async_wait([this, self](const std::error_code& ec) {
        if (ec || !running_) return;
        report_traffic();
        start_traffic_reporter();
    });
}

void KCPProxyClient::report_traffic() {
    const auto tx = tx_bytes_.load();
    const auto rx = rx_bytes_.load();
    LOG_INFO("traffic", "TRAFFIC tx=" + std::to_string(tx) +
             " rx=" + std::to_string(rx));
}

void KCPProxyClient::forward_client_to_kcp(
    std::shared_ptr<asio::ip::tcp::socket> client_socket,
    std::shared_ptr<KCPClientSession> session,
    std::shared_ptr<std::vector<uint8_t>> buf) {

    // Run the whole loop on the session strand so the KCP-state reads
    // (wait_send) are serialized with the strand handlers that mutate KCP.
    if (!session->strand().running_in_this_thread()) {
        auto self = shared_from_this();
        asio::dispatch(session->strand(), [this, self, client_socket, session, buf]() mutable {
            forward_client_to_kcp(client_socket, session, buf);
        });
        return;
    }
    // Reuse one read buffer for the whole connection (send_data() on the strand
    // copies into KCP before we re-arm, so the buffer is free again).
    if (!buf) buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);

    LOG_DEBUG("client", "forward_client_to_kcp: starting async_read_some");

    // Backpressure: if KCP's send queue is already past the threshold, the
    // network can't keep up with what we're feeding in. Pause TCP reads and
    // re-arm via a short delay so we don't tight-loop. This mirrors the
    // server's forward_tcp_to_kcp and prevents the KCP send buffer from
    // overflowing (which would otherwise tear down the session).
    if (session->wait_send() >= KCP_BACKPRESSURE_THRESHOLD) {
        LOG_DEBUG("client", "forward_client_to_kcp: backpressure (wait_send=" +
                  std::to_string(session->wait_send()) +
                  " >= threshold=" + std::to_string(KCP_BACKPRESSURE_THRESHOLD) +
                  "), delaying read");
        auto retry = std::make_shared<asio::steady_timer>(io_);
        retry->expires_after(std::chrono::milliseconds(KCP_INTERVAL_MS * 4));
        auto self = shared_from_this();
        retry->async_wait([self, client_socket, session, buf, retry](const std::error_code& ec) mutable {
            if (ec) return;
            if (session->is_connected()) {
                self->forward_client_to_kcp(client_socket, session, buf);
            }
        });
        return;
    }

    auto self = shared_from_this();
    client_socket->async_read_some(asio::buffer(*buf),
        asio::bind_executor(session->strand(),
        [this, self, client_socket, session, buf](const std::error_code& ec, size_t bytes) mutable {
            if (ec || bytes == 0) {
                if (ec == asio::error::eof) {
                    LOG_INFO("client", "client disconnected (EOF)");
                } else if (ec == asio::error::operation_aborted) {
                    LOG_DEBUG("client", "client read cancelled");
                } else if (ec) {
                    LOG_ERROR("client", "client read error: " + ec.message());
                }
                session->close();
                std::error_code ignored;
                client_socket->close(ignored);
                return;
            }

            tx_bytes_.fetch_add(bytes, std::memory_order_relaxed);
            LOG_DEBUG("client", "forward_client_to_kcp: read " + std::to_string(bytes) +
                     " bytes -> KCP");
            session->send_data(byte_view(buf->data(), bytes));
            forward_client_to_kcp(client_socket, session, buf);
        }));
}

void KCPProxyClient::forward_kcp_to_client(
    std::shared_ptr<asio::ip::tcp::socket> client_socket,
    std::shared_ptr<KCPClientSession> session,
    std::shared_ptr<std::vector<uint8_t>> buf) {

    if (!session->strand().running_in_this_thread()) {
        auto self = shared_from_this();
        asio::dispatch(session->strand(), [this, self, client_socket, session, buf]() mutable {
            forward_kcp_to_client(client_socket, session, buf);
        });
        return;
    }
    if (!buf) buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);

    LOG_DEBUG("client", "forward_kcp_to_client: starting async_read_some");
    session->async_read_some(asio::buffer(*buf),
        [this, client_socket, session, buf](const std::error_code& ec, size_t bytes) mutable {
            if (ec || bytes == 0) {
                if (ec == asio::error::eof) {
                    LOG_INFO("client", "KCP session closed (EOF)");
                } else if (ec == asio::error::operation_aborted) {
                    LOG_DEBUG("client", "KCP read cancelled");
                } else if (ec) {
                    LOG_ERROR("client", "KCP read error: " + ec.message());
                }
                std::error_code ignored;
                client_socket->close(ignored);
                session->close();
                return;
            }

            rx_bytes_.fetch_add(bytes, std::memory_order_relaxed);
            LOG_DEBUG("client", "forward_kcp_to_client: read " + std::to_string(bytes) +
                     " bytes -> client");
            asio::async_write(*client_socket,
                asio::buffer(buf->data(), bytes),
                asio::bind_executor(session->strand(),
                [this, client_socket, session, buf](const std::error_code& ec2, size_t written) mutable {
                    if (ec2) {
                        LOG_ERROR("client", "write to client error: " + ec2.message());
                        // Mirror the read-error path above: close BOTH sides.
                        // Closing only the session would leave the local TCP
                        // socket open while forward_client_to_kcp keeps reading
                        // into the dead session (send_data silently no-ops) —
                        // a black-hole connection for the local app.
                        std::error_code ignored;
                        client_socket->close(ignored);
                        session->close();
                        return;
                    }
                    LOG_DEBUG("client", "forward_kcp_to_client: write done (" +
                             std::to_string(written) + " bytes)");
                    forward_kcp_to_client(client_socket, session, buf);
                }));
        });
}

void KCPProxyClient::send_socks5_error(
    std::shared_ptr<asio::ip::tcp::socket> client_socket, uint8_t reply,
    std::function<void()> on_complete) {
    LOG_WARNING("client", "sending SOCKS5 error reply: " + std::to_string(reply));
    SOCKS5Response resp;
    resp.reply = reply;
    auto data = std::make_shared<std::vector<uint8_t>>(resp.build());
    asio::async_write(*client_socket, asio::buffer(*data),
        [client_socket, data, on_complete = std::move(on_complete)](const std::error_code&, size_t) {
            // Best-effort reply: whatever the write outcome, the caller's
            // cleanup callback must run so the session is always released.
            if (on_complete) on_complete();
        });
}

void KCPProxyClient::abort_handshake(
    std::shared_ptr<asio::ip::tcp::socket> client_socket,
    std::shared_ptr<KCPClientSession> session,
    std::shared_ptr<asio::steady_timer> handshake_deadline,
    std::shared_ptr<std::atomic<bool>> handshake_cancelled) {
    // Idempotent: several failure paths can converge here (e.g. the deadline
    // fired while an error reply was still being written). The loser of the
    // cancelled-flag race returns immediately. Mark cancelled first so
    // in-flight handlers bail out, then cancel the deadline, then close BOTH
    // ends — the KCP session owns the UDP socket and update timer, so closing
    // it releases everything the handshake allocated.
    if (handshake_cancelled->exchange(true)) return;
    std::error_code ignored;
    handshake_deadline->cancel(ignored);
    if (client_socket) client_socket->close(ignored);
    if (session) session->close();
}

} // namespace kcp_proxy
