#include "kcp_proxy/server.hpp"
#include "kcp_proxy/address.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/config.hpp"
#include "kcp_proxy/logger.hpp"
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/connect.hpp>
#include <fmt/format.h>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace kcp_proxy {

static std::string log_level_name() {
    switch (current_log_level()) {
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Info:    return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error:   return "ERROR";
    }
    return "INFO";
}

KCPServer::KCPServer(asio::io_context& io, uint16_t port, std::string key,
                     std::string host)
    : io_(io), port_(port), host_(std::move(host)),
      key_(key),
      udp_socket_(io_),
      cleanup_timer_(io_),
      update_tick_timer_(io_) {}

KCPServer::~KCPServer() {
    stop();
}

void KCPServer::wipe_key() {
    std::memset(key_.data(), 0, key_.size());
    key_.clear();
    key_.shrink_to_fit();
}

void KCPServer::start() {
    std::error_code ec;
    const auto listen_addr = asio::ip::make_address(host_, ec);
    if (ec) {
        throw std::runtime_error("invalid listen host '" + host_ + "': " + ec.message());
    }

    asio::ip::udp::endpoint listen_ep(listen_addr, port_);
    udp_socket_.open(listen_ep.protocol(), ec);
    if (ec) {
        throw std::runtime_error("failed to open UDP socket: " + ec.message());
    }
    udp_socket_.bind(listen_ep, ec);
    if (ec) {
        throw std::runtime_error("failed to bind UDP socket on " + host_ + ":" +
                                 std::to_string(port_) + ": " + ec.message());
    }

    running_ = true;

    cleanup_timer_.expires_after(std::chrono::seconds(30));
    auto self = shared_from_this();
    cleanup_timer_.async_wait([this, self](const std::error_code& ec) {
        do_cleanup(ec);
    });

    // Start the shared KCP update tick (10ms, one timer for all sessions).
    do_update_tick(std::error_code{});

    LOG_INFO("server", "listening on " + host_ + ":" + std::to_string(port_));
    LOG_INFO("server", "diagnostics udp_bind=" + host_ +
             " udp_port=" + std::to_string(port_) +
             " crypto=AES-128-GCM/HKDF-SHA256" +
             " socks5_mode=CONNECT_ONLY udp_associate=unsupported" +
             " log_level=" + log_level_name());
    LOG_INFO("server", "KCP config conv=1 mtu=" + std::to_string(KCP_MTU) +
             " nodelay=1 interval=" + std::to_string(KCP_INTERVAL_MS) +
             " resend=5 nc=1 sndWnd=" + std::to_string(KCP_SNDWND) +
             " rcvWnd=" + std::to_string(KCP_RCVWND) +
             " timeout=" + std::to_string(KCP_TIMEOUT_SEC) + "s");

    do_receive();
}

void KCPServer::stop() {
    if (!running_) return;
    running_ = false;

    std::error_code ignored;
    udp_socket_.close(ignored);
    cleanup_timer_.cancel(ignored);
    update_tick_timer_.cancel(ignored);

    std::unordered_map<std::string, std::shared_ptr<KCPSession>> drained_sessions;
    std::unordered_map<std::string, ClientConnection> drained_conns;
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        drained_sessions.swap(sessions_);
        drained_conns.swap(connections_);
    }
    for (auto& [sid, session] : drained_sessions) {
        session->stop();
    }
    for (auto& [sid, conn] : drained_conns) {
        if (conn.tcp_socket && conn.tcp_socket->is_open()) {
            conn.tcp_socket->close(ignored);
        }
    }

    LOG_INFO("server", "stopped");

    wipe_key();
}

void KCPServer::do_receive() {
    if (!running_) return;

    recv_endpoint_ = asio::ip::udp::endpoint();
    auto self = shared_from_this();

    udp_socket_.async_receive_from(
        asio::buffer(udp_recv_buf_), recv_endpoint_,
        [this, self](const std::error_code& ec, size_t bytes) {
            handle_receive(ec, bytes);
        });
}

void KCPServer::handle_receive(const std::error_code& ec, size_t bytes_transferred) {
    if (ec) {
        if (running_ && ec != asio::error::operation_aborted) {
            // UDP sockets surface ICMP Port Unreachable as an error on the next
            // receive: connection_refused on Linux/BSD, connection_reset
            // (WSAECONNRESET) on Windows. This is normal after a peer closes
            // its socket and is not fatal for the server. Just log and continue.
            if (ec == asio::error::connection_refused ||
                ec == asio::error::connection_reset) {
                LOG_DEBUG("server", "UDP ICMP port unreachable received (ignored)");
            } else {
                LOG_ERROR("server", "UDP receive error: " + ec.message());
            }
            do_receive();
        }
        return;
    }
    if (bytes_transferred == 0) {
        do_receive();
        return;
    }

    auto endpoint = recv_endpoint_;
    byte_view data(udp_recv_buf_.data(), bytes_transferred);

    LOG_DEBUG("server", "UDP recv " + std::to_string(bytes_transferred) +
              " bytes from " + endpoint.address().to_string() + ":" +
              std::to_string(endpoint.port()));

    bool already_consumed = false;
    auto session = get_or_create_session(endpoint, data, already_consumed);
    if (session) {
        if (!already_consumed) {
            LOG_DEBUG("server", session->session_id() + ": dispatching encrypted packet to session");
            // One strand dispatch: decrypt -> ikcp_input -> try_fulfill_read, then
            // run the session-driven logic (handle_kcp_data) in the SAME dispatch
            // so its KCP-state reads (peek_size/wait_send) are serialized with
            // the strand handlers that mutate KCP.
            session->receive_data(data, [this, session, endpoint]() {
                handle_kcp_data(session, endpoint);
            });
        } else {
            LOG_DEBUG("server", session->session_id() + ": first packet already consumed (injected)");
            asio::dispatch(session->strand(), [this, session, endpoint]() {
                handle_kcp_data(session, endpoint);
            });
        }
    } else {
        LOG_WARNING("server", "packet dropped from " +
                    endpoint.address().to_string() + ":" +
                    std::to_string(endpoint.port()) + " (no session created)");
    }
    // If session is null, we silently drop -- auth failed or session cap reached.

    do_receive();
}

std::shared_ptr<KCPSession> KCPServer::get_or_create_session(
    const asio::ip::udp::endpoint& addr, byte_view encrypted_packet,
    bool& already_consumed) {
    already_consumed = false;
    std::string sid = addr.address().to_string() + ":" +
                      std::to_string(addr.port());

    // Fast path: an existing live session. Read-only lookup, so concurrent
    // readers (one per incoming UDP datagram) proceed in parallel.
    // `salt_matches` rejects a NEW session that collided on the same source
    // endpoint (client reconnect reusing an ephemeral port): its salt differs,
    // so we must replace the old session rather than black-hole it.
    {
        std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
        auto it = sessions_.find(sid);
        if (it != sessions_.end() &&
            it->second && it->second->is_alive() && it->second->is_running() &&
            it->second->salt_matches(encrypted_packet)) {
            return it->second;
        }
    }

    // Slow path: session missing or stale. Take the write lock to mutate.
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        auto it = sessions_.find(sid);
        if (it != sessions_.end()) {
            // Reuse the existing session only if it is alive AND speaking the
            // same session salt. Otherwise (dead/stopped, or a new session
            // colliding after a reconnect) close it and let a new one be
            // created below.
            if (it->second && it->second->is_alive() && it->second->is_running() &&
                it->second->salt_matches(encrypted_packet)) {
                return it->second;
            }
            // Session is dead/stopped or salt-mismatched - clean it up.
            LOG_DEBUG("server", sid + ": stale or salt-mismatched session found, replacing");
            if (it->second) {
                it->second->stop();
            }
            sessions_.erase(it);
            // Close the replaced session's upstream TCP socket too (do_cleanup
            // does the same for idle-reaped sessions). Erasing the connections_
            // entry alone would orphan the socket: the forward_tcp_to_kcp loop
            // holds its own shared_ptr to it, and since close_connection can no
            // longer find the entry, the target connection would stay open
            // until the remote end closed it on its own. Closing here also
            // aborts the old session's pending reads/writes on that socket, so
            // a mid-connect old session can never re-insert connections_[sid]
            // after the new session took over the endpoint.
            auto conn_it = connections_.find(sid);
            if (conn_it != connections_.end()) {
                if (conn_it->second.tcp_socket && conn_it->second.tcp_socket->is_open()) {
                    std::error_code close_ec;
                    conn_it->second.tcp_socket->close(close_ec);
                }
                connections_.erase(conn_it);
            }
        }
        if (sessions_.size() >= MAX_CONCURRENT_SESSIONS) {
            LOG_WARNING("server", fmt::format("session cap reached ({}) dropping packet from {}",
                        MAX_CONCURRENT_SESSIONS, sid));
            return nullptr;
        }
    }

    // Authenticate BEFORE allocating a per-session KCP+strand+timer.
    // Use the same replay-protected Crypto object that will be installed into
    // the session, so the first accepted packet seeds the replay window.
    //
    // Global auth-throttle: an unknown source only ever costs us a full AEAD
    // decrypt here, so enforce a per-second budget before doing that work.
    // Without it, a garbage UDP flood (even from spoofed sources) could pin
    // the CPU on decrypt attempts. The server is single-threaded, so these
    // fields are only touched on the I/O thread.
    {
        const auto now = std::chrono::steady_clock::now();
        if (now - auth_window_start_ >= std::chrono::seconds(1)) {
            auth_attempts_window_ = 0;
            auth_window_start_ = now;
        }
        if (auth_attempts_window_ >= MAX_AUTH_ATTEMPTS_PER_SEC) {
            LOG_WARNING("server", "auth attempt rate limit reached, dropping packet from " + sid);
            return nullptr;
        }
        ++auth_attempts_window_;
    }

    LOG_DEBUG("server", sid + ": attempting auth decrypt on " +
             std::to_string(encrypted_packet.size()) + " bytes");
    std::vector<uint8_t> decrypted;
    // server_mode=true: the first decrypted packet of a brand-new session seeds
    // the replay window (handled inside Crypto::decrypt) and is never rejected
    // as a replay. The client side always enforces the window from packet #1.
    auto session_crypto = std::make_shared<Crypto>(key_, NONCE_DIR_SERVER, byte_view{}, true);
    try {
        decrypted = session_crypto->decrypt(encrypted_packet);
        LOG_DEBUG("server", sid + ": auth OK, decrypted " + std::to_string(decrypted.size()) + " bytes");
    } catch (const std::exception& e) {
        LOG_WARNING("server", "FAIL_STAGE=DECRYPT_FAILED ERROR=" + std::string(e.what()) +
                    " CLIENT_ENDPOINT=" + sid + " TARGET=-");
        return nullptr;
    }

    std::shared_ptr<KCPSession> session;
    size_t total_sessions = 0;
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        // Re-check under lock: another packet from this endpoint may have
        // beaten us here in a different I/O thread.
        auto it = sessions_.find(sid);
        if (it != sessions_.end()) {
            return it->second;
        }
        if (sessions_.size() >= MAX_CONCURRENT_SESSIONS) {
            LOG_WARNING("server", "session cap reached (" +
                        std::to_string(MAX_CONCURRENT_SESSIONS) +
                        "), dropping packet from " + sid);
            return nullptr;
        }
        // Duplicate-salt rejection: two sessions sharing a salt derive the same
        // per-session AEAD key. Because the nonce counter also starts from the
        // salt, a malicious client could force a same-key session against a live
        // target by simply reusing its salt, and AES-GCM nonce/IV reuse would be
        // catastrophic. Refuse to create a session whose salt a live session
        // already claims. (The first slow-path block above already erased any
        // dead or salt-mismatched session for this endpoint, so a client
        // reconnecting on the same source port with a fresh salt is unaffected.)
        for (const auto& [other_sid, other] : sessions_) {
            if (other_sid == sid) continue;
            if (other && other->is_alive() && other->is_running() &&
                other->salt_matches(encrypted_packet)) {
                LOG_WARNING("server", fmt::format(
                    "duplicate session salt rejected: {} collides with live session {}",
                    sid, other_sid));
                return nullptr;
            }
        }
        session = std::make_shared<KCPSession>(io_, 1, addr, std::move(session_crypto), sid);
        sessions_[sid] = session;
        total_sessions = sessions_.size();
    }

    auto self = shared_from_this();
    session->set_send_callback([self, addr](std::vector<uint8_t> data) {
        self->send_to_client(addr, std::move(data));
    });

    session->start();
    // Feed the already-decrypted bytes straight into ikcp.
    session->inject_decrypted(std::move(decrypted));
    already_consumed = true;

    LOG_INFO("server", "new session: " + sid + " (total: " +
             std::to_string(total_sessions) + ")");
    return session;
}

void KCPServer::handle_kcp_data(std::shared_ptr<KCPSession> session,
                                 const asio::ip::udp::endpoint& /*sender*/) {
    // SAFETY: This function reads KCP state (peek_size, wait_send) which must be
    // serialized with the strand handlers that mutate KCP. All callers must ensure
    // we are on the session's strand. If not, dispatch to it and return.
    // This pattern makes the function safe regardless of how it's invoked.
    if (!session->strand().running_in_this_thread()) {
        auto self = shared_from_this();
        asio::dispatch(session->strand(), [this, self, session]() {
            handle_kcp_data(session, {});
        });
        return;
    }

    LOG_DEBUG("server", session->session_id() + ": handle_kcp_data, protocol_handshake_done=" +
              std::to_string(session->is_protocol_handshake_done()) +
              " socks5_handshake_done=" +
              std::to_string(session->is_handshake_done()) +
              " forward_pending=" + std::to_string(session->is_forward_read_pending()) +
              " socks5_pending=" + std::to_string(session->is_socks5_read_pending()) +
              " peek=" + std::to_string(session->peek_size()) +
              " wait_send=" + std::to_string(session->wait_send()));
    if (session->peek_size() <= 0) {
        LOG_DEBUG("server", session->session_id() + ": no complete KCP payload to read, skipping");
        return;
    }
    if (!session->is_protocol_handshake_done()) {
        if (session->is_socks5_read_pending()) {
            LOG_DEBUG("server", session->session_id() + ": protocol handshake read already pending");
            return;
        }
        handle_protocol_handshake(session);
        return;
    }
    if (session->is_handshake_done()) {
        // forward_kcp_to_tcp claims the loop itself (at most one kcp->tcp read
        // must be outstanding at a time), so it is idempotent and safe to call
        // on every packet; a call that finds a loop already running is a no-op.
        forward_kcp_to_tcp(session);
        return;
    }
    if (session->is_socks5_read_pending() || session->is_connect_pending()) {
        LOG_DEBUG("server", session->session_id() +
                  ": SOCKS5 read or upstream connect already pending, skipping");
        return;
    }
    LOG_DEBUG("server", session->session_id() + ": starting SOCKS5 request read");
    handle_socks5_request(session);
}

void KCPServer::handle_protocol_handshake(std::shared_ptr<KCPSession> session) {
    auto buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);
    auto self = shared_from_this();
    session->set_socks5_read_pending(true);
    session->async_read_some(asio::buffer(*buf),
        [this, session, buf, self](const std::error_code& ec, size_t bytes) {
            session->set_socks5_read_pending(false);
            if (ec || bytes == 0) {
                LOG_WARNING("server", session->session_id() +
                            ": KCP_HANDSHAKE_FAILED read error: " + ec.message());
                session->stop();
                return;
            }
            const std::string msg(reinterpret_cast<const char*>(buf->data()), bytes);
            if (msg != KCP_CONTROL_HELLO) {
                session->mark_protocol_handshake_done();
                std::vector<uint8_t> initial(buf->begin(), buf->begin() + static_cast<std::ptrdiff_t>(bytes));
                LOG_INFO("server", session->session_id() +
                         ": no HELLO control frame; treating first KCP payload as SOCKS5 compatibility handshake");
                handle_socks5_request(session, std::move(initial));
                return;
            }
            session->mark_protocol_handshake_done();
            session->send_data(byte_view(reinterpret_cast<const uint8_t*>(KCP_CONTROL_HELLO_ACK),
                                         std::strlen(KCP_CONTROL_HELLO_ACK)));
            LOG_INFO("server", session->session_id() + ": KCP handshake confirmed");
        });
}

void KCPServer::handle_socks5_request(std::shared_ptr<KCPSession> session) {
    handle_socks5_request(session, {});
}

// Parse accumulated SOCKS5 request data.
// Returns: true if parsing is complete (success or error), false if more data needed.
// Side effects: on success, initiates connection; on error, sends failure reply.
bool KCPServer::parse_accumulated_socks5(std::shared_ptr<KCPSession> session,
                                         std::vector<uint8_t>& accum,
                                         bool log_details) {
    auto parsed = parse_socks5_request(accum);

    // NeedMore: incomplete request, caller should read more data
    if (parsed.status == SOCKS5ParseStatus::NeedMore) {
        if (accum.size() > FWD_BUF_SIZE) {
            // Request too large, reject immediately
            session->set_socks5_read_pending(false);
            LOG_ERROR("server", "FAIL_STAGE=SOCKS5_PARSE_FAILED ERROR=request_too_large CLIENT_ENDPOINT=" +
                      session->session_id() + " TARGET=-");
            send_socks5_reply(session, SOCKS5_REPLY_GENERAL_FAILURE);
            session->stop();
            return true;  // complete with error
        }
        return false;  // need more data
    }

    // Invalid or complete: parsing is done, clear pending flag
    session->set_socks5_read_pending(false);

    if (parsed.status == SOCKS5ParseStatus::Invalid) {
        LOG_ERROR("server", "FAIL_STAGE=SOCKS5_PARSE_FAILED ERROR=" + parsed.error +
                  " CLIENT_ENDPOINT=" + session->session_id() + " TARGET=-");
        // Only an unsupported ATYP deserves ADDRESS_TYPE_NOT_SUPPORTED; every
        // other malformed request is a general failure.
        send_socks5_reply(session, parsed.bad_atyp
            ? SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
            : SOCKS5_REPLY_GENERAL_FAILURE);
        // The client will see the failure reply and disconnect; don't leave a
        // dead session parked in the table until the 60s idle sweep.
        session->stop();
        return true;  // complete with error
    }

    // Success: parsed.request contains valid SOCKS5 request
    const auto& request = *parsed.request;
    LOG_INFO("server", session->session_id() +
             (log_details ? ": SOCKS5 connect target cmd=" +
              std::to_string(request.cmd) + " atyp=" +
              std::to_string(request.atyp) + " host=" + request.host +
              " port=" + std::to_string(request.port)
              : ": SOCKS5 CONNECT dst=" + request.host +
              ":" + std::to_string(request.port) +
              " cmd=" + std::to_string(request.cmd)));

    if (request.cmd == SOCKS5_CMD_CONNECT) {
        // Suppress further SOCKS5 dispatches until the upstream connect
        // completes (mark_handshake_done) or the session stops. Without this,
        // a data message arriving during the DNS/TCP-connect window would be
        // re-parsed as a second SOCKS5 request, fail validation, and tear the
        // session down (breaks clients that pipeline early data).
        session->set_connect_pending(true);
        handle_connect_command(session, request, request.initial_payload);
    } else if (request.cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        handle_udp_associate(session, request);
    } else {
        LOG_WARNING("server", "FAIL_STAGE=SOCKS5_UNSUPPORTED_COMMAND ERROR=cmd_" +
                    std::to_string(request.cmd) + " CLIENT_ENDPOINT=" +
                    session->session_id() + " TARGET=" + request.host +
                    ":" + std::to_string(request.port));
        send_socks5_reply(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
    }
    return true;  // complete (success or handled error)
}

void KCPServer::handle_socks5_request(std::shared_ptr<KCPSession> session,
                                      std::vector<uint8_t> initial_data) {
    auto accum = std::make_shared<std::vector<uint8_t>>(std::move(initial_data));
    auto self = shared_from_this();
    read_more_socks5(session, accum, self);
}

// Read the next fragment of a (possibly incomplete) SOCKS5 request. The request
// can span multiple KCP messages, so the async_read_some handler re-invokes
// this member function until the request parses to completion or fails.
//
// This is deliberately a plain member-function loop (like forward_tcp_to_kcp /
// forward_kcp_to_tcp), NOT a self-capturing std::function. A std::function that
// captured its own shared_ptr would form a reference cycle that is never
// broken, leaking one function object + session + accumulator per request.
void KCPServer::read_more_socks5(std::shared_ptr<KCPSession> session,
                                 std::shared_ptr<std::vector<uint8_t>> accum,
                                 std::shared_ptr<KCPServer> self) {
    if (!accum->empty() && parse_accumulated_socks5(session, *accum, false)) {
        return;
    }

    auto buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);
    LOG_DEBUG("server", session->session_id() + ": reading SOCKS5 request fragment");
    session->set_socks5_read_pending(true);
    session->async_read_some(asio::buffer(*buf),
    [this, session, accum, buf, self](const std::error_code& ec, size_t bytes) {
        if (ec) {
            session->set_socks5_read_pending(false);
            LOG_ERROR("server", session->session_id() +
                      ": SOCKS5_PARSE_FAILED read error: " + ec.message());
            send_socks5_reply(session, SOCKS5_REPLY_GENERAL_FAILURE);
            session->stop();
            return;
        }

        accum->insert(accum->end(), buf->begin(), buf->begin() + static_cast<std::ptrdiff_t>(bytes));
        if (parse_accumulated_socks5(session, *accum, true)) {
            return;
        }
        read_more_socks5(session, accum, self);
    });
}

void KCPServer::handle_connect_command(std::shared_ptr<KCPSession> session,
                                        const SOCKS5Request& request) {
    handle_connect_command(session, request, {});
}

void KCPServer::handle_connect_command(std::shared_ptr<KCPSession> session,
                                        const SOCKS5Request& request,
                                        std::vector<uint8_t> initial_payload) {
    LOG_INFO("server", session->session_id() +
             ": connecting to " + request.host + ":" + std::to_string(request.port));

    auto tcp_socket = std::make_shared<asio::ip::tcp::socket>(io_);
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(io_);
    auto deadline = std::make_shared<asio::steady_timer>(io_);
    auto fired = std::make_shared<std::atomic<bool>>(false);
    auto initial_payload_buf = std::make_shared<std::vector<uint8_t>>(std::move(initial_payload));

    deadline->expires_after(std::chrono::seconds(CONNECT_TIMEOUT_SEC));
    auto self = shared_from_this();
    deadline->async_wait([this, self, session, request, tcp_socket, resolver, fired]
                        (const std::error_code& ec) {
        if (ec == asio::error::operation_aborted) return;
        if (fired->exchange(true)) return;
        std::error_code ignored;
        resolver->cancel();
        if (tcp_socket->is_open()) tcp_socket->close(ignored);
        LOG_WARNING("server", "FAIL_STAGE=TCP_CONNECT_FAILED ERROR=connect_timeout_" +
                    std::to_string(CONNECT_TIMEOUT_SEC) + "s CLIENT_ENDPOINT=" +
                    session->session_id() + " TARGET=" + request.host +
                    ":" + std::to_string(request.port));
        send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
        session->stop();
    });

    // SSRF guard (early): if the request host is a literal IP that is a
    // restricted target (loopback/private/link-local/etc.), refuse it without
    // even resolving, so the server can never be pointed at its own network.
    {
        std::error_code ip_ec;
        const auto ip = asio::ip::make_address(request.host, ip_ec);
        if (!ip_ec && is_restricted_target(ip)) {
            if (fired->exchange(true)) return;
            std::error_code ignored;
            deadline->cancel(ignored);
            LOG_WARNING("server", "FAIL_STAGE=SSRF_BLOCKED ERROR=restricted_target CLIENT_ENDPOINT=" +
                        session->session_id() + " TARGET=" + request.host + ":" +
                        std::to_string(request.port));
            send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
            session->stop();
            return;
        }
    }

    resolver->async_resolve(request.host, std::to_string(request.port),
        [this, session, request, tcp_socket, resolver, deadline, fired, self, initial_payload_buf]
        (const std::error_code& ec, asio::ip::tcp::resolver::results_type results) mutable {
            if (fired->load()) return;
            if (ec) {
                if (fired->exchange(true)) return;
                std::error_code ignored;
                deadline->cancel(ignored);
                LOG_ERROR("server", "FAIL_STAGE=DNS_RESOLVE_FAILED ERROR=" + ec.message() +
                          " CLIENT_ENDPOINT=" + session->session_id() +
                          " TARGET=" + request.host + ":" + std::to_string(request.port));
                send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
                session->stop();
                return;
            }

            // SSRF guard (post-resolve): every resolved endpoint must be
            // publicly reachable. A domain such as "localhost" or an internal
            // hostname would resolve to a restricted address and is refused
            // here. Rejecting the whole set if any endpoint is restricted
            // prevents DNS-rebinding-style partial allowances.
            for (const auto& r : results) {
                if (is_restricted_target(r.endpoint().address())) {
                    if (fired->exchange(true)) return;
                    std::error_code ignored;
                    deadline->cancel(ignored);
                    LOG_WARNING("server", "FAIL_STAGE=SSRF_BLOCKED ERROR=restricted_target CLIENT_ENDPOINT=" +
                                session->session_id() + " TARGET=" + request.host + ":" +
                                std::to_string(request.port) +
                                " RESOLVED=" + r.endpoint().address().to_string());
                    send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
                    session->stop();
                    return;
                }
            }

            LOG_INFO("server", session->session_id() +
                     ": resolved " + request.host + " to " +
                     std::to_string(std::distance(results.begin(), results.end())) +
                     " endpoints, connecting...");
            asio::async_connect(*tcp_socket, results,
                [this, session, request, initial_payload_buf,
                 tcp_socket, resolver, deadline, fired, self]
                (const std::error_code& ec2, const asio::ip::tcp::endpoint&) mutable {
                    if (fired->exchange(true)) return;
                    std::error_code ignored;
                    deadline->cancel(ignored);
                    if (ec2) {
                        LOG_ERROR("server", "FAIL_STAGE=TCP_CONNECT_FAILED ERROR=" + ec2.message() +
                                  " CLIENT_ENDPOINT=" + session->session_id() +
                                  " TARGET=" + request.host + ":" + std::to_string(request.port));
                        uint8_t reply = get_error_reply_code(ec2);
                        send_socks5_reply(session, reply);
                        session->stop();
                        return;
                    }

                    LOG_INFO("server", session->session_id() +
                             ": connected to target " + request.host + ":" +
                             std::to_string(request.port));

                    std::string bind_host;
                    uint16_t bind_port = 0;
                    std::error_code local_ec;
                    auto local = tcp_socket->local_endpoint(local_ec);
                    if (!local_ec) {
                        bind_host = local.address().to_string();
                        bind_port = local.port();
                    }

                    send_socks5_reply(session, SOCKS5_REPLY_SUCCEEDED,
                                      bind_host, bind_port);
                    session->mark_handshake_done();

                    std::string sid = session->session_id();

                    // Serialize writes to the target socket: the initial payload
                    // (if any) must be fully written before the kcp->tcp forward
                    // loop is allowed to start, otherwise a data packet arriving
                    // during the write would start a second async_write that
                    // interleaves with this one on the same socket. connections_
                    // is populated only in start_forwarding, so any
                    // forward_kcp_to_tcp that fires while this write is in
                    // flight finds no TCP socket and is absorbed (data stays
                    // queued in KCP and is drained by the eager arm below).
                    auto start_forwarding = [this, sid, session, tcp_socket, self]() {
                        {
                            std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
                            connections_[sid] = ClientConnection{
                                sid,
                                tcp_socket,
                                std::chrono::steady_clock::now()
                            };
                        }
                        // When the upstream target closes, keep the session alive
                        // until the target data already queued in KCP's send
                        // buffer has been delivered to the client (see
                        // handle_target_closed / KCPSession::on_update_tick), then
                        // close. This prevents truncating large responses whose
                        // tail is still in flight when the target closes.
                        session->set_drained_callback([this, sid]() {
                            close_connection(sid, "target_drained");
                        });
                        forward_tcp_to_kcp(sid, session, tcp_socket);
                        // Eagerly arm the kcp->tcp direction so data that queued
                        // while the initial payload was being written is
                        // delivered immediately. forward_kcp_to_tcp is
                        // idempotent, so this is safe even if handle_kcp_data
                        // already started the loop.
                        forward_kcp_to_tcp(session);
                    };

                    if (!initial_payload_buf->empty()) {
                        asio::async_write(*tcp_socket, asio::buffer(*initial_payload_buf),
                            [this, sid, session, tcp_socket, initial_payload_buf, start_forwarding, self]
                            (const std::error_code& write_ec, size_t) mutable {
                                if (write_ec) {
                                    LOG_ERROR("server", "FAIL_STAGE=TCP_WRITE_FAILED ERROR=initial_payload_" +
                                              write_ec.message() + " CLIENT_ENDPOINT=" + sid +
                                              " TARGET=-");
                                    close_connection(sid, "initial_payload_write");
                                    return;
                                }
                                start_forwarding();
                            });
                    } else {
                        start_forwarding();
                    }
                });
        });
}

void KCPServer::handle_udp_associate(std::shared_ptr<KCPSession> session,
                                      const SOCKS5Request& request) {
    LOG_WARNING("server", "FAIL_STAGE=SOCKS5_UNSUPPORTED_COMMAND ERROR=udp_associate_unsupported CLIENT_ENDPOINT=" +
                session->session_id() + " TARGET=" + request.host +
                ":" + std::to_string(request.port));
    send_socks5_reply(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
    session->stop();
}

void KCPServer::send_socks5_reply(std::shared_ptr<KCPSession> session, uint8_t reply) {
    send_socks5_reply(session, reply, "", 0);
}

void KCPServer::send_socks5_reply(std::shared_ptr<KCPSession> session, uint8_t reply,
                                   std::string_view host, uint16_t port) {
    LOG_DEBUG("server", session->session_id() +
             ": sending SOCKS5 reply=" + std::to_string(reply) +
             " host=" + std::string(host) + " port=" + std::to_string(port));
    SOCKS5Response resp;
    resp.reply = reply;
    resp.host = std::string(host);
    resp.port = port;
    auto data = resp.build();
    LOG_DEBUG("server", session->session_id() +
             ": SOCKS5 reply bytes (" + std::to_string(data.size()) + ")");
    session->send_data(byte_view(data.data(), data.size()));
}

void KCPServer::forward_tcp_to_kcp(std::string session_id,
                                    std::shared_ptr<KCPSession> session,
                                    std::shared_ptr<asio::ip::tcp::socket> tcp_socket,
                                    std::shared_ptr<std::vector<uint8_t>> buf) {
    if (!session) {
        LOG_ERROR("server", session_id + ": forward_tcp_to_kcp - no session");
        close_connection(session_id, "tcp2kcp_no_session");
        return;
    }
    // Run the whole loop on the session strand so the KCP-state reads
    // (wait_send/peek_size) are serialized with the strand handlers that mutate
    // KCP. This removes a latent data race that would surface if the io_context
    // ever ran on more than one thread.
    if (!session->strand().running_in_this_thread()) {
        auto self = shared_from_this();
        asio::dispatch(session->strand(), [this, self, session_id = std::move(session_id),
                                           session, tcp_socket, buf]() mutable {
            forward_tcp_to_kcp(std::move(session_id), session, tcp_socket, buf);
        });
        return;
    }
    // Reuse one read buffer for the whole connection: send_data() on the strand
    // copies into KCP before we re-arm, so the buffer is free again immediately.
    if (!buf) buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);

    LOG_DEBUG("server", session_id + ": forward_tcp_to_kcp (tcp->kcp), wait_send=" +
              std::to_string(session->wait_send()) +
              " running=" + std::to_string(session->is_running()));
    if (!tcp_socket || !tcp_socket->is_open()) {
        LOG_ERROR("server", session_id + ": forward_tcp_to_kcp - socket not open");
        close_connection(session_id, "tcp2kcp_no_socket");
        return;
    }
    if (!session->is_running()) {
        LOG_ERROR("server", session_id + ": forward_tcp_to_kcp - session not running");
        close_connection(session_id, "tcp2kcp_session_stopped");
        return;
    }

    // Backpressure: if KCP's send queue is already past the threshold, the
    // network can't keep up with what we're feeding in. Pause TCP reads and
    // re-arm via a short delay so we don't tight-loop. Safe to read wait_send
    // here because we are on the strand.
    if (session->wait_send() >= KCP_BACKPRESSURE_THRESHOLD) {
        LOG_DEBUG("server", session_id + ": backpressure (wait_send=" +
                  std::to_string(session->wait_send()) +
                  " >= threshold=" + std::to_string(KCP_BACKPRESSURE_THRESHOLD) + "), delaying read");
        auto retry = std::make_shared<asio::steady_timer>(io_);
        retry->expires_after(std::chrono::milliseconds(KCP_INTERVAL_MS * 4));
        auto self = shared_from_this();
        retry->async_wait([self, session_id = std::move(session_id), session,
                           tcp_socket, buf, retry](const std::error_code& ec) mutable {
            if (ec) return;
            self->forward_tcp_to_kcp(std::move(session_id), session, tcp_socket, buf);
        });
        return;
    }

    auto self = shared_from_this();
    tcp_socket->async_read_some(asio::buffer(*buf),
        asio::bind_executor(session->strand(),
        [this, session_id = std::move(session_id), session, tcp_socket, buf, self]
        (const std::error_code& ec, size_t bytes) mutable {
            if (ec || bytes == 0) {
                if (ec == asio::error::eof) {
                    LOG_INFO("server", session_id + ": TCP closed (EOF)");
                } else if (ec == asio::error::operation_aborted) {
                    LOG_DEBUG("server", session_id + ": TCP read cancelled");
                } else if (ec) {
                    LOG_ERROR("server", "FAIL_STAGE=TCP_READ_FAILED ERROR=" + ec.message() +
                              " CLIENT_ENDPOINT=" + session_id + " TARGET=-");
                }
                // Graceful teardown: the target is gone, but any target data
                // already read into KCP's send buffer must still reach the
                // client. close_connection() would drop it, so mark the target
                // closed and let the session's update loop drain the buffer,
                // closing via the drained callback once wait_send() reaches 0.
                handle_target_closed(session, tcp_socket);
                return;
            }
            LOG_DEBUG("server", session_id + ": TCP >> KCP read " + std::to_string(bytes) +
                     " bytes -> KCP send (wait_send=" + std::to_string(session->wait_send()) + ")");
            session->send_data(byte_view(buf->data(), bytes));
            forward_tcp_to_kcp(std::move(session_id), session, tcp_socket, buf);
        }));
}

void KCPServer::forward_kcp_to_tcp(std::shared_ptr<KCPSession> session,
                                   std::shared_ptr<std::vector<uint8_t>> buf) {
    if (!session->strand().running_in_this_thread()) {
        auto self = shared_from_this();
        asio::dispatch(session->strand(), [this, self, session, buf]() {
            forward_kcp_to_tcp(session, buf);
        });
        return;
    }

    // If the target has closed, the client->target direction is dead. Never
    // start (or restart) this loop; the session is draining queued target data
    // to the client and will close via the drained callback.
    if (session->is_target_closed()) {
        session->set_forward_read_pending(false);
        return;
    }

    // Claim the kcp->tcp loop. try_set_forward_read_pending returns the OLD
    // value: false means we own it and may register a read, true means a loop
    // is already running (waiting on a read, or mid-write) and this call is a
    // no-op. This makes the function idempotent — it is safe to call from both
    // handle_kcp_data and the explicit start after connect — and guarantees at
    // most one async_read_some (and therefore one async_write) is outstanding
    // on the session at a time, so writes to the target socket never interleave.
    if (session->try_set_forward_read_pending()) {
        LOG_DEBUG("server", session->session_id() + ": forward_kcp_to_tcp already active, skipping");
        return;
    }
    if (!buf) buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);
    std::string sid = session->session_id();
    LOG_DEBUG("server", sid + ": forward_kcp_to_tcp (kcp->tcp), running=" +
              std::to_string(session->is_running()) +
              " forward_pending=" + std::to_string(session->is_forward_read_pending()));

    // Check if session is still running before initiating read.
    if (!session->is_running()) {
        LOG_INFO("server", sid + ": forward_kcp_to_tcp - session stopped");
        session->set_forward_read_pending(false);
        return;
    }

    std::shared_ptr<asio::ip::tcp::socket> tcp_sock;
    {
        std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
        auto it = connections_.find(sid);
        if (it == connections_.end() || !it->second.tcp_socket) {
            LOG_INFO("server", sid + ": forward_kcp_to_tcp - no TCP connection found");
            session->set_forward_read_pending(false);
            return;
        }
        tcp_sock = it->second.tcp_socket;
        if (!tcp_sock->is_open()) {
            LOG_INFO("server", sid + ": forward_kcp_to_tcp - TCP socket not open");
            session->set_forward_read_pending(false);
            return;
        }
    }

    auto self = shared_from_this();

    // forward_read_pending is already true (claimed above); the read below is
    // the sole active forward read.
    LOG_DEBUG("server", sid + ": async_read_some from KCP, buffer=" + std::to_string(FWD_BUF_SIZE));
    session->async_read_some(asio::buffer(*buf),
        [this, sid, session, buf, tcp_sock, self]
        (const std::error_code& ec, size_t bytes) mutable {
            if (ec || bytes == 0) {
                if (ec && ec != asio::error::operation_aborted &&
                    ec != asio::error::already_started) {
                    LOG_WARNING("server", "FAIL_STAGE=KCP_NO_RECV ERROR=" + ec.message() +
                                " CLIENT_ENDPOINT=" + sid + " TARGET=-");
                } else if (bytes == 0 && !ec) {
                    LOG_WARNING("server", "FAIL_STAGE=KCP_NO_RECV ERROR=zero_bytes CLIENT_ENDPOINT=" +
                                sid + " TARGET=-");
                }
                close_connection(sid, "kcp2tcp_read");
                return;
            }

            // The target closed while this read was pending: client data can no
            // longer be delivered, so drop it and stop the loop instead of
            // writing to a closed socket (which would error and could tear the
            // session down before its queued target data finished draining).
            if (session->is_target_closed()) {
                LOG_DEBUG("server", sid + ": target closed, dropping " +
                          std::to_string(bytes) + " bytes of client data");
                session->set_forward_read_pending(false);
                return;
            }

            LOG_DEBUG("server", sid + ": KCP >> TCP read " + std::to_string(bytes) +
                     " bytes -> TCP write");
            asio::async_write(*tcp_sock, asio::buffer(buf->data(), bytes),
                asio::bind_executor(session->strand(),
                [this, sid, session, buf, tcp_sock, self]
                (const std::error_code& ec2, size_t written) mutable {
                    if (ec2) {
                        if (ec2 != asio::error::operation_aborted) {
                            LOG_ERROR("server", "FAIL_STAGE=TCP_WRITE_FAILED ERROR=" + ec2.message() +
                                      " CLIENT_ENDPOINT=" + sid + " TARGET=-");
                        }
                        // The target connection failed (it may have been closed
                        // under us). Treat it like an upstream close: drain any
                        // queued target data to the client before tearing down.
                        handle_target_closed(session, tcp_sock);
                        return;
                    }
                    LOG_DEBUG("server", sid + ": TCP write done (" + std::to_string(written) + " bytes), re-arming");
                    if (session->is_running()) {
                        // Release the claim so the re-arm below can re-acquire
                        // it (it is still set from the read registration above).
                        session->set_forward_read_pending(false);
                        forward_kcp_to_tcp(session, buf);
                    } else {
                        session->set_forward_read_pending(false);
                    }
                }));
        });
}

void KCPServer::handle_target_closed(std::shared_ptr<KCPSession> session,
                                     std::shared_ptr<asio::ip::tcp::socket> tcp_socket) {
    if (!session->is_target_closed()) {
        LOG_INFO("server", session->session_id() + ": target connection closed, draining queued data to client");
        session->mark_target_closed();
    }
    if (tcp_socket && tcp_socket->is_open()) {
        std::error_code ignored;
        tcp_socket->close(ignored);
    }
    // The client->target direction is dead; stop the forward loop. The
    // target->client data still queued in KCP's send buffer is delivered by the
    // session's update loop, and the session is closed by the drained callback
    // once wait_send() reaches 0.
    session->set_forward_read_pending(false);
}

void KCPServer::close_connection(const std::string& session_id, const char* caller) {
    LOG_INFO("server", session_id + ": close_connection from " + std::string(caller));

    std::shared_ptr<asio::ip::tcp::socket> sock_to_close;
    std::shared_ptr<KCPSession> session_to_stop;
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        auto it = connections_.find(session_id);
        if (it != connections_.end()) {
            sock_to_close = std::move(it->second.tcp_socket);
            connections_.erase(it);
        }
        auto sit = sessions_.find(session_id);
        if (sit != sessions_.end()) {
            session_to_stop = sit->second;
            sessions_.erase(sit);
        }
    }

    if (sock_to_close && sock_to_close->is_open()) {
        std::error_code ignored;
        sock_to_close->close(ignored);
    }
    if (session_to_stop) {
        session_to_stop->stop();
    }
}

void KCPServer::do_update_tick(const std::error_code& ec) {
    if (ec || !running_) return;

    // Re-arm FIRST: the 10ms cadence must not stretch by the snapshot +
    // dispatch work below. The single timer chain also pins the server
    // (via self) in the io_context for as long as it runs.
    update_tick_timer_.expires_after(std::chrono::milliseconds(KCP_INTERVAL_MS));
    auto self = shared_from_this();
    update_tick_timer_.async_wait([this, self](const std::error_code& e) {
        do_update_tick(e);
    });

    // Phase 1: snapshot weak refs under the shared lock. Copying weak_ptr is
    // cheap and the lock is held only for the copy, so the UDP receive path
    // (which inserts sessions) and the cleanup sweep (which erases them)
    // never wait behind per-session dispatches.
    tick_snapshot_.clear();
    {
        std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
        tick_snapshot_.reserve(sessions_.size());
        for (const auto& [sid, session] : sessions_) {
            tick_snapshot_.emplace_back(session);
        }
    }

    // Phase 2: dispatch WITHOUT holding the lock. lock() on a dead weak_ptr
    // (session erased since the snapshot) returns null and is skipped, so a
    // session dying mid-tick can neither crash the tick nor be resurrected.
    // The dispatched handler re-locks inside the session strand: capture by
    // weak_ptr so a session queued behind a congested strand is not kept
    // alive artificially by the tick.
    for (const auto& w : tick_snapshot_) {
        if (auto session = w.lock()) {
            std::weak_ptr<KCPSession> ws = session;
            asio::dispatch(session->strand(), [ws]() mutable {
                if (auto s = ws.lock()) s->on_update_tick();
            });
        }
    }
}

void KCPServer::do_cleanup(const std::error_code& ec) {
    if (ec || !running_) return;

    std::vector<std::shared_ptr<KCPSession>> sessions_to_stop;
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> sockets_to_close;
    std::vector<std::string> dead_session_ids;
    // Aggregate session traffic metrics (reported each sweep).
    uint64_t total_pkts_sent = 0, total_pkts_recv = 0;
    uint64_t total_bytes_sent = 0, total_bytes_recv = 0;
    size_t active_sessions = 0;
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);

        // Aggregate per-session metrics for the periodic report.
        for (const auto& [sid, session] : sessions_) {
            if (!session) continue;
            const auto& m = session->metrics();
            total_pkts_sent += m.packets_sent.load(std::memory_order_relaxed);
            total_pkts_recv += m.packets_received.load(std::memory_order_relaxed);
            total_bytes_sent += m.bytes_sent.load(std::memory_order_relaxed);
            total_bytes_recv += m.bytes_received.load(std::memory_order_relaxed);
        }

        // Find dead sessions
        for (auto& [sid, session] : sessions_) {
            if (session && !session->is_alive()) {
                LOG_INFO("server", "FAIL_STAGE=SESSION_TIMEOUT ERROR=idle_timeout CLIENT_ENDPOINT=" +
                         sid + " TARGET=-");
                dead_session_ids.push_back(sid);
                sessions_to_stop.push_back(session);
                auto conn_it = connections_.find(sid);
                if (conn_it != connections_.end() && conn_it->second.tcp_socket) {
                    sockets_to_close.push_back(conn_it->second.tcp_socket);
                }
            }
        }

        // Erase collected sessions/connections
        for (const auto& sid : dead_session_ids) {
            sessions_.erase(sid);
            connections_.erase(sid);
        }
        // Report the post-sweep count so "sessions=N" is the live figure, not
        // the count captured before dead sessions were erased.
        active_sessions = sessions_.size();
    }

    // Stop sessions and close sockets outside the lock
    for (auto& session : sessions_to_stop) {
        session->stop();
    }
    for (auto& sock : sockets_to_close) {
        if (sock && sock->is_open()) {
            std::error_code ignored;
            sock->close(ignored);
        }
    }

    LOG_INFO("server", fmt::format("metrics sweep: sessions={} pkts_sent={} pkts_recv={} bytes_sent={} bytes_recv={}",
              active_sessions, total_pkts_sent, total_pkts_recv,
              total_bytes_sent, total_bytes_recv));

    cleanup_timer_.expires_after(std::chrono::seconds(30));
    // Hold a shared_ptr like every other async handler (start() does too), so
    // the timer chain keeps the server alive on its own.
    auto self = shared_from_this();
    cleanup_timer_.async_wait([this, self](const std::error_code& ec2) {
        do_cleanup(ec2);
    });
}

void KCPServer::send_to_client(const asio::ip::udp::endpoint& addr,
                               std::vector<uint8_t> data) {
    if (!running_ || !udp_socket_.is_open()) {
        LOG_WARNING("server", "send_to_client: not running or socket closed");
        return;
    }

    LOG_DEBUG("server", "send_to_client: sending " + std::to_string(data.size()) +
             " bytes to " + addr.address().to_string() + ":" + std::to_string(addr.port()));

    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(data));
    udp_socket_.async_send_to(
        asio::buffer(*buf), addr,
        [buf, addr](const std::error_code& ec, size_t bytes_sent) {
            if (ec && ec != asio::error::operation_aborted) {
                LOG_ERROR("server", "FAIL_STAGE=UDP_SEND_FAILED ERROR=" + ec.message() +
                          " CLIENT_ENDPOINT=" + addr.address().to_string() +
                          ":" + std::to_string(addr.port()) + " TARGET=-");
            } else if (!ec) {
                LOG_DEBUG("server", "UDP sent " + std::to_string(bytes_sent) +
                         " bytes to " + addr.address().to_string() + ":" + std::to_string(addr.port()));
            }
        });
}

uint8_t KCPServer::get_error_reply_code(const std::error_code& ec) {
    if (ec == asio::error::connection_refused)
        return SOCKS5_REPLY_CONNECTION_REFUSED;
    if (ec == asio::error::network_unreachable)
        return SOCKS5_REPLY_NETWORK_UNREACHABLE;
    if (ec == asio::error::host_unreachable)
        return SOCKS5_REPLY_HOST_UNREACHABLE;
    if (ec == asio::error::timed_out)
        return SOCKS5_REPLY_HOST_UNREACHABLE;
    return SOCKS5_REPLY_GENERAL_FAILURE;
}

} // namespace kcp_proxy
