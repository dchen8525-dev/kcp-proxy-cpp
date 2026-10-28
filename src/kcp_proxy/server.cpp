#include "kcp_proxy/server.hpp"
#include "kcp_proxy/address.hpp"
#include "kcp_proxy/buffer_pool.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/config.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/socket_buffer.hpp"
#include "kcp_proxy/target_allowlist.hpp"
#include "kcp_proxy/time_util.hpp"
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/connect.hpp>
#include <fmt/format.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <mswsock.h>
// SIO_UDP_CONNRESET and the disable_udp_connreset() wrapper live in
// socket_buffer.hpp, which both ends include (see its comment for why).
#endif
#if defined(__linux__)
// sendmmsg/recvmmsg for the batched wire paths, sockaddr_in/_in6 for the
// drain endpoint decode, MSG_DONTWAIT/MSG_NOSIGNAL, errno.
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif
#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace kcp_proxy {

KCPServer::KCPServer(asio::io_context& io, uint16_t port, std::string key, std::string host,
                     const FecConfig& fec, const AdaptiveSettings& adaptive)
    : io_(io),
      port_(port),
      host_(std::move(host)),
      key_(key),
      fec_(fec),
      // The UDP socket owns its own strand: it is a single shared object, and
      // with -T > 1 both ends touch it from different threads (receives re-arm
      // on the io_context, sends are called from per-session strands). Binding
      // the socket's executor to a strand serializes every initiation and every
      // completion on it -- see send_to_client() and do_receive().
      udp_socket_(asio::make_strand(io_.get_executor())),
      tick_strand_(asio::make_strand(io_.get_executor())),
      cleanup_timer_(tick_strand_),
      // On the socket's strand, not the raw io_context: its handler is the one
      // place outside the receive path that touches receive_backoff_armed_ and
      // the slots' parked flags, and both are strand-confined by design. Bound
      // here rather than relying on bind_executor at the call site so the timer
      // and its handler agree on the executor by construction.
      receive_backoff_timer_(udp_socket_.get_executor()),
      update_tick_timer_(tick_strand_) {
    // Adaptive parity is meaningful here even without --fec: the server adapts
    // its shard parameters per session (FEC_ADAPTIVE_DATA_SHARDS when it has
    // none of its own), so a FEC-framed client still gets a session that can
    // withhold parity.
    if (adaptive.fec_parity) {
        parity_gate_ = std::make_shared<FecParityGate>();
        parity_ctl_ =
            std::make_unique<FecParityController>(*parity_gate_, adaptive.fec_parity_tuning);
    }
    if (adaptive.rto_relax_sec > 0) {
        rto_gate_ = std::make_shared<RtoFloorGate>();
        rto_ctl_ = std::make_unique<RtoFloorController>(*rto_gate_, adaptive.rto_relax_sec);
    }
}

KCPServer::~KCPServer() {
    stop();
    // stop() defers the wipe to the receive strand (see there); if the
    // io_context was already stopped that handler never ran. Nothing can be
    // reading key_ here -- every reader holds a strong reference to the
    // server, and this only runs once the last one is gone.
    wipe_key();
}

void KCPServer::set_allowed_targets(std::vector<std::string> targets) {
    // Defense in depth: drop empty entries so a stray "--allow-target" with a
    // missing value can never create an entry that matches the empty host.
    // main_server.cpp already rejects that at the CLI, this keeps the library
    // safe for embedders that bypass the CLI.
    targets.erase(std::remove(targets.begin(), targets.end(), std::string()),
                  targets.end());
    allowed_targets_ = std::move(targets);
}

bool KCPServer::is_target_allowed(const std::string& host, uint16_t port) const {
    return target_matches_allowlist(allowed_targets_, host, port);
}

void KCPServer::wipe_key() {
    std::memset(key_.data(), 0, key_.size());
    key_.clear();
    key_.shrink_to_fit();
}

uint16_t KCPServer::bound_port() const {
    // Safe to query from any thread: the socket is bound once in start() and
    // outlives every session until stop() closes it.
    std::error_code ec;
    const auto ep = udp_socket_.local_endpoint(ec);
    return ec ? port_ : ep.port();
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
        throw std::runtime_error(
            fmt::format("failed to bind UDP socket on {}:{}: {}", host_, port_, ec.message()));
    }

    // Raise the kernel UDP send/receive buffers and report any silent clamp.
    // Shared with the client (socket_buffer.hpp) so the two cannot drift; the
    // server owns exactly one socket, so no once-per-process guard is needed.
    apply_udp_buffer_sizes(udp_socket_, "server", /*report_once=*/false);

#if defined(_WIN32)
    // Root-cause fix for the ICMP port-unreachable error path (see
    // disable_udp_connreset). The tolerant handler below stays as the
    // cross-platform safety net.
    const int wsa_rc = disable_udp_connreset(udp_socket_);
    LOG_INFO("server", fmt::format("SIO_UDP_CONNRESET disabled (wsa_rc={})", wsa_rc));
#endif

#if defined(__linux__)
    // Scratch storage for the recvmmsg drain (one slot per drainable
    // datagram). UDP_DRAIN_BATCH_MAX * UDP_RECV_BUF_SIZE = 1 MiB resident,
    // strand-confined, allocated once per server.
    drain_bufs_.assign(UDP_DRAIN_BATCH_MAX, std::vector<uint8_t>(UDP_RECV_BUF_SIZE, 0));
    drain_addrs_.assign(UDP_DRAIN_BATCH_MAX, sockaddr_storage{});
    drain_lens_.assign(UDP_DRAIN_BATCH_MAX, 0);
#endif

    running_ = true;

    cleanup_timer_.expires_after(std::chrono::seconds(30));
    auto self = shared_from_this();
    cleanup_timer_.async_wait([this, self](const std::error_code& ec) {
        do_cleanup(ec);
    });

    // Start the shared KCP update tick (10ms, one timer for all sessions).
    do_update_tick(std::error_code{});

    // Report the bound endpoint, not the requested one: -p 0 binds an
    // ephemeral port, and operators grep diagnostics by the real number.
    std::error_code bind_ec;
    const auto bound_ep = udp_socket_.local_endpoint(bind_ec);
    const uint16_t bound_port = bind_ec ? port_ : bound_ep.port();
    LOG_INFO("server", fmt::format("listening on {}:{}", host_, bound_port));
#if defined(__linux__)
    const char* udp_recv_mode = "recvmmsg-drain(256)";
#else
    const std::string udp_recv_mode = fmt::format("{}", UDP_RECV_SLOTS);
#endif
    LOG_INFO("server",
             fmt::format("diagnostics udp_bind={} udp_port={} udp_recv_slots={}"
                         " crypto=AES-128-GCM/HKDF-SHA256"
                         " socks5_mode=CONNECT_ONLY udp_associate=unsupported"
                         " log_level={}",
                         host_, bound_port, udp_recv_mode, log_level_name(current_log_level())));
    LOG_INFO("server", kcp_config_line());
    LOG_INFO("server", fec_config_line(fec_));
    const std::string fec_mode =
        fec_.enabled() ? fmt::format(" (shards={})", fec_.to_string())
                       : fmt::format(" (default shards={}:{})", FEC_ADAPTIVE_DATA_SHARDS,
                                     FEC_ADAPTIVE_PARITY_SHARDS);
    LOG_INFO("server", fmt::format("server FEC mode: auto-adapt per client framing{}", fec_mode));

    do_receive();
}

void KCPServer::stop() {
    if (!running_.exchange(false)) return;
    // Set BEFORE swapping the maps: get_or_create_session checks this under
    // the sessions_mutex_ write lock, so ordering it ahead of the swap makes
    // "reject new sessions" atomic with "drain the existing ones".
    stopped_.store(true);

    // Tear the asio objects down on their own executors, not from this thread:
    // with -T > 1 the caller (the signal handler, on the main io thread) runs
    // concurrently with handlers executing on other io threads, and asio's
    // contract forbids concurrent member calls on a shared object. If the
    // caller stops the io_context right after (as main does), the queued
    // teardown never runs and the objects are destroyed with the io_context
    // instead -- equivalent.
    //
    // Guarded by weak_from_this() rather than a strong capture: stop() is also
    // reached from ~KCPServer, where shared_from_this() would throw
    // bad_weak_ptr, and weak_from_this() is safe there (lock() yields null
    // once the last strong ref is gone). A strong capture would also keep the
    // server alive past its own destructor's intent.
    std::weak_ptr<KCPServer> weak_self = weak_from_this();
    asio::dispatch(tick_strand_, [this, weak_self]() {
        if (!weak_self.lock()) return; // server already destroyed
        std::error_code ignored;
        cleanup_timer_.cancel(ignored);
        update_tick_timer_.cancel(ignored);
    });
    asio::dispatch(udp_socket_.get_executor(), [this, weak_self]() {
        if (!weak_self.lock()) return;
        std::error_code ignored;
        udp_socket_.close(ignored);
        receive_backoff_timer_.cancel(ignored);
        // The key is wiped HERE, not by the caller: get_or_create_session reads
        // key_ while building a new session's Crypto, and every reader of it is
        // bound to this strand. wipe_key() frees the buffer, so calling it from
        // the signal-handler thread (stop()'s caller, an unrelated io thread
        // when -T > 1) races with an in-flight auth decrypt. If io.stop()
        // follows stop() immediately, as in main(), this handler never runs and
        // ~KCPServer does the wipe instead -- equally safe, since no handler
        // holding a strong reference can be live at that point.
        wipe_key();
    });

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
        // The socket lives on its session's strand; close it there rather
        // than racing its in-flight async_read_some from this thread.
        auto sock = std::move(conn.tcp_socket);
        if (!sock) continue;
        asio::dispatch(sock->get_executor(), [sock]() mutable {
            std::error_code ignored;
            sock->close(ignored);
        });
    }

    LOG_INFO("server", "stopped");
}

void KCPServer::do_receive() {
    if (!running_) return;
#if defined(__linux__)
    arm_receive_drain();
#else
    for (size_t i = 0; i < UDP_RECV_SLOTS; ++i) {
        arm_receive_slot(i);
    }
#endif
}

#if defined(__linux__)
void KCPServer::arm_receive_drain() {
    // One outstanding readiness wait replaces the 16 outstanding receives of
    // the slot model. Initiated through the socket's strand like every other
    // socket operation (start() calls do_receive() off the strand).
    auto self = shared_from_this();
    asio::dispatch(udp_socket_.get_executor(), [this, self]() {
        if (!running_) return;
        udp_socket_.async_wait(asio::ip::udp::socket::wait_read,
                               asio::bind_executor(udp_socket_.get_executor(),
                                                   [this, self](const std::error_code& ec) {
                                                       handle_receive_drain(ec);
                                                   }));
    });
}

void KCPServer::handle_receive_drain(const std::error_code& wait_ec) {
    if (wait_ec == asio::error::operation_aborted || !running_) return;
    if (wait_ec) {
        // Readiness wait itself failed: same throttled park as the slot path.
        uint32_t suppressed = 0;
        if (recv_error_log_.should_log(suppressed)) {
            LOG_ERROR("server", fmt::format("UDP readiness wait error: {}{}", wait_ec.message(),
                                            throttle_suffix(suppressed)));
        }
        // Reuse the slot backoff timer: it re-arms via arm_receive_slot in the
        // slot model, so it is only meaningful here if we re-arm the drain
        // with it. Keep it simple: a bounded retry through the same timer.
        if (!recv_backoff_armed_) {
            recv_backoff_armed_ = true;
            auto self = shared_from_this();
            receive_backoff_timer_.expires_after(std::chrono::milliseconds(10));
            receive_backoff_timer_.async_wait(asio::bind_executor(
                udp_socket_.get_executor(), [this, self](const std::error_code& timer_ec) {
                    recv_backoff_armed_ = false;
                    if (!timer_ec && running_) arm_receive_drain();
                }));
        }
        return;
    }

    // Drain phase: read everything the kernel currently holds (bounded by
    // UDP_DRAIN_BATCH_MAX) BEFORE routing any of it, so the kernel buffer
    // cannot overflow while route_datagram() runs its allocations and strand
    // dispatches -- the same handler/drain decoupling the slot model buys,
    // with one recvmmsg per 64 datagrams instead of one recvmsg per datagram.
    int fd = udp_socket_.native_handle();
    size_t drained = 0;
    bool transient_error = false;
    while (running_ && drained < UDP_DRAIN_BATCH_MAX) {
        const size_t want = std::min(UDP_DRAIN_BATCH_MAX - drained, UDP_BATCH_MAX);
        struct mmsghdr msgs[UDP_BATCH_MAX];
        struct iovec iov[UDP_BATCH_MAX];
        for (size_t i = 0; i < want; ++i) {
            iov[i].iov_base = drain_bufs_[drained + i].data();
            iov[i].iov_len = drain_bufs_[drained + i].size();
            std::memset(&msgs[i], 0, sizeof(msgs[i]));
            msgs[i].msg_hdr.msg_name = &drain_addrs_[drained + i];
            msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        ssize_t n = ::recvmmsg(fd, msgs, static_cast<unsigned int>(want), MSG_DONTWAIT, nullptr);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            transient_error = true;
            break;
        }
        for (int i = 0; i < n; ++i) {
            drain_lens_[drained + i] = msgs[i].msg_len;
        }
        drained += static_cast<size_t>(n);
        if (static_cast<size_t>(n) < want) break; // drained
    }
    if (!running_) return; // stop() raced the drain; the socket is gone

    // Route phase. Same per-datagram logic as handle_receive: containment
    // (route_datagram never throws out), zero-length drops, and the running_
    // check happen inside route_datagram's callees as before.
    for (size_t i = 0; i < drained; ++i) {
        const size_t len = drain_lens_[i];
        if (len == 0 || len > drain_bufs_[i].size()) continue;
        // Decode the source endpoint. Only AF_INET/AF_INET6 can arrive on a
        // UDP socket; anything else (never seen in practice) drops the frame.
        const sockaddr_storage& ss = drain_addrs_[i];
        asio::ip::udp::endpoint endpoint;
        if (ss.ss_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(&ss);
            endpoint.address(asio::ip::address_v4(ntohl(sin->sin_addr.s_addr)));
            endpoint.port(ntohs(sin->sin_port));
        } else if (ss.ss_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&ss);
            asio::ip::address_v6::bytes_type bytes{};
            std::memcpy(bytes.data(), sin6->sin6_addr.s6_addr, bytes.size());
            endpoint.address(asio::ip::address_v6(bytes, sin6->sin6_scope_id));
            endpoint.port(ntohs(sin6->sin6_port));
        } else {
            continue;
        }
        LOG_DEBUG("server", fmt::format("UDP recv {} bytes from {}:{}", len,
                                        endpoint.address().to_string(), endpoint.port()));
        route_datagram(endpoint, byte_view(drain_bufs_[i].data(), len));
    }

    if (transient_error) {
        uint32_t suppressed = 0;
        int err = errno; // recvmmsg failed outside EAGAIN/EINTR
        if (recv_error_log_.should_log(suppressed)) {
            LOG_ERROR("server", fmt::format("UDP receive error: {}{}", std::strerror(err),
                                            throttle_suffix(suppressed)));
        }
    }
    arm_receive_drain();
}
#endif // __linux__

void KCPServer::arm_receive_slot(size_t index) {
    // Initiate through the socket's strand. Callers are already on it (every
    // receive completion is bound to it, and so is the backoff timer), so this
    // runs inline in the normal path; the dispatch is what makes start()'s
    // initial arming safe, since start() is called from off the strand.
    auto self = shared_from_this();
    asio::dispatch(udp_socket_.get_executor(), [this, self, index]() {
        if (!running_) return;
        RecvSlot& slot = recv_slots_[index];
        slot.parked = false;
        slot.endpoint = asio::ip::udp::endpoint();
        udp_socket_.async_receive_from(
            asio::buffer(slot.buf), slot.endpoint,
            // Bound explicitly to the socket's strand: the default completion
            // executor already routes here, but this handler is one of
            // UDP_RECV_SLOTS in flight at once, and the plain (non-atomic)
            // state it touches -- auth_attempts_window_, the LogThrottles, the
            // backoff flag -- is only safe if that is guaranteed rather than
            // inferred.
            asio::bind_executor(udp_socket_.get_executor(),
                                [this, self, index](const std::error_code& ec, size_t bytes) {
                                    handle_receive(index, ec, bytes);
                                }));
    });
}

void KCPServer::park_receive_slot(size_t index) {
    recv_slots_[index].parked = true;
    // Unknown errors are the one path that can complete immediately and
    // repeatedly with no external pacing at all: an unbounded re-arm here is a
    // busy spin plus an ERROR log line per iteration. Park the slot and re-arm
    // it through a short shared backoff instead, which bounds the loop to
    // ~100 attempts/s while a transient condition (or an operator) resolves it.
    // One timer for all slots: N slots failing at once must not raise the retry
    // rate to N times that.
    if (recv_backoff_armed_) return;
    recv_backoff_armed_ = true;
    auto self = shared_from_this();
    receive_backoff_timer_.expires_after(std::chrono::milliseconds(10));
    receive_backoff_timer_.async_wait(asio::bind_executor(
        udp_socket_.get_executor(),
        [this, self](const std::error_code& timer_ec) {
            recv_backoff_armed_ = false;
            if (timer_ec || !running_) return;
            for (size_t i = 0; i < UDP_RECV_SLOTS; ++i) {
                if (recv_slots_[i].parked) arm_receive_slot(i);
            }
        }));
}

void KCPServer::handle_receive(size_t index, const std::error_code& ec,
                               size_t bytes_transferred) {
    if (ec) {
        if (running_ && ec != asio::error::operation_aborted) {
            // UDP sockets surface ICMP Port Unreachable as an error on the next
            // receive: connection_refused on Linux/BSD, connection_reset
            // (WSAECONNRESET) on Windows. This is normal after a peer closes
            // its socket and is not fatal for the server; on Windows the
            // reporting is disabled at the source (SIO_UDP_CONNRESET in
            // start()), and on Linux it only fires for connected sockets
            // anyway. Just log and continue.
            if (ec == asio::error::connection_refused ||
                ec == asio::error::connection_reset) {
                LOG_DEBUG("server", "UDP ICMP port unreachable received (ignored)");
                arm_receive_slot(index);
            } else {
                // Throttled: park_receive_slot() bounds how often the socket is
                // retried, not how often this line is emitted -- one per slot
                // per 10ms is ~1600 stderr writes/s while the condition lasts.
                // The first occurrence always prints, so the failure is still
                // visible the moment it starts.
                uint32_t suppressed = 0;
                if (recv_error_log_.should_log(suppressed)) {
                    LOG_ERROR("server", fmt::format("UDP receive error: {}{}", ec.message(),
                                                    throttle_suffix(suppressed)));
                }
                park_receive_slot(index);
            }
        }
        return;
    }
    if (bytes_transferred == 0) {
        arm_receive_slot(index);
        return;
    }

    // stop() may have run while this receive was in flight: its session maps
    // are already swapped out, so routing now would insert an orphaned session
    // that is never ticked or swept. Every slot checks this independently --
    // one handler returning here says nothing about the others still in flight.
    if (!running_) return;

    const auto endpoint = recv_slots_[index].endpoint;
    byte_view data(recv_slots_[index].buf.data(), bytes_transferred);

    LOG_DEBUG("server", fmt::format("UDP recv {} bytes from {}:{}", bytes_transferred,
                                    endpoint.address().to_string(), endpoint.port()));

    route_datagram(endpoint, data);
    arm_receive_slot(index);
}

std::shared_ptr<KCPSession> KCPServer::route_datagram(
    const asio::ip::udp::endpoint& endpoint, byte_view data) {
    // Containment: this path performs every large allocation the server can be
    // talked into (the auth Crypto's EVP contexts, the ~20KB session object,
    // the per-datagram receive copy, the strand-dispatch closures). Any of
    // them throwing under memory pressure used to unwind out of io.run() and
    // kill the whole server -- every live session -- over one datagram. The
    // client contains the identical risk in handle_client_connection; this is
    // the server's counterpart. Drop the datagram instead: a genuine client
    // retransmits (KCP), the receive slot re-arms, the process survives.
    try {
        return route_datagram_impl(endpoint, data);
    } catch (const std::exception& e) {
        uint32_t suppressed = 0;
        if (route_exception_log_.should_log(suppressed)) {
            LOG_ERROR("server", fmt::format("datagram routing failed: {}{}", e.what(),
                                            throttle_suffix(suppressed)));
        }
        return nullptr;
    } catch (...) {
        uint32_t suppressed = 0;
        if (route_exception_log_.should_log(suppressed)) {
            LOG_ERROR("server", "datagram routing failed (unknown exception)");
        }
        return nullptr;
    }
}

std::shared_ptr<KCPSession> KCPServer::route_datagram_impl(
    const asio::ip::udp::endpoint& endpoint, byte_view data) {
    bool already_consumed = false;
    auto session = get_or_create_session(endpoint, data, already_consumed);
    if (!session) {
        // Throttled for the same reason as the rate-limit line in
        // get_or_create_session: one hostile datagram, one line, no upper bound.
        uint32_t suppressed = 0;
        if (drop_log_.should_log(suppressed)) {
            LOG_WARNING("server", fmt::format("packet dropped from {}:{} (no session created){}",
                                              endpoint.address().to_string(), endpoint.port(),
                                              throttle_suffix(suppressed)));
        }
        return nullptr;
    }
    if (!already_consumed) {
        LOG_DEBUG("server", session->session_id() + ": dispatching encrypted packet to session");
        // One strand dispatch: decrypt -> ikcp_input -> try_fulfill_read, then
        // run the session-driven logic (handle_kcp_data) in the SAME dispatch
        // so its KCP-state reads (peek_size/wait_send) are serialized with
        // the strand handlers that mutate KCP.
        //
        // `self` is not optional: these closures reach the server through a raw
        // `this`, and the session no longer pins it (its send callback is a
        // weak_ptr), so a queued handler must keep the server alive itself.
        auto self = shared_from_this();
        session->receive_data(data, [this, self, session, endpoint]() {
            handle_kcp_data(session, endpoint);
        });
    } else {
        LOG_DEBUG("server", session->session_id() + ": first packet already consumed (injected)");
        auto self = shared_from_this();
        asio::dispatch(session->strand(), [this, self, session, endpoint]() {
            handle_kcp_data(session, endpoint);
        });
    }
    return session;
}

void KCPServer::prune_salt_tombstones_locked() {
    // Every entry gets the same TTL, so insertion order IS expiry order: the
    // front of the queue is always the next one to drop, which makes the sweep
    // O(entries actually removed) instead of O(table size).
    const auto now = std::chrono::steady_clock::now();
    while (!salt_tombstone_order_.empty()) {
        auto it = salt_tombstones_.find(salt_tombstone_order_.front());
        if (it == salt_tombstones_.end()) {
            // Only reachable if an eviction dropped the map entry first; keep
            // the two containers in step rather than trusting that.
            salt_tombstone_order_.pop_front();
            continue;
        }
        if (it->second > now) break;
        salt_tombstones_.erase(it);
        salt_tombstone_order_.pop_front();
    }
}

void KCPServer::remember_salt_locked(
    std::string salt_key, std::chrono::steady_clock::time_point expiry) {
    prune_salt_tombstones_locked();
    // Bound the table by discarding the OLDEST tombstones. The alternative
    // (refusing the new session at the cap) let any authenticated peer -- or
    // ordinary churn above MAX_SALT_TOMBSTONES / SALT_TOMBSTONE_TTL_SEC
    // new sessions per second -- lock out every new session on the server for
    // the rest of the TTL, to protect a salt that was about to expire anyway.
    while (salt_tombstones_.size() >= MAX_SALT_TOMBSTONES) {
        if (salt_tombstone_order_.empty()) break;
        auto oldest = salt_tombstones_.find(salt_tombstone_order_.front());
        if (oldest != salt_tombstones_.end()) salt_tombstones_.erase(oldest);
        salt_tombstone_order_.pop_front();
    }
    salt_tombstone_order_.push_back(salt_key);
    // insert_or_assign, not emplace: the caller reaches here for a salt whose
    // tombstone is present-but-expired, and emplace would leave the stale
    // expiry in place.
    salt_tombstones_.insert_or_assign(std::move(salt_key), expiry);
}

void KCPServer::fill_salt_tombstones_for_test(size_t n) {
    std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
    const auto expiry = std::chrono::steady_clock::now() +
                        std::chrono::seconds(SALT_TOMBSTONE_TTL_SEC);
    for (size_t i = 0; i < n; ++i) {
        // Distinct 16-byte keys, the same width as a real session salt.
        std::string key(SESSION_SALT_SIZE, '\0');
        key[0] = static_cast<char>(i & 0xFF);
        key[1] = static_cast<char>((i >> 8) & 0xFF);
        key[2] = static_cast<char>((i >> 16) & 0xFF);
        key[3] = static_cast<char>((i >> 24) & 0xFF);
        remember_salt_locked(std::move(key), expiry);
    }
}

size_t KCPServer::salt_tombstone_count_for_test() {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    return salt_tombstones_.size();
}

void KCPServer::drop_replaced_target_locked(const std::string& sid) {
    auto conn_it = connections_.find(sid);
    if (conn_it == connections_.end()) {
        return;
    }
    auto sock = std::move(conn_it->second.tcp_socket);
    connections_.erase(conn_it);
    if (sock) {
        // The socket lives on its session's strand; close it there. A direct
        // close() here would be a cross-thread member call racing the forward
        // loop's in-flight async_read_some on the same object (-T > 1).
        // Queuing the close still aborts those pending operations, just from
        // the strand that owns them.
        asio::dispatch(sock->get_executor(), [sock]() mutable {
            std::error_code close_ec;
            sock->close(close_ec);
        });
    }
}

std::shared_ptr<KCPSession> KCPServer::get_or_create_session(
    const asio::ip::udp::endpoint& addr, byte_view encrypted_packet,
    bool& already_consumed) {
    already_consumed = false;
    std::string sid = fmt::format("{}:{}", addr.address().to_string(), addr.port());

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
    //
    // A LIVE session at this endpoint that is speaking a DIFFERENT salt is
    // either a genuine reconnect (the client reused its ephemeral source port)
    // or a forged datagram sent from a spoofed source. The salt rides in
    // cleartext, so the two are indistinguishable here -- and this check runs
    // BEFORE the auth decrypt below, which means acting on it would let a
    // single unauthenticated datagram tear down a live tunnel and its upstream
    // TCP connection (unthrottled: this is also upstream of the auth rate
    // limiter). So do NOT evict a live incumbent here. Remember that one exists
    // and replace it after the packet authenticates; only a dead/stopped
    // session, which holds nothing worth protecting, is reclaimed now.
    bool live_salt_mismatch = false;
    bool stale_replaced = false;
    bool cap_reached = false;
    bool log_client_fec_framed = false;
    FecConfig log_client_fec_value{};
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        auto it = sessions_.find(sid);
        if (it != sessions_.end()) {
            if (it->second && it->second->is_alive() && it->second->is_running()) {
                if (it->second->salt_matches(encrypted_packet)) {
                    return it->second;
                }
                live_salt_mismatch = true;
            } else {
                stale_replaced = true;
                if (it->second) {
                    it->second->stop();
                }
                sessions_.erase(it);
                drop_replaced_target_locked(sid);
            }
        }
        // The replacement below drops the incumbent, so it does not count
        // against the cap.
        const size_t effective =
            sessions_.size() - (live_salt_mismatch ? size_t{1} : size_t{0});
        cap_reached = effective >= MAX_CONCURRENT_SESSIONS;
    }
    // Logging happens OUTSIDE the write lock: every LOG_* takes the logger's
    // global mutex and a console stderr write can block for milliseconds,
    // which would stall every concurrent router and sweeper waiting on this
    // lock. Applies to every reject path below as well.
    if (stale_replaced) {
        LOG_DEBUG("server", sid + ": stale session found, replacing");
    }
    if (cap_reached) {
        // Pre-auth path: an unauthenticated flood at the cap would otherwise
        // emit one formatted WARNING per datagram and pin the logger mutex
        // (see session_cap_log_ in server.hpp).
        uint32_t suppressed = 0;
        if (session_cap_log_.should_log(suppressed)) {
            LOG_WARNING("server",
                        fmt::format("session cap reached ({}) dropping packet from {}{}",
                                    MAX_CONCURRENT_SESSIONS, sid, throttle_suffix(suppressed)));
        }
        return nullptr;
    }

    // Authenticate BEFORE allocating a per-session KCP+strand+timer.
    // Use the same replay-protected Crypto object that will be installed into
    // the session, so the first accepted packet seeds the replay window.
    //
    // Two-level auth throttle, protecting two different things:
    //   per-address FAILURE gate: an address that has repeatedly failed auth
    //     this window is a bad actor (garbage flood / wrong key / forger); its
    //     further packets are dropped BEFORE we pay for a decrypt. Counting
    //     failures, not attempts, is what keeps this safe for real clients: a
    //     genuine session decrypts successfully on its first packet and so never
    //     enters the table, however many concurrent tunnels its host opens.
    //   global attempt budget: bounds aggregate decrypt CPU no matter how many
    //     distinct sources contribute -- the only defense against a flood spread
    //     across many spoofed addresses (each contributing a single attempt).
    // Established sessions take the salt fast path above and never reach this
    // code. These fields are only touched on the socket's strand (every receive
    // completion is bound to it), so plain values are safe.
    {
        const auto now = auth_clock_();
        if (now - auth_window_start_ >= std::chrono::seconds(1)) {
            auth_attempts_window_ = 0;
            auth_window_start_ = now;
            auth_failures_by_addr_.clear();
        }
        const auto fail_it = auth_failures_by_addr_.find(addr.address());
        if (fail_it != auth_failures_by_addr_.end() &&
            fail_it->second >= MAX_AUTH_FAILURES_PER_ADDR_PER_SEC) {
            // Proven bad actor: drop without decrypting. Shares the throttle's
            // log line class -- one hostile datagram, one line, no upper bound.
            uint32_t suppressed = 0;
            if (auth_ratelimit_log_.should_log(suppressed)) {
                LOG_WARNING("server",
                            fmt::format("auth failure per-address rate limit reached, dropping "
                                        "packet from {}{}",
                                        sid, throttle_suffix(suppressed)));
            }
            return nullptr;
        }
        if (auth_attempts_window_ >= MAX_AUTH_ATTEMPTS_PER_SEC) {
            uint32_t suppressed = 0;
            if (auth_global_budget_log_.should_log(suppressed)) {
                LOG_WARNING(
                    "server",
                    fmt::format("auth attempt rate limit reached, dropping packet from {}{}", sid,
                                throttle_suffix(suppressed)));
            }
            return nullptr;
        }
        ++auth_attempts_window_;
    }

    LOG_DEBUG("server",
              fmt::format("{}: attempting auth decrypt on {} bytes", sid, encrypted_packet.size()));
    std::vector<uint8_t> decrypted;
    // server_mode=true: the first decrypted packet of a brand-new session seeds
    // the replay window (handled inside Crypto::decrypt) and is never rejected
    // as a replay. The client side always enforces the replay window from packet #1.
    auto session_crypto = std::make_shared<Crypto>(key_, NONCE_DIR_SERVER, byte_view{}, true);
    try {
        decrypted = session_crypto->decrypt(encrypted_packet);
        LOG_DEBUG("server", fmt::format("{}: auth OK, decrypted {} bytes", sid, decrypted.size()));
    } catch (const std::exception& e) {
        // Count this failure against the source address so a repeat offender is
        // dropped pre-decrypt next time (see the per-address gate above). Bounded
        // table: increment an existing entry, else insert only while under the
        // cap -- a spoofed flood that fills it just falls back to the global gate.
        const auto fit = auth_failures_by_addr_.find(addr.address());
        if (fit != auth_failures_by_addr_.end()) {
            ++fit->second;
        } else if (auth_failures_by_addr_.size() < MAX_TRACKED_AUTH_ADDRS) {
            auth_failures_by_addr_.emplace(addr.address(), 1);
        }
        // Throttled like the other per-datagram rejection diagnostics. The auth
        // limiter already bounds this to MAX_AUTH_ATTEMPTS_PER_SEC/s, but that is
        // still up to thousands of formatted WARNING lines per second handed to
        // an attacker for free. The first occurrence always prints, so the
        // robustness suite still finds FAIL_STAGE=DECRYPT_FAILED in the log.
        uint32_t suppressed = 0;
        if (decrypt_fail_log_.should_log(suppressed)) {
            LOG_WARNING("server",
                        fmt::format("FAIL_STAGE=DECRYPT_FAILED ERROR={} CLIENT_ENDPOINT={} "
                                    "TARGET=-{}",
                                    e.what(), sid, throttle_suffix(suppressed)));
        }
        return nullptr;
    }

    // Per-session FEC auto-adaptation (see the framing notes in config.hpp):
    // this first decrypted datagram either carries a FEC header (the client
    // speaks FEC) or is a bare KCP segment (it does not). The detection is
    // reliable — a bare segment's byte 4 is the KCP command (0x51..0x54),
    // disjoint from the FEC types — and it decides this session's framing in
    // BOTH directions: a FEC-speaking client gets FEC-framed replies, a bare
    // client gets bare replies. fec_ only supplies the shard parameters used
    // when adapting, so the two ends no longer have to agree on -fec for the
    // tunnel to work at all (the GUI defaults to FEC on, the service installer
    // to off — the exact mismatch that used to kill every handshake).
    const bool client_fec_framed =
        looks_like_fec_frame(decrypted.data(), decrypted.size());

    std::shared_ptr<KCPSession> session;
    size_t total_sessions = 0;
    bool authenticated_reconnect = false;
    // 拒绝原因只记枚举，日志文本在写锁释放后构造（字符串拼接是分配，锁内只做
    // 判定）。DuplicateSalt 需要冲突会话的 sid——锁释放后 map 可能被并发修改，
    // 必须拷贝，这是锁内仅剩的一次小分配。
    enum class RejectReason {
        None,
        SessionCap,
        DuplicateSalt,
        ReplayedSalt,
    };
    RejectReason rejection = RejectReason::None;
    std::string duplicate_salt_with;
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        // stop() sets stopped_ and swaps the session maps out under this same
        // write lock, so checking it here is atomic with that swap: without it
        // a packet in flight during shutdown would insert a session that is
        // never ticked or swept. (stopped_, not running_: running_ is also
        // false before start(), and tests drive route_datagram without it.)
        if (stopped_.load()) return nullptr;
        // Re-check under lock: another packet from this endpoint may have
        // beaten us here in a different I/O thread.
        auto it = sessions_.find(sid);
        if (it != sessions_.end()) {
            if (it->second && it->second->is_alive() && it->second->is_running() &&
                it->second->salt_matches(encrypted_packet)) {
                return it->second;
            }
            // This packet decrypted, so it is genuine: a live session still
            // holding this endpoint under a different salt is a real reconnect
            // on a reused source port rather than a forgery, and replacing it
            // is exactly what the deferred eviction above was waiting for.
            authenticated_reconnect = true;
            if (it->second) {
                it->second->stop();
            }
            sessions_.erase(it);
            drop_replaced_target_locked(sid);
        }
        if (sessions_.size() >= MAX_CONCURRENT_SESSIONS) {
            rejection = RejectReason::SessionCap;
        } else {
            // Duplicate-salt rejection: two sessions sharing a salt derive the same
            // per-session AEAD key. Because the nonce counter also starts from the
            // salt, a malicious client could force a same-key session against a live
            // target by simply reusing its salt, and AES-GCM nonce/IV reuse would be
            // catastrophic. Refuse to create a session whose salt a live session
            // already claims. (Any dead session for this endpoint, or a live one
            // this authenticated packet is replacing, was already erased above, so
            // a client reconnecting on the same source port with a fresh salt is
            // unaffected.)
            for (const auto& [other_sid, other] : sessions_) {
                if (other_sid == sid) continue;
                // Compare the salt FIRST. It is a 16-byte CRYPTO_memcmp, while
                // is_alive() reads the steady clock -- the previous order paid a
                // clock read for every one of up to MAX_CONCURRENT_SESSIONS
                // entries for every new session, which is work any authenticated
                // peer can request at will. Semantics are unchanged: a salt match
                // on a session the sweep has not reaped yet is still not a
                // duplicate.
                if (!other || !other->salt_matches(encrypted_packet)) continue;
                if (other->is_alive() && other->is_running()) {
                    duplicate_salt_with = other_sid;
                    rejection = RejectReason::DuplicateSalt;
                    break;
                }
            }
            // Cross-session replay guard: the live-session check above cannot see
            // a session that already died, but a replayed first datagram of a dead
            // session would still pass AEAD (same salt -> same derived key) and the
            // first-packet replay-window bypass would accept it -- including its
            // SOCKS5 CONNECT, which we would then execute for the attacker. Refuse
            // any salt accepted within the tombstone TTL. The check and the insert
            // are under this same write lock, so two concurrent first datagrams
            // sharing a salt cannot both win. Legitimate clients always generate a
            // fresh random salt per session, so they never hit their own
            // tombstones; the salt is already known-good here (the packet
            // decrypted successfully).
            if (rejection == RejectReason::None) {
                const byte_view salt = session_crypto->session_salt();
                const std::string salt_key(reinterpret_cast<const char*>(salt.data()), salt.size());
                const auto now = std::chrono::steady_clock::now();
                const auto tomb = salt_tombstones_.find(salt_key);
                if (tomb != salt_tombstones_.end() && tomb->second > now) {
                    rejection = RejectReason::ReplayedSalt;
                } else {
                    // Shard parameters for an adapting session: the
                    // operator's -fec when set (data flows even if the
                    // client runs different values; only parity repair
                    // needs agreement), else the documented default.
                    const FecConfig session_fec =
                        client_fec_framed ? (fec_.enabled() ? fec_
                                                            : FecConfig{FEC_ADAPTIVE_DATA_SHARDS,
                                                                        FEC_ADAPTIVE_PARITY_SHARDS})
                                          : FecConfig{};
                    if (client_fec_framed) {
                        // Deferred: logging inside the sessions_mutex_ write
                        // lock stalls every router/tick/sweep behind the
                        // console write (the file's own rule, see the
                        // stale_replaced note above).
                        log_client_fec_framed = true;
                        log_client_fec_value = session_fec;
                    }
                    session =
                        std::make_shared<KCPSession>(io_, KCP_CONV, addr, std::move(session_crypto),
                                                     sid, session_fec, adaptive_hooks());
                    // Record the tombstone only after the session exists: an
                    // insert that then lost make_shared() to an exception would
                    // blacklist a salt that was never accepted for the whole TTL.
                    remember_salt_locked(std::move(salt_key),
                                         now + std::chrono::seconds(SALT_TOMBSTONE_TTL_SEC));
                    // Set the send callback BEFORE publishing the session into sessions_.
                    // The shared update tick can dispatch on_update_tick (and therefore
                    // handle_kcp_output, which reads send_callback_) onto any thread the
                    // moment the session becomes visible in the map; with -T > 1, setting
                    // the callback after insertion would race with that read (the callback
                    // is a plain std::function, not atomic). Publishing under the write
                    // lock after full initialization keeps the handoff safe.
                    // weak, NOT strong. sessions_ already holds this session; a
                    // strong server reference here completes a two-node cycle
                    // (server -> session -> server), so ~KCPServer could never
                    // run while any session was still in its own map. The
                    // session may legitimately outlive the server at shutdown --
                    // dropping the datagram is then the right answer. Same
                    // reason drained_cb_ is a weak_ptr (see start_forwarding).
                    session->set_send_callback(
                        [w = weak_from_this(), addr](std::vector<std::vector<uint8_t>> data) {
                            auto server = w.lock();
                            if (!server) return;
                            server->send_batch_to_client(addr, std::move(data));
                        });
                    sessions_[sid] = session;
                    total_sessions = sessions_.size();
                }
            }
        }
    }

    if (authenticated_reconnect) {
        LOG_DEBUG("server", sid + ": authenticated reconnect, replacing session");
    }
    if (log_client_fec_framed) {
        LOG_DEBUG("server", sid + ": client speaks FEC, session framed " +
                  log_client_fec_value.to_string());
    }
    if (rejection != RejectReason::None) {
        // Auth-key holders can drive these (up to the auth budget, 5000/s);
        // every sibling rejection path is throttled, so this one is too.
        uint32_t suppressed = 0;
        if (auth_reject_log_.should_log(suppressed)) {
            std::string rejection_line;
            switch (rejection) {
                case RejectReason::SessionCap:
                    rejection_line =
                        fmt::format("session cap reached ({}), dropping packet from {}",
                                    MAX_CONCURRENT_SESSIONS, sid);
                    break;
                case RejectReason::DuplicateSalt:
                    rejection_line = fmt::format(
                        "duplicate session salt rejected: {} collides with live session {}",
                        sid, duplicate_salt_with);
                    break;
                case RejectReason::ReplayedSalt:
                    rejection_line = "replayed session salt rejected from " + sid;
                    break;
                case RejectReason::None:
                    break;
            }
            rejection_line += throttle_suffix(suppressed);
            LOG_WARNING("server", rejection_line);
        }
        return nullptr;
    }

    session->start();
    // Feed the already-decrypted bytes straight into ikcp.
    session->inject_decrypted(std::move(decrypted));
    already_consumed = true;

    LOG_INFO("server", fmt::format("new session: {} (total: {})", sid, total_sessions));
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

    LOG_DEBUG(
        "server",
        fmt::format("{}: handle_kcp_data, protocol_handshake_done={} socks5_handshake_done={}"
                    " forward_pending={} socks5_pending={} peek={} wait_send={}",
                    session->session_id(), static_cast<int>(session->is_protocol_handshake_done()),
                    static_cast<int>(session->is_handshake_done()),
                    static_cast<int>(session->is_forward_read_pending()),
                    static_cast<int>(session->is_socks5_read_pending()), session->peek_size(),
                    session->wait_send()));
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
                close_connection(session->session_id(), "protocol_handshake_read", session);
                return;
            }
            const std::string msg(reinterpret_cast<const char*>(buf->data()), bytes);
            // V2 is the same exchange plus FIN (half-close) support. A V1 peer,
            // and the SOCKS5 compatibility path below, never get a FIN: see
            // KCP_CONTROL_FIN. Note the ACK mirrors the request, so a V1 client
            // is not told about a capability this server would use anyway.
            const bool hello_v2 = (msg == KCP_CONTROL_HELLO_V2);
            if (msg != KCP_CONTROL_HELLO && !hello_v2) {
                session->mark_protocol_handshake_done();
                std::vector<uint8_t> initial(buf->begin(), buf->begin() + static_cast<std::ptrdiff_t>(bytes));
                LOG_INFO("server", session->session_id() +
                         ": no HELLO control frame; treating first KCP payload as SOCKS5 compatibility handshake");
                handle_socks5_request(session, std::move(initial));
                return;
            }
            session->mark_protocol_handshake_done();
            if (hello_v2) session->enable_fin();
            const char* ack = hello_v2 ? KCP_CONTROL_HELLO_ACK_V2 : KCP_CONTROL_HELLO_ACK;
            session->send_data(byte_view(reinterpret_cast<const uint8_t*>(ack),
                                         std::strlen(ack)));
            LOG_INFO("server", session->session_id() + ": KCP handshake confirmed" +
                     (hello_v2 ? " (V2, half-close enabled)" : ""));
            // A pipelining peer may have queued its SOCKS5 request in the same
            // KCP batch as the HELLO (it did not wait for the ACK). Such a
            // message has no other trigger: handle_kcp_data is driven only by
            // inbound datagrams, and the next one from a peer now waiting on
            // our reply is up to one keepalive interval (~30s) away -- every
            // such connection would stall. Re-drive the dispatcher now; it
            // no-ops on an empty queue. (We are on the session strand: this
            // handler completed through complete_pending_read.)
            handle_kcp_data(session, {});
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
        // The size bound lives at the append site (read_more_socks5's read
        // handler), which checks BEFORE inserting the next fragment. Checked
        // here, after the append, one full FWD_BUF_SIZE read still fit and
        // only the second read tripped the test, so the accumulator actually
        // grew to ~2x FWD_BUF_SIZE.
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
        // The client sees the failure reply and disconnects; close_connection
        // evicts the dead session from the table immediately (no 30s sweep wait).
        close_connection(session->session_id(), "socks5_invalid", session);
        return true;  // complete with error
    }

    // Success: parsed.request contains valid SOCKS5 request
    const auto& request = *parsed.request;
    LOG_INFO(
        "server",
        session->session_id() +
            (log_details ? fmt::format(": SOCKS5 connect target cmd={} atyp={} host={} port={}",
                                       request.cmd, request.atyp, request.host, request.port)
                         : fmt::format(": SOCKS5 CONNECT dst={}:{} cmd={}", request.host,
                                       request.port, request.cmd)));

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
        LOG_WARNING("server",
                    fmt::format("FAIL_STAGE=SOCKS5_UNSUPPORTED_COMMAND ERROR=cmd_{}"
                                " CLIENT_ENDPOINT={} TARGET={}:{}",
                                request.cmd, session->session_id(), request.host, request.port));
        send_socks5_reply(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
        // Same as the other failure paths: the client sees the reply and tears
        // the KCP session down; close_connection evicts it from the table at once.
        close_connection(session->session_id(), "socks5_unsupported_cmd", session);
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
            close_connection(session->session_id(), "socks5_read_error", session);
            return;
        }

        // Bound the accumulator BEFORE appending. A valid SOCKS5 request is at
        // most ~262 bytes (4 + 1 + 255 + 2), so FWD_BUF_SIZE is pure anti-DoS
        // headroom; the point is that the buffer can never exceed it.
        if (accum->size() + bytes > FWD_BUF_SIZE) {
            session->set_socks5_read_pending(false);
            LOG_ERROR("server", "FAIL_STAGE=SOCKS5_PARSE_FAILED ERROR=request_too_large CLIENT_ENDPOINT=" +
                      session->session_id() + " TARGET=-");
            send_socks5_reply(session, SOCKS5_REPLY_GENERAL_FAILURE);
            close_connection(session->session_id(), "socks5_too_large", session);
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
    LOG_INFO("server", fmt::format("{}: connecting to {}:{}", session->session_id(), request.host,
                                   request.port));

    // Built on the SESSION strand, not the raw io_context: with -T > 1 the
    // deadline handler's resolver->cancel()/tcp_socket->close() would
    // otherwise run on a different io thread than the in-flight
    // async_resolve/async_connect, and asio's contract forbids concurrent
    // member calls on a shared object. On the strand every handler in this
    // function (timeout, resolve, connect, initial write) is serialized with
    // each other and with the session's forward loops, which also bind to it.
    auto tcp_socket = std::make_shared<asio::ip::tcp::socket>(session->strand());
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(session->strand());
    auto deadline = std::make_shared<asio::steady_timer>(session->strand());
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
        LOG_WARNING("server", fmt::format("FAIL_STAGE=TCP_CONNECT_FAILED ERROR=connect_timeout_{}s"
                                          " CLIENT_ENDPOINT={} TARGET={}:{}",
                                          CONNECT_TIMEOUT_SEC, session->session_id(), request.host,
                                          request.port));
        send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
        close_connection(session->session_id(), "connect_timeout", session);
    });

    // SSRF guard (early): if the request host is a literal IP that is a
    // restricted target (loopback/private/link-local/etc.), refuse it without
    // even resolving, so the server can never be pointed at its own network.
    // An operator-supplied --allow-target entry explicitly overrides this for
    // lab/test targets (e.g. a local echo server); production traffic has an
    // empty allowlist and stays fully protected.
    {
        std::error_code ip_ec;
        const auto ip = asio::ip::make_address(request.host, ip_ec);
        if (!ip_ec && is_restricted_target(ip) && !is_target_allowed(request.host, request.port)) {
            if (fired->exchange(true)) return;
            std::error_code ignored;
            deadline->cancel(ignored);
            LOG_WARNING("server", fmt::format("FAIL_STAGE=SSRF_BLOCKED ERROR=restricted_target"
                                              " CLIENT_ENDPOINT={} TARGET={}:{}",
                                              session->session_id(), request.host, request.port));
            send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
            close_connection(session->session_id(), "ssrf_blocked", session);
            return;
        }
        if (!ip_ec && is_restricted_target(ip)) {
            LOG_WARNING("server", fmt::format("SSRF_ALLOWLISTED CLIENT_ENDPOINT={} TARGET={}:{}",
                                              session->session_id(), request.host, request.port));
        }
    }

    resolver->async_resolve(
        request.host, fmt::to_string(request.port),
        [this, session, request, tcp_socket, resolver, deadline, fired, self, initial_payload_buf](
            const std::error_code& ec, asio::ip::tcp::resolver::results_type results) mutable {
            if (fired->load()) return;
            if (ec) {
                if (fired->exchange(true)) return;
                std::error_code ignored;
                deadline->cancel(ignored);
                LOG_ERROR(
                    "server",
                    fmt::format("FAIL_STAGE=DNS_RESOLVE_FAILED ERROR={} CLIENT_ENDPOINT={}"
                                " TARGET={}:{}",
                                ec.message(), session->session_id(), request.host, request.port));
                send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
                close_connection(session->session_id(), "dns_resolve_failed", session);
                return;
            }

            // SSRF guard (post-resolve): every resolved endpoint must be
            // publicly reachable. A domain such as "localhost" or an internal
            // hostname would resolve to a restricted address and is refused
            // here. Rejecting the whole set if any endpoint is restricted
            // prevents DNS-rebinding-style partial allowances. An operator
            // --allow-target entry overrides this for explicitly named lab
            // targets.
            bool restricted = false;
            std::string restricted_addr;
            for (const auto& r : results) {
                if (is_restricted_target(r.endpoint().address())) {
                    restricted = true;
                    // Copy the address now: endpoint() may return by value, so
                    // holding a reference/pointer past the loop would dangle.
                    restricted_addr = r.endpoint().address().to_string();
                    break;
                }
            }
            if (restricted && !is_target_allowed(request.host, request.port)) {
                if (fired->exchange(true)) return;
                std::error_code ignored;
                deadline->cancel(ignored);
                LOG_WARNING("server", fmt::format("FAIL_STAGE=SSRF_BLOCKED ERROR=restricted_target"
                                                  " CLIENT_ENDPOINT={} TARGET={}:{} RESOLVED={}",
                                                  session->session_id(), request.host, request.port,
                                                  restricted_addr));
                send_socks5_reply(session, SOCKS5_REPLY_HOST_UNREACHABLE);
                close_connection(session->session_id(), "ssrf_blocked_postresolve", session);
                return;
            }

            LOG_INFO("server", fmt::format("{}: resolved {} to {} endpoints, connecting...",
                                           session->session_id(), request.host,
                                           std::distance(results.begin(), results.end())));
            asio::async_connect(*tcp_socket, results,
                [this, session, request, initial_payload_buf,
                 tcp_socket, resolver, deadline, fired, self]
                (const std::error_code& ec2, const asio::ip::tcp::endpoint&) mutable {
                    if (fired->exchange(true)) return;
                    std::error_code ignored;
                    deadline->cancel(ignored);
                    if (ec2) {
                        LOG_ERROR("server", fmt::format("FAIL_STAGE=TCP_CONNECT_FAILED ERROR={}"
                                                        " CLIENT_ENDPOINT={} TARGET={}:{}",
                                                        ec2.message(), session->session_id(),
                                                        request.host, request.port));
                        uint8_t reply = get_error_reply_code(ec2);
                        send_socks5_reply(session, reply);
                        close_connection(session->session_id(), "tcp_connect_failed", session);
                        return;
                    }

                    LOG_INFO("server",
                             fmt::format("{}: connected to target {}:{}", session->session_id(),
                                         request.host, request.port));

                    // Nagle would hold a short write (a small response tail, or
                    // the SOCKS5 reply path) until the previous segment is
                    // ACKed, adding ~RTT/2 of latency to exactly the kind of
                    // latency-sensitive traffic a proxy carries. The tunnel
                    // already batches, so coalescing here buys nothing.
                    {
                        std::error_code nodelay_ec;
                        tcp_socket->set_option(
                            asio::ip::tcp::no_delay(true), nodelay_ec);
                        if (nodelay_ec) {
                            LOG_DEBUG("server", session->session_id() +
                                      ": failed to set TCP_NODELAY: " +
                                      nodelay_ec.message());
                        }
                    }

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
                            // Identity check: if this session was already
                            // replaced (endpoint reuse on client reconnect) while
                            // the connect was in flight, do NOT re-insert the old
                            // socket under the new session's key -- the new
                            // session owns the endpoint now. Dropping our refs
                            // here closes the stale socket.
                            auto sit = sessions_.find(sid);
                            if (sit == sessions_.end() || sit->second != session) {
                                LOG_DEBUG("server", sid + ": connect completed for a replaced session, discarding");
                                return;
                            }
                            connections_[sid] = ClientConnection{tcp_socket};
                        }
                        // When the upstream target closes, keep the session alive
                        // until the target data already queued in KCP's send
                        // buffer has been delivered to the client (see
                        // handle_target_closed / KCPSession::on_update_tick), then
                        // close. This prevents truncating large responses whose
                        // tail is still in flight when the target closes.
                        // weak_ptr: the callback lives on the session itself, a
                        // strong capture would be a self-reference cycle. If it
                        // has expired, this session is gone and the sid (if
                        // present) belongs to a newer one -- skip the teardown.
                        //
                        // The server reference is weak for the same reason as
                        // send_callback_: this callback is stored ON the session,
                        // and the tick that invokes it (do_update_tick) dispatches
                        // with a weak reference and so holds no server lifetime.
                        // A raw `this` would be a use-after-free whenever a
                        // session outlives the server during shutdown.
                        //
                        // Strand discipline: drained_cb_ is a plain std::function
                        // that on_update_tick reads and moves ON the session
                        // strand. This connect completion handler runs on that
                        // same strand (tcp_socket was built on it), so a plain
                        // store here is serialized with the tick.
                        session->set_drained_callback(
                            [w = weak_from_this(), sid, s = std::weak_ptr<KCPSession>(session)]() {
                                auto server = w.lock();
                                if (!server) return;
                                if (auto session_s = s.lock()) {
                                    server->close_connection(sid, "target_drained", session_s);
                                }
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
                                    close_connection(sid, "initial_payload_write", session);
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
    LOG_WARNING("server",
                fmt::format("FAIL_STAGE=SOCKS5_UNSUPPORTED_COMMAND"
                            " ERROR=udp_associate_unsupported CLIENT_ENDPOINT={} TARGET={}:{}",
                            session->session_id(), request.host, request.port));
    send_socks5_reply(session, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
    close_connection(session->session_id(), "udp_associate_unsupported", session);
}

void KCPServer::send_socks5_reply(std::shared_ptr<KCPSession> session, uint8_t reply) {
    send_socks5_reply(session, reply, "", 0);
}

void KCPServer::send_socks5_reply(std::shared_ptr<KCPSession> session, uint8_t reply,
                                   std::string_view host, uint16_t port) {
    LOG_DEBUG("server", fmt::format("{}: sending SOCKS5 reply={} host={} port={}",
                                    session->session_id(), reply, host, port));
    SOCKS5Response resp;
    resp.reply = reply;
    resp.host = std::string(host);
    resp.port = port;
    auto data = resp.build();
    LOG_DEBUG("server",
              fmt::format("{}: SOCKS5 reply bytes ({})", session->session_id(), data.size()));
    session->send_data(byte_view(data.data(), data.size()));
}

void KCPServer::forward_tcp_to_kcp(std::string session_id, std::shared_ptr<KCPSession> session,
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
        asio::dispatch(session->strand(), [this, self, session_id = std::move(session_id), session,
                                           tcp_socket, buf]() mutable {
            forward_tcp_to_kcp(std::move(session_id), session, tcp_socket, buf);
        });
        return;
    }
    // Reuse one read buffer for the whole connection: send_data() on the strand
    // copies into KCP before we re-arm, so the buffer is free again immediately.
    if (!buf) buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);

    // The target has closed: the client->target direction is dead, so this loop
    // must simply stop. Reaching here with a closed target used to fall through
    // to the socket check below and tear the whole session down, dropping the
    // response tail that was still queued for the client -- a stale parked hook
    // resumed by a window drain is exactly how this can happen (the hook is
    // dropped in mark_target_closed, but a resume queued before that must be
    // absorbed here too). The session keeps draining via the drained callback,
    // mirroring the guard at the top of forward_kcp_to_tcp.
    if (session->is_target_closed()) {
        LOG_DEBUG("server", session_id + ": target closed, tcp->kcp loop stops");
        return;
    }

    LOG_DEBUG("server",
              fmt::format("{}: forward_tcp_to_kcp (tcp->kcp), wait_send={} running={}", session_id,
                          session->wait_send(), static_cast<int>(session->is_running())));
    if (!tcp_socket || !tcp_socket->is_open()) {
        LOG_ERROR("server", session_id + ": forward_tcp_to_kcp - socket not open");
        close_connection(session_id, "tcp2kcp_no_socket", session);
        return;
    }
    if (!session->is_running()) {
        LOG_ERROR("server", session_id + ": forward_tcp_to_kcp - session not running");
        // Pass the owner: this is often a stopped-but-replaced session whose
        // backpressure retry fires after a new session took over the endpoint.
        close_connection(session_id, "tcp2kcp_session_stopped", session);
        return;
    }

    // Backpressure: if KCP's send queue is already past the threshold, the
    // network can't keep up with what we're feeding in. Park the loop here and
    // let the session resume it the moment ACKs free window space (see
    // KcpTunnel::park_write) -- sleeping on a fixed timer and reading one buffer
    // per wakeup is what pinned every tunnel to ~3 Mbps on a 190ms path.
    // Safe to read wait_send here because we are on the strand.
    if (session->wait_send() >= kcp_tuning().backpressure_threshold()) {
        LOG_DEBUG(
            "server",
            fmt::format("{}: backpressure (wait_send={} >= threshold={}), parking read", session_id,
                        session->wait_send(), kcp_tuning().backpressure_threshold()));
        // The hook is stored INSIDE the session, so it must hold neither the
        // session nor the server strongly: either would be a reference cycle
        // (session -> hook -> session, and server -> sessions_ -> session ->
        // hook -> server). Weak refs make an already-torn-down owner simply
        // abandon the loop, which is exactly what a closed tunnel wants.
        std::weak_ptr<KCPSession> weak_session = session;
        std::weak_ptr<KCPServer> weak_self = shared_from_this();
        std::string sid = session_id;
        session->park_write([weak_self, sid, weak_session, tcp_socket, buf]() {
            auto s = weak_session.lock();
            auto server = weak_self.lock();
            if (!s || !server) return;
            server->forward_tcp_to_kcp(sid, s, tcp_socket, buf);
        });
        return;
    }

    auto self = shared_from_this();
    tcp_socket->async_read_some(
        asio::buffer(*buf),
        asio::bind_executor(
            session->strand(), [this, session_id = std::move(session_id), session, tcp_socket, buf,
                                self](const std::error_code& ec, size_t bytes) mutable {
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
                LOG_DEBUG("server",
                          fmt::format("{}: TCP >> KCP read {} bytes -> KCP send (wait_send={})",
                                      session_id, bytes, session->wait_send()));
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
    // The client half-closed: it will send no more data for the target, and the
    // write side of the target socket has already been shut down (see the eof
    // branch in the read handler below). Without this the loop would be re-armed
    // by every later packet and write into a socket that can no longer accept
    // it, which errors out and tears the session down before the target's
    // remaining response has been drained to the client.
    if (session->peer_fin_received()) {
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
        LOG_DEBUG("server",
                  session->session_id() + ": forward_kcp_to_tcp already active, skipping");
        return;
    }
    if (!buf) buf = std::make_shared<std::vector<uint8_t>>(FWD_BUF_SIZE);
    std::string sid = session->session_id();
    LOG_DEBUG("server",
              fmt::format("{}: forward_kcp_to_tcp (kcp->tcp), running={} forward_pending={}", sid,
                          static_cast<int>(session->is_running()),
                          static_cast<int>(session->is_forward_read_pending())));

    // Check if session is still running before initiating read.
    if (!session->is_running()) {
        LOG_INFO("server", sid + ": forward_kcp_to_tcp - session stopped");
        session->set_forward_read_pending(false);
        return;
    }

    std::shared_ptr<asio::ip::tcp::socket> tcp_sock;
    {
        std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
        // Identity check first: the map key is the peer endpoint, which a
        // reconnecting client reuses. A loop still queued on a replaced
        // session's strand would otherwise pick up the NEWER session's socket
        // and make asio member calls on it from the wrong strand (a contract
        // violation) while feeding the old client's bytes into the new target
        // connection. Same rule as start_forwarding and close_connection; the
        // invariant holds because connections_[sid] is only inserted once
        // sessions_[sid] is that session, and both are erased together.
        auto sit = sessions_.find(sid);
        if (sit == sessions_.end() || sit->second != session) {
            LOG_DEBUG("server", sid + ": forward_kcp_to_tcp - session no longer owns this endpoint");
            session->set_forward_read_pending(false);
            return;
        }
        auto it = connections_.find(sid);
        if (it == connections_.end() || !it->second.tcp_socket) {
            // DEBUG, not INFO: the handshake completes before start_forwarding()
            // inserts connections_[sid], so while the pipelined initial payload
            // write is in flight this fires once per client data packet.
            // INFO is lifecycle only (AGENTS.md #8).
            LOG_DEBUG("server", sid + ": forward_kcp_to_tcp - no TCP connection found");
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
    LOG_DEBUG("server", fmt::format("{}: async_read_some from KCP, buffer={}", sid, FWD_BUF_SIZE));
    session->async_read_some(asio::buffer(*buf), [this, sid, session, buf, tcp_sock, self](
                                                     const std::error_code& ec,
                                                     size_t bytes) mutable {
        if (ec == asio::error::eof) {
            // The client half-closed (FIN): it will send no more data for
            // the target. Pass that on rather than tearing the session down
            // -- the target->client direction may still have a whole
            // response to deliver, and closing here would truncate it.
            // shutdown_send (not close) so the target sees a clean FIN and
            // can still write its answer back.
            LOG_INFO("server", sid + ": client FIN received, closing target write side");
            session->set_forward_read_pending(false);
            if (tcp_sock && tcp_sock->is_open()) {
                std::error_code shutdown_ec;
                tcp_sock->shutdown(asio::ip::tcp::socket::shutdown_send, shutdown_ec);
            }
            return;
        }
        if (ec || bytes == 0) {
            if (ec && ec != asio::error::operation_aborted && ec != asio::error::already_started) {
                LOG_WARNING("server", "FAIL_STAGE=KCP_NO_RECV ERROR=" + ec.message() +
                                          " CLIENT_ENDPOINT=" + sid + " TARGET=-");
            } else if (bytes == 0 && !ec) {
                LOG_WARNING("server", "FAIL_STAGE=KCP_NO_RECV ERROR=zero_bytes CLIENT_ENDPOINT=" +
                                          sid + " TARGET=-");
            }
            close_connection(sid, "kcp2tcp_read", session);
            return;
        }

        // The target closed while this read was pending: client data can no
        // longer be delivered, so drop it and stop the loop instead of
        // writing to a closed socket (which would error and could tear the
        // session down before its queued target data finished draining).
        if (session->is_target_closed()) {
            LOG_DEBUG("server", fmt::format("{}: target closed, dropping {} bytes of client data",
                                            sid, bytes));
            session->set_forward_read_pending(false);
            return;
        }

        LOG_DEBUG("server", fmt::format("{}: KCP >> TCP read {} bytes -> TCP write", sid, bytes));
        asio::async_write(
            *tcp_sock, asio::buffer(buf->data(), bytes),
            asio::bind_executor(session->strand(), [this, sid, session, buf, tcp_sock, self](
                                                       const std::error_code& ec2,
                                                       size_t written) mutable {
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
                LOG_DEBUG("server",
                          fmt::format("{}: TCP write done ({} bytes), re-arming", sid, written));
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
        // wait_send() is read here on the session strand (this is reached from
        // forward_tcp_to_kcp's strand-bound read handler), so it is race-free.
        // The backlog is diagnostics: it reports how much target data was still
        // queued when the FIN arrived, i.e. how much the drained teardown had to
        // flush before the session could close. On a fast link this is only the
        // tail of the last TCP read, so do not read it as a queue gauge.
        LOG_INFO("server",
                 fmt::format("{}: target connection closed, draining queued data to client "
                             "(wait_send={})",
                             session->session_id(), session->wait_send()));
        session->mark_target_closed();
        // The target will produce no more data, so half-close towards the
        // client now. Queued after everything the target already sent (KCP is
        // ordered), so the client can stop reading the moment it arrives
        // instead of waiting out its KCP_TIMEOUT_SEC idle sweep. It is also
        // queued before the drain completes below, so wait_send() keeps the
        // session alive until the FIN itself has been ACKed -- no separate
        // linger phase is needed. No-op unless the peer negotiated V2.
        session->send_fin();
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

void KCPServer::close_connection(const std::string& session_id, const char* caller,
                                 const std::shared_ptr<KCPSession>& owner) {
    std::shared_ptr<asio::ip::tcp::socket> sock_to_close;
    std::shared_ptr<KCPSession> session_to_stop;
    bool skipped_replaced = false;
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);

        // Identity check: a teardown queued by a session that was already
        // replaced (client reconnect reusing the endpoint) or idle-reaped must
        // not tear down the NEWER session registered under the same sid. With
        // an owner, only proceed when the map still holds that exact session.
        if (owner) {
            auto sit = sessions_.find(session_id);
            if (sit == sessions_.end() || sit->second != owner) {
                skipped_replaced = true;
            }
        }
        if (!skipped_replaced) {
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
    }

    // Logging happens OUTSIDE the write lock: the logger's mutex plus a
    // possibly-slow stderr write must not extend this critical section (same
    // reasoning as get_or_create_session).
    if (skipped_replaced) {
        LOG_DEBUG("server", session_id + ": close_connection from " + std::string(caller) +
                  " skipped - session already replaced");
        return;
    }
    LOG_INFO("server", session_id + ": close_connection from " + std::string(caller));

    if (sock_to_close) {
        // The socket is owned by its session's strand (see
        // handle_connect_command); close it there so this never races the
        // forward loop's in-flight async_read_some. Every caller already runs
        // on that strand, so this executes inline in the normal path; the
        // dispatch only matters for the defensive session==nullptr path.
        asio::dispatch(sock_to_close->get_executor(), [sock_to_close]() mutable {
            if (sock_to_close->is_open()) {
                std::error_code ignored;
                sock_to_close->close(ignored);
            }
        });
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

    // Adaptive-parity sampling rides the same 10ms chain and fires every
    // FEC_PARITY_SAMPLE_MS worth of ticks. Doing it here (rather than in the
    // 30s cleanup sweep) keeps the reaction to a retransmit -- i.e. turning
    // parity back on -- within a couple of seconds on both ends. Runs on
    // tick_strand_, so the controller has exactly one writer.
    if (parity_ctl_ || rto_ctl_) {
        if (++parity_ticks_ >= FEC_PARITY_SAMPLE_TICKS) {
            parity_ticks_ = 0;
            sample_adaptive_policies();
        }
    }

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

// One adaptive-parity sample (every FEC_PARITY_SAMPLE_TICKS of the 10ms tick).
// INFO on a transition and only then: the switch is a rare lifecycle event of
// the transport policy, and it is the only way an operator learns that FEC
// parity silently stopped being emitted.
void KCPServer::sample_adaptive_policies() {
    const int64_t now = now_us();
    if (parity_ctl_) {
        const auto transition = parity_ctl_->sample(now);
        if (transition == FecParityController::Transition::kToEconomy) {
            LOG_INFO("server",
                     fmt::format("FEC adaptive: parity off after {}s of clean download traffic "
                                 "(no fast retransmits); a loss falls back to KCP retransmission",
                                 parity_ctl_->probe_sec()));
        } else if (transition == FecParityController::Transition::kToProtected) {
            LOG_INFO("server",
                     fmt::format("FEC adaptive: parity on - a client reported a retransmit; "
                                 "staying protected for {}s",
                                 parity_ctl_->hold_sec()));
        }
    }
    if (rto_ctl_) {
        const auto transition = rto_ctl_->sample(now);
        if (transition == RtoFloorController::Transition::kToRelaxed) {
            LOG_INFO("server",
                     fmt::format("RTO adaptive: floor 30ms -> 100ms after {}s of clean download "
                                 "traffic; queued datagrams are no longer mistaken for lost ones",
                                 rto_ctl_->relax_sec()));
        } else if (transition == RtoFloorController::Transition::kToLowLatency) {
            LOG_INFO("server",
                     fmt::format("RTO adaptive: floor 100ms -> 30ms - a client reported a "
                                 "retransmit; staying low-latency for {}s",
                                 rto_ctl_->hold_sec()));
        }
    }
}

void KCPServer::do_cleanup(const std::error_code& ec) {
    if (ec || !running_) return;

    std::vector<std::shared_ptr<KCPSession>> sessions_to_stop;
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> sockets_to_close;
    std::vector<std::string> dead_session_ids;
    std::vector<std::string> stalled_session_ids;
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

        // Find dead sessions: idle-reaped, or stalled short of completing the
        // SOCKS5 handshake (two independent conditions; see
        // KcpTunnel::handshake_stalled for why is_alive() cannot cover the
        // second one).
        for (auto& [sid, session] : sessions_) {
            if (!session) continue;
            if (session->is_alive()) {
                if (!session->handshake_stalled(SERVER_SOCKS5_HANDSHAKE_TIMEOUT_SEC)) continue;
                stalled_session_ids.push_back(sid);
            } else {
                dead_session_ids.push_back(sid);
            }
            sessions_to_stop.push_back(session);
            auto conn_it = connections_.find(sid);
            if (conn_it != connections_.end() && conn_it->second.tcp_socket) {
                sockets_to_close.push_back(conn_it->second.tcp_socket);
            }
        }

        // Erase collected sessions/connections
        for (const auto& sid : dead_session_ids) {
            sessions_.erase(sid);
            connections_.erase(sid);
        }
        for (const auto& sid : stalled_session_ids) {
            sessions_.erase(sid);
            connections_.erase(sid);
        }
        // Sweep expired salt tombstones (see get_or_create_session).
        prune_salt_tombstones_locked();
        // Report the post-sweep count so "sessions=N" is the live figure, not
        // the count captured before dead sessions were erased.
        active_sessions = sessions_.size();
    }

    // Timeout diagnostics are logged OUTSIDE the write lock (see
    // get_or_create_session): one console-bound INFO line per reaped session
    // must not extend the sweep's critical section.
    for (const auto& sid : dead_session_ids) {
        LOG_INFO("server", "FAIL_STAGE=SESSION_TIMEOUT ERROR=idle_timeout CLIENT_ENDPOINT=" +
                 sid + " TARGET=-");
    }
    for (const auto& sid : stalled_session_ids) {
        LOG_INFO("server", "FAIL_STAGE=SESSION_TIMEOUT ERROR=handshake_timeout CLIENT_ENDPOINT=" +
                 sid + " TARGET=-");
    }

    // Stop sessions and close sockets outside the lock
    for (auto& session : sessions_to_stop) {
        session->stop();
    }
    for (auto& sock : sockets_to_close) {
        if (!sock) continue;
        // The socket lives on its session's strand (handle_connect_command
        // builds it there); close it there. A direct close() from this timer
        // thread would race the forward loop's in-flight async_read_some on
        // the same object when the io_context runs with -T > 1.
        asio::dispatch(sock->get_executor(), [sock]() mutable {
            std::error_code ignored;
            sock->close(ignored);
        });
    }

    LOG_INFO(
        "server",
        fmt::format(
            "metrics sweep: sessions={} pkts_sent={} pkts_recv={} bytes_sent={} bytes_recv={}",
            active_sessions, total_pkts_sent, total_pkts_recv, total_bytes_sent, total_bytes_recv));

    cleanup_timer_.expires_after(std::chrono::seconds(30));
    // Hold a shared_ptr like every other async handler (start() does too), so
    // the timer chain keeps the server alive on its own.
    auto self = shared_from_this();
    cleanup_timer_.async_wait([this, self](const std::error_code& ec2) {
        do_cleanup(ec2);
    });
}

void KCPServer::send_to_client(const asio::ip::udp::endpoint& addr, std::vector<uint8_t> data) {
    // No udp_socket_ state may be inspected here: this runs on a per-session
    // strand while stop() closes the socket on the socket's own strand, and
    // asio forbids concurrent member calls on a shared object (is_open() reads
    // the non-atomic socket state). The identical guard runs inside the
    // dispatch below, on the executor it belongs to.

    LOG_DEBUG("server", fmt::format("send_to_client: sending {} bytes to {}:{}", data.size(),
                                    addr.address().to_string(), addr.port()));

    // Pooled holder: one fused allocation per datagram (control block +
    // holder); the buffer itself recycles when the async send completes.
    auto buf = make_pooled_send(std::move(data));
    // Initiation is routed through the socket's strand. This is called from a
    // per-session strand (the session's send callback), while the receive path
    // re-arms on the io_context; with -T > 1 those are different threads, and
    // asio sockets are shared objects -- concurrent initiation on one is not
    // allowed. Capture self so the server stays alive until the initiation runs.
    auto self = shared_from_this();
    asio::dispatch(udp_socket_.get_executor(), [this, self, buf, addr]() {
        if (!running_ || !udp_socket_.is_open()) {
            return;
        }
        initiate_send_to(addr, buf);
    });
}

void KCPServer::send_batch_to_client(const asio::ip::udp::endpoint& addr,
                                     std::vector<std::vector<uint8_t>> batch) {
    if (batch.empty()) return;
    if (batch.size() == 1) {
        // Degenerate burst: identical to the single-datagram path.
        send_to_client(addr, std::move(batch[0]));
        return;
    }
    LOG_DEBUG("server", fmt::format("send_batch_to_client: {} datagrams to {}:{}", batch.size(),
                                    addr.address().to_string(), addr.port()));
    auto self = shared_from_this();
    asio::dispatch(
        udp_socket_.get_executor(), [this, self, batch = std::move(batch), addr]() mutable {
            if (!running_ || !udp_socket_.is_open()) {
                return;
            }
#if defined(__linux__)
            // Chunked sendmmsg: the whole burst leaves in ~batch/64 syscalls
            // instead of one per datagram. MSG_DONTWAIT keeps the strand
            // non-blocking; whatever the kernel queue refuses right now falls
            // through to the per-datagram async path, which parks on writability
            // instead of spinning. One copy of the peer address: the kernel
            // only reads msg_name on send, but it wants a writable void*, and
            // endpoint::data() hands out a const pointer.
            int fd = udp_socket_.native_handle();
            sockaddr_storage peer_sa{};
            std::memcpy(&peer_sa, addr.data(), addr.size());
            size_t idx = 0;
            while (idx < batch.size()) {
                const size_t n = std::min(batch.size() - idx, UDP_BATCH_MAX);
                struct mmsghdr msgs[UDP_BATCH_MAX];
                struct iovec iov[UDP_BATCH_MAX];
                for (size_t i = 0; i < n; ++i) {
                    iov[i].iov_base = batch[idx + i].data();
                    iov[i].iov_len = batch[idx + i].size();
                    std::memset(&msgs[i], 0, sizeof(msgs[i]));
                    msgs[i].msg_hdr.msg_name = &peer_sa;
                    msgs[i].msg_hdr.msg_namelen = static_cast<socklen_t>(addr.size());
                    msgs[i].msg_hdr.msg_iov = &iov[i];
                    msgs[i].msg_hdr.msg_iovlen = 1;
                }
                ssize_t sent = ::sendmmsg(fd, msgs, n, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                    sent = 0; // nothing accepted this round: remainder goes async
                }
                if (sent < 0) break; // unexpected: let the async path surface it
                for (size_t i = 0; i < static_cast<size_t>(sent); ++i) {
                    datagram_pool().release(std::move(batch[idx + i]));
                }
                idx += static_cast<size_t>(sent);
                if (static_cast<size_t>(sent) < n) break;
            }
            LOG_DEBUG("server", fmt::format("sendmmsg: {} of {} datagrams accepted by the kernel",
                                            idx, batch.size()));
            for (size_t i = idx; i < batch.size(); ++i) {
                initiate_send_to(addr, make_pooled_send(std::move(batch[i])));
            }
            return;
#endif
            // Non-Linux (and the Linux fallback for unsent datagrams is above, so
            // this only runs off-Linux): per-datagram async initiation, unchanged
            // from the pre-batching behavior.
            for (auto& d : batch) {
                initiate_send_to(addr, make_pooled_send(std::move(d)));
            }
        });
}

void KCPServer::initiate_send_to(const asio::ip::udp::endpoint& addr,
                                 std::shared_ptr<std::vector<uint8_t>> buf) {
    udp_socket_.async_send_to(
        asio::buffer(*buf), addr,
        [buf, addr, this, self = shared_from_this()](const std::error_code& ec, size_t bytes_sent) {
            if (ec && ec != asio::error::operation_aborted) {
                // One completion per datagram, so an unthrottled line
                // here is one line per packet whenever sends fail.
                uint32_t suppressed = 0;
                if (send_error_log_.should_log(suppressed)) {
                    LOG_ERROR("server", fmt::format("FAIL_STAGE=UDP_SEND_FAILED ERROR={}"
                                                    " CLIENT_ENDPOINT={}:{} TARGET=-{}",
                                                    ec.message(), addr.address().to_string(),
                                                    addr.port(), throttle_suffix(suppressed)));
                }
            } else if (!ec) {
                LOG_DEBUG("server", fmt::format("UDP sent {} bytes to {}:{}", bytes_sent,
                                                addr.address().to_string(), addr.port()));
            }
        });
}

uint8_t KCPServer::get_error_reply_code(const std::error_code& ec) {
    if (ec == asio::error::connection_refused) return SOCKS5_REPLY_CONNECTION_REFUSED;
    if (ec == asio::error::network_unreachable) return SOCKS5_REPLY_NETWORK_UNREACHABLE;
    if (ec == asio::error::host_unreachable) return SOCKS5_REPLY_HOST_UNREACHABLE;
    if (ec == asio::error::timed_out) return SOCKS5_REPLY_HOST_UNREACHABLE;
    return SOCKS5_REPLY_GENERAL_FAILURE;
}

} // namespace kcp_proxy
