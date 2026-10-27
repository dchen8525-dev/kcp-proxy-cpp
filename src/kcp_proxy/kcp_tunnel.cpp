#include "kcp_proxy/kcp_tunnel.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/time_util.hpp"
#include "kcp/internal/constants.h"
#include "kcp/internal/fec.h"
#include <fmt/format.h>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace kcp_proxy {

// One throttle for the whole process. The condition it guards is a *static
// misconfiguration*, so the goal is "impossible to miss, impossible to flood":
// the first datagram of every peer warns immediately, and repeated datagrams
// fold into a count, exactly like log_kcp_input_rejected.
LogThrottle& fec_peer_only_log() {
    static LogThrottle throttle;
    return throttle;
}

KcpTunnel::KcpTunnel(asio::io_context& io, uint32_t conv,
                     std::shared_ptr<Crypto> crypto,
                     std::string log_module, std::string log_tag,
                     const FecConfig& fec)
    : io_(io),
      strand_(asio::make_strand(io.get_executor())),
      crypto_(std::move(crypto)),
      kcp_(conv),
      created_us_(now_us()),
      log_module_(std::move(log_module)),
      log_tag_(std::move(log_tag)) {
    const int64_t now = now_us();
    last_activity_us_.store(now);
    last_keepalive_us_.store(now);
    if (fec.enabled()) {
        // header_offset = FEC_CRYPTO_RESERVE: the salt+nonce stay in cleartext
        // in front of the AEAD plaintext, exactly like kcp-go's sess.headerSize
        // layering. New() cannot fail here — parse_fec_config already gates
        // every configuration it could reject — so a null would be a
        // programming error, and throwing fails the session loudly instead of
        // silently mismatching the peer's FEC framing.
        fec_encoder_ = kcp::internal::FecEncoder::New(
            fec.data_shards, fec.parity_shards,
            static_cast<int>(FEC_CRYPTO_RESERVE));
        fec_decoder_ = kcp::internal::FecDecoder::New(
            fec.data_shards, fec.parity_shards);
        if (!fec_encoder_ || !fec_decoder_) {
            LOG_ERROR(log_module_, log_msg("FEC codec creation failed for " +
                      fec.to_string()));
            throw std::runtime_error("FEC codec creation failed");
        }
        // Pre-size the reusable send frame for the largest possible KCP
        // datagram (FEC_DATAGRAM_MAX); Encode/resize keep it exact below.
        fec_send_buf_.reserve(FEC_DATAGRAM_MAX);
    }
    LOG_DEBUG(log_module_, log_msg(fmt::format("created conv={} fec={}", conv, fec.to_string())));
    kcp_.set_output_callback([this](byte_view data) {
        // Always invoked from strand_ (KCP only runs there).
        on_kcp_datagram(data);
    });
}

KcpTunnel::~KcpTunnel() = default;

void KcpTunnel::on_kcp_datagram(byte_view data) {
    if (!fec_encoder_) {
        // FEC disabled: the wire stays byte-identical to pre-FEC peers.
        handle_kcp_output(data);
        return;
    }
    // Frame the datagram: [crypto reserve(28)][fec_hdr(6)][len(2)][payload].
    // The 28-byte reserve is never written here — handle_kcp_output's
    // encrypt_into treats the region from offset FEC_CRYPTO_RESERVE as the
    // AEAD plaintext and writes its own salt+nonce in front of it, exactly
    // like kcp-go's session writes over the headerOffset region.
    const size_t frame_size = FEC_CRYPTO_RESERVE + 8 + data.size();
    fec_send_buf_.resize(frame_size);
    std::memcpy(fec_send_buf_.data() + FEC_CRYPTO_RESERVE + 8,
                data.data(), data.size());
    fec_parity_.clear();
    // Burst-continuity window = the live RTT-derived RTO, like kcp-go's
    // sess.rto: a shard set spread wider than one RTO is not a burst, and the
    // encoder skips its parity while still advancing the seqid.
    fec_encoder_->Encode(fec_send_buf_.data(), frame_size, kcp_.rto(),
                         &fec_parity_);
    // The data shard first, in order, then the parity shards of this set.
    handle_kcp_output(byte_view(fec_send_buf_.data() + FEC_CRYPTO_RESERVE,
                                frame_size - FEC_CRYPTO_RESERVE));
    for (const auto& parity : fec_parity_) {
        // A parity FecPacket is one full-size buffer whose first
        // FEC_CRYPTO_RESERVE bytes are dead weight for the crypto layer, just
        // like a data packet — skip straight to the FEC header.
        handle_kcp_output(byte_view(parity.data() + FEC_CRYPTO_RESERVE,
                                    parity.size() - FEC_CRYPTO_RESERVE));
    }
}

int KcpTunnel::feed_kcp_input(const uint8_t* data, size_t size) {
    if (!fec_decoder_) {
        // Local FEC is off, so the peer must be sending bare KCP segments. If
        // the header instead carries a FEC type, the peer HAS -fec enabled and
        // this side does not -- the mirror image of the ret_=-2 arm below.
        // Without this check the mismatch was diagnosable only from the side
        // that had FEC on; the FEC-off side just logged the generic
        // "FAIL_STAGE=KCP_INPUT_FAILED ERROR=ret_-1" that ikcp_input produces
        // for any malformed segment, which says nothing about the cause.
        //
        // Still hand the datagram to KCP: the bytes are real KCP segments
        // wrapped in an 8-byte FEC prefix, and refusing early would change
        // behaviour for a case that already cannot work. The reject line that
        // ikcp_input generates stays as the FAIL_STAGE record of truth.
        if (looks_like_fec_frame(data, size)) {
            uint32_t suppressed = 0;
            if (fec_peer_only_log().should_log(suppressed)) {
                std::string line =
                    "peer is sending FEC-framed datagrams but local --fec is off "
                    "(enable --fec with the SAME DATA:PARITY, or clear it on the peer)";
                line += throttle_suffix(suppressed);
                LOG_WARNING(log_module_, log_msg(line));
            }
        }
        return kcp_.input(byte_view(data, size));
    }
    // One decrypted FEC packet: [fec_hdr(6): seqid(4)+type(2)][len(2)][payload].
    if (size < 8) {
        // Too short to even carry an FEC header + length field — same refusal
        // semantics as a truncated KCP segment.
        return -2;
    }
    const uint16_t flag = static_cast<uint16_t>(data[4]) |
                          static_cast<uint16_t>(data[5] << 8);
    int ret = 0;
    if (flag == kcp::kTypeData) {
        // The length field counts itself (fec.go:406): the encoder writes
        // declared = size - payload_offset(6), so declared already covers the
        // 2-byte length field plus the payload and must span the packet minus
        // its 6-byte FEC header exactly.
        const uint16_t declared = static_cast<uint16_t>(data[6]) |
                                  static_cast<uint16_t>(data[7] << 8);
        // declared == 2 means an empty payload; the encoder never emits one (a
        // KCP datagram always carries its 24-byte segment header), so treat it
        // as a framing error rather than handing KCP a zero-length input.
        if (declared <= 2 || declared + 6 != size) {
            // The AEAD already authenticated this datagram, so a framing
            // mismatch means the two peers disagree about FEC parameters (or a
            // bridge mangled the stream). Refuse like a truncated KCP segment:
            // the caller's throttled KCP_INPUT_FAILED line makes the condition
            // visible without per-packet spam.
            LOG_DEBUG(log_module_,
                      log_msg(fmt::format("fec data framing mismatch: {} bytes, declared={}", size,
                                          declared)));
            return -2;
        }
        ret = kcp_.input(byte_view(data + 8, size - 8));
    } else if (flag != kcp::kTypeParity && flag != kcp::kTypeOob) {
        // Not a FEC type at all. This is what a peer with a DIFFERENT -fec
        // setting looks like: an unframed KCP segment puts its cmd byte at
        // offset 4 (0x51..0x54) and its frg at 5, so the flag lands nowhere
        // near 0xf1..0xf3. Reporting success here would make a parameter
        // mismatch completely silent -- the tunnel would connect at the UDP
        // level and carry nothing, with no FAIL_STAGE line anywhere. Refuse
        // instead so the mismatch is as loud as the docs promise.
        LOG_DEBUG(log_module_, log_msg(fmt::format("fec packet type mismatch: flag={} size={} "
                                                   "(peers disagree about -fec)",
                                                   flag, size)));
        return -2;
    }
    // Every packet that reached this point (data and parity) must also feed the
    // decoder so shard sets complete; it returns only the shards the codec had
    // to rebuild. The result is a by-value vector, so the kcp_.input() calls
    // below (which may synchronously flush and therefore re-enter
    // on_kcp_datagram) cannot invalidate this loop.
    for (auto& rebuilt : fec_decoder_->Decode(data, size)) {
        // A rebuilt shard is the payload region of one data packet, i.e.
        // [len(2)|payload|zero-pad...]: the decoder zero-extends shards to
        // the set's maxlen before reconstruction, so the declared prefix is
        // what matters. The len field counts itself (declared = 2 + payload).
        if (rebuilt.size() < 2) continue;
        const uint16_t declared = static_cast<uint16_t>(rebuilt[0]) |
                                  static_cast<uint16_t>(rebuilt[1] << 8);
        if (declared <= 2 || declared > rebuilt.size()) {
            LOG_DEBUG(log_module_,
                      log_msg(fmt::format("fec rebuilt framing mismatch: {} bytes, declared={}",
                                          rebuilt.size(), declared)));
            continue;
        }
        const int r = kcp_.input(byte_view(rebuilt.data() + 2,
                                           declared - 2));
        if (r >= 0) {
            metrics_.fec_repaired.fetch_add(1, std::memory_order_relaxed);
        } else {
            LOG_DEBUG(log_module_,
                      log_msg(fmt::format("fec rebuilt shard refused by kcp input: ret={}", r)));
        }
    }
    return ret;
}

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

bool KcpTunnel::handshake_stalled(int64_t timeout_sec) const {
    if (handshake_done_.load(std::memory_order_relaxed)) return false;
    return (now_us() - created_us_) >= timeout_sec * 1000000;
}

void KcpTunnel::mark_handshake_done() {
    handshake_done_.store(true);
}

void KcpTunnel::send_fin() {
    // Latch the request, then try once now. Must run on the strand; the tick
    // re-drives via retry_pending_fin() until the segment is queued or the
    // tunnel dies.
    fin_requested_.store(true);
    do_send_fin();
}

void KcpTunnel::retry_pending_fin() {
    if (!fin_requested_.load()) return;
    if (fin_sent_.load()) return;
    // wait_send() >= KCP_SNDWND is exactly ikcp_send's refusal condition
    // (see the KCP_BACKPRESSURE_THRESHOLD note in config.hpp). Gating here
    // keeps a window that cannot drain (dead peer, pending drain) from
    // turning the 10ms tick into a futile retry every interval.
    if (kcp_.wait_send() >= KCP_SNDWND) return;
    do_send_fin();
}

void KcpTunnel::do_send_fin() {
    if (!fin_enabled_.load()) return;
    if (!is_active()) return;
    // At most one FIN per tunnel: the caller may reach here from more than one
    // teardown path (e.g. a target read EOF and a later write error). The
    // once-per-tunnel budget is only consumed when the segment is actually
    // queued -- a refused ikcp_send queues nothing, and losing the FIN
    // permanently would leave the peer waiting out its idle timeout for an
    // end-of-stream it will never see.
    if (fin_sent_.load()) return;
    auto body = build_control_payload(KCP_CONTROL_FIN);
    const size_t len = body.size();
    if (kcp_.send(byte_view(body.data(), len)) < 0) {
        // Transient: the window drains as the peer ACKs and retry_pending_fin
        // re-drives from the tick.
        LOG_DEBUG(log_module_, log_msg("FIN send refused (window full), will retry"));
        return;
    }
    fin_sent_.store(true);
    kcp_.update(now_kcp_ms());
    kcp_.flush();
    LOG_INFO(log_module_, log_msg("FIN sent (half-close)"));
}

void KcpTunnel::park_write(std::function<void()> resume) {
    // Called on the strand by the forwarding loop that just found the send queue
    // full. Replacing an existing hook is correct: at most one loop writes into
    // KCP per tunnel, so a second park can only be a re-park of the same loop
    // after a resume that found the queue full again.
    write_resume_cb_ = std::move(resume);
    LOG_DEBUG(log_module_,
              log_msg(fmt::format("write loop parked, wait_send={}", kcp_.wait_send())));
}

void KcpTunnel::unpark_write() {
    if (!write_resume_cb_) return;
    write_resume_cb_ = nullptr;
    LOG_DEBUG(log_module_, log_msg("write loop unparked (teardown)"));
}

void KcpTunnel::maybe_resume_write() {
    if (!write_resume_cb_) return;
    // Still too full to accept another message: stay parked. The check is
    // against the low watermark, not the park threshold, so a wakeup always
    // admits at least KCP_BACKPRESSURE_BURST_MSGS messages' worth of room.
    if (kcp_.wait_send() > KCP_BACKPRESSURE_RESUME_THRESHOLD) return;

    // Take-and-clear BEFORE invoking: the resumed loop usually parks again
    // immediately (the queue refills in a few messages), and it must be able to
    // install a fresh hook rather than have this call clobber it afterwards.
    auto resume = std::move(write_resume_cb_);
    write_resume_cb_ = nullptr;
    LOG_DEBUG(log_module_,
              log_msg(fmt::format("write loop resumed, wait_send={}", kcp_.wait_send())));
    resume();
}

std::string KcpTunnel::stats_summary() const {
    const auto& m = metrics_;
    return log_msg(fmt::format(
        "stats tx_pkt={} tx_bytes={} rx_pkt={} rx_bytes={} "
        "replay_dropped={} decrypt_err={} encrypt_err={} send_err={} "
        "fec_repaired={}",
        m.udp_tx_packets.load(std::memory_order_relaxed),
        m.udp_tx_bytes.load(std::memory_order_relaxed),
        m.udp_rx_packets.load(std::memory_order_relaxed),
        m.udp_rx_bytes.load(std::memory_order_relaxed),
        m.replay_dropped.load(std::memory_order_relaxed),
        m.decrypt_errors.load(std::memory_order_relaxed),
        m.encrypt_errors.load(std::memory_order_relaxed),
        m.send_errors.load(std::memory_order_relaxed),
        m.fec_repaired.load(std::memory_order_relaxed)));
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
    LOG_DEBUG(log_module_, log_msg(fmt::format("on_send {} bytes", data.size())));
    int send_ret = kcp_.send(data);
    if (send_ret < 0) {
        // A KCP-layer refusal (send window full), not a crypto failure -- it
        // gets its own counter so encrypt_errors stays a pure AEAD signal.
        metrics_.send_errors.fetch_add(1, std::memory_order_relaxed);
        LOG_ERROR(log_module_,
                  log_msg(fmt::format("ikcp_send failed, ret={}, closing session", send_ret)));
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
        // Post to the session strand (like complete_pending_read does), never
        // to the raw io_context: the forwarding loops treat their read
        // completion as strand-confined, and a raw-io post would break that
        // affinity when the io_context runs on more than one thread.
        auto self = shared_from_this();
        asio::post(strand_, [self, h = std::move(h)]() mutable {
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
        auto self = shared_from_this();
        asio::post(strand_, [self, h = std::move(h)]() mutable {
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
    //
    // The sentinel is the magic string scoped by this session's salt, so a
    // genuine payload can never be mistaken for it: the full keepalive is
    // "KCP_PROXY_KEEPALIVE_V1" || session_salt (16 random bytes), and matching
    // requires the salt exactly. A real segment carrying the bare 22-byte magic
    // (previously ambiguous) is forwarded normally.
    if (is_keepalive(kcp_recv_buf_.data(), static_cast<size_t>(size))) {
        LOG_DEBUG(log_module_, log_msg("keepalive received, dropping"));
        return;
    }

    // The peer half-closed. Like the keepalive this is a control message and not
    // stream data, but unlike it the pending read must complete: the caller's
    // forwarding loop is the only thing that can act on "no more data will
    // come", and complete-with-eof is the signal it already understands. KCP is
    // ordered, so everything the peer queued before the FIN has been handed to
    // the caller already -- nothing is lost by stopping there.
    if (is_peer_fin(kcp_recv_buf_.data(), static_cast<size_t>(size))) {
        LOG_INFO(log_module_, log_msg("peer FIN received (half-close)"));
        peer_fin_received_.store(true);
        complete_pending_read(asio::error::eof);
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
    // Salt is guaranteed set: it is learned before the handshake sequence that
    // set handshake_done_ (client generates it at construction; server learns
    // it from the first datagram). Send magic || salt so the peer can unambigu-
    // ously recognize the heartbeat and never mistake it for tunnel data.
    auto kb = build_keepalive_payload();
    const size_t klen = kb.size();
    // ikcp_send returns the number of bytes queued (>= 0) on success, NOT 0 --
    // compare against < 0 or the throttle never engages and a keepalive is
    // injected on every 10ms tick once the interval passes.
    if (kcp_.send(byte_view(kb.data(), klen)) >= 0) {
        last_keepalive_us_.store(now);
        LOG_DEBUG(log_module_, log_msg("keepalive sent"));
    }
}

// Control-message body = magic || session_salt. Requires the salt (shared with
// the peer); a tunnel that has not learned it (e.g. server before the first
// packet) has an empty payload so nothing is forwarded as if it were a control
// message.
std::vector<uint8_t> KcpTunnel::build_control_payload(const char* magic) const {
    std::vector<uint8_t> body;
    const std::string_view m = magic;
    body.insert(body.end(), m.begin(), m.end());
    const byte_view salt = crypto_->session_salt();
    body.insert(body.end(), salt.begin(), salt.end());
    return body;
}

std::vector<uint8_t> KcpTunnel::build_keepalive_payload() const {
    return build_control_payload(KCP_CONTROL_KEEPALIVE);
}

bool KcpTunnel::is_control(const uint8_t* data, size_t size, const char* magic) const {
    const byte_view salt = crypto_->session_salt();
    const size_t magic_len = std::strlen(magic);
    if (size != magic_len + salt.size()) return false;
    if (std::memcmp(data, magic, magic_len) != 0) return false;
    if (salt.size() > 0 && std::memcmp(data + magic_len, salt.data(), salt.size()) != 0) return false;
    return true;
}

bool KcpTunnel::is_keepalive(const uint8_t* data, size_t size) const {
    return is_control(data, size, KCP_CONTROL_KEEPALIVE);
}

bool KcpTunnel::is_peer_fin(const uint8_t* data, size_t size) const {
    return is_control(data, size, KCP_CONTROL_FIN);
}

} // namespace kcp_proxy
