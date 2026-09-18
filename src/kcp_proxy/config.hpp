#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace kcp_proxy {

// KCP configuration (matches Python implementation exactly)
// Conversation id. Every session on the wire carries it, so both peers must
// use the same value or ikcp silently discards the peer's packets.
constexpr uint32_t KCP_CONV = 1;
constexpr int KCP_INTERVAL_MS = 10;
constexpr int KCP_SNDWND = 256;
constexpr int KCP_RCVWND = 512;
constexpr int KCP_MTU = 1400;
// ikcp_nodelay() tuning. Named constants (instead of literals at the call
// site) so the startup log and the live ikcp state can never drift apart —
// the log renders these exact values.
constexpr int KCP_NODELAY = 1; // 1 = enable nodelay (low-latency mode)
constexpr int KCP_RESEND = 5;  // fast-retransmit after N skipped ACKs
constexpr int KCP_NC = 1;      // 1 = disable congestion control
// ikcp per-segment wire header overhead (conv4+cmd1+frg1+wnd2+ts4+sn4+una4+len4).
constexpr int KCP_SEGMENT_OVERHEAD = 24;
constexpr int KCP_TIMEOUT_SEC = 60;
// Application-layer keepalive: if a session has been idle for longer than this,
// send a small KCP heartbeat so the peer's idle sweep does not kill a live but
// quiet tunnel (e.g. an idle SSH session). Must be < KCP_TIMEOUT_SEC.
constexpr int KCP_KEEPALIVE_SEC = 30;

// Client-side half-close grace (seconds). When the local app closes its write
// side the client deliberately half-closes the tunnel instead of tearing it
// down, so a response that is still in flight is not truncated. That leaves the
// tunnel in a state neither idle sweep can ever reap: the application-layer
// keepalives keep refreshing BOTH peers' idle clocks (each side only stops
// sending them once its own session is gone), so a half-closed tunnel whose
// target never closes would survive forever and leak the local socket, the UDP
// socket and one upstream connection per abandoned app until the client hits
// MAX_CLIENT_SESSIONS and refuses everything. This bounds it: the grace starts
// when the app's read side reports EOF and is refreshed ONLY by payload
// actually delivered to the app (never by keepalives), so a slow but still
// progressing response is not cut off while a stalled one is reclaimed.
// 2x KCP_TIMEOUT_SEC: comfortably longer than a slow / long-polling target,
// short enough that abandoned tunnels cannot accumulate.
constexpr int CLIENT_HALF_CLOSE_GRACE_SEC = 2 * KCP_TIMEOUT_SEC;

// Server-side guard against memory exhaustion: any UDP source endpoint that
// fails its first decryption is dropped on the floor; only authenticated
// peers are allowed to allocate a session. The hard cap also bounds total
// memory if a fleet of legitimate clients is overwhelming us.
constexpr size_t MAX_CONCURRENT_SESSIONS = 4096;
// Client-side cap on concurrent SOCKS5 connections. The client spawns one KCP
// session + UDP socket per local TCP connection with no other bound; without
// this cap, a busy (or malfunctioning) local app can exhaust file descriptors
// and memory, amplifying any session leak. Mirrors the server-side guard.
constexpr size_t MAX_CLIENT_SESSIONS = 512;
// Global budget on new-session authentication attempts per second. Unknown
// sources are only ever charged a full AEAD decrypt here, so a garbage UDP
// flood must not be able to pin the server's CPU on decrypts. 500 legitimate
// new sessions/sec is far beyond normal use.
constexpr uint32_t MAX_AUTH_ATTEMPTS_PER_SEC = 500;
// Server connect timeout (DNS + TCP) when honoring a SOCKS5 CONNECT.
constexpr int CONNECT_TIMEOUT_SEC = 15;
constexpr int KCP_HANDSHAKE_TIMEOUT_SEC = 3;
// Client-side SOCKS5 handshake timeout (greeting + request).
constexpr int SOCKS5_HANDSHAKE_TIMEOUT_SEC = 30;

// Buffer sizes
constexpr size_t UDP_RECV_BUF_SIZE = 4096;
constexpr size_t FWD_BUF_SIZE = 16384;
constexpr size_t SOCKS5_REPLY_BUF_SIZE = 512;

// UDP socket kernel buffer sizes (SO_RCVBUF / SO_SNDBUF). The OS defaults are
// typically far too small for KCP over a lossy WAN link: when the kernel buffer
// overflows, the OS silently drops UDP datagrams, which KCP then mistakes for
// network loss and triggers whole-window retransmission (surfacing as a burst of
// "replay/stale rejected" on the peer). Raising the buffers removes that class of
// self-inflicted loss. 4 MB is generous for a proxy whose per-session rate is
// bounded by the downstream TCP + backpressure.
constexpr int UDP_SO_RCVBUF_BYTES = 4 * 1024 * 1024;
constexpr int UDP_SO_SNDBUF_BYTES = 4 * 1024 * 1024;

// Backpressure: stop reading from the local TCP socket when KCP's send buffer
// has more segments than this. Prevents unbounded memory growth when the
// network is slower than the source. The threshold must stay comfortably below
// KCP_SNDWND and leave room for at least one whole FWD_BUF_SIZE message's worth
// of segments; otherwise ikcp_send fails (it returns -1 once
// snd_nxt - snd_una >= snd_wnd, i.e. wait_send() >= KCP_SNDWND) and on_send
// tears the session down mid-transfer instead of backpressuring.
constexpr int KCP_MAX_SEGMENTS_PER_MSG =
    static_cast<int>((FWD_BUF_SIZE + (KCP_MTU - KCP_SEGMENT_OVERHEAD) - 1) /
                     (KCP_MTU - KCP_SEGMENT_OVERHEAD));
constexpr int KCP_BACKPRESSURE_THRESHOLD =
    KCP_SNDWND - KCP_MAX_SEGMENTS_PER_MSG - 8;

// Crypto configuration
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
// Per-session random salt carried in cleartext at the front of every encrypted
// datagram. Both peers derive the per-session AEAD key from PSK + this salt
// via HKDF-SHA256, so every session gets an independent key and counter/nonce
// values can never collide across sessions (AES-GCM nonce reuse would otherwise
// be catastrophic). 16 bytes keeps the chance of an honest cross-session salt
// collision negligible and makes it infeasible to collide with a target by
// guessing. The server additionally rejects any session whose salt is already
// claimed by a live session (see KCPServer::get_or_create_session).
constexpr size_t SESSION_SALT_SIZE = 16;
constexpr size_t AES_KEY_SIZE = 16;
// Hard ceiling: refuse to encrypt past this counter so the session must rekey.
// AES-GCM IND-CPA security degrades well before 2^64; pick 2^48 as a safe wall.
constexpr uint64_t MAX_COUNTER = (1ull << 48);
// Replay window size for the receiver-side sliding bitmap.
// Increased from 64 to 2048 to accommodate UDP packet reordering in high-throughput
// scenarios (e.g., large file downloads). UDP packets may arrive out of order,
// and a larger window prevents false replay rejections.
// Memory overhead: 2048 bits = 256 bytes per session.
constexpr size_t REPLAY_WINDOW_BITS = 2048;

// Nonce direction indicators
constexpr uint8_t NONCE_DIR_CLIENT = 0x01;
constexpr uint8_t NONCE_DIR_SERVER = 0x02;

// SOCKS5 constants
constexpr uint8_t SOCKS5_VERSION = 0x05;
constexpr uint8_t SOCKS5_AUTH_NONE = 0x00;
constexpr uint8_t SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF;

constexpr uint8_t SOCKS5_CMD_CONNECT = 0x01;
constexpr uint8_t SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

constexpr uint8_t SOCKS5_ATYP_IPV4 = 0x01;
constexpr uint8_t SOCKS5_ATYP_DOMAIN = 0x03;
constexpr uint8_t SOCKS5_ATYP_IPV6 = 0x04;

constexpr uint8_t SOCKS5_REPLY_SUCCEEDED = 0x00;
constexpr uint8_t SOCKS5_REPLY_GENERAL_FAILURE = 0x01;
constexpr uint8_t SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03;
constexpr uint8_t SOCKS5_REPLY_HOST_UNREACHABLE = 0x04;
constexpr uint8_t SOCKS5_REPLY_CONNECTION_REFUSED = 0x05;
constexpr uint8_t SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07;
constexpr uint8_t SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

inline constexpr char KCP_CONTROL_HELLO[] = "KCP_PROXY_HELLO_V1";
inline constexpr char KCP_CONTROL_HELLO_ACK[] = "KCP_PROXY_HELLO_ACK_V1";
// Application-layer keepalive magic. Sent as its own KCP message when a tunnel
// has been idle for KCP_KEEPALIVE_SEC, with this session's 16-byte salt
// appended (see KcpTunnel::build_keepalive_payload). The receiver drops an
// exact `magic || session_salt` match instead of forwarding it to the
// downstream TCP socket. Scoping with the per-session salt means a real payload
// can never be mistaken for the heartbeat. NOTE: Android CPP_REMOTE must build
// and drop the same `magic || session_salt` heartbeat too, otherwise it would
// forward it into the tunnel as garbage.
inline constexpr char KCP_CONTROL_KEEPALIVE[] = "KCP_PROXY_KEEPALIVE_V1";

// One-line summary of the KCP settings actually in force, rendered from the
// constants above. Server, client and (eventually) the Android CPP_REMOTE peer
// log this exact string at startup so a mismatch between two ends of a tunnel
// is visible in the logs instead of showing up as a mysterious handshake
// failure. Keep the field order stable — it is greppable output.
inline std::string kcp_config_line() {
    return "KCP config conv=" + std::to_string(KCP_CONV) +
           " mtu=" + std::to_string(KCP_MTU) +
           " nodelay=" + std::to_string(KCP_NODELAY) +
           " interval=" + std::to_string(KCP_INTERVAL_MS) +
           " resend=" + std::to_string(KCP_RESEND) +
           " nc=" + std::to_string(KCP_NC) +
           " sndWnd=" + std::to_string(KCP_SNDWND) +
           " rcvWnd=" + std::to_string(KCP_RCVWND) +
           " timeout=" + std::to_string(KCP_TIMEOUT_SEC) + "s";
}

} // namespace kcp_proxy
