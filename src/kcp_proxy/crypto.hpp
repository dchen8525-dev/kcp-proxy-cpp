#pragma once

#include "config.hpp"
#include "byte_view.hpp"
#include <array>
#include <atomic>
#include <bitset>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

// Forward-declare to avoid leaking the full OpenSSL header into clients.
struct evp_cipher_ctx_st;

namespace kcp_proxy {

// Structured error codes so callers can tell a dropped replay packet (normal
// UDP reordering, not a fault) apart from an AEAD authentication failure
// (corrupted data or wrong key). No more string-matching exception messages.
namespace crypto_errors {
    enum class errc {
        ok = 0,
        replay,      // counter rejected by the replay window (normal reordering)
        auth_failed, // AEAD tag verification failed (corrupted / wrong key)
    };
    const std::error_category& category();
    std::error_code make_error_code(errc e);
}

// RAII wrapper for OpenSSL EVP context
class EVPContext {
public:
    EVPContext();
    ~EVPContext();

    EVPContext(const EVPContext&) = delete;
    EVPContext& operator=(const EVPContext&) = delete;
    EVPContext(EVPContext&&) = delete;
    EVPContext& operator=(EVPContext&&) = delete;

    operator evp_cipher_ctx_st*() { return ctx_; }
    operator const evp_cipher_ctx_st*() const { return ctx_; }

private:
    evp_cipher_ctx_st* ctx_;
};

// Crypto owns reusable OpenSSL EVP contexts plus mutable nonce/replay state.
// It is intentionally not thread-safe. Each instance must be confined to one
// session and all calls to encrypt()/decrypt() must be serialized by that
// session's Asio strand (or by an equivalent external synchronization in tests).
class Crypto {
public:
    // Result type for noexcept operations
    struct Result {
        std::vector<uint8_t> data;
        std::error_code ec;

        explicit operator bool() const { return !ec; }
    };

    // Server mode: bypass replay window for the *first* decrypted packet only
    // (a brand-new session seeds its window from whatever counter the peer
    // starts at). After that, normal replay protection applies. Client mode
    // always enforces the replay window (its first received packet seeds it).
    explicit Crypto(std::string_view key, uint8_t direction = NONCE_DIR_CLIENT,
                    byte_view session_salt = {}, bool server_mode = false);
    ~Crypto();

    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;
    Crypto(Crypto&&) = delete;
    Crypto& operator=(Crypto&&) = delete;

    // Wire format: [session_salt(16)] + [nonce(12)] + [ciphertext + tag(16)]
    // session_salt is carried in cleartext and is unique per session; both
    // peers derive the per-session AEAD key from PSK + session_salt via
    // HKDF-SHA256. This guarantees every session uses an independent key, so
    // counter/nonce values never collide across sessions (AES-GCM nonce reuse
    // would otherwise be catastrophic). The client generates the salt and
    // sends it on every datagram; the server learns it from the first packet.
    // The nonce counter's starting value is derived from the salt (see
    // crypto.cpp derive_session_keys), so the nonce sequence is session-unique
    // even between sessions that were forced to share a key.

    // Exception-throwing versions (compatible with existing code)
    [[nodiscard]] std::vector<uint8_t> encrypt(byte_view plaintext);
    [[nodiscard]] std::vector<uint8_t> decrypt(byte_view ciphertext);

    // High-performance noexcept versions
    Result encrypt_noexcept(byte_view plaintext) noexcept;
    Result decrypt_noexcept(byte_view ciphertext) noexcept;

    // Noexcept variants that write into a caller-owned buffer (a per-session
    // reused vector on the decrypt side avoids a heap allocation per packet).
    // Resizes `out`; returns an empty error_code on success.
    std::error_code encrypt_into(byte_view plaintext, std::vector<uint8_t>& out) noexcept;
    std::error_code decrypt_into(byte_view ciphertext, std::vector<uint8_t>& out) noexcept;

    // Generate a cryptographically random per-session salt (SESSION_SALT_SIZE
    // bytes). The client calls this once per session and passes the result to
    // the Crypto constructor.
    static std::vector<uint8_t> generate_session_salt();

    // True if `packet`'s leading bytes carry this session's salt. Used by the
    // server to detect a NEW session colliding with a live one (source-port
    // reuse after a client reconnect), so the stale session can be replaced
    // instead of black-holing the reconnect for up to the idle timeout.
    bool matches_salt(byte_view packet) const;

private:
    static std::array<uint8_t, NONCE_SIZE> generate_nonce(uint64_t counter, uint8_t direction);
    // Replay window: `check_replay_window` is a pure read (does not mutate), so
    // it may be evaluated before AEAD authentication; `commit_replay_window`
    // must only run AFTER the tag verifies. Committing before auth would let an
    // on-path attacker forge a high-counter datagram that permanently desyncs
    // the session.
    bool check_replay_window(uint64_t counter) const;
    void commit_replay_window(uint64_t counter);
    // Derive the per-session encrypt/decrypt keys from `session_salt`.
    // Called exactly once: on construction (client, which generates the salt)
    // or on the first decrypt (server, which learns the salt from the wire).
    // The PSK copy held in key_ is wiped afterwards.
    void derive_session_keys(byte_view session_salt);

    // HKDF-Expand for SHA-256 producing exactly OKM_LEN bytes.
    static void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* salt, size_t salt_len,
                            std::string_view info,
                            uint8_t* okm, size_t okm_len);

    // Core encrypt/decrypt: write the wire format into `out` (resized).
    // Returns an empty error_code on success.
    std::error_code encrypt_impl(byte_view plaintext, std::vector<uint8_t>& out) noexcept;
    std::error_code decrypt_impl(byte_view ciphertext, std::vector<uint8_t>& out) noexcept;

    // HKDF-SHA256 derived keys, one per direction so encrypt/decrypt never share a key.
    alignas(64) std::array<uint8_t, AES_KEY_SIZE> encrypt_key_{};
    alignas(64) std::array<uint8_t, AES_KEY_SIZE> decrypt_key_{};
    uint8_t local_direction_;
    uint8_t peer_direction_;
    bool server_mode_;  // In server mode, skip replay check for first packet only.
    std::string key_;   // PSK, retained until derive_session_keys; then wiped.

    std::atomic<uint64_t> encrypt_counter_{0};

    // Sliding replay-protection window: highest_received_ is the largest counter
    // accepted so far; replay_window_ is a bitmap of recently-seen counters in
    // (highest-W, highest] where bit i tracks counter (highest - i - 1).
    // W = REPLAY_WINDOW_BITS (2048). A real bitset (not a 64-bit integer) is
    // used so window shifts are well-defined and UDP packet reordering within
    // 2048 packets cannot cause false replay rejections or undefined behavior.
    //
    // Thread safety: only accessed from the strand that serializes
    // encrypt/decrypt for this instance. Crypto is intentionally not thread-safe.
    uint64_t highest_received_ = 0;
    std::bitset<REPLAY_WINDOW_BITS> replay_window_{};
    bool any_received_ = false;

    // Per-session salt learned from (server) / generated for (client) this
    // session. Carried in cleartext on the wire; not secret.
    std::vector<uint8_t> session_salt_{};
    bool salt_set_ = false;

    // RAII-wrapped OpenSSL contexts
    std::unique_ptr<EVPContext> encrypt_ctx_;
    std::unique_ptr<EVPContext> decrypt_ctx_;
};

} // namespace kcp_proxy

// Enable std::error_code construction from our enum.
namespace std {
template <>
struct is_error_code_enum<kcp_proxy::crypto_errors::errc> : std::true_type {};
} // namespace std
