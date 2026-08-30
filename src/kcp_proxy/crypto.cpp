#include "kcp_proxy/crypto.hpp"
#include "kcp_proxy/byte_view.hpp"
#include "kcp_proxy/logger.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <fmt/format.h>
#include <cstring>
#include <stdexcept>

namespace kcp_proxy {

namespace crypto_errors {

class category_type : public std::error_category {
public:
    const char* name() const noexcept override { return "kcp_proxy.crypto"; }
    std::string message(int ev) const override {
        switch (static_cast<errc>(ev)) {
            case errc::ok: return "no error";
            case errc::replay: return "replay/stale counter rejected";
            case errc::auth_failed: return "AEAD authentication failed";
        }
        return "unknown crypto error";
    }
};

const std::error_category& category() {
    static category_type instance;
    return instance;
}

std::error_code make_error_code(errc e) {
    return { static_cast<int>(e), category() };
}

} // namespace crypto_errors

// RAII wrapper implementation
EVPContext::EVPContext() : ctx_(EVP_CIPHER_CTX_new()) {
    if (!ctx_) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }
}

EVPContext::~EVPContext() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

namespace {

// Direction byte -> HKDF info label. Distinct labels guarantee that the two
// directions derive different keys even with the same shared password.
constexpr std::string_view info_for_direction(uint8_t direction) {
    return (direction == NONCE_DIR_CLIENT) ? "kcp-proxy/c2s/v1" : "kcp-proxy/s2c/v1";
}

} // namespace

// Fixed application-level salt prevents cross-application precomputation attacks.
static constexpr std::string_view APP_SALT = "kcp-proxy-hkdf-salt-v1";

void Crypto::hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                         const uint8_t* salt, size_t salt_len,
                         std::string_view info,
                         uint8_t* okm, size_t okm_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }

    // RFC 5869 allows an all-zero salt when none is supplied.
    uint8_t zero_salt[SHA256_DIGEST_LENGTH] = {};
    if (salt == nullptr || salt_len == 0) {
        salt = zero_salt;
        salt_len = SHA256_DIGEST_LENGTH;
    }

    size_t derived_len = okm_len;
    const bool failed =
        EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, static_cast<int>(salt_len)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, static_cast<int>(ikm_len)) <= 0 ||
        (!info.empty() &&
         EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const uint8_t*>(info.data()),
                                     static_cast<int>(info.size())) <= 0) ||
        EVP_PKEY_derive(ctx, okm, &derived_len) <= 0 ||
        derived_len != okm_len;

    EVP_PKEY_CTX_free(ctx);
    if (failed) {
        throw std::runtime_error("HKDF derive failed");
    }
}

Crypto::Crypto(std::string_view key, uint8_t direction, byte_view session_salt,
               bool server_mode)
    : local_direction_(direction),
      peer_direction_(direction == NONCE_DIR_CLIENT ? NONCE_DIR_SERVER : NONCE_DIR_CLIENT),
      server_mode_(server_mode),
      key_(key),
      encrypt_ctx_(std::make_unique<EVPContext>()),
      decrypt_ctx_(std::make_unique<EVPContext>()) {

    LOG_DEBUG("crypto", fmt::format("direction={} server={} key_len={} salt_len={}",
              direction, server_mode, key.size(), session_salt.size()));

    if (!session_salt.empty()) {
        // Client side: we generated the salt up front, so derive now.
        derive_session_keys(session_salt);
    }
}

std::vector<uint8_t> Crypto::generate_session_salt() {
    std::vector<uint8_t> salt(SESSION_SALT_SIZE);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("failed to generate session salt (RAND_bytes)");
    }
    return salt;
}

void Crypto::derive_session_keys(byte_view session_salt) {
    if (session_salt.size() != SESSION_SALT_SIZE) {
        throw std::runtime_error("session salt must be exactly SESSION_SALT_SIZE bytes");
    }
    // Build the HKDF salt: fixed app salt + per-session random salt.
    std::string hkdf_salt(APP_SALT);
    hkdf_salt.append(reinterpret_cast<const char*>(session_salt.data()), session_salt.size());

    std::string_view enc_info = info_for_direction(local_direction_);
    std::string_view dec_info = info_for_direction(peer_direction_);

    hkdf_sha256(reinterpret_cast<const uint8_t*>(key_.data()), key_.size(),
                reinterpret_cast<const uint8_t*>(hkdf_salt.data()), hkdf_salt.size(),
                enc_info, encrypt_key_.data(), encrypt_key_.size());
    hkdf_sha256(reinterpret_cast<const uint8_t*>(key_.data()), key_.size(),
                reinterpret_cast<const uint8_t*>(hkdf_salt.data()), hkdf_salt.size(),
                dec_info, decrypt_key_.data(), decrypt_key_.size());

    // Per-session starting counter, derived from the salt (first 6 bytes,
    // big-endian, so it stays below MAX_COUNTER = 2^48). The counter fills the
    // nonce, so embedding the salt here makes each session's nonce sequence
    // unique. Combined with the server's duplicate-salt rejection, two sessions
    // can never reuse a nonce/IV pair even if a malicious client tries to force
    // a shared key by reusing another session's salt.
    uint64_t start_counter = 0;
    for (int i = 0; i < 6; ++i) {
        start_counter = (start_counter << 8) | session_salt[i];
    }
    encrypt_counter_.store(start_counter, std::memory_order_relaxed);

    // Initialize the GCM contexts with the derived key schedules. Per-packet
    // calls below only reset the IV (nonce), avoiding AES key-expansion rework.
    if (EVP_EncryptInit_ex(*encrypt_ctx_, EVP_aes_128_gcm(), nullptr, encrypt_key_.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(*encrypt_ctx_, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1 ||
        EVP_DecryptInit_ex(*decrypt_ctx_, EVP_aes_128_gcm(), nullptr, decrypt_key_.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(*decrypt_ctx_, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
        LOG_ERROR("crypto", "derive_session_keys: EVP cipher ctx init failed");
        throw std::runtime_error("EVP cipher ctx init failed");
    }
    session_salt_.assign(session_salt.begin(), session_salt.end());
    salt_set_ = true;

    // The PSK is no longer needed once the key schedule is baked into the EVP
    // contexts; wipe our copy so it doesn't linger in the Crypto object.
    if (!key_.empty()) {
        OPENSSL_cleanse(key_.data(), key_.size());
        key_.clear();
        key_.shrink_to_fit();
    }
}

Crypto::~Crypto() = default;

std::array<uint8_t, NONCE_SIZE> Crypto::generate_nonce(uint64_t counter, uint8_t direction) {
    std::array<uint8_t, NONCE_SIZE> nonce{};
    for (int i = 7; i >= 0; i--) {
        nonce[i] = static_cast<uint8_t>(counter & 0xFF);
        counter >>= 8;
    }
    nonce[8] = direction;
    return nonce;
}

bool Crypto::matches_salt(byte_view packet) const {
    if (!salt_set_ || packet.size() < SESSION_SALT_SIZE) {
        return false;
    }
    return CRYPTO_memcmp(packet.data(), session_salt_.data(), SESSION_SALT_SIZE) == 0;
}

// Pure check: does `counter` fall inside the replay window and has it not been
// seen yet? No state is mutated — commit_replay_window() records it later.
bool Crypto::check_replay_window(uint64_t counter) const {
    if (!any_received_) {
        return true; // nothing seen yet: any counter is acceptable as the first
    }
    if (counter > highest_received_) {
        return true; // newer than anything seen: always accepted
    }
    if (counter == highest_received_) {
        return false; // exact duplicate of the most-recent counter
    }
    uint64_t offset = highest_received_ - counter; // >= 1
    if (offset > REPLAY_WINDOW_BITS) {
        return false; // too old, outside the window
    }
    return !replay_window_.test(static_cast<size_t>(offset - 1));
}

// Record `counter` as seen. MUST only be called after the packet's AEAD tag
// has verified; committing an unauthenticated counter would let an on-path
// attacker forge one high-counter datagram and permanently desync the session.
void Crypto::commit_replay_window(uint64_t counter) {
    if (!any_received_) {
        any_received_ = true;
        highest_received_ = counter;
        replay_window_.reset();
        return;
    }
    if (counter > highest_received_) {
        uint64_t shift = counter - highest_received_;
        if (shift >= REPLAY_WINDOW_BITS) {
            // Jumped far past the window: everything previously seen is now
            // outside the window, so drop the bitmap entirely.
            replay_window_.reset();
        } else {
            // Slide the window left by `shift` and mark the just-accepted
            // counter (at index shift-1) as seen. Using std::bitset makes the
            // shift well-defined for any shift in [1, W).
            replay_window_ <<= shift;
            replay_window_.set(static_cast<size_t>(shift - 1));
        }
        highest_received_ = counter;
        return;
    }
    if (counter < highest_received_) {
        uint64_t offset = highest_received_ - counter; // >= 1, checked in check_replay_window
        if (offset <= REPLAY_WINDOW_BITS) {
            replay_window_.set(static_cast<size_t>(offset - 1));
        }
    }
}

// Exception-throwing versions (compatible with existing code)
std::vector<uint8_t> Crypto::encrypt(byte_view plaintext) {
    auto result = encrypt_noexcept(plaintext);
    if (!result) {
        throw std::runtime_error(result.ec.message());
    }
    return std::move(result.data);
}

std::vector<uint8_t> Crypto::decrypt(byte_view ciphertext) {
    auto result = decrypt_noexcept(ciphertext);
    if (!result) {
        throw std::runtime_error(result.ec.message());
    }
    return std::move(result.data);
}

// High-performance noexcept implementations
Crypto::Result Crypto::encrypt_noexcept(byte_view plaintext) noexcept {
    Result result;
    result.ec = encrypt_impl(plaintext, result.data);
    return result;
}

Crypto::Result Crypto::decrypt_noexcept(byte_view ciphertext) noexcept {
    Result result;
    result.ec = decrypt_impl(ciphertext, result.data);
    return result;
}

std::error_code Crypto::encrypt_into(byte_view plaintext, std::vector<uint8_t>& out) noexcept {
    return encrypt_impl(plaintext, out);
}

std::error_code Crypto::decrypt_into(byte_view ciphertext, std::vector<uint8_t>& out) noexcept {
    return decrypt_impl(ciphertext, out);
}

std::error_code Crypto::encrypt_impl(byte_view plaintext, std::vector<uint8_t>& out) noexcept {
    try {
        if (!salt_set_) {
            LOG_ERROR("crypto", "encrypt called before the session salt was established");
            return std::make_error_code(std::errc::invalid_argument);
        }
        // fetch_add returns the pre-increment value, which is the counter used
        // for this packet's nonce. The increment is intentionally NOT rolled
        // back when we refuse: once the counter reaches MAX_COUNTER the session
        // has exhausted its safe nonce space and must be re-keyed, not resumed.
        uint64_t counter = encrypt_counter_.fetch_add(1, std::memory_order_relaxed);
        if (counter >= MAX_COUNTER) {
            LOG_ERROR("crypto", fmt::format("encrypt counter overflow: {} >= {}", counter, MAX_COUNTER));
            return std::make_error_code(std::errc::value_too_large);
        }
        auto nonce = generate_nonce(counter, local_direction_);
        LOG_DEBUG("crypto", fmt::format("encrypt: counter={} plaintext={} bytes", counter, plaintext.size()));

        // Full re-init per packet (key and IV length unchanged, but reset ensures clean GCM state).
        if (EVP_EncryptInit_ex(*encrypt_ctx_, nullptr, nullptr, nullptr, nullptr) != 1) {
            LOG_ERROR("crypto", "encrypt: EVP_EncryptInit_ex (reset) failed");
            return std::make_error_code(std::errc::io_error);
        }
        if (EVP_EncryptInit_ex(*encrypt_ctx_, nullptr, nullptr, nullptr, nonce.data()) != 1) {
            LOG_ERROR("crypto", "encrypt: EVP_EncryptInit_ex (key/iv) failed");
            return std::make_error_code(std::errc::io_error);
        }

        // Wire: [session_salt(8)] + [nonce(12)] + [ciphertext + tag(16)]
        out.resize(SESSION_SALT_SIZE + NONCE_SIZE + plaintext.size() + TAG_SIZE);
        std::memcpy(out.data(), session_salt_.data(), SESSION_SALT_SIZE);
        std::memcpy(out.data() + SESSION_SALT_SIZE, nonce.data(), NONCE_SIZE);

        int out_len = 0;
        if (EVP_EncryptUpdate(*encrypt_ctx_, out.data() + SESSION_SALT_SIZE + NONCE_SIZE, &out_len,
                              plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            LOG_ERROR("crypto", fmt::format("encrypt: EVP_EncryptUpdate failed, size={}", plaintext.size()));
            out.clear();
            return std::make_error_code(std::errc::io_error);
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(*encrypt_ctx_, out.data() + SESSION_SALT_SIZE + NONCE_SIZE + out_len, &final_len) != 1) {
            LOG_ERROR("crypto", "encrypt: EVP_EncryptFinal_ex failed");
            out.clear();
            return std::make_error_code(std::errc::io_error);
        }

        int total_cipher_len = out_len + final_len;
        if (EVP_CIPHER_CTX_ctrl(*encrypt_ctx_, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                                out.data() + SESSION_SALT_SIZE + NONCE_SIZE + total_cipher_len) != 1) {
            LOG_ERROR("crypto", "encrypt: EVP_CTRL_GCM_GET_TAG failed");
            out.clear();
            return std::make_error_code(std::errc::io_error);
        }

        out.resize(SESSION_SALT_SIZE + NONCE_SIZE + total_cipher_len + TAG_SIZE);
        LOG_DEBUG("crypto", fmt::format("encrypt done: {} -> {} bytes (counter={})",
                  plaintext.size(), out.size(), counter));
        return {};
    } catch (const std::exception& e) {
        LOG_ERROR("crypto", fmt::format("encrypt exception: {}", e.what()));
        out.clear();
        return std::make_error_code(std::errc::io_error);
    }
}

std::error_code Crypto::decrypt_impl(byte_view ciphertext, std::vector<uint8_t>& out) noexcept {
    try {
        if (ciphertext.size() < SESSION_SALT_SIZE + NONCE_SIZE + TAG_SIZE) {
            LOG_ERROR("crypto", fmt::format("decrypt: ciphertext too short ({} < {})",
                      ciphertext.size(), SESSION_SALT_SIZE + NONCE_SIZE + TAG_SIZE));
            return std::make_error_code(std::errc::invalid_argument);
        }

        // 1) Learn or verify the per-session salt carried in cleartext.
        byte_view salt(ciphertext.data(), SESSION_SALT_SIZE);
        if (!salt_set_) {
            // Server side: this is the first packet of a brand-new session. Derive
            // the per-session key from the salt received on the wire.
            derive_session_keys(salt);
        } else if (!matches_salt(ciphertext)) {
            // A session that already has a key must never receive a different
            // salt: that would indicate a cross-session injection attempt.
            LOG_WARNING("crypto", "decrypt: session salt mismatch (possible injection)");
            return std::make_error_code(std::errc::permission_denied);
        }

        // 2) The rest is the normal [nonce][ciphertext+tag] body.
        byte_view body(ciphertext.data() + SESSION_SALT_SIZE,
                       ciphertext.size() - SESSION_SALT_SIZE);

        std::array<uint8_t, NONCE_SIZE> nonce;
        std::memcpy(nonce.data(), body.data(), NONCE_SIZE);

        if (nonce[8] != peer_direction_) {
            LOG_WARNING("crypto", fmt::format("decrypt: wrong direction byte {} (expected {})",
                        nonce[8], peer_direction_));
            return std::make_error_code(std::errc::permission_denied);
        }

        uint64_t counter = 0;
        for (int i = 0; i < 8; i++) {
            counter = (counter << 8) | nonce[i];
        }

        LOG_DEBUG("crypto", fmt::format("decrypt: counter={} ciphertext={} bytes", counter, ciphertext.size()));

        // Server mode: bypass the replay window for the very first packet of a
        // new session (it also seeded the key above). After that, enforce normal
        // replay protection. Client mode always enforces the replay window (its
        // first received packet seeds it via !any_received_ inside check...).
        // NOTE: we only CHECK here. The counter is committed to the window in
        // commit_replay_window() AFTER the AEAD tag verifies below, so a forged
        // unauthenticated packet can never poison the window.
        const bool first_packet = server_mode_ && !any_received_;
        if (!first_packet && !check_replay_window(counter)) {
            LOG_WARNING("crypto", fmt::format("decrypt: replay/stale rejected counter={} highest={}",
                        counter, highest_received_));
            return make_error_code(crypto_errors::errc::replay);
        }

        const uint8_t* tag_ptr = body.data() + body.size() - TAG_SIZE;
        size_t cipher_data_len = body.size() - NONCE_SIZE - TAG_SIZE;

        // Full re-init per packet for clean GCM state.
        if (EVP_DecryptInit_ex(*decrypt_ctx_, nullptr, nullptr, nullptr, nullptr) != 1) {
            LOG_ERROR("crypto", "decrypt: EVP_DecryptInit_ex (reset) failed");
            return std::make_error_code(std::errc::io_error);
        }
        if (EVP_DecryptInit_ex(*decrypt_ctx_, nullptr, nullptr, nullptr, nonce.data()) != 1) {
            LOG_ERROR("crypto", "decrypt: EVP_DecryptInit_ex (key/iv) failed");
            return std::make_error_code(std::errc::io_error);
        }
        if (EVP_CIPHER_CTX_ctrl(*decrypt_ctx_, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                const_cast<unsigned char*>(tag_ptr)) != 1) {
            LOG_ERROR("crypto", "decrypt: EVP_CTRL_GCM_SET_TAG failed");
            return std::make_error_code(std::errc::io_error);
        }

        out.resize(cipher_data_len);
        int out_len = 0;
        if (EVP_DecryptUpdate(*decrypt_ctx_, out.data(), &out_len,
                              body.data() + NONCE_SIZE,
                              static_cast<int>(cipher_data_len)) != 1) {
            LOG_ERROR("crypto", fmt::format("decrypt: EVP_DecryptUpdate failed, data_len={}", cipher_data_len));
            out.clear();
            return std::make_error_code(std::errc::io_error);
        }

        int final_len = 0;
        if (EVP_DecryptFinal_ex(*decrypt_ctx_, out.data() + out_len, &final_len) <= 0) {
            LOG_ERROR("crypto", fmt::format("decrypt: AEAD tag verification failed (corrupted/wrong key), counter={}", counter));
            out.clear();
            return make_error_code(crypto_errors::errc::auth_failed);
        }

        out.resize(out_len + final_len);
        // Authentication succeeded — only now may the counter enter the window.
        commit_replay_window(counter);
        LOG_DEBUG("crypto", fmt::format("decrypt done: {} -> {} bytes (counter={})",
                  ciphertext.size(), out.size(), counter));
        return {};
    } catch (const std::exception& e) {
        LOG_ERROR("crypto", fmt::format("decrypt exception: {}", e.what()));
        out.clear();
        return std::make_error_code(std::errc::io_error);
    }
}

} // namespace kcp_proxy
