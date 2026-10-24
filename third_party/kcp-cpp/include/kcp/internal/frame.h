// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_FRAME_H_
#define KCP_INTERNAL_FRAME_H_

#include <cstddef>
#include <cstdint>

#include "kcp/crypt.h"

namespace kcp {
namespace internal {

// Largest authentication tag any supported AEAD appends. Only AES-GCM ships today (16 bytes), and
// the session sizes its buffers with this slack so an AEAD can write the tag in place.
constexpr std::size_t kMaxAeadOverhead = 16;

// Seals one outgoing datagram in place (sess.go:706-745, the "Stage 2" block of postProcess).
//
//   buf[0, size)  = [ cipher header ][ optional FEC header ][ KCP segment ]
//
// CFB:   fills the 16-byte nonce, writes CRC32 over buf[kCryptHeaderSize, size) as little-endian
//        and encrypts the whole buffer, nonce and checksum included (§4.3).
// AEAD:  fills the nonce, then seals the plaintext that follows it and appends the tag.
// none:  leaves the buffer untouched.
//
// Returns the wire size (size, or size + overhead for AEAD), or 0 when `capacity` is too small.
// `fixed_nonce` is for the golden-vector tests; sessions pass nullptr so each packet gets fresh
// randomness.
std::size_t EncryptInPlace(BlockCrypt* block, AeadCrypt* aead, std::uint8_t* buf, std::size_t size,
                           std::size_t capacity, const std::uint8_t* fixed_nonce);

// Size of the header EncryptInPlace writes in front of the payload: 0, kCryptHeaderSize or the
// AEAD nonce size (sess.go:208-216).
std::size_t CipherHeaderSize(BlockCrypt* block, AeadCrypt* aead);

// What happened to an incoming datagram.
enum class OpenResult {
  kOk,               // decrypted, checksum verified, *data/*len point at the plaintext
  kDropped,          // shorter than the cipher header: silently ignored (sess.go:978-996)
  kIntegrityFailed,  // CRC32 or AEAD tag mismatch: caller bumps in_csum_errors
};

// Decrypts and verifies one datagram in place, advancing *data past the cipher header and
// shrinking *len to the plaintext. Shared by UdpSession::PacketInput and Listener::PacketInput so
// the two cannot drift apart.
OpenResult OpenInPlace(BlockCrypt* block, AeadCrypt* aead, std::uint8_t** data, std::size_t* len);

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_FRAME_H_
