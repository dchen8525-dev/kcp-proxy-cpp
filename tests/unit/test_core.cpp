#include "kcp/internal/constants.h"
#include "kcp/internal/fec.h"
#include "kcp_proxy/address.hpp"
#include "kcp_proxy/buffer_pool.hpp"
#include "kcp_proxy/client.hpp"
#include "kcp_proxy/config.hpp"
#include "kcp_proxy/crypto.hpp"
#include "kcp_proxy/kcp_client_session.hpp"
#include "kcp_proxy/kcp_session.hpp"
#include "kcp_proxy/kcp_tunnel.hpp"
#include "kcp_proxy/kcp_wrapper.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/server.hpp"
#include "kcp_proxy/socket_buffer.hpp"
#include "kcp_proxy/socks5.hpp"
#include "kcp_proxy/target_allowlist.hpp"

#include <asio.hpp>

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <thread>
#include <vector>
// Must stay the last include AND directly above doctest.h: the macro has to be
// defined before doctest.h is first seen, or doctest compiles without its
// single-TU implementation (and every TEST_CASE vanishes from the binary).
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace kcp_proxy;

namespace {


TEST_CASE("test_crypto_roundtrip_and_failures") {
    const std::string key = "remote_test_key_123456";
    const std::vector<uint8_t> plain{'h', 'e', 'l', 'l', 'o'};

    // Client generates a unique per-session salt; the server learns it from the
    // first packet (it is carried in cleartext on the wire).
    auto c_salt = Crypto::generate_session_salt();
    Crypto client(key, NONCE_DIR_CLIENT, c_salt);
    Crypto server(key, NONCE_DIR_SERVER);
    auto c2s = client.encrypt(byte_view(plain.data(), plain.size()));
    auto got = server.decrypt(byte_view(c2s.data(), c2s.size()));
    CHECK_MESSAGE(got == plain, "client encrypt -> server decrypt failed");

    auto s_salt = Crypto::generate_session_salt();
    Crypto server_sender(key, NONCE_DIR_SERVER, s_salt);
    Crypto client_receiver(key, NONCE_DIR_CLIENT);
    auto s2c = server_sender.encrypt(byte_view(plain.data(), plain.size()));
    got = client_receiver.decrypt(byte_view(s2c.data(), s2c.size()));
    CHECK_MESSAGE(got == plain, "server encrypt -> client decrypt failed");

    Crypto wrong_server("wrong_remote_test_key", NONCE_DIR_SERVER);
    INFO("wrong key should fail");
    CHECK_THROWS_AS((void)(wrong_server.decrypt(byte_view(c2s.data(), c2s.size()))),
                    std::runtime_error);

    auto tampered = c2s;
    tampered[tampered.size() - 1] ^= 0x01;
    Crypto tamper_server(key, NONCE_DIR_SERVER);
    INFO("tampered ciphertext should fail");
    CHECK_THROWS_AS((void)(tamper_server.decrypt(byte_view(tampered.data(), tampered.size()))),
                    std::runtime_error);

    Crypto replay_server(key, NONCE_DIR_SERVER);
    (void)replay_server.decrypt(byte_view(c2s.data(), c2s.size()));
    INFO("replayed packet should fail");
    CHECK_THROWS_AS((void)(replay_server.decrypt(byte_view(c2s.data(), c2s.size()))),
                    std::runtime_error);

    Crypto first_packet_session(key, NONCE_DIR_SERVER);
    (void)first_packet_session.decrypt(byte_view(c2s.data(), c2s.size()));
    INFO("first encrypted packet should be accepted only once per session");
    CHECK_THROWS_AS((void)(first_packet_session.decrypt(byte_view(c2s.data(), c2s.size()))),
                    std::runtime_error);

    // Per-session key isolation: two clients with different salts derive
    // different keys. A server Crypto that has bound to session A's salt must
    // reject session B's traffic (salt mismatch). This is the regression test
    // for the old bug where every session derived the SAME key, so any
    // session's first packet would decrypt in any other session's Crypto.
    auto salt_a = Crypto::generate_session_salt();
    auto salt_b = Crypto::generate_session_salt();
    Crypto client_a(key, NONCE_DIR_CLIENT, salt_a);
    Crypto client_b(key, NONCE_DIR_CLIENT, salt_b);
    auto pkt_a = client_a.encrypt(byte_view(plain.data(), plain.size()));
    auto pkt_b = client_b.encrypt(byte_view(plain.data(), plain.size()));
    CHECK_MESSAGE(pkt_a != pkt_b, "different session salts must produce different ciphertext");

    Crypto server_a(key, NONCE_DIR_SERVER);
    Crypto server_b(key, NONCE_DIR_SERVER);
    CHECK_MESSAGE(server_a.decrypt(byte_view(pkt_a.data(), pkt_a.size())) == plain,
                "server A decrypts session A packet");
    CHECK_MESSAGE(server_b.decrypt(byte_view(pkt_b.data(), pkt_b.size())) == plain,
                "server B decrypts session B packet");
    INFO("server bound to session A must reject session B packet (salt mismatch)");
    CHECK_THROWS_AS((void)(server_a.decrypt(byte_view(pkt_b.data(), pkt_b.size()))),
                    std::runtime_error);

    auto o_salt = Crypto::generate_session_salt();
    Crypto ordered_client(key, NONCE_DIR_CLIENT, o_salt);
    Crypto ordered_server(key, NONCE_DIR_SERVER);
    auto old_packet = ordered_client.encrypt(byte_view(plain.data(), plain.size()));
    auto newer_packet = ordered_client.encrypt(byte_view(plain.data(), plain.size()));
    (void)ordered_server.decrypt(byte_view(old_packet.data(), old_packet.size()));
    (void)ordered_server.decrypt(byte_view(newer_packet.data(), newer_packet.size()));
    INFO("old counter packet should be rejected after it was seen");
    CHECK_THROWS_AS((void)(ordered_server.decrypt(byte_view(old_packet.data(), old_packet.size()))),
                    std::runtime_error);

    auto w_salt = Crypto::generate_session_salt();
    Crypto window_client(key, NONCE_DIR_CLIENT, w_salt);
    Crypto window_server(key, NONCE_DIR_SERVER);
    auto too_old_packet = window_client.encrypt(byte_view(plain.data(), plain.size()));
    (void)window_server.decrypt(byte_view(too_old_packet.data(), too_old_packet.size()));
    for (size_t i = 0; i < REPLAY_WINDOW_BITS + 1; ++i) {
        auto packet = window_client.encrypt(byte_view(plain.data(), plain.size()));
        (void)window_server.decrypt(byte_view(packet.data(), packet.size()));
    }
    INFO("packet older than replay window should be rejected");
    CHECK_THROWS_AS(
        (void)(window_server.decrypt(byte_view(too_old_packet.data(), too_old_packet.size()))),
        std::runtime_error);

    // Boundary regression: a single packet that advances the window by EXACTLY
    // REPLAY_WINDOW_BITS. The old highest is still inside the window
    // (offset == bits), so a replay of it must be rejected. The old
    // `shift >= bits` reset "forgot" it and delivered the duplicate.
    {
        auto e_salt = Crypto::generate_session_salt();
        Crypto edge_client(key, NONCE_DIR_CLIENT, e_salt);
        Crypto edge_server(key, NONCE_DIR_SERVER);
        auto edge_pkt = edge_client.encrypt(byte_view(plain.data(), plain.size()));
        (void)edge_server.decrypt(byte_view(edge_pkt.data(), edge_pkt.size()));
        std::vector<uint8_t> jump;
        for (size_t i = 0; i < REPLAY_WINDOW_BITS; ++i) {
            jump = edge_client.encrypt(byte_view(plain.data(), plain.size()));
        }
        // Decrypt only the LAST packet: a single commit with shift == window bits.
        (void)edge_server.decrypt(byte_view(jump.data(), jump.size()));
        INFO("replay at exactly the window edge should be rejected");
        CHECK_THROWS_AS((void)(edge_server.decrypt(byte_view(edge_pkt.data(), edge_pkt.size()))),
                        std::runtime_error);
    }

    auto oo_salt = Crypto::generate_session_salt();
    Crypto out_of_order_client(key, NONCE_DIR_CLIENT, oo_salt);
    Crypto out_of_order_server(key, NONCE_DIR_SERVER);
    auto packet0 = out_of_order_client.encrypt(byte_view(plain.data(), plain.size()));
    auto packet1 = out_of_order_client.encrypt(byte_view(plain.data(), plain.size()));
    auto packet2 = out_of_order_client.encrypt(byte_view(plain.data(), plain.size()));
    (void)packet0;
    (void)out_of_order_server.decrypt(byte_view(packet2.data(), packet2.size()));
    auto late_packet = out_of_order_server.decrypt(byte_view(packet1.data(), packet1.size()));
    CHECK_MESSAGE(late_packet == plain,
                  "unseen out-of-order packet within replay window should work");

    // Regression: an AUTH-FAILED packet must NOT advance the replay window.
    // Otherwise one forged high-counter datagram permanently desyncs the
    // session (every later, lower counter would be rejected as "too old").
    {
        auto a_salt = Crypto::generate_session_salt();
        Crypto a_client(key, NONCE_DIR_CLIENT, a_salt);
        Crypto a_server(key, NONCE_DIR_SERVER);
        auto pkt0 = a_client.encrypt(byte_view(plain.data(), plain.size())); // counter 0
        auto pkt1 = a_client.encrypt(byte_view(plain.data(), plain.size())); // counter 1
        CHECK_MESSAGE(a_server.decrypt(byte_view(pkt0.data(), pkt0.size())) == plain,
                    "pkt0 accepted (seeds window)");

        // Forge a packet with a huge counter (attacker-chosen) and a bad tag:
        // overwrite the nonce counter bytes; the wrong IV makes the GCM tag fail.
        auto forged = pkt0;
        for (int i = 0; i < 8; ++i) forged[SESSION_SALT_SIZE + i] = 0xFF;
        INFO("forged high-counter packet must fail authentication");
        CHECK_THROWS_AS((void)(a_server.decrypt(byte_view(forged.data(), forged.size()))),
                        std::runtime_error);

        // pkt1 (counter 1) must still decrypt: the forged packet did not poison
        // the window (verify-then-commit).
        CHECK_MESSAGE(a_server.decrypt(byte_view(pkt1.data(), pkt1.size())) == plain,
                    "pkt1 must still be accepted after a forged packet (window not poisoned)");
    }
}

// A 44-byte datagram is the smallest legal wire packet: salt + nonce + tag with
// ZERO ciphertext bytes. GCM has no separate "final block" to write, so this is
// exactly the path where a zero-length output buffer reaches OpenSSL. If the
// tag check is skipped there, an unauthenticated packet is accepted -- and in
// server mode the first-packet bypass means it also gets committed to the replay
// window and allocated a session.
TEST_CASE("test_crypto_empty_payload_is_authenticated") {
    const std::string key = "remote_test_key_123456";
    auto salt = Crypto::generate_session_salt();
    Crypto sender(key, NONCE_DIR_CLIENT, salt);
    auto wire = sender.encrypt(byte_view{});
    CHECK_MESSAGE(wire.size() == SESSION_SALT_SIZE + NONCE_SIZE + TAG_SIZE,
                "empty plaintext must encrypt to salt+nonce+tag only");

    Crypto honest(key, NONCE_DIR_SERVER, {}, true);
    CHECK_MESSAGE(honest.decrypt(byte_view(wire)).empty(),
                "honest empty packet decrypts to zero bytes");

    std::vector<uint8_t> forged = wire;
    for (size_t i = wire.size() - TAG_SIZE; i < forged.size(); ++i) forged[i] ^= 0xA5;
    Crypto victim(key, NONCE_DIR_SERVER, {}, true);
    INFO("forged empty-payload packet must fail authentication");
    CHECK_THROWS_AS((void)(victim.decrypt(byte_view(forged))), std::runtime_error);

    // A zero-length ciphertext still carries the counter in the nonce, so the
    // replay window must behave exactly as it does for a non-empty packet:
    // replaying the honest one is rejected.
    Crypto window(key, NONCE_DIR_SERVER, {}, true);
    (void)window.decrypt(byte_view(wire));
    INFO("replayed empty packet must be rejected");
    CHECK_THROWS_AS((void)(window.decrypt(byte_view(wire))), std::runtime_error);
}

// The server allocates a session from the first datagram, keyed by the salt it
// carries. That allocation must never happen for a packet whose tag did not
// verify -- otherwise one spoofed 44-byte datagram per (ip,port) is enough to
// burn a session slot.
TEST_CASE("test_server_empty_packet_without_tag_does_not_create_session") {
    const std::string key = "remote_test_key_123456";
    asio::io_context io;
    auto server = std::make_shared<KCPServer>(io, 8389, key, "127.0.0.1");
    const auto ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.3"), 40009);

    auto salt = Crypto::generate_session_salt();
    Crypto attacker(key, NONCE_DIR_CLIENT, salt, false);
    auto honest = attacker.encrypt(byte_view{});

    std::vector<uint8_t> forged = honest;
    for (size_t i = honest.size() - TAG_SIZE; i < forged.size(); ++i) forged[i] ^= 0xA5;

    CHECK_MESSAGE(server->route_datagram(ep, byte_view(forged)) == nullptr,
                "forged empty-payload datagram must not create a session");
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(honest)) != nullptr,
                "honest empty-payload datagram should create a session");
}

std::vector<uint8_t> build_request(std::string_view host, uint16_t port) {
    std::vector<uint8_t> req{SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00};
    auto addr = encode_address(host, port);
    req.insert(req.end(), addr.begin(), addr.end());
    return req;
}

TEST_CASE("test_socks5_parser") {
    auto ipv4 = build_request("1.2.3.4", 443);
    auto parsed = parse_socks5_request(ipv4);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Complete, "IPv4 request did not parse");
    CHECK_MESSAGE(parsed.request.has_value(), "IPv4 request missing");
    CHECK_MESSAGE(parsed.request->host == "1.2.3.4", "IPv4 host mismatch");
    CHECK_MESSAGE(parsed.request->port == 443, "IPv4 port mismatch");

    for (size_t i = 0; i < ipv4.size(); ++i) {
        std::vector<uint8_t> partial(ipv4.begin(), ipv4.begin() + static_cast<std::ptrdiff_t>(i));
        auto r = parse_socks5_request(partial);
        CHECK_MESSAGE(r.status == SOCKS5ParseStatus::NeedMore, "partial IPv4 should need more");
    }

    auto domain = build_request("example.com", 80);
    auto domain_complete = domain;
    for (size_t i = 0; i < domain_complete.size(); ++i) {
        std::vector<uint8_t> partial(domain_complete.begin(),
                                     domain_complete.begin() + static_cast<std::ptrdiff_t>(i));
        auto r = parse_socks5_request(partial);
        CHECK_MESSAGE(r.status == SOCKS5ParseStatus::NeedMore, "partial domain should need more");
    }
    domain.push_back('G');
    domain.push_back('E');
    domain.push_back('T');
    parsed = parse_socks5_request(domain);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Complete, "domain request did not parse");
    CHECK_MESSAGE(parsed.request.has_value(), "domain request missing");
    CHECK_MESSAGE(parsed.request->host == "example.com", "domain host mismatch");
    CHECK_MESSAGE(parsed.request->initial_payload.size() == 3, "extra payload not preserved");

    auto ipv6 = build_request("2001:db8::1", 8443);
    for (size_t i = 0; i < ipv6.size(); ++i) {
        std::vector<uint8_t> partial(ipv6.begin(), ipv6.begin() + static_cast<std::ptrdiff_t>(i));
        auto r = parse_socks5_request(partial);
        CHECK_MESSAGE(r.status == SOCKS5ParseStatus::NeedMore, "partial IPv6 should need more");
    }
    parsed = parse_socks5_request(ipv6);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Complete, "IPv6 request did not parse");
    CHECK_MESSAGE(parsed.request.has_value(), "IPv6 request missing");
    CHECK_MESSAGE(parsed.request->port == 8443, "IPv6 port mismatch");

    std::vector<uint8_t> unsupported{SOCKS5_VERSION, 0x02, 0x00, SOCKS5_ATYP_IPV4,
                                     127, 0, 0, 1, 0, 80};
    parsed = parse_socks5_request(unsupported);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Complete, "unsupported command should parse");
    CHECK_MESSAGE(parsed.request->cmd == 0x02, "unsupported command value lost");

    std::vector<uint8_t> udp_assoc{SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00,
                                   SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0, 53};
    parsed = parse_socks5_request(udp_assoc);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Complete,
                  "UDP ASSOCIATE should parse before rejection");
    CHECK_MESSAGE(parsed.request->cmd == SOCKS5_CMD_UDP_ASSOCIATE,
                  "UDP ASSOCIATE command value lost");

    std::vector<uint8_t> bad_version = ipv4;
    bad_version[0] = 0x04;
    parsed = parse_socks5_request(bad_version);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Invalid, "bad version should be invalid");

    // RFC 1928 reserves the third byte and requires it to be 0x00. It used to be
    // read by nothing at all, so a request that set it was silently accepted.
    CHECK_MESSAGE(ipv4[2] == 0x00, "the request builder must emit RSV=0");
    std::vector<uint8_t> bad_rsv = ipv4;
    bad_rsv[2] = 0x01;
    parsed = parse_socks5_request(bad_rsv);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Invalid,
                "a non-zero SOCKS5 reserved byte should be invalid");

    std::vector<uint8_t> bad_atyp{SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, 0x09, 0x00, 0x50};
    parsed = parse_socks5_request(bad_atyp);
    CHECK_MESSAGE(parsed.status == SOCKS5ParseStatus::Invalid,
                  "unsupported ATYP should be invalid");
}

TEST_CASE("test_socks5_reply_bind_address") {
    SOCKS5Response resp;
    resp.reply = SOCKS5_REPLY_SUCCEEDED;
    auto zero = resp.build();
    CHECK_MESSAGE(zero.size() == 10, "zero bind reply size mismatch");
    CHECK_MESSAGE(zero[3] == SOCKS5_ATYP_IPV4, "zero bind should be IPv4");

    resp.host = "127.0.0.1";
    resp.port = 54321;
    auto local = resp.build();
    CHECK_MESSAGE(local.size() == 10, "IPv4 bind reply size mismatch");
    // doctest decomposes binary comparisons only; a && chain would be reported
    // as "Expression Too Complex", so each byte gets its own check.
    CHECK_MESSAGE(local[4] == 127, "IPv4 bind reply mismatch (byte 4)");
    CHECK_MESSAGE(local[7] == 1, "IPv4 bind reply mismatch (byte 7)");
}

// The client used to validate the server's CONNECT reply with a two-line check
// (bytes >= 2 and byte[1] == 0), so a wrong-version, wrong-ATYP or truncated
// reply was accepted as a live tunnel and any trailing payload was dropped.
TEST_CASE("test_socks5_reply_parser") {
    // VER REP RSV ATYP BND.ADDR BND.PORT for a complete IPv4 reply.
    std::vector<uint8_t> ipv4{SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00,
                              SOCKS5_ATYP_IPV4, 93, 184, 216, 34, 0x01, 0xBB};
    auto parsed = parse_socks5_reply(ipv4);
    CHECK_MESSAGE(parsed.status == SOCKS5ReplyStatus::Complete, "IPv4 reply did not parse");
    CHECK_MESSAGE(parsed.reply.has_value(), "IPv4 reply missing");
    CHECK_MESSAGE(parsed.reply->reply == SOCKS5_REPLY_SUCCEEDED, "IPv4 reply code mismatch");
    CHECK_MESSAGE(parsed.reply->host == "93.184.216.34", "IPv4 bind host mismatch");
    CHECK_MESSAGE(parsed.reply->port == 443, "IPv4 bind port mismatch");
    CHECK_MESSAGE(parsed.reply->length == 10, "IPv4 reply length mismatch");

    // Every strict prefix must report NeedMore, never Complete: a reply split
    // across KCP messages has to be accumulated, not acted upon early.
    for (size_t i = 0; i < ipv4.size(); ++i) {
        std::vector<uint8_t> partial(ipv4.begin(),
                                     ipv4.begin() + static_cast<std::ptrdiff_t>(i));
        auto r = parse_socks5_reply(partial);
        CHECK_MESSAGE(r.status == SOCKS5ReplyStatus::NeedMore, "partial reply should need more");
        CHECK_MESSAGE(!r.reply.has_value(), "partial reply must not engage a reply");
    }

    // The old check accepted a two-byte prefix as success.
    std::vector<uint8_t> two_bytes{SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED};
    CHECK_MESSAGE(parse_socks5_reply(two_bytes).status == SOCKS5ReplyStatus::NeedMore,
                "a two-byte reply must not count as complete");

    // Target payload can ride along in the same KCP message. It must be left
    // for the caller (length excludes it) instead of being discarded.
    auto with_payload = ipv4;
    with_payload.push_back('G');
    with_payload.push_back('E');
    with_payload.push_back('T');
    parsed = parse_socks5_reply(with_payload);
    CHECK_MESSAGE(parsed.status == SOCKS5ReplyStatus::Complete, "reply with payload did not parse");
    CHECK_MESSAGE(parsed.reply->length == 10, "reply length must exclude trailing payload");
    CHECK_MESSAGE(with_payload.size() - parsed.reply->length == 3,
                  "trailing payload not preserved");

    // A non-zero REP still parses (the client maps it to an error reply).
    std::vector<uint8_t> refused = ipv4;
    refused[1] = SOCKS5_REPLY_CONNECTION_REFUSED;
    parsed = parse_socks5_reply(refused);
    CHECK_MESSAGE(parsed.status == SOCKS5ReplyStatus::Complete, "rejected reply did not parse");
    CHECK_MESSAGE(parsed.reply->reply == SOCKS5_REPLY_CONNECTION_REFUSED, "reply code lost");

    // IPv6 bind address.
    std::vector<uint8_t> ipv6{SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00, SOCKS5_ATYP_IPV6};
    ipv6.insert(ipv6.end(), 15, 0);
    ipv6.push_back(0x01);
    ipv6.push_back(0x00);
    ipv6.push_back(0x50);
    for (size_t i = 0; i < ipv6.size(); ++i) {
        std::vector<uint8_t> partial(ipv6.begin(),
                                     ipv6.begin() + static_cast<std::ptrdiff_t>(i));
        CHECK_MESSAGE(parse_socks5_reply(partial).status == SOCKS5ReplyStatus::NeedMore,
                    "partial IPv6 reply should need more");
    }
    parsed = parse_socks5_reply(ipv6);
    CHECK_MESSAGE(parsed.status == SOCKS5ReplyStatus::Complete, "IPv6 reply did not parse");
    CHECK_MESSAGE(parsed.reply->length == 22, "IPv6 reply length mismatch");
    CHECK_MESSAGE(parsed.reply->port == 80, "IPv6 bind port mismatch");

    // Domain bind address, including its variable-length form.
    std::vector<uint8_t> domain{SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00,
                                SOCKS5_ATYP_DOMAIN, 11};
    const char* name = "example.com";
    domain.insert(domain.end(), name, name + 11);
    domain.push_back(0x00);
    domain.push_back(0x50);
    for (size_t i = 0; i < domain.size(); ++i) {
        std::vector<uint8_t> partial(domain.begin(),
                                     domain.begin() + static_cast<std::ptrdiff_t>(i));
        CHECK_MESSAGE(parse_socks5_reply(partial).status == SOCKS5ReplyStatus::NeedMore,
                    "partial domain reply should need more");
    }
    parsed = parse_socks5_reply(domain);
    CHECK_MESSAGE(parsed.status == SOCKS5ReplyStatus::Complete, "domain reply did not parse");
    CHECK_MESSAGE(parsed.reply->host == "example.com", "domain bind host mismatch");
    CHECK_MESSAGE(parsed.reply->port == 80, "domain bind port mismatch");
    CHECK_MESSAGE(parsed.reply->length == 18, "domain reply length mismatch");

    // Malformed replies must be Invalid, not Complete and not NeedMore (a
    // NeedMore here would hang the handshake until the deadline).
    std::vector<uint8_t> bad_ver = ipv4;
    bad_ver[0] = 0x04;
    CHECK_MESSAGE(parse_socks5_reply(bad_ver).status == SOCKS5ReplyStatus::Invalid,
                "bad reply version should be invalid");

    std::vector<uint8_t> bad_rsv = ipv4;
    bad_rsv[2] = 0x01;
    CHECK_MESSAGE(parse_socks5_reply(bad_rsv).status == SOCKS5ReplyStatus::Invalid,
                "a non-zero reply reserved byte should be invalid");

    std::vector<uint8_t> bad_atyp{SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00, 0x09, 0, 0};
    CHECK_MESSAGE(parse_socks5_reply(bad_atyp).status == SOCKS5ReplyStatus::Invalid,
                "unsupported reply ATYP should be invalid");

    std::vector<uint8_t> empty_domain{SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00,
                                      SOCKS5_ATYP_DOMAIN, 0x00};
    CHECK_MESSAGE(parse_socks5_reply(empty_domain).status == SOCKS5ReplyStatus::Invalid,
                "empty reply domain should be invalid");

    CHECK_MESSAGE(parse_socks5_reply({}).status == SOCKS5ReplyStatus::NeedMore,
                "an empty buffer should ask for more");

    // Round-trip: what the server builds must parse back to the same values, so
    // the two ends cannot drift apart.
    SOCKS5Response wire;
    wire.reply = SOCKS5_REPLY_SUCCEEDED;
    wire.host = "127.0.0.1";
    wire.port = 54321;
    parsed = parse_socks5_reply(wire.build());
    CHECK_MESSAGE(parsed.status == SOCKS5ReplyStatus::Complete, "built reply did not parse");
    CHECK_MESSAGE(parsed.reply->host == "127.0.0.1", "built reply host mismatch");
    CHECK_MESSAGE(parsed.reply->port == 54321, "built reply port mismatch");
    CHECK_MESSAGE(parsed.reply->length == wire.build().size(), "built reply length mismatch");
}

TEST_CASE("test_restricted_targets") {
    // IPv4 basics.
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("127.0.0.1")), "v4 loopback");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("10.1.2.3")), "v4 private 10/8");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("192.168.1.1")),
                  "v4 private 192.168");
    CHECK_MESSAGE(!is_restricted_target(asio::ip::make_address("1.1.1.1")), "v4 public allowed");

    // IPv4-mapped ::ffff:a.b.c.d inherits the IPv4 classification.
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("::ffff:127.0.0.1")),
                  "v4-mapped loopback");
    CHECK_MESSAGE(!is_restricted_target(asio::ip::make_address("::ffff:1.1.1.1")),
                  "v4-mapped public allowed");

    // Private/non-routable IPv6 ranges. fec0::/10 (site-local) is neither
    // fe80::/10 (link-local) nor fc00::/7 (unique-local), so it used to be the
    // one private IPv6 range the SSRF guard let through.
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("fec0::1")),
                "v6 site-local fec0::/10");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("feff::1")),
                "v6 site-local upper bound feff::");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("fc00::1")), "v6 unique-local");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("fe80::1")), "v6 link-local");
    CHECK_MESSAGE(!is_restricted_target(asio::ip::make_address("2001:4860:4860::8888")),
                "v6 public allowed");

    // 6to4 (2002::/16) embeds the IPv4 address in bytes 2-5: it must not be
    // usable to tunnel into the blocked IPv4 ranges.
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("2002:7f00:0001::1")),
                "6to4 embedding 127.0.0.1");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("2002:0a00::1")),
                "6to4 embedding 10.0.0.1");
    CHECK_MESSAGE(!is_restricted_target(asio::ip::make_address("2002:0101:0101::1")),
                "6to4 embedding public 1.1.1.1 allowed");

    // Teredo (2001:0000::/32): server IPv4 in bytes 4-7, bit-inverted client
    // IPv4 in bytes 12-15. Either embedding a restricted IPv4 must be refused.
    {
        // Client = ~80 ff ff fe = 127.0.0.1.
        asio::ip::address_v6::bytes_type b{};
        b[0] = 0x20; b[1] = 0x01; b[2] = 0x00; b[3] = 0x00;
        b[12] = 0x80; b[13] = 0xff; b[14] = 0xff; b[15] = 0xfe;
        CHECK_MESSAGE(is_restricted_target(asio::ip::address_v6(b)),
                    "teredo embedding loopback client IPv4");
    }
    {
        // Server = 7f 00 00 01 = 127.0.0.1, client = ~f7f7f7f7 = 8.8.8.8.
        asio::ip::address_v6::bytes_type b{};
        b[0] = 0x20; b[1] = 0x01; b[2] = 0x00; b[3] = 0x00;
        b[4] = 0x7f; b[5] = 0x00; b[6] = 0x00; b[7] = 0x01;
        b[12] = 0xf7; b[13] = 0xf7; b[14] = 0xf7; b[15] = 0xf7;
        CHECK_MESSAGE(is_restricted_target(asio::ip::address_v6(b)),
                    "teredo embedding loopback server IPv4");
    }
    {
        // Server 1.2.3.4, client 8.8.8.8: both public -> allowed.
        asio::ip::address_v6::bytes_type b{};
        b[0] = 0x20; b[1] = 0x01; b[2] = 0x00; b[3] = 0x00;
        b[4] = 0x01; b[5] = 0x02; b[6] = 0x03; b[7] = 0x04;
        b[12] = 0xf7; b[13] = 0xf7; b[14] = 0xf7; b[15] = 0xf7;
        CHECK_MESSAGE(!is_restricted_target(asio::ip::address_v6(b)),
                    "teredo with public IPv4s allowed");
    }

    // IPv4-compatible ::a.b.c.d (deprecated ::/96): tail bytes are the IPv4.
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("::c0a8:0101")),
                "v4-compatible embedding 192.168.1.1");
    CHECK_MESSAGE(!is_restricted_target(asio::ip::make_address("::0101:0101")),
                "v4-compatible embedding public 1.1.1.1 allowed");

    // NAT64 well-known prefix 64:ff9b::/96 (and local-use 64:ff9b:1::/48)
    // embed the translated IPv4 in the last 4 bytes.
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("64:ff9b::7f00:0001")),
                "NAT64 embedding 127.0.0.1");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("64:ff9b::c0a8:0101")),
                "NAT64 embedding 192.168.1.1");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("64:ff9b:1::0a00:0001")),
                "NAT64 local-use embedding 10.0.0.1");
    CHECK_MESSAGE(!is_restricted_target(asio::ip::make_address("64:ff9b::0101:0101")),
                "NAT64 embedding public 1.1.1.1 allowed");

    // Regular IPv6 classes unchanged.
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("::1")), "v6 loopback");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("fe80::1")), "v6 link-local");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("fd12:3456::1")), "v6 ULA");
    CHECK_MESSAGE(is_restricted_target(asio::ip::make_address("2001:db8::1")), "v6 documentation");
    CHECK_MESSAGE(!is_restricted_target(asio::ip::make_address("2606:4700:4700::1111")),
                "v6 global unicast allowed");
}

TEST_CASE("test_async_read_some_rejects_stacked_reads") {
    asio::io_context io;
    auto crypto = std::make_shared<Crypto>("remote_test_key_123456", NONCE_DIR_SERVER,
                                            Crypto::generate_session_salt());
    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);
    auto session = std::make_shared<KCPSession>(io, 1, endpoint, crypto, "unit-test-session");
    session->set_send_callback([](std::vector<std::vector<uint8_t>>) {});
    session->start();
    io.poll();
    io.restart();

    std::array<uint8_t, 16> first_buf{};
    std::array<uint8_t, 16> second_buf{};
    bool first_called = false;
    bool second_called = false;
    std::error_code second_ec;

    session->async_read_some(asio::buffer(first_buf), [&](std::error_code ec, size_t) {
        first_called = true;
        CHECK_MESSAGE(ec == asio::error::operation_aborted,
                      "first pending read should remain pending until stop");
    });
    session->async_read_some(asio::buffer(second_buf), [&](std::error_code ec, size_t) {
        second_called = true;
        second_ec = ec;
    });

    io.poll();
    CHECK_MESSAGE(!first_called, "first read handler should not be overwritten or completed");
    CHECK_MESSAGE(second_called, "second stacked read handler should be called");
    CHECK_MESSAGE(second_ec == asio::error::already_started,
                "second stacked read should receive already_started");

    session->stop();
    io.restart();
    io.poll();
    CHECK_MESSAGE(first_called, "first read should be aborted during stop");
}

TEST_CASE("test_kcp_config_line") {
    // The startup log line is the contract between the two ends of a tunnel:
    // both peers must print the same KCP settings or ikcp silently discards
    // the other's packets (the conv mismatch symptom). Pin the exact string so
    // a future drift — changing a KCP_* constant but not the log, or breaking
    // the "log renders these exact values" invariant — breaks the test instead
    // of shipping as a mysterious handshake failure.
    const std::string line = kcp_config_line();

    // Baseline revised from sndWnd=256 rcvWnd=512: a 256-segment window covers
    // only ~14 Mbps at the 190ms RTT of a China -> US-west path, and measurement
    // on that path showed the window (not the link, which sustains >1 Gbps at
    // the VPS) as the per-tunnel ceiling. See the comment on KCP_SNDWND.
    CHECK_MESSAGE(line ==
                    "KCP config conv=1 mtu=1400 nodelay=1 interval=10 "
                    "resend=5 nc=1 sndWnd=1024 rcvWnd=1024 timeout=60s",
                "kcp_config_line canonical baseline changed");

    // Each field must track its constant, so a constant change propagates to
    // the log automatically. Build the expected tokens from the constants
    // themselves (not from a second copy of the format string) so this test
    // fails if a field is ever rendered from a stale literal.
    auto has = [&](const std::string& token) {
        CHECK_MESSAGE(line.find(token) != std::string::npos,
                    ("kcp_config_line missing token: " + token).c_str());
    };
    has("conv=" + std::to_string(KCP_CONV));
    has("mtu=" + std::to_string(KCP_MTU));
    has("nodelay=" + std::to_string(KCP_NODELAY));
    has("interval=" + std::to_string(KCP_INTERVAL_MS));
    has("resend=" + std::to_string(KCP_RESEND));
    has("nc=" + std::to_string(KCP_NC));
    has("sndWnd=" + std::to_string(KCP_SNDWND));
    has("rcvWnd=" + std::to_string(KCP_RCVWND));
    has("timeout=" + std::to_string(KCP_TIMEOUT_SEC) + "s");
}

TEST_CASE("test_receive_buffers_cover_the_largest_legal_datagram") {
    // A datagram larger than the receive buffer is not refused by the kernel:
    // recvfrom()/recvmmsg() truncate it and discard the tail WITHOUT an error
    // (Linux) or with WSAEMSGSIZE after the payload is already lost (Windows).
    // The AEAD tag can then never verify, so the tunnel stops working with
    // nothing but decrypt failures in the log. UDP_RECV_BUF_SIZE was a 4096
    // literal, which silently broke every --mtu above ~4 KB although the CLI
    // accepts up to KCP_MTU_MAX (9000).
    CHECK(UDP_RECV_BUF_SIZE >= UDP_WIRE_DATAGRAM_MAX);

    // Wire size of the worst packet at the largest legal --mtu: salt+nonce,
    // FEC header+length, one full KCP datagram, AEAD tag.
    const size_t worst_case = FEC_CRYPTO_RESERVE + 8 + static_cast<size_t>(KCP_MTU_MAX) + TAG_SIZE;
    CHECK(worst_case <= UDP_RECV_BUF_SIZE);

    // The default MTU fits with room to spare (the shipped path).
    CHECK(FEC_CRYPTO_RESERVE + 8 + static_cast<size_t>(KCP_MTU) + TAG_SIZE <= UDP_RECV_BUF_SIZE);

    // --mtu is clamped, so no accepted value can ever exceed what the receive
    // path holds.
    CHECK(clamp_kcp_value(KCP_MTU_MAX + 1000, KCP_MTU_MIN, KCP_MTU_MAX) == KCP_MTU_MAX);
    CHECK(clamp_kcp_value(0, KCP_MTU_MIN, KCP_MTU_MAX) == KCP_MTU_MIN);

    // The per-datagram pool must still recycle a datagram of that size: an
    // 8 KiB cap sat below the 9 KB one, so a wide --mtu paid a malloc/free per
    // packet on the hot path instead of reusing the buffer.
    {
        std::vector<uint8_t> big(UDP_WIRE_DATAGRAM_MAX, 0);
        const size_t big_capacity = big.capacity();
        datagram_pool().release(std::move(big));
        auto recycled = datagram_pool().acquire();
        CHECK(recycled.capacity() >= big_capacity);
    }
}

TEST_CASE("test_socket_buffer_clamp_detection") {
    // The clamp this detects is invisible at the call site: setsockopt() returns
    // success while the kernel silently caps the request at net.core.rmem_max /
    // wmem_max, so the only signal is the value getsockopt() reports back. If
    // this predicate ever stops firing on a shortfall, the server and client
    // both go quiet about a lost buffer -- exactly the failure mode that cost a
    // production incident (4 MiB requested, 208 KiB granted, burst datagrams
    // dropped and misread by KCP as network loss).

    // A shortfall must produce a message naming the option, both sizes, and the
    // sysctl that caused it -- the numbers are what make the line actionable.
    const std::string clamped = describe_buffer_clamp(
        "so_rcvbuf", "net.core.rmem_max", 4 * 1024 * 1024, 212992);
    CHECK_MESSAGE(!clamped.empty(), "a clamped buffer must be reported");
    CHECK_MESSAGE(clamped.find("so_rcvbuf") != std::string::npos,
                "clamp message must name the socket option");
    CHECK_MESSAGE(clamped.find("4194304") != std::string::npos,
                "clamp message must carry the requested size");
    CHECK_MESSAGE(clamped.find("212992") != std::string::npos,
                "clamp message must carry the effective size");
    CHECK_MESSAGE(clamped.find("net.core.rmem_max") != std::string::npos,
                "clamp message must name the sysctl to raise");

    // Equal is not clamped: that is the ordinary Windows / already-tuned case
    // and must stay silent, or every startup on a healthy host logs a warning.
    CHECK_MESSAGE(
        describe_buffer_clamp("so_sndbuf", "net.core.wmem_max", 4 * 1024 * 1024, 4 * 1024 * 1024)
            .empty(),
        "an exactly-honored request must not be reported");

    // Linux reports a buffer it doubled, so a value above the request is the
    // normal success path there too -- and it must not be reported as a clamp.
    CHECK_MESSAGE(
        describe_buffer_clamp("so_rcvbuf", "net.core.rmem_max", 4 * 1024 * 1024, 8 * 1024 * 1024)
            .empty(),
        "a buffer larger than requested must not be reported");

    // One byte short still counts: the predicate is the exact condition under
    // which there is nothing to say, not an approximate "close enough".
    CHECK_MESSAGE(!describe_buffer_clamp("so_rcvbuf", "net.core.rmem_max", 212992, 212991).empty(),
                  "any shortfall, however small, must be reported");
}

TEST_CASE("test_apply_udp_buffer_sizes_report_once_returns_cached_sizes") {
    // report_once exists so a client with one socket per local TCP connection
    // logs the (process-invariant) clamp report a single time. Its CONTRACT is
    // that every call still returns real sizes: the pre-fix version left the
    // result inside the call_once lambda, so calls after the first returned
    // the {"?", "?"} defaults of a fresh EffectiveBufferSizes -- a trap for any
    // future caller that uses the return value for a per-session banner.
    asio::io_context io;
    asio::ip::udp::socket sock(io);
    sock.open(asio::ip::udp::v4());

    const auto first = apply_udp_buffer_sizes(sock, "test", /*report_once=*/true);
    const auto second = apply_udp_buffer_sizes(sock, "test", /*report_once=*/true);

    CHECK_MESSAGE(first.rcv != "?", "first report_once call must read back so_rcvbuf");
    CHECK_MESSAGE(first.snd != "?", "first report_once call must read back so_sndbuf");
    // Two checks, not one && chain: doctest cannot decompose operator&&.
    CHECK_MESSAGE(first.rcv == second.rcv,
                  "report_once must return the cached so_rcvbuf, not a placeholder");
    CHECK_MESSAGE(first.snd == second.snd,
                  "report_once must return the cached so_sndbuf, not a placeholder");
}

TEST_CASE("test_kcp_wrapper_applies_constants") {
    // configure() must apply the KCP_* constants to the live KCP state. The
    // whole point of promoting the literals to named constants (b52a8bb) was
    // that the startup log (kcp_config_line) and the live KCP tuning can
    // never drift apart; this asserts the live side actually carries them, so
    // the "log renders these exact values" promise is enforced, not just
    // asserted textually by test_kcp_config_line.
    KcpWrapper wrapper(KCP_CONV);
    const kcp::Kcp& k = wrapper.kcp();

    CHECK_MESSAGE(k.conv() == KCP_CONV, "kcp conv mismatch");
    CHECK_MESSAGE(k.mtu() == static_cast<uint32_t>(KCP_MTU), "kcp mtu mismatch");
    CHECK_MESSAGE(k.snd_wnd() == static_cast<uint32_t>(KCP_SNDWND), "kcp snd_wnd mismatch");
    CHECK_MESSAGE(k.rcv_wnd() == static_cast<uint32_t>(KCP_RCVWND), "kcp rcv_wnd mismatch");
    CHECK_MESSAGE(k.nodelay() == static_cast<uint32_t>(KCP_NODELAY), "kcp nodelay mismatch");
    CHECK_MESSAGE(k.interval() == static_cast<uint32_t>(KCP_INTERVAL_MS), "kcp interval mismatch");
    // NoDelay() maps the resend argument to fastresend and nc to nocwnd.
    CHECK_MESSAGE(k.fastresend() == KCP_RESEND, "kcp fastresend (resend) mismatch");
    CHECK_MESSAGE(k.nocwnd() == KCP_NC, "kcp nocwnd (nc) mismatch");
}

// ---------------------------------------------------------------------------
// FEC (forward error correction)
// ---------------------------------------------------------------------------

TEST_CASE("test_parse_fec_config") {
    // Enabled form: both shards parse, and the pair survives the codec's own
    // constraints (data >= 1, parity >= 1, data+parity <= 256, parity <= data).
    FecConfig fec;
    CHECK_MESSAGE(parse_fec_config("10:3", fec), "10:3 must parse");
    // doctest decomposes binary comparisons only (see the && note above), and
    // enabled() is a bool member -- so it gets its own check rather than a
    // three-term &&.
    CHECK_MESSAGE(fec.enabled(), "10:3 must yield an enabled config");
    CHECK_MESSAGE(fec.data_shards == 10, "10:3 must yield 10 data shards");
    CHECK_MESSAGE(fec.parity_shards == 3, "10:3 must yield 3 parity shards");
    CHECK_MESSAGE(fec.to_string() == "10:3", "to_string must render 10:3");

    // Disabled form.
    CHECK_MESSAGE(parse_fec_config("0:0", fec), "0:0 must parse");
    CHECK_MESSAGE(!fec.enabled(), "0:0 must be disabled");
    CHECK_MESSAGE(fec.to_string() == "off", "disabled must render as off");

    // Every reject case: no colon, empty halves, non-digits, trailing junk,
    // parity > data, the codec ceiling, and zero-data-nonzero-parity.
    const char* rejects[] = {"10", "10:", ":3", "", "abc:3", "10:3x", "x10:3",
                             "3:10", "0:3", "10:0", "250:10", "-1:3", "10:-3",
                             // Digit-count gate: 4+ significant digits can never
                             // be a legal shard count (max 255) and must be
                             // rejected without ever reaching std::stol.
                             "1000:1", "1:1000", "99999999999999999999:1"};
    for (const char* text : rejects) {
        FecConfig sink;
        CHECK_MESSAGE(!parse_fec_config(text, sink),
                    (std::string("parse_fec_config must reject '") + text + "'").c_str());
    }
    // Leading zeros are a legitimate spelling of the same number; the gate must
    // count SIGNIFICANT digits, not characters.
    {
        FecConfig lead;
        CHECK_MESSAGE(parse_fec_config("010:03", lead),
                    "leading zeros must not be rejected by the digit-count gate");
        CHECK_MESSAGE(lead.data_shards == 10, "010:03 must normalize data to 10");
        CHECK_MESSAGE(lead.parity_shards == 3, "010:03 must normalize parity to 3");
        FecConfig zeros;
        CHECK_MESSAGE(parse_fec_config("000:000", zeros),
                    "all-zero halves must still parse as the disabled form");
        CHECK_MESSAGE(!zeros.enabled(), "000:000 must be disabled");
    }
}

TEST_CASE("test_fec_codec_repairs_lost_shards") {
    using kcp::internal::FecDecoder;
    using kcp::internal::FecEncoder;

    auto encoder = FecEncoder::New(10, 3, 0);
    auto decoder = FecDecoder::New(10, 3);
    CHECK_MESSAGE(encoder != nullptr, "FecEncoder::New(10,3,0) must succeed");
    CHECK_MESSAGE(decoder != nullptr, "FecDecoder::New(10,3) must succeed");

    // One shard set of 10 data packets, each with a distinct payload pattern.
    // header_offset = 0: the frame is [fec_hdr(6)][len(2)][payload], i.e. the
    // exact shape the proxy hands out at FEC_CRYPTO_RESERVE offset.
    constexpr int kDataShards = 10;
    std::vector<std::vector<uint8_t>> wire_packets;   // sealed encoder outputs
    std::vector<std::vector<uint8_t>> payloads;       // the bytes behind len(2)
    std::vector<std::vector<uint8_t>> parity;
    for (int i = 0; i < kDataShards; i++) {
        const size_t payload_len = 100 + static_cast<size_t>(i);
        std::vector<uint8_t> frame(8 + payload_len);
        for (size_t j = 0; j < payload_len; j++) {
            frame[8 + j] = static_cast<uint8_t>((j * 31 + i) & 0xff);
        }
        std::vector<std::vector<uint8_t>> emitted;
        // rto=500ms: packets are emitted back-to-back, so the set is one burst
        // and parity must be generated (fec.go's continuity branch).
        encoder->Encode(frame.data(), frame.size(), 500, &emitted);
        wire_packets.push_back(frame);
        payloads.push_back(std::vector<uint8_t>(frame.begin() + 8, frame.end()));
        for (auto& p : emitted) parity.push_back(std::move(p));
    }
    CHECK_MESSAGE(parity.size() == 3, "a complete 10:3 set must emit exactly 3 parity packets");

    // The encoder seals each data packet: type flag = kTypeData at [4..6) and
    // the self-counting length field at [6..8).
    for (const auto& frame : wire_packets) {
        const uint16_t flag = static_cast<uint16_t>(frame[4]) |
                              static_cast<uint16_t>(frame[5] << 8);
        CHECK_MESSAGE(flag == kcp::kTypeData, "sealed data packet must carry kTypeData");
        const uint16_t declared = static_cast<uint16_t>(frame[6]) |
                                  static_cast<uint16_t>(frame[7] << 8);
        CHECK_MESSAGE(
            declared + 6 == frame.size(),
            "the FEC length field must count itself and span the packet minus its header");
    }

    // Drop data shards 2, 5 and 9; feed the 7 survivors plus the 3 parity
    // packets to the decoder and expect exactly the 3 lost payloads rebuilt.
    const size_t dropped[] = {2, 5, 9};
    std::vector<std::vector<uint8_t>> rebuilt;
    for (size_t i = 0; i < wire_packets.size(); i++) {
        bool is_dropped = false;
        for (size_t d : dropped) is_dropped = is_dropped || (i == d);
        if (is_dropped) continue;
        auto got = decoder->Decode(wire_packets[i].data(), wire_packets[i].size());
        // Surviving native data packets are buffered by the decoder, never
        // handed back — only genuinely rebuilt shards are returned.
        CHECK_MESSAGE(got.empty(), "a surviving data packet must not be rebuilt");
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(got.begin()),
                       std::make_move_iterator(got.end()));
    }
    for (const auto& p : parity) {
        auto got = decoder->Decode(p.data(), p.size());
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(got.begin()),
                       std::make_move_iterator(got.end()));
    }
    CHECK_MESSAGE(rebuilt.size() == 3,
                (std::string("exactly the 3 lost shards must come back, got ") +
                 std::to_string(rebuilt.size())).c_str());

    // Each rebuilt shard is [len(2)|payload|zero-pad...] — the decoder
    // zero-extends every shard to the set's maxlen before reconstruction, so
    // only the declared prefix is meaningful. The len field counts itself
    // (declared = 2 + payload). Shards come back in ascending seqid order.
    for (size_t k = 0; k < rebuilt.size(); k++) {
        const auto& shard = rebuilt[k];
        CHECK_MESSAGE(shard.size() >= 2, "rebuilt shard must carry its length field");
        const uint16_t declared = static_cast<uint16_t>(shard[0]) |
                                  static_cast<uint16_t>(shard[1] << 8);
        const auto& want = payloads[dropped[k]];
        CHECK_MESSAGE(declared == 2 + want.size(),
                    "rebuilt shard length field must count itself plus the payload");
        CHECK_MESSAGE(declared <= shard.size(),
                    "the declared payload must fit inside the possibly zero-extended shard");
        CHECK_MESSAGE(std::equal(want.begin(), want.end(), shard.begin() + 2),
                    "rebuilt payload must match the lost original byte-for-byte");
    }
}

// ---------------------- adaptive parity (--fec-adaptive) --------------------
// Two contracts hold the whole feature up:
//   1. the codec's rto=0 path is exactly "skip this set's parity, keep the
//      seqid advanced" -- the tunnel relies on it for the wire format, and the
//      peer must still decode the NEXT set;
//   2. the controller provably flips the gate on the measured signal and
//      nothing else (clean traffic -> economy, a fast retransmit -> protected
//      plus a hold, idle traffic -> no decision).

TEST_CASE("test_fec_rto_zero_skips_parity_and_keeps_set_alignment") {
    using kcp::internal::FecDecoder;
    using kcp::internal::FecEncoder;

    constexpr int kData = 10;
    constexpr int kParity = 3;
    auto encoder = FecEncoder::New(kData, kParity, 0);
    auto decoder = FecDecoder::New(kData, kParity);
    REQUIRE_MESSAGE(encoder != nullptr, "FecEncoder::New(10,3,0) must succeed");
    REQUIRE_MESSAGE(decoder != nullptr, "FecDecoder::New(10,3) must succeed");

    // --- Set 1: adaptive "economy" -- rto=0 means every packet is treated as
    // "not part of a burst", which is the codec's documented SkipParity()
    // branch. No parity packet may be emitted, and after 10 data packets the
    // seqid must have advanced by data+parity = 13 (not 10): that advancement
    // is what keeps the peer's seqid/data+parity grouping aligned.
    std::vector<std::vector<uint8_t>> skipped_frames;
    for (int i = 0; i < kData; i++) {
        std::vector<uint8_t> frame(8 + 64);
        for (size_t j = 0; j < 64; j++) {
            frame[8 + j] = static_cast<uint8_t>(i * 7 + j);
        }
        std::vector<std::vector<uint8_t>> emitted;
        encoder->Encode(frame.data(), frame.size(), 0, &emitted);
        CHECK_MESSAGE(emitted.empty(), "rto=0 must emit no parity for the set");
        skipped_frames.push_back(frame);
    }
    CHECK_MESSAGE(encoder->next() == static_cast<uint32_t>(kData + kParity),
                  "a skipped set must still advance the seqid by data+parity");

    // --- Set 2: protected -- parity comes back, and it must describe THIS set.
    // If the skipped set had advanced the seqid by only data, or not at all, the
    // encoder and a stock 10:3 decoder would disagree about where the set
    // boundary is and the rebuild below would fail.
    std::vector<std::vector<uint8_t>> protected_frames;
    std::vector<std::vector<uint8_t>> parity;
    for (int i = 0; i < kData; i++) {
        std::vector<uint8_t> frame(8 + 64);
        for (size_t j = 0; j < 64; j++) {
            frame[8 + j] = static_cast<uint8_t>(100 + i * 3 + j);
        }
        std::vector<std::vector<uint8_t>> emitted;
        // rto=500ms: back-to-back packets are one burst, so parity is built.
        encoder->Encode(frame.data(), frame.size(), 500, &emitted);
        protected_frames.push_back(frame);
        for (auto& p : emitted)
            parity.push_back(std::move(p));
    }
    CHECK_MESSAGE(parity.size() == static_cast<size_t>(kParity),
                  "a protected 10:3 set must emit exactly 3 parity packets");
    CHECK_MESSAGE(encoder->next() == static_cast<uint32_t>(2 * (kData + kParity)),
                  "two complete sets must have consumed exactly two seqid spans");

    // Feed every data packet of both sets, then set 2's parity minus one dropped
    // data shard: exactly that shard must be rebuilt, byte-exact.
    for (const auto& frame : skipped_frames) {
        decoder->Decode(frame.data(), frame.size());
    }
    const size_t dropped = 4;
    std::vector<std::vector<uint8_t>> rebuilt;
    for (size_t i = 0; i < protected_frames.size(); i++) {
        if (i == dropped) continue;
        for (auto& shard :
             decoder->Decode(protected_frames[i].data(), protected_frames[i].size())) {
            rebuilt.push_back(std::move(shard));
        }
    }
    for (const auto& p : parity) {
        for (auto& shard : decoder->Decode(p.data(), p.size())) {
            rebuilt.push_back(std::move(shard));
        }
    }
    REQUIRE_MESSAGE(rebuilt.size() == 1,
                    "exactly the one dropped shard of the protected set must be rebuilt");
    const auto& shard = rebuilt.front();
    REQUIRE(shard.size() >= 2);
    const uint16_t declared =
        static_cast<uint16_t>(shard[0]) | static_cast<uint16_t>(shard[1] << 8);
    CHECK_MESSAGE(declared == 2 + 64, "rebuilt length field must count itself plus the payload");
    for (size_t j = 0; j < 64; j++) {
        CHECK_MESSAGE(shard[2 + j] == static_cast<uint8_t>(100 + dropped * 3 + j),
                      "rebuilt payload must match the dropped original byte-for-byte");
    }
}

TEST_CASE("test_fec_parity_controller_state_machine") {
    FecParityGate gate;
    CHECK_MESSAGE(gate.enabled(), "a fresh gate must allow parity (pre-adaptive default)");

    FecParityTuning tuning;
    tuning.probe_sec = 4;
    tuning.hold_sec = 10;
    tuning.min_seg_rate = 50.0;
    FecParityController ctl(gate, tuning);
    CHECK(ctl.probe_sec() == 4);

    using Transition = FecParityController::Transition;
    int64_t now = 1'000'000; // arbitrary monotonic origin, micros
    uint64_t segs = 0;
    uint64_t fast = 0;

    // The first sample only establishes a baseline: it must never transition,
    // however much history the counters already carry.
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);

    // Two idle seconds: below min_seg_rate, so it counts as neither clean nor
    // lossy. An idle tunnel must not "accumulate cleanliness" for free.
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
    CHECK(ctl.clean_us() == 0);

    // 2s of real traffic (400 segments = 200/s >= 50/s): half of the probe.
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
    CHECK(gate.enabled());

    // Another clean 2s reaches the 4s probe: parity goes off.
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kToEconomy);
    CHECK_FALSE(gate.enabled());
    CHECK(ctl.economy());

    // One fast retransmit is enough to go back, immediately.
    fast += 1;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kToProtected);
    CHECK(gate.enabled());
    CHECK_FALSE(ctl.economy());

    // Inside the 10s hold clean traffic is ignored, so a single probe cannot
    // start a new countdown early: 4 windows = 8s, still short of the hold.
    for (int i = 0; i < 4; i++) {
        segs += 400;
        now += 2'000'000;
        CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
    }
    CHECK(gate.enabled());

    // Past the hold the clean clock restarts from zero: 2s is short of the
    // 4s probe again, and only the following window downgrades.
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kToEconomy);
    CHECK_FALSE(gate.enabled());
}

TEST_CASE("test_rto_floor_controller_state_machine") {
    // The adaptive RTO floor is the fix for self-inflicted retransmissions: a
    // 1024-segment window is ~1.4 MB, which at 150 Mbit/s takes 75ms to drain,
    // so with the 30ms floor (nodelay=1) segments near the end of a burst are
    // resent while still queued. Relaxing to 100ms removes them, but must only
    // happen on evidence of a CLEAN path -- a lossy one keeps the fast floor.
    RtoFloorGate gate;
    CHECK_MESSAGE(gate.low_latency(), "a fresh gate must keep the 30ms floor");

    RtoFloorController ctl(gate, /*relax_sec=*/4, /*hold_sec=*/10, /*min_seg_rate=*/50.0);
    CHECK(ctl.relax_sec() == 4);

    using Transition = RtoFloorController::Transition;
    int64_t now = 1'000'000;
    uint64_t segs = 0;
    uint64_t fast = 0;

    // Baseline sample: never transitions, and leaves the floor alone.
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
    CHECK(gate.low_latency());

    // Idle window: below min_seg_rate, so it does not count as clean.
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);

    // 2s of real traffic: half the relax window, still low-latency.
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
    CHECK(gate.low_latency());

    // The second clean window reaches 4s: relax to the 100ms floor.
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kToRelaxed);
    CHECK_FALSE(gate.low_latency());
    CHECK(ctl.relaxed());

    // One fast retransmit puts the 30ms floor back immediately, and starts the
    // hold: clean traffic cannot relax it again until the hold expires.
    fast += 1;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kToLowLatency);
    CHECK(gate.low_latency());

    for (int i = 0; i < 4; i++) { // 8s of clean traffic, hold is 10s
        segs += 400;
        now += 2'000'000;
        CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
        CHECK(gate.low_latency());
    }

    // Past the hold the clean clock starts from zero: 2s is short of 4s, the
    // following window relaxes again.
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kNone);
    CHECK(gate.low_latency());
    segs += 400;
    now += 2'000'000;
    CHECK(ctl.on_sample(segs, fast, now) == Transition::kToRelaxed);
    CHECK_FALSE(gate.low_latency());
}

TEST_CASE("test_fec_frame_layout_at_crypto_reserve") {
    // The tunnel frames KCP datagrams at header_offset = FEC_CRYPTO_RESERVE,
    // i.e. the FEC header starts AFTER the 28-byte region the crypto layer
    // fills with salt+nonce. Only the e2e suite exercised that offset before,
    // which is exactly where an off-by-one in the payload_offset arithmetic
    // would hide: a wrong offset still produces plausible-looking frames that
    // simply never repair anything.
    using kcp::internal::FecDecoder;
    using kcp::internal::FecEncoder;

    auto encoder = FecEncoder::New(10, 3, static_cast<int>(FEC_CRYPTO_RESERVE));
    auto decoder = FecDecoder::New(10, 3);
    CHECK_MESSAGE(encoder != nullptr, "FecEncoder::New(10,3,crypto_reserve) must succeed");
    CHECK_MESSAGE(decoder != nullptr, "FecDecoder::New(10,3) must succeed");

    // Exactly the largest datagram KCP can emit, which is the budget the
    // FEC_WIRE_DATAGRAM_MAX static_assert is built on.
    constexpr int kDataShards = 10;
    const size_t kcp_len = KCP_MTU;
    const size_t frame_size = FEC_CRYPTO_RESERVE + 8 + kcp_len;

    std::vector<std::vector<uint8_t>> frames;
    std::vector<std::vector<uint8_t>> payloads;
    std::vector<std::vector<uint8_t>> parity;
    for (int i = 0; i < kDataShards; i++) {
        // 0xA5 in the reserve region: the crypto layer owns those bytes and
        // must never see them modified by the FEC seal.
        std::vector<uint8_t> frame(frame_size, 0xA5);
        for (size_t j = 0; j < kcp_len; j++) {
            frame[FEC_CRYPTO_RESERVE + 8 + j] = static_cast<uint8_t>((j * 17 + i) & 0xff);
        }
        std::vector<std::vector<uint8_t>> emitted;
        encoder->Encode(frame.data(), frame_size, 500, &emitted);
        frames.push_back(frame);
        payloads.push_back(std::vector<uint8_t>(frame.begin() + FEC_CRYPTO_RESERVE + 8,
                                                frame.end()));
        for (auto& p : emitted) parity.push_back(std::move(p));
    }

    CHECK_MESSAGE(parity.size() == 3, "a complete 10:3 set must emit exactly 3 parity packets");

    for (const auto& frame : frames) {
        // The reserve region stays byte-identical: the FEC seal only writes
        // from header_offset onwards.
        bool reserve_untouched = true;
        for (size_t j = 0; j < FEC_CRYPTO_RESERVE; j++) {
            reserve_untouched = reserve_untouched && frame[j] == 0xA5;
        }
        CHECK_MESSAGE(reserve_untouched,
                    "the crypto reserve region must not be written by the FEC seal");
        const uint16_t flag = static_cast<uint16_t>(frame[FEC_CRYPTO_RESERVE + 4]) |
                              static_cast<uint16_t>(frame[FEC_CRYPTO_RESERVE + 5] << 8);
        CHECK_MESSAGE(flag == kcp::kTypeData, "sealed data packet must carry kTypeData");
        const uint16_t declared = static_cast<uint16_t>(frame[FEC_CRYPTO_RESERVE + 6]) |
                                  static_cast<uint16_t>(frame[FEC_CRYPTO_RESERVE + 7] << 8);
        // The length field counts itself: everything from payload_offset to
        // the end of the frame, which here is 2 + KCP_MTU.
        CHECK_MESSAGE(declared == 2 + kcp_len,
                    "declared must cover the length field plus the KCP datagram");
    }

    // Drop shards 0, 4 and 8 (the extremes plus the middle), then verify the
    // rebuilt payload is the KCP datagram itself -- not the length field and
    // not shifted by the crypto reserve.
    //
    // Decode() must be handed the packet the ENCODER produced starting at
    // header_offset, not the whole crypto-reserved buffer: on_kcp_datagram
    // passes `fec_send_buf_ + FEC_CRYPTO_RESERVE` and the parity loop passes
    // `parity.data() + FEC_CRYPTO_RESERVE` (kcp_tunnel.cpp:82-89), because the
    // decrypt path also strips the salt+nonce before feed_kcp_input sees the
    // bytes. Feeding the reserve in would make ReadLe32 read 0x... as the
    // seqid and silently drop every shard into one slot.
    const size_t dropped[] = {0, 4, 8};
    std::vector<std::vector<uint8_t>> rebuilt;
    for (size_t i = 0; i < frames.size(); i++) {
        bool is_dropped = false;
        for (size_t d : dropped) is_dropped = is_dropped || (i == d);
        if (is_dropped) continue;
        auto got = decoder->Decode(frames[i].data() + FEC_CRYPTO_RESERVE,
                                   frames[i].size() - FEC_CRYPTO_RESERVE);
        CHECK_MESSAGE(got.empty(), "a surviving data packet must not be rebuilt");
    }
    for (const auto& p : parity) {
        auto got = decoder->Decode(p.data() + FEC_CRYPTO_RESERVE,
                                   p.size() - FEC_CRYPTO_RESERVE);
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(got.begin()),
                       std::make_move_iterator(got.end()));
    }
    CHECK_MESSAGE(rebuilt.size() == 3,
                (std::string("exactly 3 shards must be rebuilt at the reserve offset, got ") +
                 std::to_string(rebuilt.size())).c_str());

    for (size_t k = 0; k < rebuilt.size(); k++) {
        const auto& shard = rebuilt[k];
        CHECK_MESSAGE(shard.size() >= 2, "rebuilt shard must carry its length field");
        const uint16_t declared = static_cast<uint16_t>(shard[0]) |
                                  static_cast<uint16_t>(shard[1] << 8);
        const auto& want = payloads[dropped[k]];
        CHECK_MESSAGE(declared == 2 + want.size(),
                    "rebuilt shard must declare the length field plus the KCP datagram");
        CHECK_MESSAGE(declared <= shard.size(),
                    "the declared prefix must fit inside the zero-extended shard");
        CHECK_MESSAGE(std::equal(want.begin(), want.end(), shard.begin() + 2),
                    "rebuilt KCP datagram must match the lost original byte-for-byte");
    }
}

TEST_CASE("test_fec_encoder_does_not_leak_stale_shard_bytes") {
    // shard_cache_ is reused across shard sets and only grows
    // (fec.cc:102-105, 124-126), so slot i keeps whatever the previous set put
    // there. GenerateParity zeroes [shard_length_, max_size_) for every data
    // shard (fec.cc:158-162) before copying the payload out, which is what
    // makes a shorter follow-up set safe. If that memset were ever dropped, the
    // parity shards would carry the tail of a previous, longer datagram -- the
    // decoder would then "successfully" rebuild a shard whose trailing bytes are
    // another packet's ciphertext, and KCP would consume corruption as if it had
    // been authenticated on the wire. Pin the behaviour down end-to-end.
    using kcp::internal::FecDecoder;
    using kcp::internal::FecEncoder;

    constexpr int kDataShards = 4;
    auto encoder = FecEncoder::New(kDataShards, 2, 0);
    CHECK_MESSAGE(encoder != nullptr, "FecEncoder::New(4,2,0) must succeed");

    // Set 1: every shard fills the full 1400-byte budget with a loud pattern.
    const size_t long_len = 8 + 1392;
    for (int i = 0; i < kDataShards; i++) {
        std::vector<uint8_t> frame(long_len, 0xEE);
        std::vector<std::vector<uint8_t>> emitted;
        encoder->Encode(frame.data(), frame.size(), 500, &emitted);
    }

    // Set 2: same slots, but each shard is only the minimum 8 + 16 bytes.
    // Every byte the second set exposes beyond its own length must be zero.
    const size_t short_len = 8 + 16;
    std::vector<std::vector<uint8_t>> short_payloads;
    std::vector<std::vector<uint8_t>> short_frames;
    std::vector<std::vector<uint8_t>> parity;
    for (int i = 0; i < kDataShards; i++) {
        std::vector<uint8_t> frame(short_len, 0);
        // 0x11.. so a leaked 0xEE tail is unmistakable.
        std::fill(frame.begin() + 8, frame.end(), static_cast<uint8_t>(0x10 + i));
        std::vector<std::vector<uint8_t>> emitted;
        encoder->Encode(frame.data(), frame.size(), 500, &emitted);
        short_frames.push_back(frame);
        short_payloads.push_back(std::vector<uint8_t>(frame.begin() + 8, frame.end()));
        for (auto& p : emitted) parity.push_back(std::move(p));
    }
    CHECK_MESSAGE(parity.size() == 2, "a complete 4:2 set must emit exactly 2 parity packets");

    // The parity packets of set 2 are max_size long (8 + 16 here), never the
    // 1400 bytes set 1 used -- GenerateParity truncates to max_size_.
    for (const auto& p : parity) {
        CHECK_MESSAGE(p.size() == short_len,
                    "parity length must follow the CURRENT set's max_size, not a stale one");
    }

    // Drop one shard of set 2 and rebuild it from the survivors plus parity.
    auto decoder = FecDecoder::New(kDataShards, 2);
    CHECK_MESSAGE(decoder != nullptr, "FecDecoder::New(4,2) must succeed");
    const size_t dropped_index = 2;
    std::vector<std::vector<uint8_t>> rebuilt;
    for (size_t i = 0; i < short_frames.size(); i++) {
        if (i == dropped_index) continue;
        auto got = decoder->Decode(short_frames[i].data(), short_frames[i].size());
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(got.begin()),
                       std::make_move_iterator(got.end()));
    }
    for (const auto& p : parity) {
        auto got = decoder->Decode(p.data(), p.size());
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(got.begin()),
                       std::make_move_iterator(got.end()));
    }
    CHECK_MESSAGE(rebuilt.size() == 1,
                (std::string("the dropped short shard must be rebuilt, got ") +
                 std::to_string(rebuilt.size())).c_str());

    if (rebuilt.size() == 1) {
        const auto& shard = rebuilt[0];
        const uint16_t declared = static_cast<uint16_t>(shard[0]) |
                                  static_cast<uint16_t>(shard[1] << 8);
        const auto& want = short_payloads[dropped_index];
        CHECK_MESSAGE(declared == 2 + want.size(),
                    "rebuilt short shard must declare its own length, not set 1's");
        CHECK_MESSAGE(std::equal(want.begin(), want.end(), shard.begin() + 2),
                    "rebuilt short shard payload must match its original");
        // The decisive assertion: nothing past the declared prefix may carry a
        // byte from set 1. With a 4:2 set the rebuild is zero-extended to
        // maxlen == short_len, so the whole trailing region must be 0x00 --
        // never 0xEE.
        bool no_stale_byte = true;
        for (size_t j = declared; j < shard.size(); j++) {
            no_stale_byte = no_stale_byte && shard[j] == 0x00;
        }
        CHECK_MESSAGE(no_stale_byte,
                    "a rebuilt shard must never expose bytes from a previous, longer set");
        bool no_stale_anywhere = true;
        for (uint8_t b : shard) {
            no_stale_anywhere = no_stale_anywhere && b != 0xEE;
        }
        CHECK_MESSAGE(no_stale_anywhere, "no 0xEE filler from set 1 may survive into set 2");
    }
}

// Minimal concrete KcpTunnel. feed_kcp_input is the only member under test, so
// every abstract hook is an inert stub: KcpTunnel's constructor is protected and
// the class is abstract by design (the two real sessions own the wire), which is
// exactly why a probe has to exist to reach the FEC-off branch at all.
class InertTunnel : public KcpTunnel {
public:
    InertTunnel(asio::io_context& io, uint32_t conv, std::shared_ptr<Crypto> crypto,
                const FecConfig& fec)
        : KcpTunnel(io, conv, std::move(crypto), "inert_tunnel", "p", fec) {}

    // feed_kcp_input is protected (strand-only by contract). Re-expose it under a
    // distinct name rather than widening the base's interface for a test.
    int feed(const uint8_t* data, size_t size) { return feed_kcp_input(data, size); }

protected:
    bool can_accept_data() const override { return false; }
    bool is_active() const override { return false; }
    void shut_down() override {}
    void handle_kcp_output(byte_view) override {}
};

TEST_CASE("test_server_adapts_fec_per_client_framing") {
    // The server's per-session FEC auto-adaptation (see
    // KCPServer::get_or_create_session): the first decrypted datagram decides
    // the session's framing in BOTH directions. A FEC-speaking client must get
    // FEC-framed replies (the GUI default FEC on used to die against a
    // FEC-off service), a bare client must keep bare datagrams even when the
    // server was started with -fec (client framing overrides server config),
    // and the adaptive shard default is FEC_ADAPTIVE_{DATA,PARITY}_SHARDS.
    const std::string key = "remote_test_key_123456";
    const auto ep = [](uint16_t port) {
        return asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), port);
    };

    // Frame one KCP segment the way a FEC client's on_kcp_datagram does:
    // [reserve(28)][fec_hdr(6)][len(2)][segment], sealed by the real encoder.
    const auto frame_segment = [](const std::vector<uint8_t>& seg,
                                  kcp::internal::FecEncoder& enc) {
        std::vector<uint8_t> frame(FEC_CRYPTO_RESERVE + 8 + seg.size());
        std::memcpy(frame.data() + FEC_CRYPTO_RESERVE + 8, seg.data(), seg.size());
        std::vector<std::vector<uint8_t>> parity;
        enc.Encode(frame.data(), frame.size(), 1000, &parity);
        // The sealed data shard only; parity is not needed to drive a handshake.
        return std::vector<uint8_t>(
            frame.begin() + static_cast<std::ptrdiff_t>(FEC_CRYPTO_RESERVE),
            frame.end());
    };

    const auto decrypt_reply = [](const std::vector<uint8_t>& wire,
                                  Crypto& client_crypto,
                                  const char* what) {
        auto plain = client_crypto.decrypt(byte_view(wire.data(), wire.size()));
        CHECK_MESSAGE(plain.size() >= 8, what);
        const uint16_t type = static_cast<uint16_t>(plain[4]) |
                              static_cast<uint16_t>(plain[5] << 8);
        return std::make_pair(std::move(plain), type);
    };

    // ---- A. FEC-off server + FEC-speaking client: session adapts, replies are
    //         FEC-framed, and the unwrapped ACK is a valid KCP segment. --------
    {
        asio::io_context io;
        auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");
        auto fec_encoder =
            kcp::internal::FecEncoder::New(10, 3, static_cast<int>(FEC_CRYPTO_RESERVE));
        CHECK_MESSAGE(fec_encoder != nullptr, "adaptive-test FecEncoder must create");

        const auto salt = Crypto::generate_session_salt();
        Crypto client_crypto(key, NONCE_DIR_CLIENT, salt, false);
        KcpWrapper peer(KCP_CONV);

        // HELLO_V2 as a real KCP segment, then FEC-framed, then encrypted.
        const std::vector<uint8_t> hello(KCP_CONTROL_HELLO_V2,
                                         KCP_CONTROL_HELLO_V2 + std::strlen(KCP_CONTROL_HELLO_V2));
        std::vector<uint8_t> hello_seg;
        peer.set_output_callback([&hello_seg](byte_view d) {
            hello_seg.assign(d.begin(), d.end());
        });
        CHECK_MESSAGE(peer.send(byte_view(hello.data(), hello.size())) >= 0, "peer HELLO send");
        peer.update(10);
        peer.flush();
        CHECK_MESSAGE(!hello_seg.empty(),
                    "the flushed HELLO datagram must be captured for framing");

        const std::vector<uint8_t> framed_first = frame_segment(hello_seg, *fec_encoder);
        auto first = client_crypto.encrypt(byte_view(framed_first.data(), framed_first.size()));
        const LogLevel dbg_prev = current_log_level();
        set_log_level(LogLevel::Debug);
        auto session = server->route_datagram(ep(42001), byte_view(first.data(), first.size()));
        CHECK_MESSAGE(session != nullptr, "a FEC-framed first packet must create a session");

        // Install the collector BEFORE polling: the strand handlers queued by
        // route_datagram (inject + handle_kcp_data) complete the whole
        // handshake on the first poll, so the default send callback (which
        // goes to the unstarted server's socket and drops) must be replaced
        // before any of that runs.
        std::vector<std::vector<uint8_t>> replies;
        session->set_send_callback([&replies](std::vector<std::vector<uint8_t>> wire) {
            for (auto& d : wire)
                replies.push_back(std::move(d));
        });
        io.restart();
        io.poll();

        // A second (duplicate) datagram drives handle_kcp_data, which reads
        // the queued HELLO and answers. The datagram itself may be a KCP
        // duplicate — only its strand dispatch matters here.
        auto dup_seg = hello_seg; // same sn -> KCP dedups, framing still drives
        const std::vector<uint8_t> framed_second = frame_segment(dup_seg, *fec_encoder);
        auto second = client_crypto.encrypt(byte_view(framed_second.data(), framed_second.size()));
        CHECK_MESSAGE(
            server->route_datagram(ep(42001), byte_view(second.data(), second.size())) != nullptr,
            "the second datagram must reuse the adapted session");
        io.restart();
        io.poll();
        set_log_level(dbg_prev);

        CHECK_MESSAGE(!replies.empty(), "the adapted session must answer the HELLO");
        auto [plain, type] = decrypt_reply(replies.front(), client_crypto,
                                           "the reply must decrypt with the client's key");
        CHECK_MESSAGE(type == kcp::kTypeData,
                      "a FEC-speaking client must receive FEC-framed replies");
        // Unwrap [fec_hdr(6)|len(2)|segment] and verify the ACK payload.
        const uint16_t declared =
            static_cast<uint16_t>(plain[6]) | static_cast<uint16_t>(plain[7] << 8);
        CHECK_MESSAGE(declared + 6 == plain.size(),
                      "the reply's FEC length field must match its size");
        KcpWrapper unwrapper(KCP_CONV);
        CHECK_MESSAGE(unwrapper.input(byte_view(plain.data() + 8, plain.size() - 8)) >= 0,
                      "the unwrapped reply must be a valid KCP segment");
        std::vector<uint8_t> ack;
        CHECK_MESSAGE(
            unwrapper.recv(ack) == static_cast<int>(std::strlen(KCP_CONTROL_HELLO_ACK_V2)),
            "the unwrapped reply must carry HELLO_ACK_V2");
        CHECK_MESSAGE(std::memcmp(ack.data(), KCP_CONTROL_HELLO_ACK_V2, ack.size()) == 0,
                      "the ACK payload must be exactly HELLO_ACK_V2");

        session->stop();
    }

    // ---- B. FEC-off server + bare client: session stays bare (byte 4 is a KCP
    //         cmd, not a FEC type), even though the client could have been
    //         "upgraded". Framing must mirror the client, not the server. -----
    {
        asio::io_context io;
        auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");
        const auto salt = Crypto::generate_session_salt();
        Crypto client_crypto(key, NONCE_DIR_CLIENT, salt, false);
        KcpWrapper peer(KCP_CONV);

        const std::vector<uint8_t> hello(KCP_CONTROL_HELLO_V2,
                                         KCP_CONTROL_HELLO_V2 + std::strlen(KCP_CONTROL_HELLO_V2));
        std::vector<uint8_t> hello_seg;
        peer.set_output_callback([&hello_seg](byte_view d) {
            hello_seg.assign(d.begin(), d.end());
        });
        CHECK_MESSAGE(peer.send(byte_view(hello.data(), hello.size())) >= 0, "bare HELLO send");
        peer.update(10);
        peer.flush();
        CHECK_MESSAGE(!hello_seg.empty(), "the bare HELLO datagram must be captured");

        auto first = client_crypto.encrypt(byte_view(hello_seg.data(), hello_seg.size()));
        auto session = server->route_datagram(ep(42002), byte_view(first.data(), first.size()));
        CHECK_MESSAGE(session != nullptr, "a bare first packet must create a session");
        // Collector installed before polling (same ordering as part A).
        std::vector<std::vector<uint8_t>> replies;
        session->set_send_callback([&replies](std::vector<std::vector<uint8_t>> wire) {
            for (auto& d : wire)
                replies.push_back(std::move(d));
        });
        io.restart();
        io.poll();

        auto second = client_crypto.encrypt(byte_view(hello_seg.data(), hello_seg.size()));
        CHECK_MESSAGE(
            server->route_datagram(ep(42002), byte_view(second.data(), second.size())) != nullptr,
            "the second bare datagram must reuse the session");
        io.restart();
        io.poll();

        CHECK_MESSAGE(!replies.empty(), "the bare session must answer the HELLO");
        auto [plain, type] = decrypt_reply(replies.front(), client_crypto,
                                           "the bare reply must decrypt with the client's key");
        (void)type;
        CHECK_MESSAGE(!looks_like_fec_frame(plain.data(), plain.size()),
                      "a bare client must keep receiving bare datagrams");
        // The bare plaintext IS the KCP segment: it must unwrap to HELLO_ACK_V2.
        KcpWrapper unwrapper(KCP_CONV);
        CHECK_MESSAGE(unwrapper.input(byte_view(plain.data(), plain.size())) >= 0,
                      "the bare reply must be a valid KCP segment");
        std::vector<uint8_t> ack;
        CHECK_MESSAGE(
            unwrapper.recv(ack) == static_cast<int>(std::strlen(KCP_CONTROL_HELLO_ACK_V2)),
            "the bare reply must carry HELLO_ACK_V2");
        session->stop();
    }

    // ---- C. Server started WITH -fec + bare client: the client's framing
    //         still wins. A FEC-off client must never be sent framed datagrams
    //         (it would reject them), so the explicit server -fec only matters
    //         for FEC-speaking clients. --------------------------------------
    {
        asio::io_context io;
        auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1", FecConfig{10, 3});
        const auto salt = Crypto::generate_session_salt();
        Crypto client_crypto(key, NONCE_DIR_CLIENT, salt, false);
        KcpWrapper peer(KCP_CONV);

        const std::vector<uint8_t> hello(KCP_CONTROL_HELLO_V2,
                                         KCP_CONTROL_HELLO_V2 + std::strlen(KCP_CONTROL_HELLO_V2));
        std::vector<uint8_t> hello_seg;
        peer.set_output_callback([&hello_seg](byte_view d) {
            hello_seg.assign(d.begin(), d.end());
        });
        CHECK_MESSAGE(peer.send(byte_view(hello.data(), hello.size())) >= 0, "bare HELLO send (C)");
        peer.update(10);
        peer.flush();
        CHECK_MESSAGE(!hello_seg.empty(), "the bare HELLO datagram must be captured (C)");

        auto first = client_crypto.encrypt(byte_view(hello_seg.data(), hello_seg.size()));
        auto session = server->route_datagram(ep(42003), byte_view(first.data(), first.size()));
        CHECK_MESSAGE(session != nullptr, "a bare first packet must create a session (C)");
        // Collector installed before polling (same ordering as part A).
        std::vector<std::vector<uint8_t>> replies;
        session->set_send_callback([&replies](std::vector<std::vector<uint8_t>> wire) {
            for (auto& d : wire)
                replies.push_back(std::move(d));
        });
        io.restart();
        io.poll();

        auto second = client_crypto.encrypt(byte_view(hello_seg.data(), hello_seg.size()));
        CHECK_MESSAGE(
            server->route_datagram(ep(42003), byte_view(second.data(), second.size())) != nullptr,
            "the second bare datagram must reuse the session (C)");
        io.restart();
        io.poll();

        CHECK_MESSAGE(!replies.empty(), "the session must answer the HELLO (C)");
        auto [plain, type] = decrypt_reply(replies.front(), client_crypto,
                                           "the reply must decrypt (C)");
        (void)type;
        CHECK_MESSAGE(!looks_like_fec_frame(plain.data(), plain.size()),
                    "an explicit server -fec must not frame towards a bare client");
        session->stop();
    }
}

TEST_CASE("test_fec_off_detects_a_fec_peer") {
    // The mirror image of the ret_-2 arm in feed_kcp_input. When the LOCAL side
    // has -fec off but the PEER has it on, the datagram is [fec_hdr(6)|len(2)|
    // KCP segment] and this side strips nothing, so ikcp_input reads the FEC
    // seqid as the conv and returns -1. That generic reject line is
    // indistinguishable from any other malformed datagram: before this check the
    // operator saw "FAIL_STAGE=KCP_INPUT_FAILED ERROR=ret_-1" and nothing else.
    // Confirmed on the real server: server without -fec, client with -fec 10:3,
    // server logged ret_-1 while the same failure from the other direction
    // logged the explanatory ret_-2.
    //
    // The fix logs and must NOT change the return value: the datagram still goes
    // to kcp_.input(), so the throttled reject line stays the FAIL_STAGE record
    // of truth at the session layer.
    asio::io_context io;
    auto crypto = std::make_shared<Crypto>("test_key_0123456789", NONCE_DIR_SERVER);
    InertTunnel off(io, 1, crypto, FecConfig{});
    InertTunnel on(io, 1, crypto, FecConfig{10, 3});

    // A peer-encoded FEC frame at the real crypto reserve offset: that is the
    // shape the wire carries once salt+nonce are stripped, i.e. what
    // feed_kcp_input receives. Encode() seals IN PLACE (the data packet is
    // already in the [reserve|hdr|len|payload] layout) and only EMITS parity, so
    // the frame under test is `frame`, not an entry in `emitted`.
    auto encoder = kcp::internal::FecEncoder::New(
        10, 3, static_cast<int>(FEC_CRYPTO_RESERVE));
    CHECK_MESSAGE(encoder != nullptr, "FecEncoder::New(10,3,reserve) must succeed");
    const size_t kcp_len = static_cast<size_t>(KCP_MTU);
    const size_t frame_size = FEC_CRYPTO_RESERVE + 8 + kcp_len;
    std::vector<uint8_t> framed(frame_size, 0);
    for (size_t j = 0; j < kcp_len; j++) {
        framed[FEC_CRYPTO_RESERVE + 8 + j] = static_cast<uint8_t>((j * 17 + 1) & 0xff);
    }
    std::vector<std::vector<uint8_t>> emitted;
    encoder->Encode(framed.data(), framed.size(), 1, &emitted);
    const uint8_t* plain = framed.data() + FEC_CRYPTO_RESERVE;
    const size_t plain_len = framed.size() - FEC_CRYPTO_RESERVE;
    // Sanity: the seal must have written a data header at the reserve offset,
    // otherwise the test would be asserting against the wrong bytes.
    const uint16_t sealed_flag = static_cast<uint16_t>(plain[4]) |
                                 static_cast<uint16_t>(plain[5] << 8);
    CHECK_MESSAGE(sealed_flag == kcp::kTypeData,
                "the encoded frame must carry kTypeData at the reserve offset");

    // ORDER MATTERS. fec_peer_only_log() is one process-wide LogThrottle, so a
    // step that emits a line opens a 1s window during which every later step is
    // silent no matter what the predicate does. A "must stay silent" assertion
    // placed after an emitting step therefore passes even if the predicate is
    // hard-wired to true -- it proves nothing. So the silence check runs FIRST,
    // while the throttle is still virgin, and the emitting checks come after.

    // 1. No false positive: an ordinary KCP segment on an FEC-off tunnel must
    //    stay silent. Its bytes 4..5 are cmd/frg; cmd must be 0x51..0x54 while a
    //    match needs 0xf1..0xf3, so a healthy segment can never trip the probe.
    {
        std::atomic<int> peer_lines{0};
        set_log_sink_for_test([&](LogLevel level, std::string_view,
                                  std::string_view message) {
            if (level == LogLevel::Warning &&
                message.find("local --fec is off") != std::string_view::npos) {
                peer_lines.fetch_add(1, std::memory_order_relaxed);
            }
        });
        const LogLevel prev = current_log_level();
        set_log_level(LogLevel::Debug);
        // A real KCP segment: conv(4) + cmd(1)=PUSH(0x51) + frg(1)=0 + wnd(2)
        // + ts/seq/una/len = the 24-byte header. Offsets 4..5 = 0x51,0x00.
        std::vector<uint8_t> seg(24, 0);
        seg[0] = 1;  // conv = 1, little-endian, matches the tunnel
        seg[4] = static_cast<uint8_t>(kcp::kCmdPush);  // 0x51
        seg[5] = 0;
        off.feed(seg.data(), seg.size());
        set_log_level(prev);
        set_log_sink_for_test(LogSink{});
        CHECK_MESSAGE(peer_lines.load() == 0,
                    "an unframed KCP segment must never trigger the FEC-peer warning");
    }

    // 2. FEC-off side: KCP still refuses (the bytes are not a valid segment),
    //    but the mismatch must be named in a WARNING.
    {
        std::atomic<int> peer_lines{0};
        std::atomic<int> reject_lines{0};
        set_log_sink_for_test([&](LogLevel level, std::string_view,
                                  std::string_view message) {
            if (level != LogLevel::Warning) return;
            if (message.find("local --fec is off") != std::string_view::npos) {
                peer_lines.fetch_add(1, std::memory_order_relaxed);
            }
            if (message.find("FAIL_STAGE=KCP_INPUT_FAILED") != std::string_view::npos) {
                reject_lines.fetch_add(1, std::memory_order_relaxed);
            }
        });
        const LogLevel prev = current_log_level();
        set_log_level(LogLevel::Debug);
        const int ret = off.feed(plain, plain_len);
        set_log_level(prev);
        set_log_sink_for_test(LogSink{});
        CHECK_MESSAGE(ret < 0, "a FEC frame on an FEC-off tunnel must still be refused by KCP");
        CHECK_MESSAGE(peer_lines.load() == 1,
                      "the peer-has-FEC mismatch must be reported exactly once, by name");
        CHECK_MESSAGE(reject_lines.load() == 0,
                    "feed_kcp_input itself must not emit the FAIL_STAGE line; the "
                    "session layer owns it");
    }

    // 3. Throttled: a burst must not turn into one line per datagram.
    {
        std::atomic<int> peer_lines{0};
        set_log_sink_for_test([&](LogLevel level, std::string_view,
                                  std::string_view message) {
            if (level == LogLevel::Warning &&
                message.find("local --fec is off") != std::string_view::npos) {
                peer_lines.fetch_add(1, std::memory_order_relaxed);
            }
        });
        const LogLevel prev = current_log_level();
        set_log_level(LogLevel::Debug);
        constexpr int kDatagrams = 5000;
        for (int i = 0; i < kDatagrams; ++i) {
            off.feed(plain, plain_len);
        }
        set_log_level(prev);
        set_log_sink_for_test(LogSink{});
        CHECK_MESSAGE(peer_lines.load() <= 2,
                    "the mismatch warning must be throttled, not one line per datagram");
    }

}

TEST_CASE("test_kcp_wrapper_oversized_message_is_not_truncated") {
    // FWD_BUF_SIZE is the per-message cap every forwarding loop relies on. A
    // sender that exceeds it is a protocol violation, and the fixed-buffer
    // recv() must report KCP_RECV_MSG_TOO_BIG *without consuming* the message:
    // silently truncating would corrupt the byte stream this proxy exists to
    // preserve, and the caller's recovery (peek + vector overload) depends on
    // the message still being queued.
    KcpWrapper sender(KCP_CONV);
    KcpWrapper receiver(KCP_CONV);
    // Wire both directions so KCP can carry the ACKs the sender needs.
    sender.set_output_callback([&receiver](byte_view d) { (void)receiver.input(d); });
    receiver.set_output_callback([&sender](byte_view d) { (void)sender.input(d); });

    // Bigger than the caller's buffer, so the receiver's own cap is what
    // rejects it -- not a malformed segment.
    const size_t payload_size = FWD_BUF_SIZE + 512;
    std::vector<uint8_t> payload(payload_size);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    }
    CHECK_MESSAGE(sender.send(byte_view(payload.data(), payload.size())) >= 0,
                "sender.send must accept the oversized payload");

    // Drive both sides until the message is fully reassembled.
    uint32_t now = 0;
    for (int i = 0; i < 200 && receiver.peek_size() != static_cast<int>(payload_size); ++i) {
        now += KCP_INTERVAL_MS;
        sender.update(now);
        sender.flush();
        receiver.update(now);
        receiver.flush();
    }
    CHECK_MESSAGE(receiver.peek_size() == static_cast<int>(payload_size),
                "receiver must reassemble the whole message");

    // A buffer that cannot hold it is rejected instead of truncated...
    std::vector<uint8_t> too_small(FWD_BUF_SIZE);
    CHECK_MESSAGE(
        receiver.recv(too_small.data(), too_small.size()) == KcpWrapper::KCP_RECV_MSG_TOO_BIG,
        "oversized message must be reported, never truncated");
    // ...and it stays queued, which is what makes recovery possible.
    CHECK_MESSAGE(receiver.peek_size() == static_cast<int>(payload_size),
                "the rejected message must still be queued");

    // The vector overload is the documented recovery path: it must hand back
    // the full message, byte-exact.
    std::vector<uint8_t> recovered;
    CHECK_MESSAGE(receiver.recv(recovered) == static_cast<int>(payload_size),
                "vector recv must return the whole message");
    CHECK_MESSAGE(recovered == payload, "the recovered payload must be byte-exact");
    // ikcp_peeksize() reports -1 (not 0) once nothing is queued.
    CHECK_MESSAGE(receiver.peek_size() <= 0, "the queue must be drained after recovery");
}

TEST_CASE("test_server_session_routing_and_auth") {
    // get_or_create_session holds the server's only real branching logic (auth,
    // auth rate limit, duplicate-salt rejection, session cap) and the E2E
    // suites only reach it incidentally. route_datagram drives it directly --
    // no bound socket and no KCP timing -- so every reject path is assertable.
    asio::io_context io;
    const std::string key = "remote_test_key_123456";
    auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");

    const auto ep_a = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 40001);
    const auto ep_b = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 40002);

    // A bare SOCKS5 CONNECT is the documented compatibility path: the first
    // valid encrypted packet does not have to be a HELLO.
    const std::vector<uint8_t> connect_req = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80};
    const byte_view req_view(connect_req.data(), connect_req.size());

    const auto salt_a = Crypto::generate_session_salt();
    Crypto client_a(key, NONCE_DIR_CLIENT, salt_a, false);
    auto first = client_a.encrypt(req_view);
    auto session_a = server->route_datagram(ep_a, byte_view(first.data(), first.size()));
    CHECK_MESSAGE(session_a != nullptr, "a valid first packet must create a session");

    // A second packet from the same endpoint reuses that session instead of
    // creating a new one.
    auto second = client_a.encrypt(req_view);
    CHECK_MESSAGE(
        server->route_datagram(ep_a, byte_view(second.data(), second.size())) == session_a,
        "a repeat packet must reuse the endpoint's session");

    // Wrong key: the AEAD tag cannot verify, so no session may be created.
    Crypto wrong_key("wrong_key_0000000000", NONCE_DIR_CLIENT,
                     Crypto::generate_session_salt(), false);
    auto bad = wrong_key.encrypt(req_view);
    CHECK_MESSAGE(server->route_datagram(ep_b, byte_view(bad.data(), bad.size())) == nullptr,
                "a wrong-key packet must be rejected");

    // Duplicate salt: another endpoint must not be able to force a session that
    // shares a live session's salt -- that would reuse the same AES-GCM key and
    // nonce base across two sessions, which is catastrophic for GCM.
    Crypto replayed_salt(key, NONCE_DIR_CLIENT, salt_a, false);
    auto dup = replayed_salt.encrypt(req_view);
    CHECK_MESSAGE(server->route_datagram(ep_b, byte_view(dup.data(), dup.size())) == nullptr,
                "a duplicate session salt must be rejected");

    const std::vector<uint8_t> garbage(64, 0xAB);

    // --- Per-source-address FAILURE gate ---
    // A single address that keeps failing auth is a bad actor: after
    // MAX_AUTH_FAILURES_PER_ADDR_PER_SEC failed decrypts in the window its
    // further packets are dropped BEFORE the decrypt. Use a fresh loopback
    // address so the earlier 127.0.0.1 traffic does not interfere.
    const auto ep_e = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.2"), 40005);
    const auto ep_f = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.2"), 40006);
    const auto ep_g = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.2"), 40007);

    // A SUCCESS must never count against the address: prove a valid packet is
    // accepted and does not consume the failure budget (the gate trips only on
    // failures).
    Crypto client_e(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
    auto valid_e = client_e.encrypt(req_view);
    CHECK_MESSAGE(
        server->route_datagram(ep_e, byte_view(valid_e.data(), valid_e.size())) != nullptr,
        "a valid packet must be accepted (a success never counts toward the failure gate)");

    Crypto client_g(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
    auto valid_g = client_g.encrypt(req_view);
    {
        // The per-datagram WARNINGs this flood triggers would drown the test
        // report; raise the level only for the loop and restore it afterwards.
        const auto prev_level = current_log_level();
        set_log_level(LogLevel::Error);
        // Drive this address's FAILURE count to the threshold with garbage
        // (different ports, same /32, so one shared failure budget).
        for (uint32_t i = 0; i < MAX_AUTH_FAILURES_PER_ADDR_PER_SEC; ++i) {
            (void)server->route_datagram(ep_f, byte_view(garbage.data(), garbage.size()));
        }
        // Now even a VALID packet from the same address is dropped pre-decrypt.
        const bool rejected = server->route_datagram(ep_g, byte_view(valid_g.data(), valid_g.size())) == nullptr;
        set_log_level(prev_level);
        CHECK_MESSAGE(rejected,
                    "a valid packet must be dropped once its source address's per-second FAILURE budget is spent");
    }

    // --- Legitimate high-rate clients must NOT be throttled ---
    // Regression guard for the concurrency path: the gate counts FAILURES, not
    // attempts, so one address opening many concurrent tunnels (each of which
    // authenticates on its first packet) is never limited. Create well over the
    // failure threshold of SUCCESSFUL sessions from a single fresh address; all
    // must be accepted.
    {
        const auto busy_addr = asio::ip::make_address("127.0.0.3");
        bool all_ok = true;
        for (uint32_t i = 0; i < MAX_AUTH_FAILURES_PER_ADDR_PER_SEC * 3; ++i) {
            Crypto c(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
            auto pkt = c.encrypt(req_view);
            const auto ep = asio::ip::udp::endpoint(busy_addr, static_cast<uint16_t>(41000 + i));
            if (server->route_datagram(ep, byte_view(pkt.data(), pkt.size())) == nullptr) {
                all_ok = false;
                break;
            }
        }
        CHECK_MESSAGE(all_ok,
                    "many concurrent successful sessions from one address must not be throttled");
    }

    // --- Global auth budget ---
    // The per-address gate cannot stop a flood spread across many DISTINCT
    // spoofed addresses (each fails only once, staying under its failure
    // threshold), so the global attempt budget is the backstop. Drive it with
    // one garbage attempt from each of many distinct addresses; once it is
    // spent, even a valid packet from a brand-new address must be dropped.
    //
    // The 1s rate-limit window runs on an INJECTED clock (100us per packet):
    // 5002 calls advance fake time ~0.5s, so the window can never reset
    // mid-flood. On the real clock this test raced the window -- under ASAN
    // the 5001-iteration flood took >1s, the window reset, the budget
    // refilled, and the final assertion flipped with build speed.
    {
        auto fake_now = std::chrono::steady_clock::time_point{} +
                        std::chrono::microseconds(1000);
        server->set_auth_clock_for_test([fake_now]() mutable {
            fake_now += std::chrono::microseconds(100);
            return fake_now;
        });
        const auto prev_level = current_log_level();
        set_log_level(LogLevel::Error);
        for (uint32_t i = 0; i <= MAX_AUTH_ATTEMPTS_PER_SEC; ++i) {
            const auto addr = asio::ip::make_address(
                "10." + std::to_string((i >> 16) & 0xFF) + "." +
                std::to_string((i >> 8) & 0xFF) + "." + std::to_string(i & 0xFF));
            const auto ep = asio::ip::udp::endpoint(addr, 40008);
            (void)server->route_datagram(ep, byte_view(garbage.data(), garbage.size()));
        }
        Crypto client_h(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
        auto valid_h = client_h.encrypt(req_view);
        const auto ep_h = asio::ip::udp::endpoint(asio::ip::make_address("10.200.200.200"), 40009);
        const bool rejected = server->route_datagram(ep_h, byte_view(valid_h.data(), valid_h.size())) == nullptr;
        set_log_level(prev_level);
        CHECK_MESSAGE(rejected,
                    "a valid packet must be dropped once the global per-second auth budget is spent");
    }
}

TEST_CASE("test_server_unauth_packet_cannot_evict_live_session") {
    // Regression: get_or_create_session used to answer "is this a reconnect?"
    // with salt_matches(), i.e. from unauthenticated cleartext, and to act on it
    // BEFORE the auth decrypt. So any datagram from a live endpoint whose first
    // 16 bytes differed from the session salt -- one byte total is enough --
    // stopped the session, erased it and closed its upstream TCP socket, and
    // was then itself dropped as unauthenticated. One spoofed packet per
    // teardown, and it sat upstream of the auth rate limiter, so it was not
    // even throttled.
    asio::io_context io;
    const std::string key = "remote_test_key_123456";
    auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");

    const auto ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 41001);
    const std::vector<uint8_t> connect_req = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80};
    const byte_view req_view(connect_req.data(), connect_req.size());

    const auto salt = Crypto::generate_session_salt();
    Crypto client(key, NONCE_DIR_CLIENT, salt, false);
    auto first = client.encrypt(req_view);
    auto live = server->route_datagram(ep, byte_view(first.data(), first.size()));
    CHECK_MESSAGE(live != nullptr, "a valid first packet must create a session");

    const auto prev_level = current_log_level();
    set_log_level(LogLevel::Error);

    // (1) A sub-salt-length datagram: salt_matches() is false by construction,
    // and no decrypt can ever succeed on it.
    const std::vector<uint8_t> tiny{0x00};
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(tiny.data(), tiny.size())) == nullptr,
                "a sub-salt-length datagram must be rejected");

    // (2) A full-length forged datagram whose salt prefix is wrong.
    const std::vector<uint8_t> forged(64, 0x5A);
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(forged.data(), forged.size())) == nullptr,
                "a forged-salt datagram must be rejected");

    set_log_level(prev_level);

    // The live session must have survived both: the next genuine packet, still
    // carrying the ORIGINAL salt, has to land on the very same session object.
    auto again = client.encrypt(req_view);
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(again.data(), again.size())) == live,
                "an unauthenticated datagram must not evict the live session");

    // ...while a genuine reconnect -- a NEW salt that actually authenticates --
    // must still replace it. That is the behaviour the deferred eviction exists
    // to preserve, so pin it too.
    const auto salt2 = Crypto::generate_session_salt();
    Crypto reconnected(key, NONCE_DIR_CLIENT, salt2, false);
    auto re_first = reconnected.encrypt(req_view);
    auto replaced = server->route_datagram(ep, byte_view(re_first.data(), re_first.size()));
    CHECK_MESSAGE(replaced != nullptr, "an authenticated reconnect must create a session");
    CHECK_MESSAGE(replaced != live, "an authenticated reconnect must replace the old session");

    // And the replacement is genuinely usable: its own next packet reuses it.
    auto re_second = reconnected.encrypt(req_view);
    CHECK_MESSAGE(
        server->route_datagram(ep, byte_view(re_second.data(), re_second.size())) == replaced,
        "the reconnected session must serve subsequent packets");
}

TEST_CASE("test_server_stale_handshake_replay_keeps_live_session") {
    // A retransmitted first datagram of an ALREADY-REPLACED session must be
    // refused WITHOUT evicting the session that replaced it. get_or_create_session
    // used to stop and erase the live session first ("authenticated reconnect")
    // and only then consult the salt tombstone: a stale handshake retransmit --
    // whose salt the first acceptance tombstoned -- destroyed the live session
    // and was itself refused, leaving the endpoint with no session and walled
    // off until the TTL expired. Seen in CI: two client tunnels behind one
    // relay endpoint; the first tunnel's handshake retransmit killed the second
    // tunnel's live session mid-transfer.
    asio::io_context io;
    const std::string key = "stale_replay_test_key_01";
    auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");

    const auto ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 41002);
    const std::vector<uint8_t> connect_req = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80};
    const byte_view req_view(connect_req.data(), connect_req.size());

    // Tunnel A: accepted first; keep a copy of its first datagram -- the stale
    // handshake retransmit that the relay/NAT path will replay later.
    const auto salt_a = Crypto::generate_session_salt();
    Crypto tunnel_a(key, NONCE_DIR_CLIENT, salt_a, false);
    auto a_first = tunnel_a.encrypt(req_view);
    auto session_a = server->route_datagram(ep, byte_view(a_first.data(), a_first.size()));
    CHECK_MESSAGE(session_a != nullptr, "the first tunnel must be accepted");

    // Tunnel B from the SAME endpoint: a genuine reconnect (fresh salt) must
    // replace A -- the deferred-eviction contract pinned by
    // test_server_unauth_packet_cannot_evict_live_session.
    const auto salt_b = Crypto::generate_session_salt();
    Crypto tunnel_b(key, NONCE_DIR_CLIENT, salt_b, false);
    auto b_first = tunnel_b.encrypt(req_view);
    auto session_b = server->route_datagram(ep, byte_view(b_first.data(), b_first.size()));
    CHECK_MESSAGE(session_b != nullptr, "the reconnecting tunnel must be accepted");
    CHECK_MESSAGE(session_b != session_a, "the reconnect must replace the old session");

    const auto prev_level = current_log_level();
    set_log_level(LogLevel::Error);

    // A's stale retransmit arrives after B took over: refused ...
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(a_first.data(), a_first.size())) == nullptr,
                  "the stale handshake retransmit must be rejected");

    // ... and B must have survived it: B's own next packet lands on B.
    auto b_second = tunnel_b.encrypt(req_view);
    CHECK_MESSAGE(
        server->route_datagram(ep, byte_view(b_second.data(), b_second.size())) == session_b,
        "the stale retransmit must not evict the live session");

    set_log_level(prev_level);
}

TEST_CASE("test_server_rejects_replayed_salt_after_session_death") {
    // A recorded first datagram replayed after its session has died must be
    // rejected. Without the salt tombstone the server's first-packet
    // replay-window bypass would decrypt it (same salt -> same derived key)
    // and create a brand-new session, re-executing the SOCKS5 CONNECT the
    // recording contains -- the live-session duplicate-salt check cannot see
    // a session that is already gone.
    asio::io_context io;
    const std::string key = "replay_guard_test_key_123";
    auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");

    const auto ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 41001);
    const std::vector<uint8_t> connect_req = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80};
    const byte_view req_view(connect_req.data(), connect_req.size());

    const auto salt = Crypto::generate_session_salt();
    Crypto client(key, NONCE_DIR_CLIENT, salt, false);
    auto first = client.encrypt(req_view);  // the datagram an attacker records

    auto session = server->route_datagram(ep, byte_view(first.data(), first.size()));
    CHECK_MESSAGE(session != nullptr, "the first packet must create a session");

    // Kill it, then drain the io_context so stop() actually clears RUNNING
    // (stop() dispatches onto the session strand).
    session->stop();
    io.poll();
    CHECK_MESSAGE(!session->is_running(), "the session must be stopped before the replay");

    // Replay the recorded datagram verbatim, from the same source endpoint
    // (the realistic case: the attacker reuses the recorded source port).
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(first.data(), first.size())) == nullptr,
                "a replayed first datagram of a dead session must be rejected");

    // The tombstone must not break normal operation: a genuine reconnect with
    // a FRESH salt is still accepted (real clients generate one per session).
    Crypto reconnected(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
    auto fresh = reconnected.encrypt(req_view);
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(fresh.data(), fresh.size())) != nullptr,
                "a fresh-salt session must still be accepted after a tombstone");
}

// The tombstone table is bounded, and hitting the cap must not become a
// server-wide refusal. With the original fail-closed semantics, any
// authenticated peer -- or simply ordinary churn above MAX_SALT_TOMBSTONES /
// SALT_TOMBSTONE_TTL_SEC new sessions per second -- could lock every new client
// out for the remainder of the TTL, to protect a salt that was about to expire
// anyway. remember_salt_locked() now evicts the OLDEST entry instead.
TEST_CASE("test_server_tombstone_cap_evicts_instead_of_locking_out") {
    asio::io_context io;
    const std::string key = "tombstone_cap_test_key_1";
    auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");

    server->fill_salt_tombstones_for_test(MAX_SALT_TOMBSTONES);
    CHECK_MESSAGE(server->salt_tombstone_count_for_test() == MAX_SALT_TOMBSTONES,
                "the table must be exactly at its cap");

    const auto ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 41088);
    const std::vector<uint8_t> connect_req = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80};
    const byte_view req_view(connect_req.data(), connect_req.size());

    Crypto client(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
    auto first = client.encrypt(req_view);
    auto session = server->route_datagram(ep, byte_view(first.data(), first.size()));
    CHECK_MESSAGE(session != nullptr, "a new salt must be accepted when the table is full");
    CHECK_MESSAGE(server->salt_tombstone_count_for_test() == MAX_SALT_TOMBSTONES,
                "accepting it must evict an old tombstone, not grow past the cap");

    // The session created on the eviction path is genuinely usable, not a
    // half-initialised one.
    auto second = client.encrypt(req_view);
    CHECK_MESSAGE(server->route_datagram(ep, byte_view(second.data(), second.size())) == session,
                "the accepted session must keep serving its own salt");
}

// The session's send callback used to capture a STRONG shared_ptr to the server
// while sessions_ holds the session: a two-node cycle, so the server stayed
// alive (and ~KCPServer never ran) for as long as any session was in its own
// map -- i.e. an embedder that drops its last reference leaks the whole server
// plus every session, every EVP context and every ikcpcb in it. Every other
// session-held callback (drained_cb_) is a weak_ptr for exactly this reason.
//
// This also pins down the counterpart requirement: route_datagram's strand
// handlers touch the server through raw `this`, so they must hold a strong
// reference themselves, or breaking the cycle would turn a leak into a
// use-after-free of the server object.
TEST_CASE("test_server_is_released_when_its_owner_drops_it") {
    asio::io_context io;
    const std::string key = "release_cycle_test_key_123";
    std::weak_ptr<KCPServer> weak_server;
    {
        auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");
        weak_server = server;

        const auto ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 41055);
        const std::vector<uint8_t> connect_req = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80};
        Crypto client(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
        auto first = client.encrypt(byte_view(connect_req.data(), connect_req.size()));

        auto session = server->route_datagram(ep, byte_view(first.data(), first.size()));
        CHECK_MESSAGE(session != nullptr, "the first packet must create a session");

        // Nothing but the server's own map (and the handler queued above) keeps
        // them alive from here on.
        session.reset();
        server.reset();
        io.poll();
    }
    CHECK_MESSAGE(weak_server.expired(),
                "dropping the last external reference must destroy the server");
}

// The idle sweep alone cannot reclaim a session whose peer never finishes the
// SOCKS5 handshake: touch_activity() fires on every authenticated packet, so a
// peer holding the key that dribbles an unfinished CONNECT keeps is_alive()
// true forever and pins one of the MAX_CONCURRENT_SESSIONS slots (plus its
// FWD_BUF_SIZE buffers) indefinitely. do_cleanup now also reaps on
// handshake_stalled(), which is measured from creation and never refreshed.
TEST_CASE("test_server_session_handshake_stall_is_bounded") {
    asio::io_context io;
    const std::string key = "handshake_stall_test_key_1";
    auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");

    const auto ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 41077);
    // Truncated CONNECT (VER/CMD/RSV only): parse_socks5_request returns
    // NeedMore, so the session stays in the pending-handshake state.
    const std::vector<uint8_t> partial = {0x05, 0x01, 0x00};
    Crypto client(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
    auto first = client.encrypt(byte_view(partial.data(), partial.size()));

    auto session = server->route_datagram(ep, byte_view(first.data(), first.size()));
    CHECK_MESSAGE(session != nullptr, "the first packet must create a session");
    CHECK_MESSAGE(!session->is_handshake_done(),
                  "a truncated request cannot complete the handshake");
    // The blind spot itself: a stalled session still looks alive to the old
    // sweep condition, so nothing but the new bound reclaims it.
    CHECK_MESSAGE(session->is_alive(), "a handshake-stalled session must still report alive");

    CHECK_MESSAGE(!session->handshake_stalled(SERVER_SOCKS5_HANDSHAKE_TIMEOUT_SEC),
                "a just-created session must not be reaped");
    // Zero grace: the clock runs from creation, so steady dribbling cannot
    // postpone the reap the way it postpones the idle sweep.
    CHECK_MESSAGE(session->handshake_stalled(0), "an overdue handshake must be detected");

    // Completion clears it, so a healthy tunnel can never be reaped this way.
    session->mark_handshake_done();
    CHECK_MESSAGE(!session->handshake_stalled(0),
                "a completed handshake must never count as stalled");
}

TEST_CASE("test_session_oversized_kcp_message_fails_read") {
    // try_fulfill_read() has two distinct reject paths, neither of which was
    // covered: a KCP message larger than FWD_BUF_SIZE (a protocol violation --
    // consumed so KCP stays consistent, then the read is failed) and a message
    // that fits FWD_BUF_SIZE but not the caller's buffer. Both must fail the
    // read rather than hand back a truncated stream, which would corrupt the
    // tunnel the proxy exists to preserve.
    asio::io_context io;
    const std::string key = "remote_test_key_123456";
    const auto salt = Crypto::generate_session_salt();

    // The session decrypts as the server (it learns the salt from the first
    // datagram); the peer encrypts as the client with the same salt, so both
    // derive matching per-direction keys.
    auto server_crypto = std::make_shared<Crypto>(key, NONCE_DIR_SERVER, byte_view{}, true);
    Crypto peer_crypto(key, NONCE_DIR_CLIENT, salt, false);

    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);
    auto session = std::make_shared<KCPSession>(io, KCP_CONV, endpoint, server_crypto,
                                                "oversized-session");

    // Peer KCP output -> encrypt -> session.receive_data (decrypt -> ikcp_input).
    KcpWrapper peer(KCP_CONV);
    peer.set_output_callback([&](byte_view plain) {
        auto wire = peer_crypto.encrypt(plain);
        session->receive_data(byte_view(wire.data(), wire.size()));
    });
    // Session output -> decrypt -> peer ikcp_input, so ACKs can flow back.
    session->set_send_callback([&](std::vector<std::vector<uint8_t>> wire) {
        try {
            for (const auto& d : wire) {
                auto plain = peer_crypto.decrypt(byte_view(d.data(), d.size()));
                (void)peer.input(byte_view(plain.data(), plain.size()));
            }
        } catch (const std::exception&) {
            // Best effort; a datagram the peer cannot decrypt is not the point.
        }
    });

    session->start();
    io.restart();
    io.poll();

    uint32_t now = 0;
    const auto pump_until = [&](const bool& done, int iterations) {
        for (int i = 0; i < iterations && !done; ++i) {
            now += KCP_INTERVAL_MS;
            peer.update(now);
            peer.flush();
            io.restart();
            io.poll();
        }
    };

    // --- path 1: message fits FWD_BUF_SIZE, but not the caller's buffer ------
    std::array<uint8_t, 16> small_buf{};
    bool small_failed = false;
    std::error_code small_ec;
    session->async_read_some(asio::buffer(small_buf), [&](std::error_code ec, size_t) {
        small_failed = true;
        small_ec = ec;
    });
    io.restart();
    io.poll();  // let the read registration reach the strand

    std::vector<uint8_t> payload1(200, 0x11);
    CHECK_MESSAGE(peer.send(byte_view(payload1.data(), payload1.size())) >= 0,
                "peer.send must accept the path-1 payload");
    pump_until(small_failed, 60);
    CHECK_MESSAGE(small_failed, "a message larger than the caller's buffer must fail the read");
    CHECK_MESSAGE(small_ec == asio::error::message_size,
                "path 1 must report message_size, not a truncated success");

    // --- path 2: message larger than FWD_BUF_SIZE (protocol violation) -------
    std::vector<uint8_t> full_buf(FWD_BUF_SIZE);
    bool big_failed = false;
    std::error_code big_ec;
    session->async_read_some(asio::buffer(full_buf), [&](std::error_code ec, size_t) {
        big_failed = true;
        big_ec = ec;
    });
    io.restart();
    io.poll();

    std::vector<uint8_t> payload2(FWD_BUF_SIZE + 256, 0x22);
    CHECK_MESSAGE(peer.send(byte_view(payload2.data(), payload2.size())) >= 0,
                "peer.send must accept the path-2 payload");
    pump_until(big_failed, 120);
    CHECK_MESSAGE(big_failed, "a message larger than FWD_BUF_SIZE must fail the read");
    CHECK_MESSAGE(big_ec == asio::error::message_size,
                  "path 2 must report message_size, not a truncated success");
}

TEST_CASE("test_session_stop_makes_inert") {
    // Regression for the session-cleanup audit: once stop() runs, the session
    // must be fully inert so a dead session can safely linger in the server's
    // sessions_ map (reclaimed by the 30s sweep) without spinning, sending, or
    // crashing the shared 10ms update tick.
    asio::io_context io;
    auto crypto = std::make_shared<Crypto>("remote_test_key_123456", NONCE_DIR_SERVER,
                                           Crypto::generate_session_salt());
    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);
    auto session = std::make_shared<KCPSession>(io, 1, endpoint, crypto, "stop-inert");
    bool sent = false;
    session->set_send_callback([&](std::vector<std::vector<uint8_t>>) {
        sent = true;
    });
    session->start();
    io.poll();
    io.restart();

    CHECK_MESSAGE(session->is_running(), "session should run after start");
    CHECK_MESSAGE(session->is_alive(), "session should be alive after start");

    session->stop();
    io.restart();
    io.poll();

    CHECK_MESSAGE(!session->is_running(), "session must not run after stop");
    CHECK_MESSAGE(!session->is_alive(), "session must not be alive after stop");

    // on_update_tick is driven by the server's shared tick for EVERY session in
    // the map, including stopped ones. On a stopped session it must be a no-op
    // and must NOT invoke the send path.
    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    CHECK_MESSAGE(!sent, "on_update_tick on a stopped session must not send");

    // Idempotent: a second stop must be safe and leave state unchanged.
    session->stop();
    CHECK_MESSAGE(!session->is_running(), "second stop must stay not-running");
    CHECK_MESSAGE(!session->is_alive(), "second stop must stay not-alive");
}

TEST_CASE("test_session_drained_callback_on_target_closed") {
    // Regression for graceful upstream teardown: when the target TCP closes
    // while KCP still has queued data, the session stays alive until wait_send()
    // reaches 0, then the drained callback fires exactly once and tears the
    // session down (close_connection in production). This pins the
    // "fires once, then clears" contract.
    asio::io_context io;
    auto crypto = std::make_shared<Crypto>("remote_test_key_123456", NONCE_DIR_SERVER,
                                            Crypto::generate_session_salt());
    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);
    auto session = std::make_shared<KCPSession>(io, 1, endpoint, crypto, "drain");
    session->set_send_callback([](std::vector<std::vector<uint8_t>>) {});
    session->start();
    io.poll();
    io.restart();

    bool drained = false;
    session->set_drained_callback([&]() { drained = true; });
    session->mark_target_closed();

    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    io.restart();
    CHECK_MESSAGE(drained, "drained callback must fire when target closed and buffer empty");

    // Must not re-fire on a subsequent tick (callback was moved out and nulled).
    drained = false;
    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    CHECK_MESSAGE(!drained, "drained callback must not re-fire");
}

TEST_CASE("test_session_drained_deferred_while_send_buffer_nonempty") {
    // The anti-truncation half of the drained contract, and the one that keeps
    // large responses intact: when the target closes while KCP still holds
    // undelivered bytes, the session must NOT be torn down yet. Doing so would
    // drop the tail of the stream. The companion test above only covers the
    // firing case (empty buffer, callback runs on the first tick); this one
    // pins the deferral, i.e. that wait_send() > 0 withholds the callback.
    asio::io_context io;
    auto crypto = std::make_shared<Crypto>("remote_test_key_123456", NONCE_DIR_SERVER,
                                            Crypto::generate_session_salt());
    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);
    auto session = std::make_shared<KCPSession>(io, 1, endpoint, crypto, "drain-defer");
    session->set_send_callback([](std::vector<std::vector<uint8_t>>) {});
    session->start();
    io.poll();
    io.restart();

    // Queue far more than one KCP segment so the send buffer cannot already be
    // empty when the target closes. Nothing ACKs it, so it stays queued -- the
    // same state the server is in when a fast target FINs a large response.
    std::vector<uint8_t> payload(8192, 0x5A);
    session->send_data(byte_view(payload.data(), payload.size()));
    io.poll();
    io.restart();
    CHECK_MESSAGE(session->wait_send() > 0, "send_data must leave bytes queued in KCP");

    bool drained = false;
    session->set_drained_callback([&]() { drained = true; });
    session->mark_target_closed();

    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    io.restart();
    CHECK_MESSAGE(!drained,
                "drained callback fired while KCP still held undelivered data "
                "(an early teardown would truncate the stream)");
    CHECK_MESSAGE(session->is_alive(),
                "session must stay alive until its send buffer drains");

    session->stop();
}

TEST_CASE("test_session_half_close_fin_gate_and_delivery") {
    // The FIN (half-close) contract, in three parts.
    //
    // 1. GATE. A FIN is only sent to a peer that negotiated it (HELLO_V2 /
    //    ACK_V2), and only once. A V1 peer -- an older client, or Android
    //    CPP_REMOTE before it implements FIN -- would forward the control
    //    message into the tunnel as stream data, so the gate is a wire
    //    compatibility guarantee, not an optimization. Once-only matters
    //    because both teardown paths that call it (a target read EOF and a
    //    later write error) can run.
    // 2. DELIVERY. A received FIN completes the parked read with eof and latches
    //    peer_fin_received(), which is what lets the forwarding loops stop
    //    reading instead of waiting out KCP_TIMEOUT_SEC. Before this, a local
    //    app whose target had hung up stayed blocked for up to a minute, and a
    //    target waiting on the app's half-close for up to three.
    // 3. SCOPING. A FIN is salt-scoped exactly like the keepalive, so one
    //    carrying a foreign salt is ordinary stream data: it must be delivered,
    //    never silently swallowed.
    asio::io_context io;
    const std::string key = "remote_test_key_123456";
    const auto salt = Crypto::generate_session_salt();
    const auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);

    // The session decrypts as the server (it learns the salt from the peer's
    // first datagram); the peer encrypts as the client with the same salt, so
    // both derive matching per-direction keys.
    const auto fin_payload_with = [](const std::vector<uint8_t>& scope_salt) {
        std::vector<uint8_t> payload(KCP_CONTROL_FIN,
                                     KCP_CONTROL_FIN + std::strlen(KCP_CONTROL_FIN));
        payload.insert(payload.end(), scope_salt.begin(), scope_salt.end());
        return payload;
    };

    // ---- 1. the gate: who may be sent a FIN, and how often ------------------
    {
        auto server_crypto = std::make_shared<Crypto>(key, NONCE_DIR_SERVER, byte_view{}, true);
        Crypto peer_crypto(key, NONCE_DIR_CLIENT, salt, false);
        auto session =
            std::make_shared<KCPSession>(io, KCP_CONV, endpoint, server_crypto, "fin-gate");
        std::vector<std::vector<uint8_t>> emitted;
        session->set_send_callback([&](std::vector<std::vector<uint8_t>> wire) {
            for (auto& d : wire)
                emitted.push_back(std::move(d));
        });
        session->start();
        io.restart();
        io.poll();

        // The FIN payload is scoped with the peer's salt, so the peer has to
        // speak first -- exactly as the server learns it in production.
        KcpWrapper peer(KCP_CONV);
        peer.set_output_callback([&](byte_view plain) {
            auto wire = peer_crypto.encrypt(plain);
            session->receive_data(byte_view(wire.data(), wire.size()));
        });
        std::vector<uint8_t> seed(8, 0x42);
        CHECK_MESSAGE(peer.send(byte_view(seed.data(), seed.size())) >= 0, "peer seed send");
        uint32_t now = 0;
        // ikcp_flush() is a no-op until ikcp_update() has run once, so every
        // pump below advances the peer's clock before flushing.
        for (int i = 0; i < 60 && server_crypto->session_salt().empty(); ++i) {
            now += KCP_INTERVAL_MS;
            peer.update(now);
            peer.flush();
            io.restart();
            io.poll();
        }
        CHECK_MESSAGE(server_crypto->session_salt().size() == salt.size(),
                    "the session must learn the peer's salt from its first datagram");

        // Not negotiated: a V1 peer must never see one.
        emitted.clear();
        session->send_fin();
        io.restart();
        io.poll();
        CHECK_MESSAGE(emitted.empty(), "send_fin must be a no-op until FIN is negotiated");

        // Negotiated: exactly one FIN, however many times it is requested.
        session->enable_fin();
        session->send_fin();
        session->send_fin();
        io.restart();
        io.poll();

        const auto expected = fin_payload_with(salt);
        size_t fin_segments = 0;
        for (const auto& enc : emitted) {
            std::vector<uint8_t> plain;
            try {
                plain = peer_crypto.decrypt(byte_view(enc.data(), enc.size()));
            } catch (const std::exception&) {
                continue;
            }
            if (plain.size() >= expected.size() &&
                std::memcmp(plain.data() + (plain.size() - expected.size()),
                            expected.data(), expected.size()) == 0) {
                ++fin_segments;
            }
        }
        CHECK_MESSAGE(fin_segments == 1,
                    "an enabled session must emit exactly one FIN, scoped with its salt");
        session->stop();
    }

    // ---- 2. delivery: a FIN completes the parked read with eof --------------
    {
        auto server_crypto = std::make_shared<Crypto>(key, NONCE_DIR_SERVER, byte_view{}, true);
        Crypto peer_crypto(key, NONCE_DIR_CLIENT, salt, false);
        auto session = std::make_shared<KCPSession>(io, KCP_CONV, endpoint, server_crypto, "fin-rx");
        session->set_send_callback([](std::vector<std::vector<uint8_t>>) {});
        session->start();
        io.restart();
        io.poll();

        KcpWrapper peer(KCP_CONV);
        peer.set_output_callback([&](byte_view plain) {
            auto wire = peer_crypto.encrypt(plain);
            session->receive_data(byte_view(wire.data(), wire.size()));
        });

        std::array<uint8_t, FWD_BUF_SIZE> buf{};
        bool completed = false;
        std::error_code read_ec;
        session->async_read_some(asio::buffer(buf), [&](std::error_code ec, size_t) {
            completed = true;
            read_ec = ec;
        });
        io.restart();
        io.poll();

        const auto payload = fin_payload_with(salt);
        CHECK_MESSAGE(peer.send(byte_view(payload.data(), payload.size())) >= 0, "peer FIN send");
        uint32_t now = 0;
        for (int i = 0; i < 60 && !completed; ++i) {
            now += KCP_INTERVAL_MS;
            peer.update(now);
            peer.flush();
            io.restart();
            io.poll();
        }
        CHECK_MESSAGE(completed, "a FIN must complete the parked read instead of hanging it");
        CHECK_MESSAGE(
            read_ec == asio::error::eof,
            "a FIN must complete the read with eof, the signal the forwarding loops act on");
        CHECK_MESSAGE(session->peer_fin_received(), "a FIN must latch peer_fin_received()");
        session->stop();
    }

    // ---- 3. scoping: a foreign salt is stream data, not a FIN ---------------
    {
        auto server_crypto = std::make_shared<Crypto>(key, NONCE_DIR_SERVER, byte_view{}, true);
        Crypto peer_crypto(key, NONCE_DIR_CLIENT, salt, false);
        auto session = std::make_shared<KCPSession>(io, KCP_CONV, endpoint, server_crypto,
                                                    "fin-foreign");
        session->set_send_callback([](std::vector<std::vector<uint8_t>>) {});
        session->start();
        io.restart();
        io.poll();

        KcpWrapper peer(KCP_CONV);
        peer.set_output_callback([&](byte_view plain) {
            auto wire = peer_crypto.encrypt(plain);
            session->receive_data(byte_view(wire.data(), wire.size()));
        });

        std::array<uint8_t, FWD_BUF_SIZE> buf{};
        bool completed = false;
        std::error_code read_ec;
        size_t read_bytes = 0;
        session->async_read_some(asio::buffer(buf), [&](std::error_code ec, size_t bytes) {
            completed = true;
            read_ec = ec;
            read_bytes = bytes;
        });
        io.restart();
        io.poll();

        // Same magic, different salt: only a peer holding THIS session's salt
        // may half-close it.
        const auto foreign = fin_payload_with(Crypto::generate_session_salt());
        CHECK_MESSAGE(peer.send(byte_view(foreign.data(), foreign.size())) >= 0,
                      "peer foreign send");
        uint32_t now = 0;
        for (int i = 0; i < 60 && !completed; ++i) {
            now += KCP_INTERVAL_MS;
            peer.update(now);
            peer.flush();
            io.restart();
            io.poll();
        }
        CHECK_MESSAGE(completed, "a foreign-salt FIN must be delivered as data, not dropped");
        CHECK_MESSAGE(!read_ec, "a foreign-salt FIN must not be reported as eof");
        CHECK_MESSAGE(read_bytes == foreign.size(),
                    "a foreign-salt FIN must arrive as ordinary stream bytes");
        CHECK_MESSAGE(!session->peer_fin_received(),
                    "a foreign-salt FIN must not latch the half-close flag");
        session->stop();
    }
}

// --------------------------------------------------------------------------- //
// client-side cleanup contract (KCPClientSession::close / abort_handshake)
// --------------------------------------------------------------------------- //
//
// The server-side teardown is pinned by the KCPSession tests above. The client
// is not symmetric: KCPProxyClient::abort_handshake() (client.hpp) is the single
// funnel for every failed SOCKS5/KCP handshake, and all it does beyond closing
// the local TCP socket is call KCPClientSession::close(). These tests pin the
// contract that funnel depends on, so the class of bug it was written to fix
// (a failed handshake leaking the session + its UDP socket until the idle
// timeout, because only the deadline timer was cancelled) cannot come back.

uint16_t free_tcp_port() {
    asio::io_context io;
    asio::ip::tcp::acceptor acceptor(
        io, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return acceptor.local_endpoint().port();
}

uint16_t free_udp_port() {
    asio::io_context io;
    asio::ip::udp::socket sock(
        io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return sock.local_endpoint().port();
}

std::shared_ptr<KCPClientSession> make_client_session(asio::io_context& io,
                                                      uint16_t server_port) {
    auto crypto = std::make_shared<Crypto>("remote_test_key_123456", NONCE_DIR_CLIENT,
                                           Crypto::generate_session_salt());
    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), server_port);
    return std::make_shared<KCPClientSession>(io, endpoint, crypto);
}

TEST_CASE("test_client_session_close_before_connect_is_safe_and_idempotent") {
    // abort_handshake() can run before the session ever reached connect(): the
    // local app may disconnect (or send a bad greeting) while the SOCKS5 step is
    // still in flight, and the handshake deadline can fire first. close() must
    // therefore be safe on a session whose running_ is still false, and must
    // tolerate being called more than once (the funnel is idempotent by design).
    asio::io_context io;
    auto session = make_client_session(io, free_udp_port());

    CHECK_MESSAGE(!session->is_connected(), "fresh client session must not look connected");

    session->close();
    io.poll();
    io.restart();
    CHECK_MESSAGE(!session->is_connected(), "close before connect must not connect the session");

    session->close();
    io.restart();
    io.poll();
    CHECK_MESSAGE(!session->is_connected(), "second close must stay a no-op");

    // KCPProxyClient's shared 10ms tick calls on_update_tick() for every
    // registered session; on a closed one it must be inert (no crash, no queued
    // data), exactly as the server-side equivalent must be.
    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.restart();
    io.poll();
    CHECK_MESSAGE(!session->is_connected(),
                  "on_update_tick on a closed session must not revive it");
    CHECK_MESSAGE(session->wait_send() == 0, "closed session must not queue KCP data");
}

TEST_CASE("test_client_session_close_mid_handshake_makes_it_inert") {
    // The state abort_handshake() has to leave the session in. While the
    // handshake read is parked the session is live, so a caller's read is
    // rejected instead of stacked (observable proof of the parked read); after
    // close() the session must be inert -- reads abort immediately rather than
    // parking forever, which would strand a forwarding loop.
    asio::io_context io;
    auto session = make_client_session(io, free_udp_port());

    // connect() starts the session (running_ = true) and parks its own read for
    // the HELLO_ACK. No peer answers, so it stays pending -- which is all this
    // test needs; the 3s handshake timeout never elapses.
    session->connect([](bool) {});
    io.poll();
    io.restart();

    std::array<uint8_t, 16> buf{};
    bool stacked_called = false;
    std::error_code stacked_ec;
    session->async_read_some(asio::buffer(buf), [&](std::error_code ec, size_t) {
        stacked_called = true;
        stacked_ec = ec;
    });
    io.poll();
    io.restart();
    CHECK_MESSAGE(stacked_called, "read issued while the handshake read is parked must not hang");
    CHECK_MESSAGE(stacked_ec == asio::error::already_started,
                "a stacked read must be rejected with already_started");

    session->close();
    io.poll();
    io.restart();
    io.poll();
    CHECK_MESSAGE(!session->is_connected(), "closed session must not report connected");

    bool read_called = false;
    std::error_code read_ec;
    session->async_read_some(asio::buffer(buf), [&](std::error_code ec, size_t) {
        read_called = true;
        read_ec = ec;
    });
    io.poll();
    io.restart();
    io.poll();
    CHECK_MESSAGE(read_called, "read on a closed session must complete, not hang");
    CHECK_MESSAGE(read_ec == asio::error::operation_aborted,
                "read on a closed session must report operation_aborted");
    CHECK_MESSAGE(!session->is_connected(), "session must stay closed");
}

TEST_CASE("test_client_session_close_releases_parked_handler") {
    // The leak regression, made observable. connect() parks a read handler that
    // captures the session's own shared_ptr; if close() did not release it, the
    // session -- and with it the UDP socket -- would outlive every owner, which
    // is exactly the leak abort_handshake() was written to stop. A weak_ptr is
    // the instrument: once close() has run and the completions it queued have
    // been drained, no handler may still be holding the session.
    asio::io_context io;
    std::weak_ptr<KCPClientSession> weak;
    {
        auto session = make_client_session(io, free_udp_port());
        weak = session;
        session->connect([](bool) {});
        io.poll();
        io.restart();

        session->close();
        io.poll();
        io.restart();
        io.poll();
    }
    // Drain whatever the teardown queued (aborted read, cancelled timer, aborted
    // UDP receive): each of those handlers holds a self-reference until it runs.
    io.restart();
    io.poll();
    CHECK_MESSAGE(weak.expired(),
                "closed client session was still referenced by a parked handler "
                "(session + UDP socket leak)");
}

TEST_CASE("test_client_session_keepalive_released_with_session") {
    // set_keepalive() carries the client's session-cap ticket (see
    // handle_client_connection in client.cpp): the counter must drop exactly
    // when the session object dies, on every teardown path, which is what lets
    // the cap survive handshake failures without a per-path cleanup hook. Pin
    // that the resource is owned by the session and released with it.
    asio::io_context io;
    auto probe = std::make_shared<int>(1);
    {
        auto session = make_client_session(io, free_udp_port());
        session->set_keepalive(probe);
        CHECK_MESSAGE(probe.use_count() == 2, "the session must hold the keepalive resource");
    }
    CHECK_MESSAGE(probe.use_count() == 1,
                "keepalive resource must be released when the session is destroyed");
}

// Stops the client's io_context and joins its runner on scope exit, so an
// assertion failure (which throws) cannot leave a joinable std::thread behind
// and terminate the process.
struct ClientIoGuard {
    asio::io_context& io;
    std::thread& runner;
    ~ClientIoGuard() {
        io.stop();
        if (runner.joinable()) runner.join();
    }
};

TEST_CASE("test_client_abort_handshake_closes_local_socket") {
    // Regression for abort_handshake() (see client.hpp). The KCP handshake to an
    // unreachable server never completes, so the failure path must close BOTH
    // the local app socket and the KCP session. Before the fix only the deadline
    // was cancelled, whose callback owned the cleanup and returns early on
    // operation_aborted -- so the local app kept a socket that would never
    // answer, and the session + UDP socket leaked until the idle timeout.
    //
    // What is asserted here is the half the local app can see: its socket is
    // closed promptly instead of hanging. The session half is pinned by the
    // KCPClientSession tests above (close() drops the parked handler and
    // releases the UDP socket / keepalive ticket).
    asio::io_context io;
    const uint16_t listen_port = free_tcp_port();
    const uint16_t dead_server_port = free_udp_port();  // deliberately nothing here

    auto client = std::make_shared<KCPProxyClient>(
        io, "127.0.0.1", dead_server_port, "remote_test_key_123456",
        "127.0.0.1", listen_port);
    client->start();

    std::thread runner([&io]() { io.run(); });
    ClientIoGuard guard{io, runner};

    const auto listen_ep =
        asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), listen_port);

    // The listener comes up asynchronously (resolve -> bind -> listen).
    asio::io_context probe_io;
    bool up = false;
    for (int i = 0; i < 100 && !up; ++i) {
        asio::ip::tcp::socket probe(probe_io);
        std::error_code ec;
        probe.connect(listen_ep, ec);
        up = !ec;
        if (up) {
            probe.close(ec);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    CHECK_MESSAGE(up, "client SOCKS5 listener never came up");

    // A local app opens a tunnel. The KCP handshake times out after
    // KCP_HANDSHAKE_TIMEOUT_SEC, after which abort_handshake() must close this
    // socket rather than leave the app waiting on a tunnel that will never come.
    asio::io_context app_io;
    asio::ip::tcp::socket app(app_io);
    std::error_code ec;
    app.connect(listen_ep, ec);
    CHECK_MESSAGE(!ec, "local app could not connect to the client listener");
    const std::array<uint8_t, 3> greeting{0x05, 0x01, 0x00};
    asio::write(app, asio::buffer(greeting), ec);

    bool peer_closed = false;
    bool timed_out = false;
    std::array<uint8_t, 32> buf{};
    asio::steady_timer deadline(app_io);
    deadline.expires_after(std::chrono::seconds(15));
    deadline.async_wait([&](const std::error_code& timer_ec) {
        if (!timer_ec) timed_out = true;
    });
    app.async_read_some(asio::buffer(buf),
        [&](const std::error_code& read_ec, size_t n) {
            // A clean close surfaces as EOF, an abrupt one as connection_reset.
            peer_closed = (read_ec == asio::error::eof) ||
                          (read_ec == asio::error::connection_reset) ||
                          (!read_ec && n == 0);
            deadline.cancel();
        });
    app_io.run();

    CHECK_MESSAGE(!timed_out,
                "abort_handshake left the local app hanging after the KCP "
                "handshake failed (socket neither closed nor reset)");
    CHECK_MESSAGE(peer_closed,
                "abort_handshake must close the local socket when the KCP handshake fails");

    // The client must still be serving afterwards: a fresh local connection is
    // accepted, which also shows the failed session was released rather than
    // held against the session cap.
    asio::ip::tcp::socket app2(app_io);
    app2.connect(listen_ep, ec);
    CHECK_MESSAGE(!ec, "client stopped accepting connections after a failed handshake");
    app2.close(ec);
    app.close(ec);
}

// The RST-discard race in abort_handshake(), made observable end to end.
//
// A local app that opens with a malformed greeting AND pipelines one extra
// byte ([0x04, 0x01, 0x00] -- the greeting read consumes only the first two)
// used to lose the 0x05 0xFF method-selection reply ~25% of the time on
// Windows: abort_handshake() called close() with the third byte still sitting
// in the receive queue, the kernel answered a close-with-unread-data with an
// RST, and the RST DISCARDED the reply bytes already queued for the app. The
// app saw connection_reset where RFC 1928 promised a reply -- and the same
// shape (reply + pipelined bytes) covers every rejection path: 0xFF for a
// bad greeting, 0x07 for BIND/UDP-ASSOCIATE, 0x04 for an SSRF-blocked target.
//
// The race is an arrival-order contest, so it is not assertable in a single
// shot; the exchange therefore repeats. close_local_socket() drains the
// queue and half-closes (FIN) before closing, so every iteration must deliver
// exactly the two reply bytes followed by a clean EOF.
//
// A live in-process KCP server is required because the greeting is only read
// after the KCP handshake succeeds (see handle_client_connection): against a
// dead server port the greeting is never consumed and nothing is replied.
TEST_CASE("test_client_malformed_greeting_keeps_its_reply") {
    asio::io_context io;
    const std::string key = "remote_test_key_123456";
    const uint16_t server_port = free_udp_port();
    const uint16_t listen_port = free_tcp_port();

    auto server = std::make_shared<KCPServer>(io, server_port, key, "127.0.0.1");
    server->start();
    auto client = std::make_shared<KCPProxyClient>(
        io, "127.0.0.1", server_port, key, "127.0.0.1", listen_port);
    client->start();

    std::thread runner([&io]() { io.run(); });
    ClientIoGuard guard{io, runner};

    const auto listen_ep =
        asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), listen_port);

    // The listener comes up asynchronously (resolve -> bind -> listen).
    asio::io_context probe_io;
    bool up = false;
    for (int i = 0; i < 100 && !up; ++i) {
        asio::ip::tcp::socket probe(probe_io);
        std::error_code ec;
        probe.connect(listen_ep, ec);
        up = !ec;
        if (up) {
            probe.close(ec);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    CHECK_MESSAGE(up, "client SOCKS5 listener never came up");

    // 20 iterations: without the fix the per-iteration loss probability was
    // ~25%, so a broken close is caught with probability 1 - 0.75^20 > 99.6%.
    // The per-connection INFO chatter (new connection / greeting / KCP
    // session lines) would otherwise bury the report, so it is folded away
    // for the loop only -- a failing iteration still logs at ERROR.
    int lost_replies = 0;
    int resets = 0;
    const int iterations = 20;
    const auto prev_level = current_log_level();
    set_log_level(LogLevel::Error);
    for (int i = 0; i < iterations; ++i) {
        asio::io_context app_io;
        asio::ip::tcp::socket app(app_io);
        std::error_code ec;
        app.connect(listen_ep, ec);
        CHECK_MESSAGE(!ec, "local app could not connect to the client listener");

        // Malformed greeting (version 0x04) with one pipelined extra byte.
        const std::array<uint8_t, 3> greeting{0x04, 0x01, 0x00};
        asio::write(app, asio::buffer(greeting), ec);

        // The reply must arrive intact: exactly [0x05, 0xFF].
        std::array<uint8_t, 2> reply{};
        asio::read(app, asio::buffer(reply), ec);
        if (ec || reply[0] != SOCKS5_VERSION ||
            reply[1] != SOCKS5_AUTH_NO_ACCEPTABLE) {
            if (ec == asio::error::connection_reset) ++resets;
            ++lost_replies;
            LOG_ERROR("test", "iteration " + std::to_string(i) +
                      ": reply lost (ec=" +
                      (ec ? ec.message() : std::string("none")) + ")");
            app.close(ec);
            continue;
        }

        // ...then a clean FIN, never an RST, and never an echo of the byte
        // the greeting parse left behind.
        std::array<uint8_t, 1> extra{};
        const size_t n = app.read_some(asio::buffer(extra), ec);
        if (ec != asio::error::eof) {
            if (ec == asio::error::connection_reset) ++resets;
            ++lost_replies;
            LOG_ERROR("test", "iteration " + std::to_string(i) +
                      ": expected FIN after the reply, got ec=" +
                      (ec ? ec.message()
                          : std::string("none, n=" + std::to_string(n))));
        }
        app.close(ec);
    }
    set_log_level(prev_level);

    CHECK_MESSAGE(lost_replies == 0,
                "a malformed greeting must always be answered before the close "
                "(an RST discards the reply -- see close_local_socket)");
    CHECK_MESSAGE(resets == 0, "the rejection close must be a FIN, not an RST");

    // The client must still be serving afterwards, and the rejected sessions
    // must have been released rather than held against the session cap.
    asio::io_context app_io;
    asio::ip::tcp::socket app2(app_io);
    std::error_code ec;
    app2.connect(listen_ep, ec);
    CHECK_MESSAGE(!ec, "client stopped accepting connections after rejections");
    app2.close(ec);

    server->stop();
}

// --allow-target is the only SSRF-guard bypass, so its parser is pinned
// boundary by boundary. The wrapping regressions are the point of the two
// "must NOT match" cases: loose std::stoi parsing used to turn "host:99999"
// into port 34463 and "host:-1" into 65535, silently allowlisting the wrong
// port. Malformed entries must match nothing, never crash, never widen.
// The server's packet-rejection diagnostics must collapse into at most one line
// per interval, because they otherwise fire once per hostile datagram (see
// LogThrottle). What must NOT change is the first line of a burst: the
// robustness suite greps the flood log for exactly those messages, so a
// throttle that swallowed the first occurrence would turn a flood into a
// silent one -- and silently losing the diagnostic is worse than the spam.
TEST_CASE("test_log_throttle") {
    LogThrottle throttle(std::chrono::milliseconds(40));
    uint32_t suppressed = 0;

    // The first call always emits, reporting nothing suppressed.
    suppressed = 12345;  // must be overwritten on the emitting path
    CHECK_MESSAGE(throttle.should_log(suppressed), "first call must emit");
    CHECK_MESSAGE(suppressed == 0, "first emission reports nothing suppressed");

    // Everything inside the window is folded in instead of logged.
    for (uint32_t i = 0; i < 3; ++i) {
        suppressed = 12345;
        CHECK_MESSAGE(!throttle.should_log(suppressed),
                    "a call inside the window must be suppressed");
        CHECK_MESSAGE(suppressed == 12345, "a suppressed call must not touch the out-param");
        CHECK_MESSAGE(throttle.pending() == i + 1, "pending() tracks the suppressed occurrences");
    }

    // After the window elapses the next call emits and reports the tally, which
    // then resets -- so a flood yields one line per interval carrying the count.
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    suppressed = 0;
    CHECK_MESSAGE(throttle.should_log(suppressed), "post-window call must emit");
    CHECK_MESSAGE(suppressed == 3, "emission must report the suppressed count");
    CHECK_MESSAGE(throttle.pending() == 0, "the tally resets after an emission");
}

TEST_CASE("test_log_throttle_concurrent_calls_balance") {
    // LogThrottle is now internally synchronized because Crypto::decrypt_impl's
    // rejection paths share process-wide instances across the server's UDP
    // strand AND every session strand (see crypto.cpp). The invariant that
    // makes the mutex observable: every call either emits or is folded into a
    // later emission's tally, so across T threads the books must still balance
    // exactly. A lost ++suppressed_ -- the symptom of the data race the mutex
    // exists to stop -- leaves folded occurrences unaccounted for. The balance
    // is timing-independent, so this cannot flake.
    LogThrottle throttle(std::chrono::milliseconds(20));
    constexpr int kThreads = 8;
    constexpr int kCallsPerThread = 400;

    std::atomic<int> emissions{0};
    std::atomic<uint32_t> reported{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&throttle, &emissions, &reported, kCallsPerThread] {
            for (int i = 0; i < kCallsPerThread; ++i) {
                uint32_t suppressed = 0;
                if (throttle.should_log(suppressed)) {
                    emissions.fetch_add(1, std::memory_order_relaxed);
                    reported.fetch_add(suppressed, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& thread : threads) thread.join();

    const uint32_t total = static_cast<uint32_t>(kThreads * kCallsPerThread);
    const uint32_t folded_away = total - static_cast<uint32_t>(emissions.load());
    CHECK_MESSAGE(reported.load() + throttle.pending() == folded_away,
                "concurrent LogThrottle calls lost occurrences "
                "(suppressed tally does not balance: unsynchronized?)");
}

TEST_CASE("test_allowlist_matching") {
    using kcp_proxy::parse_allow_target_entry;
    using kcp_proxy::target_matches_allowlist;

    std::string host;
    bool has_port = false;
    uint16_t port = 0;

    // Exact host+port entries.
    CHECK_MESSAGE(parse_allow_target_entry("127.0.0.1:9000", host, has_port, port),
                "host:port entry should parse");
    CHECK_MESSAGE(host == "127.0.0.1", "host:port parsed host");
    CHECK_MESSAGE(has_port, "host:port entry must set has_port");
    CHECK_MESSAGE(port == 9000, "host:port parsed port");
    CHECK_MESSAGE(target_matches_allowlist({"127.0.0.1:9000"}, "127.0.0.1", 9000),
                "exact entry matches its host and port");
    CHECK_MESSAGE(!target_matches_allowlist({"127.0.0.1:9000"}, "127.0.0.1", 9001),
                "exact entry must not match a different port");
    CHECK_MESSAGE(!target_matches_allowlist({"127.0.0.1:9000"}, "127.0.0.2", 9000),
                "exact entry must not match a different host");

    // Host-only entries match every port on that host (documented semantics).
    CHECK_MESSAGE(target_matches_allowlist({"127.0.0.1"}, "127.0.0.1", 1),
                "host-only entry matches low port");
    CHECK_MESSAGE(target_matches_allowlist({"127.0.0.1"}, "127.0.0.1", 65535),
                "host-only entry matches high port");
    CHECK_MESSAGE(!target_matches_allowlist({"127.0.0.1"}, "127.0.0.2", 1),
                "host-only entry must not match another host");
    CHECK_MESSAGE(target_matches_allowlist({"example.com"}, "example.com", 443),
                "hostname-only entry matches any port");
    CHECK_MESSAGE(target_matches_allowlist({"example.com:443"}, "example.com", 443),
                "hostname:port entry matches");

    // IPv6 forms.
    CHECK_MESSAGE(parse_allow_target_entry("[::1]:9000", host, has_port, port),
                "bracketed IPv6 with port should parse");
    CHECK_MESSAGE(host == "::1", "bracketed IPv6 parsed host");
    CHECK_MESSAGE(has_port, "bracketed IPv6 entry must set has_port");
    CHECK_MESSAGE(port == 9000, "bracketed IPv6 parsed port");
    CHECK_MESSAGE(target_matches_allowlist({"[::1]:9000"}, "::1", 9000),
                "bracketed IPv6 entry matches");
    CHECK_MESSAGE(target_matches_allowlist({"[::1]"}, "::1", 1234),
                "bracketed host-only IPv6 matches any port");
    CHECK_MESSAGE(target_matches_allowlist({"::1"}, "::1", 1234),
                "bare multi-colon IPv6 is a host-only entry");
    CHECK_MESSAGE(target_matches_allowlist({"2001:db8::1"}, "2001:db8::1", 80),
                "bare IPv6 literal host-only matches");
    CHECK_MESSAGE(!target_matches_allowlist({"[::1]:9000"}, "::1", 9001),
                "bracketed entry must not match another port");

    // Malformed entries are rejected by the parser and match nothing.
    //
    // The over-long ports matter beyond mere strictness: the parser used to
    // check "all digits" and then call std::stol, but digits do not imply the
    // value fits in a long. On Windows (32-bit long) "host:3000000000" made
    // std::stol throw std::out_of_range, and --allow-target is parsed in
    // main()'s argv loop -- OUTSIDE its try block -- so the exception escaped
    // as an uncaught exception and the process aborted with no diagnostic at
    // all, instead of the documented "Error: invalid --allow-target entry".
    // These cases must return false, never throw.
    const char* malformed[] = {
        "", ":80", "host:", "host:-1", "host:99999", "host:80x",
        "host:0", "[::1", "[::1]x", "[::1]:", "[]:80", "[::1]:99999",
        "host:65536",
        "host:3000000000", "[::1]:3000000000", "host:99999999999999999999999"
    };
    for (const char* entry : malformed) {
        CHECK_MESSAGE(!parse_allow_target_entry(entry, host, has_port, port),
                      "malformed entry must be rejected");
        CHECK_MESSAGE(!target_matches_allowlist({entry}, "host", 9000),
                      "malformed entry must not match host:9000");
        CHECK_MESSAGE(!target_matches_allowlist({entry}, "::1", 9000),
                      "malformed entry must not match [::1]:9000");
    }
    // The wrapping regressions: these ports must not have been silently
    // allowlisted by the typo'd entries above.
    CHECK_MESSAGE(!target_matches_allowlist({"host:99999"}, "host", 34463),
                "port 99999 must not wrap to 34463");
    CHECK_MESSAGE(!target_matches_allowlist({"host:-1"}, "host", 65535),
                "port -1 must not wrap to 65535");

    // No wildcard support: '*' (and any glob-ish entry) is inert.
    CHECK_MESSAGE(!target_matches_allowlist({"*"}, "anything", 80),
                "wildcard entry must not match everything");
    CHECK_MESSAGE(!target_matches_allowlist({"*:80"}, "anything", 80),
                "wildcard host with port must not match");

    // A malformed entry is skipped without hiding a later valid one, and the
    // matcher is safe against an empty allowlist (production default).
    CHECK_MESSAGE(target_matches_allowlist({"host:", "127.0.0.1:9000"}, "127.0.0.1", 9000),
                  "valid entry after a malformed one still matches");
    CHECK_MESSAGE(!target_matches_allowlist({}, "127.0.0.1", 9000),
                  "empty allowlist matches nothing");
}

// --------------------------------------------------------------------------- //
// Round 1-5: adversarial review follow-ups
// --------------------------------------------------------------------------- //

TEST_CASE("test_log_throttle_saturates_instead_of_wrapping") {
    constexpr uint32_t kU32Max = std::numeric_limits<uint32_t>::max();
    // The tally is what an operator reads to size a flood. A counter that wraps
    // at 2^32 reports a count LOWER than what was actually dropped -- and does
    // so silently, only under the sustained flood where the number matters.
    LogThrottle throttle(std::chrono::seconds(30));

    // Far past the uint32 range: a saturated counter must still report the
    // maximum, never wrap around to a small (or zero) number.
    throttle.add_suppressed_for_test(static_cast<uint64_t>(kU32Max) + 1000ull);
    CHECK_MESSAGE(throttle.pending() == kU32Max,
                "suppressed tally must saturate at kU32Max");

    // And it must stay there, not decay past the cap on further occurrences.
    throttle.add_suppressed_for_test(1);
    CHECK_MESSAGE(throttle.pending() == kU32Max,
                "saturated tally must not move on further occurrences");

    // The reported value on emission is the saturated one.
    uint32_t suppressed = 0;
    CHECK_MESSAGE(throttle.should_log(suppressed), "first emission should fire");
    CHECK_MESSAGE(suppressed == kU32Max, "emission reports the saturated tally");
    CHECK_MESSAGE(throttle.pending() == 0, "tally resets after an emission");
}

TEST_CASE("test_kcp_input_rejection_log_is_bounded_and_single_line") {
    // Two defects in one path, both attacker-paced:
    //   * KcpWrapper::input() logged its own WARNING AND every caller logged a
    //     second one, so one rejected datagram cost two lines.
    //   * neither was throttled, so a peer holding the session key (a
    //     truncated segment or a wrong conv is enough to make ikcp_input
    //     refuse) got a formatted stderr write per datagram, for free.
    std::atomic<int> warnings{0};
    std::atomic<int> kcp_input_lines{0};
    set_log_sink_for_test([&](LogLevel level, std::string_view,
                              std::string_view message) {
        if (level != LogLevel::Warning) return;
        warnings.fetch_add(1, std::memory_order_relaxed);
        if (message.find("FAIL_STAGE=KCP_INPUT_FAILED") != std::string_view::npos) {
            kcp_input_lines.fetch_add(1, std::memory_order_relaxed);
        }
    });

    // Feed a burst far larger than any plausible packet rate.
    constexpr int kDatagrams = 5000;
    for (int i = 0; i < kDatagrams; ++i) {
        log_kcp_input_rejected("kcp_test", "sid:1234", -1, 37);
    }
    set_log_sink_for_test(LogSink{});

    // Bounded: one line per interval, not one per datagram.
    CHECK_MESSAGE(kcp_input_lines.load() >= 1, "the first rejection must always be visible");
    CHECK_MESSAGE(kcp_input_lines.load() <= 2,
                  "ikcp_input rejections must be throttled, not one line per datagram");
    // Single line per event: no second WARNING from the wrapper for the same
    // datagram (that duplication doubled the cost of the DoS).
    CHECK_MESSAGE(warnings.load() == kcp_input_lines.load(),
                "one rejected datagram must produce exactly one warning line");
}

TEST_CASE("test_session_target_close_drops_parked_write_hook") {
    // Regression: when the target TCP closed while the server's tcp->kcp loop
    // was parked on backpressure, the parked hook survived the close. The next
    // window drain (an ACK arrival, or the update tick's safety net) then
    // resumed the loop, whose forward_tcp_to_kcp found the target socket closed
    // and tore the whole session down -- dropping the response tail still queued
    // in KCP's send buffer, which is exactly what the drained-callback design
    // (mark_target_closed + wait for wait_send()==0) exists to deliver. Large
    // downloads whose FIN arrived while the tunnel was window-saturated were
    // truncated by up to ~KCP_BACKPRESSURE_RESUME_THRESHOLD segments.
    //
    // Two contracts are pinned, and the second is the one that actually
    // reproduces the original failure: merely asserting write_parked() after
    // the close says nothing about the resume path unless the window is drained
    // below the resume watermark, because maybe_resume_write refuses to fire
    // the hook while wait_send() stays above it. A peer KCP wired back-to-back
    // with the session supplies real ACKs, so the drain (and the stale resume
    // it used to trigger) is genuinely exercised.
    asio::io_context io;
    const std::string key = "remote_test_key_123456";
    const auto salt = Crypto::generate_session_salt();
    // Server crypto WITH the salt up front: a server-mode Crypto with no salt
    // refuses every encrypt, which would shut the session down instead of
    // letting it queue the response this test needs.
    auto crypto = std::make_shared<Crypto>(key, NONCE_DIR_SERVER, salt);
    Crypto peer_crypto(key, NONCE_DIR_CLIENT, salt, false);
    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);
    auto session = std::make_shared<KCPSession>(io, KCP_CONV, endpoint, crypto,
                                                "park-target-close");

    // Wire the session to a peer KCP so ACKs can actually drain the window:
    // session output (encrypted as the server) -> peer input, peer output
    // (encrypted as the client) -> session input. Everything runs inside
    // io.poll() on the test thread, the same back-to-back pattern as the FIN
    // tests, so there is no cross-thread access to the peer wrapper.
    KcpWrapper peer(KCP_CONV);
    peer.set_output_callback([&](byte_view plain) {
        auto wire = peer_crypto.encrypt(plain);
        session->receive_data(byte_view(wire.data(), wire.size()));
    });
    session->set_send_callback([&](std::vector<std::vector<uint8_t>> wire) {
        for (const auto& d : wire) {
            auto plain = peer_crypto.decrypt(byte_view(d.data(), d.size()));
            if (peer.input(byte_view(plain.data(), plain.size())) < 0) {
            // The session only emits genuine segments with the same conv; a
            // refusal here would mean the back-to-back wiring is broken and
            // every later wait_send assertion would be measuring nothing.
                throw std::runtime_error("peer kcp input refused a session datagram");
            }
        }
    });

    session->start();
    io.restart();
    io.poll();

    // Queue a response large enough to fill the window past the park threshold.
    // The peer has not ticked yet, so its ACKs are pending and nothing drains.
    const std::vector<uint8_t> payload(FWD_BUF_SIZE, 0x5A);
    for (int i = 0; i < 100; ++i) {
        session->send_data(byte_view(payload.data(), payload.size()));
    }
    io.restart();
    io.poll();
    CHECK_MESSAGE(session->wait_send() >= KCP_BACKPRESSURE_THRESHOLD,
                "the queued response must exceed the backpressure park threshold");

    // Park the tcp->kcp loop's hook exactly like forward_tcp_to_kcp does, then
    // close the target. The hook deliberately throws if it is ever run: with
    // the fix it is dropped by mark_target_closed and never invoked.
    session->park_write([]() {
        throw std::runtime_error(
            "stale tcp->kcp hook must never resume after the target closed");
    });
    CHECK_MESSAGE(session->write_parked(), "the parked hook must be registered before the close");
    session->mark_target_closed();
    io.restart();
    io.poll();
    CHECK_MESSAGE(!session->write_parked(),
                  "mark_target_closed must drop the parked tcp->kcp hook");

    // Drain the window with real peer ACKs until the resume watermark is
    // crossed -- the exact condition under which maybe_resume_write used to
    // fire the stale hook (from on_receive as the ACKs land, or from the tick).
    // The iteration bound is a hang guard only; the assertion after the loop
    // proves the drain actually happened, so the test cannot pass vacuously.
    uint32_t now = 0;
    for (int i = 0;
         i < 200 && session->wait_send() > KCP_BACKPRESSURE_RESUME_THRESHOLD;
         ++i) {
        now += KCP_INTERVAL_MS;
        peer.update(now);
        peer.flush();               // ACKs for everything received so far
        io.restart();
        io.poll();                  // session consumes the ACKs (on_receive)
        asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
        io.restart();
        io.poll();                  // session flushes more of the queued tail
    }
    CHECK_MESSAGE(session->wait_send() <= KCP_BACKPRESSURE_RESUME_THRESHOLD,
                "the peer ACKs must have drained the window below the resume "
                "watermark (a vacuous drain would leave it above)");

    // The safety-net tick with a drained window: with the fix this is a no-op
    // for the (dropped) hook; without it, the stale resume fires here -- or
    // earlier inside the pump -- and the throw fails the test outright.
    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.restart();
    io.poll();
    CHECK_MESSAGE(session->is_running(),
                "the draining session must not have been stopped by a stale resume");
    CHECK_MESSAGE(session->is_alive(),
                "the draining session must stay alive after the target closed");

    session->stop();
    io.restart();
    io.poll();
}

// Pins the SOCKS5 reply codes this server actually emits. They are wire-visible
// diagnostics: a client (and the Android CPP_REMOTE peer, which logs
// "SOCKS5 response rep=0x%02X") has nothing else to go on when a CONNECT is
// refused, so a code that says the wrong thing sends an operator hunting for a
// nonexistent host instead of a firewall rule.
TEST_CASE("test_socks5_reply_codes_are_rfc1928") {
    using namespace kcp_proxy;

    // RFC 1928 section 6 assignments.
    CHECK(SOCKS5_REPLY_SUCCEEDED == 0x00);
    CHECK(SOCKS5_REPLY_GENERAL_FAILURE == 0x01);
    CHECK(SOCKS5_REPLY_NOT_ALLOWED == 0x02);
    CHECK(SOCKS5_REPLY_NETWORK_UNREACHABLE == 0x03);
    CHECK(SOCKS5_REPLY_HOST_UNREACHABLE == 0x04);
    CHECK(SOCKS5_REPLY_CONNECTION_REFUSED == 0x05);
    CHECK(SOCKS5_REPLY_TTL_EXPIRED == 0x06);
    CHECK(SOCKS5_REPLY_COMMAND_NOT_SUPPORTED == 0x07);
    CHECK(SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED == 0x08);

    // 0x02 and 0x06 must stay distinct from their neighbours. Both were absent
    // once, so an SSRF refusal reported HOST_UNREACHABLE (0x04) and a connect
    // timeout reported HOST_UNREACHABLE too -- "no such host" for a rule
    // refusal and for a silent target respectively.
    CHECK(SOCKS5_REPLY_NOT_ALLOWED != SOCKS5_REPLY_HOST_UNREACHABLE);
    CHECK(SOCKS5_REPLY_TTL_EXPIRED != SOCKS5_REPLY_HOST_UNREACHABLE);
    CHECK(SOCKS5_REPLY_TTL_EXPIRED != SOCKS5_REPLY_CONNECTION_REFUSED);
}

// A connect timeout and an explicitly-not-allowed target must not collapse into
// the same error code, since get_error_reply_code() is what turns the client's
// OS-level error into the reply the app sees.
TEST_CASE("test_error_reply_code_distinguishes_timeout") {
    using namespace kcp_proxy;

    const uint8_t timeout = KCPServer::get_error_reply_code(asio::error::timed_out);
    CHECK_MESSAGE(timeout == SOCKS5_REPLY_TTL_EXPIRED,
                "a connect timeout must report TTL expired, not host unreachable");
    CHECK(timeout != SOCKS5_REPLY_HOST_UNREACHABLE);

    // The mappings that were already correct must stay that way.
    CHECK(KCPServer::get_error_reply_code(asio::error::connection_refused) ==
          SOCKS5_REPLY_CONNECTION_REFUSED);
    CHECK(KCPServer::get_error_reply_code(asio::error::network_unreachable) ==
          SOCKS5_REPLY_NETWORK_UNREACHABLE);
    CHECK(KCPServer::get_error_reply_code(asio::error::host_unreachable) ==
          SOCKS5_REPLY_HOST_UNREACHABLE);
    // Anything unrecognised stays a general failure rather than inventing a code.
    CHECK(KCPServer::get_error_reply_code(asio::error::invalid_argument) ==
          SOCKS5_REPLY_GENERAL_FAILURE);
}

// The runtime KcpTuning the CLI (--sndwnd/--rcvwnd/--mtu) produces must keep the
// same backpressure invariant the compile-time constants are static_asserted on.
// Each individual CLI bound is legal; it is the COMBINATION that can break it
// (a big mtu shrinks mss, so one FWD_BUF_SIZE message needs more of the window).
TEST_CASE("test_kcp_tuning_backpressure_invariant") {
    using namespace kcp_proxy;

    // Defaults must hold.
    CHECK(KcpTuning{}.backpressure_invariant_holds());

    // The extremes on their own must still hold -- these are the values the CLI
    // ranges actually permit.
    KcpTuning smallest;
    smallest.sndwnd = KCP_SNDWND_MIN;
    smallest.rcvwnd = KCP_RCVWND_MIN;
    smallest.mtu = KCP_MTU_MIN;
    CHECK_MESSAGE(smallest.backpressure_invariant_holds(),
                  "min sndwnd with min mtu must keep the watermarks ordered");
    KcpTuning widest;
    widest.sndwnd = KCP_SNDWND_MAX;
    widest.rcvwnd = KCP_RCVWND_MAX;
    widest.mtu = KCP_MTU_MAX;
    CHECK_MESSAGE(widest.backpressure_invariant_holds(),
                  "max sndwnd with max mtu must keep the watermarks ordered");

    // Every legal mtu with the smallest legal sndwnd: no combination may yield a
    // non-positive resume watermark, because a non-positive one makes the park
    // predicate permanently true and busy-spins the writer.
    for (int mtu = KCP_MTU_MIN; mtu <= KCP_MTU_MAX; mtu += 128) {
        KcpTuning t;
        t.sndwnd = KCP_SNDWND_MIN;
        t.rcvwnd = KCP_RCVWND_MIN;
        t.mtu = mtu;
        const std::string at = "at mtu=" + std::to_string(mtu);
        INFO(at);
        CHECK_MESSAGE(t.backpressure_resume() > 0,
                      "resume watermark went non-positive");
        CHECK_MESSAGE(t.backpressure_threshold() + t.max_segments_per_msg() <= t.sndwnd,
                      "threshold must leave room for a whole message");
        CHECK_MESSAGE(t.backpressure_invariant_holds(), "invariant must hold");
    }

    // set_kcp_tuning clamps each field into its declared range.
    set_kcp_tuning(1, 1, 1);
    CHECK(kcp_tuning().sndwnd == KCP_SNDWND_MIN);
    CHECK(kcp_tuning().rcvwnd == KCP_RCVWND_MIN);
    CHECK(kcp_tuning().mtu == KCP_MTU_MIN);
    set_kcp_tuning(99999, 99999, 99999);
    CHECK(kcp_tuning().sndwnd == KCP_SNDWND_MAX);
    CHECK(kcp_tuning().rcvwnd == KCP_RCVWND_MAX);
    CHECK(kcp_tuning().mtu == KCP_MTU_MAX);
    // Restore the defaults so later test cases see the baseline.
    set_kcp_tuning(KCP_SNDWND, KCP_RCVWND, KCP_MTU);
    CHECK(kcp_tuning().sndwnd == KCP_SNDWND);
    CHECK(kcp_tuning().backpressure_invariant_holds());
}

} // namespace
