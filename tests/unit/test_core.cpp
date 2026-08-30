#include "kcp_proxy/address.hpp"
#include "kcp_proxy/config.hpp"
#include "kcp_proxy/crypto.hpp"
#include "kcp_proxy/kcp_session.hpp"
#include "kcp_proxy/socks5.hpp"
#include <asio.hpp>
#include <cassert>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace kcp_proxy;

namespace {

void expect_true(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

template <typename Fn>
void expect_throw(Fn&& fn, const char* message) {
    try {
        fn();
    } catch (...) {
        return;
    }
    throw std::runtime_error(message);
}

void test_crypto_roundtrip_and_failures() {
    const std::string key = "remote_test_key_123456";
    const std::vector<uint8_t> plain{'h', 'e', 'l', 'l', 'o'};

    // Client generates a unique per-session salt; the server learns it from the
    // first packet (it is carried in cleartext on the wire).
    auto c_salt = Crypto::generate_session_salt();
    Crypto client(key, NONCE_DIR_CLIENT, c_salt);
    Crypto server(key, NONCE_DIR_SERVER);
    auto c2s = client.encrypt(byte_view(plain.data(), plain.size()));
    auto got = server.decrypt(byte_view(c2s.data(), c2s.size()));
    expect_true(got == plain, "client encrypt -> server decrypt failed");

    auto s_salt = Crypto::generate_session_salt();
    Crypto server_sender(key, NONCE_DIR_SERVER, s_salt);
    Crypto client_receiver(key, NONCE_DIR_CLIENT);
    auto s2c = server_sender.encrypt(byte_view(plain.data(), plain.size()));
    got = client_receiver.decrypt(byte_view(s2c.data(), s2c.size()));
    expect_true(got == plain, "server encrypt -> client decrypt failed");

    Crypto wrong_server("wrong_remote_test_key", NONCE_DIR_SERVER);
    expect_throw([&] { (void)wrong_server.decrypt(byte_view(c2s.data(), c2s.size())); },
                 "wrong key should fail");

    auto tampered = c2s;
    tampered[tampered.size() - 1] ^= 0x01;
    Crypto tamper_server(key, NONCE_DIR_SERVER);
    expect_throw([&] { (void)tamper_server.decrypt(byte_view(tampered.data(), tampered.size())); },
                 "tampered ciphertext should fail");

    Crypto replay_server(key, NONCE_DIR_SERVER);
    (void)replay_server.decrypt(byte_view(c2s.data(), c2s.size()));
    expect_throw([&] { (void)replay_server.decrypt(byte_view(c2s.data(), c2s.size())); },
                 "replayed packet should fail");

    Crypto first_packet_session(key, NONCE_DIR_SERVER);
    (void)first_packet_session.decrypt(byte_view(c2s.data(), c2s.size()));
    expect_throw([&] { (void)first_packet_session.decrypt(byte_view(c2s.data(), c2s.size())); },
                 "first encrypted packet should be accepted only once per session");

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
    expect_true(pkt_a != pkt_b,
                "different session salts must produce different ciphertext");

    Crypto server_a(key, NONCE_DIR_SERVER);
    Crypto server_b(key, NONCE_DIR_SERVER);
    expect_true(server_a.decrypt(byte_view(pkt_a.data(), pkt_a.size())) == plain,
                "server A decrypts session A packet");
    expect_true(server_b.decrypt(byte_view(pkt_b.data(), pkt_b.size())) == plain,
                "server B decrypts session B packet");
    expect_throw([&] { (void)server_a.decrypt(byte_view(pkt_b.data(), pkt_b.size())); },
                 "server bound to session A must reject session B packet (salt mismatch)");

    auto o_salt = Crypto::generate_session_salt();
    Crypto ordered_client(key, NONCE_DIR_CLIENT, o_salt);
    Crypto ordered_server(key, NONCE_DIR_SERVER);
    auto old_packet = ordered_client.encrypt(byte_view(plain.data(), plain.size()));
    auto newer_packet = ordered_client.encrypt(byte_view(plain.data(), plain.size()));
    (void)ordered_server.decrypt(byte_view(old_packet.data(), old_packet.size()));
    (void)ordered_server.decrypt(byte_view(newer_packet.data(), newer_packet.size()));
    expect_throw([&] { (void)ordered_server.decrypt(byte_view(old_packet.data(), old_packet.size())); },
                 "old counter packet should be rejected after it was seen");

    auto w_salt = Crypto::generate_session_salt();
    Crypto window_client(key, NONCE_DIR_CLIENT, w_salt);
    Crypto window_server(key, NONCE_DIR_SERVER);
    auto too_old_packet = window_client.encrypt(byte_view(plain.data(), plain.size()));
    (void)window_server.decrypt(byte_view(too_old_packet.data(), too_old_packet.size()));
    for (size_t i = 0; i < REPLAY_WINDOW_BITS + 1; ++i) {
        auto packet = window_client.encrypt(byte_view(plain.data(), plain.size()));
        (void)window_server.decrypt(byte_view(packet.data(), packet.size()));
    }
    expect_throw([&] { (void)window_server.decrypt(byte_view(too_old_packet.data(), too_old_packet.size())); },
                 "packet older than replay window should be rejected");

    auto oo_salt = Crypto::generate_session_salt();
    Crypto out_of_order_client(key, NONCE_DIR_CLIENT, oo_salt);
    Crypto out_of_order_server(key, NONCE_DIR_SERVER);
    auto packet0 = out_of_order_client.encrypt(byte_view(plain.data(), plain.size()));
    auto packet1 = out_of_order_client.encrypt(byte_view(plain.data(), plain.size()));
    auto packet2 = out_of_order_client.encrypt(byte_view(plain.data(), plain.size()));
    (void)packet0;
    (void)out_of_order_server.decrypt(byte_view(packet2.data(), packet2.size()));
    auto late_packet = out_of_order_server.decrypt(byte_view(packet1.data(), packet1.size()));
    expect_true(late_packet == plain, "unseen out-of-order packet within replay window should work");

    // Regression: an AUTH-FAILED packet must NOT advance the replay window.
    // Otherwise one forged high-counter datagram permanently desyncs the
    // session (every later, lower counter would be rejected as "too old").
    {
        auto a_salt = Crypto::generate_session_salt();
        Crypto a_client(key, NONCE_DIR_CLIENT, a_salt);
        Crypto a_server(key, NONCE_DIR_SERVER);
        auto pkt0 = a_client.encrypt(byte_view(plain.data(), plain.size())); // counter 0
        auto pkt1 = a_client.encrypt(byte_view(plain.data(), plain.size())); // counter 1
        expect_true(a_server.decrypt(byte_view(pkt0.data(), pkt0.size())) == plain,
                    "pkt0 accepted (seeds window)");

        // Forge a packet with a huge counter (attacker-chosen) and a bad tag:
        // overwrite the nonce counter bytes; the wrong IV makes the GCM tag fail.
        auto forged = pkt0;
        for (int i = 0; i < 8; ++i) forged[SESSION_SALT_SIZE + i] = 0xFF;
        expect_throw([&] { (void)a_server.decrypt(byte_view(forged.data(), forged.size())); },
                     "forged high-counter packet must fail authentication");

        // pkt1 (counter 1) must still decrypt: the forged packet did not poison
        // the window (verify-then-commit).
        expect_true(a_server.decrypt(byte_view(pkt1.data(), pkt1.size())) == plain,
                    "pkt1 must still be accepted after a forged packet (window not poisoned)");
    }
}

std::vector<uint8_t> build_request(std::string_view host, uint16_t port) {
    std::vector<uint8_t> req{SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00};
    auto addr = encode_address(host, port);
    req.insert(req.end(), addr.begin(), addr.end());
    return req;
}

void test_socks5_parser() {
    auto ipv4 = build_request("1.2.3.4", 443);
    auto parsed = parse_socks5_request(ipv4);
    expect_true(parsed.status == SOCKS5ParseStatus::Complete, "IPv4 request did not parse");
    expect_true(parsed.request.has_value(), "IPv4 request missing");
    expect_true(parsed.request->host == "1.2.3.4", "IPv4 host mismatch");
    expect_true(parsed.request->port == 443, "IPv4 port mismatch");

    for (size_t i = 0; i < ipv4.size(); ++i) {
        std::vector<uint8_t> partial(ipv4.begin(), ipv4.begin() + static_cast<std::ptrdiff_t>(i));
        auto r = parse_socks5_request(partial);
        expect_true(r.status == SOCKS5ParseStatus::NeedMore, "partial IPv4 should need more");
    }

    auto domain = build_request("example.com", 80);
    auto domain_complete = domain;
    for (size_t i = 0; i < domain_complete.size(); ++i) {
        std::vector<uint8_t> partial(domain_complete.begin(),
                                     domain_complete.begin() + static_cast<std::ptrdiff_t>(i));
        auto r = parse_socks5_request(partial);
        expect_true(r.status == SOCKS5ParseStatus::NeedMore, "partial domain should need more");
    }
    domain.push_back('G');
    domain.push_back('E');
    domain.push_back('T');
    parsed = parse_socks5_request(domain);
    expect_true(parsed.status == SOCKS5ParseStatus::Complete, "domain request did not parse");
    expect_true(parsed.request.has_value(), "domain request missing");
    expect_true(parsed.request->host == "example.com", "domain host mismatch");
    expect_true(parsed.request->initial_payload.size() == 3, "extra payload not preserved");

    auto ipv6 = build_request("2001:db8::1", 8443);
    for (size_t i = 0; i < ipv6.size(); ++i) {
        std::vector<uint8_t> partial(ipv6.begin(), ipv6.begin() + static_cast<std::ptrdiff_t>(i));
        auto r = parse_socks5_request(partial);
        expect_true(r.status == SOCKS5ParseStatus::NeedMore, "partial IPv6 should need more");
    }
    parsed = parse_socks5_request(ipv6);
    expect_true(parsed.status == SOCKS5ParseStatus::Complete, "IPv6 request did not parse");
    expect_true(parsed.request.has_value(), "IPv6 request missing");
    expect_true(parsed.request->port == 8443, "IPv6 port mismatch");

    std::vector<uint8_t> unsupported{SOCKS5_VERSION, 0x02, 0x00, SOCKS5_ATYP_IPV4,
                                     127, 0, 0, 1, 0, 80};
    parsed = parse_socks5_request(unsupported);
    expect_true(parsed.status == SOCKS5ParseStatus::Complete, "unsupported command should parse");
    expect_true(parsed.request->cmd == 0x02, "unsupported command value lost");

    std::vector<uint8_t> udp_assoc{SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00,
                                   SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0, 53};
    parsed = parse_socks5_request(udp_assoc);
    expect_true(parsed.status == SOCKS5ParseStatus::Complete, "UDP ASSOCIATE should parse before rejection");
    expect_true(parsed.request->cmd == SOCKS5_CMD_UDP_ASSOCIATE, "UDP ASSOCIATE command value lost");

    std::vector<uint8_t> bad_version = ipv4;
    bad_version[0] = 0x04;
    parsed = parse_socks5_request(bad_version);
    expect_true(parsed.status == SOCKS5ParseStatus::Invalid, "bad version should be invalid");

    std::vector<uint8_t> bad_atyp{SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, 0x09, 0x00, 0x50};
    parsed = parse_socks5_request(bad_atyp);
    expect_true(parsed.status == SOCKS5ParseStatus::Invalid, "unsupported ATYP should be invalid");
}

void test_socks5_reply_bind_address() {
    SOCKS5Response resp;
    resp.reply = SOCKS5_REPLY_SUCCEEDED;
    auto zero = resp.build();
    expect_true(zero.size() == 10, "zero bind reply size mismatch");
    expect_true(zero[3] == SOCKS5_ATYP_IPV4, "zero bind should be IPv4");

    resp.host = "127.0.0.1";
    resp.port = 54321;
    auto local = resp.build();
    expect_true(local.size() == 10, "IPv4 bind reply size mismatch");
    expect_true(local[4] == 127 && local[7] == 1, "IPv4 bind reply mismatch");
}

void test_restricted_targets() {
    // IPv4 basics.
    expect_true(is_restricted_target(asio::ip::make_address("127.0.0.1")), "v4 loopback");
    expect_true(is_restricted_target(asio::ip::make_address("10.1.2.3")), "v4 private 10/8");
    expect_true(is_restricted_target(asio::ip::make_address("192.168.1.1")), "v4 private 192.168");
    expect_true(!is_restricted_target(asio::ip::make_address("1.1.1.1")), "v4 public allowed");

    // IPv4-mapped ::ffff:a.b.c.d inherits the IPv4 classification.
    expect_true(is_restricted_target(asio::ip::make_address("::ffff:127.0.0.1")), "v4-mapped loopback");
    expect_true(!is_restricted_target(asio::ip::make_address("::ffff:1.1.1.1")), "v4-mapped public allowed");

    // 6to4 (2002::/16) embeds the IPv4 address in bytes 2-5: it must not be
    // usable to tunnel into the blocked IPv4 ranges.
    expect_true(is_restricted_target(asio::ip::make_address("2002:7f00:0001::1")),
                "6to4 embedding 127.0.0.1");
    expect_true(is_restricted_target(asio::ip::make_address("2002:0a00::1")),
                "6to4 embedding 10.0.0.1");
    expect_true(!is_restricted_target(asio::ip::make_address("2002:0101:0101::1")),
                "6to4 embedding public 1.1.1.1 allowed");

    // Teredo (2001:0000::/32): server IPv4 in bytes 4-7, bit-inverted client
    // IPv4 in bytes 12-15. Either embedding a restricted IPv4 must be refused.
    {
        // Client = ~80 ff ff fe = 127.0.0.1.
        asio::ip::address_v6::bytes_type b{};
        b[0] = 0x20; b[1] = 0x01; b[2] = 0x00; b[3] = 0x00;
        b[12] = 0x80; b[13] = 0xff; b[14] = 0xff; b[15] = 0xfe;
        expect_true(is_restricted_target(asio::ip::address_v6(b)),
                    "teredo embedding loopback client IPv4");
    }
    {
        // Server = 7f 00 00 01 = 127.0.0.1, client = ~f7f7f7f7 = 8.8.8.8.
        asio::ip::address_v6::bytes_type b{};
        b[0] = 0x20; b[1] = 0x01; b[2] = 0x00; b[3] = 0x00;
        b[4] = 0x7f; b[5] = 0x00; b[6] = 0x00; b[7] = 0x01;
        b[12] = 0xf7; b[13] = 0xf7; b[14] = 0xf7; b[15] = 0xf7;
        expect_true(is_restricted_target(asio::ip::address_v6(b)),
                    "teredo embedding loopback server IPv4");
    }
    {
        // Server 1.2.3.4, client 8.8.8.8: both public -> allowed.
        asio::ip::address_v6::bytes_type b{};
        b[0] = 0x20; b[1] = 0x01; b[2] = 0x00; b[3] = 0x00;
        b[4] = 0x01; b[5] = 0x02; b[6] = 0x03; b[7] = 0x04;
        b[12] = 0xf7; b[13] = 0xf7; b[14] = 0xf7; b[15] = 0xf7;
        expect_true(!is_restricted_target(asio::ip::address_v6(b)),
                    "teredo with public IPv4s allowed");
    }

    // IPv4-compatible ::a.b.c.d (deprecated ::/96): tail bytes are the IPv4.
    expect_true(is_restricted_target(asio::ip::make_address("::c0a8:0101")),
                "v4-compatible embedding 192.168.1.1");
    expect_true(!is_restricted_target(asio::ip::make_address("::0101:0101")),
                "v4-compatible embedding public 1.1.1.1 allowed");

    // Regular IPv6 classes unchanged.
    expect_true(is_restricted_target(asio::ip::make_address("::1")), "v6 loopback");
    expect_true(is_restricted_target(asio::ip::make_address("fe80::1")), "v6 link-local");
    expect_true(is_restricted_target(asio::ip::make_address("fd12:3456::1")), "v6 ULA");
    expect_true(is_restricted_target(asio::ip::make_address("2001:db8::1")), "v6 documentation");
    expect_true(!is_restricted_target(asio::ip::make_address("2606:4700:4700::1111")),
                "v6 global unicast allowed");
}

void test_async_read_some_rejects_stacked_reads() {
    asio::io_context io;
    auto crypto = std::make_shared<Crypto>("remote_test_key_123456", NONCE_DIR_SERVER,
                                            Crypto::generate_session_salt());
    auto endpoint = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 8388);
    auto session = std::make_shared<KCPSession>(io, 1, endpoint, crypto, "unit-test-session");
    session->set_send_callback([](std::vector<uint8_t>) {});
    session->start();
    io.poll();
    io.restart();

    std::array<uint8_t, 16> first_buf{};
    std::array<uint8_t, 16> second_buf{};
    bool first_called = false;
    bool second_called = false;
    std::error_code second_ec;

    session->async_read_some(asio::buffer(first_buf),
        [&](std::error_code ec, size_t) {
            first_called = true;
            expect_true(ec == asio::error::operation_aborted,
                        "first pending read should remain pending until stop");
        });
    session->async_read_some(asio::buffer(second_buf),
        [&](std::error_code ec, size_t) {
            second_called = true;
            second_ec = ec;
        });

    io.poll();
    expect_true(!first_called, "first read handler should not be overwritten or completed");
    expect_true(second_called, "second stacked read handler should be called");
    expect_true(second_ec == asio::error::already_started,
                "second stacked read should receive already_started");

    session->stop();
    io.restart();
    io.poll();
    expect_true(first_called, "first read should be aborted during stop");
}

} // namespace

int main() {
    try {
        test_crypto_roundtrip_and_failures();
        test_socks5_parser();
        test_socks5_reply_bind_address();
        test_restricted_targets();
        test_async_read_some_rejects_stacked_reads();
    } catch (const std::exception& e) {
        std::cerr << "test failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "all core tests passed\n";
    return 0;
}
