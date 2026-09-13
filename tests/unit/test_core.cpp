#include "kcp_proxy/address.hpp"
#include "kcp_proxy/client.hpp"
#include "kcp_proxy/config.hpp"
#include "kcp_proxy/crypto.hpp"
#include "kcp_proxy/kcp_client_session.hpp"
#include "kcp_proxy/kcp_session.hpp"
#include "kcp_proxy/kcp_wrapper.hpp"
#include "kcp_proxy/logger.hpp"
#include "kcp_proxy/server.hpp"
#include "kcp_proxy/socks5.hpp"
#include "kcp_proxy/target_allowlist.hpp"
#include <asio.hpp>
#include <cassert>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
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
        expect_throw([&] { (void)edge_server.decrypt(byte_view(edge_pkt.data(), edge_pkt.size())); },
                     "replay at exactly the window edge should be rejected");
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

    // RFC 1928 reserves the third byte and requires it to be 0x00. It used to be
    // read by nothing at all, so a request that set it was silently accepted.
    expect_true(ipv4[2] == 0x00, "the request builder must emit RSV=0");
    std::vector<uint8_t> bad_rsv = ipv4;
    bad_rsv[2] = 0x01;
    parsed = parse_socks5_request(bad_rsv);
    expect_true(parsed.status == SOCKS5ParseStatus::Invalid,
                "a non-zero SOCKS5 reserved byte should be invalid");

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

    // Private/non-routable IPv6 ranges. fec0::/10 (site-local) is neither
    // fe80::/10 (link-local) nor fc00::/7 (unique-local), so it used to be the
    // one private IPv6 range the SSRF guard let through.
    expect_true(is_restricted_target(asio::ip::make_address("fec0::1")),
                "v6 site-local fec0::/10");
    expect_true(is_restricted_target(asio::ip::make_address("feff::1")),
                "v6 site-local upper bound feff::");
    expect_true(is_restricted_target(asio::ip::make_address("fc00::1")), "v6 unique-local");
    expect_true(is_restricted_target(asio::ip::make_address("fe80::1")), "v6 link-local");
    expect_true(!is_restricted_target(asio::ip::make_address("2001:4860:4860::8888")),
                "v6 public allowed");

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

    // NAT64 well-known prefix 64:ff9b::/96 (and local-use 64:ff9b:1::/48)
    // embed the translated IPv4 in the last 4 bytes.
    expect_true(is_restricted_target(asio::ip::make_address("64:ff9b::7f00:0001")),
                "NAT64 embedding 127.0.0.1");
    expect_true(is_restricted_target(asio::ip::make_address("64:ff9b::c0a8:0101")),
                "NAT64 embedding 192.168.1.1");
    expect_true(is_restricted_target(asio::ip::make_address("64:ff9b:1::0a00:0001")),
                "NAT64 local-use embedding 10.0.0.1");
    expect_true(!is_restricted_target(asio::ip::make_address("64:ff9b::0101:0101")),
                "NAT64 embedding public 1.1.1.1 allowed");

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

void test_kcp_config_line() {
    // The startup log line is the contract between the two ends of a tunnel:
    // both peers must print the same KCP settings or ikcp silently discards
    // the other's packets (the conv mismatch symptom). Pin the exact string so
    // a future drift — changing a KCP_* constant but not the log, or breaking
    // the "log renders these exact values" invariant — breaks the test instead
    // of shipping as a mysterious handshake failure.
    const std::string line = kcp_config_line();

    expect_true(line ==
                    "KCP config conv=1 mtu=1400 nodelay=1 interval=10 "
                    "resend=5 nc=1 sndWnd=256 rcvWnd=512 timeout=60s",
                "kcp_config_line canonical baseline changed");

    // Each field must track its constant, so a constant change propagates to
    // the log automatically. Build the expected tokens from the constants
    // themselves (not from a second copy of the format string) so this test
    // fails if a field is ever rendered from a stale literal.
    auto has = [&](const std::string& token) {
        expect_true(line.find(token) != std::string::npos,
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

void test_kcp_wrapper_applies_constants() {
    // configure() must apply the KCP_* constants to the live ikcp state. The
    // whole point of promoting the literals to named constants (b52a8bb) was
    // that the startup log (kcp_config_line) and the live ikcp tuning can
    // never drift apart; this asserts the live side actually carries them, so
    // the "log renders these exact values" promise is enforced, not just
    // asserted textually by test_kcp_config_line.
    KcpWrapper wrapper(KCP_CONV);
    const ikcpcb* k = wrapper.ikcp();
    expect_true(k != nullptr, "KcpWrapper.ikcp() returned null");

    expect_true(k->conv == KCP_CONV, "ikcp conv mismatch");
    expect_true(k->mtu == static_cast<IUINT32>(KCP_MTU), "ikcp mtu mismatch");
    expect_true(k->snd_wnd == static_cast<IUINT32>(KCP_SNDWND), "ikcp snd_wnd mismatch");
    expect_true(k->rcv_wnd == static_cast<IUINT32>(KCP_RCVWND), "ikcp rcv_wnd mismatch");
    expect_true(k->nodelay == static_cast<IUINT32>(KCP_NODELAY), "ikcp nodelay mismatch");
    expect_true(k->interval == static_cast<IUINT32>(KCP_INTERVAL_MS), "ikcp interval mismatch");
    // ikcp_nodelay() maps the resend argument to fastresend and nc to nocwnd.
    expect_true(k->fastresend == KCP_RESEND, "ikcp fastresend (resend) mismatch");
    expect_true(k->nocwnd == KCP_NC, "ikcp nocwnd (nc) mismatch");
}

void test_kcp_wrapper_oversized_message_is_not_truncated() {
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
    expect_true(sender.send(byte_view(payload.data(), payload.size())) >= 0,
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
    expect_true(receiver.peek_size() == static_cast<int>(payload_size),
                "receiver must reassemble the whole message");

    // A buffer that cannot hold it is rejected instead of truncated...
    std::vector<uint8_t> too_small(FWD_BUF_SIZE);
    expect_true(receiver.recv(too_small.data(), too_small.size()) ==
                    KcpWrapper::KCP_RECV_MSG_TOO_BIG,
                "oversized message must be reported, never truncated");
    // ...and it stays queued, which is what makes recovery possible.
    expect_true(receiver.peek_size() == static_cast<int>(payload_size),
                "the rejected message must still be queued");

    // The vector overload is the documented recovery path: it must hand back
    // the full message, byte-exact.
    std::vector<uint8_t> recovered;
    expect_true(receiver.recv(recovered) == static_cast<int>(payload_size),
                "vector recv must return the whole message");
    expect_true(recovered == payload, "the recovered payload must be byte-exact");
    // ikcp_peeksize() reports -1 (not 0) once nothing is queued.
    expect_true(receiver.peek_size() <= 0, "the queue must be drained after recovery");
}

void test_server_session_routing_and_auth() {
    // get_or_create_session holds the server's only real branching logic (auth,
    // auth rate limit, duplicate-salt rejection, session cap) and the E2E
    // suites only reach it incidentally. route_datagram drives it directly --
    // no bound socket and no KCP timing -- so every reject path is assertable.
    asio::io_context io;
    const std::string key = "remote_test_key_123456";
    auto server = std::make_shared<KCPServer>(io, 8388, key, "127.0.0.1");

    const auto ep_a = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 40001);
    const auto ep_b = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 40002);
    const auto ep_c = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 40003);
    const auto ep_d = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 40004);

    // A bare SOCKS5 CONNECT is the documented compatibility path: the first
    // valid encrypted packet does not have to be a HELLO.
    const std::vector<uint8_t> connect_req = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0, 80};
    const byte_view req_view(connect_req.data(), connect_req.size());

    const auto salt_a = Crypto::generate_session_salt();
    Crypto client_a(key, NONCE_DIR_CLIENT, salt_a, false);
    auto first = client_a.encrypt(req_view);
    auto session_a = server->route_datagram(ep_a, byte_view(first.data(), first.size()));
    expect_true(session_a != nullptr, "a valid first packet must create a session");

    // A second packet from the same endpoint reuses that session instead of
    // creating a new one.
    auto second = client_a.encrypt(req_view);
    expect_true(server->route_datagram(ep_a, byte_view(second.data(), second.size())) == session_a,
                "a repeat packet must reuse the endpoint's session");

    // Wrong key: the AEAD tag cannot verify, so no session may be created.
    Crypto wrong_key("wrong_key_0000000000", NONCE_DIR_CLIENT,
                     Crypto::generate_session_salt(), false);
    auto bad = wrong_key.encrypt(req_view);
    expect_true(server->route_datagram(ep_b, byte_view(bad.data(), bad.size())) == nullptr,
                "a wrong-key packet must be rejected");

    // Duplicate salt: another endpoint must not be able to force a session that
    // shares a live session's salt -- that would reuse the same AES-GCM key and
    // nonce base across two sessions, which is catastrophic for GCM.
    Crypto replayed_salt(key, NONCE_DIR_CLIENT, salt_a, false);
    auto dup = replayed_salt.encrypt(req_view);
    expect_true(server->route_datagram(ep_b, byte_view(dup.data(), dup.size())) == nullptr,
                "a duplicate session salt must be rejected");

    // Rate limit. First prove the very packet we will expect to be dropped IS
    // accepted while the budget has room, so the assertion below cannot pass for
    // some unrelated reason.
    Crypto client_d(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
    auto valid_d = client_d.encrypt(req_view);
    expect_true(server->route_datagram(ep_d, byte_view(valid_d.data(), valid_d.size())) != nullptr,
                "a valid packet must be accepted while the auth budget has room");

    Crypto client_c(key, NONCE_DIR_CLIENT, Crypto::generate_session_salt(), false);
    auto valid_c = client_c.encrypt(req_view);
    const std::vector<uint8_t> garbage(64, 0xAB);

    // The per-datagram WARNINGs this flood triggers would drown the test report;
    // raise the level only for the loop and restore it afterwards.
    const auto prev_level = current_log_level();
    set_log_level(LogLevel::Error);
    for (uint32_t i = 0; i < MAX_AUTH_ATTEMPTS_PER_SEC + 1; ++i) {
        (void)server->route_datagram(ep_c, byte_view(garbage.data(), garbage.size()));
    }
    const bool rejected = server->route_datagram(ep_c, byte_view(valid_c.data(), valid_c.size())) == nullptr;
    set_log_level(prev_level);
    expect_true(rejected,
                "a valid packet must be dropped once the per-second auth budget is spent");
}

void test_session_oversized_kcp_message_fails_read() {
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
    session->set_send_callback([&](std::vector<uint8_t> wire) {
        try {
            auto plain = peer_crypto.decrypt(byte_view(wire.data(), wire.size()));
            (void)peer.input(byte_view(plain.data(), plain.size()));
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
    expect_true(peer.send(byte_view(payload1.data(), payload1.size())) >= 0,
                "peer.send must accept the path-1 payload");
    pump_until(small_failed, 60);
    expect_true(small_failed, "a message larger than the caller's buffer must fail the read");
    expect_true(small_ec == asio::error::message_size,
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
    expect_true(peer.send(byte_view(payload2.data(), payload2.size())) >= 0,
                "peer.send must accept the path-2 payload");
    pump_until(big_failed, 120);
    expect_true(big_failed, "a message larger than FWD_BUF_SIZE must fail the read");
    expect_true(big_ec == asio::error::message_size,
                "path 2 must report message_size, not a truncated success");
}

void test_session_stop_makes_inert() {
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
    session->set_send_callback([&](std::vector<uint8_t>) { sent = true; });
    session->start();
    io.poll();
    io.restart();

    expect_true(session->is_running(), "session should run after start");
    expect_true(session->is_alive(), "session should be alive after start");

    session->stop();
    io.restart();
    io.poll();

    expect_true(!session->is_running(), "session must not run after stop");
    expect_true(!session->is_alive(), "session must not be alive after stop");

    // on_update_tick is driven by the server's shared tick for EVERY session in
    // the map, including stopped ones. On a stopped session it must be a no-op
    // and must NOT invoke the send path.
    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    expect_true(!sent, "on_update_tick on a stopped session must not send");

    // Idempotent: a second stop must be safe and leave state unchanged.
    session->stop();
    expect_true(!session->is_running(), "second stop must stay not-running");
    expect_true(!session->is_alive(), "second stop must stay not-alive");
}

void test_session_drained_callback_on_target_closed() {
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
    session->set_send_callback([](std::vector<uint8_t>) {});
    session->start();
    io.poll();
    io.restart();

    bool drained = false;
    session->set_drained_callback([&]() { drained = true; });
    session->mark_target_closed();

    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    io.restart();
    expect_true(drained, "drained callback must fire when target closed and buffer empty");

    // Must not re-fire on a subsequent tick (callback was moved out and nulled).
    drained = false;
    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    expect_true(!drained, "drained callback must not re-fire");
}

void test_session_drained_deferred_while_send_buffer_nonempty() {
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
    session->set_send_callback([](std::vector<uint8_t>) {});
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
    expect_true(session->wait_send() > 0, "send_data must leave bytes queued in KCP");

    bool drained = false;
    session->set_drained_callback([&]() { drained = true; });
    session->mark_target_closed();

    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.poll();
    io.restart();
    expect_true(!drained,
                "drained callback fired while KCP still held undelivered data "
                "(an early teardown would truncate the stream)");
    expect_true(session->is_alive(),
                "session must stay alive until its send buffer drains");

    session->stop();
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

void test_client_session_close_before_connect_is_safe_and_idempotent() {
    // abort_handshake() can run before the session ever reached connect(): the
    // local app may disconnect (or send a bad greeting) while the SOCKS5 step is
    // still in flight, and the handshake deadline can fire first. close() must
    // therefore be safe on a session whose running_ is still false, and must
    // tolerate being called more than once (the funnel is idempotent by design).
    asio::io_context io;
    auto session = make_client_session(io, free_udp_port());

    expect_true(!session->is_connected(), "fresh client session must not look connected");

    session->close();
    io.poll();
    io.restart();
    expect_true(!session->is_connected(), "close before connect must not connect the session");

    session->close();
    io.restart();
    io.poll();
    expect_true(!session->is_connected(), "second close must stay a no-op");

    // KCPProxyClient's shared 10ms tick calls on_update_tick() for every
    // registered session; on a closed one it must be inert (no crash, no queued
    // data), exactly as the server-side equivalent must be.
    asio::dispatch(session->strand(), [&]() { session->on_update_tick(); });
    io.restart();
    io.poll();
    expect_true(!session->is_connected(), "on_update_tick on a closed session must not revive it");
    expect_true(session->wait_send() == 0, "closed session must not queue KCP data");
}

void test_client_session_close_mid_handshake_makes_it_inert() {
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
    expect_true(stacked_called, "read issued while the handshake read is parked must not hang");
    expect_true(stacked_ec == asio::error::already_started,
                "a stacked read must be rejected with already_started");

    session->close();
    io.poll();
    io.restart();
    io.poll();
    expect_true(!session->is_connected(), "closed session must not report connected");

    bool read_called = false;
    std::error_code read_ec;
    session->async_read_some(asio::buffer(buf), [&](std::error_code ec, size_t) {
        read_called = true;
        read_ec = ec;
    });
    io.poll();
    io.restart();
    io.poll();
    expect_true(read_called, "read on a closed session must complete, not hang");
    expect_true(read_ec == asio::error::operation_aborted,
                "read on a closed session must report operation_aborted");
    expect_true(!session->is_connected(), "session must stay closed");
}

void test_client_session_close_releases_parked_handler() {
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
    expect_true(weak.expired(),
                "closed client session was still referenced by a parked handler "
                "(session + UDP socket leak)");
}

void test_client_session_keepalive_released_with_session() {
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
        expect_true(probe.use_count() == 2, "the session must hold the keepalive resource");
    }
    expect_true(probe.use_count() == 1,
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

void test_client_abort_handshake_closes_local_socket() {
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
    expect_true(up, "client SOCKS5 listener never came up");

    // A local app opens a tunnel. The KCP handshake times out after
    // KCP_HANDSHAKE_TIMEOUT_SEC, after which abort_handshake() must close this
    // socket rather than leave the app waiting on a tunnel that will never come.
    asio::io_context app_io;
    asio::ip::tcp::socket app(app_io);
    std::error_code ec;
    app.connect(listen_ep, ec);
    expect_true(!ec, "local app could not connect to the client listener");
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

    expect_true(!timed_out,
                "abort_handshake left the local app hanging after the KCP "
                "handshake failed (socket neither closed nor reset)");
    expect_true(peer_closed,
                "abort_handshake must close the local socket when the KCP handshake fails");

    // The client must still be serving afterwards: a fresh local connection is
    // accepted, which also shows the failed session was released rather than
    // held against the session cap.
    asio::ip::tcp::socket app2(app_io);
    app2.connect(listen_ep, ec);
    expect_true(!ec, "client stopped accepting connections after a failed handshake");
    app2.close(ec);
    app.close(ec);
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
void test_log_throttle() {
    LogThrottle throttle(std::chrono::milliseconds(40));
    uint32_t suppressed = 0;

    // The first call always emits, reporting nothing suppressed.
    suppressed = 12345;  // must be overwritten on the emitting path
    expect_true(throttle.should_log(suppressed), "first call must emit");
    expect_true(suppressed == 0, "first emission reports nothing suppressed");

    // Everything inside the window is folded in instead of logged.
    for (uint32_t i = 0; i < 3; ++i) {
        suppressed = 12345;
        expect_true(!throttle.should_log(suppressed),
                    "a call inside the window must be suppressed");
        expect_true(suppressed == 12345,
                    "a suppressed call must not touch the out-param");
        expect_true(throttle.pending() == i + 1,
                    "pending() tracks the suppressed occurrences");
    }

    // After the window elapses the next call emits and reports the tally, which
    // then resets -- so a flood yields one line per interval carrying the count.
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    suppressed = 0;
    expect_true(throttle.should_log(suppressed), "post-window call must emit");
    expect_true(suppressed == 3, "emission must report the suppressed count");
    expect_true(throttle.pending() == 0, "the tally resets after an emission");
}

void test_allowlist_matching() {
    using kcp_proxy::parse_allow_target_entry;
    using kcp_proxy::target_matches_allowlist;

    std::string host;
    bool has_port = false;
    uint16_t port = 0;

    // Exact host+port entries.
    expect_true(parse_allow_target_entry("127.0.0.1:9000", host, has_port, port),
                "host:port entry should parse");
    expect_true(host == "127.0.0.1" && has_port && port == 9000,
                "host:port parsed values");
    expect_true(target_matches_allowlist({"127.0.0.1:9000"}, "127.0.0.1", 9000),
                "exact entry matches its host and port");
    expect_true(!target_matches_allowlist({"127.0.0.1:9000"}, "127.0.0.1", 9001),
                "exact entry must not match a different port");
    expect_true(!target_matches_allowlist({"127.0.0.1:9000"}, "127.0.0.2", 9000),
                "exact entry must not match a different host");

    // Host-only entries match every port on that host (documented semantics).
    expect_true(target_matches_allowlist({"127.0.0.1"}, "127.0.0.1", 1),
                "host-only entry matches low port");
    expect_true(target_matches_allowlist({"127.0.0.1"}, "127.0.0.1", 65535),
                "host-only entry matches high port");
    expect_true(!target_matches_allowlist({"127.0.0.1"}, "127.0.0.2", 1),
                "host-only entry must not match another host");
    expect_true(target_matches_allowlist({"example.com"}, "example.com", 443),
                "hostname-only entry matches any port");
    expect_true(target_matches_allowlist({"example.com:443"}, "example.com", 443),
                "hostname:port entry matches");

    // IPv6 forms.
    expect_true(parse_allow_target_entry("[::1]:9000", host, has_port, port),
                "bracketed IPv6 with port should parse");
    expect_true(host == "::1" && has_port && port == 9000,
                "bracketed IPv6 parsed values");
    expect_true(target_matches_allowlist({"[::1]:9000"}, "::1", 9000),
                "bracketed IPv6 entry matches");
    expect_true(target_matches_allowlist({"[::1]"}, "::1", 1234),
                "bracketed host-only IPv6 matches any port");
    expect_true(target_matches_allowlist({"::1"}, "::1", 1234),
                "bare multi-colon IPv6 is a host-only entry");
    expect_true(target_matches_allowlist({"2001:db8::1"}, "2001:db8::1", 80),
                "bare IPv6 literal host-only matches");
    expect_true(!target_matches_allowlist({"[::1]:9000"}, "::1", 9001),
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
        expect_true(!parse_allow_target_entry(entry, host, has_port, port),
                    "malformed entry must be rejected");
        expect_true(!target_matches_allowlist({entry}, "host", 9000) &&
                    !target_matches_allowlist({entry}, "::1", 9000),
                    "malformed entry must match nothing");
    }
    // The wrapping regressions: these ports must not have been silently
    // allowlisted by the typo'd entries above.
    expect_true(!target_matches_allowlist({"host:99999"}, "host", 34463),
                "port 99999 must not wrap to 34463");
    expect_true(!target_matches_allowlist({"host:-1"}, "host", 65535),
                "port -1 must not wrap to 65535");

    // No wildcard support: '*' (and any glob-ish entry) is inert.
    expect_true(!target_matches_allowlist({"*"}, "anything", 80),
                "wildcard entry must not match everything");
    expect_true(!target_matches_allowlist({"*:80"}, "anything", 80),
                "wildcard host with port must not match");

    // A malformed entry is skipped without hiding a later valid one, and the
    // matcher is safe against an empty allowlist (production default).
    expect_true(target_matches_allowlist({"host:", "127.0.0.1:9000"},
                                         "127.0.0.1", 9000),
                "valid entry after a malformed one still matches");
    expect_true(!target_matches_allowlist({}, "127.0.0.1", 9000),
                "empty allowlist matches nothing");
}

} // namespace

int main() {
    try {
        test_crypto_roundtrip_and_failures();
        test_socks5_parser();
        test_socks5_reply_bind_address();
        test_restricted_targets();
        test_log_throttle();
        test_allowlist_matching();
        test_async_read_some_rejects_stacked_reads();
        test_kcp_config_line();
        test_kcp_wrapper_applies_constants();
        test_kcp_wrapper_oversized_message_is_not_truncated();
        test_server_session_routing_and_auth();
        test_session_oversized_kcp_message_fails_read();
        test_session_stop_makes_inert();
        test_session_drained_callback_on_target_closed();
        test_session_drained_deferred_while_send_buffer_nonempty();
        test_client_session_close_before_connect_is_safe_and_idempotent();
        test_client_session_close_mid_handshake_makes_it_inert();
        test_client_session_close_releases_parked_handler();
        test_client_session_keepalive_released_with_session();
        test_client_abort_handshake_closes_local_socket();
    } catch (const std::exception& e) {
        std::cerr << "test failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "all core tests passed\n";
    return 0;
}
