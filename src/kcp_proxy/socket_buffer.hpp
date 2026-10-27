#pragma once

#include "kcp_proxy/config.hpp"
#include "kcp_proxy/logger.hpp"

#include <asio.hpp>

#include <mutex>
#include <string>
#include <string_view>

#if defined(_WIN32)
// Old Winsock headers do not declare SIO_UDP_CONNRESET; the value is stable in
// every SDK that has it, so defining it is safe for the toolchains that do not.
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#include <winsock2.h>
#endif

namespace kcp_proxy {

// Detect and describe a socket buffer the kernel silently clamped.
//
// setsockopt(SO_RCVBUF / SO_SNDBUF, N) is a request, not a guarantee: the kernel
// silently caps N at net.core.rmem_max / net.core.wmem_max (and on Linux applies
// its own doubling on the way back out), so a program that asks for 4 MiB on a
// stock host can end up with a couple of hundred KiB. Nothing fails -- no error
// code, no errno -- and the shortfall only surfaces much later, as datagrams the
// OS drops under burst that KCP then misreads as network loss and answers with
// whole-window retransmission. Comparing what getsockopt() reports against what
// was asked for is the only way to notice.
//
// Because the kernel never reports less than it granted, `effective >= requested`
// is a sound "you got what you asked for" test: it is the exact condition under
// which there is nothing to report. Returns an empty string in that case.
//
// Pure, so it is unit-tested without binding a socket.
inline std::string describe_buffer_clamp(std::string_view option_name, std::string_view sysctl_name,
                                         int requested, int effective) {
    if (effective >= requested) return std::string();

    return "UDP socket buffer clamped by the kernel: " + std::string(option_name) +
           " requested=" + std::to_string(requested) + " effective=" + std::to_string(effective) +
           " -- the kernel caps it at " + std::string(sysctl_name) +
           " (raise it, e.g. via /etc/sysctl.d/99-kcp-proxy.conf; otherwise a burst "
           "overflows the buffer and the resulting drops look like network loss)";
}

// Raise SO_RCVBUF/SO_SNDBUF and report what the kernel actually granted.
//
// Both ends of the tunnel need this and had grown identical copies (server.cpp
// for its one shared socket, kcp_client_session.cpp for its per-connection one);
// the copy in the client had already drifted -- it added the once-per-process
// guard below, which the server never got. It lives here so the two cannot
// disagree again about what a clamp means.
//
// `log_module` is the LOG_* module tag ("server", "kcp_client"), so the lines
// keep landing in the stream the GUI and the e2e suite already expect.
//
// `report_once` exists because the client opens one UDP socket per local TCP
// connection: without it, an identical clamp WARNING would be emitted per
// session for a value that cannot change while the process runs. The server
// owns a single socket and passes false.
//
// Returns the two effective sizes as the "<rcv>/<snd>" strings the caller logs,
// or "?" for an option that could not be read back.
struct EffectiveBufferSizes {
    std::string rcv{"?"};
    std::string snd{"?"};
};

inline EffectiveBufferSizes apply_udp_buffer_sizes(asio::ip::udp::socket& socket,
                                                   std::string_view log_module, bool report_once) {
    std::error_code opt_ec;

    socket.set_option(asio::socket_base::receive_buffer_size(UDP_SO_RCVBUF_BYTES), opt_ec);
    if (opt_ec) {
        LOG_WARNING(log_module, "failed to set SO_RCVBUF: " + opt_ec.message());
    }
    socket.set_option(asio::socket_base::send_buffer_size(UDP_SO_SNDBUF_BYTES), opt_ec);
    if (opt_ec) {
        LOG_WARNING(log_module, "failed to set SO_SNDBUF: " + opt_ec.message());
    }

    // The values above are the whole point of the set_option calls, so a silent
    // clamp is a silent loss of the protection. setsockopt() reports success
    // either way, which is why this comparison -- not the error code -- is what
    // actually detects it. Windows has no rmem_max/wmem_max to raise, so this
    // is visibility only, never an automatic repair.
    auto read_and_report = [&socket, log_module]() -> EffectiveBufferSizes {
        EffectiveBufferSizes out;
        std::error_code read_ec;

        asio::socket_base::receive_buffer_size eff_rcv;
        socket.get_option(eff_rcv, read_ec);
        const bool rcv_ok = !read_ec;
        if (rcv_ok) out.rcv = std::to_string(eff_rcv.value());

        asio::socket_base::send_buffer_size eff_snd;
        socket.get_option(eff_snd, read_ec);
        const bool snd_ok = !read_ec;
        if (snd_ok) out.snd = std::to_string(eff_snd.value());

        LOG_INFO(log_module, "UDP socket buffers so_rcvbuf=" + out.rcv + " so_sndbuf=" + out.snd);
        if (rcv_ok) {
            const std::string clamp = describe_buffer_clamp("so_rcvbuf", "net.core.rmem_max",
                                                            UDP_SO_RCVBUF_BYTES, eff_rcv.value());
            if (!clamp.empty()) LOG_WARNING(log_module, clamp);
        }
        if (snd_ok) {
            const std::string clamp = describe_buffer_clamp("so_sndbuf", "net.core.wmem_max",
                                                            UDP_SO_SNDBUF_BYTES, eff_snd.value());
            if (!clamp.empty()) LOG_WARNING(log_module, clamp);
        }
        return out;
    };

    if (report_once) {
        static std::once_flag once;
        EffectiveBufferSizes out;
        std::call_once(once, [&] {
            out = read_and_report();
        });
        return out;
    }
    return read_and_report();
}

#if defined(_WIN32)
// Turn off WSAECONNRESET reporting for an unconnected-or-connected UDP socket.
//
// On Windows a UDP socket reports WSAECONNRESET on the next receive after every
// send to a dead peer port: an ICMP port-unreachable from one dead destination
// permanently arms the error channel. A hostile or churning peer would keep it
// hot forever -- each error is a log line plus a re-arm of the receive slot.
// SIO_UDP_CONNRESET=FALSE turns the reporting off at the source; the tolerant
// receive handlers in both ends stay as the cross-platform safety net.
//
// The single definition shared by the server and the client session (which had
// byte-identical copies, differing only in the log module and, in the process,
// in whether the copy was correct at all).
inline int disable_udp_connreset(asio::ip::udp::socket& socket) {
    BOOLEAN disable_connreset = FALSE;
    DWORD bytes_returned = 0;
    // native_handle() already yields the SOCKET integer type on Windows.
    return ::WSAIoctl(socket.native_handle(), SIO_UDP_CONNRESET, &disable_connreset,
                      sizeof(disable_connreset), nullptr, 0, &bytes_returned, nullptr, nullptr);
}
#endif

} // namespace kcp_proxy
