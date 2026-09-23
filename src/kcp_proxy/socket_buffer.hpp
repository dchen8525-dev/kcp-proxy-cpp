#pragma once

#include <string>
#include <string_view>

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
inline std::string describe_buffer_clamp(std::string_view option_name,
                                         std::string_view sysctl_name,
                                         int requested, int effective) {
    if (effective >= requested) return std::string();

    return "UDP socket buffer clamped by the kernel: " + std::string(option_name) +
           " requested=" + std::to_string(requested) +
           " effective=" + std::to_string(effective) +
           " -- the kernel caps it at " + std::string(sysctl_name) +
           " (raise it, e.g. via /etc/sysctl.d/99-kcp-proxy.conf; otherwise a burst "
           "overflows the buffer and the resulting drops look like network loss)";
}

} // namespace kcp_proxy
