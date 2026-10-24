# Vendored build script for kcp-cpp (see VENDORED.md for provenance).
#
# Compile scope is a deliberate subset of upstream's full library:
#   * KCP state machine core ......... src/kcp.cc, src/internal/clock.cc
#   * protocol SNMP counters ......... src/snmp.cc
#   * forward error correction ....... src/internal/fec.cc, rs.cc, galois.cc
#
# The FEC trio is the reason this vendor exists: kcp-proxy applies
# Reed-Solomon forward error correction between the KCP output/input and the
# crypto layer (see src/kcp_proxy/kcp_tunnel.*). Everything else upstream
# (udp_session, crypt/frame, its own crypto and platform layers) stays
# uncompiled: the proxy brings its own transport (asio) and crypto (OpenSSL
# AEAD), so compiling those layers would only add build time and dependencies.
#
# The target name and alias (`kcp` / `kcp::kcp`) match the header-only include
# surface, so the proxy's `target_link_libraries(... kcp::kcp)` keeps working
# unchanged after the switch away from the vcpkg C ikcp port.

set(KCP_CORE_SOURCES
    src/kcp.cc
    src/internal/clock.cc
    src/internal/fec.cc
    src/internal/galois.cc
    src/internal/rs.cc
    src/snmp.cc
)

add_library(kcp STATIC ${KCP_CORE_SOURCES})
add_library(kcp::kcp ALIAS kcp)

target_include_directories(kcp
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)

if(MSVC)
    # Same strictness as the kcp-cpp project itself (zero-warning gate).
    target_compile_options(kcp PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(kcp PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(kcp PRIVATE -Wall -Wextra -Wpedantic)
endif()
