cmake_minimum_required(VERSION 3.22)

# --- vcpkg toolchain (must be set before project()) ---
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

project(kcp_proxy VERSION 0.0.6 LANGUAGES C CXX)

# Default build type and compile_commands.json export
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type (Debug/Release)" FORCE)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# --- Dependencies ---
find_package(OpenSSL REQUIRED)
find_package(asio REQUIRED)
find_package(kcp REQUIRED)
find_package(fmt REQUIRED)

# Platform-specific link deps
find_package(Threads REQUIRED)
if(WIN32)
    set(kcp_proxy_lib_LINK_DEPS
        asio::asio
        OpenSSL::SSL OpenSSL::Crypto
        Threads::Threads
        ws2_32 iphlpapi crypt32 mswsock
    )
else()
    set(kcp_proxy_lib_LINK_DEPS
        asio::asio
        OpenSSL::SSL OpenSSL::Crypto
        Threads::Threads
    )
endif()

# --- kcp_proxy_lib ---
add_library(kcp_proxy_lib STATIC
    ${PROJECT_ROOT}/src/kcp_proxy/logger.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/crypto.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/kcp_wrapper.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/kcp_tunnel.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/kcp_session.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/kcp_client_session.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/socks5.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/address.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/server.cpp
    ${PROJECT_ROOT}/src/kcp_proxy/client.cpp
)
target_include_directories(kcp_proxy_lib PUBLIC ${PROJECT_ROOT}/src)
target_link_libraries(kcp_proxy_lib PUBLIC ${kcp_proxy_lib_LINK_DEPS} kcp::kcp fmt::fmt)
target_compile_definitions(kcp_proxy_lib PUBLIC ASIO_STANDALONE FMT_HEADER_ONLY)

# Performance optimization flags
option(KCP_PROXY_ENABLE_NATIVE_TUNE
    "Optimize for the local CPU (-march=native). Keep OFF for portable release binaries."
    OFF)
if(MSVC)
    target_compile_options(kcp_proxy_lib PRIVATE
        /W4           # Higher warning level
        /wd4324       # C4324: padding from intentional alignas(64) cache-line
                      # isolation on crypto keys / hot buffers -- suppress at
                      # compiler level; header #pragma push/disable is not
                      # reliable here under precompiled headers.
        /O2           # Optimization level
        /GL           # Whole program optimization
        /Gy           # Enable function-level linking
    )
    target_link_options(kcp_proxy_lib PRIVATE /LTCG)  # Link-time code generation
else()
    target_compile_options(kcp_proxy_lib PRIVATE
        -Wall -Wextra -Wpedantic
        -O3
        -flto          # Link-time optimization
    )
    if(KCP_PROXY_ENABLE_NATIVE_TUNE)
        # Only for local dev machines; never ship release binaries built with
        # -march=native (CI runners may emit AVX-512 that SIGILLs on user CPUs).
        target_compile_options(kcp_proxy_lib PRIVATE -march=native)
    endif()
    target_link_options(kcp_proxy_lib PRIVATE -flto)
endif()

# Precompiled headers for faster compilation
target_precompile_headers(kcp_proxy_lib PRIVATE
    <vector>
    <string>
    <memory>
    <array>
    <cstdint>
    <cstring>
    <asio.hpp>
)

if(WIN32)
    target_compile_definitions(kcp_proxy_lib PUBLIC _WIN32_WINNT=0x0601)
endif()

# --- Executables ---
add_executable(kcp-proxy-server ${PROJECT_ROOT}/src/main_server.cpp)
target_link_libraries(kcp-proxy-server PRIVATE kcp_proxy_lib)

add_executable(kcp-proxy-client ${PROJECT_ROOT}/src/main_client.cpp)
target_link_libraries(kcp-proxy-client PRIVATE kcp_proxy_lib)

enable_testing()

add_executable(kcp_proxy_test ${PROJECT_ROOT}/tests/unit/test_core.cpp)
target_link_libraries(kcp_proxy_test PRIVATE kcp_proxy_lib)
add_test(
    NAME kcp_proxy_test
    COMMAND ${CMAKE_COMMAND}
        -DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
        -P ${PROJECT_ROOT}/tests/run_core_tests.cmake
)
# Every other test here has a TIMEOUT; without one a hung unit test blocks the
# CI job until the runner's own (much longer) limit expires.
set_tests_properties(kcp_proxy_test PROPERTIES TIMEOUT 300)

# --- End-to-end tunnel test (server <-> client <-> echo, offline) ---
# Spawns the built binaries plus a local echo target and a minimal SOCKS5
# client, then asserts real payloads survive the full SOCKS5-over-KCP path
# byte-for-byte. Registered only when a Python 3 interpreter is available.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    # Static packaging / deployment smoke tests. No build outputs needed: every
    # check reads tracked sources, so it runs in under a second and belongs in
    # the same gate as the binaries -- CI runs it too, and registering it here
    # keeps `ctest` locally equivalent to CI.
    add_test(
        NAME kcp_proxy_smoke
        COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_ROOT}/tests/smoke/smoke_test.py
    )
    set_tests_properties(kcp_proxy_smoke PROPERTIES TIMEOUT 60)

    add_test(
        NAME kcp_proxy_e2e_tunnel
        COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_ROOT}/tests/e2e/tunnel_e2e.py
            --server $<TARGET_FILE:kcp-proxy-server>
            --client $<TARGET_FILE:kcp-proxy-client>
    )
    set_tests_properties(kcp_proxy_e2e_tunnel PROPERTIES TIMEOUT 120)

    # Negative / robustness suite: wrong key, hostile UDP flood, concurrency and
    # session reclamation. Slower than the happy path (it drives ~100 tunnels and
    # a 1500-packet flood), hence the separate registration and timeout.
    add_test(
        NAME kcp_proxy_e2e_robustness
        COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_ROOT}/tests/e2e/robustness_e2e.py
            --server $<TARGET_FILE:kcp-proxy-server>
            --client $<TARGET_FILE:kcp-proxy-client>
    )
    set_tests_properties(kcp_proxy_e2e_robustness PROPERTIES TIMEOUT 300)
else()
    message(STATUS "Python3 interpreter not found: skipping smoke + E2E tests")
endif()

install(TARGETS kcp-proxy-server kcp-proxy-client
    RUNTIME DESTINATION bin
)
install(FILES "${PROJECT_ROOT}/README.md" DESTINATION .)
install(FILES "${PROJECT_ROOT}/scripts/runtime/start.sh" DESTINATION . OPTIONAL)
if(WIN32)
    install(FILES "${PROJECT_ROOT}/scripts/runtime/start.bat" DESTINATION . OPTIONAL)
endif()

# NOTE: the project deliberately has no CPack configuration and no generated
# version manifest. Releases are produced by scripts/package/package.py (see
# .github/workflows/release.yml), which derives the version from CMakeLists.txt
# itself -- a second, untested packaging path here only drifted: it shipped
# binaries without the OpenSSL runtime they need, and nothing ever invoked
# `cpack` or read the version.json it installed to share/kcp-proxy.
