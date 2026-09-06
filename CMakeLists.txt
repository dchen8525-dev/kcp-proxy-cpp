cmake_minimum_required(VERSION 3.22)

# --- vcpkg toolchain (must be set before project()) ---
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

project(kcp_proxy VERSION 0.0.3 LANGUAGES C CXX)

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

install(TARGETS kcp-proxy-server kcp-proxy-client
    RUNTIME DESTINATION bin
)
install(FILES "${PROJECT_ROOT}/README.md" DESTINATION .)
install(FILES "${PROJECT_ROOT}/scripts/runtime/start.sh" DESTINATION . OPTIONAL)
if(WIN32)
    install(FILES "${PROJECT_ROOT}/scripts/runtime/start.bat" DESTINATION . OPTIONAL)
endif()

# Generate a small version manifest consumed by packaging and smoke tests.
set(KCP_PROXY_VERSION_MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/generated/version.json")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(WRITE "${KCP_PROXY_VERSION_MANIFEST}"
    "{\n"
    "  \"version\": \"${PROJECT_VERSION}\",\n"
    "  \"project\": \"kcp-proxy\"\n"
    "}\n")
install(FILES "${KCP_PROXY_VERSION_MANIFEST}" DESTINATION share/kcp-proxy)

# Packaging with CPack
set(CPACK_PACKAGE_NAME "kcp-proxy")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "KCP-based encrypted SOCKS5 proxy")
set(CPACK_PACKAGE_CONTACT "dchen8525@gmail.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/dchen8525-dev/kcp-proxy-cpp")
# CPack license/readme resources are optional - fall back to CPack defaults
# when the repo does not ship a LICENSE file.
if(EXISTS "${PROJECT_ROOT}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_ROOT}/LICENSE")
endif()
if(EXISTS "${PROJECT_ROOT}/README.md")
    set(CPACK_RESOURCE_FILE_README "${PROJECT_ROOT}/README.md")
endif()

# Platform-specific package settings
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-windows-x64")
else()
    set(CPACK_GENERATOR "TGZ")
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-linux-x64")
endif()

include(CPack)
