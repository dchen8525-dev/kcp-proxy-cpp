# Overlay port for kcp-cpp (github.com/dchen8525-dev/kcp-cpp): the C++17 port
# of the kcp-go v5 state machine + Reed-Solomon FEC that replaces the C ikcp
# vcpkg port. Pinned to the upstream release tag; bump REF (and the version in
# vcpkg.json next to this file) together on every upstream release.
vcpkg_from_git(
  OUT_SOURCE_PATH SOURCE_PATH
  URL https://github.com/dchen8525-dev/kcp-cpp
  REF ca8ad19c18c83400d392986b24bb3a2e389fa41c  # v0.1.0
  HEAD_REF master
)

# The proxy embeds the library: no echo tools, no benchmarks, no tests. Upstream
# gates examples/bench behind KCP_BUILD_TOOLS and tests behind BUILD_TESTING
# (which vcpkg's toolchain already disables, kept explicit for clarity).
vcpkg_cmake_configure(
  SOURCE_PATH "${SOURCE_PATH}"
  OPTIONS
    -DKCP_BUILD_TOOLS=OFF
    -DBUILD_TESTING=OFF
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/kcp)
vcpkg_copy_pdbs()
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
