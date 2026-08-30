#pragma once

#include <cassert>
#include <cstdint>
#include <cstddef>
#include <vector>

namespace kcp_proxy {

// C++17-compatible replacement for std::span<const uint8_t>
struct byte_view {
    const uint8_t* data_;
    size_t size_;

    constexpr byte_view() : data_(nullptr), size_(0) {}
    constexpr byte_view(const uint8_t* data, size_t size) : data_(data), size_(size) {}
    byte_view(const std::vector<uint8_t>& v) : data_(v.data()), size_(v.size()) {}

    constexpr const uint8_t* data() const { return data_; }
    constexpr size_t size() const { return size_; }
    constexpr bool empty() const { return size_ == 0; }
    const uint8_t& operator[](size_t i) const { assert(i < size_); return data_[i]; }
    constexpr const uint8_t* begin() const { return data_; }
    constexpr const uint8_t* end() const { return data_ + size_; }
};

} // namespace kcp_proxy
