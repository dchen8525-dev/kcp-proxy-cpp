// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/bufferpool.h"

#include <utility>

#include "kcp/internal/constants.h"

namespace kcp {
namespace internal {

BufferPool::BufferPool(std::size_t buffer_size) : buffer_size_(buffer_size) {}

std::vector<std::uint8_t> BufferPool::Get() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!free_.empty()) {
      std::vector<std::uint8_t> buffer = std::move(free_.back());
      free_.pop_back();
      // Callers receive a full-size buffer even if it was returned shorter (Go reslices to cap).
      buffer.resize(buffer_size_);
      return buffer;
    }
  }
  return std::vector<std::uint8_t>(buffer_size_);
}

bool BufferPool::Put(std::vector<std::uint8_t> buffer) {
  if (buffer.capacity() != buffer_size_) {
    return false;
  }
  buffer.resize(buffer_size_);
  std::lock_guard<std::mutex> lock(mutex_);
  free_.push_back(std::move(buffer));
  return true;
}

std::size_t BufferPool::FreeCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return free_.size();
}

BufferPool& DefaultBufferPool() {
  static BufferPool* pool = new BufferPool(kMtuLimit);
  return *pool;
}

}  // namespace internal
}  // namespace kcp
