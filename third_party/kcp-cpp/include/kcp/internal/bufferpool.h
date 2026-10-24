// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_BUFFERPOOL_H_
#define KCP_INTERNAL_BUFFERPOOL_H_

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace kcp {
namespace internal {

// Fixed-size buffer pool standing in for Go's sync.Pool (bufferpool.go:33-65).
//
// Get() hands out a buffer of exactly buffer_size() bytes; Put() takes it back. Put() rejects a
// buffer whose capacity differs, mirroring errBufferSizeMismatch: silently accepting a resized
// buffer would poison later packets with the wrong MTU. There is no eviction - the pool only grows
// to the high-water mark of concurrent packets, which is bounded by the post-processing queue.
class BufferPool {
 public:
  explicit BufferPool(std::size_t buffer_size);

  std::vector<std::uint8_t> Get();
  bool Put(std::vector<std::uint8_t> buffer);

  std::size_t buffer_size() const { return buffer_size_; }

  // Idle buffer count. Test-only observability; Go's sync.Pool offers nothing comparable.
  std::size_t FreeCount() const;

 private:
  const std::size_t buffer_size_;
  mutable std::mutex mutex_;
  std::vector<std::vector<std::uint8_t>> free_;
};

// Process-wide pool with 1500-byte buffers (mtuLimit). Function-local static, never destroyed:
// in-flight packets may still be returned to it during static destruction (§3.5).
BufferPool& DefaultBufferPool();

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_BUFFERPOOL_H_
