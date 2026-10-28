// Freelist recycling for per-datagram buffers on the UDP hot path.
//
// At ~2700 pps each direction (30 Mbps at MTU-sized datagrams), a fresh
// std::vector per datagram -- plus the make_shared holder that keeps it alive
// across an async_send -- costs thousands of malloc/free round trips per
// second per endpoint. The pool below hands out vectors whose capacity is
// recycled once the async operation that borrowed them completes, so the
// steady state costs one small heap allocation per datagram (the fused
// control-block holder in make_pooled_send) instead of two to three.
//
// The pool carries no protocol state: an acquire that finds the freelist
// empty (or a caller that never releases) degrades to plain allocation and
// everything stays correct. Buffers larger than kMaxPooledCapacity are never
// stored, so an anomalous huge datagram cannot pin pool slots.

#pragma once

#include <cstddef>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

namespace kcp_proxy {

class BufferPool {
public:
    BufferPool(size_t max_buffers, size_t max_capacity) noexcept
        : max_buffers_(max_buffers), max_capacity_(max_capacity) {}

    // Returns a (possibly recycled) buffer. Never throws; an empty pool just
    // means a fresh allocation. Callers resize, so leftover capacity is free.
    std::vector<uint8_t> acquire() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (free_.empty()) return {};
        auto buf = std::move(free_.back());
        free_.pop_back();
        return buf;
    }

    // Recycles a buffer back to the freelist. Oversized or over-budget
    // buffers are dropped; both bounds keep the pool's footprint fixed.
    void release(std::vector<uint8_t>&& buf) noexcept {
        if (buf.capacity() == 0 || buf.capacity() > max_capacity_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (free_.size() >= max_buffers_) return;
        free_.push_back(std::move(buf));
    }

private:
    const size_t max_buffers_;
    const size_t max_capacity_;
    std::mutex mutex_;
    std::vector<std::vector<uint8_t>> free_;
};

// The process-wide datagram pool. Sized for the worst realistic burst:
// 256 buffers of up to 8 KiB (max KCP datagram + crypto framing + FEC
// header, with headroom) is at most 2 MiB, typically far less.
inline BufferPool& datagram_pool() {
    static BufferPool pool(256, 8192);
    return pool;
}

// Owns a datagram buffer and returns it to the pool on destruction. Wrap the
// data member through a shared_ptr aliasing constructor (see
// make_pooled_send) so async completions can capture one shared_ptr while the
// buffer's release is tied to the last reference, wherever it dies.
struct PooledBuffer {
    explicit PooledBuffer(BufferPool& p) : pool(&p) {}

    PooledBuffer(const PooledBuffer&) = delete;
    PooledBuffer& operator=(const PooledBuffer&) = delete;

    ~PooledBuffer() {
        if (pool) pool->release(std::move(data));
    }

    BufferPool* pool;
    std::vector<uint8_t> data;
};

// Moves `data` into a pooled holder and returns a shared_ptr aliasing the
// vector, so call sites keep their existing `shared_ptr<vector<uint8_t>>`
// shape. Steady-state cost: one fused allocation (control block + holder).
inline std::shared_ptr<std::vector<uint8_t>> make_pooled_send(std::vector<uint8_t> data) {
    auto holder = std::make_shared<PooledBuffer>(datagram_pool());
    holder->data = std::move(data);
    return std::shared_ptr<std::vector<uint8_t>>(holder, &holder->data);
}

} // namespace kcp_proxy
