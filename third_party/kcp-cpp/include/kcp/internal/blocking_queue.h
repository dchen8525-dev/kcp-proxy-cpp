// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_BLOCKING_QUEUE_H_
#define KCP_INTERNAL_BLOCKING_QUEUE_H_

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

namespace kcp {
namespace internal {

// Bounded multi-producer / single-consumer queue. Replaces the Go buffered channel
// `chPostProcessing` (sess.go:161).
//
// The producer side is TryPush, never Push: a full queue must drop the datagram and let KCP
// retransmit (issue #38). Blocking here would be a deadlock - the producer holds the session
// mutex - and it would also be useless, because the flow-control decision already belongs to
// KCP's send window.
//
// Close() lets the consumer drain whatever is already queued and then returns false from Pop(),
// which is what PostProcess needs so a final flush is not swallowed by shutdown.
template <typename T>
class BlockingQueue {
 public:
  explicit BlockingQueue(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

  BlockingQueue(const BlockingQueue&) = delete;
  BlockingQueue& operator=(const BlockingQueue&) = delete;

  // Returns false when the queue is full or already closed; the caller owns `value` again.
  bool TryPush(T value) {
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_.load(std::memory_order_acquire) || queue_.size() >= capacity_) {
      return false;
    }
    queue_.push_back(std::move(value));
    not_empty_.notify_one();
    return true;
  }

  // Blocks until an element is available. Returns false once the queue is closed and drained.
  bool Pop(T* out) {
    std::unique_lock<std::mutex> lock(mu_);
    not_empty_.wait(lock,
                    [this] { return closed_.load(std::memory_order_acquire) || !queue_.empty(); });
    if (queue_.empty()) {
      return false;
    }
    *out = std::move(queue_.front());
    queue_.pop_front();
    return true;
  }

  // Non-blocking variant; false when empty.
  bool TryPop(T* out) {
    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.empty()) {
      return false;
    }
    *out = std::move(queue_.front());
    queue_.pop_front();
    return true;
  }

  void Close() {
    {
      std::lock_guard<std::mutex> lock(mu_);
      closed_.store(true, std::memory_order_release);
    }
    not_empty_.notify_all();
  }

  bool closed() const { return closed_.load(std::memory_order_acquire); }

  std::size_t size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return queue_.size();
  }

  std::size_t capacity() const { return capacity_; }

 private:
  const std::size_t capacity_;
  mutable std::mutex mu_;
  std::condition_variable not_empty_;
  std::deque<T> queue_;
  std::atomic<bool> closed_{false};
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_BLOCKING_QUEUE_H_
