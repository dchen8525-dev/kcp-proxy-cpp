// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_RINGBUFFER_H_
#define KCP_INTERNAL_RINGBUFFER_H_

#include <cstddef>
#include <utility>
#include <vector>

#include "kcp/internal/constants.h"

namespace kcp {
namespace internal {

// Generic circular FIFO with automatic growth, ported from ringbuffer.go. The reference uses it
// for all three of KCP's segment queues; the semantics that matter are:
//   - Push never fails: the buffer grows when full.
//   - Usable capacity is len - 1 (one slot stays empty so head == tail means "empty").
//   - Iteration order is oldest first (ForEach) or newest first (ForEachReverse).
//   - Discard(n) drops from the head without touching the tail.
template <typename T>
class RingBuffer {
 public:
  explicit RingBuffer(std::size_t size) {
    elements_.resize(size <= kRingBufferMin ? kRingBufferMin : size);
  }

  std::size_t Len() const {
    if (head_ <= tail_) {
      return tail_ - head_;
    }
    return elements_.size() - head_ + tail_;
  }

  bool IsEmpty() const { return head_ == tail_; }

  bool IsFull() const { return (tail_ + 1) % elements_.size() == head_; }

  // ringbuffer.go:238 - capacity as the reference reports it, i.e. len - 1.
  std::size_t MaxLen() const { return elements_.size() - 1; }

  void Push(T value) {
    if (IsFull()) {
      Grow();
    }
    elements_[tail_] = std::move(value);
    tail_ = (tail_ + 1) % elements_.size();
  }

  bool Pop(T* out) {
    if (Len() == 0) {
      return false;
    }
    *out = std::move(elements_[head_]);
    elements_[head_] = T();
    head_ = (head_ + 1) % elements_.size();
    return true;
  }

  T* Peek() { return Len() == 0 ? nullptr : &elements_[head_]; }

  const T* Peek() const { return Len() == 0 ? nullptr : &elements_[head_]; }

  std::size_t Discard(std::size_t n) {
    const std::size_t current_len = Len();
    if (n > current_len) {
      n = current_len;
    }
    if (n == current_len) {
      Clear();
      return n;
    }
    const std::size_t capacity = elements_.size();
    const std::size_t end = head_ + n;
    if (end < capacity) {
      for (std::size_t i = head_; i < end; ++i) {
        elements_[i] = T();
      }
      head_ = end;
    } else {
      for (std::size_t i = head_; i < capacity; ++i) {
        elements_[i] = T();
      }
      for (std::size_t i = 0; i < end - capacity; ++i) {
        elements_[i] = T();
      }
      head_ = end - capacity;
    }
    return n;
  }

  // The visitor returns false to stop, which is how the reference expresses `break` inside a
  // range-over-func loop. Callers that only want the last element return false immediately.
  template <typename Fn>
  void ForEach(Fn&& fn) {
    if (Len() == 0) {
      return;
    }
    if (head_ < tail_) {
      for (std::size_t i = head_; i < tail_; ++i) {
        if (!fn(elements_[i])) {
          return;
        }
      }
    } else {
      for (std::size_t i = head_; i < elements_.size(); ++i) {
        if (!fn(elements_[i])) {
          return;
        }
      }
      for (std::size_t i = 0; i < tail_; ++i) {
        if (!fn(elements_[i])) {
          return;
        }
      }
    }
  }

  template <typename Fn>
  void ForEach(Fn&& fn) const {
    if (Len() == 0) {
      return;
    }
    if (head_ < tail_) {
      for (std::size_t i = head_; i < tail_; ++i) {
        if (!fn(elements_[i])) {
          return;
        }
      }
    } else {
      for (std::size_t i = head_; i < elements_.size(); ++i) {
        if (!fn(elements_[i])) {
          return;
        }
      }
      for (std::size_t i = 0; i < tail_; ++i) {
        if (!fn(elements_[i])) {
          return;
        }
      }
    }
  }

  template <typename Fn>
  void ForEachReverse(Fn&& fn) {
    if (Len() == 0) {
      return;
    }
    if (head_ < tail_) {
      for (std::size_t i = tail_; i > head_; --i) {
        if (!fn(elements_[i - 1])) {
          return;
        }
      }
    } else {
      for (std::size_t i = tail_; i > 0; --i) {
        if (!fn(elements_[i - 1])) {
          return;
        }
      }
      for (std::size_t i = elements_.size(); i > head_; --i) {
        if (!fn(elements_[i - 1])) {
          return;
        }
      }
    }
  }

  void Clear() {
    // Only the occupied slots hold live values; the rest are already default-constructed, so
    // clearing them would be a pointless pass over the whole capacity (this runs from
    // ParseUna whenever the send buffer drains).
    if (head_ <= tail_) {
      for (std::size_t i = head_; i < tail_; ++i) {
        elements_[i] = T();
      }
    } else {
      for (std::size_t i = head_; i < elements_.size(); ++i) {
        elements_[i] = T();
      }
      for (std::size_t i = 0; i < tail_; ++i) {
        elements_[i] = T();
      }
    }
    head_ = 0;
    tail_ = 0;
  }

 private:
  // ringbuffer.go:265-289 - double below 1024 slots, then grow by 10% (rounded up), so a very
  // large queue does not pay a full copy of its contents on every capacity step.
  void Grow() {
    const std::size_t current_len = Len();
    const std::size_t current_size = elements_.size();
    std::size_t new_size = 0;
    if (current_size < kRingBufferMin) {
      new_size = kRingBufferMin;
    } else if (current_size < kRingBufferExp) {
      new_size = current_size * 2;
    } else {
      new_size = current_size + (current_size + 9) / 10;
    }

    std::vector<T> new_elements(new_size);
    if (head_ < tail_) {
      for (std::size_t i = head_; i < tail_; ++i) {
        new_elements[i - head_] = std::move(elements_[i]);
      }
    } else {
      std::size_t n = 0;
      for (std::size_t i = head_; i < elements_.size(); ++i) {
        new_elements[n++] = std::move(elements_[i]);
      }
      for (std::size_t i = 0; i < tail_; ++i) {
        new_elements[n++] = std::move(elements_[i]);
      }
    }

    head_ = 0;
    tail_ = current_len;
    elements_ = std::move(new_elements);
  }

  std::size_t head_ = 0;
  std::size_t tail_ = 0;
  std::vector<T> elements_;
};

}  // namespace internal
}  // namespace kcp

#endif  // KCP_INTERNAL_RINGBUFFER_H_
