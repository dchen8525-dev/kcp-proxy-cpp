// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/timedsched.h"

#include <utility>

namespace kcp {
namespace internal {

TimedSched& TimedSched::Default() {
  static TimedSched* instance = new TimedSched();
  return *instance;
}

TimedSched::TimedSched() : worker_([this] { Run(); }) {}

TimedSched::~TimedSched() { Shutdown(); }

void TimedSched::Put(std::function<void()> fn, TimePoint deadline) {
  if (!fn) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mu_);
    if (stopped_) {
      return;
    }
    tasks_.push(Task{deadline, next_seq_++, std::move(fn)});
  }
  cv_.notify_one();
}

void TimedSched::Shutdown() {
  {
    std::lock_guard<std::mutex> lock(mu_);
    stopped_ = true;
  }
  cv_.notify_all();
  if (worker_.joinable()) {
    worker_.join();
  }
}

std::size_t TimedSched::size() const {
  std::lock_guard<std::mutex> lock(mu_);
  return tasks_.size();
}

void TimedSched::Run() {
  std::unique_lock<std::mutex> lock(mu_);
  for (;;) {
    if (stopped_) {
      return;
    }
    if (tasks_.empty()) {
      cv_.wait(lock);
      continue;
    }

    const TimePoint due = tasks_.top().due;
    const TimePoint now = std::chrono::steady_clock::now();
    if (due > now) {
      cv_.wait_until(lock, due);
      continue;
    }

    // Pop and run with the lock released: a task is allowed to call Put() again (every session
    // Update does) and must never hold the scheduler lock while it runs user code.
    Task task = tasks_.top();
    tasks_.pop();
    lock.unlock();
    task.fn();
    lock.lock();
  }
}

}  // namespace internal
}  // namespace kcp
