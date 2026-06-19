#pragma once

/**
 * @file mpsc_queue.h
 * @brief Multi-producer / single-consumer task queue used to hand work to a Reactor.
 *
 * Many threads call push(); exactly one (the reactor thread) calls drain().
 * drain() swaps the entire backlog out under a single lock, so the consumer
 * pays one lock per *batch*, not per item — the lock guards the handoff, never
 * the work itself. This is deliberately simple and correct; it can be swapped
 * for an intrusive lock-free MPSC later without touching callers.
 */

#include <mutex>
#include <vector>

namespace librats {

template <typename T>
class MpscQueue {
public:
    /// Enqueue an item. Safe to call from any thread.
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(std::move(item));
    }

    /// Move the entire backlog into `out` (cleared first). Single consumer only.
    /// Returns the number of items handed over.
    size_t drain(std::vector<T>& out) {
        out.clear();
        std::lock_guard<std::mutex> lock(mutex_);
        out.swap(queue_);
        return out.size();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    mutable std::mutex mutex_;
    std::vector<T>     queue_;
};

} // namespace librats
