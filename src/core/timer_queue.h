#pragma once

/**
 * @file timer_queue.h
 * @brief Deadline-ordered timer set driven by the reactor loop.
 *
 * Backs handshake timeouts, reconnection backoff, keep-alives, etc. The reactor
 * asks next_timeout_ms() to size its poll wait, then calls run_due() once it
 * wakes. Cancellation is lazy (tombstone set) so cancel() is O(1) and never has
 * to find the entry in the heap.
 *
 * Complexity: schedule O(log n), run_due amortised O(log n) per fired timer.
 * A hashed timing wheel can replace this behind the same interface if O(1)
 * scheduling ever becomes necessary; for thousands of timers a heap is ample.
 *
 * Single-threaded: only ever touched by the owning reactor thread.
 */

#include "core/types.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <unordered_set>
#include <vector>

namespace librats {

class TimerQueue {
public:
    using Clock    = std::chrono::steady_clock;
    using Callback = std::function<void()>;

    /// Schedule `cb` to fire after `delay`. Returns a handle for cancel().
    TimerId schedule(Clock::duration delay, Callback cb) {
        const TimerId id = ++last_id_;
        heap_.push_back(Entry{Clock::now() + delay, id, std::move(cb)});
        std::push_heap(heap_.begin(), heap_.end(), later_first_);
        return id;
    }

    /// Cancel a pending timer. Safe even if it has already fired or never existed.
    void cancel(TimerId id) {
        if (id != kInvalidTimerId) cancelled_.insert(id);
    }

    /// Milliseconds until the next timer is due, clamped to [0, max_ms].
    int next_timeout_ms(int max_ms) const {
        if (heap_.empty()) return max_ms;
        const auto now = Clock::now();
        const auto due = heap_.front().when;
        if (due <= now) return 0;
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(due - now).count();
        return static_cast<int>(std::min<long long>(ms, max_ms));
    }

    /// Fire every timer whose deadline has passed (skipping cancelled ones).
    void run_due() {
        const auto now = Clock::now();
        while (!heap_.empty() && heap_.front().when <= now) {
            std::pop_heap(heap_.begin(), heap_.end(), later_first_);
            Entry e = std::move(heap_.back());
            heap_.pop_back();

            auto it = cancelled_.find(e.id);
            if (it != cancelled_.end()) {
                cancelled_.erase(it);
                continue;
            }
            e.cb();
        }
    }

    bool empty() const { return heap_.empty(); }

private:
    struct Entry {
        Clock::time_point when;
        TimerId           id;
        Callback          cb;
    };
    // Min-heap on `when`: std::*_heap are max-heaps, so invert the comparison.
    struct LaterFirst {
        bool operator()(const Entry& a, const Entry& b) const { return a.when > b.when; }
    } later_first_;

    std::vector<Entry>          heap_;
    std::unordered_set<TimerId> cancelled_;
    TimerId                     last_id_ = kInvalidTimerId;
};

} // namespace librats
