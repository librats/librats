#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  net_mock.h — a deterministic stand-in for the kernel's socket buffers.
//
//  The buffers under test are pure userland data structures; what makes them
//  fast or slow is *how many times they have to talk to the kernel* and *how
//  many bytes they copy on the way*. A real socket would make that impossible
//  to measure repeatably (scheduler, loopback MTU, SO_SNDBUF autotuning), so
//  the syscall boundary is modelled instead:
//
//    RxKernel  — holds bytes "already in the socket's receive queue"; recv()
//                hands back min(len, queued) and returns EWOULDBLOCK when dry.
//                A short read therefore means exactly what it means on a real
//                socket: the queue is empty right now.
//
//    TxKernel  — accepts at most `per_call` bytes per send()/sendmsg() (a real
//                socket is bounded by SO_SNDBUF) and at most `budget` bytes
//                before it returns EWOULDBLOCK (a congested peer). refill()
//                is the next writable event.
//
//  Both memcpy the payload into a sink, exactly as copy_to/from_user would, so
//  neither side gets to skip touching the bytes it claims to have transferred.
//
//  Every call is counted. That is where the "syscalls" column comes from.
// ─────────────────────────────────────────────────────────────────────────────

#include "core/bytes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace mock {

using librats::ByteView;

struct Counters {
    std::uint64_t calls      = 0;  ///< recv() / send() / sendmsg() invocations
    std::uint64_t slices     = 0;  ///< iovec entries handed to the kernel (tx only)
    std::uint64_t bytes      = 0;  ///< bytes actually transferred
    std::uint64_t wouldblock = 0;  ///< calls that came back EWOULDBLOCK

    void reset() { *this = Counters{}; }
};

// ── Receive side ─────────────────────────────────────────────────────────────

class RxKernel {
public:
    /// The peer's bytes land in the socket's receive queue.
    void deliver(const uint8_t* p, std::size_t n) {
        queue_.insert(queue_.end(), p, p + n);
    }

    /// recv(2) on a non-blocking socket: hands back what is queued, up to `len`.
    /// Returns -1 (EWOULDBLOCK) when the queue is empty.
    std::ptrdiff_t recv(uint8_t* dst, std::size_t len) {
        ++c.calls;
        const std::size_t avail = queue_.size() - pos_;
        if (avail == 0) {
            ++c.wouldblock;
            return -1;
        }
        const std::size_t n = (std::min)(len, avail);
        std::memcpy(dst, queue_.data() + pos_, n);  // copy_to_user
        pos_ += n;
        c.bytes += n;
        if (pos_ == queue_.size()) {  // drained — recycle the queue storage
            queue_.clear();
            pos_ = 0;
        }
        return static_cast<std::ptrdiff_t>(n);
    }

    bool has_data() const { return pos_ < queue_.size(); }
    void reset() {
        queue_.clear();
        pos_ = 0;
        c.reset();
    }

    Counters c;

private:
    std::vector<uint8_t> queue_;
    std::size_t          pos_ = 0;
};

// ── Send side ────────────────────────────────────────────────────────────────

class TxKernel {
public:
    /// @param per_call  most bytes one send()/sendmsg() will accept (~SO_SNDBUF)
    /// @param budget    bytes accepted before EWOULDBLOCK; SIZE_MAX = never congested
    explicit TxKernel(std::size_t per_call = 256 * 1024,
                      std::size_t budget   = SIZE_MAX)
        : per_call_(per_call), budget_(budget), initial_budget_(budget) {
        sink_.resize(per_call_);
    }

    /// send(2), one contiguous buffer.
    std::ptrdiff_t send(const uint8_t* p, std::size_t n) {
        ++c.calls;
        ++c.slices;
        if (budget_ == 0) {
            ++c.wouldblock;
            return -1;
        }
        const std::size_t take = (std::min)((std::min)(n, per_call_), budget_);
        std::memcpy(sink_.data(), p, take);  // copy_from_user
        consume(take);
        return static_cast<std::ptrdiff_t>(take);
    }

    /// sendmsg(2) / WSASend, scatter-gather.
    std::ptrdiff_t sendv(const ByteView* slices, std::size_t count) {
        ++c.calls;
        c.slices += count;
        if (budget_ == 0) {
            ++c.wouldblock;
            return -1;
        }
        std::size_t room = (std::min)(per_call_, budget_);
        std::size_t take = 0;
        for (std::size_t i = 0; i < count && room > 0; ++i) {
            const std::size_t n = (std::min)(slices[i].size(), room);
            std::memcpy(sink_.data() + take, slices[i].data(), n);  // per-iov copy
            take += n;
            room -= n;
        }
        if (take == 0) {  // nothing offered
            ++c.wouldblock;
            return -1;
        }
        consume(take);
        return static_cast<std::ptrdiff_t>(take);
    }

    /// The next writable event: the peer drained its window.
    void refill() { budget_ = initial_budget_; }

    void reset() {
        budget_ = initial_budget_;
        c.reset();
    }

    Counters c;

private:
    void consume(std::size_t n) {
        c.bytes += n;
        if (budget_ != SIZE_MAX) budget_ -= n;
    }

    std::size_t          per_call_;
    std::size_t          budget_;
    std::size_t          initial_budget_;
    std::vector<uint8_t> sink_;
};

}  // namespace mock
