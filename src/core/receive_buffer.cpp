#include "core/receive_buffer.h"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace librats {

namespace {

/// Weight of one sample in the usage average: watermark += (peak - watermark) / 16.
/// Slow enough that a single quiet moment can't shrink a busy buffer, fast enough
/// that a connection that saw one big message releases it within a few messages.
constexpr size_t kUsageAverageShift = 4;  // 1/16

/// Allocations are rounded up to this, so a chain of 1.5x growth steps lands on
/// allocator-friendly sizes rather than 17496-byte oddities.
constexpr size_t kAllocGranularity = 256;

constexpr size_t round_up(size_t n, size_t granularity) noexcept {
    return (n + granularity - 1) / granularity * granularity;
}

} // namespace

ReceiveBuffer::ReceiveBuffer(size_t initial_capacity) {
    if (initial_capacity > 0) grow_to(round_up(initial_capacity, kAllocGranularity));
}

ReceiveBuffer& ReceiveBuffer::operator=(ReceiveBuffer&& other) noexcept {
    if (this == &other) return *this;

    // Every cursor moves with the allocation. Zeroing the source is what makes it a
    // valid *empty* buffer rather than one that still claims cap_/end_ bytes it no
    // longer owns — the state the compiler-generated move would have left behind.
    buf_       = std::move(other.buf_);
    cap_       = std::exchange(other.cap_, 0);
    start_     = std::exchange(other.start_, 0);
    end_       = std::exchange(other.end_, 0);
    peak_      = std::exchange(other.peak_, 0);
    watermark_ = std::exchange(other.watermark_, 0);
    received_since_decay_ = std::exchange(other.received_since_decay_, false);
    return *this;
}

// ── Write side ──────────────────────────────────────────────────────────────

ByteSpan ReceiveBuffer::prepare(size_t min_bytes) {
    if (cap_ - end_ < min_bytes) make_room(min_bytes);

    // Fold the *demand* into the peak, not just the bytes that end up arriving. A
    // caller reads with a fixed chunk size (16 KiB here, 64 KiB in the BitTorrent
    // peer), so an allocation too small to serve the next prepare() is not idle
    // memory — no matter how little the last message actually used. Sampling only
    // the live bytes would let the average sink below the read size, shrink the
    // buffer, and have the very next prepare() grow it straight back.
    // (libtorrent samples max(recv_end, packet_size) for the same reason.)
    peak_ = (std::max)(peak_, size() + min_bytes);

    return ByteSpan(buf_.get() + end_, cap_ - end_);
}

void ReceiveBuffer::commit(size_t bytes) {
    assert(bytes <= cap_ - end_ && "commit() past the span handed out by prepare()");
    end_ += bytes;
    peak_ = (std::max)(peak_, size());
    received_since_decay_ = true;  // this tick saw traffic; decay() must leave us alone
}

void ReceiveBuffer::make_room(size_t bytes) {
    const size_t live = size();

    // Reclaiming the consumed prefix is enough: a memmove of the live bytes beats
    // an allocation. Only reachable when something has been consumed, so it costs
    // at most one memmove per bufferful of traffic.
    if (cap_ - live >= bytes) {
        compact();
        return;
    }
    grow_to(grown_capacity(live + bytes));
}

void ReceiveBuffer::grow_to(size_t new_capacity) {
    reallocate(new_capacity);
    // Restart the usage average at the new size: the buffer just grew for a reason,
    // and judging it oversized on the next drained message would only make it flap
    // between two sizes. Demand has to fall for a while before it shrinks again.
    watermark_ = cap_;
    peak_      = size();
}

size_t ReceiveBuffer::grown_capacity(size_t needed) const noexcept {
    size_t next = cap_ + cap_ / 2;              // 1.5x, as libtorrent does
    if (next < kMinCapacity) next = kMinCapacity;
    if (next < needed)       next = needed;     // a single big message may outrun 1.5x
    return round_up(next, kAllocGranularity);
}

void ReceiveBuffer::reallocate(size_t new_capacity) {
    const size_t live = size();
    assert(new_capacity >= live);

    // Deliberately uninitialised (`new uint8_t[n]` default-initialises scalars,
    // i.e. does nothing): every byte is about to be overwritten by recv().
    std::unique_ptr<uint8_t[]> fresh(new uint8_t[new_capacity]);
    if (live > 0) std::memcpy(fresh.get(), data(), live);

    buf_   = std::move(fresh);
    cap_   = new_capacity;
    start_ = 0;
    end_   = live;
}

// ── Read side ───────────────────────────────────────────────────────────────

void ReceiveBuffer::consume(size_t bytes) {
    assert(bytes <= size() && "consume() past the live data");
    start_ += bytes;
    if (start_ != end_) return;

    // Fully drained — the common case. Rewinding both cursors keeps the buffer
    // normalised for free, so the steady state never memmoves.
    start_ = end_ = 0;
    sample_usage();
    maybe_shrink();
}

// ── Maintenance ─────────────────────────────────────────────────────────────

void ReceiveBuffer::compact() {
    if (start_ == 0) return;

    const size_t live = size();
    if (live > 0) std::memmove(buf_.get(), buf_.get() + start_, live);
    start_ = 0;
    end_   = live;
    sample_usage();
}

void ReceiveBuffer::decay() {
    // Nothing worth reclaiming, or a partial message still needs the storage it is
    // sitting in. (maybe_shrink() may only run on a drained buffer.)
    if (cap_ <= kMinCapacity || !empty()) return;

    // Traffic since the last tick: consume() already sampled it, and this connection
    // is sized for a reason. Aging it as well would shrink it below its read size only
    // for the next prepare() to grow it straight back.
    if (std::exchange(received_since_decay_, false)) return;

    // Silent for a whole tick. Halving (rather than folding in one more zero sample)
    // is what makes this converge in seconds rather than minutes: maybe_shrink() wants
    // the allocation to be more than twice the watermark, so halving the watermark
    // halves the allocation every couple of ticks until it is back at the floor.
    watermark_ /= 2;
    maybe_shrink();
}

void ReceiveBuffer::clear() noexcept {
    start_ = end_ = 0;
    peak_  = 0;
}

void ReceiveBuffer::reset() noexcept {
    buf_.reset();
    cap_ = start_ = end_ = peak_ = watermark_ = 0;
}

void ReceiveBuffer::sample_usage() noexcept {
    // Exponential average; the +(N-1) rounds up so the average still tracks a
    // rising peak instead of stalling below it on integer division.
    constexpr size_t n = size_t{1} << kUsageAverageShift;
    watermark_ = (watermark_ * (n - 1) + peak_ + (n - 1)) / n;
    peak_      = size();
}

void ReceiveBuffer::maybe_shrink() {
    assert(empty() && "shrinking is only decided on a drained buffer");

    // Only when the allocation is worth reclaiming *and* recent demand has clearly
    // moved on — otherwise a buffer merely sitting between two messages would free
    // and re-allocate itself on every single message.
    if (cap_ <= kMinCapacity || cap_ / 2 <= watermark_) return;

    // Fall back to what recent demand actually says, not to a padded version of it:
    // the trigger above guarantees that halves the allocation at least, so a buffer
    // that ballooned for one huge message is back to normal in a handful of steps
    // (at most log2(cap) reallocations), not by creeping down a few percent at a
    // time. Growth is geometric and cheap if demand returns.
    // The watermark is deliberately NOT reset here (unlike after a grow): it is the
    // decaying memory of demand that has to keep falling to shrink us further.
    const size_t target = round_up((std::max)(kMinCapacity, watermark_), kAllocGranularity);
    if (target < cap_) reallocate(target);
}

} // namespace librats
