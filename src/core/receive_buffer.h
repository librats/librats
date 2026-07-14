#pragma once

/**
 * @file receive_buffer.h
 * @brief Stream receive buffer: O(1) consume, amortised growth, automatic shrink.
 *
 * A byte stream arrives in arbitrary slices and is parsed in whole messages, so a
 * receive buffer must hold a partial message across reads while handing complete
 * ones to the parser. Three cursors describe it:
 *
 *      |<-- consumed -->|<------ live ------>|<----- writable ----->|
 *      0             start_                end_                   cap_
 *
 *   - `consumed` — already parsed; dead space, reclaimed by compact().
 *   - `live`     — received but not yet parsed: data()/size().
 *   - `writable` — free tail, handed to recv() by prepare().
 *
 * consume() only advances `start_`, so dropping a parsed message is O(1) — the
 * point of the class (std::vector::erase() would be O(n) per message). Draining
 * the buffer rewinds both cursors to 0, so the steady state needs no memmove at
 * all; a memmove only happens when the tail runs out with a partial message still
 * live, i.e. at most once per bufferful.
 *
 * Memory:
 *   - Storage is raw, *uninitialised* (`new uint8_t[]`), not a std::vector: recv()
 *     overwrites it anyway, so value-initialising every byte is pure waste. It is
 *     also allocated at exactly the requested size, without the hidden ~2x
 *     over-allocation std::vector::resize() performs when it grows.
 *   - Growth is geometric (1.5x), so filling the buffer stays amortised O(1)/byte.
 *   - The buffer shrinks by itself: a running average of recent demand (the
 *     `watermark`) is sampled whenever the buffer drains, and once the allocation
 *     is more than twice that average it is reallocated down. Without this, one
 *     large message would pin a large allocation for the connection's lifetime.
 *     "Demand" is what prepare() was asked for, not merely what arrived — a caller
 *     reads with a fixed chunk size, so an allocation too small to serve the next
 *     read is not idle memory, and counting only the bytes that turned up would
 *     shrink the buffer just for the next prepare() to grow it straight back.
 *     (This mirrors libtorrent's receive_buffer watermark — which samples
 *     max(recv_end, packet_size) for the same reason — but as a plain exponential
 *     average instead of a 20-sample sliding window.)
 *
 * Not thread-safe: like everything on the connection path, it is owned and touched
 * by exactly one reactor thread.
 *
 * Usage:
 *   ByteSpan into = buf.prepare(16 * 1024);        // room for at least 16 KiB
 *   int n = recv(sock, into.data(), into.size());
 *   buf.commit(n);                                 // n bytes are now live
 *   while (auto msg = parse(buf.data(), buf.size()))
 *       buf.consume(msg.size());                   // O(1)
 */

#include "core/bytes.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace librats {

class ReceiveBuffer {
public:
    /// Floor for any allocation, and the size the buffer shrinks back towards.
    static constexpr size_t kMinCapacity = 1024;

    /// Starts with no allocation at all by default: a connection that never
    /// receives anything never pays for a buffer. The first prepare() allocates.
    explicit ReceiveBuffer(size_t initial_capacity = 0);

    /// Moving leaves the source empty and unallocated — a defaulted move would carry
    /// the cursors over while the unique_ptr went null, leaving prepare() handing out
    /// a span into nullptr.
    ReceiveBuffer(ReceiveBuffer&& other) noexcept { *this = std::move(other); }
    ReceiveBuffer& operator=(ReceiveBuffer&& other) noexcept;
    ReceiveBuffer(const ReceiveBuffer&) = delete;
    ReceiveBuffer& operator=(const ReceiveBuffer&) = delete;

    // ── Write side (recv) ───────────────────────────────────────────────────

    /// Make room for at least `min_bytes` and return the writable tail. The span
    /// is usually *larger* than asked for — pass its full size() to recv() so a
    /// single syscall can take everything the kernel has. Invalidates data() and
    /// any view into the buffer (it may compact or reallocate).
    ByteSpan prepare(size_t min_bytes);

    /// Publish `bytes` freshly written into the span from prepare(): they become
    /// live. `bytes` must not exceed that span's size().
    void commit(size_t bytes);

    // ── Read side (parsing) ─────────────────────────────────────────────────

    const uint8_t* data()  const noexcept { return buf_.get() + start_; }
    size_t         size()  const noexcept { return end_ - start_; }
    bool           empty() const noexcept { return start_ == end_; }
    ByteView       view()  const noexcept { return ByteView(data(), size()); }

    /// Drop `bytes` of parsed data from the front — O(1). `bytes` must not exceed
    /// size(). Invalidates views into the consumed region only; the rest of the
    /// live data stays put (this call never moves memory).
    void consume(size_t bytes);

    // ── Maintenance / diagnostics ───────────────────────────────────────────

    /// Move the live bytes to the front, reclaiming the consumed prefix. prepare()
    /// does this on its own when it pays off, so callers rarely need it.
    void compact();

    /// Idle tick: age the remembered demand and shrink if the allocation has outgrown
    /// it. Call this periodically (once per keep-alive tick is plenty) from whatever
    /// already visits the connection on a timer. May reallocate, so — like prepare() —
    /// it invalidates data() and any view into the buffer.
    ///
    /// The traffic-driven shrink in consume() only ever samples when a message
    /// *arrives*, so it cannot reclaim anything from a peer that has gone quiet — and
    /// a peer that sends one big message and then falls silent is exactly the case that
    /// pins a big allocation. This is the other half: it halves the watermark once per
    /// idle tick, so a silent connection halves its buffer every couple of ticks until
    /// it is back at kMinCapacity.
    ///
    /// A tick in which anything at all was received does not age the buffer — the
    /// traffic-driven path already sampled it, and decaying on top of that would shrink
    /// a live connection below its read size just for the next prepare() to grow it
    /// straight back.
    ///
    /// A partial message still being live does *not* stop the tick: a peer that sends
    /// the first slice of a large frame and then stalls never drains the buffer, so
    /// bailing out here would pin its eager allocation for the life of the connection.
    /// The shrink never goes below the live bytes (they are moved to the front), so the
    /// stalled data is kept and only the unused tail is handed back — and it stops once
    /// those bytes fill half the allocation, since below that the tail is worth less
    /// than the memcpy of keeping the data (and the next byte would grow it back).
    void decay();

    /// Drop all data, keep the allocation (e.g. re-using the buffer for a new peer).
    void clear() noexcept;

    /// Release the allocation entirely.
    void reset() noexcept;

    size_t capacity()    const noexcept { return cap_; }
    /// Consumed-but-not-yet-reclaimed bytes at the front.
    size_t front_waste() const noexcept { return start_; }
    /// Running average of recent peak demand; drives the shrink decision.
    size_t watermark()   const noexcept { return watermark_; }

private:
    /// Guarantee `bytes` of writable tail, by compacting or reallocating.
    void   make_room(size_t bytes);
    /// Reallocate upwards, and restart the usage average at the new size.
    void   grow_to(size_t new_capacity);
    /// Reallocate to `new_capacity` (>= live size), moving the live bytes to the front.
    void   reallocate(size_t new_capacity);
    /// Next capacity that holds `needed`: 1.5x growth, floored by kMinCapacity.
    size_t grown_capacity(size_t needed) const noexcept;
    /// Fold the peak demand seen since the last sample into the running average.
    void   sample_usage() noexcept;
    /// Reallocate down when the allocation has outgrown recent demand by over 2x.
    void   maybe_shrink();

    std::unique_ptr<uint8_t[]> buf_;
    size_t cap_       = 0;  ///< allocated bytes
    size_t start_     = 0;  ///< first live byte
    size_t end_       = 0;  ///< one past the last live byte (== write cursor)
    size_t peak_      = 0;  ///< max demand (live bytes, or what prepare() asked for) since the last sample
    size_t watermark_ = 0;  ///< exponential average of peak_ samples
    bool   received_since_decay_ = false;  ///< anything committed since the last decay() tick
};

} // namespace librats
