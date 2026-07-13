#pragma once

/**
 * @file chained_send_buffer.h
 * @brief Outbound byte queue: a chain of heap chunks drained with gather I/O.
 *
 * A socket accepts what it accepts; whatever is left over has to wait for the next
 * writable event. Rather than keeping that backlog in one contiguous buffer (where
 * every partial write costs an O(n) erase of the sent prefix, and every message
 * costs a copy into it), the queue is a chain of chunks:
 *
 *      chunks_:  [ sent | pending ] → [ pending ] → [ pending ]
 *                        ^ head_.sent
 *
 *   - pop_front() after a send just advances a cursor and drops whole chunks: O(1)
 *     amortised, no memmove.
 *   - append(Bytes) takes ownership of a buffer someone else already built, so a
 *     message the caller allocated (an encrypted frame, a piece read from disk) is
 *     never copied.
 *   - gather() exposes the chain as a slice list for writev()/WSASend(), so a
 *     backlog of N queued messages leaves in ONE syscall instead of N.
 *
 * Two things keep small messages cheap, since a chunk-per-message would otherwise
 * mean a malloc per 5-byte keep-alive:
 *   - copy-appends are packed into the spare capacity of the tail chunk
 *     (libtorrent's allocate_appendix), so a burst of small messages costs one
 *     allocation, not one per message;
 *   - the last fully-sent small chunk is kept and re-used, so a steady drip of
 *     small messages settles into allocating nothing at all.
 *
 * Memory is accounted two ways: size() is what still has to go out, while
 * allocated() is what the chain actually holds — larger, because a partially sent
 * chunk keeps its whole allocation and a packed chunk keeps its spare room. A
 * send high-water mark should watch allocated(): that is the memory a peer who
 * stops reading can make us carry.
 *
 * Not thread-safe: owned and touched by exactly one reactor thread.
 *
 * Usage:
 *   buf.append(std::move(frame));                       // queue, no copy
 *   ByteView slices[kMaxSendSlices];
 *   const size_t n = buf.gather(slices, kMaxSendSlices);
 *   const auto sent = send_vectored(sock, slices, n);   // one syscall
 *   if (sent > 0) buf.pop_front(size_t(sent));          // O(1)
 */

#include "core/bytes.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>

namespace librats {

class ChainedSendBuffer {
public:
    /// Capacity of a chunk opened for a small copy-append. Sized so a run of
    /// protocol chatter (keep-alives, HAVEs, REQUESTs, ACKs) packs into one.
    static constexpr size_t kScratchCapacity = 1024;

    /// Chunks up to this size are kept for re-use when they drain; larger ones
    /// (payload buffers) are released, so the queue never squats on real memory.
    static constexpr size_t kMaxRecycledCapacity = 4 * 1024;

    ChainedSendBuffer() = default;

    /// Moving leaves the source empty. A defaulted move would carry pending_ and
    /// allocated_ over to a source whose chunks_ had been emptied, leaving it claiming
    /// bytes it no longer holds (empty() false, front() empty — a flush() that never
    /// finishes).
    ChainedSendBuffer(ChainedSendBuffer&& other) noexcept { *this = std::move(other); }
    ChainedSendBuffer& operator=(ChainedSendBuffer&& other) noexcept;
    ChainedSendBuffer(const ChainedSendBuffer&) = delete;
    ChainedSendBuffer& operator=(const ChainedSendBuffer&) = delete;

    // ── Queueing ────────────────────────────────────────────────────────────

    /// Queue `data`, taking ownership — the bytes are never copied. Prefer this for
    /// anything the caller already had to allocate (a framed message, disk block…).
    void append(Bytes data);

    /// Queue a copy of `bytes`. Small copies land in the tail chunk's spare capacity
    /// when they fit, so headers and short control messages don't each cost a malloc.
    void append(ByteView bytes);

    // ── Draining ────────────────────────────────────────────────────────────

    /// Fill `out` with up to `max_slices` contiguous runs covering the front of the
    /// queue, in order. Returns the number of slices written. The views stay valid
    /// until the next pop_front()/clear() (append() never invalidates them).
    size_t gather(ByteView* out, size_t max_slices) const;

    /// The first contiguous run — the single-slice form of gather(), for a plain
    /// send(). Empty when the queue is empty.
    ByteView front() const noexcept;

    /// Drop `bytes` from the front after a successful send. Must not exceed size().
    void pop_front(size_t bytes);

    // ── State ───────────────────────────────────────────────────────────────

    bool   empty()       const noexcept { return pending_ == 0; }
    /// Bytes still waiting to go out — what a send high-water mark should watch.
    size_t size()        const noexcept { return pending_; }
    /// Heap actually held by the chain: pending bytes, the already-sent prefix of a
    /// partially sent chunk, spare capacity, and the recycled chunk.
    size_t allocated()   const noexcept { return allocated_ + recycled_.capacity(); }
    size_t chunk_count() const noexcept { return chunks_.size(); }

    /// Drop everything and release all chunks.
    void clear() noexcept;

private:
    struct Chunk {
        Bytes  data;
        size_t sent = 0;  ///< bytes of `data` already handed to the socket

        size_t         remaining() const noexcept { return data.size() - sent; }
        const uint8_t* head()      const noexcept { return data.data() + sent; }
    };

    /// The tail chunk if `bytes` fit in its spare capacity (so appending to it
    /// cannot reallocate, and therefore cannot invalidate outstanding slices).
    Bytes* coalescable_tail(size_t bytes) noexcept;

    /// A chunk with at least `bytes` of capacity: the recycled one if it fits,
    /// otherwise a fresh allocation.
    Bytes  take_chunk(size_t bytes);

    /// Offer a drained chunk back for re-use.
    void   recycle(Bytes&& chunk) noexcept;

    std::deque<Chunk> chunks_;
    size_t            pending_   = 0;  ///< sum of remaining() over chunks_
    size_t            allocated_ = 0;  ///< sum of data.capacity() over chunks_
    Bytes             recycled_;       ///< one drained small chunk, kept for re-use
};

} // namespace librats
