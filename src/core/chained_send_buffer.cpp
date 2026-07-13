#include "core/chained_send_buffer.h"

#include <algorithm>
#include <cassert>

namespace librats {

ChainedSendBuffer& ChainedSendBuffer::operator=(ChainedSendBuffer&& other) noexcept {
    if (this == &other) return *this;

    // clear() the source rather than relying on the containers' moved-from state: a
    // moved-from deque/vector is only guaranteed *valid*, not empty, and the counters
    // must be zeroed to match whatever it ends up holding.
    chunks_    = std::move(other.chunks_);
    recycled_  = std::move(other.recycled_);
    pending_   = std::exchange(other.pending_, 0);
    allocated_ = std::exchange(other.allocated_, 0);
    other.clear();
    return *this;
}

// ── Queueing ────────────────────────────────────────────────────────────────

void ChainedSendBuffer::append(Bytes data) {
    if (data.empty()) return;

    pending_   += data.size();
    allocated_ += data.capacity();
    chunks_.push_back(Chunk{std::move(data), 0});
}

void ChainedSendBuffer::append(ByteView bytes) {
    if (bytes.empty()) return;

    // Pack into the tail chunk when it has the room. The capacity check guarantees
    // the insert cannot reallocate, so slices handed out by gather() — including one
    // pointing into this very chunk — stay valid.
    if (Bytes* tail = coalescable_tail(bytes.size())) {
        tail->insert(tail->end(), bytes.begin(), bytes.end());
        pending_ += bytes.size();
        return;
    }

    Bytes chunk = take_chunk(bytes.size());
    chunk.assign(bytes.begin(), bytes.end());
    append(std::move(chunk));
}

Bytes* ChainedSendBuffer::coalescable_tail(size_t bytes) noexcept {
    if (chunks_.empty()) return nullptr;
    Bytes& tail = chunks_.back().data;
    return tail.capacity() - tail.size() >= bytes ? &tail : nullptr;
}

Bytes ChainedSendBuffer::take_chunk(size_t bytes) {
    if (recycled_.capacity() >= bytes) {
        Bytes chunk = std::move(recycled_);
        recycled_ = Bytes{};  // a moved-from vector is only guaranteed *valid*, not empty
        return chunk;
    }

    // A small message opens a chunk with spare room, so the messages behind it can
    // be packed in for free (see coalescable_tail). A large one is sized exactly —
    // padding a payload buffer would only waste memory.
    Bytes chunk;
    chunk.reserve((std::max)(bytes, kScratchCapacity));
    return chunk;
}

void ChainedSendBuffer::recycle(Bytes&& chunk) noexcept {
    // Keep at most one drained chunk, and only a small one: holding on to a piece-
    // sized payload buffer would trade a malloc for permanently resident memory.
    if (chunk.capacity() > kMaxRecycledCapacity) return;
    if (chunk.capacity() <= recycled_.capacity()) return;

    recycled_ = std::move(chunk);
    recycled_.clear();  // keeps the capacity
}

// ── Draining ────────────────────────────────────────────────────────────────

size_t ChainedSendBuffer::gather(ByteView* out, size_t max_slices) const {
    size_t n = 0;
    for (const Chunk& chunk : chunks_) {
        if (n == max_slices) break;
        out[n++] = ByteView(chunk.head(), chunk.remaining());
    }
    return n;
}

ByteView ChainedSendBuffer::front() const noexcept {
    if (chunks_.empty()) return {};
    const Chunk& head = chunks_.front();
    return ByteView(head.head(), head.remaining());
}

void ChainedSendBuffer::pop_front(size_t bytes) {
    assert(bytes <= pending_ && "pop_front() past the queued bytes");

    while (bytes > 0 && !chunks_.empty()) {
        Chunk& head = chunks_.front();
        const size_t left = head.remaining();

        if (bytes < left) {  // chunk partially sent: just advance its cursor
            head.sent += bytes;
            pending_  -= bytes;
            return;
        }

        bytes      -= left;
        pending_   -= left;
        allocated_ -= head.data.capacity();
        recycle(std::move(head.data));
        chunks_.pop_front();
    }
}

void ChainedSendBuffer::clear() noexcept {
    chunks_.clear();
    recycled_  = Bytes{};
    pending_   = 0;
    allocated_ = 0;
}

} // namespace librats
