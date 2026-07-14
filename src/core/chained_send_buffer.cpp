#include "core/chained_send_buffer.h"

#include <algorithm>
#include <cassert>

namespace librats {

ChainedSendBuffer& ChainedSendBuffer::operator=(ChainedSendBuffer&& other) noexcept {
    if (this == &other) return *this;

    // clear() the source rather than relying on the containers' moved-from state: a
    // moved-from vector is only guaranteed *valid*, not empty, and the counters must
    // be zeroed to match whatever it ends up holding.
    chunks_    = std::move(other.chunks_);
    recycled_  = std::move(other.recycled_);
    head_      = std::exchange(other.head_, 0);
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
    if (head_ == chunks_.size()) return nullptr;  // no live chunk to pack into
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
    // Take ownership unconditionally, so a chunk we decline is freed *here* rather
    // than lingering in its (already dead, but not yet swept) slot. pop_front() has
    // just subtracted this chunk's capacity from allocated_, and allocated() is what
    // the send high-water mark watches — leaving the buffer alive until
    // reclaim_drained_slots() gets round to it would let the queue hold up to twice
    // the mark while reporting that it is under it.
    Bytes dead = std::move(chunk);

    // Keep at most one drained chunk, and only a small one: holding on to a piece-
    // sized payload buffer would trade a malloc for permanently resident memory.
    if (dead.capacity() > kMaxRecycledCapacity) return;
    if (dead.capacity() <= recycled_.capacity()) return;

    recycled_ = std::move(dead);
    recycled_.clear();  // keeps the capacity
}

// ── Draining ────────────────────────────────────────────────────────────────

size_t ChainedSendBuffer::gather(ByteView* out, size_t max_slices) const {
    size_t n = 0;
    for (size_t i = head_; i < chunks_.size() && n < max_slices; ++i) {
        const Chunk& chunk = chunks_[i];
        out[n++] = ByteView(chunk.head(), chunk.remaining());
    }
    return n;
}

ByteView ChainedSendBuffer::front() const noexcept {
    if (head_ == chunks_.size()) return {};
    const Chunk& head = chunks_[head_];
    return ByteView(head.head(), head.remaining());
}

void ChainedSendBuffer::pop_front(size_t bytes) {
    assert(bytes <= pending_ && "pop_front() past the queued bytes");

    while (bytes > 0 && head_ < chunks_.size()) {
        Chunk& head = chunks_[head_];
        const size_t left = head.remaining();

        if (bytes < left) {  // chunk partially sent: just advance its cursor
            head.sent += bytes;
            pending_  -= bytes;
            break;  // NOT return — the drained slots behind us still need sweeping
        }

        bytes      -= left;
        pending_   -= left;
        allocated_ -= head.data.capacity();
        recycle(std::move(head.data));
        ++head_;  // the slot stays; reclaim_drained_slots() sweeps it up in bulk
    }
    reclaim_drained_slots();
}

void ChainedSendBuffer::reclaim_drained_slots() {
    if (head_ == 0) return;

    if (head_ == chunks_.size()) {
        // Fully drained — the common case. Rewinding to 0 keeps the vector's storage
        // for the next burst, so a steady drip of messages allocates nothing at all:
        // neither a payload buffer (recycled_) nor a slot to hang it off.
        chunks_.clear();
        head_ = 0;
        if (chunks_.capacity() > kMaxRetainedSlots) {
            chunks_.shrink_to_fit();             // hand back the array a backlog grew
            chunks_.reserve(kMaxRetainedSlots);  // …but not the steady-state working set
        }
        return;
    }

    // A backlog that never fully empties: drop the dead prefix once it is at least
    // half the vector, so the moves are paid for by the slots they retire (amortised
    // O(1) per chunk) rather than run on every pop.
    if (head_ * 2 >= chunks_.size()) {
        chunks_.erase(chunks_.begin(), chunks_.begin() + static_cast<std::ptrdiff_t>(head_));
        head_ = 0;
    }
}

void ChainedSendBuffer::clear() noexcept {
    // swap-with-empty rather than clear()+shrink_to_fit(): constructing an empty
    // vector cannot allocate, so this releases the storage without the throwing
    // reallocation shrink_to_fit() is allowed to perform (this function is noexcept).
    std::vector<Chunk>().swap(chunks_);
    Bytes().swap(recycled_);
    head_      = 0;
    pending_   = 0;
    allocated_ = 0;
}

} // namespace librats
