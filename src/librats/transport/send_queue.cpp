#include "librats/transport/send_queue.h"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace librats {

namespace {

/// Drained pack chunks, shared by every queue on this thread. A queue lives and
/// dies on one reactor thread, so this needs no lock, and pooling per thread
/// rather than per queue is what lets a thousand idle connections hold none.
///
/// Held by pointer: a thread_local with a destructor is not safe on MinGW, whose
/// emutls frees its storage at thread exit before running the destructor on it.
/// The thread empties its own pool instead (SendQueue::release_pooled_chunks).
std::vector<Bytes>*& pool_slot() {
    static thread_local std::vector<Bytes>* pool = nullptr;
    return pool;
}

std::vector<Bytes>& pooled_chunks() {
    std::vector<Bytes>*& pool = pool_slot();
    if (!pool) pool = new std::vector<Bytes>;
    return *pool;
}

/// A pack chunk of at least `capacity`: a pooled one when one is big enough.
Bytes take_pooled_chunk(size_t capacity) {
    auto& pool = pooled_chunks();
    for (size_t i = pool.size(); i-- > 0;) {
        if (pool[i].capacity() < capacity) continue;
        Bytes chunk = std::move(pool[i]);
        pool.erase(pool.begin() + static_cast<std::ptrdiff_t>(i));
        return chunk;
    }
    Bytes chunk;
    chunk.reserve(capacity);
    return chunk;
}

} // namespace

void SendQueue::release_pooled_chunks() {
    std::vector<Bytes>*& pool = pool_slot();
    delete pool;
    pool = nullptr;
}

void SendQueue::push(FrameHeader header, ByteView payload, Deadline deadline, uint64_t tag,
                     uint8_t rank) {
    const bool live = is_live(deadline);
    const uint32_t index = lane_for(header.type, live,
                                    live ? static_cast<uint8_t>((std::min)(size_t{rank}, kLiveRanks - 1)) : 0);
    Lane& lane = lanes_[index];

    const size_t inner = framer::kHeaderSize + payload.size();
    uint8_t* record;
    if (inner <= kPackLimit) {
        record = reserve_packed(lane, kRecordHeader + inner);
    } else {
        // Laid out as the block it will leave as, with the tag's room reserved, so
        // seal_next() can seal it in place and hand the buffer over whole.
        Bytes own;
        own.reserve(kRecordHeader + inner + seal_room_);
        own.resize(kRecordHeader + inner);
        allocated_ += own.capacity();
        lane.chunks.push_back(std::move(own));
        lane.tail_packs = false;
        record = lane.chunks.back().data();
    }

    const uint32_t size = static_cast<uint32_t>(inner);
    std::memcpy(record, &size, sizeof size);
    framer::encode_header(record + kRecordHeader, header);
    if (!payload.empty())
        std::memcpy(record + kRecordHeader + framer::kHeaderSize, payload.data(), payload.size());

    if (live) {
        lane.live_queue.push_back(Lane::Live{deadline, tag});
        ++live_queued_;
        ++live_sent_;
    }
    ++count_;
    bytes_ += inner;
    if (!lane.active) activate(index);
}

bool SendQueue::seal_next(const Session& session, uint64_t nonce, ChainedSendBuffer& out, Deadline now) {
    while (!empty()) {
        const uint32_t index = next_lane();
        Lane& lane = lanes_[index];
        // What can no longer arrive in time goes now, before it costs a nonce and
        // a place on the wire.
        if (lane.live)
            while (!lane.empty() && lane.live_queue.front().deadline <= now) drop_front(lane);
        if (lane.empty()) continue;   // and out of its ring: next_lane() took it off
        seal_front(lane, session, nonce, out);
        // Back of its ring, behind the other lanes of its priority: that is the turn-
        // taking. A lane that is the only one simply comes straight round again.
        if (!lane.empty()) activate(index);
        return true;
    }
    return false;
}

void SendQueue::seal_front(Lane& lane, const Session& session, uint64_t nonce, ChainedSendBuffer& out) {
    Bytes& chunk = lane.chunks[lane.head];
    const uint8_t* record = chunk.data() + lane.offset;

    uint32_t size = 0;
    std::memcpy(&size, record, sizeof size);
    const size_t inner = size;
    const size_t body  = inner + session.overhead();

    if (inner > kPackLimit) {
        // A chunk of its own: seal where it lies, then hand over the buffer.
        Bytes own = std::move(chunk);
        allocated_ -= own.capacity();
        assert(own.capacity() >= kRecordHeader + body && "the session needs more room than set_seal_room() gave");
        own.resize(kRecordHeader + body);
        session.seal(nonce, {}, own.data() + kRecordHeader, inner);
        framer::encode_block_header(own.data(), body);
        out.append(std::move(own));
        next_chunk(lane);
    } else {
        // Packed with others: copied into the send buffer and sealed there.
        uint8_t* block = out.append_slot(kRecordHeader + body);
        framer::encode_block_header(block, body);
        std::memcpy(block + kRecordHeader, record + kRecordHeader, inner);
        session.seal(nonce, {}, block + kRecordHeader, inner);
        lane.offset += kRecordHeader + inner;
        if (lane.offset == chunk.size()) retire_front(lane);
    }

    if (lane.live) settle_live(lane, /*delivered=*/true);
    --count_;
    bytes_ -= inner;
}

void SendQueue::drop_front(Lane& lane) {
    Bytes& chunk = lane.chunks[lane.head];
    uint32_t size = 0;
    std::memcpy(&size, chunk.data() + lane.offset, sizeof size);
    const size_t inner = size;

    if (inner > kPackLimit) {
        allocated_ -= chunk.capacity();
        Bytes().swap(chunk);
        next_chunk(lane);
    } else {
        lane.offset += kRecordHeader + inner;
        if (lane.offset == chunk.size()) retire_front(lane);
    }

    settle_live(lane, /*delivered=*/false);
    ++live_expired_;
    --count_;
    bytes_ -= inner;
}

void SendQueue::settle_live(Lane& lane, bool delivered) {
    const uint64_t tag = lane.live_queue.front().tag;
    if (tag != 0) outcomes_.push_back(LiveOutcome{lane.type, tag, delivered});
    lane.live_queue.pop_front();
    --live_queued_;
}

void SendQueue::next_chunk(Lane& lane) noexcept {
    if (++lane.head == lane.chunks.size()) {
        lane.chunks.clear();
        lane.head = 0;
        lane.tail_packs = false;
    }
}

uint32_t SendQueue::lane_for(MessageType type, bool live, uint8_t rank) {
    const auto is = [&](const Lane& lane) {
        return lane.type == type && lane.live == live && lane.rank == rank;
    };
    // Most pushes go to the lane the previous one did — one subsystem streaming.
    if (last_ != kNone && is(lanes_[last_])) return last_;

    for (uint32_t i = 0; i < lanes_.size(); ++i)
        if (is(lanes_[i])) return last_ = i;

    Lane lane;
    lane.type = type;
    lane.live = live;
    lane.rank = rank;
    // The live ranks sit where Priority::Live is; the priorities after it move up.
    const auto priority = static_cast<size_t>(live ? Priority::Live : priority_of(type));
    lane.schedule_class = static_cast<uint8_t>(
        live ? priority + rank
             : priority > static_cast<size_t>(Priority::Live) ? priority + kLiveRanks - 1 : priority);
    lanes_.push_back(std::move(lane));
    return last_ = static_cast<uint32_t>(lanes_.size() - 1);
}

uint8_t* SendQueue::reserve_packed(Lane& lane, size_t bytes) {
    if (lane.tail_packs) {
        Bytes& tail = lane.chunks.back();
        if (tail.capacity() - tail.size() >= bytes) {
            const size_t at = tail.size();
            tail.resize(at + bytes);   // within capacity: nothing moves
            return tail.data() + at;
        }
    }
    Bytes chunk = take_pooled_chunk(lane.empty() ? kFirstPackChunk : kPackChunk);
    chunk.resize(bytes);
    allocated_ += chunk.capacity();
    lane.chunks.push_back(std::move(chunk));
    lane.tail_packs = true;
    return lane.chunks.back().data();
}

void SendQueue::retire_front(Lane& lane) {
    Bytes& chunk = lane.chunks[lane.head];
    allocated_ -= chunk.capacity();
    auto& pool = pooled_chunks();
    if (pool.size() < kMaxPooledChunks) {
        chunk.clear();   // keeps the capacity
        pool.push_back(std::move(chunk));
    } else {
        Bytes().swap(chunk);
    }
    lane.offset = 0;
    next_chunk(lane);
}

void SendQueue::activate(uint32_t index) noexcept {
    Lane& lane = lanes_[index];
    const size_t p = lane.schedule_class;
    lane.active = true;
    lane.next   = kNone;
    if (ring_tail_[p] == kNone) ring_head_[p] = index;
    else                        lanes_[ring_tail_[p]].next = index;
    ring_tail_[p] = index;
}

uint32_t SendQueue::next_lane() noexcept {
    for (size_t p = 0; p < kClasses; ++p) {
        const uint32_t index = ring_head_[p];
        if (index == kNone) continue;
        Lane& lane = lanes_[index];
        ring_head_[p] = lane.next;
        if (ring_head_[p] == kNone) ring_tail_[p] = kNone;
        lane.next   = kNone;
        lane.active = false;
        return index;
    }
    assert(false && "seal_next() on an empty queue");
    return kNone;
}

} // namespace librats
