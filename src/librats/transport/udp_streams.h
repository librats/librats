#pragma once

/**
 * @file udp_streams.h
 * @brief The streams of a datagram connection: what is sent, what has arrived.
 *
 * A connection carries one stream per lane — per MessageType, so its id is the
 * type — and each is an ordered run of messages, every one a varint length and
 * the inner message of wire/frame.h. Streams are independent: a hole in one holds
 * up nothing in another, which is the whole reason there are several. Order within
 * a stream is what a lane guarantees; order across streams is not promised.
 *
 * Both halves here are byte-offset bookkeeping and nothing else. Which packet
 * carried what, and whether it arrived, is Recovery's business; a SendStream only
 * hears "these bytes were delivered" or "these were lost" and keeps track of what
 * is still owed. Flow control is the connection's, across all streams together.
 */

#include "librats/core/bytes.h"
#include "librats/core/receive_buffer.h"
#include "librats/core/ring_buffer.h"
#include "librats/transport/udp_wire.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <vector>

namespace librats {
namespace udp {

/// Disjoint, sorted [lo, hi) ranges of stream offsets. Small in practice — one
/// entry per hole — so a sorted vector beats a tree.
class RangeSet {
public:
    bool empty() const noexcept { return ranges_.empty(); }
    size_t size() const noexcept { return ranges_.size(); }
    const std::pair<uint64_t, uint64_t>& front() const noexcept { return ranges_.front(); }

    void add(uint64_t lo, uint64_t hi);
    void remove(uint64_t lo, uint64_t hi);
    void clear() noexcept { ranges_.clear(); }
    /// Whether all of [lo, hi) is in the set.
    bool covers(uint64_t lo, uint64_t hi) const noexcept;
    void pop_front() { ranges_.erase(ranges_.begin()); }

    /// The parts of [lo, hi) NOT in the set, lowest first.
    template <typename Fn>
    void for_each_gap(uint64_t lo, uint64_t hi, Fn&& fn) const {
        auto it = std::upper_bound(ranges_.begin(), ranges_.end(), std::make_pair(lo, UINT64_MAX));
        if (it != ranges_.begin() && std::prev(it)->second > lo) lo = std::prev(it)->second;
        for (; lo < hi && it != ranges_.end() && it->first < hi; ++it) {
            if (it->first > lo) fn(lo, it->first);
            lo = (std::max)(lo, it->second);
        }
        if (lo < hi) fn(lo, hi);
    }

private:
    std::vector<std::pair<uint64_t, uint64_t>> ranges_;
};

/// What every datagram connection on one socket may hold out of order, together.
///
/// A flow-control window is a promise to one peer; this is the bound across all
/// of them. Each window is honest only about what its own peer can make us hold,
/// and a node with thousands of peers — or a few hostile ones each filling their
/// window with nothing but holes — would otherwise hold the sum. Data in order
/// costs nothing here: it is delivered at once.
///
/// What is charged is what is actually held, not what was promised, so an idle
/// connection with a large window costs nothing. A packet that does not fit is
/// not held — the peer sees it as lost, repairs it and backs off, which is the
/// right response to a receiver running out of room. Every connection may hold
/// kGuaranteed whatever the others do, so one greedy peer cannot starve the rest.
class UdpReceiveBudget {
public:
    static constexpr size_t kGuaranteed = 128 * 1024;

    explicit UdpReceiveBudget(size_t limit) noexcept : limit_(limit) {}

    /// Charge `bytes` for a connection already holding `held`. False, and nothing
    /// charged, when it fits neither the connection's guarantee nor the budget.
    bool charge(size_t bytes, size_t held) noexcept {
        if (held + bytes > kGuaranteed && used_ + bytes > limit_) return false;
        used_ += bytes;
        return true;
    }
    void release(size_t bytes) noexcept { used_ -= (std::min)(bytes, used_); }
    /// Whether `bytes` more would still fit — what a window may grow on.
    bool has_room(size_t bytes) const noexcept { return used_ + bytes <= limit_; }

    size_t used()  const noexcept { return used_; }
    size_t limit() const noexcept { return limit_; }

private:
    size_t limit_;
    size_t used_ = 0;
};

/// Where a connection's held bytes are charged: its own count, and the shared
/// budget behind it (none in a test that runs a connection on its own).
struct HoldAccount {
    UdpReceiveBudget* shared = nullptr;
    size_t            held   = 0;

    bool charge(size_t bytes) noexcept {
        if (shared && !shared->charge(bytes, held)) return false;
        held += bytes;
        return true;
    }
    void release(size_t bytes) noexcept {
        held -= (std::min)(bytes, held);
        if (shared) shared->release(bytes);
    }
};

/// The sending half of one stream: every byte written and not yet acknowledged,
/// which of them still has to go (for the first time or again), and which have
/// arrived.
///
/// Bytes live in fixed-size chunks aligned to the stream's offsets, so the chunk
/// holding any offset is found by division; a chunk is handed back the moment
/// everything in it is acknowledged, to a pool shared by every stream on the
/// thread, so a quiet stream holds nothing and a busy one allocates nothing.
class SendStream {
public:
    static constexpr size_t kChunk = 16 * 1024;
    /// Drained chunks kept for re-use per thread.
    static constexpr size_t kMaxPooledChunks = 32;

    SendStream() = default;
    ~SendStream();
    SendStream(const SendStream&) = delete;
    SendStream& operator=(const SendStream&) = delete;
    SendStream(SendStream&&) noexcept = default;
    SendStream& operator=(SendStream&&) noexcept = default;

    /// Append `len` bytes to the stream.
    void write(const uint8_t* data, size_t len);

    /// Bytes written and never sent.
    uint64_t unsent() const noexcept { return end_ - sent_end_; }
    /// Bytes waiting to be sent again.
    uint64_t lost_bytes() const noexcept { return lost_bytes_; }
    bool     has_pending() const noexcept { return lost_bytes_ > 0 || end_ > sent_end_; }
    /// Everything written has been acknowledged.
    bool     flushed() const noexcept { return base_ == end_; }
    /// Memory the chunks hold.
    size_t   allocated() const noexcept { return chunks_.size() * kChunk; }

    /// What would go next: a repair if there is one, else new data — of which at
    /// most `new_budget` bytes may be taken (flow control). `len` is everything
    /// available at `offset`; the caller takes what fits.
    struct Piece {
        uint64_t offset = 0;
        size_t   len    = 0;
        bool     repair = false;
    };
    bool peek(uint64_t new_budget, Piece& out) const noexcept;
    /// Commit the first `len` bytes of a piece peek() returned.
    void take(const Piece& piece, size_t len);

    /// Copy [offset, offset + len) out. Every byte of it must still be held.
    void copy(uint64_t offset, size_t len, uint8_t* out) const noexcept;
    /// Whether any of [offset, offset + len) is still unacknowledged — what a
    /// probe repeating an older packet checks before copying it.
    bool unacked(uint64_t offset, size_t len) const noexcept;

    void on_acked(uint64_t offset, size_t len);
    void on_lost(uint64_t offset, size_t len);

    /// Drop everything (the connection is gone).
    void clear();

private:
    uint8_t* chunk_at(uint64_t offset) noexcept;
    const uint8_t* chunk_at(uint64_t offset) const noexcept;
    void     release_acked_chunks();

    /// Chunk i covers [(first_chunk_ + i) * kChunk, +kChunk). Raw storage, never
    /// zeroed: only bytes that were written are ever read.
    RingBuffer<std::unique_ptr<uint8_t[]>> chunks_;
    uint64_t          first_chunk_ = 0;
    uint64_t          base_     = 0;    ///< everything below is acknowledged
    uint64_t          sent_end_ = 0;    ///< everything below has been sent at least once
    uint64_t          end_      = 0;    ///< everything below has been written
    RangeSet          acked_;           ///< acknowledged, above base_
    RangeSet          lost_;            ///< to be sent again
    uint64_t          lost_bytes_ = 0;
};

/// The receiving half of one stream: bytes put back in order, and the messages
/// they make up.
class RecvStream {
public:
    RecvStream() = default;
    RecvStream(const RecvStream&) = delete;
    RecvStream& operator=(const RecvStream&) = delete;
    RecvStream(RecvStream&&) noexcept = default;
    RecvStream& operator=(RecvStream&&) noexcept = default;

    /// Take `data` at `offset`. Bytes that are the next in order go straight to the
    /// inbox (with whatever was held behind them); the rest are held, charged to
    /// `account`. False when the account refused something — the packet should
    /// then be treated as never received, so the peer sends it again.
    bool on_data(uint64_t offset, ByteView data, HoldAccount& account);

    /// Everything before this offset has arrived.
    uint64_t in_order() const noexcept { return next_; }
    /// One past the highest byte that has arrived — what flow control counts.
    uint64_t highest() const noexcept { return highest_; }
    bool     has_held() const noexcept { return !held_.empty(); }

    /// Hand every complete message in the inbox to `fn(ByteView inner)`, in order,
    /// until it returns false. Returns false when the inbox holds something that is
    /// not a message (a length past `max_message`) — a protocol error.
    template <typename Fn>
    bool deliver(size_t max_message, Fn&& fn, bool& stopped);

    bool has_messages() const noexcept { return !inbox_.empty(); }
    /// Give back an inbox grown by a burst once it has been idle.
    void decay() { inbox_.decay(); }

    /// Drop everything held, releasing it from `account`.
    void clear(HoldAccount& account);

private:
    static size_t held_cost(size_t bytes) noexcept { return bytes + 96; }
    void          append(const uint8_t* data, size_t len);
    void          drain_held(HoldAccount& account);

    uint64_t                  next_    = 0;
    uint64_t                  highest_ = 0;
    std::map<uint64_t, Bytes> held_;    ///< out of order, disjoint, keyed by offset
    ReceiveBuffer             inbox_;   ///< in order, not yet parsed into messages
};

template <typename Fn>
bool RecvStream::deliver(size_t max_message, Fn&& fn, bool& stopped) {
    stopped = false;
    size_t at = 0;
    const uint8_t* data = inbox_.data();
    const size_t   size = inbox_.size();
    bool ok = true;
    while (at < size) {
        Reader r(data + at, size - at);
        uint64_t len = 0;
        if (!r.varint(len)) break;   // the length itself is still arriving
        if (len > max_message) { ok = false; break; }
        const size_t head = size - at - r.left();
        if (r.left() < len) break;   // the message is still arriving
        const bool more = fn(ByteView(data + at + head, static_cast<size_t>(len)));
        at += head + static_cast<size_t>(len);
        // The handler closed the connection from inside the delivery, and the
        // inbox went with it: there is nothing left to walk or to consume.
        if (inbox_.data() != data || inbox_.size() != size) { stopped = true; return ok; }
        if (!more) { stopped = true; break; }
    }
    inbox_.consume(at);
    return ok;
}

} // namespace udp
} // namespace librats
