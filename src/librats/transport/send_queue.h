#pragma once

/**
 * @file send_queue.h
 * @brief Messages waiting for a byte-stream transport, by lane, sealed as they leave.
 *
 * A connection carries every subsystem's traffic at once, and one of them moving a
 * file must not hold up another's ping. So queued messages are not one FIFO but one
 * per *lane* — one per MessageType — and the queue decides at each step which lane
 * goes next:
 *
 *   - lanes of a more urgent Priority always go first (see priority_of);
 *   - lanes of the same priority take turns, one message each, so a subsystem with
 *     a deep backlog cannot starve another one beside it;
 *   - within a lane the order is exactly the order of push().
 *
 * That last line is the whole ordering guarantee a connection gives: messages of
 * one type arrive in the order they were sent; messages of different types may be
 * reordered against each other. A lane is a type and not a (type, channel) pair on
 * purpose: an application's channels are one lane, so everything it sends keeps
 * the order it was sent in — code that sends a "done" on one channel after data on
 * another is entitled to have it arrive last, and did before lanes existed.
 *
 * What makes the scheduling worth anything is *when* a message is sealed. A
 * stream's nonces run in lockstep at both ends, so a message encrypted early can
 * no longer be overtaken — or dropped — without breaking every one behind it. So
 * messages wait here in the clear and are sealed by seal_next() only at the moment
 * the transport is ready to write them, which keeps everything still waiting free
 * to be reordered.
 *
 * Storage is chosen per message size:
 *   - small messages (up to kPackLimit) are packed back to back into shared chunks,
 *     so a stream of chatter allocates nothing in the steady state; on the way out
 *     each is copied into the send buffer and sealed there;
 *   - a large one gets a chunk of its own, laid out as the block it will become —
 *     room for the length prefix in front, room for the tag behind — so it is
 *     sealed where it lies and handed to the send buffer without a copy.
 *
 * Not thread-safe: owned by one transport, on one reactor thread.
 */

#include "librats/core/bytes.h"
#include "librats/core/chained_send_buffer.h"
#include "librats/security/session.h"
#include "librats/wire/frame.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace librats {

/// How urgently a lane's messages should leave, ahead of others on the same
/// connection. Lower values go first.
enum class Priority : uint8_t {
    Control     = 0,  ///< the connection's own plane (identify)
    Interactive = 1,  ///< small and latency-bound: ping, hole-punch rendezvous
    Normal      = 2,  ///< everything else
    Bulk        = 3,  ///< file transfer, which would otherwise crowd the rest out
};
constexpr size_t kPriorityCount = 4;

/// The priority every lane of `type` is scheduled at.
Priority priority_of(MessageType type) noexcept;

class SendQueue {
public:
    /// Messages (header + payload) up to this size are packed together and copied
    /// on the way out; larger ones are sealed in a chunk of their own.
    static constexpr size_t kPackLimit = ChainedSendBuffer::kScratchCapacity;
    /// Bytes in front of each queued message: its size while it waits, its block
    /// length prefix once it leaves.
    static constexpr size_t kRecordHeader = framer::kLengthPrefixSize;
    /// Capacity of a chunk small messages are packed into once a lane has a
    /// backlog: a few dozen of them. A lane with nothing queued starts smaller,
    /// since most of the time it carries one message and is drained the same turn.
    static constexpr size_t kPackChunk      = 4 * 1024;
    static constexpr size_t kFirstPackChunk = kPackLimit + kRecordHeader;
    /// Drained pack chunks kept for re-use, shared by every queue on the thread —
    /// so a steady stream of small messages allocates nothing, while a connection
    /// that has gone quiet holds no spare memory of its own.
    static constexpr size_t kMaxPooledChunks = 4;

    /// Bytes seal() appends — room every large message's chunk keeps behind it.
    /// Set once the session exists, before the first push().
    void set_seal_room(size_t bytes) noexcept { seal_room_ = bytes; }

    /// Queue one message on its lane.
    void push(FrameHeader header, ByteView payload);

    bool   empty()     const noexcept { return count_ == 0; }
    /// Messages queued.
    size_t count()     const noexcept { return count_; }
    /// Bytes queued: header + payload of every message.
    size_t size()      const noexcept { return bytes_; }
    /// Memory the queue holds, spare capacity included — what a backlog mark weighs.
    size_t allocated() const noexcept { return allocated_; }

    /// Frame and seal the next message in scheduling order as one block —
    /// `[u32 length][sealed message]` — onto the end of `out`, under `nonce`.
    /// The queue must not be empty, and `session` must append no more than the
    /// seal room.
    void seal_next(const Session& session, uint64_t nonce, ChainedSendBuffer& out);

private:
    static constexpr uint32_t kNone = UINT32_MAX;

    struct Lane {
        MessageType        type = MessageType::App;
        Priority           priority = Priority::Normal;
        /// Chunks holding this lane's messages, oldest first; live from `head`.
        std::vector<Bytes> chunks;
        size_t             head   = 0;
        size_t             offset = 0;      ///< read position in chunks[head]
        bool               tail_packs = false;  ///< chunks.back() takes small messages
        /// Its place in its priority's ring of lanes with something queued.
        bool               active = false;
        uint32_t           next   = kNone;

        bool empty() const noexcept { return head == chunks.size(); }
    };

    uint32_t lane_for(MessageType type);                ///< its slot in lanes_, made on first use
    uint8_t* reserve_packed(Lane& lane, size_t bytes);  ///< room at the tail of a pack chunk
    void     retire_front(Lane& lane);   ///< drop a drained pack chunk, pooling it for re-use

    void     activate(uint32_t index) noexcept;   ///< append to its priority's ring
    uint32_t next_lane() noexcept;                ///< pop the ring front of the most urgent priority

    /// One per type that has ever queued anything here — a handful, so found by a
    /// scan rather than a map.
    std::vector<Lane>                      lanes_;
    uint32_t                               last_ = kNone;  ///< the lane push() last used
    std::array<uint32_t, kPriorityCount>   ring_head_{kNone, kNone, kNone, kNone};
    std::array<uint32_t, kPriorityCount>   ring_tail_{kNone, kNone, kNone, kNone};
    size_t                                 seal_room_ = 0;
    size_t                                 count_     = 0;
    size_t                                 bytes_     = 0;
    size_t                                 allocated_ = 0;
};

} // namespace librats
