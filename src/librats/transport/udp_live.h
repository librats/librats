#pragma once

/**
 * @file udp_live.h
 * @brief Live messages on a datagram connection: repaired while they can still be on time.
 *
 * A live message (SendOptions::lifetime) is worth delivering only until its
 * deadline. It does not travel on a stream — a stream delivers in order, and in
 * order is exactly what holds a fresh video frame behind a stale one — but as
 * LIVE frames of its own (udp_wire.h): each names the message, the piece of it
 * it carries, and how long the message has left.
 *
 * The sender keeps a message until it is acknowledged whole or can no longer
 * arrive in time, and repairs what the path loses meanwhile. "In time" is judged
 * whenever there is something of it still to send: a message whose deadline is
 * nearer than the one-way delay the round trip suggests is dropped, whole — what
 * was never sent and what was waiting for a repair alike. So the queue in front of
 * the path never holds anything stale, which is what lets the fresh frame through
 * right after an outage instead of a second's worth of old ones.
 *
 * A source asking for more than the path carries needs one more judgement, or
 * every message misses: each waits its turn until it is nearly due, starts,
 * and runs out of time half sent (EDF's domino effect under overload). So a
 * message that has not started yet, and cannot *leave* in time behind what is
 * queued ahead of it at the rate the connection paces at, is dropped before it
 * costs anything — but only while another message waits behind it, which is
 * what it would be dropped for. A message alone, or one already started, is
 * left to make its deadline or miss it: the pacing rate of a flow that sends
 * less than the path holds is a floor, not the path, and dropping by it alone
 * keeps such a flow sending less — on a long path, at the start, it starves the
 * very measurement that would raise it.
 *
 * The receiver puts each message together from its pieces and hands it over the
 * moment it is whole, in no order. A message is given up on when the time it had
 * left (plus a round trip of slack) has passed since its first piece came in —
 * the sender stopped repairing it by then — and the memory of what is being put
 * together is charged to the same account a stream's holes are.
 *
 * Message ids count up from 0 on each connection, and both ends agree on a window
 * of them: the sender never sends an id kWindow or more past the oldest message
 * it is still trying to deliver, so the receiver may forget everything kWindow
 * behind the newest id it has seen. That is what bounds the receiver's memory of
 * which ids it has already delivered, without which a late repair of a delivered
 * message would deliver it twice.
 *
 * Like everything on this path these hold no locks and never read the clock.
 */

#include "librats/core/bytes.h"
#include "librats/core/receive_buffer.h"
#include "librats/core/ring_buffer.h"
#include "librats/transport/congestion_control.h"
#include "librats/transport/udp_streams.h"
#include "librats/transport/udp_wire.h"
#include "librats/wire/frame.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace librats {
namespace udp {

class LiveSender {
public:
    using Clock = std::chrono::steady_clock;

    /// Ids the sender may have under way at once (see the file comment).
    static constexpr uint64_t kWindow = 1024;

    LiveSender() = default;
    LiveSender(const LiveSender&) = delete;
    LiveSender& operator=(const LiveSender&) = delete;

    /// Queue `header` + `payload` as one live message, worth delivering until
    /// `deadline`. If kWindow messages are already under way, the oldest is given up.
    void push(FrameHeader header, ByteView payload, Clock::time_point deadline);

    /// Drop every message with something still to send that can no longer arrive
    /// in time: its deadline is `one_way` or less from `now`. And, if the
    /// connection paces at `rate`, every message not started yet that would leave
    /// too late for that behind the bytes queued ahead of it, unless it is the last
    /// one waiting (see the file comment).
    void expire(Clock::time_point now, Clock::duration one_way, cc::PacingRate rate = {});
    /// When expire() will next drop something, given the same `one_way`; nullopt
    /// when nothing is waiting to be sent.
    std::optional<Clock::time_point> next_expiry(Clock::duration one_way) const noexcept;

    /// What would go next: from the message whose deadline is nearest, a repair if
    /// it has one, else what it has not sent yet. `len` is all that is available at
    /// `offset`; the caller takes what fits.
    struct Piece {
        uint64_t          id     = 0;
        uint32_t          offset = 0;
        uint32_t          len    = 0;
        uint32_t          size   = 0;   ///< the whole message
        bool              repair = false;
        Clock::time_point deadline{};
    };
    bool peek(Piece& out) noexcept;
    /// Commit the first `len` bytes of a piece peek() returned.
    void take(const Piece& piece, size_t len);
    /// The bytes of message `id` from `offset`. The message must still be held.
    const uint8_t* bytes(uint64_t id, size_t offset) const noexcept;

    /// Part of a message worth sending again, as a piece — what a probe repeating
    /// an older packet asks for. False unless the message is still held, not all of
    /// [offset, offset + len) has been acknowledged, and a copy that arrives by
    /// `arrival` is still in time.
    bool repeat(uint64_t id, size_t offset, size_t len, Clock::time_point arrival,
                Piece& out) const noexcept;

    void on_acked(uint64_t id, size_t offset, size_t len);
    void on_lost(uint64_t id, size_t offset, size_t len);

    /// Bytes never sent, and bytes waiting to be sent again, of messages still held.
    uint64_t unsent()     const noexcept { return unsent_; }
    uint64_t lost_bytes() const noexcept { return lost_; }
    bool     has_pending() const noexcept { return unsent_ + lost_ > 0; }
    /// Nothing is held: every message was delivered or given up on.
    bool     empty() const noexcept { return held_ == 0; }

    /// Messages pushed, and messages given up on, since the connection opened.
    uint64_t sent()    const noexcept { return sent_; }
    uint64_t expired() const noexcept { return expired_; }

    /// Drop everything (the connection is gone).
    void clear();
    /// Give back the memory of an empty queue.
    void release_memory() noexcept;

private:
    struct Message {
        Clock::time_point deadline{};
        Bytes    data;              ///< the inner message; empty once resolved
        uint32_t sent       = 0;    ///< everything below has been sent at least once
        uint32_t lost_bytes = 0;    ///< in `lost`
        RangeSet lost;              ///< to be sent again
        RangeSet acked;
        bool     held   = false;    ///< not yet delivered or given up on
        bool     queued = false;    ///< has an entry in order_
    };
    /// A message with something to send, by deadline. Entries go stale when their
    /// message stops having anything to send by other means (a late acknowledgement)
    /// and are dropped as they reach the front.
    struct Entry {
        Clock::time_point deadline{};
        uint64_t          id = 0;
    };

    Message*       find(uint64_t id) noexcept;
    const Message* find(uint64_t id) const noexcept;
    bool           pending(const Message& m) const noexcept { return m.sent < m.data.size() || m.lost_bytes > 0; }
    void           enqueue(uint64_t id, Message& m);
    /// Stop holding `m`: delivered, or given up on.
    void           resolve(Message& m, bool given_up);
    /// Pop resolved messages off the front, and stale entries off the order.
    void           settle() noexcept;
    /// The overload half of expire().
    void           shed(Clock::time_point now, Clock::duration one_way, cc::PacingRate rate);

    /// Message base_ + i is messages_[i].
    RingBuffer<Message> messages_;
    uint64_t            base_ = 0;
    RingBuffer<Entry>   order_;
    uint64_t            unsent_  = 0;
    uint64_t            lost_    = 0;
    size_t              held_    = 0;   ///< messages still held
    uint64_t            sent_    = 0;
    uint64_t            expired_ = 0;
};

class LiveReceiver {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr uint64_t kWindow = LiveSender::kWindow;
    /// Bytes of messages still being put together that one connection may hold:
    /// a few of the largest at once, whatever the shared budget has left.
    static constexpr size_t kMaxAssembling = 4 * kMaxLiveMessage;

    enum class Result {
        Taken,     ///< kept, delivered, or already had
        Refused,   ///< no room to hold it: treat the packet as never received
        Invalid,   ///< contradicts an earlier piece of the same message
    };

    LiveReceiver() = default;
    LiveReceiver(const LiveReceiver&) = delete;
    LiveReceiver& operator=(const LiveReceiver&) = delete;

    /// Take one LIVE frame, charging what is held to `account`. A message still
    /// incomplete is given up on its lifetime plus `slack` from now.
    Result on_frame(const LiveFrame& frame, Clock::time_point now, Clock::duration slack,
                    HoldAccount& account);

    /// Give up on what has outlived its message's lifetime.
    void expire(Clock::time_point now, HoldAccount& account);
    std::optional<Clock::time_point> next_expiry() const noexcept;

    bool   has_messages() const noexcept { return !inbox_.empty() || !assembled_.empty(); }
    /// Bytes held: messages complete and not yet delivered, and those being put together.
    size_t buffered() const noexcept;

    /// Hand every complete message to `fn(ByteView inner)`, until it returns false.
    /// `stopped` says the walk ended early — `fn` said so, or closed the
    /// connection, which cleared what it was walking.
    template <typename Fn>
    void deliver(Fn&& fn, bool& stopped);

    /// Drop everything, releasing it from `account`.
    void clear(HoldAccount& account);
    /// Give back an inbox grown by a burst once it has been idle.
    void decay() { inbox_.decay(); }

private:
    struct Assembly {
        uint64_t          id = 0;
        Clock::time_point expires{};
        Bytes             data;
        RangeSet          have;
    };

    bool is_done(uint64_t id) const noexcept;
    void mark_done(uint64_t id);
    /// Forget everything below `floor`: it is past the window.
    void advance(uint64_t floor, HoldAccount& account);
    /// Take assembling_[index] out, releasing what it was charged.
    Bytes remove(size_t index, HoldAccount& account);
    static size_t cost(size_t bytes) noexcept { return bytes + 96; }

    /// Every id below floor_ is done with; above it, done_ has a bit per id —
    /// made with the first live message, so a connection that never carries one
    /// does not hold it.
    uint64_t                     floor_ = 0;
    std::vector<uint64_t>        done_;
    std::vector<Assembly>        assembling_;   ///< a few at most: scanned, not mapped
    size_t                       assembling_bytes_ = 0;
    /// Messages that came in one frame, as [varint length][message], back to back.
    ReceiveBuffer                inbox_;
    RingBuffer<Bytes>            assembled_;    ///< put together from pieces
    uint64_t                     epoch_ = 0;    ///< bumped by clear()
};

template <typename Fn>
void LiveReceiver::deliver(Fn&& fn, bool& stopped) {
    stopped = false;
    const uint64_t epoch = epoch_;
    size_t at = 0;
    while (at < inbox_.size()) {
        Reader r(inbox_.data() + at, inbox_.size() - at);
        uint64_t len = 0;
        r.varint(len);   // written by on_frame: always whole
        const size_t head = inbox_.size() - at - r.left();
        const bool more = fn(ByteView(inbox_.data() + at + head, static_cast<size_t>(len)));
        if (epoch_ != epoch) { stopped = true; return; }   // cleared under us
        at += head + static_cast<size_t>(len);
        if (!more) { stopped = true; break; }
    }
    inbox_.consume(at);
    if (stopped) return;
    while (!assembled_.empty()) {
        Bytes message = std::move(assembled_.front());
        assembled_.pop_front();
        const bool more = fn(ByteView(message));
        if (epoch_ != epoch || !more) { stopped = true; return; }
    }
}

} // namespace udp
} // namespace librats
