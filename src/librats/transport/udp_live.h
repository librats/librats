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
 * Messages leave by rank (SendOptions::rank) and, within a rank, nearest deadline
 * first (EDF): a call's sound goes ahead of a keyframe sent before it, however
 * much later its own deadline. Each rank is a queue of its own, by deadline, so
 * what is due to expire is always at the front of one of them.
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
 * On a path that loses packets, a message may be sent with repair symbols behind
 * it (udp_fec.h), so the receiver can rebuild what was lost without asking. How
 * many is the connection's call, made as the message starts (protect()). They go
 * after the data of every message waiting — what is being repaired never holds up
 * what is new — and are not sent once they could only land too late. A loss is
 * still sent again while there is time, since a repair can be lost as well; once
 * there is not, the message is not given up while every block has lost no more
 * symbols (repairs included) than it has repairs — the receiver can still put it
 * together. To the sender a message is delivered once every block has as many
 * of its symbols acknowledged as it has source symbols, whether or not the rest
 * ever arrives.
 *
 * The receiver puts each message together from its pieces and hands it over the
 * moment it is whole, in no order. A message is given up on when the time it had
 * left (plus a round trip of slack) has passed since its first piece came in —
 * the sender stopped repairing it by then — and the memory of what is being put
 * together is charged to the same account a stream's holes are.
 *
 * A message pushed with a tag (SendOptions::tag) leaves word of what became of
 * it — delivered or given up on — once that is settled, for the connection to
 * pass on to whoever sent it. One the connection drops with everything else as
 * it goes away leaves none.
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
#include "librats/transport/udp_fec.h"
#include "librats/transport/udp_streams.h"
#include "librats/transport/udp_wire.h"
#include "librats/wire/frame.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
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

    /// Ranks of messages, the lowest sent first (SendOptions::rank).
    static constexpr size_t kRanks = SendOptions::kLiveRanks;

    /// Queue `header` + `payload` as one live message, worth delivering until
    /// `deadline`, in `rank` (past the last: the last); a nonzero `tag` asks for
    /// its outcome. If kWindow messages are already under way, the oldest is given
    /// up.
    void push(FrameHeader header, ByteView payload, Clock::time_point deadline, uint64_t tag = 0,
              uint8_t rank = 0);

    /// Drop every message with something still to send that can no longer arrive
    /// in time: its deadline is `one_way` or less from `now` — unless all of it is
    /// out and its repair symbols can still stand in for what is missing — and
    /// every repair symbol still to send of such a message. And, if the
    /// connection paces at `rate`, every message not started yet that would leave
    /// too late for that behind the bytes queued ahead of it, unless it is the last
    /// one waiting (see the file comment).
    void expire(Clock::time_point now, Clock::duration one_way, cc::PacingRate rate = {});
    /// When expire() will next drop something, given the same `one_way`; nullopt
    /// when nothing is waiting to be sent.
    std::optional<Clock::time_point> next_expiry(Clock::duration one_way) const noexcept;

    /// What would go next: from the message of the lowest rank whose deadline is
    /// nearest, a repair if it has one, else what it has not sent yet; with nothing
    /// of the kind left, a repair symbol, from the message whose deadline is
    /// nearest whatever its rank. `len` is
    /// all that is available at `offset`; the caller takes what fits — of a repair
    /// symbol, all of it or nothing.
    struct Piece {
        uint64_t          id     = 0;
        uint32_t          offset = 0;
        uint32_t          len    = 0;
        uint32_t          size   = 0;   ///< the whole message
        bool              repair = false;   ///< sent before, and lost
        /// Nothing of the message has been sent and its protection is not settled:
        /// protect() it before taking anything.
        bool              fresh  = false;
        /// Repair symbol `index` (udp_fec.h), `len` bytes.
        bool              parity = false;
        uint32_t          index  = 0;
        /// The message's symbol size if it is protected, else 0. Its pieces are
        /// best cut at multiples of it: then a lost packet costs one symbol.
        uint32_t          symbol = 0;
        Clock::time_point deadline{};
    };
    bool peek(Piece& out) noexcept;
    /// Settle how message `id`, about to start, is protected: `rows` repair symbols
    /// per block of `layout` (whose size is the message's), or none for rows 0.
    void protect(uint64_t id, const fec::Layout& layout, uint32_t rows);
    /// Commit the first `len` bytes of a piece peek() returned (of a repair
    /// symbol, all of it).
    void take(const Piece& piece, size_t len);
    /// The bytes of message `id` from `offset`. The message must still be held.
    const uint8_t* bytes(uint64_t id, size_t offset) const noexcept;
    /// Repair symbol `index` of message `id`. The message must still be held.
    const uint8_t* parity_bytes(uint64_t id, uint32_t index) const noexcept;

    /// Part of a message worth sending again, as a piece — what a probe repeating
    /// an older packet asks for. False unless the message is still held, not all of
    /// [offset, offset + len) has been acknowledged, and a copy that arrives by
    /// `arrival` is still in time.
    bool repeat(uint64_t id, size_t offset, size_t len, Clock::time_point arrival,
                Piece& out) const noexcept;
    /// Likewise for repair symbol `index`: false unless it is still held, not
    /// acknowledged, and a copy that arrives by `arrival` is in time.
    bool repeat_parity(uint64_t id, uint32_t index, Clock::time_point arrival,
                       Piece& out) const noexcept;

    void on_acked(uint64_t id, size_t offset, size_t len);
    void on_lost(uint64_t id, size_t offset, size_t len);
    void on_parity_acked(uint64_t id, uint32_t index);
    void on_parity_lost(uint64_t id, uint32_t index);

    /// Bytes never sent, and bytes waiting to be sent again, of messages still
    /// held: what a new message would wait behind.
    uint64_t unsent()     const noexcept { return unsent_; }
    uint64_t lost_bytes() const noexcept { return lost_; }
    /// Bytes of repair symbols waiting to be sent, which wait behind all of that.
    uint64_t parity_unsent() const noexcept { return parity_; }
    bool     has_pending() const noexcept { return unsent_ + parity_ + lost_ > 0; }
    /// Nothing is held: every message was delivered or given up on.
    bool     empty() const noexcept { return held_ == 0; }

    /// Messages pushed, and messages given up on, since the connection opened.
    uint64_t sent()    const noexcept { return sent_; }
    uint64_t expired() const noexcept { return expired_; }
    /// Of those, the ones given up before a byte of them went.
    uint64_t unstarted() const noexcept { return unstarted_; }
    /// Bytes of the messages pushed since the connection opened, frame headers
    /// included: what OfferedRate is fed.
    uint64_t pushed_bytes() const noexcept { return pushed_bytes_; }
    /// Bytes of repair symbols sent since the connection opened.
    uint64_t parity_sent() const noexcept { return parity_sent_; }

    /// What became of the tagged messages settled since the last take, in the
    /// order they were.
    bool has_outcomes() const noexcept { return !outcomes_.empty(); }
    std::vector<LiveOutcome> take_outcomes() noexcept { return std::exchange(outcomes_, {}); }

    /// Drop everything (the connection is gone), outcomes not yet taken included.
    void clear();
    /// Give back the memory of an empty queue.
    void release_memory() noexcept;

private:
    /// What a symbol has become, as far as the acknowledgements say.
    enum : uint8_t { kOpen, kLost, kAcked };

    /// A protected message's repair symbols, and how its blocks stand.
    struct Coding {
        fec::Layout layout;
        uint32_t    rows = 0;           ///< repair symbols per block
        Bytes       parity;             ///< repair `index` at index * symbol
        uint32_t    next = 0;           ///< repairs below were sent, or never will be
        /// Per source symbol, then per repair symbol.
        std::vector<uint8_t>  state;
        std::vector<uint16_t> acked;    ///< per block: symbols of either kind acknowledged
        std::vector<uint16_t> lost;     ///< per block: symbols of either kind lost
        uint32_t    complete = 0;       ///< blocks with as many acknowledged as they have columns
        /// Source bytes lost, too late to send again, that the repairs stand in for.
        RangeSet    deferred;

        uint32_t repairs() const noexcept { return rows * layout.blocks; }
        bool     has_unsent() const noexcept { return next < repairs(); }
        /// The block has lost more than its repairs can stand in for.
        bool     failed(uint32_t b) const noexcept { return lost[b] > rows; }
        bool     any_failed() const noexcept {
            for (uint32_t b = 0; b < layout.blocks; ++b)
                if (failed(b)) return true;
            return false;
        }
    };
    struct Message {
        Clock::time_point deadline{};
        Bytes    data;              ///< the inner message; empty once resolved
        uint64_t tag        = 0;    ///< its outcome is asked for, under this
        uint8_t  rank       = 0;    ///< below kRanks: which of orders_ it waits in
        uint32_t sent       = 0;    ///< everything below has been sent at least once
        uint32_t lost_bytes = 0;    ///< in `lost`
        RangeSet lost;              ///< to be sent again
        RangeSet acked;
        std::unique_ptr<Coding> coding;   ///< none: not protected
        bool     held    = false;   ///< not yet delivered or given up on
        bool     queued  = false;   ///< has an entry in its rank's order
        bool     decided = false;   ///< protected or not: protect() was called, or it started
    };
    /// A message with something to send, by deadline, in the queue of its rank.
    /// Entries go stale when their message stops having anything to send by other
    /// means (a late acknowledgement) and are dropped as they reach the front.
    struct Entry {
        Clock::time_point deadline{};
        uint64_t          id = 0;
    };

    Message*       find(uint64_t id) noexcept;
    const Message* find(uint64_t id) const noexcept;
    bool           pending(const Message& m) const noexcept { return m.sent < m.data.size() || m.lost_bytes > 0; }
    bool           has_parity(const Message& m) const noexcept { return m.coding && m.coding->has_unsent(); }
    /// As far as the sender can tell, the receiver has all of it, or can rebuild it.
    bool           delivered(const Message& m) const noexcept;
    static void    insert(RingBuffer<Entry>& queue, Entry e);
    void           enqueue(uint64_t id, Message& m);
    /// Owe the parts of [lo, hi) not already owed. Bytes added.
    uint64_t       owe(Message& m, uint64_t lo, uint64_t hi);
    /// Symbol `slot` of `m` (a source symbol's index, or count + a repair's) has
    /// been acknowledged or lost; a block lost past its repairs owes again what it
    /// had been leaving to them.
    void           mark(uint64_t id, Message& m, uint32_t slot, uint8_t to);
    /// Repairs not yet sent will not be: they could only land too late.
    void           drop_parity(uint64_t id, Message& m);
    /// Stop holding `m`: delivered, or given up on — which its outcome says.
    void           resolve(Message& m, bool given_up);
    /// Pop resolved messages off the front, and stale entries off the orders.
    void           settle() noexcept;
    /// The overload half of expire().
    void           shed(Clock::time_point now, Clock::duration one_way, cc::PacingRate rate);
    /// The rank whose front is due first; kRanks when none has anything waiting.
    size_t         first_due() const noexcept;

    /// Message base_ + i is messages_[i].
    RingBuffer<Message> messages_;
    uint64_t            base_ = 0;
    std::array<RingBuffer<Entry>, kRanks> orders_;
    /// Messages with repair symbols still to send, by deadline: what goes once
    /// nothing in orders_ does, whatever its rank. Stale entries as in orders_.
    RingBuffer<Entry>   repairs_;
    uint64_t            unsent_  = 0;
    uint64_t            parity_  = 0;   ///< bytes of repair symbols still to send
    uint64_t            lost_    = 0;
    size_t              held_    = 0;   ///< messages still held
    uint64_t            sent_    = 0;
    uint64_t            pushed_bytes_ = 0;
    uint64_t            expired_ = 0;
    uint64_t            unstarted_ = 0;
    uint64_t            parity_sent_ = 0;
    std::vector<LiveOutcome> outcomes_;
    std::vector<Message*>    shed_scratch_;   ///< shed()'s, kept to spare an allocation
};

/// The rate live messages are handed to a connection at, in bytes per second:
/// what a feed of constant rate asks of the path from its first message, before
/// the congestion controller has found what the path holds
/// (cc::live_floor_window()).
///
/// The connection samples LiveSender::pushed_bytes() whenever it runs — always
/// soon after a push, which it flushes — so neither needs a clock of its own. The
/// rate is over the last kSpan, or since the feed started if that is shorter; the
/// bytes the first sample of a feed finds are not counted, since when they came
/// is not known. A second is long enough that a video's keyframe weighs in as
/// part of its rate rather than as a burst, and short enough that a feed which
/// stopped is forgotten soon: after kSpan with nothing pushed the rate is 0 and
/// whatever comes next starts afresh.
class OfferedRate {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr Clock::duration kSpan = std::chrono::seconds(1);
    /// A feed younger than this has no rate yet: a few messages close together
    /// are no rate to go by.
    static constexpr Clock::duration kMinSpan = std::chrono::milliseconds(10);

    /// `pushed` bytes since the connection opened, as of `now`.
    void sample(Clock::time_point now, uint64_t pushed);

    uint64_t bytes_per_second() const noexcept { return rate_; }

private:
    /// A point is kept every kSpan / kSteps: the window slides that finely.
    static constexpr int kSteps = 8;

    struct Point {
        Clock::time_point at{};
        uint64_t          pushed = 0;
    };

    RingBuffer<Point> points_;   ///< oldest first; the front is where the rate counts from
    Clock::time_point changed_{};   ///< when pushed_ last grew
    uint64_t          pushed_ = 0;
    uint64_t          rate_   = 0;
};

class LiveReceiver {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr uint64_t kWindow = LiveSender::kWindow;
    /// Bytes of messages still being put together that one connection may hold:
    /// two of the largest at once (a keyframe and the frames behind it), whatever
    /// the shared budget has left.
    static constexpr size_t kMaxAssembling = 2 * kMaxLiveMessage;

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
    /// Take one LIVE_REPAIR frame, likewise. What a repair symbol stands in for is
    /// rebuilt the moment there are enough of them.
    Result on_repair(const LiveRepairFrame& frame, Clock::time_point now, Clock::duration slack,
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
    /// A message some repair symbols of which have come in.
    struct Decoding {
        fec::Layout           layout;
        std::vector<uint8_t>  known;     ///< per source symbol: all of it is here
        std::vector<uint16_t> have;      ///< per block: symbols of either kind in hand
        /// Repair symbols held, of blocks not yet whole.
        std::vector<std::pair<uint32_t, Bytes>> repairs;
    };
    struct Assembly {
        uint64_t          id = 0;
        Clock::time_point expires{};
        Bytes             data;
        RangeSet          have;
        size_t            charged = 0;   ///< what the account holds for it
        std::unique_ptr<Decoding> fec;
    };

    bool is_done(uint64_t id) const noexcept;
    void mark_done(uint64_t id);
    /// Forget everything below `floor`: it is past the window.
    void advance(uint64_t floor, HoldAccount& account);
    /// The window's verdict on a frame of message `id`: false if it is behind it, or
    /// done with already.
    bool admit(uint64_t id, HoldAccount& account);
    /// assembling_'s entry for `id`, or its size if there is none.
    size_t find(uint64_t id) const noexcept;
    /// Begin putting together a message of `size` bytes, if there is room for all of
    /// it. Its index, or assembling_.size() if there is not.
    size_t start(uint64_t id, uint64_t size, uint64_t lifetime, Clock::time_point now,
                 Clock::duration slack, HoldAccount& account);
    bool charge(Assembly& a, size_t bytes, HoldAccount& account);
    /// Bytes [lo, hi) of `a` are in: a symbol they complete counts towards its block.
    void note_source(Assembly& a, uint64_t lo, uint64_t hi, HoldAccount& account);
    /// Block `b` of `a` has as many symbols as it has columns: rebuild what it lacks.
    void rebuild(Assembly& a, uint32_t b, HoldAccount& account);
    /// If assembling_[index] is whole, hand it to the inbox.
    void finish(size_t index, HoldAccount& account);
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
