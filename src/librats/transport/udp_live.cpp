#include "librats/transport/udp_live.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace librats {
namespace udp {

static_assert(kInnerHeaderSize == framer::kHeaderSize, "udp_wire.h's copy of the inner header size");

namespace {

/// Bytes of [lo, hi) that `set` covers.
uint64_t covered(const RangeSet& set, uint64_t lo, uint64_t hi) {
    uint64_t gaps = 0;
    set.for_each_gap(lo, hi, [&](uint64_t a, uint64_t b) { gaps += b - a; });
    return (hi - lo) - gaps;
}

} // namespace

// ── LiveSender ──────────────────────────────────────────────────────────────

void LiveSender::push(FrameHeader header, ByteView payload, Clock::time_point deadline) {
    // The window is full: the oldest message under way gives way to the newest.
    // Its id may not be outrun further, or the receiver would forget it (see the
    // file comment), and of the two the older is the one less worth having.
    while (messages_.size() >= kWindow) {
        if (messages_.front().held) resolve(messages_.front(), /*given_up=*/true);
        settle();
    }

    Message m;
    m.deadline = deadline;
    m.data.reserve(framer::kHeaderSize + payload.size());
    m.data.resize(framer::kHeaderSize);
    framer::encode_header(m.data.data(), header);
    m.data.insert(m.data.end(), payload.begin(), payload.end());
    m.held = true;

    const uint64_t id = base_ + messages_.size();
    unsent_ += m.data.size();
    messages_.push_back(std::move(m));
    ++held_;
    ++sent_;
    enqueue(id, messages_.back());
}

void LiveSender::enqueue(uint64_t id, Message& m) {
    m.queued = true;
    order_.push_back(Entry{m.deadline, id});
    // Usually that is its place already: messages sent with the same lifetime come
    // due in the order they were sent. A shorter lifetime, or a repair of an older
    // message, moves further in.
    const auto later = [](const Entry& a, const Entry& b) {
        return a.deadline > b.deadline || (a.deadline == b.deadline && a.id > b.id);
    };
    for (size_t i = order_.size() - 1; i > 0 && later(order_[i - 1], order_[i]); --i)
        std::swap(order_[i - 1], order_[i]);
}

LiveSender::Message* LiveSender::find(uint64_t id) noexcept {
    if (id < base_ || id - base_ >= messages_.size()) return nullptr;
    Message& m = messages_[static_cast<size_t>(id - base_)];
    return m.held ? &m : nullptr;
}

const LiveSender::Message* LiveSender::find(uint64_t id) const noexcept {
    return const_cast<LiveSender*>(this)->find(id);
}

void LiveSender::resolve(Message& m, bool given_up) {
    unsent_ -= m.data.size() - m.sent;
    lost_   -= m.lost_bytes;
    if (given_up) ++expired_;
    --held_;
    // Freed now rather than when the slot is reused: a ring keeps what it pops.
    m.held       = false;
    m.data       = Bytes();
    m.sent       = 0;
    m.lost_bytes = 0;
    m.lost       = RangeSet();
    m.acked      = RangeSet();
}

void LiveSender::settle() noexcept {
    while (!messages_.empty() && !messages_.front().held) {
        messages_.pop_front();
        ++base_;
    }
    while (!order_.empty()) {
        Message* m = find(order_.front().id);
        if (m && pending(*m)) break;
        if (m) m->queued = false;
        order_.pop_front();
    }
}

void LiveSender::expire(Clock::time_point now, Clock::duration one_way, cc::PacingRate rate) {
    for (;;) {
        settle();
        if (order_.empty() || now + one_way < order_.front().deadline) break;
        resolve(*find(order_.front().id), /*given_up=*/true);
    }
    if (rate.paced() && order_.size() > 1) shed(now, one_way, rate);
}

void LiveSender::shed(Clock::time_point now, Clock::duration one_way, cc::PacingRate rate) {
    const auto waiting = [&](size_t i) -> Message* {
        Message* m = find(order_[i].id);
        return m && pending(*m) ? m : nullptr;   // else a stale entry
    };
    // The last message waiting is never shed: nothing waits for its bytes.
    size_t last = order_.size();
    while (last > 0 && !waiting(last - 1)) --last;
    if (last < 2) return;
    --last;

    uint64_t ahead = 0;   // bytes that leave before the message at i does
    for (size_t i = 0; i < last; ++i) {
        Message* m = waiting(i);
        if (!m) continue;
        const uint64_t owed = (m->data.size() - m->sent) + m->lost_bytes;
        if (m->sent == 0 && now + one_way + rate.time_for(ahead + owed) > m->deadline) {
            resolve(*m, /*given_up=*/true);
            continue;
        }
        ahead += owed;
    }
    settle();
}

std::optional<LiveSender::Clock::time_point> LiveSender::next_expiry(Clock::duration one_way) const noexcept {
    // The front may be stale; then this wakes the connection early, and the
    // expire() that wake-up runs drops it.
    if (order_.empty()) return std::nullopt;
    return order_.front().deadline - one_way;
}

bool LiveSender::peek(Piece& out) noexcept {
    settle();
    if (order_.empty()) return false;
    const Message& m = *find(order_.front().id);
    out.id       = order_.front().id;
    out.size     = static_cast<uint32_t>(m.data.size());
    out.deadline = m.deadline;
    if (m.lost_bytes > 0) {
        out.offset = static_cast<uint32_t>(m.lost.front().first);
        out.len    = static_cast<uint32_t>(m.lost.front().second - m.lost.front().first);
        out.repair = true;
    } else {
        out.offset = m.sent;
        out.len    = out.size - m.sent;
        out.repair = false;
    }
    return true;
}

void LiveSender::take(const Piece& piece, size_t len) {
    Message& m = *find(piece.id);
    if (piece.repair) {
        m.lost.remove(piece.offset, piece.offset + len);
        m.lost_bytes -= static_cast<uint32_t>(len);
        lost_        -= len;
    } else {
        m.sent  += static_cast<uint32_t>(len);
        unsent_ -= len;
    }
}

const uint8_t* LiveSender::bytes(uint64_t id, size_t offset) const noexcept {
    return find(id)->data.data() + offset;
}

bool LiveSender::repeat(uint64_t id, size_t offset, size_t len, Clock::time_point arrival,
                        Piece& out) const noexcept {
    const Message* m = find(id);
    if (!m || arrival >= m->deadline || m->acked.covers(offset, offset + len)) return false;
    out.id       = id;
    out.offset   = static_cast<uint32_t>(offset);
    out.len      = static_cast<uint32_t>(len);
    out.size     = static_cast<uint32_t>(m->data.size());
    out.repair   = true;
    out.deadline = m->deadline;
    return true;
}

void LiveSender::on_acked(uint64_t id, size_t offset, size_t len) {
    Message* m = find(id);
    if (!m) return;
    const uint64_t lo = offset, hi = offset + len;
    // A packet given up on can still be acknowledged late: what of it was waiting
    // to be sent again no longer needs to be.
    if (const uint64_t was_lost = covered(m->lost, lo, hi)) {
        m->lost.remove(lo, hi);
        m->lost_bytes -= static_cast<uint32_t>(was_lost);
        lost_         -= was_lost;
    }
    m->acked.add(lo, hi);
    if (m->acked.covers(0, m->data.size())) {
        resolve(*m, /*given_up=*/false);
        settle();
    }
}

void LiveSender::on_lost(uint64_t id, size_t offset, size_t len) {
    Message* m = find(id);
    if (!m) return;
    // Only what has not arrived by another packet since, and is not already owed.
    uint64_t added = 0;
    m->acked.for_each_gap(offset, offset + len, [&](uint64_t a, uint64_t b) {
        added += (b - a) - covered(m->lost, a, b);
        m->lost.add(a, b);
    });
    if (added == 0) return;
    m->lost_bytes += static_cast<uint32_t>(added);
    lost_         += added;
    // Whether it can still make its deadline is judged when it comes up to be sent.
    if (!m->queued) enqueue(id, *m);
}

void LiveSender::clear() {
    base_    += messages_.size();
    messages_ = RingBuffer<Message>();
    order_    = RingBuffer<Entry>();
    unsent_   = lost_ = 0;
    held_     = 0;
}

void LiveSender::release_memory() noexcept {
    settle();
    messages_.release();
    order_.release();
}

// ── LiveReceiver ────────────────────────────────────────────────────────────

bool LiveReceiver::is_done(uint64_t id) const noexcept {
    if (done_.empty()) return false;
    const uint64_t slot = id % kWindow;
    return (done_[slot / 64] >> (slot % 64)) & 1;
}

void LiveReceiver::mark_done(uint64_t id) {
    if (done_.empty()) done_.assign(kWindow / 64, 0);
    const uint64_t slot = id % kWindow;
    done_[slot / 64] |= uint64_t{1} << (slot % 64);
}

void LiveReceiver::advance(uint64_t floor, HoldAccount& account) {
    // The slots of the ids falling out of the window are the ones the ids coming
    // into it will use.
    if (done_.empty()) {
        // Nothing marked yet: nothing to clear.
    } else if (floor - floor_ >= kWindow) {
        std::fill(done_.begin(), done_.end(), 0);
    } else {
        for (uint64_t id = floor_; id < floor; ++id) {
            const uint64_t slot = id % kWindow;
            done_[slot / 64] &= ~(uint64_t{1} << (slot % 64));
        }
    }
    floor_ = floor;
    for (size_t i = assembling_.size(); i-- > 0;)
        if (assembling_[i].id < floor_) remove(i, account);
}

Bytes LiveReceiver::remove(size_t index, HoldAccount& account) {
    Bytes data = std::move(assembling_[index].data);
    const size_t c = cost(data.size());
    account.release(c);
    assembling_bytes_ -= c;
    if (index + 1 != assembling_.size()) assembling_[index] = std::move(assembling_.back());
    assembling_.pop_back();
    return data;
}

LiveReceiver::Result LiveReceiver::on_frame(const LiveFrame& f, Clock::time_point now,
                                            Clock::duration slack, HoldAccount& account) {
    // Behind the window, or delivered (or given up on) already: a late repair, or
    // a copy a probe sent.
    if (f.id < floor_) return Result::Taken;
    if (f.id - floor_ >= kWindow) advance(f.id - kWindow + 1, account);
    if (is_done(f.id)) return Result::Taken;

    size_t index = assembling_.size();
    for (size_t i = 0; i < assembling_.size(); ++i)
        if (assembling_[i].id == f.id) { index = i; break; }

    if (index == assembling_.size()) {
        if (f.whole()) {
            // The common case — the message fits a packet — goes straight to the
            // inbox, with no assembly and nothing to hold.
            uint8_t len[8];
            const size_t n = static_cast<size_t>(put_varint(len, f.size) - len);
            const ByteSpan into = inbox_.prepare(n + f.data.size());
            std::memcpy(into.data(), len, n);
            std::memcpy(into.data() + n, f.data.data(), f.data.size());
            inbox_.commit(n + f.data.size());
            mark_done(f.id);
            return Result::Taken;
        }
        // The first piece of a larger one: room for all of it, at once.
        const size_t c = cost(static_cast<size_t>(f.size));
        if (assembling_bytes_ + c > kMaxAssembling || !account.charge(c)) return Result::Refused;
        assembling_bytes_ += c;
        const auto lifetime = std::chrono::milliseconds(
            (std::min<uint64_t>)(f.lifetime, static_cast<uint64_t>(SendOptions::kMaxLifetime.count())));
        Assembly a;
        a.id      = f.id;
        a.expires = now + lifetime + slack;
        a.data.resize(static_cast<size_t>(f.size));
        assembling_.push_back(std::move(a));
    } else if (assembling_[index].data.size() != f.size) {
        return Result::Invalid;
    }

    Assembly& a = assembling_[index];
    if (!f.data.empty()) std::memcpy(a.data.data() + f.offset, f.data.data(), f.data.size());
    a.have.add(f.offset, f.offset + f.data.size());
    if (a.have.covers(0, a.data.size())) {
        mark_done(a.id);
        assembled_.push_back(remove(index, account));
    }
    return Result::Taken;
}

void LiveReceiver::expire(Clock::time_point now, HoldAccount& account) {
    // Its sender stopped repairing it a round trip ago: what is missing is not
    // coming. Marked done, so a stray piece arriving later does not start it over.
    for (size_t i = assembling_.size(); i-- > 0;) {
        if (assembling_[i].expires > now) continue;
        mark_done(assembling_[i].id);
        remove(i, account);
    }
}

std::optional<LiveReceiver::Clock::time_point> LiveReceiver::next_expiry() const noexcept {
    std::optional<Clock::time_point> due;
    for (const Assembly& a : assembling_)
        if (!due || a.expires < *due) due = a.expires;
    return due;
}

size_t LiveReceiver::buffered() const noexcept {
    size_t n = inbox_.size() + assembling_bytes_;
    for (size_t i = 0; i < assembled_.size(); ++i) n += assembled_[i].size();
    return n;
}

void LiveReceiver::clear(HoldAccount& account) {
    account.release(assembling_bytes_);
    assembling_.clear();
    assembling_bytes_ = 0;
    inbox_     = ReceiveBuffer();
    assembled_ = RingBuffer<Bytes>();
    ++epoch_;
}

} // namespace udp
} // namespace librats
