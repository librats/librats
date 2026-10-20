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

void LiveSender::push(FrameHeader header, ByteView payload, Clock::time_point deadline, uint64_t tag) {
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
    m.tag  = tag;
    m.held = true;

    const uint64_t id = base_ + messages_.size();
    unsent_ += m.data.size();
    messages_.push_back(std::move(m));
    ++held_;
    ++sent_;
    enqueue(id, messages_.back());
}

void LiveSender::insert(RingBuffer<Entry>& queue, Entry e) {
    queue.push_back(e);
    // Usually that is its place already: messages sent with the same lifetime come
    // due in the order they were sent. A shorter lifetime, or a repair of an older
    // message, moves further in.
    const auto later = [](const Entry& a, const Entry& b) {
        return a.deadline > b.deadline || (a.deadline == b.deadline && a.id > b.id);
    };
    for (size_t i = queue.size() - 1; i > 0 && later(queue[i - 1], queue[i]); --i)
        std::swap(queue[i - 1], queue[i]);
}

void LiveSender::enqueue(uint64_t id, Message& m) {
    m.queued = true;
    insert(order_, Entry{m.deadline, id});
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
    if (m.coding) parity_ -= uint64_t{m.coding->repairs() - m.coding->next} * m.coding->layout.symbol;
    if (given_up) {
        ++expired_;
        if (m.sent == 0) ++unstarted_;
    }
    if (m.tag != 0)
        outcomes_.push_back(LiveOutcome{static_cast<MessageType>(m.data[0]), m.tag, !given_up});
    --held_;
    // Freed now rather than when the slot is reused: a ring keeps what it pops.
    m.held       = false;
    m.data       = Bytes();
    m.sent       = 0;
    m.lost_bytes = 0;
    m.tag        = 0;
    m.lost       = RangeSet();
    m.acked      = RangeSet();
    m.coding.reset();
}

bool LiveSender::delivered(const Message& m) const noexcept {
    if (m.coding) return m.coding->complete == m.coding->layout.blocks;
    return m.acked.covers(0, m.data.size());
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
    // A message enters repairs_ once, when it is protected, and leaves it once
    // it has no repair left to send.
    while (!repairs_.empty()) {
        Message* m = find(repairs_.front().id);
        if (m && has_parity(*m)) break;
        repairs_.pop_front();
    }
}

void LiveSender::expire(Clock::time_point now, Clock::duration one_way, cc::PacingRate rate) {
    for (;;) {
        settle();
        // Repairs first: dropping them can leave their message owing what they
        // were standing in for — and then that is too late as well.
        if (!repairs_.empty() && now + one_way >= repairs_.front().deadline) {
            drop_parity(repairs_.front().id, *find(repairs_.front().id));
            continue;
        }
        if (order_.empty() || now + one_way < order_.front().deadline) break;
        Message& m = *find(order_.front().id);
        // Too late to send again what was lost — but if all of it has gone out and
        // no block has lost more than its repairs, they may still give it back.
        if (m.coding && m.sent == m.data.size() && !m.coding->any_failed()) {
            m.lost.for_each([&](uint64_t lo, uint64_t hi) { m.coding->deferred.add(lo, hi); });
            lost_       -= m.lost_bytes;
            m.lost       = RangeSet();
            m.lost_bytes = 0;
            continue;
        }
        resolve(m, /*given_up=*/true);
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
    std::optional<Clock::time_point> due;
    if (!order_.empty())   due = order_.front().deadline - one_way;
    if (!repairs_.empty()) due = (std::min)(due.value_or((Clock::time_point::max)()), repairs_.front().deadline - one_way);
    return due;
}

bool LiveSender::peek(Piece& out) noexcept {
    settle();
    out = Piece{};
    if (!order_.empty()) {
        const Message& m = *find(order_.front().id);
        out.id       = order_.front().id;
        out.size     = static_cast<uint32_t>(m.data.size());
        out.deadline = m.deadline;
        out.fresh    = !m.decided;
        out.symbol   = m.coding ? m.coding->layout.symbol : 0;
        if (m.lost_bytes > 0) {
            out.offset = static_cast<uint32_t>(m.lost.front().first);
            out.len    = static_cast<uint32_t>(m.lost.front().second - m.lost.front().first);
            out.repair = true;
        } else {
            out.offset = m.sent;
            out.len    = out.size - m.sent;
        }
        return true;
    }
    if (repairs_.empty()) return false;
    const Message& m = *find(repairs_.front().id);
    out.id       = repairs_.front().id;
    out.size     = static_cast<uint32_t>(m.data.size());
    out.deadline = m.deadline;
    out.parity   = true;
    out.index    = m.coding->next;
    out.symbol   = m.coding->layout.symbol;
    out.len      = out.symbol;
    return true;
}

void LiveSender::protect(uint64_t id, const fec::Layout& layout, uint32_t rows) {
    Message* m = find(id);
    if (!m || m->decided) return;
    m->decided = true;
    if (rows == 0) return;
    auto c = std::make_unique<Coding>();
    c->layout = layout;
    c->rows   = rows;
    c->parity.resize(size_t{c->repairs()} * layout.symbol);
    fec::encode(layout, m->data.data(), rows, c->parity.data());
    c->state.assign(layout.count + c->repairs(), kOpen);
    c->acked.assign(layout.blocks, 0);
    c->lost.assign(layout.blocks, 0);
    parity_ += c->parity.size();
    m->coding = std::move(c);
    insert(repairs_, Entry{m->deadline, id});
}

void LiveSender::take(const Piece& piece, size_t len) {
    Message& m = *find(piece.id);
    m.decided = true;   // started: unprotected, if protect() was not asked
    if (piece.parity) {
        ++m.coding->next;
        parity_      -= piece.len;
        parity_sent_ += piece.len;
    } else if (piece.repair) {
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

const uint8_t* LiveSender::parity_bytes(uint64_t id, uint32_t index) const noexcept {
    const Coding& c = *find(id)->coding;
    return c.parity.data() + size_t{index} * c.layout.symbol;
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

bool LiveSender::repeat_parity(uint64_t id, uint32_t index, Clock::time_point arrival,
                               Piece& out) const noexcept {
    const Message* m = find(id);
    if (!m || !m->coding || arrival >= m->deadline || index >= m->coding->next ||
        m->coding->state[m->coding->layout.count + index] == kAcked)
        return false;
    out          = Piece{};
    out.id       = id;
    out.size     = static_cast<uint32_t>(m->data.size());
    out.parity   = true;
    out.index    = index;
    out.symbol   = m->coding->layout.symbol;
    out.len      = out.symbol;
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
    if (m->coding) {
        Coding& c = *m->coding;
        const fec::Layout& l = c.layout;
        c.deferred.remove(lo, hi);
        for (uint32_t j = static_cast<uint32_t>(lo / l.symbol); j < l.count && l.offset(j) < hi; ++j)
            if (m->acked.covers(l.offset(j), l.offset(j) + l.length(j))) mark(id, *m, j, kAcked);
    }
    if (delivered(*m)) {
        resolve(*m, /*given_up=*/false);
        settle();
    }
}

uint64_t LiveSender::owe(Message& m, uint64_t lo, uint64_t hi) {
    const uint64_t added = (hi - lo) - covered(m.lost, lo, hi);
    if (added == 0) return 0;
    m.lost.add(lo, hi);
    m.lost_bytes += static_cast<uint32_t>(added);
    lost_        += added;
    return added;
}

void LiveSender::on_lost(uint64_t id, size_t offset, size_t len) {
    Message* m = find(id);
    if (!m) return;
    // Only what has not arrived by another packet since, and is not already owed.
    uint64_t added = 0;
    m->acked.for_each_gap(offset, offset + len, [&](uint64_t a, uint64_t b) {
        // Sent again even if the repairs may stand in for it: they may be lost too,
        // and the loss of the last of them is the slowest to come to light.
        added += owe(*m, a, b);
        if (!m->coding) return;
        const fec::Layout& l = m->coding->layout;
        for (uint32_t j = static_cast<uint32_t>(a / l.symbol); j < l.count && l.offset(j) < b; ++j)
            mark(id, *m, j, kLost);
    });
    // Whether it can still make its deadline is judged when it comes up to be sent.
    if (added > 0 && !m->queued) enqueue(id, *m);
}

void LiveSender::on_parity_acked(uint64_t id, uint32_t index) {
    Message* m = find(id);
    if (!m || !m->coding) return;
    mark(id, *m, m->coding->layout.count + index, kAcked);
    if (delivered(*m)) {
        resolve(*m, /*given_up=*/false);
        settle();
    }
}

void LiveSender::on_parity_lost(uint64_t id, uint32_t index) {
    Message* m = find(id);
    if (m && m->coding) mark(id, *m, m->coding->layout.count + index, kLost);
}

void LiveSender::mark(uint64_t id, Message& m, uint32_t slot, uint8_t to) {
    Coding& c = *m.coding;
    const fec::Layout& l = c.layout;
    uint8_t& state = c.state[slot];
    if (state == kAcked || state == to) return;
    const uint32_t b = slot < l.count ? l.block_of(slot) : (slot - l.count) % l.blocks;
    if (state == kLost) --c.lost[b];
    state = to;
    if (to == kAcked) {
        if (++c.acked[b] == l.columns(b)) ++c.complete;
        return;
    }
    if (++c.lost[b] != c.rows + 1) return;
    // The block has just lost one more than its repairs can stand in for: what it
    // was leaving to them is owed again — to be given up on, as it is too late.
    std::vector<std::pair<uint64_t, uint64_t>> parts;
    c.deferred.for_each([&](uint64_t lo, uint64_t hi) {
        for (uint32_t j = static_cast<uint32_t>(lo / l.symbol); j < l.count && l.offset(j) < hi; ++j)
            if (l.block_of(j) == b)
                parts.emplace_back((std::max<uint64_t>)(lo, l.offset(j)),
                                   (std::min<uint64_t>)(hi, l.offset(j) + l.length(j)));
    });
    uint64_t added = 0;
    for (const auto& [lo, hi] : parts) {
        c.deferred.remove(lo, hi);
        added += owe(m, lo, hi);
    }
    if (added > 0 && !m.queued) enqueue(id, m);
}

void LiveSender::drop_parity(uint64_t id, Message& m) {
    Coding& c = *m.coding;
    const uint32_t from = c.next;
    parity_ -= uint64_t{c.repairs() - from} * c.layout.symbol;
    c.next = c.repairs();
    for (uint32_t r = from; r < c.repairs(); ++r) mark(id, m, c.layout.count + r, kLost);
}

void LiveSender::clear() {
    base_    += messages_.size();
    messages_ = RingBuffer<Message>();
    order_    = RingBuffer<Entry>();
    repairs_  = RingBuffer<Entry>();
    unsent_   = parity_ = lost_ = 0;
    held_     = 0;
    outcomes_.clear();
}

void LiveSender::release_memory() noexcept {
    settle();
    messages_.release();
    order_.release();
    repairs_.release();
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
    account.release(assembling_[index].charged);
    assembling_bytes_ -= assembling_[index].charged;
    if (index + 1 != assembling_.size()) assembling_[index] = std::move(assembling_.back());
    assembling_.pop_back();
    return data;
}

bool LiveReceiver::admit(uint64_t id, HoldAccount& account) {
    // Behind the window, or delivered (or given up on) already: a late repair, or
    // a copy a probe sent.
    if (id < floor_) return false;
    if (id - floor_ >= kWindow) advance(id - kWindow + 1, account);
    return !is_done(id);
}

size_t LiveReceiver::find(uint64_t id) const noexcept {
    for (size_t i = 0; i < assembling_.size(); ++i)
        if (assembling_[i].id == id) return i;
    return assembling_.size();
}

bool LiveReceiver::charge(Assembly& a, size_t bytes, HoldAccount& account) {
    if (assembling_bytes_ + bytes > kMaxAssembling || !account.charge(bytes)) return false;
    assembling_bytes_ += bytes;
    a.charged         += bytes;
    return true;
}

size_t LiveReceiver::start(uint64_t id, uint64_t size, uint64_t lifetime, Clock::time_point now,
                           Clock::duration slack, HoldAccount& account) {
    // Room for all of it, at once.
    Assembly a;
    if (!charge(a, cost(static_cast<size_t>(size)), account)) return assembling_.size();
    a.id      = id;
    a.expires = now + std::chrono::milliseconds((std::min<uint64_t>)(
                    lifetime, static_cast<uint64_t>(SendOptions::kMaxLifetime.count()))) + slack;
    a.data.resize(static_cast<size_t>(size));
    assembling_.push_back(std::move(a));
    return assembling_.size() - 1;
}

void LiveReceiver::finish(size_t index, HoldAccount& account) {
    Assembly& a = assembling_[index];
    if (!a.have.covers(0, a.data.size())) return;
    mark_done(a.id);
    assembled_.push_back(remove(index, account));
}

LiveReceiver::Result LiveReceiver::on_frame(const LiveFrame& f, Clock::time_point now,
                                            Clock::duration slack, HoldAccount& account) {
    if (!admit(f.id, account)) return Result::Taken;

    size_t index = find(f.id);
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
        index = start(f.id, f.size, f.lifetime, now, slack, account);
        if (index == assembling_.size()) return Result::Refused;
    } else if (assembling_[index].data.size() != f.size) {
        return Result::Invalid;
    }

    Assembly& a = assembling_[index];
    if (!f.data.empty()) std::memcpy(a.data.data() + f.offset, f.data.data(), f.data.size());
    a.have.add(f.offset, f.offset + f.data.size());
    if (a.fec) note_source(a, f.offset, f.offset + f.data.size(), account);
    finish(index, account);
    return Result::Taken;
}

LiveReceiver::Result LiveReceiver::on_repair(const LiveRepairFrame& f, Clock::time_point now,
                                             Clock::duration slack, HoldAccount& account) {
    if (!admit(f.id, account)) return Result::Taken;
    const fec::Layout layout(static_cast<uint32_t>(f.size), static_cast<uint32_t>(f.symbol));
    if (f.index >= uint64_t{layout.blocks} * fec::kMaxRows) return Result::Invalid;
    const uint32_t index = static_cast<uint32_t>(f.index);

    size_t at = find(f.id);
    if (at == assembling_.size()) {
        at = start(f.id, f.size, f.lifetime, now, slack, account);
        if (at == assembling_.size()) return Result::Refused;
    } else if (assembling_[at].data.size() != f.size ||
               (assembling_[at].fec && assembling_[at].fec->layout.symbol != f.symbol)) {
        return Result::Invalid;
    }
    Assembly& a = assembling_[at];
    if (!a.fec) {
        // The first repair symbol: which source symbols are here already is
        // counted once, and kept up as pieces come in.
        auto d = std::make_unique<Decoding>();
        d->layout = layout;
        d->known.assign(layout.count, 0);
        d->have.assign(layout.blocks, 0);
        for (uint32_t j = 0; j < layout.count; ++j)
            if (a.have.covers(layout.offset(j), layout.offset(j) + layout.length(j))) {
                d->known[j] = 1;
                ++d->have[layout.block_of(j)];
            }
        a.fec = std::move(d);
    }
    Decoding& d = *a.fec;
    const uint32_t b = index % layout.blocks;
    if (d.have[b] >= layout.columns(b)) return Result::Taken;   // nothing it could add
    for (const auto& r : d.repairs)
        if (r.first == index) return Result::Taken;            // a copy
    if (!charge(a, cost(f.data.size()), account)) return Result::Refused;
    d.repairs.emplace_back(index, Bytes(f.data.begin(), f.data.end()));
    if (++d.have[b] == layout.columns(b)) rebuild(a, b, account);
    finish(at, account);
    return Result::Taken;
}

void LiveReceiver::note_source(Assembly& a, uint64_t lo, uint64_t hi, HoldAccount& account) {
    Decoding& d = *a.fec;
    const fec::Layout& l = d.layout;
    for (uint32_t j = static_cast<uint32_t>(lo / l.symbol); j < l.count && l.offset(j) < hi; ++j) {
        if (d.known[j] || !a.have.covers(l.offset(j), l.offset(j) + l.length(j))) continue;
        d.known[j] = 1;
        const uint32_t b = l.block_of(j);
        if (++d.have[b] == l.columns(b)) rebuild(a, b, account);
    }
}

void LiveReceiver::rebuild(Assembly& a, uint32_t b, HoldAccount& account) {
    Decoding& d = *a.fec;
    const fec::Layout& l = d.layout;
    std::vector<fec::Repair> use;
    for (const auto& r : d.repairs)
        if (r.first % l.blocks == b) use.push_back(fec::Repair{r.first, r.second.data()});
    // As many symbols as columns in hand: the repairs are exactly enough for what
    // is missing, which the code always gives back.
    fec::recover(l, b, a.data.data(), d.known.data(), use.data(), use.size());
    for (uint32_t c = 0; c < l.columns(b); ++c) {
        const uint32_t j = c * l.blocks + b;
        if (d.known[j]) continue;
        d.known[j] = 1;
        a.have.add(l.offset(j), l.offset(j) + l.length(j));
    }
    // The block's repairs have done their work.
    for (size_t i = d.repairs.size(); i-- > 0;) {
        if (d.repairs[i].first % l.blocks != b) continue;
        const size_t c = cost(d.repairs[i].second.size());
        account.release(c);
        assembling_bytes_ -= c;
        a.charged         -= c;
        d.repairs[i] = std::move(d.repairs.back());
        d.repairs.pop_back();
    }
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
