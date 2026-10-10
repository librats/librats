#include "librats/transport/udp_stream.h"
#include "librats/core/io_poller.h"   // PollIn / PollOut / PollErr
#include "librats/util/logger.h"

#include <algorithm>
#include <cstring>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace librats {

namespace {

using Clock = UdpStream::Clock;

/// Sentinel for "no delayed ack is armed".
constexpr Clock::time_point kNoDeadline{};

template <typename A, typename B>
Clock::duration clamp_duration(Clock::duration v, A lo, B hi) {
    const auto low  = std::chrono::duration_cast<Clock::duration>(lo);
    const auto high = std::chrono::duration_cast<Clock::duration>(hi);
    return v < low ? low : (v > high ? high : v);
}

/// Heap order for UdpStream::lost_: the lowest sequence number on top.
struct LaterSeq {
    bool operator()(uint32_t a, uint32_t b) const noexcept { return rudp::seq_less(b, a); }
};

/// Index of the highest set bit of a non-zero word.
int highest_bit(uint64_t v) noexcept {
#if defined(_MSC_VER)
    unsigned long i = 0;
    if (_BitScanReverse(&i, static_cast<unsigned long>(v >> 32))) return static_cast<int>(i) + 32;
    _BitScanReverse(&i, static_cast<unsigned long>(v));
    return static_cast<int>(i);
#else
    return 63 - __builtin_clzll(v);
#endif
}

} // namespace

UdpStream::UdpStream(UdpStreamHost& host, const Address& remote, uint32_t recv_id,
                     uint32_t send_id, ConnRole role, Clock::time_point now,
                     DialProfile profile, CongestionAlgorithm algorithm,
                     UdpReceiveConfig receive)
    : host_(host), remote_(remote), recv_id_(recv_id), send_id_(send_id), role_(role),
      state_(role == ConnRole::Outbound ? State::SynSent : State::Connected),
      last_recv_(now), last_send_(now) {
    // The receive window, settled before anything is sent: the Syn already carries
    // the limit it implies.
    max_window_     = (std::min)((std::max)(receive.max_window, kMinWindowPackets),
                                 rudp::kMaxWindowPackets);
    initial_window_ = (std::min)(rudp::kInitialWindowPackets, max_window_);
    window_         = initial_window_;
    budget_         = receive.budget;
    recv_limit_     = (recv_next_ - 1) + window_;

    pace_last_   = now;
    pace_tokens_ = kPaceMinBurst;   // nothing to pace against until the first RTT sample
    rtt_.rto     = kInitialRto;
    // Seeded by the connection ids, so a stream's randomised choices (BBR's probe
    // schedule) are reproducible for a given pair and differ between pairs.
    cc_ = cc::make_controller(algorithm, rtt_, sampler_, now,
                              (static_cast<uint64_t>(recv_id) << 32) | send_id);

    if (role_ != ConnRole::Outbound) return;

    // The dial's own retry shape (see DialProfile). Clamped rather than trusted:
    // zero attempts would be a stream that dies on its first timeout with nothing
    // ever sent twice, and an interval outside the RTO bounds would either spin the
    // timer or stall the dial past the establish deadline above it.
    syn_attempts_ = (std::max)(1, profile.syn_attempts);
    syn_backoff_  = profile.syn_backoff;
    rtt_.rto = clamp_duration(std::chrono::milliseconds(profile.syn_rto_ms), kMinRto, kMaxRto);

    // The dial itself is just the first packet of the stream: a Syn occupies a
    // sequence number like any other, so the ordinary retransmission machinery
    // covers a lost dial with no special case — only a tighter attempt cap (see
    // kSynMaxAttempts), so a UDP-blocked path gives up quickly enough for the
    // dialer to fall back to TCP.
    OutPacket syn = new_packet(rudp::PacketType::Syn);
    syn.seq = next_seq_++;
    sent_.push_back(std::move(syn));
    transmit(sent_.back(), now);
}

UdpStream::~UdpStream() {
    if (budget_) budget_->release(held_bytes_);
}

// ── Outbound ────────────────────────────────────────────────────────────────

UdpStream::OutPacket UdpStream::new_packet(rudp::PacketType type) {
    OutPacket pkt;
    pkt.type = type;
    if (!spare_.empty()) {
        pkt.buf = std::move(spare_.back());
        spare_.pop_back();
        pkt.buf.clear();  // capacity survives; the bytes do not
    } else {
        pkt.buf.reserve(rudp::kMaxDatagram);  // headroom + a full payload, allocated once
    }
    pkt.buf.resize(rudp::kHeaderSize);        // reserve the headroom transmit() writes into
    return pkt;
}

void UdpStream::recycle(OutPacket& pkt) {
    if (spare_.size() >= kMaxSpareBuffers) return;
    pkt.buf.clear();
    spare_.push_back(std::move(pkt.buf));
}

uint32_t UdpStream::unread_packets() const noexcept {
    return static_cast<uint32_t>((std::min)(inbox_.size() / rudp::kMaxPayload,
                                            size_t{rudp::kMaxWindowPackets}));
}

uint32_t UdpStream::receive_room() const noexcept {
    // What we are still willing to buffer past the cumulative ack. Whatever the
    // connection has not read out of the in-order buffer yet sits behind the ack
    // and is taken off; what the reorder buffer holds is not, because all of it
    // already lies inside the span this describes.
    const uint32_t unread = unread_packets();
    return unread >= window_ ? 0 : window_ - unread;
}

bool UdpStream::grow_window(const rudp::Packet& p) noexcept {
    if (window_ >= max_window_) return false;
    // An echo: sent against a limit the window has already grown past.
    if (have_grown_ && !rudp::seq_less(grown_mark_, p.seq)) return false;
    // Held back by our own reader rather than by the window: what it has not read
    // is what fills the window, and a larger one would only let the peer park more
    // of it here. The connection drains a stream as fast as it arrives, so this is
    // an application that has stopped reading, and flow control is doing its job.
    if (unread_packets() > window_ / 4) return false;

    const uint32_t next = (std::min)(window_ * 2, max_window_);
    // A larger window is a larger promise of what the peer may make us hold; grow
    // it only while the budget behind all of them could still honour the growth.
    if (budget_ && !budget_->has_room(size_t{next - window_} * rudp::kMaxPayload)) return false;

    grown_mark_ = recv_limit_ + 1;
    have_grown_ = true;
    window_     = next;
    if (!held_.empty()) size_ring(window_);   // otherwise sized when first needed
    // The peer is stopped on the old limit and sends nothing until it hears the
    // new one, so it is told at once.
    need_ack_ = true;
    return true;
}

void UdpStream::size_ring(uint32_t span) {
    uint32_t cap = 64;
    while (cap <= span) cap *= 2;   // strictly more than span: offsets run 1..span
    if (cap - 1 <= ring_mask_) return;

    // The ring is indexed by sequence number modulo its length, so every held
    // packet moves when the length changes; it is rebuilt from the reorder buffer,
    // which is what it mirrors.
    held_.assign(cap / 64, 0);
    ring_mask_ = cap - 1;
    for (const auto& entry : reorder_) set_held(entry.first, true);
    ranges_dirty_ = true;
}

size_t UdpStream::held_cost(size_t payload) noexcept {
    // The payload, and roughly what the map node and the buffer's own allocation
    // cost around it — so a flood of tiny packets is not held for free.
    return payload + 96;
}

uint32_t UdpStream::advertise_limit() noexcept {
    // Monotone by construction. Unread data the connection is sitting on moves
    // the ack forward and the room back by the same amount, so the reach stands
    // still rather than retreating; reading moves it on.
    const uint32_t reach = (recv_next_ - 1) + receive_room();
    if (rudp::seq_less(recv_limit_, reach)) recv_limit_ = reach;
    return recv_limit_;
}

void UdpStream::fill_common(rudp::Packet& p, Clock::time_point now) {
    p.conn_id = send_id_;
    // Cumulative: the highest sequence number received with no gap before it.
    // recv_next_ is the first one still missing, so the ack is the one before it
    // (0 while nothing has arrived — sequence numbers start at 1).
    p.ack   = recv_next_ - 1;
    p.limit = advertise_limit();
    // Data waiting that only the peer's limit is holding back: the one thing that
    // tells the peer its window is too small (see grow_window).
    if (state_ == State::Connected && have_peer_limit_ && !unsent_.empty() &&
        rudp::seq_less(peer_limit_, next_seq_))
        p.flags |= rudp::FlagBlocked;

    // How long the newest packet we have received has waited for this one to
    // leave. A peer measuring its round trip off this acknowledgement takes it
    // back out (see sample_rtt), so a delayed ack reads as the path it crossed
    // rather than as a slower one.
    if (have_recv_) {
        const auto held  = now - largest_recv_at_;
        const auto units = held <= Clock::duration::zero() ? 0 : held / rudp::kAckDelayUnit;
        p.ack_delay = static_cast<uint16_t>((std::min<int64_t>)(units, 0xFFFF));
    }
}

bool UdpStream::is_held(uint32_t seq) const noexcept {
    if (held_.empty()) return false;   // nothing has ever been held
    const uint32_t idx = seq & ring_mask_;
    return (held_[idx / 64] >> (idx % 64)) & 1u;
}

void UdpStream::set_held(uint32_t seq, bool on) noexcept {
    const uint32_t idx  = seq & ring_mask_;
    const uint64_t mask = uint64_t{1} << (idx % 64);
    if (on) held_[idx / 64] |= mask;
    else    held_[idx / 64] &= ~mask;
}

uint32_t UdpStream::scan_down(uint32_t off, bool held) const noexcept {
    // Offsets are past recv_next_, and only 1..ring_mask_ of them can be held;
    // anything a word reaches below offset 1 is the ring wrapping round to the far
    // end of the window, and is never the answer.
    const uint32_t base = recv_next_;
    while (off >= 1) {
        const uint32_t idx = (base + off) & ring_mask_;
        const uint32_t bit = idx % 64;
        uint64_t word = held_[idx / 64];
        if (!held) word = ~word;
        if (bit < 63) word &= (uint64_t{1} << (bit + 1)) - 1;   // at or below `off`
        if (word != 0) {
            const uint32_t down = bit - static_cast<uint32_t>(highest_bit(word));
            return down < off ? off - down : 0;
        }
        if (off <= bit) return 0;   // this word already reached below offset 1
        off -= bit + 1;
    }
    return 0;
}

size_t UdpStream::ack_ranges() const noexcept {
    if (!ranges_dirty_) return range_count_;

    // Every run of packets held past the hole, newest first: the newest delivery
    // is what the peer's loss detection reads, and a run the list has no room for
    // is an old one, which earlier acknowledgements named when it was new. Each
    // run costs two word-at-a-time scans of the ring, so building the list is
    // bounded by the runs it names and the window's words, not its packets.
    size_t   count  = 0;
    uint32_t lowest = 0;   ///< offset the last run named starts at
    const auto emit = [&](size_t slot, uint32_t lo, uint32_t hi) {
        rudp::encode_ack_range(rudp::AckRange{static_cast<uint16_t>(lo),
                                              static_cast<uint16_t>(hi - lo + 1)},
                               range_buf_.data() + slot * rudp::kAckRangeSize);
    };
    if (!reorder_.empty()) {
        uint32_t off = static_cast<uint32_t>(rudp::seq_diff(largest_recv_, recv_next_));
        while (count < rudp::kMaxAckRanges) {
            const uint32_t hi = scan_down(off, true);
            if (hi == 0) break;
            const uint32_t lo = scan_down(hi, false) + 1;
            emit(count++, lo, hi);
            lowest = lo;
            off    = lo - 1;
        }

        // The run the newest arrival landed in, if the list ran out before reaching
        // it — a repair filling a hole deep in the window. It is the one the peer is
        // waiting to hear about (until it does, the repair looks lost too), so it
        // takes the place of the oldest run named (RFC 2018's first-block rule).
        const int32_t latest = rudp::seq_diff(latest_recv_, recv_next_);
        if (count == rudp::kMaxAckRanges && latest > 0 &&
            static_cast<uint32_t>(latest) < lowest && is_held(latest_recv_)) {
            const uint32_t at = static_cast<uint32_t>(latest);
            emit(count - 1, scan_down(at, false) + 1, at);
        }
    }

    range_count_  = count;
    ranges_dirty_ = false;
    return count;
}

void UdpStream::transmit(OutPacket& pkt, Clock::time_point now) {
    rudp::Packet p;
    p.type = pkt.type;
    fill_common(p, now);
    p.seq = pkt.seq;

    // The payload is already sitting in pkt.buf behind kHeaderSize bytes of
    // headroom, so the header goes in immediately ahead of it and the datagram
    // leaves as one contiguous range. Nothing is copied here — not on the first
    // transmission, and not on any retransmission.
    const size_t hdr = rudp::encode_header(p, pkt.buf.data());
    host_.send_datagram(remote_, pkt.buf.data(), hdr + pkt.size());
    const uint64_t flight_before = flight_bytes_;

    // Everything that reaches the wire is metered, retransmissions included: a
    // repair loads the bottleneck exactly as new data does, and a pacer that
    // ignored repairs would let a recovering stream burst precisely when the path
    // has just proved it cannot take one. Only *new* data is gated by the pacer
    // though (see can_transmit) — holding a retransmission back would stall the
    // recovery the timeout just started.
    const uint64_t on_wire = hdr + pkt.size();
    pace_tokens_ = pace_tokens_ > on_wire ? pace_tokens_ - on_wire : 0;

    // These bytes are on the path now. A retransmission of a packet that was never
    // given up on adds nothing — it is the same bytes travelling again, not more of
    // them — which is why this is a transition rather than an addition.
    bool repair = false;
    if (!pkt.in_flight) {
        if (pkt.sends > 0 && !pkt.acked) {   // a repair going out
            --lost_pending_;
            repair = true;
        }
        pkt.in_flight  = true;
        flight_bytes_ += pkt.size();
    }
    // Every send in recovery is charged to the credit (RFC 6937's prr_out), not
    // only the ones the window alone would have refused: credit left to pile up
    // while the window had room would otherwise go out as one burst above it the
    // moment the window filled.
    if (in_recovery_) recovery_credit_ -= (std::min<uint64_t>)(recovery_credit_, pkt.size());

    // RFC 6298 (5.1): something is outstanding, so the timer has to be running —
    // set to whichever of the probe and the timeout comes first (see loss_timeout).
    if (rto_deadline_ == kNoDeadline) {
        rto_deadline_ = now + loss_timeout();
    } else if (repair && in_recovery_) {
        // A repair is the newest thing the timer is guarding, and it gets a full
        // interval of its own to be answered in (RFC 9002 arms from the last packet
        // sent, for the same reason). Measured from the last acknowledgement
        // instead, a repair sent a little after it would be given up on a little
        // before its own answer could possibly arrive — on a path whose round trip
        // is close to the interval, every time. The probe interval where a probe is
        // still allowed: the timeout here is what kept a lost last repair waiting
        // kMinRto and more for something a probe asks about in a round trip.
        rto_deadline_ = (std::max)(rto_deadline_, now + loss_timeout());
    }

    pkt.sends++;
    // A repair (or a probe) is judged by when it left, not by where it sits in the
    // sequence, so it joins the transmission-ordered list detect_losses() reads.
    if (pkt.sends > 1) repairs_.push_back(Repair{pkt.seq, pkt.sends});
    last_send_ = now;
    // The delivery-rate snapshot (sent_at included) describes this copy: it is the
    // one an acknowledgement will be answering, if any is.
    sampler_.on_sent(pkt.tx, now, flight_before, flight_bytes_);
    cc_->on_packet_sent(now, pkt.size(), flight_bytes_);

    // Every packet carries the ack field, so sending one settles whatever
    // acknowledgement was owed — the delayed-ack timer exists precisely to give
    // this a chance to happen.
    need_ack_        = false;
    unacked_packets_ = 0;
    ack_due_         = kNoDeadline;
}

void UdpStream::send_control(rudp::PacketType type, Clock::time_point now) {
    uint8_t buf[rudp::kMaxDatagram];

    rudp::Packet p;
    p.type = type;
    fill_common(p, now);
    // A control packet consumes no sequence number: it carries the next one we
    // *will* use, purely so a peer can see where the stream stands. Nothing
    // retransmits it — a lost ack is repaired by the next one.
    p.seq = next_seq_;

    // A pure acknowledgement is the one packet with room to name every hole, and
    // the one place the peer learns of them (see udp_packet.h).
    if (type == rudp::PacketType::Ack && !reorder_.empty()) {
        const size_t n = ack_ranges();
        if (n > 0) p.ranges = ByteView(range_buf_.data(), n * rudp::kAckRangeSize);
    }

    host_.send_datagram(remote_, buf, rudp::encode(p, buf));

    last_send_       = now;
    need_ack_        = false;
    unacked_packets_ = 0;
    ack_due_         = kNoDeadline;
}

bool UdpStream::cwnd_allows(size_t bytes) const noexcept {
    // Always allow one packet out when the path is idle. This keeps a stream from
    // deadlocking when the congestion window shrinks below a single packet — a
    // window is an estimate of what the path will carry, and an estimate that has
    // collapsed to nothing still has to be able to take a sample. It says nothing
    // about the *receiver's* window, which is not an estimate at all and is
    // enforced ahead of this, in window_allows().
    if (flight_bytes_ == 0) return true;
    if (flight_bytes_ + bytes <= cc_->cwnd()) return true;
    // Proportional rate reduction (RFC 6937), for a controller that wants it: in
    // recovery, what has been delivered since it began earns sends even while the
    // window — just cut below what is still in flight — says no. Otherwise nothing at all would go out
    // until half a window of acknowledgements had come back: not the repairs, and
    // not the new data whose arrival is what tells RACK a repair was lost too.
    return in_recovery_ && cc_->uses_rate_reduction() && recovery_credit_ >= bytes;
}

uint64_t UdpStream::prr_share(uint64_t delivered) const noexcept {
    // Sends earned by `delivered` bytes: in proportion to how far the controller
    // cut the window against what was outstanding when the episode began. Reno's
    // halving earns half; BBR's packet conservation earns all of it.
    if (recover_fs_ == 0) return 0;   // a timeout: slow start, not PRR
    const uint64_t target = (std::min<uint64_t>)(cc_->cwnd(), recover_fs_);
    return cc::mul_div(delivered, target, recover_fs_);
}

bool UdpStream::window_allows() const noexcept {
    if (state_ != State::Connected) return false;   // nothing may overtake the Syn
    if (unsent_.empty()) return false;

    // A receiver whose limit we have reached has said it will buffer nothing
    // more, and that is absolute: it is the only bound on the memory one peer can make
    // another spend on it, so an empty pipe is no licence to send anyway. It would
    // not stay a single probe if it were — the packet is ordinary in-order data,
    // the peer acknowledges it and holds it, the pipe empties, and the next one
    // follows on its heels. What looks like a persist probe is then a steady
    // trickle that fills the receiver far past the window it advertised, bounded
    // in the end by the sender's own queue rather than by anything the receiver
    // said.
    //
    // Nothing is needed from this side to get going again: a receiver whose reader
    // drains a full buffer announces the re-opened window at once and unprompted
    // (see read(), and UdpStreamLink::read for the wake-up that carries it), and
    // its keep-alive carries the limit if that announcement is lost.
    //
    // The limit is the peer's to set and only ever moves forward, so this is the
    // whole check: the next packet takes next_seq_, and may go if that is within
    // it. Repairs are never held by it — every one of them was within the limit
    // when it first went out, and still is.
    if (!have_peer_limit_ || rudp::seq_less(peer_limit_, next_seq_)) return false;
    return cwnd_allows(unsent_.front().size());
}

bool UdpStream::can_transmit() const noexcept {
    if (!window_allows()) return false;
    return pace_allows(unsent_.front().size());
}

// ── Pacing ──────────────────────────────────────────────────────────────────

void UdpStream::pace_accrue(Clock::time_point now) {
    auto dt = now - pace_last_;
    if (dt < Clock::duration::zero()) dt = Clock::duration::zero();
    // The bucket is capped a few lines below, so integrating over a long silence
    // buys nothing — and the clamp is what keeps the multiplication finite.
    const auto cap = std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1));
    if (dt > cap) dt = cap;
    pace_last_ = now;

    const cc::PacingRate rate = cc_->pacing_rate();
    if (!rate.paced()) {
        // Not pacing yet. Keep the bucket at the floor rather than at zero, so
        // the first packet after the first round-trip sample is not held back by
        // an empty bucket the stream never had a chance to fill.
        pace_tokens_ = kPaceMinBurst;
        return;
    }

    pace_tokens_ += rate.bytes_over(dt);
    uint64_t burst = (std::max)(static_cast<uint64_t>(kPaceMinBurst),
                                rate.bytes_over(kPaceQuantum));
    // Woken late for a packet the pacer was holding: what accrued since the moment
    // it asked for is the host's timer slop, not a burst the stream chose, and
    // capping it away would make the clock, not the controller, set the rate. A
    // virtualised or power-managed host routinely sleeps 2-15 ms on a 1 ms timeout
    // (Windows rounds to 15.6 ms), which at a one-quantum bucket sent a fraction of
    // the pacing rate — and BBR, reading that as the path, paced lower each round
    // until the stream crawled at two packets per wake-up. So the lateness is kept,
    // as Chromium's pacer does; the window still bounds what it can release.
    if (pace_due_ != kNoDeadline && now > pace_due_) burst += rate.bytes_over(now - pace_due_);
    if (pace_tokens_ > burst) pace_tokens_ = burst;
}

bool UdpStream::pace_allows(size_t bytes) const noexcept {
    if (!cc_->pacing_rate().paced()) return true;   // no rate to pace against
    // Never hold back a stream with an empty pipe. That covers the lone packet a
    // recovering stream is allowed and the first packet after an idle period —
    // neither of which can congest anything, and both of which would deadlock if a
    // rate derived from an empty pipe were allowed to refuse them.
    if (flight_bytes_ == 0) return true;
    return pace_tokens_ >= bytes;
}

UdpStream::Clock::duration UdpStream::pace_wait(size_t bytes) const noexcept {
    const cc::PacingRate rate = cc_->pacing_rate();
    if (!rate.paced() || pace_tokens_ >= bytes) return Clock::duration::zero();
    // How long the deficit takes to accrue at the current rate.
    return rate.time_for(static_cast<uint64_t>(bytes) - pace_tokens_);
}

void UdpStream::retransmit_lost(Clock::time_point now) {
    // The count keeps this off the hot path entirely: a healthy transfer has
    // nothing to repair and learns so without touching the work list.
    if (lost_pending_ == 0) {
        lost_.clear();   // whatever is left in it is stale
        return;
    }

    // Packets declared lost — by the acknowledgements around them, or by a
    // timeout: still owed to the peer, no longer counted against the window. They
    // are re-sent from the front, ahead of any new data and under the congestion
    // window — so a hole is always repaired before anything queued behind it is
    // sent, and the pipe refills at the rate the controller dictates.
    //
    // In recovery the window is supplemented by proportional rate reduction (see
    // cwnd_allows), which is what keeps a window just cut below what is in flight
    // from holding every repair back for half a round trip.
    //
    // Taken from a heap rather than found by walking the queue: in recovery the
    // repairs are spread across a window that is mostly in flight or already
    // acknowledged, and walking it from the front on every acknowledgement would
    // cost the whole window each time, for the handful the window lets out.
    while (lost_pending_ > 0 && !lost_.empty()) {
        const int32_t idx = rudp::seq_diff(lost_.front(), sent_.front().seq);
        OutPacket* pkt = (idx >= 0 && static_cast<size_t>(idx) < sent_.size())
                             ? &sent_[static_cast<size_t>(idx)] : nullptr;
        // Delivered after all, or already re-sent by a probe: nothing owed here.
        if (!pkt || pkt->acked || pkt->in_flight || pkt->sends == 0) {
            std::pop_heap(lost_.begin(), lost_.end(), LaterSeq{});
            lost_.pop_back();
            continue;
        }
        if (!cwnd_allows(pkt->size())) {   // more still owed: come back with room
            cwnd_limited_ = true;
            return;
        }
        std::pop_heap(lost_.begin(), lost_.end(), LaterSeq{});
        lost_.pop_back();
        transmit(*pkt, now);
        ++retransmits_;
    }
}

void UdpStream::pump(Clock::time_point now) {
    // The controller sees the send opportunity first: a window that has gone
    // unused for a round trip is stale before anything else here reads it (Reno),
    // and a restart from idle is not a reason to probe (BBR).
    if (cc_->on_send_opportunity(now, flight_bytes_, !unsent_.empty(), sampler_.app_limited())) {
        // The bucket describes a rate that no longer applies: release the one
        // packet an empty pipe always allows, then pace the rest at the new rate.
        pace_tokens_ = 0;
        pace_last_   = now;
    }
    pace_accrue(now);

    // Repairs first: what the peer is missing blocks everything queued behind it,
    // so spending the window on new data before the hole is filled would only grow
    // the peer's reorder buffer.
    retransmit_lost(now);

    while (can_transmit()) {
        OutPacket pkt = std::move(unsent_.front());
        unsent_.pop_front();
        pkt.seq = next_seq_++;

        sent_.push_back(std::move(pkt));
        transmit(sent_.back(), now);   // this is what puts it in flight
    }

    // If the loop stopped and every window would still have allowed the next
    // packet, the pacer is the only thing holding it — and a pacer is released by
    // time, not by an acknowledgement, so it needs a deadline of its own. When a
    // window is what stopped us there is deliberately no timer: the ack that
    // opens it is what wakes the stream, and arming one here would spin.
    pace_due_ = Clock::time_point{};
    if (window_allows()) {
        const auto wait = pace_wait(unsent_.front().size());
        if (wait > Clock::duration::zero()) pace_due_ = now + wait;
    }

    note_send_limits();
}

void UdpStream::note_send_limits() {
    if (state_ != State::Connected) return;
    const uint32_t cwnd = cc_->cwnd();

    // Something is waiting and the window is what keeps it waiting — not the
    // pacer, which time resolves, and not the receiver, which only it can.
    if (!unsent_.empty() && have_peer_limit_ && rudp::seq_le(next_seq_, peer_limit_) &&
        !cwnd_allows(unsent_.front().size()))
        cwnd_limited_ = true;

    // Nothing to send, nothing owed, and room in the window: the sender is
    // waiting on the application. Until what is in flight now is delivered,
    // every rate sample measures the application rather than the path.
    if (unsent_.empty() && lost_pending_ == 0 && flight_bytes_ < cwnd)
        sampler_.mark_app_limited(flight_bytes_);
}

size_t UdpStream::send_queue_limit() const noexcept {
    // Twice the window: what is in flight, and as much again behind it — which is
    // also the slack a loss episode needs, when everything selectively acknowledged
    // past a hole still sits in the queue until the hole is repaired.
    size_t limit = 2 * size_t{cc_->cwnd()};
    // But only what the peer could take. Everything in `sent_` lies within its
    // limit, so a queue longer than the span from our oldest unacknowledged packet
    // to that limit — plus the floor, to keep it fed — can never be sent sooner
    // for being here.
    if (have_peer_limit_) {
        const uint32_t oldest = sent_.empty() ? next_seq_ : sent_.front().seq;
        const int32_t  room   = rudp::seq_diff(peer_limit_, oldest) + 1;
        const size_t   reach  = room > 0 ? size_t(room) * rudp::kMaxPayload : 0;
        limit = (std::min)(limit, reach + kSendQueueFloor);
    }
    return (std::max)(limit, kSendQueueFloor);
}

size_t UdpStream::write(const ByteView* slices, size_t count, Clock::time_point now) {
    if (state_ != State::Connected || fin_queued_) return 0;

    const size_t limit = send_queue_limit();
    size_t budget = queued_bytes_ >= limit ? 0 : limit - queued_bytes_;
    if (budget == 0) return 0;

    size_t taken = 0;
    for (size_t i = 0; i < count && budget > 0; ++i) {
        const uint8_t* src  = slices[i].data();
        size_t         left = slices[i].size();
        while (left > 0 && budget > 0) {
            // Pack into the tail packet while it has room, so a burst of small
            // frames leaves as one datagram instead of one datagram each. Only a
            // Data packet can be topped up — a queued Fin closes the stream and
            // must stay the last thing in the queue.
            if (unsent_.empty() || unsent_.back().type != rudp::PacketType::Data ||
                unsent_.back().space() == 0) {
                unsent_.push_back(new_packet(rudp::PacketType::Data));
            }
            OutPacket& tail = unsent_.back();

            const size_t n = (std::min)({left, tail.space(), budget});
            tail.buf.insert(tail.buf.end(), src, src + n);
            src           += n;
            left          -= n;
            budget        -= n;
            taken         += n;
            queued_bytes_ += n;
        }
    }

    pump(now);
    return taken;
}

void UdpStream::begin_close(Clock::time_point now) {
    if (state_ != State::Connected || fin_queued_) return;
    fin_queued_ = true;

    unsent_.push_back(new_packet(rudp::PacketType::Fin));
    pump(now);
}

void UdpStream::abort(Clock::time_point now) {
    if (state_ != State::Dead) send_control(rudp::PacketType::Reset, now);
    die(CloseReason::LocalClose);
    events_ = 0;  // the connection asked for this; it does not need telling
}

// ── Inbound ─────────────────────────────────────────────────────────────────

void UdpStream::on_packet(const rudp::Packet& p, Clock::time_point now) {
    if (state_ == State::Dead) return;

    last_recv_ = now;

    if (p.type == rudp::PacketType::Reset) {
        LOG_DEBUG("udp", "Stream " << recv_id_ << " reset by " << remote_.to_string());
        die(CloseReason::PeerReset);
        flush_events();
        return;
    }

    // Handled before anything else reads the header: a Retry comes from a responder
    // that is holding no state for us at all, so its window and sequence number
    // describe nothing and must not be folded into what we believe about the peer.
    if (p.type == rudp::PacketType::Retry) {
        handle_retry(p, now);
        flush_events();
        return;
    }

    bool ack_now = (p.type == rudp::PacketType::Syn || p.type == rudp::PacketType::Fin);
    // The peer has to hear about a hole, which only a pure Ack can name (see below).
    bool ranges_owed = false;

    handle_ack(p, now);

    // The peer is stopped on our limit. A larger window is owed at once if it is
    // granted at all (and grow_window says the ack is owed).
    if ((p.flags & rudp::FlagBlocked) && grow_window(p)) ack_now = true;

    // The Syn is the first entry in the retransmission queue, so the moment it is
    // no longer there the dial has been answered and the stream is up.
    if (state_ == State::SynSent &&
        (sent_.empty() || sent_.front().type != rudp::PacketType::Syn)) {
        state_ = State::Connected;
        raise(PollOut);
        LOG_DEBUG("udp", "Stream " << recv_id_ << " connected to " << remote_.to_string());
    }

    if (p.type == rudp::PacketType::Syn || p.type == rudp::PacketType::Data ||
        p.type == rudp::PacketType::Fin) {
        // The peer is sending again, so it is not stopped on a window we re-opened
        // and there is nothing left to announce. A bare acknowledgement deliberately
        // does not count: a sender stopped at our limit still keep-alives, and
        // taking that as proof would call off the very repeats meant for it.
        window_announces_ = 0;

        const uint32_t before   = recv_next_;
        const bool     had_hole = !reorder_.empty();
        handle_sequenced(p, now);
        // A packet that did not fill the gap it was expected to means the peer is
        // missing something: say so at once rather than waiting out the delayed
        // ack, since that ack is what triggers its fast retransmit. And one that
        // did fill it is a repair the peer is waiting on, with everything held
        // behind it now delivered too (RFC 5681 4.2): delaying that ack would only
        // stall a recovery and push it towards its timeout.
        if (recv_next_ == before || had_hole) {
            ack_now = true;
            // Decided before pump(): the Data it may send carries the cumulative
            // ack too, but nothing about what is held past the hole.
            ranges_owed = !reorder_.empty();
        }
    }

    pump(now);

    // The connection asked to be told when it could write again, and an ack just
    // freed queue space.
    if (want_write_ && state_ == State::Connected && queued_bytes_ < send_queue_limit())
        raise(PollOut);

    if (need_ack_) {
        // Acknowledge every second packet even without a hole (the classic
        // ack-every-other-segment rule), so a bulk sender's window keeps opening
        // without a round trip's worth of delay per packet.
        if (ack_now || unacked_packets_ >= 2) send_control(rudp::PacketType::Ack, now);
        else if (ack_due_ == kNoDeadline)     ack_due_ = now + kDelayedAck;
    } else if (ranges_owed) {
        // The acknowledgement went out on our own Data, so nothing is owed by the
        // usual rule — but that Data could not name the hole. A peer sending to us
        // while we send to it would otherwise find it only once the hole in front
        // of it fills, a round trip later; one pure ack, sent only for news about
        // holes, is what ranges exist for.
        send_control(rudp::PacketType::Ack, now);
    }

    flush_events();
}

void UdpStream::handle_ack(const rudp::Packet& p, Clock::time_point now) {
    // An ack past the highest sequence number we have ever assigned is nonsense;
    // honouring it would retire packets that were never sent.
    if (rudp::seq_less(next_seq_ - 1, p.ack)) return;

    // How far the receiver will let us go. Its limit only ever moves forward, so
    // the largest one seen is the current one, and a packet that was reordered or
    // duplicated on the way — carrying an older, lower limit — changes nothing.
    // One that is not even ahead of its own cumulative ack, or that claims more
    // room than any receive buffer has, is corrupt or forged and is not believed:
    // a limit from the far future would otherwise be latched for good.
    const int32_t room = rudp::seq_diff(p.limit, p.ack);
    if (room >= 0 && room <= kMaxPeerRoom &&
        (!have_peer_limit_ || rudp::seq_less(peer_limit_, p.limit))) {
        peer_limit_      = p.limit;
        have_peer_limit_ = true;
    }

    size_t newly_acked = 0;   ///< bytes the cumulative ack retired, not already sacked
    size_t retired     = 0;   ///< packets the cumulative ack removed from the queue
    ack_newly_acked_   = 0;   ///< every byte acknowledged for the first time, either way
    ack_newest_        = Newest{};
    ack_prior_flight_  = flight_bytes_;
    while (!sent_.empty() && rudp::seq_le(sent_.front().seq, p.ack)) {
        OutPacket& front = sent_.front();
        // A packet a selective ack already retired was accounted for then; only the
        // ones this acknowledgement is the first to cover count as news.
        if (!front.acked) {
            newly_acked += front.size();
            on_newly_acked(front, now);
        } else {
            --sacked_in_queue_;
        }
        recycle(front);
        sent_.pop_front();
        ++retired;
    }
    // Nothing outstanding: whatever the loss-detection lists still name is stale.
    if (sent_.empty()) {
        repairs_.clear();
        repairs_head_ = 0;
        lost_.clear();
    }

    // The episode ends once everything that was outstanding when the loss was
    // detected has been acknowledged (the NewReno recovery point). Until then the
    // window has already been reduced for it and must not be reduced again.
    if (in_recovery_ && rudp::seq_le(recover_seq_, p.ack)) {
        in_recovery_      = false;
        timeout_recovery_ = false;
        recovery_credit_  = 0;
        cc_->on_recovery_exit(now);
    }

    // Selective acknowledgements. Every packet in the queue occupies exactly one
    // sequence number, so the packet a range names is found by subtraction rather
    // than by search.
    uint32_t largest = p.ack;   ///< the newest packet this acknowledgement names
    for (size_t r = 0, n = p.range_count(); r < n; ++r) {
        const rudp::AckRange range = rudp::ack_range(p, r);
        const uint32_t first = p.ack + 1 + range.offset;
        const uint32_t last  = first + range.length - 1;
        if (rudp::seq_less(largest, last)) largest = last;
        if (sent_.empty()) continue;
        // Clipped to the queue once, so a range that reaches past what we sent (or
        // starts before what is left of it) costs nothing per out-of-range packet.
        const int32_t lo = (std::max)(rudp::seq_diff(first, sent_.front().seq), int32_t{0});
        const int32_t hi = (std::min)(rudp::seq_diff(first + range.length, sent_.front().seq),
                                      static_cast<int32_t>(sent_.size()));
        // Every Ack repeats every range the receiver holds, so most of what a range
        // names was acknowledged by an earlier one. Stepping over those runs rather
        // than through them is what makes an Ack cost what it newly acknowledges
        // instead of the size of the window.
        if (lo >= hi) continue;
        for (size_t idx = next_unacked(static_cast<size_t>(lo)); idx < static_cast<size_t>(hi);
             idx = next_unacked(idx + 1)) {
            on_newly_acked(sent_[idx], now);
            ++sacked_in_queue_;
        }
    }

    // One round-trip sample per acknowledgement, from the newest packet it newly
    // covers — the one whose arrival the acknowledgement was sent for. Every other
    // packet it covers waited at the receiver for that one (or for a hole to fill),
    // and measuring them would add the wait to the estimate. Karn's rule on top: a
    // retransmitted packet cannot say which copy is being answered.
    //
    // The delay the peer reports is how long the newest packet it holds waited
    // for this acknowledgement, so it describes our sample only when that is the
    // packet sampled — and never more than the peer is allowed to hold one for
    // (RFC 9002 5.3), so a peer cannot talk our estimate down by claiming more.
    if (ack_newest_.have && ack_newest_.sends == 1) {
        Clock::duration delay{};
        if (ack_newest_.seq == largest)
            delay = (std::min)(Clock::duration(p.ack_delay * rudp::kAckDelayUnit),
                               Clock::duration(kDelayedAck));
        sample_rtt(now - ack_newest_.sent_at, delay);
    }

    // What this acknowledgement delivered earns sends in a recovery already under
    // way (one opened by this acknowledgement is credited in enter_recovery).
    if (in_recovery_) recovery_credit_ += prr_share(ack_newly_acked_);

    // What the acknowledgements around a missing packet say about it.
    detect_losses(now);

    // Progress means the path is alive: drop back to the estimated RTO, undoing
    // any doubling a previous timeout applied.
    if (newly_acked > 0 && rtt_.have_rtt) rtt_.rto = estimated_rto();

    // The controller hears the totals once everything the ack implies has been
    // applied — retirements, selective acks, losses, the episode they opened.
    const cc::RateSample rs = sampler_.take_sample(rtt_.min_or_zero());
    if (rs.acked || lost_since_ack_ > 0) {
        cc::AckEvent ev;
        ev.now             = now;
        ev.cum_ack         = p.ack;
        ev.next_seq        = next_seq_;
        ev.newly_cum_acked = newly_acked;
        ev.newly_acked     = ack_newly_acked_;
        ev.newly_lost      = lost_since_ack_;
        ev.bytes_in_flight = flight_bytes_;
        ev.cwnd_limited    = cwnd_limited_;
        ev.rs              = rs;
        cc_->on_ack(ev);
        lost_since_ack_ = 0;
        cwnd_limited_   = false;
        if (cc_->wants_app_limited()) sampler_.mark_app_limited(flight_bytes_);
    }
    const bool progress = retired > 0 || ack_newly_acked_ > 0;
    ack_newly_acked_ = 0;

    // RFC 6298 (5.2/5.3): the timer restarts whenever an acknowledgement covers
    // something new, and stops once nothing is outstanding. "New" includes what a
    // selective ack covers (RFC 9002 6.2.1): during recovery the cumulative ack
    // stands still behind the hole for a couple of round trips while the selective
    // ones keep reporting progress, and a timer that only the cumulative ack could
    // restart would fire in the middle of a recovery that is going fine. Retired
    // packets are counted as well as bytes, because a Syn and a Fin each occupy a
    // sequence number while carrying no payload — a byte count alone would leave
    // the timer running on the deadline the *handshake* set.
    //
    // Progress also ends the silence the probes were counting (RFC 9002 resets its
    // probe count on any acknowledgement). In recovery the cumulative ack can stand
    // still behind a hole for rounds on end, and a count only it could reset would
    // spend the whole episode's probes on its first two silences.
    if (progress) {
        tail_probes_  = 0;
        rto_deadline_ = sent_.empty() ? kNoDeadline : now + loss_timeout();
    }
}

void UdpStream::handle_retry(const rudp::Packet& p, Clock::time_point now) {
    // "Not until you prove you are really at that address." A responder under load
    // answers a dial with a cookie instead of a stream, and will not spend a byte of
    // memory on us until it comes back. Only a dial that has not been answered yet
    // can be retried, and only once — see retried_.
    if (state_ != State::SynSent || retried_) return;
    if (p.payload.size() != rudp::kCookieSize) return;
    if (sent_.empty() || sent_.front().type != rudp::PacketType::Syn) return;

    retried_ = true;
    OutPacket& syn = sent_.front();

    // The same Syn, same sequence number, now carrying the cookie. Its payload was
    // empty until now, and the send accounting has to learn about the bytes: the
    // cumulative ack that eventually retires this packet subtracts size() from both
    // counters, so anything that grows a queued packet must add to them first.
    syn.buf.resize(rudp::kHeaderSize);
    syn.buf.insert(syn.buf.end(), p.payload.begin(), p.payload.end());
    queued_bytes_ += rudp::kCookieSize;
    // Only if the packet is currently counted as in flight: if a timeout has just
    // given up on it, transmit() below will count the whole grown packet afresh,
    // and adding the difference here as well would count the cookie twice.
    if (syn.in_flight) flight_bytes_ += rudp::kCookieSize;

    // The round trip we just spent proving our address is not a lost packet, so it
    // does not count against the dial's attempt budget — and the dial gets a fresh
    // timeout to answer in, rather than what was left of the first one.
    syn.sends     = 0;
    rto_deadline_ = now + rtt_.rto;
    transmit(syn, now);

    LOG_DEBUG("udp", "Stream " << recv_id_ << " re-dialing " << remote_.to_string()
              << " with an address-validation cookie");
}

void UdpStream::on_newly_acked(OutPacket& pkt, Clock::time_point now) {
    pkt.acked = true;
    pkt.skip  = pkt.seq + 1;
    if (pkt.in_flight) {
        flight_bytes_ -= pkt.size();
        pkt.in_flight  = false;
    } else if (pkt.sends > 0) {
        --lost_pending_;   // declared lost, then delivered after all: nothing to repair
    }
    queued_bytes_    -= pkt.size();
    ack_newly_acked_ += pkt.size();
    sampler_.on_delivered(pkt.tx, pkt.seq, pkt.size(), now);

    // The newest packet this acknowledgement covers, by transmission time.
    if (!ack_newest_.have || pkt.tx.sent_at > ack_newest_.sent_at) {
        ack_newest_.have    = true;
        ack_newest_.seq     = pkt.seq;
        ack_newest_.sent_at = pkt.tx.sent_at;
        ack_newest_.sends   = pkt.sends;
    }

    if (!have_largest_acked_ || rudp::seq_less(largest_acked_, pkt.seq)) {
        largest_acked_      = pkt.seq;
        have_largest_acked_ = true;
    }
    // RACK (RFC 8985): the newest transmission known to have arrived. A
    // retransmission acknowledged sooner than a round trip after it left was almost
    // certainly the original arriving late, and must not move the mark — or every
    // packet sent between the two copies would be declared lost on the strength of
    // a delivery that never happened.
    const bool ambiguous = pkt.sends > 1 && rtt_.have_rtt && now - pkt.tx.sent_at < rtt_.min_rtt;
    if (!ambiguous && (!have_rack_ || pkt.tx.sent_at > rack_sent_at_)) {
        rack_sent_at_ = pkt.tx.sent_at;
        have_rack_    = true;
    }
}

size_t UdpStream::next_unacked(size_t idx) noexcept {
    const size_t   n    = sent_.size();
    if (idx >= n) return n;
    const uint32_t base = sent_.front().seq;
    // A skip always points forward, past the packet holding it, so it is never
    // before the front; one past the back is "none yet" (and stays right when the
    // queue grows, since everything it stepped over is still acknowledged).
    const auto index_of = [&](uint32_t seq) {
        return (std::min)(static_cast<size_t>(rudp::seq_diff(seq, base)), n);
    };

    size_t root = idx;
    while (root < n && sent_[root].acked) root = index_of(sent_[root].skip);

    // Path compression: everything walked through now points straight at the
    // answer, so the next walk over the same run is a single hop.
    const uint32_t root_seq = base + static_cast<uint32_t>(root);
    while (idx < root) {
        OutPacket&   pkt  = sent_[idx];
        const size_t next = index_of(pkt.skip);
        pkt.skip = root_seq;
        idx      = next;
    }
    return root;
}

void UdpStream::detect_losses(Clock::time_point now) {
    if (sent_.empty() || !have_largest_acked_) return;

    // The reordering a path is allowed before a packet counts as lost: a quarter of
    // the minimum round trip (RFC 8985's default), at least a millisecond, never
    // more than a round trip.
    Clock::duration reo_wnd = std::chrono::milliseconds(1);
    if (rtt_.have_rtt) {
        reo_wnd = (std::max)(reo_wnd, Clock::duration(rtt_.min_rtt / 4));
        reo_wnd = (std::min)(reo_wnd, rtt_.srtt);
    }
    const auto too_old = [&](const OutPacket& pkt) {
        return have_rack_ && pkt.tx.sent_at + reo_wnd < rack_sent_at_;
    };

    bool           lost_any = false;
    const uint32_t front    = sent_.front().seq;
    const auto     at = [&](uint32_t seq) -> OutPacket* {
        const int32_t idx = rudp::seq_diff(seq, front);
        return (idx >= 0 && static_cast<size_t>(idx) < sent_.size())
                   ? &sent_[static_cast<size_t>(idx)] : nullptr;
    };

    // Repairs (and probes) are judged by time alone: their sequence number is old,
    // so counting by it would condemn every repair the moment it left. They are
    // listed in the order they left, so the first one sent too recently to judge
    // ends the scan — everything behind it left later still.
    for (; repairs_head_ < repairs_.size(); ++repairs_head_) {
        const Repair r   = repairs_[repairs_head_];
        OutPacket*   pkt = at(r.seq);
        if (pkt && !pkt->acked && pkt->in_flight && pkt->sends == r.sends) {
            if (!too_old(*pkt)) break;
            mark_lost(*pkt, now);
            lost_any = true;
        }
    }
    // Give back what has been consumed once it is most of the list, so the copy
    // is paid for by the entries it drops.
    if (repairs_head_ == repairs_.size()) {
        repairs_.clear();
        repairs_head_ = 0;
    } else if (repairs_head_ >= 64 && 2 * repairs_head_ >= repairs_.size()) {
        repairs_.erase(repairs_.begin(), repairs_.begin() + static_cast<std::ptrdiff_t>(repairs_head_));
        repairs_head_ = 0;
    }

    // First transmissions, from where the last scan stopped. Nothing past the
    // largest acknowledged packet can be judged: no evidence about it has come back
    // yet. On a healthy stream that is the front of the queue, so this costs
    // nothing; only a stream with holes walks anything at all, and it walks each
    // packet once.
    if (rudp::seq_less(loss_scan_, front) || rudp::seq_less(next_seq_, loss_scan_))
        loss_scan_ = front;
    for (; rudp::seq_less(loss_scan_, largest_acked_); ++loss_scan_) {
        OutPacket* pkt = at(loss_scan_);
        if (!pkt) break;
        // Delivered, given up on, or a repair (the list above has it): passed over.
        if (pkt->acked || !pkt->in_flight || pkt->sends != 1) continue;

        // Lost once kReorderThreshold packets behind it have arrived — the
        // duplicate-ack rule, read off the selective acks — or once something sent
        // a reordering window after it has. Both only become true of later packets
        // later, so the first packet in good standing is where the scan stops.
        const bool by_count = rudp::seq_diff(largest_acked_, pkt->seq) >= kReorderThreshold;
        if (!by_count && !too_old(*pkt)) break;

        mark_lost(*pkt, now);
        lost_any = true;
    }
    // One window reduction for the whole episode — not one per packet repaired,
    // and not one per ack that repairs something. Several selective acks arrive
    // per round trip and recovery spans several round trips, so halving on each
    // of them would drive the window to the floor over a loss TCP would have
    // ridden out with a single halving. enter_recovery() enforces that.
    if (lost_any) enter_recovery(now);
}

void UdpStream::mark_lost(OutPacket& pkt, Clock::time_point now) {
    // No longer on the path: it stops counting against the window, which is what
    // lets its repair go out under that window rather than past it.
    if (pkt.in_flight) {
        pkt.in_flight  = false;
        flight_bytes_ -= pkt.size();
    }
    ++lost_pending_;
    lost_.push_back(pkt.seq);
    std::push_heap(lost_.begin(), lost_.end(), LaterSeq{});
    declare_lost(pkt, now);
}

void UdpStream::handle_sequenced(const rudp::Packet& p, Clock::time_point now) {
    need_ack_ = true;

    if (rudp::seq_less(p.seq, recv_next_)) return;  // already delivered; just re-ack

    // Past the limit we advertised: a peer ignoring flow control, and buffering
    // it would let one peer decide how much memory we spend. The limit is brought
    // up to date first — a packet the buffer has room for is not refused merely
    // because no acknowledgement has said so yet.
    if (rudp::seq_less(advertise_limit(), p.seq)) return;
    const int32_t ahead = rudp::seq_diff(p.seq, recv_next_);
    if (static_cast<uint32_t>(ahead) > rudp::kMaxWindowPackets) return;   // the limit ensures this
    if (ahead > 0 && is_held(p.seq)) return;   // a duplicate of one held: news to nobody

    // Only Data carries stream content. A Syn occupies a sequence number like any
    // other packet, but what it carries is the address-validation cookie the mux
    // has already checked — delivering that as stream bytes would splice four bytes
    // of nonsense into the front of the peer's handshake.
    const ByteView body = (p.type == rudp::PacketType::Data) ? p.payload : ByteView{};

    // Out of order, it has to be held — and held memory is charged to the budget
    // every stream shares. Refused, it is as good as lost: the peer will repair it.
    // It is priced before the payload is copied, so a refusal — likeliest exactly
    // when the budget is under pressure — costs no allocation.
    InPacket held;
    if (ahead > 0) {
        const size_t cost = held_cost(body.size());
        if (budget_ && !budget_->charge(cost, held_bytes_)) return;
        held_bytes_ += cost;
        held.payload = body.to_bytes();
        held.fin     = (p.type == rudp::PacketType::Fin);
        // The ring is allocated the first time anything is held, so a stream that
        // never sees a hole never pays for it; it covers whatever the limit admits,
        // which after a window has shrunk back can still be more than the window.
        size_ring((std::max)(window_, static_cast<uint32_t>(ahead)));
    }

    // Something new arrived. The newest of them is what the ack delay is measured
    // from; the latest, whichever it is, is the run an Ack always names.
    latest_recv_ = p.seq;
    if (!have_recv_ || rudp::seq_less(largest_recv_, p.seq)) {
        largest_recv_    = p.seq;
        largest_recv_at_ = now;
        have_recv_       = true;
    }
    ranges_dirty_ = true;

    if (ahead == 0) {
        ++unacked_packets_;
        deliver(body, p.type == rudp::PacketType::Fin);
        ++recv_next_;
        drain_reorder();
        return;
    }

    // Past the gap: hold it until the gap fills.
    reorder_.emplace(p.seq, std::move(held));
    set_held(p.seq, true);
}

void UdpStream::deliver(ByteView payload, bool fin) {
    if (peer_fin_) return;  // nothing follows a Fin

    if (!payload.empty()) {
        const ByteSpan into = inbox_.prepare(payload.size());
        std::memcpy(into.data(), payload.data(), payload.size());
        inbox_.commit(payload.size());
        raise(PollIn);
    }
    if (fin) {
        peer_fin_ = true;
        raise(PollIn);  // the reader has to see the end of stream
    }
}

void UdpStream::drain_reorder() {
    for (;;) {
        auto it = reorder_.find(recv_next_);
        if (it == reorder_.end()) break;
        deliver(ByteView(it->second.payload), it->second.fin);
        const size_t cost = held_cost(it->second.payload.size());
        held_bytes_ -= cost;
        if (budget_) budget_->release(cost);
        reorder_.erase(it);
        set_held(recv_next_, false);
        ++recv_next_;
    }
}

size_t UdpStream::read(uint8_t* into, size_t len) {
    const size_t n = (std::min)(len, inbox_.size());
    if (n == 0) return 0;

    std::memcpy(into, inbox_.data(), n);
    const uint32_t before = receive_room();
    inbox_.consume(n);
    // Draining the buffer may have re-opened a window we had advertised as full.
    // The peer is waiting on that limit, so it has to be told without waiting for
    // traffic that will never come while it is stopped — hence an owed ack with no
    // deadline attached, which the next tick() sends outright rather than holding
    // for company (see there). Leaving ack_due_ unset is the *signal*, not an
    // omission: everything else that owes an ack has a packet of its own to wait for.
    //
    // And again after that, a few times, if the peer stays quiet. Nothing
    // retransmits a bare acknowledgement, and the sender this one is for is stopped
    // — so were it dropped, the only thing left to restart the transfer would be
    // the keep-alive ten seconds out. Cleared as soon as the peer sends anything
    // sequenced, which is proof it heard us.
    if (before == 0 && receive_room() > 0) {
        need_ack_         = true;
        window_announces_ = kMaxWindowAnnounces;
        window_due_       = kNoDeadline;   // the first one goes at once
    }
    return n;
}

// ── Timing, congestion control, lifecycle ───────────────────────────────────

void UdpStream::sample_rtt(Clock::duration rtt, Clock::duration ack_delay) {
    if (rtt < Clock::duration::zero()) return;

    if (!rtt_.have_rtt) {
        rtt_.srtt     = rtt;
        rtt_.rttvar   = rtt / 2;
        rtt_.have_rtt = true;
    } else {
        // RFC 9002 5.3: the peer's ack delay comes off the sample, but never so far
        // that the result is shorter than the shortest round trip ever seen — a
        // delay that would is one the clocks cannot account for, and believing it
        // would put the estimate below anything the path has ever done.
        auto adjusted = rtt;
        if (rtt >= rtt_.min_rtt + ack_delay) adjusted -= ack_delay;
        // RFC 6298: rttvar = 3/4 rttvar + 1/4 |srtt - r| ; srtt = 7/8 srtt + 1/8 r.
        const auto err = rtt_.srtt > adjusted ? rtt_.srtt - adjusted : adjusted - rtt_.srtt;
        rtt_.rttvar = (rtt_.rttvar * 3 + err) / 4;
        rtt_.srtt   = (rtt_.srtt * 7 + adjusted) / 8;
    }
    // The minimum and the controller see the raw sample: a minimum is only a
    // floor while nothing has been subtracted from it, and BBR's model of the
    // path is built from the round trips it actually observed.
    rtt_.latest  = rtt;
    rtt_.min_rtt = (std::min)(rtt_.min_rtt, rtt);
    rtt_.rto     = estimated_rto();

    cc_->on_rtt_sample(rtt);
}

UdpStream::Clock::duration UdpStream::estimated_rto() const noexcept {
    // RFC 6298's srtt + 4 * rttvar, plus what the peer may hold an acknowledgement
    // back for (RFC 9002 puts max_ack_delay in its probe timeout for the same
    // reason). Without it, on a path whose round trip is steady enough for rttvar
    // to vanish, the timeout is a round trip and nothing more — and the first
    // delayed acknowledgement arrives after it has fired.
    return clamp_duration(rtt_.srtt + 4 * rtt_.rttvar +
                              std::chrono::duration_cast<Clock::duration>(kDelayedAck),
                          kMinRto, kMaxRto);
}

void UdpStream::enter_recovery(Clock::time_point now) {
    if (in_recovery_) return;   // already paid for this episode
    in_recovery_ = true;
    // Everything assigned a sequence number so far is what has to be acknowledged
    // before the episode is over. next_seq_ is the number the *next* packet will
    // take, so the highest one outstanding is one below it.
    recover_seq_ = next_seq_ - 1;
    ++congestion_events_;
    cc_->on_congestion_event(now, flight_bytes_, ack_newly_acked_);
    // PRR's RecoverFS: what was outstanding when the episode began. The share is
    // taken against the window the controller has just cut to.
    recover_fs_      = (std::max<uint64_t>)(ack_prior_flight_, 1);
    recovery_credit_ = prr_share(ack_newly_acked_);
}

void UdpStream::declare_lost(const OutPacket& pkt, Clock::time_point now) {
    const uint64_t bytes = pkt.size();
    if (bytes == 0) return;   // a Syn or a Fin: nothing the path model counts
    sampler_.on_lost(bytes);
    lost_since_ack_ += bytes;

    cc::LostPacket lost;
    lost.now             = now;
    lost.bytes           = bytes;
    lost.tx_in_flight    = pkt.tx.in_flight;
    lost.lost_since_sent = sampler_.lost() - pkt.tx.lost;
    lost.app_limited     = pkt.tx.app_limited;
    cc_->on_packet_lost(lost);
}

UdpStream::Clock::duration UdpStream::probe_timeout() const noexcept {
    if (!rtt_.have_rtt) return kInitialRto;

    // RFC 9002's PTO: a round trip, the variance allowance, and the time the peer
    // is entitled to hold an acknowledgement back for. The last term is what stops
    // the probe racing our own delayed-ack rule and calling a slow peer a lost one.
    const auto granularity = std::chrono::duration_cast<Clock::duration>(kMinProbeTimeout) / 8;
    auto pto = rtt_.srtt + (std::max)(4 * rtt_.rttvar, granularity)
                     + std::chrono::duration_cast<Clock::duration>(kDelayedAck);

    // Doubled per consecutive probe: if the first went unanswered the path is
    // worse than the estimate said, and asking again at the same spacing would
    // just be asking twice.
    for (int i = 0; i < tail_probes_ && pto < std::chrono::duration_cast<Clock::duration>(kMaxRto); ++i)
        pto *= 2;

    return clamp_duration(pto, kMinProbeTimeout, kMaxRto);
}

UdpStream::Clock::duration UdpStream::loss_timeout() const noexcept {
    // Probes run in recovery too (RFC 9002 keeps one timer in every state; Linux,
    // which probes only in Open, leaves the case below to its timeout). The case is
    // a lost repair with nothing sent after it — the last loss of a message, or of
    // a transfer — which no acknowledgement can reveal, because RACK needs a later
    // delivery and there is none. A probe costs one packet where the timeout costs
    // kMinRto and the window. It does not race a repair that is merely on its way:
    // every repair re-arms the timer from its own departure (see transmit), and the
    // probe interval is a round trip plus the peer's ack delay.
    //
    // Not after a timeout, though: that episode began with the path silent for a
    // whole timeout, and backing off is what keeps a dead path from being hammered.
    if (state_ != State::Connected || timeout_recovery_ || tail_probes_ >= kMaxTailProbes)
        return rtt_.rto;

    // Never later than the timeout it stands in front of. A probe exists to ask
    // the question *sooner* and more cheaply than the retransmission timeout would
    // — on a path whose round trip is long enough that the probe interval exceeds
    // the timeout, waiting for the probe would be pure added delay. Capped, the
    // worst case is that it fires exactly when the timeout would have, and the
    // stream still keeps its window instead of collapsing it.
    return (std::min)(probe_timeout(), rtt_.rto);
}

void UdpStream::on_rto(Clock::time_point now) {
    // Find the oldest packet the peer has not confirmed. A selectively acknowledged
    // one at the front would mean the peer already has it, so it is not what the
    // timeout is about.
    OutPacket* oldest = nullptr;
    for (OutPacket& pkt : sent_) {
        if (!pkt.acked) { oldest = &pkt; break; }
    }
    if (!oldest || oldest->sends == 0) {
        rto_deadline_ = kNoDeadline;  // nothing outstanding; the timer has no work
        return;
    }

    const int cap = (state_ == State::SynSent) ? syn_attempts_ : kMaxRetransmits;
    if (oldest->sends >= cap) {
        die(state_ == State::SynSent ? CloseReason::ConnectFailed : CloseReason::PeerReset);
        return;
    }

    // Tail loss probe, before any of the collapse below is believed. The peer has
    // gone quiet, which on a stream whose last packet was lost is indistinguishable
    // from a peer that is merely slow — and the two call for opposite responses.
    // So ask first: re-send something it has not acknowledged, change nothing else,
    // and let the answer decide. A probe that was unnecessary costs one packet;
    // the collapse below, taken wrongly, costs the whole window.
    //
    // Deliberately not for a dial: a Syn has its own, tighter attempt budget that
    // the transport race depends on (see kSynMaxAttempts).
    if (state_ == State::Connected && !timeout_recovery_ && tail_probes_ < kMaxTailProbes) {
        // The LAST unacknowledged packet, not the first (RFC 8985 §7.2). This is
        // the whole mechanism, not a detail of it: the probe's acknowledgement has
        // to land *past* every hole in front of it, so the receiver holds it out of
        // order and the selective ack that comes back names all of them at once —
        // which is what lets one round trip repair a whole lost burst.
        //
        // Probing the front instead produces an acknowledgement that advances the
        // cumulative number by exactly one and names nothing. Each probe would then
        // recover a single packet, and because that acknowledgement is new data it
        // resets tail_probes_ — so the escalation below is never reached, the rest
        // of the burst stays counted in flight with the window shut behind it, and
        // grow_window() walks the window *up* through what is in fact a total loss.
        // For a single lost packet the two are the same packet and the difference
        // does not show; for a lost burst it is the difference between repairing in
        // one round trip and crawling out one packet per probe.
        OutPacket* probe = oldest;
        for (auto it = sent_.rbegin(); it != sent_.rend(); ++it) {
            if (!it->acked) { probe = &*it; break; }
        }

        ++tail_probes_;
        transmit(*probe, now);
        ++retransmits_;
        rto_deadline_ = now + loss_timeout();   // backed off, still capped by the RTO
        return;
    }

    // A timeout is the stronger signal and always collapses the window, even
    // mid-recovery — but it also restarts the episode, so the selective acks that
    // come back as the pipe refills do not each take another halving out of a
    // window that is already down to one packet. (The controller reads what was in
    // flight, so it has to hear of this before the accounting below is undone.)
    ++congestion_events_;
    cc_->on_timeout(now, flight_bytes_);
    in_recovery_      = true;
    timeout_recovery_ = true;
    recover_seq_      = next_seq_ - 1;

    // Everything outstanding has had a full retransmission timeout to arrive and
    // nothing acknowledged it, so it is presumed lost and stops occupying the path.
    //
    // This step is what makes recovery possible at all. Leaving the bytes counted
    // would leave flight_bytes_ holding a whole window while the window is back down to
    // one packet, and cwnd_allows() — the gate every transmission goes through —
    // would refuse for as long as those packets sat in the queue. The sender would
    // then crawl forward one packet per timeout, unable to grow the window or
    // repair the rest, until the transfer effectively stopped.
    for (OutPacket& pkt : sent_)
        if (pkt.in_flight) mark_lost(pkt, now);
    recovery_credit_ = 0;
    recover_fs_      = 0;   // what follows a timeout is slow start, not PRR

    // Exponential backoff, so a path that is down is probed ever more cheaply
    // instead of being hammered. The deadline is set from it before anything goes
    // out, so the retransmissions below do not each restart the timer.
    //
    // A punching dial is the one case that opts out (see DialProfile): there the
    // peer's NAT is expected to swallow the early Syns, so backing off would spread
    // the few attempts we get across seconds and leave the window in which both
    // sides are actually probing barely covered. Only the dial can ask for this —
    // an established stream always backs off.
    if (syn_backoff_ || state_ != State::SynSent)
        rtt_.rto = clamp_duration(rtt_.rto * 2, kMinRto, kMaxRto);
    rto_deadline_ = now + rtt_.rto;

    retransmit_lost(now);
}

std::optional<Clock::time_point> UdpStream::next_deadline() const noexcept {
    // A dead stream has no timers left to run; the mux collects it instead of
    // servicing it, so it asks for no wake-up at all.
    if (state_ == State::Dead) return std::nullopt;

    // The idle deadline is the one thing always armed: silence from the peer ends
    // the stream whatever else is or is not outstanding.
    Clock::time_point due = last_recv_ + kIdleTimeout;

    // An owed acknowledgement. The epoch here is not "no deadline" but "at once" —
    // read() leaves it that way to ask for a window update, and a peer stopped on a
    // zero window sends nothing for the ack to ride on. Returning the epoch makes
    // that the earliest possible deadline, which is exactly what it means.
    if (need_ack_) due = (std::min)(due, ack_due_);

    // A re-opened window still waiting to be heard back on. Same convention as the
    // owed ack above — the count is what arms this, so the epoch means "at once".
    if (window_announces_ > 0) due = (std::min)(due, window_due_);

    if (rto_deadline_ != kNoDeadline) due = (std::min)(due, rto_deadline_);

    // A packet the pacer is holding back. Unlike everything else here this one is
    // released by the clock alone — no acknowledgement is coming to free it — so
    // without this deadline a paced stream would sit until the keep-alive.
    if (pace_due_ != kNoDeadline) due = (std::min)(due, pace_due_);

    // Keep-alive: says we are still here, and keeps a NAT's mapping for this port
    // open. Only meaningful once the stream is up — a Syn in flight is covered by
    // the retransmission timeout above.
    if (state_ == State::Connected) due = (std::min)(due, last_send_ + kKeepAlive);

    return due;
}

void UdpStream::tick(Clock::time_point now) {
    if (state_ == State::Dead) return;

    if (now - last_recv_ >= kIdleTimeout) {
        LOG_DEBUG("udp", "Stream " << recv_id_ << " to " << remote_.to_string()
                  << " idle for " << kIdleTimeout.count() << "s; closing");
        die(CloseReason::IdleTimeout);
        flush_events();
        return;
    }

    // A window grown for a transfer that has since gone quiet goes back to where
    // it started. The limit already advertised stands — it is a promise — so this
    // only stops it being carried further once the peer resumes.
    if (window_ > initial_window_ && reorder_.empty() && have_recv_ &&
        now - largest_recv_at_ >= kWindowDecay) {
        window_     = initial_window_;
        have_grown_ = false;
    }

    if (rto_deadline_ != kNoDeadline && now >= rto_deadline_) {
        on_rto(now);
        if (state_ == State::Dead) { flush_events(); return; }
    }

    // A delayed acknowledgement that has come due — or one carrying no deadline at
    // all, which is how read() asks for a window update. That case deliberately has
    // no deadline to wait out: the peer is stopped on a window of zero and will send
    // nothing for an acknowledgement to ride on, so an ack sent from here is the
    // only thing that can tell it to start again.
    // A window we re-opened that the peer has not answered. It is stopped, so it
    // will not produce a packet for the update to ride on however long we wait —
    // the announcement has to be volunteered, and volunteered again if it is lost.
    if (window_announces_ > 0 && now >= window_due_) {
        need_ack_ = true;
        ack_due_  = kNoDeadline;   // at once, for the same reason read() leaves it so
    }

    if (need_ack_ && (ack_due_ == kNoDeadline || now >= ack_due_)) {
        send_control(rudp::PacketType::Ack, now);
        // That one carried the window. Space the rest by the retransmission
        // timeout: it is this side's own estimate of how long an answer would take
        // to come back, and asking again sooner would only ask twice.
        if (window_announces_ > 0) {
            --window_announces_;
            window_due_ = now + rtt_.rto;
        }
    } else if (state_ == State::Connected && now - last_send_ >= kKeepAlive) {
        // Say something now and then: it keeps the peer's idle timer from firing
        // and, just as importantly, keeps a NAT's mapping for this port alive.
        send_control(rudp::PacketType::Ack, now);
    }

    pump(now);
    flush_events();
}

void UdpStream::die(CloseReason reason) {
    if (state_ == State::Dead) return;
    state_        = State::Dead;
    close_reason_ = reason;
    sent_.clear();
    unsent_.clear();
    reorder_.clear();
    if (budget_) budget_->release(held_bytes_);
    held_bytes_ = 0;
    spare_.clear();
    flight_bytes_ = 0;
    queued_bytes_ = 0;
    rto_deadline_ = kNoDeadline;
    pace_due_     = kNoDeadline;
    pace_tokens_  = 0;
    lost_pending_    = 0;
    lost_.clear();
    repairs_.clear();
    repairs_head_ = 0;
    sacked_in_queue_ = 0;
    recovery_credit_ = 0;
    std::fill(held_.begin(), held_.end(), 0);
    range_count_     = 0;
    ranges_dirty_    = false;
    window_announces_ = 0;   // nobody is waiting on a window this stream will never serve
    raise(PollErr);
}

void UdpStream::flush_events() {
    if (events_ == 0) return;
    const uint32_t events = events_;
    events_ = 0;
    host_.stream_events(*this, events);
}

} // namespace librats
