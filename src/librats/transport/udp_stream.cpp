#include "librats/transport/udp_stream.h"
#include "librats/core/io_poller.h"   // PollIn / PollOut / PollErr
#include "librats/util/logger.h"

#include <algorithm>
#include <cstring>

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

} // namespace

UdpStream::UdpStream(UdpStreamHost& host, const Address& remote, uint32_t recv_id,
                     uint32_t send_id, ConnRole role, Clock::time_point now)
    : host_(host), remote_(remote), recv_id_(recv_id), send_id_(send_id), role_(role),
      state_(role == ConnRole::Outbound ? State::SynSent : State::Connected),
      last_recv_(now), last_send_(now) {
    pace_last_      = now;
    pace_tokens_    = kPaceMinBurst;   // nothing to pace against until the first RTT sample
    // Seeded rather than left at the epoch: a sentinel there would collide with a
    // clock whose zero is a real instant, which is exactly what a test driving
    // virtual time hands us.
    last_data_send_ = now;
    hystart_reset();

    if (role_ != ConnRole::Outbound) return;

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
    pkt.buf.resize(rudp::kMaxHeaderSize);     // reserve the headroom transmit() writes into
    return pkt;
}

void UdpStream::recycle(OutPacket& pkt) {
    if (spare_.size() >= kMaxSpareBuffers) return;
    pkt.buf.clear();
    spare_.push_back(std::move(pkt.buf));
}

uint16_t UdpStream::advertised_window() const noexcept {
    // What we are still willing to buffer: the reorder slots a gap is holding,
    // plus whatever the connection has not read out of the in-order buffer yet.
    const size_t used = reorder_.size() + inbox_.size() / rudp::kMaxPayload;
    if (used >= rudp::kMaxWindowPackets) return 0;
    return static_cast<uint16_t>(rudp::kMaxWindowPackets - used);
}

void UdpStream::fill_common(rudp::Packet& p) const {
    p.conn_id = send_id_;
    p.window  = advertised_window();
    // Cumulative: the highest sequence number received with no gap before it.
    // recv_next_ is the first one still missing, so the ack is the one before it
    // (0 while nothing has arrived — sequence numbers start at 1).
    p.ack = recv_next_ - 1;

    if (reorder_.empty()) return;

    const uint32_t bits = sack_bitmap();
    if (bits != 0) {
        p.flags |= rudp::FlagSack;
        p.sack = bits;
    }
}

uint32_t UdpStream::sack_bitmap() const noexcept {
    if (!sack_dirty_) return sack_bits_;

    // Selective ack: bit i covers ack+2+i, i.e. the 32 packets that follow the
    // hole at recv_next_. Derived from the reorder buffer and recv_next_ alone, so
    // it is rebuilt only when one of those moves — not on every packet sent.
    uint32_t bits = 0;
    for (uint32_t i = 0; i < rudp::kSackBits; ++i)
        if (reorder_.count(recv_next_ + 1 + i)) bits |= (1u << i);

    sack_bits_  = bits;
    sack_dirty_ = false;
    return bits;
}

void UdpStream::transmit(OutPacket& pkt, Clock::time_point now) {
    rudp::Packet p;
    p.type = pkt.type;
    fill_common(p);   // may raise FlagSack, which is what decides the header length
    p.seq = pkt.seq;

    // The payload is already sitting in pkt.buf behind kMaxHeaderSize bytes of
    // headroom, so the header goes in immediately ahead of it and the datagram
    // leaves as one contiguous range. Nothing is copied here — not on the first
    // transmission, and not on any retransmission.
    const size_t   hdr   = rudp::header_size(p);
    uint8_t* const start = pkt.buf.data() + (rudp::kMaxHeaderSize - hdr);
    rudp::encode_header(p, start);

    host_.send_datagram(remote_, start, hdr + pkt.size());

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
    if (!pkt.in_flight) {
        pkt.in_flight  = true;
        flight_bytes_ += pkt.size();
    }
    // RFC 6298 (5.1): something is outstanding, so the timer has to be running —
    // set to whichever of the probe and the timeout comes first (see loss_timeout).
    if (rto_deadline_ == kNoDeadline) rto_deadline_ = now + loss_timeout();

    pkt.sends++;
    pkt.sent_at     = now;
    last_send_      = now;
    // Data, not a bare acknowledgement — this is the clock the idle-restart rule
    // reads, and the keep-alive must not be allowed to keep resetting it.
    last_data_send_ = now;

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
    fill_common(p);
    // A control packet consumes no sequence number: it carries the next one we
    // *will* use, purely so a peer can see where the stream stands. Nothing
    // retransmits it — a lost ack is repaired by the next one.
    p.seq = next_seq_;

    host_.send_datagram(remote_, buf, rudp::encode(p, buf));

    last_send_       = now;
    need_ack_        = false;
    unacked_packets_ = 0;
    ack_due_         = kNoDeadline;
}

bool UdpStream::cwnd_allows(size_t bytes) const noexcept {
    // Always allow one packet out when the path is idle. This keeps a stream from
    // deadlocking when the window shrinks below a single packet, and doubles as the
    // zero-window probe: the lone in-flight packet is retransmitted on the RTO until
    // the peer opens up again, which is exactly what a persist timer does.
    if (flight_bytes_ == 0) return true;
    return flight_bytes_ + bytes <= cwnd_;
}

bool UdpStream::window_allows() const noexcept {
    if (state_ != State::Connected) return false;   // nothing may overtake the Syn
    if (unsent_.empty()) return false;
    if (sent_.empty()) return true;
    if (sent_.size() >= peer_window_) return false;
    if (sent_.size() >= rudp::kMaxWindowPackets) return false;
    return cwnd_allows(unsent_.front().size());
}

bool UdpStream::can_transmit() const noexcept {
    if (!window_allows()) return false;
    return pace_allows(unsent_.front().size());
}

// ── Pacing ──────────────────────────────────────────────────────────────────

uint64_t UdpStream::pace_window() const noexcept {
    // No round-trip estimate, no rate: there is nothing to derive a pace from,
    // and the window at that point is four packets, which cannot hurt anyone.
    if (!have_rtt_ || srtt_ <= Clock::duration::zero()) return 0;

    // The cautious phase grows at a quarter of slow start, so it does not need
    // slow start's doubling headroom.
    const bool doubling = in_slow_start() && !css_;
    const uint32_t num = doubling ? kPaceGainSlowStartNum : kPaceGainSteadyNum;
    const uint32_t den = doubling ? kPaceGainSlowStartDen : kPaceGainSteadyDen;
    return static_cast<uint64_t>(cwnd_) * num / den;
}

uint64_t UdpStream::pace_bytes_over(Clock::duration dt) const noexcept {
    const uint64_t window = pace_window();
    if (window == 0 || dt <= Clock::duration::zero()) return 0;

    // window * dt / srtt. The caller clamps dt to a second and a window is at
    // most ~1.2 MB, so the product stays four orders of magnitude inside 64 bits.
    const auto dt_ns   = std::chrono::duration_cast<std::chrono::nanoseconds>(dt).count();
    const auto srtt_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(srtt_).count();
    if (srtt_ns <= 0) return 0;
    return window * static_cast<uint64_t>(dt_ns) / static_cast<uint64_t>(srtt_ns);
}

void UdpStream::pace_accrue(Clock::time_point now) {
    auto dt = now - pace_last_;
    if (dt < Clock::duration::zero()) dt = Clock::duration::zero();
    // The bucket is capped a few lines below, so integrating over a long silence
    // buys nothing — and the clamp is what keeps the multiplication finite.
    const auto cap = std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1));
    if (dt > cap) dt = cap;
    pace_last_ = now;

    if (pace_window() == 0) {
        // Not pacing yet. Keep the bucket at the floor rather than at zero, so
        // the first packet after the first round-trip sample is not held back by
        // an empty bucket the stream never had a chance to fill.
        pace_tokens_ = kPaceMinBurst;
        return;
    }

    pace_tokens_ += pace_bytes_over(dt);
    const uint64_t burst = (std::max)(static_cast<uint64_t>(kPaceMinBurst),
                                      pace_bytes_over(kPaceQuantum));
    if (pace_tokens_ > burst) pace_tokens_ = burst;
}

bool UdpStream::pace_allows(size_t bytes) const noexcept {
    if (pace_window() == 0) return true;   // no estimate to pace against
    // Never hold back a stream with an empty pipe. That covers the zero-window
    // persist probe, the lone packet a recovering stream is allowed, and the
    // first packet after an idle period — none of which can congest anything,
    // and all of which would deadlock if a rate derived from an empty pipe were
    // allowed to refuse them.
    if (flight_bytes_ == 0) return true;
    return pace_tokens_ >= bytes;
}

UdpStream::Clock::duration UdpStream::pace_wait(size_t bytes) const noexcept {
    const uint64_t window = pace_window();
    if (window == 0 || pace_tokens_ >= bytes) return Clock::duration::zero();

    const uint64_t deficit = static_cast<uint64_t>(bytes) - pace_tokens_;
    const auto     srtt_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(srtt_).count();
    if (srtt_ns <= 0) return Clock::duration::zero();

    // The inverse of pace_bytes_over(): how long this many bytes take to accrue.
    const uint64_t wait_ns = deficit * static_cast<uint64_t>(srtt_ns) / window;
    return std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(wait_ns));
}

void UdpStream::restart_after_idle(Clock::time_point now) {
    // Only with the pipe genuinely empty. While anything is outstanding the
    // window describes a path we are actively measuring, and is not stale.
    if (flight_bytes_ != 0) return;
    if (cwnd_ <= kInitialCwnd) return;   // nothing to give back

    const auto idle = now - last_data_send_;
    if (idle < rto_) return;

    // RFC 2861. A congestion window is a measurement, and one nobody has
    // validated for a round trip is a guess about a path we stopped watching. The
    // shape of P2P traffic makes this the common case rather than the corner one
    // — silence, a burst of gossip, silence — and without this the burst goes out
    // at a rate justified by what the path looked like ten seconds ago.
    //
    // Halve once per timeout of silence, down to the window a fresh stream would
    // start with. ssthresh is deliberately untouched: it records where this path
    // congested, and going quiet does not make that wrong — keeping it is what
    // lets the stream climb back in slow start instead of re-running the whole
    // discovery from scratch.
    const auto rto_ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(rto_).count();
    const auto idle_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(idle).count();
    const uint64_t halvings = rto_ns > 0 ? static_cast<uint64_t>(idle_ns / rto_ns) : 32;

    cwnd_ = halvings >= 32 ? kInitialCwnd
                           : (std::max)(cwnd_ >> halvings, kInitialCwnd);

    // Consume the silence that was just paid for. Without this the *same* elapsed
    // time is re-read on every tick and halves an already-halved window again, so
    // a window would decay per tick rather than per timeout — far faster than
    // intended, and enough to undo a healthy window during an ordinary lull.
    last_data_send_ += Clock::duration(rto_ * static_cast<Clock::rep>(halvings));

    // The bucket describes a rate that no longer applies either. Zeroing it (and
    // the clock behind it) means the stream releases the one packet an empty pipe
    // always allows and then paces the rest at the restarted rate, instead of
    // spending a burst allowance earned while it was silent.
    pace_tokens_ = 0;
    pace_last_   = now;
}

void UdpStream::retransmit_lost(Clock::time_point now) {
    // The flag keeps this off the hot path entirely: without it the scan below
    // would walk the whole retransmission queue on every acknowledgement of a
    // healthy transfer — a window's worth of packets, every time — to discover
    // that there is nothing to repair.
    if (!have_lost_) return;

    // Packets a timeout has given up on: still owed to the peer, no longer counted
    // against the window. They are re-sent from the front, under whatever the
    // congestion window currently allows — so the pipe refills at the rate the
    // recovering window dictates instead of all at once, and a hole is always
    // repaired before anything queued behind it is sent.
    for (OutPacket& pkt : sent_) {
        if (pkt.acked || pkt.in_flight) continue;  // the peer has it, or it is already back out
        if (pkt.sends == 0) continue;              // never sent; pump() owns it
        if (!cwnd_allows(pkt.size())) return;      // more still owed: come back with a bigger window
        transmit(pkt, now);
        ++retransmits_;
    }
    have_lost_ = false;  // the scan reached the end, so nothing is waiting to go back out
}

void UdpStream::pump(Clock::time_point now) {
    // A window that has gone unused for a round trip is stale before anything
    // else here reads it, so this comes first.
    restart_after_idle(now);
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
}

size_t UdpStream::write(const ByteView* slices, size_t count, Clock::time_point now) {
    if (state_ != State::Connected || fin_queued_) return 0;

    size_t budget = queued_bytes_ >= kSendQueueLimit ? 0 : kSendQueueLimit - queued_bytes_;
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

    peer_window_ = p.window;

    bool ack_now = (p.type == rudp::PacketType::Syn || p.type == rudp::PacketType::Fin);

    handle_ack(p, now);

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
        const uint32_t before = recv_next_;
        handle_sequenced(p);
        // A packet that did not fill the gap it was expected to means the peer is
        // missing something: say so at once rather than waiting out the delayed
        // ack, since that ack is what triggers its fast retransmit.
        if (recv_next_ == before) ack_now = true;
    }

    pump(now);

    // The connection asked to be told when it could write again, and an ack just
    // freed queue space.
    if (want_write_ && state_ == State::Connected && queued_bytes_ < kSendQueueLimit)
        raise(PollOut);

    if (need_ack_) {
        // Acknowledge every second packet even without a hole (the classic
        // ack-every-other-segment rule), so a bulk sender's window keeps opening
        // without a round trip's worth of delay per packet.
        if (ack_now || unacked_packets_ >= 2) send_control(rudp::PacketType::Ack, now);
        else if (ack_due_ == kNoDeadline)     ack_due_ = now + kDelayedAck;
    }

    flush_events();
}

void UdpStream::handle_ack(const rudp::Packet& p, Clock::time_point now) {
    // An ack past the highest sequence number we have ever assigned is nonsense;
    // honouring it would retire packets that were never sent.
    if (rudp::seq_less(next_seq_ - 1, p.ack)) return;

    size_t newly_acked = 0;
    size_t retired     = 0;   ///< packets the cumulative ack removed from the queue
    while (!sent_.empty() && rudp::seq_le(sent_.front().seq, p.ack)) {
        OutPacket& front = sent_.front();
        // Karn's rule: a packet that was retransmitted cannot say which copy this
        // ack answers, so it contributes no round-trip sample. Nor does one that a
        // selective ack already retired — its real round trip was over when that
        // SACK arrived, and measuring it against this later cumulative ack would
        // inflate the estimate by however long the hole in front of it took to
        // fill, which is exactly when a *tight* RTO matters most.
        if (front.sends == 1 && !front.acked) sample_rtt(now - front.sent_at);

        if (front.in_flight) {
            flight_bytes_   -= front.size();
            front.in_flight  = false;
        }
        // A packet a selective ack already retired left the queue's accounting then;
        // one a timeout gave up on left only the *flight* accounting, and still owes
        // its bytes to queued_bytes_ — which is why the two are settled separately.
        if (!front.acked) {
            queued_bytes_ -= front.size();
            newly_acked   += front.size();
        }
        recycle(front);
        sent_.pop_front();
        ++retired;
    }

    // The episode ends once everything that was outstanding when the loss was
    // detected has been acknowledged (the NewReno recovery point). Until then the
    // window has already been reduced for it and must not be reduced again.
    if (in_recovery_ && rudp::seq_le(recover_seq_, p.ack)) in_recovery_ = false;

    if (p.has_sack() && !sent_.empty()) {
        // Every packet in the queue occupies exactly one sequence number, so the
        // packet a bit refers to is found by subtraction rather than by search.
        const uint32_t base = p.ack + 2;
        for (uint32_t i = 0; i < rudp::kSackBits; ++i) {
            if ((p.sack & (1u << i)) == 0) continue;
            const int32_t idx = rudp::seq_diff(base + i, sent_.front().seq);
            if (idx < 0 || static_cast<size_t>(idx) >= sent_.size()) continue;
            OutPacket& pkt = sent_[static_cast<size_t>(idx)];
            if (pkt.acked) continue;
            pkt.acked = true;
            if (pkt.in_flight) {
                flight_bytes_  -= pkt.size();
                pkt.in_flight   = false;
            }
            queued_bytes_ -= pkt.size();
        }
    }

    // Selective acks name what got through, which by elimination names what did
    // not. Repairing those now is the difference between recovering a lossy
    // window in one round trip and unpicking it one duplicate-ack at a time.
    if (p.has_sack()) repair_sacked_holes(now);

    if (newly_acked > 0) {
        dup_acks_      = 0;
        tail_probes_   = 0;   // the peer answered; this silence is over
        last_ack_recv_ = p.ack;
        grow_window(newly_acked);
        // After the window moves, not before: the round-trip rise HyStart++ acts
        // on is only meaningful against the window that produced it.
        hystart_on_ack(p.ack);
        // Progress means the path is alive: drop back to the estimated RTO,
        // undoing any doubling a previous timeout applied.
        if (have_rtt_) rto_ = clamp_duration(srtt_ + 4 * rttvar_, kMinRto, kMaxRto);
    } else if (p.type == rudp::PacketType::Ack && p.ack == last_ack_recv_ && p.ack != 0 &&
               !sent_.empty()) {
        // A *pure* ack whose cumulative number stood still: the peer is receiving
        // packets past a hole and re-reporting the same edge. Three of those is the
        // classic loss signal, and repairing it now saves a whole retransmission
        // timeout.
        //
        // The type check is what makes this a loss signal rather than a coincidence,
        // and RFC 5681 defines a duplicate ack that way for exactly this reason. Every
        // packet here carries the ack field, so on a two-way stream the peer's own
        // Data rides over the same number until our next packet reaches it — three of
        // *those* say nothing about loss, they only say the peer had something of its
        // own to send. Counting them halved the window and re-sent a packet that was
        // merely still in flight, on a stream where nothing had been dropped at all —
        // which on a peer-to-peer link (gossip during a transfer, any request while a
        // response streams back) is the normal case rather than the corner one.
        //
        // Nothing is lost by being strict: a hole makes the receiver acknowledge at
        // once (see on_packet), so a one-way flow still produces the pure acks this
        // counts, and a two-way one is covered by repair_sacked_holes() above, which
        // names the missing packets outright instead of inferring them.
        if (++dup_acks_ == 3) {
            enter_recovery();
            transmit(sent_.front(), now);
            ++retransmits_;
        }
    }

    // RFC 6298 (5.2/5.3): the timer restarts whenever the cumulative ack retires
    // something, and stops once nothing is outstanding. Counted in packets rather
    // than bytes, because a Syn and a Fin each occupy a sequence number while
    // carrying no payload — a byte count would leave the timer running on the
    // deadline the *handshake* set, which is neither the one the first data packet
    // deserves nor one anything else will correct.
    if (retired > 0) rto_deadline_ = sent_.empty() ? kNoDeadline : now + loss_timeout();
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
    syn.buf.resize(rudp::kMaxHeaderSize);
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
    rto_deadline_ = now + rto_;
    transmit(syn, now);

    LOG_DEBUG("udp", "Stream " << recv_id_ << " re-dialing " << remote_.to_string()
              << " with an address-validation cookie");
}

void UdpStream::repair_sacked_holes(Clock::time_point now) {
    // Everything before the highest selectively acknowledged packet has had its
    // chance: the peer received something sent *after* it, so it is not merely
    // late. Three packets of margin is the usual allowance for reordering — the
    // same threshold the duplicate-ack rule uses, for the same reason.
    //
    // The search is bounded by the reach of a selective ack rather than by the
    // length of the queue. A bit can only ever mark the kSackBits packets after
    // the hole — handle_ack() resolves bit i to index (p.ack + 2 + i) - front,
    // and the cumulative retire above leaves front at exactly p.ack + 1, so the
    // highest index it can set is kSackBits — and an index only ever moves *down*
    // as the queue drains from the front. So nothing past that window can carry
    // the flag, and walking the whole queue to discover it (a full window of
    // packets, on every acknowledgement of a loss episode — which is when they
    // are at their most frequent) was searching where the answer cannot be.
    // Backwards inside that window, so the common case returns on the first hit.
    const size_t limit = (std::min)(sent_.size(), size_t{rudp::kSackBits} + 1);
    int highest_acked = -1;
    for (size_t i = limit; i-- > 0;) {
        if (sent_[i].acked) { highest_acked = static_cast<int>(i); break; }
    }
    if (highest_acked < 3) return;

    const auto spacing = (std::max)(std::chrono::duration_cast<Clock::duration>(kMinRepairSpacing),
                                    srtt_);

    int repaired = 0;
    for (int i = 0; i + 3 <= highest_acked && repaired < kMaxRepairsPerAck; ++i) {
        OutPacket& pkt = sent_[static_cast<size_t>(i)];
        if (pkt.acked) continue;
        if (now - pkt.sent_at < spacing) continue;  // already re-sent very recently
        transmit(pkt, now);
        ++retransmits_;
        ++repaired;
    }
    // One window reduction for the whole episode — not one per packet repaired,
    // and not one per ack that repairs something. Several selective acks arrive
    // per round trip and recovery spans several round trips, so halving on each
    // of them would drive the window to the floor over a loss TCP would have
    // ridden out with a single halving. enter_recovery() enforces that.
    if (repaired > 0) enter_recovery();
}

void UdpStream::handle_sequenced(const rudp::Packet& p) {
    need_ack_ = true;

    if (rudp::seq_less(p.seq, recv_next_)) return;  // already delivered; just re-ack

    // Only Data carries stream content. A Syn occupies a sequence number like any
    // other packet, but what it carries is the address-validation cookie the mux
    // has already checked — delivering that as stream bytes would splice four bytes
    // of nonsense into the front of the peer's handshake.
    const ByteView body = (p.type == rudp::PacketType::Data) ? p.payload : ByteView{};

    if (p.seq == recv_next_) {
        ++unacked_packets_;
        deliver(body, p.type == rudp::PacketType::Fin);
        ++recv_next_;
        sack_dirty_ = true;   // the bitmap is relative to recv_next_, which just moved
        drain_reorder();
        return;
    }

    // Past the gap: hold it, but only within the window we advertised — anything
    // beyond that is a peer ignoring flow control, and buffering it would let one
    // peer decide how much memory we spend.
    const int32_t ahead = rudp::seq_diff(p.seq, recv_next_);
    if (ahead <= 0 || ahead >= rudp::kMaxWindowPackets) return;
    if (reorder_.count(p.seq)) return;

    InPacket held;
    held.payload = body.to_bytes();
    held.fin     = (p.type == rudp::PacketType::Fin);
    reorder_.emplace(p.seq, std::move(held));
    sack_dirty_ = true;
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
        reorder_.erase(it);
        ++recv_next_;
        sack_dirty_ = true;
    }
}

size_t UdpStream::read(uint8_t* into, size_t len) {
    const size_t n = (std::min)(len, inbox_.size());
    if (n == 0) return 0;

    std::memcpy(into, inbox_.data(), n);
    const uint16_t before = advertised_window();
    inbox_.consume(n);
    // Draining the buffer may have re-opened a window we had advertised as full.
    // The peer is waiting on that number, so it has to be told without waiting for
    // traffic that will never come while it is stopped — hence an owed ack with no
    // deadline attached, which the next tick() sends outright rather than holding
    // for company (see there). Leaving ack_due_ unset is the *signal*, not an
    // omission: everything else that owes an ack has a packet of its own to wait for.
    if (before == 0 && advertised_window() > 0) need_ack_ = true;
    return n;
}

// ── Timing, congestion control, lifecycle ───────────────────────────────────

void UdpStream::sample_rtt(Clock::duration rtt) {
    if (rtt < Clock::duration::zero()) return;

    hystart_sample(rtt);

    if (!have_rtt_) {
        srtt_     = rtt;
        rttvar_   = rtt / 2;
        have_rtt_ = true;
    } else {
        // RFC 6298: rttvar = 3/4 rttvar + 1/4 |srtt - r| ; srtt = 7/8 srtt + 1/8 r.
        const auto err = srtt_ > rtt ? srtt_ - rtt : rtt - srtt_;
        rttvar_ = (rttvar_ * 3 + err) / 4;
        srtt_   = (srtt_ * 7 + rtt) / 8;
    }
    rto_ = clamp_duration(srtt_ + 4 * rttvar_, kMinRto, kMaxRto);
}

void UdpStream::enter_recovery() {
    if (in_recovery_) return;   // already paid for this episode
    in_recovery_ = true;
    // Everything assigned a sequence number so far is what has to be acknowledged
    // before the episode is over. next_seq_ is the number the *next* packet will
    // take, so the highest one outstanding is one below it.
    recover_seq_ = next_seq_ - 1;
    on_loss(false);
}

void UdpStream::on_loss(bool timeout) {
    ++window_reductions_;
    // A loss settles the question the cautious phase was asking, and settles it
    // the expensive way. Whatever slow start is entered from here starts its
    // round-trip comparison afresh rather than against a queue that has since
    // drained.
    css_ = false;
    if (timeout) {
        // A timeout says the path is congested enough to have dropped everything
        // in flight: back down to one packet and re-probe from there.
        ssthresh_ = (std::max)(static_cast<uint32_t>(flight_bytes_ / 2), kMinCwnd);
        cwnd_     = rudp::kMaxPayload;
    } else {
        // A fast retransmit means packets are still flowing, so halve rather than
        // collapse.
        ssthresh_ = (std::max)(cwnd_ / 2, kMinCwnd);
        cwnd_     = ssthresh_;
    }
}

UdpStream::Clock::duration UdpStream::probe_timeout() const noexcept {
    if (!have_rtt_) return kInitialRto;

    // RFC 9002's PTO: a round trip, the variance allowance, and the time the peer
    // is entitled to hold an acknowledgement back for. The last term is what stops
    // the probe racing our own delayed-ack rule and calling a slow peer a lost one.
    const auto granularity = std::chrono::duration_cast<Clock::duration>(kMinProbeTimeout) / 8;
    auto pto = srtt_ + (std::max)(4 * rttvar_, granularity)
                     + std::chrono::duration_cast<Clock::duration>(kDelayedAck);

    // Doubled per consecutive probe: if the first went unanswered the path is
    // worse than the estimate said, and asking again at the same spacing would
    // just be asking twice.
    for (int i = 0; i < tail_probes_ && pto < std::chrono::duration_cast<Clock::duration>(kMaxRto); ++i)
        pto *= 2;

    return clamp_duration(pto, kMinProbeTimeout, kMaxRto);
}

UdpStream::Clock::duration UdpStream::loss_timeout() const noexcept {
    if (state_ != State::Connected || tail_probes_ >= kMaxTailProbes) return rto_;

    // Never later than the timeout it stands in front of. A probe exists to ask
    // the question *sooner* and more cheaply than the retransmission timeout would
    // — on a path whose round trip is long enough that the probe interval exceeds
    // the timeout, waiting for the probe would be pure added delay. Capped, the
    // worst case is that it fires exactly when the timeout would have, and the
    // stream still keeps its window instead of collapsing it.
    return (std::min)(probe_timeout(), rto_);
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

    const int cap = (state_ == State::SynSent) ? kSynMaxAttempts : kMaxRetransmits;
    if (oldest->sends >= cap) {
        die(state_ == State::SynSent ? CloseReason::ConnectFailed : CloseReason::PeerReset);
        return;
    }

    // A timeout is the stronger signal and always collapses the window, even
    // mid-recovery — but it also restarts the episode, so the selective acks that
    // come back as the pipe refills do not each take another halving out of a
    // window that is already down to one packet. (on_loss reads flight_bytes_, so
    // it has to run before the accounting below is undone.)
    // Tail loss probe, before any of the above is believed. The peer has gone
    // quiet, which on a stream whose last packet was lost is indistinguishable
    // from a peer that is merely slow — and the two call for opposite responses.
    // So ask first: re-send what it has not acknowledged, change nothing else,
    // and let the answer decide. A probe that was unnecessary costs one packet;
    // the collapse below, taken wrongly, costs the whole window.
    //
    // Deliberately not for a dial: a Syn has its own, tighter attempt budget that
    // the transport race depends on (see kSynMaxAttempts).
    if (state_ == State::Connected && tail_probes_ < kMaxTailProbes) {
        ++tail_probes_;
        transmit(*oldest, now);
        ++retransmits_;
        rto_deadline_ = now + loss_timeout();   // backed off, still capped by the RTO
        return;
    }

    on_loss(true);
    in_recovery_ = true;
    recover_seq_ = next_seq_ - 1;

    // Everything outstanding has had a full retransmission timeout to arrive and
    // nothing acknowledged it, so it is presumed lost and stops occupying the path.
    //
    // This step is what makes recovery possible at all. Leaving the bytes counted
    // would leave flight_bytes_ holding a whole window while cwnd_ is back down to
    // one packet, and cwnd_allows() — the gate every transmission goes through —
    // would refuse for as long as those packets sat in the queue. The sender would
    // then crawl forward one packet per timeout, unable to grow the window or
    // repair the rest, until the transfer effectively stopped.
    for (OutPacket& pkt : sent_) {
        if (!pkt.in_flight) continue;
        pkt.in_flight  = false;
        flight_bytes_ -= pkt.size();
        have_lost_     = true;
    }

    // Exponential backoff, so a path that is down is probed ever more cheaply
    // instead of being hammered. The deadline is set from it before anything goes
    // out, so the retransmissions below do not each restart the timer.
    rto_          = clamp_duration(rto_ * 2, kMinRto, kMaxRto);
    rto_deadline_ = now + rto_;

    retransmit_lost(now);
}

void UdpStream::hystart_reset() {
    css_                = false;
    css_rounds_         = 0;
    css_baseline_rtt_   = Clock::duration::max();
    round_min_rtt_      = Clock::duration::max();
    prev_round_min_rtt_ = Clock::duration::max();
    round_samples_      = 0;
    round_end_          = next_seq_ - 1;
}

void UdpStream::hystart_sample(Clock::duration rtt) {
    // The *minimum* of the round, not the average: a queue building in front of
    // the bottleneck lifts even the luckiest packet's round trip, where an
    // average moves just as readily for one straggler that had nothing to do
    // with congestion.
    if (rtt < round_min_rtt_) round_min_rtt_ = rtt;
    ++round_samples_;
}

void UdpStream::hystart_on_ack(uint32_t ack) {
    // Only slow start is in question. Congestion avoidance has already found its
    // ceiling and climbs a packet per round trip, which no queue signal improves.
    if (!in_slow_start()) { css_ = false; return; }

    // Entry: this round's best round trip has risen clear of the previous round's
    // by more than the threshold, which means a queue is forming ahead of us.
    // Leave doubling for the cautious phase rather than exiting outright — one
    // round's rise may be noise, and CSS is how that gets settled without
    // throwing the remaining growth away.
    if (!css_ && round_samples_ >= kHyRttSamples &&
        prev_round_min_rtt_ != Clock::duration::max() &&
        round_min_rtt_ != Clock::duration::max()) {
        const auto thresh = clamp_duration(prev_round_min_rtt_ / 8,
                                           kHyMinRttThresh, kHyMaxRttThresh);
        if (round_min_rtt_ >= prev_round_min_rtt_ + thresh) {
            css_              = true;
            css_rounds_       = 0;
            css_baseline_rtt_ = round_min_rtt_;
        }
    }

    if (!rudp::seq_le(round_end_, ack)) return;   // the round is still running

    const auto ended_min = round_min_rtt_;
    prev_round_min_rtt_  = ended_min;
    round_min_rtt_       = Clock::duration::max();
    round_samples_       = 0;
    round_end_           = next_seq_ - 1;

    if (!css_) return;

    // The rise did not hold — it was one round's noise. Take the caution back and
    // let slow start carry on, which is the whole reason CSS exists.
    if (ended_min != Clock::duration::max() && ended_min < css_baseline_rtt_) {
        css_ = false;
        return;
    }

    // It held long enough to believe. Stop doubling *here*, at a window the path
    // demonstrably carries — this is the point of the exercise: the ceiling is
    // found without having had to lose a window to find it.
    if (++css_rounds_ >= kHyCssRounds) {
        ssthresh_ = cwnd_;
        css_      = false;
    }
}

void UdpStream::grow_window(size_t acked_bytes) {
    if (cwnd_ < ssthresh_) {
        uint32_t inc = static_cast<uint32_t>((std::min)(acked_bytes, size_t{rudp::kMaxPayload} * 2));
        // The cautious phase probes at a quarter of slow start: still upward, so a
        // spurious signal costs almost nothing, but no longer doubling while it is
        // being decided whether the round-trip rise was a real queue.
        if (css_) inc /= kHyCssGrowthDivisor;
        cwnd_ += inc;
    } else {
        // Additive increase: one packet per window, spread over the acks that
        // make up that window.
        const uint64_t inc = static_cast<uint64_t>(rudp::kMaxPayload) * acked_bytes / cwnd_;
        cwnd_ += static_cast<uint32_t>(inc > 0 ? inc : 1);
    }
    cwnd_ = (std::min)(cwnd_, kMaxCwnd);
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

    if (rto_deadline_ != kNoDeadline && now >= rto_deadline_) {
        on_rto(now);
        if (state_ == State::Dead) { flush_events(); return; }
    }

    // A delayed acknowledgement that has come due — or one carrying no deadline at
    // all, which is how read() asks for a window update. That case deliberately has
    // no deadline to wait out: the peer is stopped on a window of zero and will send
    // nothing for an acknowledgement to ride on, so an ack sent from here is the
    // only thing that can tell it to start again.
    if (need_ack_ && (ack_due_ == kNoDeadline || now >= ack_due_)) {
        send_control(rudp::PacketType::Ack, now);
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
    spare_.clear();
    sack_bits_    = 0;
    sack_dirty_   = false;
    flight_bytes_ = 0;
    queued_bytes_ = 0;
    rto_deadline_ = kNoDeadline;
    pace_due_     = kNoDeadline;
    pace_tokens_  = 0;
    have_lost_    = false;
    raise(PollErr);
}

void UdpStream::flush_events() {
    if (events_ == 0) return;
    const uint32_t events = events_;
    events_ = 0;
    host_.stream_events(*this, events);
}

} // namespace librats
