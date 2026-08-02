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
    for (uint32_t i = 0; i < 32; ++i)
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

    pkt.sends++;
    pkt.sent_at = now;
    last_send_  = now;

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

bool UdpStream::can_transmit() const noexcept {
    if (state_ != State::Connected) return false;   // nothing may overtake the Syn
    if (unsent_.empty()) return false;
    // Always allow one packet out. This keeps a stream from deadlocking when the
    // window shrinks below a single packet, and doubles as the zero-window probe:
    // the lone in-flight packet is retransmitted on the RTO until the peer opens
    // up again, which is exactly what a persist timer does.
    if (sent_.empty()) return true;
    if (sent_.size() >= peer_window_) return false;
    if (sent_.size() >= rudp::kMaxWindowPackets) return false;
    return flight_bytes_ + unsent_.front().size() <= cwnd_;
}

void UdpStream::pump(Clock::time_point now) {
    while (can_transmit()) {
        OutPacket pkt = std::move(unsent_.front());
        unsent_.pop_front();
        pkt.seq = next_seq_++;

        flight_bytes_ += pkt.size();
        sent_.push_back(std::move(pkt));
        transmit(sent_.back(), now);
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
    while (!sent_.empty() && rudp::seq_le(sent_.front().seq, p.ack)) {
        OutPacket& front = sent_.front();
        // Karn's rule: a packet that was retransmitted cannot say which copy this
        // ack answers, so it contributes no round-trip sample. Nor does one that a
        // selective ack already retired — its real round trip was over when that
        // SACK arrived, and measuring it against this later cumulative ack would
        // inflate the estimate by however long the hole in front of it took to
        // fill, which is exactly when a *tight* RTO matters most.
        if (front.sends == 1 && !front.acked) sample_rtt(now - front.sent_at);

        if (!front.acked) {
            flight_bytes_ -= front.size();
            queued_bytes_ -= front.size();
            newly_acked   += front.size();
        }
        recycle(front);
        sent_.pop_front();
    }

    // The episode ends once everything that was outstanding when the loss was
    // detected has been acknowledged (the NewReno recovery point). Until then the
    // window has already been reduced for it and must not be reduced again.
    if (in_recovery_ && rudp::seq_le(recover_seq_, p.ack)) in_recovery_ = false;

    if (p.has_sack() && !sent_.empty()) {
        // Every packet in the queue occupies exactly one sequence number, so the
        // packet a bit refers to is found by subtraction rather than by search.
        const uint32_t base = p.ack + 2;
        for (uint32_t i = 0; i < 32; ++i) {
            if ((p.sack & (1u << i)) == 0) continue;
            const int32_t idx = rudp::seq_diff(base + i, sent_.front().seq);
            if (idx < 0 || static_cast<size_t>(idx) >= sent_.size()) continue;
            OutPacket& pkt = sent_[static_cast<size_t>(idx)];
            if (pkt.acked) continue;
            pkt.acked      = true;
            flight_bytes_ -= pkt.size();
            queued_bytes_ -= pkt.size();
        }
    }

    // Selective acks name what got through, which by elimination names what did
    // not. Repairing those now is the difference between recovering a lossy
    // window in one round trip and unpicking it one duplicate-ack at a time.
    if (p.has_sack()) repair_sacked_holes(now);

    if (newly_acked > 0) {
        dup_acks_      = 0;
        last_ack_recv_ = p.ack;
        grow_window(newly_acked);
        // Progress means the path is alive: drop back to the estimated RTO,
        // undoing any doubling a previous timeout applied.
        if (have_rtt_) rto_ = clamp_duration(srtt_ + 4 * rttvar_, kMinRto, kMaxRto);
    } else if (p.ack == last_ack_recv_ && p.ack != 0 && !sent_.empty()) {
        // The cumulative ack stood still while the peer kept talking: packets are
        // arriving past a hole. Three of those is the classic loss signal, and
        // repairing it now saves a whole retransmission timeout.
        if (++dup_acks_ == 3) {
            enter_recovery();
            transmit(sent_.front(), now);
            ++retransmits_;
        }
    }
}

void UdpStream::repair_sacked_holes(Clock::time_point now) {
    // Everything before the highest selectively acknowledged packet has had its
    // chance: the peer received something sent *after* it, so it is not merely
    // late. Three packets of margin is the usual allowance for reordering — the
    // same threshold the duplicate-ack rule uses, for the same reason.
    int highest_acked = -1;
    for (size_t i = 0; i < sent_.size(); ++i)
        if (sent_[i].acked) highest_acked = static_cast<int>(i);
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

    if (p.seq == recv_next_) {
        ++unacked_packets_;
        deliver(p.payload, p.type == rudp::PacketType::Fin);
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
    held.payload = p.payload.to_bytes();
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
    // traffic that will never come while it is stopped.
    if (before == 0 && advertised_window() > 0) need_ack_ = true;
    return n;
}

// ── Timing, congestion control, lifecycle ───────────────────────────────────

void UdpStream::sample_rtt(Clock::duration rtt) {
    if (rtt < Clock::duration::zero()) return;

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

void UdpStream::grow_window(size_t acked_bytes) {
    if (cwnd_ < ssthresh_) {
        cwnd_ += static_cast<uint32_t>((std::min)(acked_bytes, size_t{rudp::kMaxPayload} * 2));
    } else {
        // Additive increase: one packet per window, spread over the acks that
        // make up that window.
        const uint64_t inc = static_cast<uint64_t>(rudp::kMaxPayload) * acked_bytes / cwnd_;
        cwnd_ += static_cast<uint32_t>(inc > 0 ? inc : 1);
    }
    cwnd_ = (std::min)(cwnd_, kMaxCwnd);
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

    if (!sent_.empty()) {
        OutPacket& front = sent_.front();
        if (front.sends > 0 && now - front.sent_at >= rto_) {
            const int cap = (state_ == State::SynSent) ? kSynMaxAttempts : kMaxRetransmits;
            if (front.sends >= cap) {
                die(state_ == State::SynSent ? CloseReason::ConnectFailed : CloseReason::PeerReset);
                flush_events();
                return;
            }
            // A timeout is the stronger signal and always collapses the window,
            // even mid-recovery — but it also restarts the episode, so the
            // selective acks that come back as the pipe refills do not each take
            // another halving out of a window that is already down to one packet.
            on_loss(true);
            in_recovery_ = true;
            recover_seq_ = next_seq_ - 1;
            transmit(front, now);
            ++retransmits_;
            // Exponential backoff, so a path that is down is probed ever more
            // cheaply instead of being hammered.
            rto_ = clamp_duration(rto_ * 2, kMinRto, kMaxRto);
        }
    }

    if (need_ack_ && ack_due_ != kNoDeadline && now >= ack_due_) {
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
    raise(PollErr);
}

void UdpStream::flush_events() {
    if (events_ == 0) return;
    const uint32_t events = events_;
    events_ = 0;
    host_.stream_events(*this, events);
}

} // namespace librats
