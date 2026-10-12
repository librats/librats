#include "librats/transport/udp_connection.h"
#include "librats/core/io_poller.h"   // PollIn / PollOut / PollErr
#include "librats/transport/send_queue.h"   // priority_of
#include "librats/util/logger.h"

#include <algorithm>
#include <cstring>

namespace librats {

using namespace udp;

namespace {

using Clock = UdpConnection::Clock;
constexpr Clock::time_point kNever{};

template <typename A, typename B>
Clock::duration clamp_duration(Clock::duration v, A lo, B hi) {
    const auto low  = std::chrono::duration_cast<Clock::duration>(lo);
    const auto high = std::chrono::duration_cast<Clock::duration>(hi);
    return v < low ? low : (v > high ? high : v);
}

void put_cid(uint8_t* p, Cid cid) noexcept {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<uint8_t>(cid);
        cid >>= 8;
    }
}

} // namespace

// ── Construction and the handshake ──────────────────────────────────────────

UdpConnection::UdpConnection(UdpConnectionHost& host, SecurityProvider& security,
                             const Address& remote, ConnRole role, Cid local, Cid remote_cid,
                             Clock::time_point now, const UdpConnectionConfig& config)
    : host_(host), security_(security), remote_(remote), role_(role), local_cid_(local),
      remote_cid_(remote_cid), config_(config),
      // Seeded by the connection id, so a connection's randomised choices (BBR's
      // probe schedule) are reproducible for a given id and differ between them.
      recovery_(config.congestion, now, local),
      last_send_(now), last_eliciting_send_(now), last_recv_(now),
      recv_window_(kInitialWindow), initial_window_(kInitialWindow),
      max_window_((std::max<uint64_t>)(config.max_window, kInitialWindow)),
      last_data_recv_(now) {
    account_.shared = config.budget;
}

UdpConnection::~UdpConnection() {
    for (auto& lane : lanes_) lane->recv.clear(account_);
}

std::unique_ptr<UdpConnection> UdpConnection::dial(UdpConnectionHost& host, SecurityProvider& security,
                                                   const Address& remote, Cid local,
                                                   Clock::time_point now, UdpConnectionConfig config) {
    std::unique_ptr<UdpConnection> c(new UdpConnection(host, security, remote, ConnRole::Outbound,
                                                       local, paired_cid(local), now, config));
    // A handshake that cannot even start leaves a dead connection, which its
    // transport reports like any other failed dial.
    c->start_dial(now);
    c->flush_events();
    return c;
}

std::unique_ptr<UdpConnection> UdpConnection::accept(UdpConnectionHost& host, SecurityProvider& security,
                                                     const Address& remote, const LongPacket& initial,
                                                     size_t datagram_len, bool validated,
                                                     Clock::time_point now, UdpConnectionConfig config) {
    if (initial.type != LongType::Initial || initial.scid != paired_cid(initial.dcid)) return nullptr;
    std::unique_ptr<UdpConnection> c(new UdpConnection(host, security, remote, ConnRole::Inbound,
                                                       initial.dcid, initial.scid, now, config));
    c->heard_             = true;
    c->amp_received_      = datagram_len;
    c->address_validated_ = validated;
    c->handshaker_        = security.create(ConnRole::Inbound);

    Bytes out;
    if (!c->handshaker_->start(out)) return nullptr;
    auto oc = c->handshaker_->consume(initial.message, out);
    if (oc.status == Handshaker::Outcome::Failed || out.empty() || out.size() > kMaxHandshakeMessage)
        return nullptr;
    c->hs_expect_   = 2;
    c->hs_number_   = 1;
    c->hs_last_     = std::move(out);
    // The plaintext handshake is done on the dialer's first message.
    if (oc.status == Handshaker::Outcome::Done) c->establish(std::move(oc.session), oc.remote_id, now);
    return c;
}

bool UdpConnection::start_dial(Clock::time_point now) {
    handshaker_ = security_.create(ConnRole::Outbound);
    Bytes out;
    if (!handshaker_->start(out) || out.empty() || out.size() > kMaxHandshakeMessage) {
        die(CloseReason::HandshakeFailed);
        return false;
    }
    hs_last_   = std::move(out);
    hs_number_ = 0;
    // The dial's own retry shape (see DialProfile), clamped rather than trusted:
    // zero attempts would be a dial that never repeats, and an interval outside the
    // timer's bounds would either spin it or outlast the establish deadline.
    const DialProfile& profile = config_.dial;
    hs_max_attempts_ = (std::max)(1, profile.attempts);
    hs_backoff_      = profile.backoff;
    hs_interval_     = clamp_duration(std::chrono::milliseconds(profile.interval_ms),
                                      Recovery::kMinRto, Recovery::kMaxRto);
    send_initial(now);
    return true;
}

void UdpConnection::send_initial(Clock::time_point now) {
    uint8_t* buf = host_.datagram_buffer();
    const size_t n = encode_initial(buf, remote_cid_, local_cid_, ByteView(token_), ByteView(hs_last_));
    host_.send_datagram(remote_, n);
    last_send_   = now;
    hs_sent_at_  = now;
    ++hs_attempts_;
    hs_deadline_ = now + hs_interval_;
    if (hs_backoff_) hs_interval_ = clamp_duration(hs_interval_ * 2, Recovery::kMinRto, Recovery::kMaxRto);
}

void UdpConnection::send_handshake_message(Clock::time_point now) {
    uint8_t* buf = host_.datagram_buffer();
    const size_t n = encode_handshake(buf, remote_cid_, local_cid_, hs_number_, ByteView(hs_last_));
    if (!amplification_allows(n)) return;   // the room is simply not used
    host_.send_datagram(remote_, n);
    note_sent(n);
    hs_sent_at_ = now;
    ++hs_sends_;
}

void UdpConnection::answer(Clock::time_point now) {
    answered_ = true;
    send_handshake_message(now);
    if (established()) pump(now);
    flush_events();
}

void UdpConnection::on_long(const LongPacket& p, size_t len, Clock::time_point now) {
    (void)len;
    switch (p.type) {
        case LongType::Initial:
            // The dialer is repeating itself: our answer was lost, or is on its way.
            if (role_ == ConnRole::Inbound && answered_) send_handshake_message(now);
            return;

        case LongType::Retry:
            // "Prove you are at that address first." Honoured once, and only for a
            // dial nothing has answered yet: a second would let anyone who can
            // forge a datagram from the responder keep the dial going round forever.
            if (role_ != ConnRole::Outbound || heard_ || retried_ || p.token.size() != kTokenSize) return;
            retried_ = true;
            token_.assign(p.token.begin(), p.token.end());
            // The round trip spent proving the address is not a lost packet: it does
            // not count against the dial's attempts.
            hs_attempts_ = 0;
            send_initial(now);
            LOG_DEBUG("udp", "Dial to " << remote_.to_string() << " re-sent with an address-validation token");
            return;

        case LongType::Close:
            // Believed only while the handshake runs: afterwards a goodbye comes
            // sealed, and an unsealed one is anyone's forgery.
            if (phase_ != Phase::Handshaking) return;
            LOG_DEBUG("udp", "Handshake with " << remote_.to_string() << " refused (" << p.error << ")");
            die(CloseReason::PeerReset);
            return;

        case LongType::Handshake:
            break;
    }

    if (role_ == ConnRole::Outbound && !heard_) {
        // The dial has been answered: the path works. The round trip it took is the
        // first estimate there is — unless the Initial went more than once, when
        // nobody can say which copy this answers.
        heard_       = true;
        hs_deadline_ = kNever;
        if (hs_attempts_ == 1) recovery_.sample_rtt(now - hs_sent_at_, Clock::duration::zero());
        raise(PollOut);
    }
    last_recv_ = now;

    if (p.number < hs_expect_) {
        // A message we have already consumed, so ours in answer to it was lost.
        if (role_ == ConnRole::Outbound) {
            if (!confirmed_ && hs_number_ >= 2) send_handshake_message(now);
        } else if (established()) {
            ping_owed_ = true;   // any short packet shows the dialer we have our keys
            pump(now);
        }
        return;
    }
    if (p.number != hs_expect_ || !handshaker_) return;
    consume_handshake(p.message, now);
}

void UdpConnection::consume_handshake(ByteView message, Clock::time_point now) {
    Bytes out;
    auto oc = handshaker_->consume(message, out);
    const uint8_t consumed = hs_expect_;
    hs_expect_ = static_cast<uint8_t>(consumed + 2);   // our reply takes the number between
    if (oc.status == Handshaker::Outcome::Failed || out.size() > kMaxHandshakeMessage) {
        LOG_DEBUG("udp", "Handshake with " << remote_.to_string() << " failed");
        fail(now, CloseReason::HandshakeFailed, kCloseRefused);
        return;
    }
    if (role_ == ConnRole::Inbound) {
        // Only a dialer that received our answer could have produced this.
        address_validated_ = true;
        // Our answer's round trip, if it went once: a repeated one cannot say
        // which copy this replies to.
        if (hs_sends_ == 1) recovery_.sample_rtt(now - hs_sent_at_, Clock::duration::zero());
    }
    if (!out.empty()) {
        hs_last_   = std::move(out);
        hs_number_ = static_cast<uint8_t>(consumed + 1);
        send_handshake_message(now);
        if (role_ == ConnRole::Outbound) {
            // Repeated until the responder shows it has its keys too: its first
            // short packet stops this.
            hs_attempts_     = 1;
            hs_max_attempts_ = kMaxConfirmAttempts;
            hs_backoff_      = true;
            hs_interval_     = recovery_.probe_timeout();
            hs_deadline_     = now + hs_interval_;
        }
    }
    if (oc.status == Handshaker::Outcome::Done) establish(std::move(oc.session), oc.remote_id, now);
}

void UdpConnection::establish(std::unique_ptr<Session> session, const PeerId& remote,
                              Clock::time_point now) {
    session_   = std::move(session);
    remote_id_ = remote;
    handshaker_.reset();
    phase_     = Phase::Established;
    // A dialer with no last message to repeat finished second: the responder had
    // its keys first. A responder always has the dialer's confirmation in hand.
    if (role_ == ConnRole::Inbound || hs_number_ < 2) confirmed_ = true;
    // The responder shows the dialer it has its keys, which stops the dialer's
    // repeats; both hand the peer what a stateless reset for them will look like.
    if (role_ == ConnRole::Inbound) ping_owed_ = true;
    token_owed_ = true;
    raise(PollIn | PollOut);
    LOG_DEBUG("udp", "Connection " << local_cid_ << " to " << remote_.to_string() << " established");

    // What arrived before the keys did, in the order it came.
    std::vector<Bytes> early;
    early.swap(early_);
    for (Bytes& b : early) on_short(b.data(), b.size(), now);
    // A responder sends nothing before its answer to the Initial.
    if (role_ == ConnRole::Outbound || answered_) pump(now);
}

void UdpConnection::handshake_timer(Clock::time_point now) {
    if (hs_deadline_ == kNever || now < hs_deadline_) return;
    if (hs_attempts_ >= hs_max_attempts_) {
        LOG_DEBUG("udp", "Dial to " << remote_.to_string() << " unanswered after " << hs_attempts_
                  << " attempts");
        die(heard_ ? CloseReason::HandshakeFailed : CloseReason::ConnectFailed);
        return;
    }
    if (!heard_) {
        send_initial(now);
        return;
    }
    if (!confirmed_ && hs_number_ >= 2) {
        send_handshake_message(now);
        ++hs_attempts_;
        hs_deadline_ = now + hs_interval_;
        hs_interval_ = clamp_duration(hs_interval_ * 2, Recovery::kMinRto, Recovery::kMaxRto);
        return;
    }
    hs_deadline_ = kNever;
}

// ── Packets in ──────────────────────────────────────────────────────────────

void UdpConnection::on_datagram(uint8_t* data, size_t len, Clock::time_point now) {
    if (dead() || len == 0) return;
    // Until the dialer has proved its address, what it sends is what we may answer
    // with (three times over).
    if (role_ == ConnRole::Inbound && !address_validated_) amp_received_ += len;

    if (is_long_header(data[0])) {
        LongPacket p;
        if (decode_long(data, len, p) && p.scid == remote_cid_ && p.dcid == local_cid_) on_long(p, len, now);
    } else {
        on_short(data, len, now);
    }
    flush_events();
}

bool UdpConnection::is_reset(const uint8_t* data, size_t len) const noexcept {
    return have_peer_token_ && len >= kMinShortPacket &&
           std::memcmp(data + len - kResetTokenSize, peer_token_.data(), kResetTokenSize) == 0;
}

void UdpConnection::on_short(uint8_t* data, size_t len, Clock::time_point now) {
    if (len < kMinShortPacket || !has_fixed_bit(data[0])) return;
    if (!session_) {
        // Sent behind the handshake message that will give us the keys, and
        // overtook it.
        if (phase_ == Phase::Handshaking && early_.size() < kMaxEarlyPackets)
            early_.emplace_back(data, data + len);
        return;
    }
    // A peer that has forgotten this connection says so with its token at the end
    // of something shaped like a packet; nothing else ends with those bytes.
    if (is_reset(data, len)) {
        LOG_DEBUG("udp", "Connection " << local_cid_ << " reset by " << remote_.to_string());
        die(CloseReason::PeerReset);
        return;
    }

    uint8_t mask[5];
    session_->header_mask(false, data + kShortHeaderSize + kMaxPnLength, mask);
    const uint8_t first  = data[0] ^ (mask[0] & 0x1f);
    const size_t  pn_len = (first & 0x03) + 1;
    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; ++i)
        truncated = (truncated << 8) | static_cast<uint8_t>(data[kShortHeaderSize + i] ^ mask[1 + i]);
    const uint64_t pn = decode_pn(truncated, pn_len, have_recv_ ? largest_recv_ + 1 : 0);
    if (is_duplicate(pn)) return;

    // The header as it was sealed is the associated data.
    data[0] = first;
    for (size_t i = 0; i < pn_len; ++i) data[kShortHeaderSize + i] ^= mask[1 + i];
    const size_t header = kShortHeaderSize + pn_len;
    const auto plain = session_->open(pn, ByteView(data, header), data + header, len - header);
    if (!plain) return;   // forged, damaged, or not for these keys

    if (first & 0x1c) {   // reserved bits, sent as zero and now authenticated
        fail(now, CloseReason::ProtocolError, kCloseProtocol);
        return;
    }
    last_recv_ = now;
    heard_     = true;
    // A packet the dialer could only have sealed after our answer: its address is
    // proven, and (seen from the dialer) the responder has its keys.
    if (role_ == ConnRole::Inbound) address_validated_ = true;
    if (role_ == ConnRole::Outbound && !confirmed_) {
        confirmed_   = true;
        hs_deadline_ = kNever;
    }

    const bool reordered = have_recv_ && pn != largest_recv_ + 1;
    bool eliciting = false, refused = false;
    ack_urgent_ = false;
    if (!apply_frames(data + header, *plain, now, eliciting, refused)) {
        fail(now, CloseReason::ProtocolError, kCloseProtocol);
        return;
    }
    if (dead()) return;   // it was a goodbye

    // A packet whose data could not be held is not acknowledged: the peer will
    // send what it carried again, which is the right answer to a full receiver.
    if (!refused) {
        record_received(pn, now);
        if (eliciting) on_ack_eliciting(reordered || ack_urgent_, now);
    }
    maybe_update_window(now);
    pump(now);

    // An acknowledgement owed at once that no packet of ours has carried yet.
    // Inside a burst it waits for the end of it, unless it has waited long enough.
    if (ack_owed_ && ack_now_) {
        if (in_burst_ && unacked_ < kMaxBurstAck) burst_ack_owed_ = true;
        else                                     send_ack(now);
    }
}

bool UdpConnection::apply_frames(const uint8_t* payload, size_t len, Clock::time_point now,
                                 bool& eliciting, bool& refused) {
    FrameReader reader(payload, len);
    udp::Frame f;
    while (reader.next(f)) {
        switch (f.type) {
            case kPing:
                eliciting = true;
                break;
            case kAck:
                if (!recovery_.on_ack(f.ack, now, *this)) return false;
                break;
            case kStream:
                eliciting = true;
                if (!on_stream(f.stream, now, refused)) return false;
                break;
            case kMaxData:
                eliciting = true;
                peer_max_data_ = (std::max)(peer_max_data_, f.value);
                break;
            case kDataBlocked:
                eliciting = true;
                on_data_blocked(f.value);
                break;
            case kResetToken:
                eliciting = true;
                std::memcpy(peer_token_.data(), f.token.data(), kResetTokenSize);
                have_peer_token_ = true;
                break;
            case kClose:
                // An orderly close comes once everything the peer sent has been
                // acknowledged, so all of it is here: deliver it, then report the end.
                LOG_DEBUG("udp", "Connection " << local_cid_ << " closed by " << remote_.to_string()
                          << " (" << f.value << ")");
                if (f.value == kCloseOrderly) die(CloseReason::PeerClosed, /*keep_inbox=*/true);
                else                          die(CloseReason::PeerReset);
                return true;
            default:
                return false;
        }
    }
    return !reader.error();
}

bool UdpConnection::on_stream(const StreamFrame& f, Clock::time_point now, bool& refused) {
    if (f.stream == 0 || f.stream > 0xFF) return false;
    Lane* lane = lane_for(static_cast<MessageType>(f.stream), true);
    const uint64_t high_before = lane->recv.highest();
    const uint64_t next_before = lane->recv.in_order();
    // Once one fragment of a packet has been refused the packet will come again
    // whole, so the rest of it is not worth holding either.
    const bool had_hole = lane->recv.has_held();
    if (!refused && !lane->recv.on_data(f.offset, f.data, account_)) refused = true;
    last_data_recv_ = now;
    // Data past a hole, or the repair that fills one, is acknowledged at once: the
    // first is what tells the sender the hole is there, the second what tells it
    // the hole is gone — and a sender in recovery waits on exactly that.
    if (had_hole || lane->recv.has_held()) ack_urgent_ = true;

    // Flow control counts the highest byte of every stream, holes and all: that is
    // what the peer could make us hold.
    received_highest_ += lane->recv.highest() - high_before;
    if (received_highest_ > advertised_) {
        LOG_DEBUG("udp", "Connection " << local_cid_ << ": " << remote_.to_string()
                  << " sent past the window it was given");
        return false;
    }
    if (const uint64_t moved = lane->recv.in_order() - next_before; moved > 0) {
        consumed_ += moved;
        raise(PollIn);
    }
    return true;
}

void UdpConnection::on_data_blocked(uint64_t limit) {
    // The window is announced again either way: the peer is stopped, and sends
    // nothing for an update to ride on.
    max_data_owed_ = true;
    // Stopped at a limit granted before the window last grew: an echo of a stall
    // already answered, and the growth it would ask for has happened.
    if (have_grown_ && limit <= grown_mark_) return;
    grow_window();
}

bool UdpConnection::grow_window() {
    // Grown only while the budget behind every connection could still honour the
    // larger promise.
    if (recv_window_ >= max_window_) return false;
    const uint64_t next = (std::min)(recv_window_ * 2, max_window_);
    if (account_.shared && !account_.shared->has_room(static_cast<size_t>(next - recv_window_))) return false;
    grown_mark_  = advertised_;
    have_grown_  = true;
    recv_window_ = next;
    advertised_  = (std::max)(advertised_, consumed_ + recv_window_);
    return true;
}

void UdpConnection::maybe_update_window(Clock::time_point now) {
    // Re-granted once an eighth of the window has been used, not half of it as
    // QUIC stacks commonly do: what the sender can count on is the limit it last
    // heard, and with half-window updates that is anything down to half the
    // window — which on a long fat path is half the throughput. An update is a few
    // bytes on a packet the receiver is sending anyway. Monotone: a limit is a
    // promise.
    if (advertised_ - consumed_ > recv_window_ - recv_window_ / 8) return;

    // A whole window used up in under two round trips is too small for the path:
    // a window exactly the size of the path takes one (Chromium's auto-tuning).
    // The peer's DATA_BLOCKED catches the rest, but only once it has stalled; this
    // grows the window while the transfer is still running.
    if (consumed_ - window_epoch_bytes_ >= recv_window_) {
        const cc::RttEstimate& rtt = recovery_.rtt();
        if (rtt.have_rtt && now - window_epoch_ < 2 * rtt.srtt) grow_window();
        window_epoch_       = now;
        window_epoch_bytes_ = consumed_;
    }
    advertised_    = (std::max)(advertised_, consumed_ + recv_window_);
    max_data_owed_ = true;
}

// ── Acknowledgements we owe ─────────────────────────────────────────────────

bool UdpConnection::is_duplicate(uint64_t pn) const noexcept {
    if (pn < ack_floor_) return true;
    for (const auto& [lo, hi] : received_) {
        if (pn > hi) return false;
        if (pn >= lo) return true;
    }
    return false;
}

void UdpConnection::record_received(uint64_t pn, Clock::time_point now) {
    if (!have_recv_ || pn > largest_recv_) {
        largest_recv_    = pn;
        largest_recv_at_ = now;
        have_recv_       = true;
    }
    // Runs newest first. The common case — the next number — extends the first.
    if (!received_.empty() && pn == received_.front().second + 1) {
        received_.front().second = pn;
    } else {
        // The first run (newest first) that reaches down to pn + 1 or below.
        size_t i = 0;
        while (i < received_.size() && received_[i].first > pn + 1) ++i;
        if (i < received_.size() && received_[i].second + 1 >= pn) {
            // Adjacent to run i: grow it, and join it to a neighbour if pn was the
            // one number between them.
            auto& run  = received_[i];
            run.first  = (std::min)(run.first, pn);
            run.second = (std::max)(run.second, pn);
            if (i + 1 < received_.size() && received_[i + 1].second + 1 == run.first) {
                run.first = received_[i + 1].first;
                received_.erase(received_.begin() + static_cast<std::ptrdiff_t>(i + 1));
            }
            if (i > 0 && received_[i - 1].first == received_[i].second + 1) {
                received_[i - 1].first = received_[i].first;
                received_.erase(received_.begin() + static_cast<std::ptrdiff_t>(i));
            }
        } else {
            received_.insert(received_.begin() + static_cast<std::ptrdiff_t>(i), {pn, pn});
        }
    }
    // What does not fit an ACK any more is forgotten, oldest first: earlier ACKs
    // named it, and it is below anything the peer can still be waiting to hear of.
    while (received_.size() > kMaxAckRanges) {
        ack_floor_ = (std::max)(ack_floor_, received_.back().second + 1);
        received_.pop_back();
    }
}

void UdpConnection::on_ack_eliciting(bool urgent, Clock::time_point now) {
    ack_owed_ = true;
    ++unacked_;
    // Every other packet at once (RFC 9000 §13.2.1); and at once a packet out of
    // order, or one that opens or closes a hole in a stream — those ACKs are what
    // the sender's loss detection and the end of its recovery read, and holding
    // one back only delays the repair.
    if (urgent || unacked_ >= 2) ack_now_ = true;
    else if (ack_due_ == kNever)     ack_due_ = now + kDelayedAck;
}

size_t UdpConnection::ack_size(Clock::time_point now) const noexcept {
    if (received_.empty()) return 0;
    uint64_t los[kMaxAckRanges], his[kMaxAckRanges];
    const size_t n = (std::min)(received_.size(), kMaxAckRanges);
    for (size_t i = 0; i < n; ++i) { los[i] = received_[i].first; his[i] = received_[i].second; }
    const auto held = now > largest_recv_at_ ? now - largest_recv_at_ : Clock::duration::zero();
    return ack_frame_size(los, his, n, static_cast<uint64_t>(held / kAckDelayUnit));
}

uint8_t* UdpConnection::write_ack(uint8_t* p, Clock::time_point now) {
    uint64_t los[kMaxAckRanges], his[kMaxAckRanges];
    const size_t n = (std::min)(received_.size(), kMaxAckRanges);
    for (size_t i = 0; i < n; ++i) { los[i] = received_[i].first; his[i] = received_[i].second; }
    // How long the newest packet waited for this ACK, which the peer takes back
    // out of its round-trip sample.
    const auto held = now > largest_recv_at_ ? now - largest_recv_at_ : Clock::duration::zero();
    p = put_ack(p, los, his, n, static_cast<uint64_t>(held / kAckDelayUnit));
    SentFrame f;
    f.kind   = SentFrame::Ack;
    f.offset = his[0];
    recovery_.add_frame(f);
    return p;
}

void UdpConnection::ack_sent() noexcept {
    ack_owed_       = false;
    ack_now_        = false;
    unacked_        = 0;
    ack_due_        = kNever;
    burst_ack_owed_ = false;
}

void UdpConnection::send_ack(Clock::time_point now) {
    if (!established() || received_.empty()) return;
    send_packet(now, /*data=*/false, /*probe=*/false, /*force_ack=*/true);
}

void UdpConnection::end_burst(Clock::time_point now) {
    in_burst_ = false;
    if (burst_ack_owed_) {
        burst_ack_owed_ = false;
        if (ack_owed_) send_ack(now);
    }
    flush_events();
}

// ── Packets out ─────────────────────────────────────────────────────────────

bool UdpConnection::amplification_allows(size_t bytes) const noexcept {
    return role_ == ConnRole::Outbound || address_validated_ ||
           amp_sent_ + bytes <= kAmplificationFactor * amp_received_;
}

void UdpConnection::note_sent(size_t bytes) noexcept {
    if (!address_validated_) amp_sent_ += bytes;
}

uint64_t UdpConnection::new_data_budget() const noexcept {
    return peer_max_data_ > sent_new_total_ ? peer_max_data_ - sent_new_total_ : 0;
}

bool UdpConnection::has_control() const noexcept {
    return token_owed_ || max_data_owed_ || blocked_owed_ || ping_owed_;
}

bool UdpConnection::has_repairs() const noexcept {
    for (const auto& lane : lanes_)
        if (lane->send.lost_bytes() > 0) return true;
    return false;
}

bool UdpConnection::has_sendable_data() const noexcept {
    const bool budget = new_data_budget() > 0;
    for (const auto& lane : lanes_)
        if (lane->send.lost_bytes() > 0 || (budget && lane->send.unsent() > 0)) return true;
    return false;
}

uint64_t UdpConnection::total_unsent() const noexcept {
    uint64_t n = 0;
    for (const auto& lane : lanes_) n += lane->send.unsent();
    return n;
}

size_t UdpConnection::estimate_packet(Clock::time_point now) const noexcept {
    // What the next packet will weigh, so the window and the pacer are asked about
    // the packet actually going out: a small message must not wait for the tokens
    // of a full one.
    size_t n = kShortHeaderSize + kMaxPnLength + session_->overhead() + 24;
    if (ack_owed_) n += ack_size(now);
    uint64_t budget = new_data_budget();
    for (const auto& lane : lanes_) {
        const uint64_t fresh = (std::min)(lane->send.unsent(), budget);
        budget -= fresh;
        const uint64_t pending = lane->send.lost_bytes() + fresh;
        if (pending > 0) n += static_cast<size_t>((std::min<uint64_t>)(pending, kMaxDatagram)) + 12;
        if (n >= kMaxDatagram) return kMaxDatagram;
    }
    return (std::min)(n, kMaxDatagram);
}

size_t UdpConnection::begin_packet(uint8_t* buf, uint64_t pn, size_t& pn_len) const noexcept {
    pn_len = pn_length(pn, recovery_.largest_acked(), recovery_.have_largest_acked());
    buf[0] = static_cast<uint8_t>(0x40 | (pn_len - 1));
    put_cid(buf + 1, remote_cid_);
    for (size_t i = 0; i < pn_len; ++i)
        buf[kShortHeaderSize + i] = static_cast<uint8_t>(pn >> (8 * (pn_len - 1 - i)));
    return kShortHeaderSize + pn_len;
}

size_t UdpConnection::finish_packet(uint8_t* buf, size_t header, size_t pn_len, uint8_t* end,
                                    uint64_t pn, Clock::time_point now, bool eliciting, bool data,
                                    bool repair, bool probe) {
    // Padded so the 16 bytes the header mask is drawn from exist.
    const size_t overhead = session_->overhead();
    size_t payload = static_cast<size_t>(end - (buf + header));
    if (header + payload + overhead < kMinShortPacket) {
        const size_t pad = kMinShortPacket - header - payload - overhead;
        std::memset(end, kPadding, pad);
        payload += pad;
    }
    session_->seal(pn, ByteView(buf, header), buf + header, payload);
    const size_t total = header + payload + overhead;

    uint8_t mask[5];
    session_->header_mask(true, buf + kShortHeaderSize + kMaxPnLength, mask);
    buf[0] ^= mask[0] & 0x1f;
    for (size_t i = 0; i < pn_len; ++i) buf[kShortHeaderSize + i] ^= mask[1 + i];

    host_.send_datagram(remote_, total);
    recovery_.on_packet_sent(now, total, eliciting, data, repair, probe);
    note_sent(total);
    last_send_ = now;
    if (eliciting) last_eliciting_send_ = now;
    return total;
}

size_t UdpConnection::amplification_room() const noexcept {
    if (role_ == ConnRole::Outbound || address_validated_) return kMaxDatagram;
    const uint64_t allowed = kAmplificationFactor * amp_received_;
    return allowed > amp_sent_ ? static_cast<size_t>((std::min<uint64_t>)(allowed - amp_sent_, kMaxDatagram)) : 0;
}

size_t UdpConnection::send_packet(Clock::time_point now, bool data, bool probe, bool force_ack,
                                  bool keepalive) {
    // Whatever kind of packet it is, it fits what an unproven dialer has earned.
    const size_t room = amplification_room();
    if (room < kMinShortPacket) return 0;
    uint8_t* buf = host_.datagram_buffer();
    const uint64_t pn = recovery_.next_pn();
    size_t pn_len = 0;
    const size_t header = begin_packet(buf, pn, pn_len);
    uint8_t* p   = buf + header;
    uint8_t* end = buf + room - session_->overhead();

    bool eliciting = false, repair = false, has_ack = false;
    if ((ack_owed_ || force_ack || keepalive) && !received_.empty() &&
        ack_size(now) <= static_cast<size_t>(end - p)) {
        p = write_ack(p, now);
        has_ack = true;
    }
    p = write_control(p, end, eliciting);
    bool data_sent = false;
    if (data) {
        uint8_t* before = p;
        p = write_streams(p, end, repair);
        data_sent = p != before;
        eliciting |= data_sent;
    }
    if (probe && !eliciting) {
        // Nothing new to say: repeat the newest packet still out, so the probe's
        // acknowledgement lands past every hole in front of it — or just ask.
        uint8_t* before = p;
        p = write_repeat(p, end);
        data_sent = p != before;
        if (p == before) {
            *p++ = kPing;
            SentFrame f;
            f.kind = SentFrame::Ping;
            recovery_.add_frame(f);
        }
        eliciting = true;
    } else if (!eliciting && has_ack && !keepalive && received_.size() > 1) {
        // A receiver that only ever acknowledges never has its ACKs acknowledged,
        // and so never learns it may stop naming old holes. Once a round trip it
        // makes one of them ack-eliciting, so the next ACK it gets back lets it
        // forget them (RFC 9000 §13.2.4).
        const auto rtt = recovery_.rtt().have_rtt ? recovery_.rtt().srtt : Clock::duration(Recovery::kMaxAckDelay);
        if (now - last_eliciting_send_ >= rtt) {
            *p++ = kPing;
            eliciting = true;
        }
    }
    if (p == buf + header && !keepalive) {
        recovery_.cancel_frames();
        return 0;
    }
    if (has_ack) ack_sent();
    return finish_packet(buf, header, pn_len, p, pn, now, eliciting, data_sent, repair, probe);
}

uint8_t* UdpConnection::write_control(uint8_t* p, uint8_t* end, bool& eliciting) {
    // Each of these is a few bytes; a packet always has room for all of them.
    (void)end;
    if (token_owed_) {
        uint8_t token[kResetTokenSize];
        host_.reset_token(local_cid_, token);
        p = put_reset_token(p, token);
        token_owed_ = false;
        SentFrame f;
        f.kind = SentFrame::ResetToken;
        recovery_.add_frame(f);
        eliciting = true;
    }
    if (max_data_owed_) {
        p = put_value_frame(p, kMaxData, advertised_);
        max_data_owed_ = false;
        SentFrame f;
        f.kind   = SentFrame::MaxData;
        f.offset = advertised_;
        recovery_.add_frame(f);
        eliciting = true;
    }
    if (blocked_owed_) {
        p = put_value_frame(p, kDataBlocked, blocked_at_);
        blocked_owed_ = false;
        SentFrame f;
        f.kind   = SentFrame::DataBlocked;
        f.offset = blocked_at_;
        recovery_.add_frame(f);
        eliciting = true;
    }
    if (ping_owed_) {
        *p++ = kPing;
        ping_owed_ = false;
        SentFrame f;
        f.kind = SentFrame::Ping;
        recovery_.add_frame(f);
        eliciting = true;
    }
    return p;
}

uint8_t* UdpConnection::write_streams(uint8_t* p, uint8_t* end, bool& repair) {
    // Below this much room another frame is not worth its header.
    constexpr size_t kMinFrameRoom = 16;
    uint64_t budget = new_data_budget();

    // The most urgent priority first; within one, the lanes take turns, one packet
    // each, starting a little further round every packet.
    size_t lo = 0;
    while (lo < lanes_.size()) {
        const uint8_t prio = lanes_[lo]->priority;
        size_t hi = lo;
        while (hi < lanes_.size() && lanes_[hi]->priority == prio) ++hi;
        const size_t n     = hi - lo;
        const size_t start = rr_[prio] % n;
        bool rotated = false;
        for (size_t k = 0; k < n; ++k) {
            const size_t idx  = lo + (start + k) % n;
            Lane&        lane = *lanes_[idx];
            const uint64_t id = static_cast<uint8_t>(lane.type);
            SendStream::Piece piece;
            while (lane.send.peek(budget, piece)) {
                const size_t room = static_cast<size_t>(end - p);
                if (room < kMinFrameRoom) return p;
                size_t len = (std::min)(piece.len, room);
                size_t hdr = stream_header_size(id, piece.offset, len, true);
                if (hdr >= room) return p;
                len = (std::min)(len, room - hdr);
                hdr = stream_header_size(id, piece.offset, len, true);
                if (hdr + len > room) len = room - hdr;

                p = put_stream_header(p, id, piece.offset, len, true);
                lane.send.copy(piece.offset, len, p);
                p += len;
                lane.send.take(piece, len);
                if (piece.repair) {
                    repair = true;
                } else {
                    budget          -= len;
                    sent_new_total_ += len;
                }
                SentFrame f;
                f.kind   = SentFrame::Stream;
                f.stream = static_cast<uint8_t>(id);
                f.length = static_cast<uint32_t>(len);
                f.offset = piece.offset;
                recovery_.add_frame(f);
                if (!rotated) {
                    rr_[prio] = (start + k + 1) % n;
                    rotated   = true;
                }
            }
        }
        lo = hi;
    }
    return p;
}

uint8_t* UdpConnection::write_repeat(uint8_t* p, uint8_t* end) {
    size_t first = 0, count = 0;
    if (!recovery_.newest_in_flight(first, count)) return p;
    // Copied out first: the frames are recorded again below, which may move the log.
    std::vector<SentFrame> frames;
    frames.reserve(count);
    for (size_t i = 0; i < count; ++i) frames.push_back(recovery_.frames()[first + i]);
    for (SentFrame f : frames) {
        if (f.kind != SentFrame::Stream) continue;
        Lane* lane = lane_for(static_cast<MessageType>(f.stream), false);
        // Only what is still unacknowledged: the front of the frame may have been
        // delivered since by another packet, and its bytes released.
        uint64_t offset = f.offset;
        size_t   length = f.length;
        if (!lane || !lane->send.unacked_part(offset, length)) continue;
        f.offset = offset;
        f.length = static_cast<uint32_t>(length);
        const size_t room = static_cast<size_t>(end - p);
        const size_t hdr  = stream_header_size(f.stream, f.offset, f.length, true);
        if (hdr + f.length > room) break;
        p = put_stream_header(p, f.stream, f.offset, f.length, true);
        lane->send.copy(f.offset, f.length, p);
        p += f.length;
        recovery_.add_frame(f);
    }
    return p;
}

void UdpConnection::pump(Clock::time_point now) {
    // A responder says nothing before its answer to the Initial is out.
    if (!established() || (role_ == ConnRole::Inbound && !answered_)) return;
    const uint64_t queued_before = total_unsent();
    recovery_.begin_sending(now, has_sendable_data());
    recovery_.clear_pacer_hold();

    bool window_stopped = false;
    for (;;) {
        // Stopped by the peer's window with data waiting: say so, once per limit —
        // it is the only way a receiver learns its window is what holds us back.
        if (new_data_budget() == 0 && total_unsent() > 0 && blocked_at_ != peer_max_data_) {
            blocked_at_   = peer_max_data_;
            blocked_owed_ = true;
        }
        const bool data    = has_sendable_data();
        const bool control = has_control();
        if (!data && !control) break;

        bool with_data = data;
        if (data) {
            const size_t size = estimate_packet(now);
            if (!recovery_.cwnd_allows(size)) {
                window_stopped = true;
                with_data      = false;
            } else if (!has_repairs() && !recovery_.pace_allows(size)) {
                // Repairs are not held by the pacer: what the peer is missing holds
                // up everything behind it.
                recovery_.hold_for_pacer(now, size);
                with_data = false;
            }
        }
        if (!with_data && !control) break;
        const size_t owed_before = queued_bytes();
        if (send_packet(now, with_data, false, false) == 0) break;
        // The control frames went and the windows still say no — or, never
        // expected, a packet that should have carried data did not.
        if (!with_data || queued_bytes() == owed_before) break;
    }
    recovery_.note_send_limits(total_unsent() > 0, window_stopped, !has_sendable_data());

    if (want_write_ && total_unsent() < queued_before) raise(PollOut);
    // An orderly close finishes once everything is delivered.
    if (closing_ && flushed()) {
        send_close(now, kCloseOrderly);
        die(CloseReason::LocalClose);
        events_ = 0;
    }
}

void UdpConnection::send_probe(Clock::time_point now) {
    // Past every window: the point of a probe is to be answered.
    send_packet(now, /*data=*/true, /*probe=*/true, /*force_ack=*/false);
}

void UdpConnection::send_close(Clock::time_point now, uint64_t code) {
    if (close_sent_) return;
    close_sent_ = true;
    uint8_t* buf = host_.datagram_buffer();
    if (session_) {
        if (amplification_room() < kMinShortPacket) return;
        const uint64_t pn = recovery_.next_pn();
        size_t pn_len = 0;
        const size_t header = begin_packet(buf, pn, pn_len);
        uint8_t* p = put_value_frame(buf + header, kClose, code);
        finish_packet(buf, header, pn_len, p, pn, now, /*eliciting=*/false, false, false, false);
    } else if (role_ == ConnRole::Outbound || answered_) {
        const size_t n = encode_close(buf, remote_cid_, local_cid_, code);
        if (amplification_allows(n)) {
            host_.send_datagram(remote_, n);
            note_sent(n);
        }
    }
}

void UdpConnection::fail(Clock::time_point now, CloseReason reason, uint64_t code) {
    if (dead()) return;
    send_close(now, code);
    die(reason);
}

// ── The transport's side ────────────────────────────────────────────────────

UdpConnection::Lane* UdpConnection::lane_for(MessageType type, bool create) {
    for (const auto& lane : lanes_)
        if (lane->type == type) return lane.get();
    if (!create) return nullptr;
    // Kept sorted by priority, so building a packet walks the most urgent first.
    auto lane      = std::make_unique<Lane>();
    lane->type     = type;
    lane->priority = static_cast<uint8_t>(priority_of(type));
    const auto at = std::find_if(lanes_.begin(), lanes_.end(), [&](const std::unique_ptr<Lane>& l) {
        return l->priority > lane->priority || (l->priority == lane->priority && l->type > type);
    });
    return lanes_.insert(at, std::move(lane))->get();
}

bool UdpConnection::send_message(FrameHeader header, ByteView payload) {
    if (!established() || closing_) return false;
    Lane* lane = lane_for(header.type, true);
    const size_t inner = framer::kHeaderSize + payload.size();
    uint8_t head[8 + framer::kHeaderSize];
    uint8_t* q = put_varint(head, inner);
    framer::encode_header(q, header);
    q += framer::kHeaderSize;
    lane->send.write(head, static_cast<size_t>(q - head));
    if (!payload.empty()) lane->send.write(payload.data(), payload.size());
    return true;
}

void UdpConnection::flush(Clock::time_point now) {
    pump(now);
    flush_events();
}

void UdpConnection::close(CloseReason reason, Clock::time_point now) {
    if (dead()) return;
    if (established() && (reason == CloseReason::LocalClose || reason == CloseReason::PeerClosed)) {
        // Orderly: everything already queued is still delivered, and the goodbye
        // follows it (see pump).
        closing_ = true;
        pump(now);
        flush_events();
        return;
    }
    abort(now);
}

bool UdpConnection::flushed() const noexcept {
    for (const auto& lane : lanes_)
        if (!lane->send.flushed()) return false;
    return true;
}

size_t UdpConnection::queued_bytes() const noexcept {
    uint64_t n = 0;
    for (const auto& lane : lanes_) n += lane->send.unsent() + lane->send.lost_bytes();
    return static_cast<size_t>(n);
}

PathStats UdpConnection::path_stats() const noexcept {
    using std::chrono::duration_cast;
    using std::chrono::microseconds;
    using std::chrono::nanoseconds;

    PathStats s;
    s.valid = established();
    const auto per_second = [](uint64_t bytes, Clock::duration per) -> uint64_t {
        const auto ns = duration_cast<nanoseconds>(per).count();
        return ns > 0 ? static_cast<uint64_t>(bytes * 8.0 * 1e9 / static_cast<double>(ns)) : 0;
    };
    const cc::RttEstimate& rtt = recovery_.rtt();
    if (rtt.have_rtt) {
        s.srtt_us    = static_cast<uint32_t>(duration_cast<microseconds>(rtt.srtt).count());
        s.min_rtt_us = static_cast<uint32_t>(duration_cast<microseconds>(rtt.min_rtt).count());
    }
    const cc::CongestionController& cc = recovery_.congestion();
    if (const uint64_t bw = cc.bandwidth()) s.bandwidth_bps = bw * 8;
    else if (rtt.have_rtt)                   s.bandwidth_bps = per_second(cc.cwnd(), rtt.srtt);
    const cc::PacingRate rate = cc.pacing_rate();
    if (rate.paced()) s.pacing_bps = per_second(rate.bytes, rate.per);
    s.app_limited     = recovery_.sampler().app_limited();
    s.queued_bytes    = queued_bytes();
    s.bytes_in_flight = recovery_.bytes_in_flight();
    s.bytes_delivered = recovery_.sampler().delivered();
    s.bytes_lost      = recovery_.sampler().lost();
    return s;
}

void UdpConnection::release_memory() {
    recovery_.release_memory();
    for (auto& lane : lanes_) lane->recv.decay();
}

// ── Timers ──────────────────────────────────────────────────────────────────

std::optional<Clock::time_point> UdpConnection::next_deadline() const noexcept {
    if (dead()) return std::nullopt;
    // Silence from the peer ends the connection whatever else is outstanding.
    Clock::time_point due = last_recv_ + kIdleTimeout;
    if (hs_deadline_ != kNever) due = (std::min)(due, hs_deadline_);
    if (!established()) return due;

    if (ack_owed_) {
        if (ack_now_) return Clock::time_point{};   // at once
        if (ack_due_ != kNever) due = (std::min)(due, ack_due_);
    }
    if (const auto r = recovery_.deadline()) due = (std::min)(due, *r);
    // Keep-alive: proof we are here, and a NAT mapping kept open.
    due = (std::min)(due, last_send_ + kKeepAlive);
    return due;
}

void UdpConnection::tick(Clock::time_point now) {
    if (dead()) return;
    if (now - last_recv_ >= kIdleTimeout) {
        LOG_DEBUG("udp", "Connection " << local_cid_ << " to " << remote_.to_string() << " idle for "
                  << kIdleTimeout.count() << "s; closing");
        die(CloseReason::IdleTimeout);
        flush_events();
        return;
    }
    handshake_timer(now);
    if (!established()) { flush_events(); return; }

    // A window grown for a transfer that has gone quiet goes back to where it
    // started. What was advertised stands — it is a promise — so this only stops
    // it being carried further.
    if (recv_window_ > initial_window_ && account_.held == 0 && now - last_data_recv_ >= kWindowDecay)
        recv_window_ = initial_window_;

    switch (recovery_.on_timer(now, *this)) {
        case Recovery::Timeout::Probe:
            send_probe(now);
            break;
        case Recovery::Timeout::GiveUp:
            LOG_DEBUG("udp", "Connection " << local_cid_ << " to " << remote_.to_string()
                      << " stopped answering");
            die(CloseReason::PeerReset);
            flush_events();
            return;
        case Recovery::Timeout::Collapsed:
        case Recovery::Timeout::None:
            break;
    }

    if (ack_owed_ && (ack_now_ || (ack_due_ != kNever && now >= ack_due_))) send_ack(now);
    pump(now);
    // Say something now and then: it keeps the peer's idle timer from firing and
    // a NAT's mapping for the socket open. Not ack-eliciting, so a lost one costs
    // nothing — no timer, no window — and an idle connection stays idle to the
    // congestion controller.
    if (now - last_send_ >= kKeepAlive) send_packet(now, false, false, false, /*keepalive=*/true);
    flush_events();
}

// ── FrameSink ───────────────────────────────────────────────────────────────

void UdpConnection::frames_acked(const RingBuffer<SentFrame>& log, size_t first, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const SentFrame& f = log[first + i];
        switch (f.kind) {
            case SentFrame::Stream:
                if (Lane* lane = lane_for(static_cast<MessageType>(f.stream), false))
                    lane->send.on_acked(f.offset, f.length);
                break;
            case SentFrame::Ack: {
                // The peer has our ACK naming everything up to f.offset, so those
                // numbers need never be named again (RFC 9000 §13.2.4).
                const uint64_t floor = f.offset + 1;
                if (floor <= ack_floor_) break;
                ack_floor_ = floor;
                while (!received_.empty() && received_.back().second < floor) received_.pop_back();
                if (!received_.empty() && received_.back().first < floor) received_.back().first = floor;
                break;
            }
            case SentFrame::ResetToken:
                token_acked_ = true;
                break;
            default:
                break;
        }
    }
}

void UdpConnection::frames_lost(const RingBuffer<SentFrame>& log, size_t first, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const SentFrame& f = log[first + i];
        switch (f.kind) {
            case SentFrame::Stream:
                if (Lane* lane = lane_for(static_cast<MessageType>(f.stream), false))
                    lane->send.on_lost(f.offset, f.length);
                break;
            // Control frames are repeated only while what they said still holds:
            // a later window update supersedes a lost one.
            case SentFrame::MaxData:
                if (f.offset == advertised_) max_data_owed_ = true;
                break;
            case SentFrame::DataBlocked:
                if (f.offset == peer_max_data_ && blocked_at_ == f.offset) blocked_owed_ = true;
                break;
            case SentFrame::ResetToken:
                if (!token_acked_) token_owed_ = true;
                break;
            default:
                break;
        }
    }
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

void UdpConnection::die(CloseReason reason, bool keep_inbox) {
    if (dead()) return;
    phase_        = Phase::Dead;
    close_reason_ = reason;
    recovery_.clear();
    for (auto& lane : lanes_) {
        lane->send.clear();
        // An orderly close leaves what has arrived to be delivered; the transport
        // reports the end once it has been.
        if (!keep_inbox) lane->recv.clear(account_);
    }
    early_.clear();
    handshaker_.reset();
    hs_deadline_ = kNever;
    ack_sent();
    raise(keep_inbox ? PollIn : PollErr);
}

void UdpConnection::flush_events() {
    if (events_ == 0) return;
    const uint32_t events = events_;
    events_ = 0;
    host_.connection_events(*this, events);
}

} // namespace librats
