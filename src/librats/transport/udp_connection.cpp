#include "librats/transport/udp_connection.h"
#include "librats/core/io_poller.h"   // PollIn / PollOut / PollErr
#include "librats/util/logger.h"

#include <algorithm>
#include <cstring>

namespace librats {

using namespace udp;

namespace {

using Clock = UdpConnection::Clock;
constexpr Clock::time_point kNever{};

/// Below this much room another frame is not worth its header.
constexpr size_t kMinFrameRoom = 16;
/// Milliseconds a live message has left at `now`, rounded up: what its LIVE frames
/// carry, and the receiver must never give up on it early.
uint64_t ms_left(Clock::time_point deadline, Clock::time_point now) {
    if (deadline <= now) return 0;
    return static_cast<uint64_t>(std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count());
}

/// A live message this small is not split behind other data: one that does not fit
/// what is left of a packet waits for the next, which costs nothing and spares the
/// receiver an assembly.
constexpr size_t kMaxUnsplitLive = 1024;

/// Room a packet keeps beside a symbol of a protected live message: the largest
/// LIVE or LIVE_REPAIR header, and a small ACK. So a symbol goes in a packet of
/// its own, and a lost packet costs one.
constexpr size_t kLiveFrameRoom = 24 + 16;
/// The share of a protected live message's blocks that may be lost beyond what
/// their repairs give back: when what the path loses can no longer be sent again
/// in time, and when it still can.
constexpr double kLiveLossTarget       = 0.01;
constexpr double kLiveLossTargetWithArq = 0.1;

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
    live_recv_.clear(account_);
}

std::unique_ptr<UdpConnection> UdpConnection::dial(UdpConnectionHost& host, SecurityProvider& security,
                                                   const Address& remote, Cid local,
                                                   Clock::time_point now, UdpConnectionConfig config) {
    std::unique_ptr<UdpConnection> c(new UdpConnection(host, security, remote, ConnRole::Outbound,
                                                       local, paired_cid(local), now, config));
    c->address_validated_ = true;   // it is where we chose to send
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
    for (Bytes& b : early) on_short(b.data(), b.size(), remote_, now);
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

void UdpConnection::on_datagram(uint8_t* data, size_t len, const Address& from, Clock::time_point now) {
    if (dead() || len == 0) return;
    // Until the peer has proved its address, what it sends is what we may answer
    // with (three times over).
    if (!address_validated_ && from == remote_) amp_received_ += len;

    if (is_long_header(data[0])) {
        // The handshake stays on the address it began on; a long header from
        // anywhere else is nobody's.
        LongPacket p;
        if (from == remote_ && decode_long(data, len, p) && p.scid == remote_cid_ && p.dcid == local_cid_)
            on_long(p, len, now);
    } else {
        on_short(data, len, from, now);
    }
    flush_events();
}

bool UdpConnection::is_reset(const uint8_t* data, size_t len) const noexcept {
    return have_peer_token_ && len >= kMinShortPacket &&
           std::memcmp(data + len - kResetTokenSize, peer_token_.data(), kResetTokenSize) == 0;
}

void UdpConnection::on_short(uint8_t* data, size_t len, const Address& from, Clock::time_point now) {
    if (len < kMinShortPacket || !has_fixed_bit(data[0])) return;
    if (!session_) {
        // Sent behind the handshake message that will give us the keys, and
        // overtook it.
        if (phase_ == Phase::Handshaking && from == remote_ && early_.size() < kMaxEarlyPackets)
            early_.emplace_back(data, data + len);
        return;
    }
    // A peer that has forgotten this connection says so with its token at the end
    // of something shaped like a packet. It is believed only of a datagram that is
    // not a packet of ours — a duplicate, one that does not open, one whose frames
    // do not parse (RFC 9000 §10.3.1): under a session that appends no tag the
    // tail of a real packet is its last frame, and a RESET_TOKEN frame sent last
    // ends with exactly those bytes.
    const bool reset = is_reset(data, len);
    const auto not_ours = [&] {
        if (!reset) return false;
        LOG_DEBUG("udp", "Connection " << local_cid_ << " reset by " << remote_.to_string());
        die(CloseReason::PeerReset);
        return true;
    };

    uint8_t mask[5];
    session_->header_mask(false, data + kShortHeaderSize + kMaxPnLength, mask);
    const uint8_t first  = data[0] ^ (mask[0] & 0x1f);
    const size_t  pn_len = (first & 0x03) + 1;
    uint64_t truncated = 0;
    for (size_t i = 0; i < pn_len; ++i)
        truncated = (truncated << 8) | static_cast<uint8_t>(data[kShortHeaderSize + i] ^ mask[1 + i]);
    const uint64_t pn = decode_pn(truncated, pn_len, have_recv_ ? largest_recv_ + 1 : 0);
    if (is_duplicate(pn)) {
        not_ours();
        return;
    }

    // The header as it was sealed is the associated data.
    data[0] = first;
    for (size_t i = 0; i < pn_len; ++i) data[kShortHeaderSize + i] ^= mask[1 + i];
    const size_t header = kShortHeaderSize + pn_len;
    const auto plain = session_->open(pn, ByteView(data, header), data + header, len - header);
    if (!plain) {   // forged, damaged, or not for these keys
        not_ours();
        return;
    }

    if (first & 0x1c) {   // reserved bits, sent as zero and now authenticated
        if (!not_ours()) fail(now, CloseReason::ProtocolError, kCloseProtocol);
        return;
    }
    // The peer's, but from somewhere else: it has moved, or this is a copy someone
    // sent from elsewhere (see "Migration"). Only its newest packet can move the
    // connection, and nothing moves before the handshake is confirmed.
    const bool newest = !have_recv_ || pn > largest_recv_;
    if (from != remote_ && !may_move()) return;
    last_recv_ = now;
    heard_     = true;
    // A packet the dialer could only have sealed after our answer: its address is
    // proven, and (seen from the dialer) the responder has its keys. Not so after
    // a move, which only a PATH_RESPONSE proves.
    if (!previous_ && from == remote_) address_validated_ = true;
    if (role_ == ConnRole::Outbound && !confirmed_) {
        confirmed_   = true;
        hs_deadline_ = kNever;
    }

    const bool reordered = have_recv_ && pn != largest_recv_ + 1;
    const Clock::time_point data_before = last_data_recv_;
    bool eliciting = false, refused = false;
    ack_urgent_    = false;
    path_answered_ = false;
    if (!apply_frames(data + header, *plain, now, eliciting, refused)) {
        if (!not_ours()) fail(now, CloseReason::ProtocolError, kCloseProtocol);
        return;
    }
    if (dead()) return;   // it was a goodbye
    if (last_data_recv_ != data_before) note_data_gap(now - data_before, now);
    if (from != remote_ && newest) move_to(from, len, now);
    if (path_answered_) path_proven(now);

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
            case kLive:
                eliciting = true;
                if (!on_live(f.live, now, refused)) return false;
                break;
            case kLiveRepair:
                eliciting = true;
                if (!on_live_repair(f.repair, now, refused)) return false;
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
            case kPathChallenge:
                eliciting = true;
                on_path_challenge(f.path, f.path_flags, now);
                break;
            case kPathResponse:
                eliciting = true;
                // Applied once the packet is: it may also be what moves the
                // connection to where the challenge went.
                if (challenge_.active && f.path == challenge_.data) path_answered_ = true;
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
    if (!reading_) {
        // Nobody reads it: noted for flow control, acknowledged, and dropped.
        received_highest_ += lane->recv.skip(f.offset, f.data.size());
        return received_highest_ <= advertised_;
    }
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
        // In order is consumed as far as the window goes, but held until the
        // message is whole: that is bounded here, not by the window.
        if (!lane->recv.track_messages(framer::kMaxBlockSize)) {
            LOG_DEBUG("udp", "Connection " << local_cid_ << ": " << remote_.to_string()
                      << " announced a message past the size limit");
            return false;
        }
        if (!unfinished_ok(*lane)) {
            LOG_DEBUG("udp", "Connection " << local_cid_ << ": " << remote_.to_string()
                      << " left more unfinished messages than it may");
            return false;
        }
    }
    return true;
}

bool UdpConnection::on_live(const LiveFrame& f, Clock::time_point now, bool& refused) {
    // Nobody reads it, or the packet will come again whole: acknowledged or not,
    // there is nothing to keep.
    if (!reading_ || refused) return true;
    last_data_recv_ = now;
    // What is being put together is given up a probe timeout after its sender
    // stopped repairing it: slack for a repair that left just in time.
    switch (live_recv_.on_frame(f, now, recovery_.probe_timeout(), account_)) {
        case LiveReceiver::Result::Taken:
            if (live_recv_.has_messages()) raise(PollIn);
            return true;
        case LiveReceiver::Result::Refused:
            refused = true;
            return true;
        case LiveReceiver::Result::Invalid:
            LOG_DEBUG("udp", "Connection " << local_cid_ << ": " << remote_.to_string()
                      << " sent pieces of one live message that disagree");
            return false;
    }
    return false;
}

bool UdpConnection::on_live_repair(const LiveRepairFrame& f, Clock::time_point now, bool& refused) {
    if (!reading_ || refused) return true;
    last_data_recv_ = now;
    switch (live_recv_.on_repair(f, now, recovery_.probe_timeout(), account_)) {
        case LiveReceiver::Result::Taken:
            if (live_recv_.has_messages()) raise(PollIn);
            return true;
        case LiveReceiver::Result::Refused:
            refused = true;
            return true;
        case LiveReceiver::Result::Invalid:
            LOG_DEBUG("udp", "Connection " << local_cid_ << ": " << remote_.to_string()
                      << " sent a repair symbol that disagrees with its live message");
            return false;
    }
    return false;
}

bool UdpConnection::unfinished_ok(const Lane& lane) const noexcept {
    // Only the lane that just grew can have pushed the total over.
    const uint64_t mine = lane.recv.unfinished();
    if (mine == 0) return true;
    uint64_t sum = 0, top = 0;
    for (const auto& l : lanes_) {
        const uint64_t u = l->recv.unfinished();
        sum += u;
        top = (std::max)(top, u);
    }
    return sum - top <= config_.max_unfinished;
}

UdpConnection::Spread UdpConnection::spread() const noexcept {
    Spread s;
    for (const auto& l : lanes_) {
        const uint64_t u = l->send.unfinished_bound();
        s.sum += u;
        if (u > s.top) {
            s.second   = s.top;
            s.top      = u;
            s.top_lane = l.get();
        } else if (u > s.second) {
            s.second = u;
        }
    }
    return s;
}

uint64_t UdpConnection::unfinished_room(const Lane& lane, const Spread& s) const noexcept {
    // What the receiver counts is the sum of every stream's unfinished message
    // less the largest. Sending on the stream that has (or ties for) the largest
    // leaves that unchanged, so it is never held back — which is what keeps the
    // streams from deadlocking. Any other stream may grow until the rest of them
    // together, itself included, reach the limit. Measured with each stream's
    // upper bound, so the receiver's own count is never larger.
    const uint64_t mine   = lane.send.unfinished_bound();
    const uint64_t others = s.top_lane == &lane ? s.second : s.top;
    if (mine >= others) return UINT64_MAX;
    const uint64_t counted = s.sum - others;   // everything but the largest, mine included
    return counted < config_.max_unfinished ? config_.max_unfinished - counted : 0;
}

void UdpConnection::stop_reading() {
    if (!reading_) return;
    reading_ = false;
    for (auto& lane : lanes_) lane->recv.stop(account_);
    live_recv_.clear(account_);
}

size_t UdpConnection::buffered_bytes() const noexcept {
    size_t n = live_recv_.buffered();
    for (const auto& lane : lanes_) n += lane->recv.buffered();
    return n;
}

void UdpConnection::on_data_blocked(uint64_t limit) {
    // The window is announced again either way: the peer is stopped, and sends
    // nothing for an update to ride on.
    max_data_owed_ = true;
    if (!reading_) return;   // and not grown for data nobody will read
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
    if (!reading_ || advertised_ - consumed_ > recv_window_ - recv_window_ / 8) return;

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

// ── Migration ───────────────────────────────────────────────────────────────

bool UdpConnection::may_move() const noexcept {
    return established() && confirmed_ && (address_validated_ || previous_);
}

void UdpConnection::move_to(const Address& to, size_t len, Clock::time_point now) {
    if (previous_ && to == *previous_) {
        // Back where it was proven: nothing to ask. Whatever pointed us elsewhere
        // was a copy, or a path the peer has already left again.
        remote_ = to;
        previous_.reset();
        address_validated_ = true;
        challenge_ = Challenge{};
        return;
    }
    LOG_DEBUG("udp", "Connection " << local_cid_ << ": peer moved from " << remote_.to_string()
              << " to " << to.to_string());
    if (address_validated_) previous_ = remote_;
    remote_            = to;
    address_validated_ = false;
    amp_received_      = len;
    amp_sent_          = 0;
    // Already asked, if a probe of ours went there: its answer is the proof.
    if (!challenge_.active || challenge_.to != to) start_challenge(to, now);
}

void UdpConnection::probe_path(const Address& candidate, Clock::time_point now) {
    if (!may_move() || challenge_.active || candidate == remote_) return;
    start_challenge(candidate, now);
    flush_events();
}

void UdpConnection::start_challenge(const Address& to, Clock::time_point now) {
    const Address& proven = previous_ ? *previous_ : remote_;
    challenge_        = Challenge{};
    challenge_.active = true;
    challenge_.to     = to;
    // Unique is enough: it travels sealed, so only the peer can read it and answer,
    // and a copy of an answer is a duplicate packet.
    challenge_.data   = ++challenges_;
    challenge_.new_ip = to.ip != proven.ip;
    send_challenge(now);
}

void UdpConnection::send_challenge(Clock::time_point now) {
    // One that waits on the amplification limit counts as sent: a peer that sends
    // nothing from there has nothing there to prove.
    challenge_.due = now + recovery_.probe_timeout() * (1 << challenge_.sends);
    ++challenge_.sends;
    const bool here = challenge_.to == remote_;
    const size_t size = (std::max)(kMinShortPacket, kShortHeaderSize + kMaxPnLength + kPathChallengeSize +
                                                    session_->overhead());
    if (here && amplification_room() < size) return;

    uint8_t* buf = host_.datagram_buffer();
    const uint64_t pn = recovery_.next_pn();
    size_t pn_len = 0;
    const size_t header = begin_packet(buf, pn, pn_len);
    uint8_t* p = put_path_challenge(buf + header, challenge_.data, challenge_.new_ip ? kPathNewIp : 0);
    const size_t total = seal_packet(buf, header, pn_len, p, pn);
    host_.send_datagram(challenge_.to, total);
    // Never in flight: one that is lost — as one sent where a forger pointed us
    // always is — says nothing about the path, and the challenge has a timer of
    // its own.
    recovery_.on_packet_sent(now, total, /*ack_eliciting=*/false, false, false, false);
    if (here) note_sent(total);
}

void UdpConnection::on_path_challenge(uint64_t data, uint8_t flags, Clock::time_point now) {
    response_owed_ = true;
    response_data_ = data;
    if (data == last_challenge_) return;   // a repeat, already taken in
    last_challenge_ = data;
    // The peer sees us somewhere new. Over another IP it is another path, for our
    // estimate of it as for the peer's.
    if (flags & kPathNewIp) restart_path(now);
    moved_ = true;
    raise(PollIn);
}

void UdpConnection::path_proven(Clock::time_point now) {
    path_answered_ = false;
    const Challenge proven = challenge_;
    challenge_ = Challenge{};
    // The peer received there, but its packets come from elsewhere by now: the
    // next of them starts over.
    if (remote_ != proven.to) return;
    LOG_DEBUG("udp", "Connection " << local_cid_ << ": peer proven at " << remote_.to_string());
    previous_.reset();
    address_validated_ = true;
    if (proven.new_ip) restart_path(now);
    moved_ = true;
    raise(PollIn);
    host_.peer_moved(*this);
}

void UdpConnection::path_timer(Clock::time_point now) {
    if (!challenge_.active || now < challenge_.due) return;
    if (challenge_.sends < kMaxPathChallenges) {
        send_challenge(now);
        return;
    }
    // Never answered: the peer is not there, or never was. Back to where it was
    // proven, if that is what it was moved from.
    LOG_DEBUG("udp", "Connection " << local_cid_ << ": " << challenge_.to.to_string()
              << " never answered its challenge");
    if (remote_ == challenge_.to && previous_) {
        remote_ = *previous_;
        previous_.reset();
        address_validated_ = true;
    }
    challenge_ = Challenge{};
}

void UdpConnection::restart_path(Clock::time_point now) {
    recovery_.on_new_path(now, *this);
    live_loss_.restart(recovery_.sampler().delivered(), recovery_.path_lost());
}

void UdpConnection::note_data_gap(Clock::duration gap, Clock::time_point now) {
    // The peer is streaming to us: should it stop for far longer than it pauses,
    // we speak up (kQuietProbe).
    data_gap_   = (data_gap_ * 7 + gap) / 8;
    quiet_wait_ = (std::max)(Clock::duration(kQuietProbe), data_gap_ * kQuietGaps);
    quiet_due_  = quiet_wait_ < kKeepAlive ? now + quiet_wait_ : kNever;
}

void UdpConnection::nudge(Clock::time_point now) {
    if (!established()) return;
    ping_owed_ = true;
    pump(now);
    flush_events();
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
    if (!established()) return;
    // Owed, but everything it would name has been pruned since — an ack-of-ack in
    // a packet that was itself refused, so never recorded. Nothing left to say:
    // the debt is settled, or next_deadline() would keep asking for it at once.
    if (received_.empty()) {
        ack_sent();
        return;
    }
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
    return address_validated_ || amp_sent_ + bytes <= kAmplificationFactor * amp_received_;
}

void UdpConnection::note_sent(size_t bytes) noexcept {
    if (!address_validated_) amp_sent_ += bytes;
}

uint64_t UdpConnection::new_data_budget() const noexcept {
    return peer_max_data_ > sent_new_total_ ? peer_max_data_ - sent_new_total_ : 0;
}

bool UdpConnection::has_control() const noexcept {
    return token_owed_ || max_data_owed_ || blocked_owed_ || ping_owed_ || response_owed_;
}

bool UdpConnection::has_repairs() const noexcept {
    if (live_send_.lost_bytes() > 0) return true;
    for (const auto& lane : lanes_)
        if (lane->send.lost_bytes() > 0) return true;
    return false;
}

bool UdpConnection::repairs_go_at_once() const noexcept {
    // A few repairs are not held by the pacer: what the peer is missing holds up
    // everything behind it. A backlog of them is — a timeout writes off the whole
    // flight, BBR hands the window back on the first acknowledgement, and let past
    // the pacer that window would leave in one line-rate burst that a shallow
    // queue mostly drops. One pacer release is the most that goes at once.
    uint64_t owed = live_send_.lost_bytes();
    for (const auto& lane : lanes_) owed += lane->send.lost_bytes();
    return owed > 0 && owed <= udp::Recovery::kPaceMaxBurst;
}

bool UdpConnection::has_sendable_data() const noexcept {
    // Live messages are not under the peer's window: what bounds them is how long
    // they live, and what the receiver will hold of them (udp_live.h).
    if (live_send_.has_pending()) return true;
    const bool budget = new_data_budget() > 0;
    const Spread s = spread();
    for (const auto& lane : lanes_)
        if (lane->send.lost_bytes() > 0 ||
            (budget && lane->send.unsent() > 0 && unfinished_room(*lane, s) > 0))
            return true;
    return false;
}

uint64_t UdpConnection::stream_unsent() const noexcept {
    uint64_t n = 0;
    for (const auto& lane : lanes_) n += lane->send.unsent();
    return n;
}

Clock::duration UdpConnection::one_way() const noexcept {
    const cc::RttEstimate& rtt = recovery_.rtt();
    return rtt.have_rtt ? rtt.srtt / 2 : Clock::duration::zero();
}

size_t UdpConnection::estimate_packet(Clock::time_point now) const noexcept {
    // What the next packet will weigh, so the window and the pacer are asked about
    // the packet actually going out: a small message must not wait for the tokens
    // of a full one.
    size_t n = kShortHeaderSize + kMaxPnLength + session_->overhead() + 24;
    if (ack_owed_) n += ack_size(now);
    const uint64_t live = live_send_.unsent() + live_send_.lost_bytes() + live_send_.parity_unsent();
    if (live > 0) {
        n += static_cast<size_t>((std::min<uint64_t>)(live, kMaxDatagram)) + 12;
        if (n >= kMaxDatagram) return kMaxDatagram;
    }
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

size_t UdpConnection::seal_packet(uint8_t* buf, size_t header, size_t pn_len, uint8_t* end, uint64_t pn) {
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
    return total;
}

size_t UdpConnection::finish_packet(uint8_t* buf, size_t header, size_t pn_len, uint8_t* end,
                                    uint64_t pn, Clock::time_point now, bool eliciting, bool data,
                                    bool repair, bool probe) {
    const size_t total = seal_packet(buf, header, pn_len, end, pn);
    host_.send_datagram(remote_, total);
    recovery_.on_packet_sent(now, total, eliciting, data, repair, probe);
    note_sent(total);
    last_send_ = now;
    if (eliciting) last_eliciting_send_ = now;
    return total;
}

size_t UdpConnection::amplification_room() const noexcept {
    if (address_validated_) return kMaxDatagram;
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
        p = write_data(p, end, now, repair);
        data_sent = p != before;
        eliciting |= data_sent;
    }
    if (probe && !eliciting) {
        // Nothing new to say: repeat the newest packet still out, so the probe's
        // acknowledgement lands past every hole in front of it — or just ask.
        uint8_t* before = p;
        p = write_repeat(p, end, now);
        data_sent = p != before;
        if (p == before && p < end) {
            *p++ = kPing;
            SentFrame f;
            f.kind = SentFrame::Ping;
            recovery_.add_frame(f);
        }
        eliciting = p != before;
    } else if (!eliciting && has_ack && !keepalive && received_.size() > 1) {
        // A receiver that only ever acknowledges never has its ACKs acknowledged,
        // and so never learns it may stop naming old holes. Once a round trip it
        // makes one of them ack-eliciting, so the next ACK it gets back lets it
        // forget them (RFC 9000 §13.2.4).
        const auto rtt = recovery_.rtt().have_rtt ? recovery_.rtt().srtt : Clock::duration(Recovery::kMaxAckDelay);
        if (now - last_eliciting_send_ >= rtt && p < end) {
            *p++ = kPing;
            eliciting = true;
        }
    }
    sent_data_ = data_sent;
    if (p == buf + header && !keepalive) {
        recovery_.cancel_frames();
        return 0;
    }
    if (has_ack) ack_sent();
    return finish_packet(buf, header, pn_len, p, pn, now, eliciting, data_sent, repair, probe);
}

uint8_t* UdpConnection::write_control(uint8_t* p, uint8_t* end, bool& eliciting) {
    // Each of these is a few bytes, and a full packet always has room for all of
    // them — but one an unproven dialer has earned may be barely a header. What
    // does not fit stays owed for the next packet.
    const auto fits = [&](size_t n) { return p < end && static_cast<size_t>(end - p) >= n; };
    // Not recorded: lost, the challenge it answers is sent again.
    if (response_owed_ && fits(kPathResponseSize)) {
        p = put_path_response(p, response_data_);
        response_owed_ = false;
        eliciting      = true;
    }
    if (token_owed_ && fits(1 + kResetTokenSize)) {
        uint8_t token[kResetTokenSize];
        host_.reset_token(local_cid_, token);
        p = put_reset_token(p, token);
        token_owed_ = false;
        SentFrame f;
        f.kind = SentFrame::ResetToken;
        recovery_.add_frame(f);
        eliciting = true;
    }
    if (max_data_owed_ && fits(1 + varint_size(advertised_))) {
        p = put_value_frame(p, kMaxData, advertised_);
        max_data_owed_ = false;
        SentFrame f;
        f.kind   = SentFrame::MaxData;
        f.offset = advertised_;
        recovery_.add_frame(f);
        eliciting = true;
    }
    if (blocked_owed_ && fits(1 + varint_size(blocked_at_))) {
        p = put_value_frame(p, kDataBlocked, blocked_at_);
        blocked_owed_ = false;
        SentFrame f;
        f.kind   = SentFrame::DataBlocked;
        f.offset = blocked_at_;
        recovery_.add_frame(f);
        eliciting = true;
    }
    if (ping_owed_ && fits(1)) {
        *p++ = kPing;
        ping_owed_ = false;
        SentFrame f;
        f.kind = SentFrame::Ping;
        recovery_.add_frame(f);
        eliciting = true;
    }
    return p;
}

uint8_t* UdpConnection::write_data(uint8_t* p, uint8_t* end, Clock::time_point now, bool& repair) {
    // The most urgent priority first. Lanes are sorted by it, and none is ever at
    // Priority::Live, so the live messages go between the lanes ahead of them and
    // those behind.
    uint8_t* const start = p;
    size_t split = 0;
    while (split < lanes_.size() && lanes_[split]->priority < static_cast<uint8_t>(Priority::Live)) ++split;
    p = write_lanes(p, end, 0, split, repair);
    p = write_live(p, end, now, /*first=*/p == start, repair);
    return write_lanes(p, end, split, lanes_.size(), repair);
}

uint8_t* UdpConnection::write_lanes(uint8_t* p, uint8_t* end, size_t from, size_t to, bool& repair) {
    uint64_t budget = new_data_budget();

    // A priority at a time; within one, the lanes take turns, one packet each,
    // starting a little further round every packet.
    size_t lo = from;
    while (lo < to) {
        const uint8_t prio = lanes_[lo]->priority;
        size_t hi = lo;
        while (hi < to && lanes_[hi]->priority == prio) ++hi;
        const size_t n     = hi - lo;
        const size_t start = rr_[prio] % n;
        bool rotated = false;
        for (size_t k = 0; k < n; ++k) {
            const size_t idx  = lo + (start + k) % n;
            Lane&        lane = *lanes_[idx];
            const uint64_t id = static_cast<uint8_t>(lane.type);
            SendStream::Piece piece;
            // New data also waits while the peer is holding as much of unfinished
            // messages as it agreed to (max_unfinished); repairs never do.
            while (lane.send.peek((std::min)(budget, unfinished_room(lane, spread())), piece)) {
                if (p >= end) return p;
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
                f.length = static_cast<uint16_t>(len);
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

uint8_t* UdpConnection::write_live(uint8_t* p, uint8_t* end, Clock::time_point now, bool first,
                                   bool& repair) {
    LiveSender::Piece piece;
    for (; live_send_.peek(piece); first = false) {
        if (piece.fresh) {
            protect_live(piece, now);
            live_send_.peek(piece);
        }
        if (p >= end || static_cast<size_t>(end - p) < kMinFrameRoom) return p;

        if (piece.parity) {
            // Whole or not at all; a packet with less in it has room.
            if (!put_parity(p, end, piece, now)) return p;
            live_send_.take(piece, piece.len);
            SentFrame f;
            f.kind   = SentFrame::LiveRepair;
            f.length = static_cast<uint16_t>(piece.len);
            f.at     = piece.index;
            f.offset = piece.id;
            recovery_.add_frame(f);
            continue;
        }

        const size_t room = static_cast<size_t>(end - p);
        const uint64_t lifetime = ms_left(piece.deadline, now);
        size_t len = piece.len;
        // A protected message goes a symbol to a frame.
        if (piece.symbol) len = (std::min<size_t>)(len, piece.symbol - piece.offset % piece.symbol);
        size_t hdr = live_header_size(piece.id, lifetime, piece.size, piece.offset, len);
        if (hdr + len > room) {
            // A small message waits for a packet it fits whole, and a symbol for one
            // it fits in — unless this one has no data in it yet, when waiting
            // would only send it without any.
            if (!first && (piece.symbol || (piece.offset == 0 && piece.len == piece.size &&
                                            piece.size <= kMaxUnsplitLive)))
                return p;
            // Cut to fit: as a piece the header may grow (it names the size and
            // offset), and with a shorter length it can only shrink again.
            hdr = live_header_size(piece.id, lifetime, piece.size, piece.offset, (std::min)(len, room));
            if (hdr >= room) return p;
            len = room - hdr;
            hdr = live_header_size(piece.id, lifetime, piece.size, piece.offset, len);
        }

        p = put_live_header(p, piece.id, lifetime, piece.size, piece.offset, len);
        std::memcpy(p, live_send_.bytes(piece.id, piece.offset), len);
        p += len;
        live_send_.take(piece, len);
        if (piece.repair) repair = true;

        SentFrame f;
        f.kind   = SentFrame::Live;
        f.length = static_cast<uint16_t>(len);
        f.at     = piece.offset;
        f.offset = piece.id;
        recovery_.add_frame(f);
    }
    return p;
}

bool UdpConnection::put_parity(uint8_t*& p, uint8_t* end, const LiveSender::Piece& piece,
                               Clock::time_point now) {
    const uint64_t lifetime = ms_left(piece.deadline, now);
    const size_t hdr = live_repair_header_size(piece.id, lifetime, piece.size, piece.symbol, piece.index);
    if (p >= end || hdr + piece.len > static_cast<size_t>(end - p)) return false;
    p = put_live_repair_header(p, piece.id, lifetime, piece.size, piece.symbol, piece.index);
    std::memcpy(p, live_send_.parity_bytes(piece.id, piece.index), piece.len);
    p += piece.len;
    return true;
}

void UdpConnection::protect_live(const LiveSender::Piece& piece, Clock::time_point now) {
    const size_t symbol = kMaxDatagram - kShortHeaderSize - kMaxPnLength - session_->overhead() - kLiveFrameRoom;
    const fec::Layout layout = fec::Layout::fit(piece.size, static_cast<uint32_t>(symbol));
    live_send_.protect(piece.id, layout, live_repairs(layout, piece.deadline, now));
}

uint32_t UdpConnection::live_repairs(const fec::Layout& layout, Clock::time_point deadline,
                                     Clock::time_point now) {
    if (!config_.live_fec) return 0;
    // What an outage wrote off is no loss rate: repair symbols could not have
    // stood in for any of it.
    live_loss_.update(recovery_.sampler().delivered(), recovery_.path_lost());
    const cc::RttEstimate& rtt = recovery_.rtt();
    if (!rtt.have_rtt || live_loss_.rate() <= 0) return 0;
    // Whether a piece lost now could still be sent again in time: the message
    // leaves at the pacing rate, a loss is known a round trip and a reordering
    // window after — an ack delay more for the last piece — and the second copy
    // takes the one-way delay.
    const cc::PacingRate rate = recovery_.congestion().pacing_rate();
    const Clock::duration out   = rate.paced() ? rate.time_for(layout.size) : Clock::duration::zero();
    const Clock::duration again = rtt.srtt + rtt.srtt / 8 + Recovery::kMaxAckDelay + one_way();
    const double target = now + out + again <= deadline ? kLiveLossTargetWithArq : kLiveLossTarget;
    return fec::rows_for(layout.columns(0), live_loss_.rate(), target);
}

uint8_t* UdpConnection::write_repeat(uint8_t* p, uint8_t* end, Clock::time_point now) {
    size_t first = 0, count = 0;
    if (!recovery_.newest_in_flight(first, count)) return p;
    // Copied out first: the frames are recorded again below, which may move the log.
    std::vector<SentFrame> frames;
    frames.reserve(count);
    for (size_t i = 0; i < count; ++i) frames.push_back(recovery_.frames()[first + i]);
    for (SentFrame f : frames) {
        if (f.kind == SentFrame::LiveRepair) {
            LiveSender::Piece piece;
            if (!live_send_.repeat_parity(f.offset, f.at, now + one_way(), piece)) continue;
            if (!put_parity(p, end, piece, now)) break;
            recovery_.add_frame(f);
            continue;
        }
        if (f.kind == SentFrame::Live) {
            LiveSender::Piece piece;
            if (!live_send_.repeat(f.offset, f.at, f.length, now + one_way(), piece)) continue;
            const uint64_t lifetime = ms_left(piece.deadline, now);
            if (p >= end) break;
            const size_t hdr = live_header_size(piece.id, lifetime, piece.size, piece.offset, piece.len);
            if (hdr + piece.len > static_cast<size_t>(end - p)) break;
            p = put_live_header(p, piece.id, lifetime, piece.size, piece.offset, piece.len);
            std::memcpy(p, live_send_.bytes(piece.id, piece.offset), piece.len);
            p += piece.len;
            recovery_.add_frame(f);
            continue;
        }
        if (f.kind != SentFrame::Stream) continue;
        Lane* lane = lane_for(static_cast<MessageType>(f.stream), false);
        // Only what is still unacknowledged: the front of the frame may have been
        // delivered since by another packet, and its bytes released.
        uint64_t offset = f.offset;
        size_t   length = f.length;
        if (!lane || !lane->send.unacked_part(offset, length)) continue;
        f.offset = offset;
        f.length = static_cast<uint16_t>(length);
        if (p >= end) break;
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
    // Nothing goes out that can no longer arrive in time, and while something
    // still can, a path gone quiet is probed without backing off.
    live_send_.expire(now, one_way(), recovery_.congestion().pacing_rate());
    recovery_.set_impatient(live_send_.has_pending());
    const size_t queued_before = queued_bytes();
    recovery_.begin_sending(now, has_sendable_data());
    recovery_.clear_pacer_hold();

    bool window_stopped = false;
    for (;;) {
        // Stopped by the peer's window with data waiting: say so, once per limit —
        // it is the only way a receiver learns its window is what holds us back.
        if (new_data_budget() == 0 && stream_unsent() > 0 && blocked_at_ != peer_max_data_) {
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
            } else if (!recovery_.pace_allows(size) && !repairs_go_at_once()) {
                recovery_.hold_for_pacer(now, size);
                with_data = false;
            }
        }
        if (!with_data && !control) break;
        if (send_packet(now, with_data, false, false) == 0) break;
        // The control frames went and the windows still say no — or, never
        // expected, a packet that should have carried data did not. (Asked of the
        // packet, not of the bytes queued: repair symbols are not among those.)
        if (!with_data || !sent_data_) break;
    }
    const uint64_t waiting = stream_unsent() + live_send_.unsent() + live_send_.parity_unsent();
    recovery_.note_send_limits(waiting > 0, window_stopped, !has_sendable_data());

    // Sending — or dropping what expired — made room.
    if (want_write_ && queued_bytes() < queued_before) raise(PollOut);
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
        const size_t needed = kShortHeaderSize + kMaxPnLength + session_->overhead() + 1 + varint_size(code);
        if (amplification_room() < (std::max)(kMinShortPacket, needed)) return;
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
    lane->send.end_message();
    return true;
}

bool UdpConnection::send_live(FrameHeader header, ByteView payload, Clock::time_point deadline) {
    if (!established() || closing_) return false;
    live_send_.push(header, payload, deadline);
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
    // A live message is settled within its lifetime either way, so waiting for one
    // never holds a close up for long.
    if (!live_send_.empty()) return false;
    for (const auto& lane : lanes_)
        if (!lane->send.flushed()) return false;
    return true;
}

size_t UdpConnection::queued_bytes() const noexcept {
    uint64_t n = live_send_.unsent() + live_send_.lost_bytes();
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
    s.live_sent       = live_send_.sent();
    s.live_expired    = live_send_.expired();
    s.live_repair_bytes = live_send_.parity_sent();
    return s;
}

void UdpConnection::release_memory() {
    recovery_.release_memory();
    live_send_.release_memory();
    live_recv_.decay();
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
    if (challenge_.active) due = (std::min)(due, challenge_.due);
    if (quiet_due_ != kNever) due = (std::min)(due, quiet_due_);
    // A grown window goes back once what it was grown for is over (see tick).
    if (recv_window_ > initial_window_ && account_.held == 0) due = (std::min)(due, last_data_recv_ + kWindowDecay);
    // A live message that runs out while it waits is dropped then, not at the next
    // packet: what it holds counts against the queue's marks. One being put
    // together is given up the same way.
    if (const auto e = live_send_.next_expiry(one_way())) due = (std::min)(due, *e);
    if (const auto e = live_recv_.next_expiry())          due = (std::min)(due, *e);
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
    path_timer(now);

    // A window grown for a transfer that has gone quiet goes back to where it
    // started. What was advertised stands — it is a promise — so this only stops
    // it being carried further.
    if (recv_window_ > initial_window_ && account_.held == 0 && now - last_data_recv_ >= kWindowDecay)
        recv_window_ = initial_window_;
    live_recv_.expire(now, account_);

    live_send_.expire(now, one_way(), recovery_.congestion().pacing_rate());
    recovery_.set_impatient(live_send_.has_pending());
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
    if (quiet_due_ != kNever && now >= quiet_due_) {
        // Nothing from a peer that was sending. Whatever we sent in the meantime
        // already showed it where we are.
        if (now - last_send_ >= quiet_wait_) send_packet(now, false, false, false, /*keepalive=*/true);
        if (now - last_data_recv_ >= kQuietSteady) quiet_wait_ *= 2;
        quiet_due_ = quiet_wait_ < kKeepAlive ? now + quiet_wait_ : kNever;
    }
    // Say something now and then: it keeps the peer's idle timer from firing and
    // a NAT's mapping for the socket open. Not ack-eliciting, so a lost one costs
    // nothing — no timer, no window — and an idle connection stays idle to the
    // congestion controller.
    if (now - last_send_ >= kKeepAlive && send_packet(now, false, false, false, /*keepalive=*/true) == 0) {
        // Nothing could go — a responder whose dialer never proved its address has
        // spent what it may send. The keep-alive is due again a period from now,
        // not at once: a deadline left in the past would spin the reactor.
        last_send_ = now;
    }
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
            case SentFrame::Live:
                live_send_.on_acked(f.offset, f.at, f.length);
                break;
            case SentFrame::LiveRepair:
                live_send_.on_parity_acked(f.offset, f.at);
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
            case SentFrame::Live:
                live_send_.on_lost(f.offset, f.at, f.length);
                break;
            case SentFrame::LiveRepair:
                live_send_.on_parity_lost(f.offset, f.at);
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
    live_send_.clear();
    for (auto& lane : lanes_) {
        lane->send.clear();
        // An orderly close leaves what has arrived to be delivered; the transport
        // reports the end once it has been.
        if (!keep_inbox) lane->recv.clear(account_);
    }
    if (!keep_inbox) live_recv_.clear(account_);
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
