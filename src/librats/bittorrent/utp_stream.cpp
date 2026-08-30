#include "librats/bittorrent/utp_stream.h"

#include "librats/bittorrent/log.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <random>

namespace librats::bittorrent::utp {

namespace {

/// The wire carries a 32-bit microsecond clock. Its epoch is irrelevant — the peer
/// only ever subtracts two readings of *its own* clock from ours — so a steady
/// clock truncated to 32 bits is exactly right, and immune to the wall clock being
/// stepped underneath a live connection.
std::uint32_t micros(Stream::Clock::time_point t) noexcept {
    using namespace std::chrono;
    return std::uint32_t(duration_cast<microseconds>(t.time_since_epoch()).count() & 0xffffffffu);
}

std::uint16_t random_seq() {
    static thread_local std::mt19937 rng{std::random_device{}()};
    return std::uint16_t(std::uniform_int_distribution<std::uint32_t>(1, 0xfffe)(rng));
}

/// uTorrent has been observed sending an uninitialised INT_MAX here; treat it as
/// "no sample" rather than as 35 minutes of queuing delay.
constexpr std::uint32_t kBogusDelay = 0x7fffffffu;

constexpr std::uint32_t kNoRtt = (std::numeric_limits<std::uint32_t>::max)();

} // namespace

// ---- DelayHistory ------------------------------------------------------------

std::uint32_t DelayHistory::add_sample(std::uint32_t sample, bool step) {
    if (!initialized()) {
        for (auto& h : history_) h = sample;
        base_        = sample;
        num_samples_ = 0;
    }
    if (num_samples_ < 0xfffe) ++num_samples_;

    // Wrapping compares throughout: the samples are 32-bit clock differences, so a
    // sample taken either side of the clock's wrap must still order correctly.
    if (seq_less_u32(sample, base_)) {
        base_            = sample;
        history_[index_] = sample;
    } else if (seq_less_u32(sample, history_[index_])) {
        history_[index_] = sample;
    }

    const std::uint32_t ret = sample - base_;

    // Only step the ring when the connection has actually been busy. On an idle
    // link a handful of samples say nothing about the path's true minimum, and
    // stepping on them would throw away a good base for a bad one.
    if (step && num_samples_ > 120) {
        num_samples_     = 0;
        index_           = std::uint16_t((index_ + 1) % kHistorySize);
        history_[index_] = sample;
        base_            = sample;
        for (auto h : history_) {
            if (seq_less_u32(h, base_)) base_ = h;
        }
    }
    return ret;
}

void DelayHistory::adjust_base(int change) {
    base_ += std::uint32_t(change);
    // Make the adjustment stick: a history slot below the new base would pull it
    // straight back down on the next step.
    for (auto& h : history_) {
        if (seq_less_u32(h, base_)) h = base_;
    }
}

// ---- SlidingAverage ----------------------------------------------------------

void SlidingAverage::add_sample(int s) {
    s *= 64;  // fixed point
    const int deviation = num_samples_ > 0 ? std::abs(mean_ - s) : 0;
    if (num_samples_ < kInvertedGain) ++num_samples_;
    mean_ += (s - mean_) / num_samples_;
    // The deviation always has one sample fewer than the mean — you need two
    // readings before the first deviation exists.
    if (num_samples_ > 1) deviation_ += (deviation - deviation_) / (num_samples_ - 1);
}

// ---- Stream: construction & lifecycle ----------------------------------------

Stream::Stream(Host& host, std::uint16_t recv_id, std::uint16_t send_id)
    : host_(host), recv_id_(recv_id), send_id_(send_id) {
    // Start at one packet's worth of window, which is also LEDBAT's floor: the
    // controller never takes cwnd below one MSS, so a stream can always make
    // progress without waiting for a timeout.
    cwnd_ = std::int64_t(kMaxPayload) << 16;
}

void Stream::connect(const Address& to, Clock::time_point now) {
    remote_ = to;
    last_history_step_ = now;
    send_syn(now);
}

void Stream::send_syn(Clock::time_point now) {
    seq_nr_             = random_seq();
    acked_seq_nr_       = std::uint16_t(seq_nr_ - 1);
    loss_seq_nr_        = acked_seq_nr_;
    fast_resend_seq_nr_ = seq_nr_;
    ack_nr_             = 0;

    outbuf_.push_back(OutPacket{seq_nr_, PacketType::Syn, Bytes{}, {}, 0, false, false});
    transmit(outbuf_.back(), now);
    seq_nr_ = std::uint16_t(seq_nr_ + 1);

    state_   = State::SynSent;
    timeout_ = now + std::chrono::milliseconds(kConnectTimeoutMs);
}

void Stream::close(Clock::time_point now) {
    if (out_eof_ || state_ == State::Closed) return;
    out_eof_   = true;
    closed_at_ = now;

    if (state_ != State::Connected) {
        // Never got far enough for a FIN to mean anything. A half-open dial is torn
        // down silently; anything further along gets a reset so the peer stops
        // retransmitting into a socket that no longer exists.
        if (state_ == State::SynSent) send_reset_packet(now);
        state_ = State::Closed;
        return;
    }

    // The FIN is not queued here: it has to take the sequence number *after* the
    // last byte, and whatever is still in pending_ has not been given one yet (they
    // are assigned as packets go out, not as bytes arrive). Emitting it now would
    // number it ahead of data the peer has yet to see, and that peer would then
    // stop reading at the FIN and discard the rest. pump() releases it once the
    // queue behind it has drained; out_eof_ also disables Nagle, so the tail packet
    // no longer waits for anything.
    pump(now);
}

void Stream::reset(Clock::time_point now) {
    if (state_ == State::Closed) return;
    if (state_ != State::Idle) send_reset_packet(now);
    state_   = State::Closed;
    out_eof_ = true;
    closed_at_ = now;
}

bool Stream::reapable(Clock::time_point now) const noexcept {
    if (state_ == State::Closed) return true;
    if (!out_eof_) return false;
    // Our FIN is out. Once it has been acknowledged and the peer's own FIN has
    // arrived there is nothing left to say; otherwise linger briefly so a lost FIN
    // still gets retransmitted rather than leaving the peer hanging.
    if (outbuf_.empty() && in_eof_) return true;
    return now - closed_at_ > kLinger;
}

void Stream::fail(const std::string& why) {
    if (error_) return;
    error_ = true;
    state_ = State::Closed;
    if (obs_) obs_->on_utp_error(why);
}

// ---- Stream: sending ---------------------------------------------------------

std::uint32_t Stream::advertised_window() const noexcept {
    const std::size_t used = recv_bytes_ + inbuf_bytes_;
    return used >= kRecvBufferCapacity ? 0u : std::uint32_t(kRecvBufferCapacity - used);
}

std::size_t Stream::window_available() const noexcept {
    std::size_t win = (std::min)(std::size_t(cwnd_ >> 16), std::size_t(adv_wnd_));
    // Zero-window persist: if the peer has closed its window and nothing is in
    // flight, nothing would ever prompt it to tell us the window reopened — the
    // update it sent could itself have been lost. Force one packet through so the
    // conversation cannot stall permanently.
    if (probe_) win = (std::max)(win, kMaxPayload);
    return win > bytes_in_flight_ ? win - bytes_in_flight_ : 0;
}

std::size_t Stream::write_sack(std::uint8_t* out) const {
    std::memset(out, 0, kSackBytes);
    // Bit i names ack_nr_ + 2 + i: the packet after the hole at ack_nr_ + 1, which
    // is by definition the one we are missing.
    for (std::size_t i = 0; i < kSackBytes * 8; ++i) {
        if (inbuf_.count(std::uint16_t(ack_nr_ + 2 + i)) != 0) {
            out[i / 8] = std::uint8_t(out[i / 8] | (1u << (i % 8)));
        }
    }
    return kSackBytes;
}

void Stream::emit(PacketType type, std::uint16_t seq, const std::uint8_t* payload,
                  std::size_t payload_len, Clock::time_point now, bool with_sack) {
    Header h;
    h.type = type;
    // The one asymmetry in the protocol: a SYN goes out under the id its sender
    // expects the *answer* on, everything after it under the peer's id.
    h.connection_id  = (type == PacketType::Syn) ? recv_id_ : send_id_;
    h.timestamp      = micros(now);
    h.timestamp_diff = reply_micro_;
    h.wnd_size       = advertised_window();
    h.seq_nr         = seq;
    h.ack_nr         = ack_nr_;

    const bool sack = with_sack && has_sack();
    h.extension = sack ? std::uint8_t(ExtensionType::Sack) : 0;
    write_header(scratch_, h);

    std::size_t off = kHeaderSize;
    if (sack) {
        scratch_[off++] = 0;                          // no further extension
        scratch_[off++] = std::uint8_t(kSackBytes);   // record length
        off += write_sack(scratch_ + off);
    }
    if (payload_len > 0) {
        std::memcpy(scratch_ + off, payload, payload_len);
        off += payload_len;
    }
    host_.utp_send(remote_, scratch_, off);
    ++out_packets_;
}

void Stream::transmit(OutPacket& p, Clock::time_point now) {
    p.send_time = now;
    ++p.transmissions;
    if (!p.in_flight) {
        p.in_flight = true;
        bytes_in_flight_ += p.payload.size();
    }
    emit(p.type, p.seq, p.payload.data(), p.payload.size(), now, /*with_sack=*/true);
}

void Stream::send_state(Clock::time_point now) {
    // A pure acknowledgement consumes no sequence number, which is why seq_nr_ (the
    // number of the packet we have *not* sent yet) is the right thing to put in it.
    emit(PacketType::State, seq_nr_, nullptr, 0, now, /*with_sack=*/true);
    deferred_ack_ = false;
}

void Stream::send_reset_packet(Clock::time_point now) {
    emit(PacketType::Reset, random_seq(), nullptr, 0, now, /*with_sack=*/false);
}

void Stream::defer_ack() {
    if (deferred_ack_) return;
    deferred_ack_ = true;
    host_.utp_defer_ack(*this);
}

void Stream::send_deferred_ack(Clock::time_point now) {
    if (!deferred_ack_ || state_ == State::Closed || error_) { deferred_ack_ = false; return; }
    send_state(now);
}

Stream::IoResult Stream::write(const ByteView* slices, std::size_t count,
                               Clock::time_point now) {
    if (error_ || state_ == State::Closed) return {0, Status::Error};
    if (out_eof_) return {0, Status::Error};

    std::size_t taken = 0;
    bool        full  = false;
    for (std::size_t i = 0; i < count && !full; ++i) {
        const std::uint8_t* p = slices[i].data();
        std::size_t         n = slices[i].size();
        while (n > 0) {
            const std::size_t queued = pending_bytes_ + bytes_in_flight_ + taken;
            if (queued >= kSendHighWater) { full = true; break; }
            const std::size_t room = kSendHighWater - queued;

            // Grow the tail chunk up to a full packet before starting another. All
            // but the last chunk are therefore full, which is what lets pump()
            // decide "send now" from the front chunk's size alone.
            if (pending_.empty() || pending_.back().size() >= kMaxPayload) {
                pending_.emplace_back();
                pending_.back().reserve(kMaxPayload);
            }
            Bytes&            tail = pending_.back();
            const std::size_t take = (std::min)((std::min)(kMaxPayload - tail.size(), n), room);
            tail.insert(tail.end(), p, p + take);
            p     += take;
            n     -= take;
            taken += take;
        }
    }

    pending_bytes_ += taken;
    pump(now);

    if (taken == 0) {
        write_blocked_ = true;
        return {0, Status::WouldBlock};
    }
    // A short write is still backpressure: remember it so the reopening of the
    // window wakes the writer rather than leaving it waiting on nothing.
    if (pending_bytes_ + bytes_in_flight_ >= kSendHighWater) write_blocked_ = true;
    return {taken, Status::Ok};
}

void Stream::pump(Clock::time_point now) {
    if (state_ != State::Connected && state_ != State::FinSent) return;

    // Retransmissions first, in order. A timeout writes every outstanding packet off
    // (clearing in_flight) and resets the window to one; this is what puts them back
    // on the wire, one per ack as the window reopens. Sending only the oldest and
    // waiting for the next timeout to reach the one behind it would crawl at one
    // packet per RTO — a stall in everything but name on a path that loses anything.
    for (auto& p : outbuf_) {
        if (p.acked || p.in_flight) continue;
        if (window_available() < p.payload.size()) return;
        transmit(p, now);
    }

    while (!pending_.empty()) {
        Bytes& front = pending_.front();
        // Nagle: a part-full packet waits while anything is unacknowledged, so a
        // burst of small messages leaves as one packet instead of one each. It is
        // released the moment the link goes quiet — which, with an ack always on
        // its way, is never longer than a round trip.
        if (front.size() < kMaxPayload && bytes_in_flight_ > 0 && !out_eof_) break;
        if (window_available() < front.size()) break;

        outbuf_.push_back(OutPacket{seq_nr_, PacketType::Data, std::move(front), {}, 0, false, false});
        pending_.pop_front();
        pending_bytes_ -= outbuf_.back().payload.size();
        seq_nr_ = std::uint16_t(seq_nr_ + 1);
        transmit(outbuf_.back(), now);
    }

    // Everything the caller wrote is now numbered and on the wire, so the FIN can
    // take the next sequence number and genuinely mean "that was the last byte".
    // It carries no payload, so no window has to have room for it.
    if (out_eof_ && pending_.empty() && state_ == State::Connected) {
        outbuf_.push_back(OutPacket{seq_nr_, PacketType::Fin, Bytes{}, {}, 0, false, false});
        transmit(outbuf_.back(), now);
        seq_nr_  = std::uint16_t(seq_nr_ + 1);
        state_   = State::FinSent;
        timeout_ = now + std::chrono::milliseconds(packet_timeout());
    }
}

// ---- Stream: receiving -------------------------------------------------------

Stream::IoResult Stream::read(ByteSpan into) {
    std::size_t copied = 0;
    while (copied < into.size() && !recv_q_.empty()) {
        Bytes&            front = recv_q_.front();
        const std::size_t avail = front.size() - recv_head_;
        const std::size_t take  = (std::min)(avail, into.size() - copied);
        std::memcpy(into.data() + copied, front.data() + recv_head_, take);
        copied      += take;
        recv_head_  += take;
        recv_bytes_ -= take;
        if (recv_head_ == front.size()) {
            recv_q_.pop_front();
            recv_head_ = 0;
        }
    }
    if (copied > 0) return {copied, Status::Ok};
    if (error_) return {0, Status::Error};
    // Only report end-of-stream once everything before the FIN has been delivered:
    // a FIN that overtook a retransmission must not truncate the stream.
    if (in_eof_ && recv_q_.empty() && ack_nr_ == in_eof_seq_nr_) return {0, Status::Eof};
    return {0, Status::WouldBlock};
}

void Stream::deliver(const std::uint8_t* data, std::size_t len) {
    if (len == 0) return;
    recv_q_.emplace_back(data, data + len);
    recv_bytes_ += len;
}

void Stream::consume_data(const Header& h, const std::uint8_t* payload, std::size_t len) {
    if (h.type != PacketType::Data) return;
    if (in_eof_ && ack_nr_ == in_eof_seq_nr_) return;  // everything is already in

    // A peer that ignores the window we advertised gets its packets dropped rather
    // than being allowed to grow our buffers without bound.
    if (recv_bytes_ + inbuf_bytes_ + len > kRecvBufferCapacity) return;

    if (h.seq_nr == std::uint16_t(ack_nr_ + 1)) {
        deliver(payload, len);
        ack_nr_ = h.seq_nr;
        // The packet that arrived may have been the hole everything else was
        // queued behind, so drain the reorder buffer as far as it now reaches.
        for (;;) {
            auto it = inbuf_.find(std::uint16_t(ack_nr_ + 1));
            if (it == inbuf_.end()) break;
            inbuf_bytes_ -= it->second.size();
            deliver(it->second.data(), it->second.size());
            ack_nr_ = std::uint16_t(ack_nr_ + 1);
            inbuf_.erase(it);
        }
    } else {
        if (!seq_less(ack_nr_, h.seq_nr)) return;   // already delivered
        if (len == 0) return;
        if (inbuf_.count(h.seq_nr) != 0) return;    // already buffered
        inbuf_.emplace(h.seq_nr, Bytes(payload, payload + len));
        inbuf_bytes_ += len;
    }
}

// ---- Stream: acknowledgement -------------------------------------------------

Stream::OutPacket* Stream::packet_at(std::uint16_t seq) {
    if (outbuf_.empty()) return nullptr;
    const int idx = seq_diff(seq, outbuf_.front().seq);
    if (idx < 0 || std::size_t(idx) >= outbuf_.size()) return nullptr;
    return &outbuf_[std::size_t(idx)];
}

void Stream::ack_packet(OutPacket& p, Clock::time_point now, std::uint32_t& min_rtt) {
    p.acked = true;
    if (p.in_flight) {
        bytes_in_flight_ -= p.payload.size();
        p.in_flight = false;
    }
    // Karn's algorithm: a retransmitted packet gives an ambiguous sample (we cannot
    // tell which copy was acknowledged), so it contributes nothing to the estimate.
    if (p.transmissions == 1) {
        using namespace std::chrono;
        auto us = duration_cast<microseconds>(now - p.send_time).count();
        if (us < 0) us = 0;
        min_rtt = (std::min)(min_rtt, std::uint32_t(us));
        rtt_.add_sample(int(us / 1000));
    }
}

void Stream::pop_acked_front() {
    while (!outbuf_.empty() && outbuf_.front().acked) {
        acked_seq_nr_ = outbuf_.front().seq;
        outbuf_.pop_front();
    }
}

void Stream::process_ack(std::uint16_t ack_nr, Clock::time_point now,
                         int& acked_bytes, std::uint32_t& min_rtt) {
    for (std::uint16_t s = std::uint16_t(acked_seq_nr_ + 1);; s = std::uint16_t(s + 1)) {
        if (fast_resend_seq_nr_ == s) fast_resend_seq_nr_ = std::uint16_t(s + 1);
        if (OutPacket* p = packet_at(s); p != nullptr && !p->acked) {
            acked_bytes += int(p->payload.size());
            ack_packet(*p, now, min_rtt);
        }
        if (s == ack_nr) break;
    }
    pop_acked_front();
    if (outbuf_.empty()) duplicate_acks_ = 0;
}

void Stream::process_sack(std::uint16_t packet_ack, const std::uint8_t* bitmap, std::size_t len,
                          Clock::time_point now, int& acked_bytes, std::uint32_t& min_rtt) {
    if (len == 0) return;

    // At most five candidates: past that the loss is severe enough that the
    // retransmit timer is the right recovery mechanism, not fast resend.
    std::uint16_t to_resend[5];
    int           num_to_resend = 0;

    // The packet at packet_ack + 1 is the hole the SACK exists to describe.
    if (!seq_less(std::uint16_t(packet_ack + 1), fast_resend_seq_nr_)) {
        to_resend[num_to_resend++] = std::uint16_t(packet_ack + 1);
    }

    std::uint16_t ack  = std::uint16_t(packet_ack + 2);
    bool          done = false;
    for (std::size_t i = 0; i < len && !done; ++i) {
        const std::uint8_t bits = bitmap[i];
        for (int b = 0; b < 8; ++b) {
            if (bits & (1u << b)) {
                if (OutPacket* p = packet_at(ack); p != nullptr && !p->acked) {
                    acked_bytes += int(p->payload.size());
                    ack_packet(*p, now, min_rtt);
                }
            } else if (!seq_less(ack, fast_resend_seq_nr_) && num_to_resend < 5) {
                to_resend[num_to_resend++] = ack;
            }
            ack = std::uint16_t(ack + 1);
            // Bits past the last packet we sent describe nothing.
            if (ack == seq_nr_) { done = true; break; }
        }
    }

    pop_acked_front();
    if (outbuf_.empty()) duplicate_acks_ = 0;

    // Scan back from the end of the bitmap counting acknowledged packets: only a
    // hole with more than kDupAckLimit acked packets *behind* it is loss rather
    // than reordering, and only holes before that point may be resent.
    std::uint16_t last_resend = std::uint16_t(packet_ack + 1 + len * 8);
    int           dups        = 0;
    for (std::size_t i = len; i > 0; --i) {
        const std::uint8_t bits = bitmap[i - 1];
        std::uint8_t       mask = 0x80;
        for (int k = 0; k < 8; ++k) {
            if (mask & bits) ++dups;
            if (dups > kDupAckLimit) break;
            last_resend = std::uint16_t(last_resend - 1);
            mask >>= 1;
        }
        if (dups > kDupAckLimit) break;
    }
    if (dups <= kDupAckLimit) num_to_resend = 0;
    while (num_to_resend > 0 && !seq_less(to_resend[num_to_resend - 1], last_resend)) --num_to_resend;

    bool cut_cwnd = true;
    for (int i = 0; i < num_to_resend; ++i) {
        OutPacket* p = packet_at(to_resend[i]);
        if (p == nullptr || p->acked) continue;
        // One window cut per loss event, not per lost packet.
        if (cut_cwnd) {
            experienced_loss(to_resend[i], now);
            cut_cwnd = false;
        }
        resend(*p, now, /*fast=*/true);
        duplicate_acks_     = 0;
        fast_resend_seq_nr_ = std::uint16_t(to_resend[i] + 1);
    }
}

void Stream::resend(OutPacket& p, Clock::time_point now, bool fast) {
    (void)fast;
    if (p.acked) return;
    // A retransmission is not new data in flight; it replaces what was already
    // counted, so the accounting only changes when the packet had been written off
    // by a timeout (which clears in_flight).
    transmit(p, now);
}

// ---- Stream: congestion control ----------------------------------------------

void Stream::experienced_loss(std::uint16_t seq, Clock::time_point now) {
    // Loss arrives in bursts, and a burst inside one round trip is one event. Two
    // guards enforce that: only a packet sent *after* the last cut can cause the
    // next one, and no two cuts happen inside kCwndReduceTimerMs.
    if (seq_less(seq, std::uint16_t(loss_seq_nr_ + 1))) return;
    if (next_loss_ >= now) return;
    next_loss_ = now + std::chrono::milliseconds(kCwndReduceTimerMs);

    cwnd_ = (std::max)(cwnd_ * kLossMultiplier / 100, std::int64_t(kMaxPayload) << 16);
    loss_seq_nr_ = seq_nr_;

    if (slow_start_) {
        // Set the threshold to the window *after* the cut, so the next slow start
        // stops before overshooting into the same loss again.
        ssthresh_   = std::int32_t(cwnd_ >> 16);
        slow_start_ = false;
    }
}

void Stream::do_ledbat(int acked_bytes, int delay, int in_flight) {
    if (in_flight <= 0 || acked_bytes <= 0) return;

    const int target_delay = (std::max)(1, kTargetDelayUs);

    // Only steer the window when the application is actually trying to fill it.
    // Growing an idle connection's window would let it burst at an unproven rate
    // the moment it has something to send.
    const bool cwnd_saturated =
        (std::int64_t(bytes_in_flight_) + acked_bytes + std::int64_t(kMaxPayload)) > (cwnd_ >> 16);

    // Both fixed point, 16 fractional bits. window_factor scales the update by the
    // share of the window this ack covers, so the formula applies once per RTT
    // however many acks that RTT is split into.
    const std::int64_t window_factor = (std::int64_t(acked_bytes) * (1 << 16)) / in_flight;
    const std::int64_t delay_factor  = (std::int64_t(target_delay - delay) * (1 << 16)) / target_delay;
    std::int64_t       scaled_gain;

    if (delay >= target_delay && slow_start_) {
        // We have found the path's queuing point; stop doubling.
        ssthresh_   = std::int32_t((cwnd_ >> 16) / 2);
        slow_start_ = false;
    }

    const std::int64_t linear_gain = ((window_factor * delay_factor) >> 16) * std::int64_t(kGainFactor);

    if (cwnd_saturated) {
        const std::int64_t exponential_gain = std::int64_t(acked_bytes) * (1 << 16);
        if (slow_start_) {
            if (ssthresh_ != 0 && ((cwnd_ + exponential_gain) >> 16) > ssthresh_) {
                // Doubling would take us past the threshold we already learned the
                // hard way; walk in linearly from here instead.
                slow_start_ = false;
                scaled_gain = linear_gain;
            } else {
                scaled_gain = (std::max)(exponential_gain, linear_gain);
            }
        } else {
            scaled_gain = linear_gain;
        }
    } else {
        scaled_gain = 0;
    }

    if (scaled_gain >= (std::numeric_limits<std::int64_t>::max)() - cwnd_) {
        scaled_gain = (std::numeric_limits<std::int64_t>::max)() - cwnd_ - 1;
    }

    // RFC 6817 floors the window at one MSS. BEP 29 allows it to reach zero, but
    // then only a timeout can restart the flow — a full second of silence to
    // recover from a delay spike that has probably already passed.
    if ((cwnd_ + scaled_gain) >> 16 < std::int64_t(kMaxPayload)) {
        cwnd_ = std::int64_t(kMaxPayload) << 16;
    } else {
        cwnd_ += scaled_gain;
    }

}

int Stream::packet_timeout() const {
    // No RTT estimate exists before the handshake completes, so guess conservatively.
    if (state_ == State::Idle || state_ == State::SynSent) return kConnectTimeoutMs;
    if (num_timeouts_ >= 7) return 60000;
    int timeout = (std::max)(kMinTimeoutMs, rtt_.mean() + rtt_.avg_deviation() * 2);
    if (num_timeouts_ > 0) timeout += (1 << (num_timeouts_ - 1)) * 1000;
    return (std::min)(timeout, 60000);
}

// ---- Stream: the incoming packet ---------------------------------------------

bool Stream::on_packet(const std::uint8_t* data, std::size_t len,
                       const Address& from, Clock::time_point now) {
    if (state_ == State::Closed || error_) return false;

    Header h;
    if (!parse_header(data, len, h)) return false;
    if (std::uint8_t(h.type) >= kNumPacketTypes) return false;
    // A SYN names the id its sender will listen on, so it is the one packet whose
    // connection_id is not ours.
    if (h.type != PacketType::Syn && h.connection_id != recv_id_) return false;
    if (state_ != State::Idle && h.type == PacketType::Syn) return true;  // duplicate SYN

    if (state_ == State::Idle && h.type == PacketType::Syn) remote_ = from;

    const bool step = last_history_step_ == Clock::time_point{}
                      || now - last_history_step_ > std::chrono::minutes(1);
    if (step) last_history_step_ = now;

    // Measure how long their packet took to reach us. The absolute number is
    // meaningless (unrelated clocks); what we do with it is reflect it back in
    // every packet we send, which is what feeds *their* congestion control.
    std::uint32_t their_delay = 0;
    if (h.timestamp != 0) {
        reply_micro_ = micros(now) - h.timestamp;
        const std::uint32_t prev_base = their_delay_hist_.initialized() ? their_delay_hist_.base() : 0;
        their_delay = their_delay_hist_.add_sample(reply_micro_, step);
        const int base_change = int(their_delay_hist_.base() - prev_base);
        // Their base delay fell: the two clocks are drifting apart rather than the
        // path improving, so shift our own base by the same amount to compensate.
        if (prev_base != 0 && base_change < 0 && base_change > -10000 && delay_hist_.initialized()) {
            delay_hist_.adjust_base(-base_change);
        }
    }
    (void)their_delay;

    const bool state_or_fin = h.type == PacketType::State || h.type == PacketType::Fin;
    // seq_nr_ is the number of the packet we have *not* sent yet, so the last one
    // we did send is seq_nr_ - 1. An ack beyond it acknowledges something that does
    // not exist — a third party's injection, or a confused peer. Drop it, but do
    // not tear the connection down over it.
    const std::uint16_t cmp_seq_nr = std::uint16_t(seq_nr_ - 1);
    if ((state_ != State::Idle || h.type != PacketType::Syn)
        && (seq_less(cmp_seq_nr, h.ack_nr)
            || seq_less(h.ack_nr, std::uint16_t(acked_seq_nr_ - kDupAckLimit)))) {
        return true;
    }

    // Anything claiming to come after a FIN we have already seen is bogus; a STATE
    // or FIN carrying the FIN's own sequence number is the legitimate exception.
    if (in_eof_ && seq_less(in_eof_seq_nr_, h.seq_nr)
        && !(in_eof_seq_nr_ == h.seq_nr && state_or_fin)) {
        return true;
    }

    // A reset is judged on its ack_nr alone. Its seq_nr is deliberately random (it
    // ends a stream rather than carrying a place in one), so it has to be handled
    // before the reordering window below would throw it away as impossibly far
    // ahead. What keeps it from being a way to tear down any connection you can
    // guess an id for is the ack: it must name something we really sent, which
    // together with the source-address check is a window an off-path attacker
    // cannot practically hit.
    if (h.type == PacketType::Reset) {
        if (seq_less(cmp_seq_nr, h.ack_nr)) return true;  // not acking anything we sent
        fail("connection reset by peer");
        return true;
    }

    // Too far ahead to ever fit in the reorder buffer: either an attack or a
    // connection so damaged that dropping this is the least of its problems.
    const std::uint32_t max_reorder = (std::max)(std::uint32_t(16), std::uint32_t(kRecvBufferCapacity / 1100));
    if (state_ != State::Idle && state_ != State::SynSent
        && seq_less(std::uint16_t(ack_nr_ + max_reorder), h.seq_nr)) {
        return true;
    }

    const std::uint32_t sample = h.timestamp_diff == kBogusDelay ? 0 : h.timestamp_diff;
    std::uint32_t       delay  = 0;
    if (sample != 0) {
        delay = delay_hist_.add_sample(sample, step);
        delay_samples_[delay_sample_idx_++] = delay;
        if (delay_sample_idx_ >= kDelaySampleCount) delay_sample_idx_ = 0;
    }

    int               acked_bytes      = 0;
    const std::size_t prev_in_flight   = bytes_in_flight_;
    adv_wnd_ = h.wnd_size;

    // Only a STATE counts towards duplicate acks: a stream of DATA packets carries
    // whatever ack number happens to be current, which says nothing about loss in
    // the other direction.
    if (h.ack_nr == acked_seq_nr_ && !outbuf_.empty() && h.type == PacketType::State) {
        ++duplicate_acks_;
    }

    std::uint32_t min_rtt = kNoRtt;
    if (state_ != State::Idle && seq_less(acked_seq_nr_, h.ack_nr)) {
        process_ack(h.ack_nr, now, acked_bytes, min_rtt);
    }

    const std::size_t header_size = walk_extensions(data, len, h, [&](const Extension& e) {
        if (e.type == ExtensionType::Sack) {
            process_sack(h.ack_nr, e.data, e.len, now, acked_bytes, min_rtt);
        }
        // ExtensionType::CloseReason is deliberately ignored — see utp_stream.h.
    });
    if (header_size == 0) return true;  // malformed extension chain

    // A packet that made it this far is proof the peer is alive; reset the
    // retransmit clock. Done after the acks, since they change packet_timeout().
    num_timeouts_ = 0;
    timeout_      = now + std::chrono::milliseconds(packet_timeout());

    if (duplicate_acks_ >= kDupAckLimit
        && std::uint16_t(acked_seq_nr_ + 1) == fast_resend_seq_nr_) {
        OutPacket* p        = packet_at(fast_resend_seq_nr_);
        fast_resend_seq_nr_ = std::uint16_t(fast_resend_seq_nr_ + 1);
        if (p != nullptr && !p->acked) {
            experienced_loss(p->seq, now);
            resend(*p, now, /*fast=*/true);
        }
    }

    const std::uint8_t* payload      = data + header_size;
    const std::size_t   payload_size = len - header_size;

    if (h.type == PacketType::Fin) {
        // A duplicate FIN still has to be acknowledged, or the peer keeps sending it.
        if (h.seq_nr == std::uint16_t(ack_nr_ + 1) || h.seq_nr == ack_nr_) ack_nr_ = h.seq_nr;
        if (!in_eof_) {
            in_eof_        = true;
            in_eof_seq_nr_ = h.seq_nr;
        }
        confirmed_ = true;
        defer_ack();
        if (obs_ != nullptr) obs_->on_utp_readable();
        return true;
    }

    const std::uint32_t prev_out_packets = out_packets_;

    switch (state_) {
        case State::Idle: {
            if (h.type != PacketType::Syn) break;
            // The responder's half of the handshake. Our send id must be the id the
            // SYN named, or the manager routed this to the wrong stream.
            if (send_id_ != h.connection_id) return false;
            state_              = State::Connected;
            remote_             = from;
            ack_nr_             = h.seq_nr;
            seq_nr_             = random_seq();
            acked_seq_nr_       = std::uint16_t(seq_nr_ - 1);
            loss_seq_nr_        = acked_seq_nr_;
            fast_resend_seq_nr_ = seq_nr_;
            defer_ack();
            break;
        }
        case State::SynSent: {
            // Nothing but the answer to our SYN is interesting here.
            if (h.ack_nr != std::uint16_t(seq_nr_ - 1)) break;
            state_ = State::Connected;
            // ack_nr_ is uninitialised until now; a STATE carries the sequence
            // number it *will* use next, so step back one to keep it in order.
            ack_nr_    = (h.type == PacketType::Data) ? h.seq_nr : std::uint16_t(h.seq_nr - 1);
            confirmed_ = true;
            timeout_   = now + std::chrono::milliseconds(packet_timeout());
            if (obs_ != nullptr) obs_->on_utp_connected();
            if (error_ || state_ == State::Closed) return true;
            [[fallthrough]];
        }
        case State::Connected:
        case State::FinSent: {
            if (sample != 0 && acked_bytes > 0 && prev_in_flight > 0) {
                // The lowest of the last three samples, clamped by the round-trip
                // time: a one-way delay cannot exceed the round trip, and taking the
                // minimum filters out the spikes a single scheduling hiccup causes.
                delay = *std::min_element(std::begin(delay_samples_), std::end(delay_samples_));
                if (delay > min_rtt) delay = min_rtt;
                do_ledbat(acked_bytes, int(delay), int(prev_in_flight));
            }

            consume_data(h, payload, payload_size);
            // Past every check, so the source address is not spoofed: whoever is
            // there answered with sequence numbers only the real peer could know.
            if (h.type != PacketType::Syn) confirmed_ = true;

            pump(now);

            // We owe an ack for anything that consumed a sequence number. If pump()
            // put a packet on the wire it already carried one; otherwise defer it to
            // the end of this receive burst so N packets cost one ack, not N.
            if (payload_size > 0 && out_packets_ == prev_out_packets) defer_ack();
            break;
        }
        case State::Closed:
            break;
    }

    if (obs_ != nullptr && !error_) {
        // Anything the reader could act on — bytes, or the end of the stream.
        if (recv_bytes_ > 0 || (in_eof_ && ack_nr_ == in_eof_seq_nr_)) obs_->on_utp_readable();
        if (write_blocked_ && pending_bytes_ + bytes_in_flight_ < kSendHighWater) {
            write_blocked_ = false;
            obs_->on_utp_writable();
        }
    }
    return true;
}

// ---- Stream: the timer -------------------------------------------------------

void Stream::tick(Clock::time_point now) {
    if (state_ == State::Closed || error_) return;
    if (now < timeout_) return;

    // Nothing in flight but data waiting: the peer's window is shut and the update
    // reopening it may never come. Probe with one packet regardless — the classic
    // TCP persist timer, and the only thing standing between us and a permanent stall.
    if (outbuf_.empty() && !pending_.empty()) {
        probe_ = true;
        pump(now);
        probe_   = false;
        timeout_ = now + std::chrono::milliseconds(packet_timeout());
        return;
    }

    if (!outbuf_.empty()) ++num_timeouts_;

    const int max_resends = state_ == State::SynSent ? kSynResends
                            : out_eof_               ? kFinResends
                                                     : kNumResends;
    // A peer we have never heard from fails on its first timeout: the address may
    // simply be wrong, and there is no reason to spend three retransmissions on it.
    if (num_timeouts_ > max_resends || (num_timeouts_ > 0 && !confirmed_)) {
        if (state_ == State::FinSent) {
            // Our close never got acknowledged. Nothing is owed to anyone here.
            state_ = State::Closed;
            return;
        }
        fail("connection timed out");
        return;
    }

    if (!outbuf_.empty()) {
        // Back to one packet. An idle connection only decays its window, since a
        // timeout there says nothing about the path — we simply weren't using it.
        if (bytes_in_flight_ == 0 && (cwnd_ >> 16) >= std::int64_t(kMaxPayload)) {
            cwnd_ = (std::max)(cwnd_ * 2 / 3, std::int64_t(kMaxPayload) << 16);
        } else {
            cwnd_ = std::int64_t(kMaxPayload) << 16;
        }
        // Don't charge the window again for packets that just timed out together,
        // and re-enter slow start: with an ssthresh now known, ramping back up is
        // both fast and bounded.
        loss_seq_nr_ = seq_nr_;
        slow_start_  = true;

        // Everything outstanding is written off. pump() then puts the oldest back on
        // the wire immediately and the rest as acks reopen the window, rather than
        // dumping the whole flight into a path that has just shown it cannot take it.
        for (auto& p : outbuf_) {
            if (p.in_flight) {
                bytes_in_flight_ -= p.payload.size();
                p.in_flight = false;
            }
        }
        const OutPacket& oldest = outbuf_.front();
        if (fast_resend_seq_nr_ == oldest.seq) fast_resend_seq_nr_ = std::uint16_t(oldest.seq + 1);
        pump(now);
    }

    timeout_ = now + std::chrono::milliseconds(packet_timeout());
}

} // namespace librats::bittorrent::utp
