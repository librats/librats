#pragma once

/**
 * @file delivery_rate.h
 * @brief How fast the path is actually delivering: one rate sample per
 *        acknowledgement, independent of the controller that consumes it.
 *
 * A congestion window says how much *may* be outstanding; what a model-based
 * controller needs instead is a measurement of how much the path *delivered*, and
 * over how long. This is the estimator from draft-cheng-iccrg-delivery-rate-
 * estimation (the one Linux TCP and every BBR implementation run), and it works
 * by snapshotting the connection's delivery counters onto each packet as it
 * leaves:
 *
 *   - when an acknowledgement arrives, the newest packet it covers says how much
 *     had been delivered when that packet was sent (`prior_delivered`) and when;
 *   - the difference to what has been delivered now, over the longer of the send
 *     and the ack intervals, is the rate — the longer of the two, so a burst of
 *     acknowledgements compressed by the path cannot inflate it;
 *   - a packet sent while the application had nothing more to give is flagged
 *     *app-limited*, so the sample it produces is known to say "the sender was
 *     slow", not "the path was". Peer-to-peer traffic is app-limited most of the
 *     time, which is why this flag matters more here than in a bulk server.
 *
 * Bytes, not packets: every counter here is in payload bytes, the same unit the
 * stream's flight accounting uses, so a partly filled packet weighs what it
 * carries.
 *
 * Owned by the UdpStream and touched only on its reactor thread, like the stream.
 */

#include "librats/transport/udp_packet.h"

#include <algorithm>
#include <chrono>
#include <cstdint>

namespace librats {
namespace cc {

using Clock = std::chrono::steady_clock;

/// a * b / c, rounded down, without the intermediate product overflowing.
///
/// Exact for any divisor below 2^32 (a nanosecond duration up to ~4.3 s, a byte
/// count up to 4 GB), which covers everything the transport divides by; beyond
/// that it falls back to extended precision. The split is a*b = (qa*c + ra)*b,
/// and ra*b = ra*(qb*c + rb), so every product left over is below c^2.
inline uint64_t mul_div(uint64_t a, uint64_t b, uint64_t c) noexcept {
    if (c == 0) return 0;
    if ((c >> 32) != 0)
        return static_cast<uint64_t>(static_cast<long double>(a) * static_cast<long double>(b) /
                                     static_cast<long double>(c));
    const uint64_t qa = a / c, ra = a % c;
    const uint64_t qb = b / c, rb = b % c;
    return qa * b + ra * qb + (ra * rb) / c;
}

/// Nanoseconds in `d`, never negative.
inline uint64_t to_ns(Clock::duration d) noexcept {
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
    return ns > 0 ? static_cast<uint64_t>(ns) : 0;
}

/// What the sampler records on a packet each time it is transmitted. A
/// retransmission overwrites it: the sample a packet produces describes the copy
/// that was acknowledged, which is the only one the receiver can speak for.
struct TxState {
    Clock::time_point sent_at{};
    Clock::time_point first_sent_time{};   ///< start of the send interval it closes
    Clock::time_point delivered_time{};    ///< when `delivered` was last advanced
    uint64_t          delivered = 0;       ///< bytes delivered when this was sent
    uint64_t          lost      = 0;       ///< bytes declared lost when this was sent
    /// Bytes in flight once this was sent. 32 bits is plenty — a stream never has
    /// more than a window (~1.2 MB) out — and keeps the snapshot, which every
    /// queued packet carries, at 48 bytes.
    uint32_t          in_flight = 0;
    bool              app_limited = false; ///< sent with nothing else queued behind it
};

/// One acknowledgement's worth of measurement.
struct RateSample {
    /// The acknowledgement covered at least one packet, so `prior_delivered`,
    /// `tx_in_flight` and `lost` describe something. Rounds are counted off this.
    bool     acked = false;
    /// The interval was long enough to believe, so `delivery_rate` means something.
    /// An interval shorter than the minimum round trip is an artifact of
    /// acknowledgement compression and is discarded rather than trusted.
    bool     rate_valid = false;
    uint64_t delivery_rate = 0;       ///< bytes per second
    uint64_t delivered = 0;           ///< bytes delivered over the interval
    uint64_t prior_delivered = 0;     ///< total delivered when the newest acked packet left
    Clock::duration interval{};
    bool     is_app_limited = false;  ///< the newest acked packet was sent app-limited
    uint64_t tx_in_flight = 0;        ///< bytes in flight when the newest acked packet left
    uint64_t lost = 0;                ///< bytes declared lost since it left
};

class DeliveryRateSampler {
public:
    /// Stamp `tx` for a transmission at `now`. `flight_before` is what was in flight
    /// before this packet joined it; an empty pipe restarts both interval clocks,
    /// because the time the pipe stood empty was not time spent delivering.
    void on_sent(TxState& tx, Clock::time_point now, uint64_t flight_before,
                 uint64_t flight_after) noexcept {
        if (flight_before == 0) first_sent_time_ = delivered_time_ = now;
        tx.sent_at         = now;
        tx.first_sent_time = first_sent_time_;
        tx.delivered_time  = delivered_time_;
        tx.delivered       = delivered_;
        tx.lost            = lost_;
        tx.in_flight       = static_cast<uint32_t>(flight_after);
        tx.app_limited     = app_limited_until_ != 0;
    }

    /// A packet carrying `bytes` was acknowledged — cumulatively or selectively, but
    /// only ever once. `seq` breaks ties between packets sent in the same instant.
    void on_delivered(const TxState& tx, uint32_t seq, uint64_t bytes,
                      Clock::time_point now) noexcept {
        delivered_      += bytes;
        delivered_time_  = now;

        // The newest packet acknowledged decides the sample: it is the one whose
        // interval covers everything else this acknowledgement reports.
        const bool newer = !have_ || tx.sent_at > newest_sent_ ||
                           (tx.sent_at == newest_sent_ && rudp::seq_less(newest_seq_, seq));
        if (!newer) return;
        have_         = true;
        newest_sent_  = tx.sent_at;
        newest_seq_   = seq;
        prior_time_   = tx.delivered_time;
        send_elapsed_ = tx.sent_at - tx.first_sent_time;
        lost_at_send_ = tx.lost;
        sample_.prior_delivered = tx.delivered;
        sample_.is_app_limited  = tx.app_limited;
        sample_.tx_in_flight    = tx.in_flight;
        // The next interval starts where this one ended.
        first_sent_time_ = tx.sent_at;
    }

    void on_lost(uint64_t bytes) noexcept { lost_ += bytes; }

    /// Close the acknowledgement and hand over what it measured. `min_rtt` is the
    /// smallest round trip seen (zero when none has been), below which an interval
    /// is not a measurement of the path at all.
    RateSample take_sample(Clock::duration min_rtt) noexcept {
        // The app-limited bubble is over once everything sent inside it has been
        // delivered: from here on a sample describes the path again.
        if (app_limited_until_ != 0 && delivered_ > app_limited_until_) app_limited_until_ = 0;

        RateSample s = sample_;
        sample_ = RateSample{};
        if (!have_) return s;
        have_ = false;

        s.acked     = true;
        s.delivered = delivered_ - s.prior_delivered;
        s.lost      = lost_ - lost_at_send_;
        const Clock::duration ack_elapsed = delivered_time_ - prior_time_;
        s.interval  = (std::max)(send_elapsed_, ack_elapsed);
        if (s.interval > Clock::duration::zero() && s.interval >= min_rtt) {
            s.rate_valid    = true;
            s.delivery_rate = mul_div(s.delivered, 1000000000ull, to_ns(s.interval));
        }
        return s;
    }

    /// The application has nothing more to send and the window is not what is
    /// holding it back: every sample until what is in flight now has been
    /// delivered is a measurement of the sender, not of the path.
    void mark_app_limited(uint64_t bytes_in_flight) noexcept {
        app_limited_until_ = (std::max<uint64_t>)(delivered_ + bytes_in_flight, 1);
    }

    bool     app_limited() const noexcept { return app_limited_until_ != 0; }
    uint64_t delivered()   const noexcept { return delivered_; }
    uint64_t lost()        const noexcept { return lost_; }

private:
    uint64_t          delivered_ = 0;
    uint64_t          lost_      = 0;
    Clock::time_point delivered_time_{};
    Clock::time_point first_sent_time_{};
    uint64_t          app_limited_until_ = 0;

    // The acknowledgement being assembled.
    bool              have_ = false;
    Clock::time_point newest_sent_{};
    uint32_t          newest_seq_ = 0;
    Clock::time_point prior_time_{};
    Clock::duration   send_elapsed_{};
    uint64_t          lost_at_send_ = 0;
    RateSample        sample_;
};

} // namespace cc
} // namespace librats
