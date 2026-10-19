#pragma once

/**
 * @file congestion_control.h
 * @brief The seam between a datagram connection's loss recovery and the algorithm
 *        that decides how much it may have in flight and how fast it may send it.
 *
 * Recovery (udp_recovery.h) owns everything that is a *fact* about the
 * connection: which packets are outstanding, which were acknowledged, which it
 * has given up on, the round-trip estimate and the loss timer, and the
 * delivery-rate samples (delivery_rate.h). A controller owns only the *policy* —
 * a congestion window and a pacing rate — and learns about the connection
 * through the hooks below. That split is what lets two very different algorithms
 * sit behind one interface:
 *
 *   - Reno (reno.h) is driven by loss: it grows on acknowledged bytes and halves
 *     once per loss episode.
 *   - BBR (bbr.h) is driven by a model: it reads bandwidth and minimum round trip
 *     off the rate samples, and treats loss as a signal only above a threshold.
 *
 * Hook order on one acknowledgement is fixed, so a controller can rely on it:
 * on_rtt_sample() for each packet that yields a clean round trip, then
 * on_packet_lost() for each packet declared lost while processing it, then
 * on_congestion_event() if that opened a loss episode, then on_ack() with the
 * totals. Like the connection, a controller runs on one reactor thread and holds
 * no locks.
 */

#include "librats/core/types.h"
#include "librats/transport/delivery_rate.h"
#include "librats/transport/udp_wire.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>

namespace librats {
namespace cc {

/// The unit every window here is a multiple of: one full datagram. Windows count
/// whole packets as they leave — header, frames and tag — the way RFC 9002 does.
constexpr uint32_t kMss = static_cast<uint32_t>(udp::kMaxDatagram);
/// Initial congestion window. Four packets is the classic conservative start
/// (RFC 3390 territory) — enough to get an RTT sample and trigger fast retransmit
/// on an early loss, without a burst into an unknown path.
constexpr uint32_t kInitialWindow = 4 * kMss;
/// The ceiling on the congestion window, ~80 MB. What the receiver will hold is
/// its flow-control limit to enforce, separately and absolutely — this only keeps
/// the arithmetic bounded. A controller must not grow its window on acks that a
/// full window did not produce (see RenoController::on_ack): with nothing else
/// above it, a window that runs away past what is really in flight takes a
/// spurious loss with it when it is finally cut.
constexpr uint32_t kMaxWindow = 65535 * kMss;

/// The connection's round-trip estimator, readable by the controller. RFC 6298 state
/// plus the minimum and the latest sample, which model-based controllers want.
struct RttEstimate {
    Clock::duration srtt{};
    Clock::duration rttvar{};
    Clock::duration latest{};
    Clock::duration min_rtt = (Clock::duration::max)();
    /// The current retransmission timeout, backoff included.
    Clock::duration rto{};
    bool            have_rtt = false;

    /// The minimum round trip, or zero before there is one — the form the
    /// delivery-rate sampler takes it in.
    Clock::duration min_or_zero() const noexcept {
        return have_rtt ? min_rtt : Clock::duration::zero();
    }
};

/// The queueing delay that counts as a queue on a path whose least round trip is
/// `min_rtt`: an eighth of it, within 4–16 ms (RFC 9406's RTT threshold) — above
/// the jitter a path shows with nothing queued, below what one burst builds.
inline Clock::duration queue_threshold(Clock::duration min_rtt) noexcept {
    const Clock::duration lo = std::chrono::milliseconds(4), hi = std::chrono::milliseconds(16);
    return (std::min)((std::max)(min_rtt / 8, lo), hi);
}

/// A pacing rate as a ratio: `bytes` released every `per`. A ratio rather than a
/// bytes-per-second figure so a window-based controller can say "cwnd per srtt"
/// without first rounding it into a rate, and a rate-based one simply passes one
/// second. `bytes == 0` means "do not pace".
struct PacingRate {
    uint64_t        bytes = 0;
    Clock::duration per{};

    bool paced() const noexcept { return bytes > 0 && per > Clock::duration::zero(); }

    /// Bytes this rate releases over `dt`, rounded down.
    uint64_t bytes_over(Clock::duration dt) const noexcept {
        if (!paced() || dt <= Clock::duration::zero()) return 0;
        return mul_div(bytes, to_ns(dt), to_ns(per));
    }

    /// How long this rate takes to release `n` bytes, rounded down.
    Clock::duration time_for(uint64_t n) const noexcept {
        if (!paced()) return Clock::duration::zero();
        return std::chrono::duration_cast<Clock::duration>(
            std::chrono::nanoseconds(mul_div(n, to_ns(per), bytes)));
    }

    static PacingRate per_second(uint64_t bytes_per_second) noexcept {
        return PacingRate{bytes_per_second, std::chrono::seconds(1)};
    }
};

/// Everything one acknowledgement changed.
struct AckEvent {
    Clock::time_point now{};
    uint64_t largest_acked = 0;     ///< the highest packet number acknowledged so far
    uint64_t next_pn       = 0;     ///< the number the next packet sent will take
    /// Bytes acknowledged for the first time.
    uint64_t newly_acked = 0;
    /// Of those, the bytes acknowledged outside a loss episode, of packets sent
    /// after the last one began: what a classic window grows by. Growing during an
    /// episode, or on what was sent into the congestion it answers, would undo the
    /// reduction (RFC 9002 §7.3.2).
    uint64_t newly_acked_clean = 0;
    /// Bytes declared lost since the previous acknowledgement, by this one. What a
    /// timeout in between wrote off is not among them: on_timeout was the news.
    uint64_t newly_lost = 0;
    uint64_t bytes_in_flight = 0;   ///< after the acknowledgement was applied
    /// The window, not the application or the pacer, held the sender back at some
    /// point since the previous acknowledgement.
    bool     cwnd_limited = false;
    /// How long the packets it newly acknowledges spent in flight — sent to this
    /// acknowledgement, less the delay the peer reports — summed over them, and
    /// how many. Unlike the one round-trip sample an acknowledgement gives, taken
    /// from its newest packet, which on a path that reorders is the one that
    /// overtook the rest.
    Clock::duration flight_time{};
    uint32_t        flight_packets = 0;
    RateSample rs;
};

/// One packet declared lost: what it carried, and the state it was sent into.
struct LostPacket {
    Clock::time_point now{};
    uint64_t bytes = 0;
    uint64_t tx_in_flight = 0;       ///< bytes in flight when it was sent
    uint64_t lost_since_sent = 0;    ///< bytes lost since it was sent, itself included
    bool     app_limited = false;
};

class CongestionController {
public:
    virtual ~CongestionController() = default;

    virtual CongestionAlgorithm algorithm() const noexcept = 0;

    /// Bytes that may be in flight.
    virtual uint32_t cwnd() const noexcept = 0;

    /// How fast new data may leave. Recovery meters every transmission against it
    /// with a token bucket a millisecond deep (see its pacer).
    virtual PacingRate pacing_rate() const noexcept = 0;

    /// An ack-eliciting packet of `bytes` just went on the wire; `bytes_in_flight`
    /// already includes it.
    virtual void on_packet_sent(Clock::time_point now, uint64_t bytes,
                                uint64_t bytes_in_flight) = 0;

    /// One round-trip measurement, after the connection's estimator has absorbed it,
    /// and how long the peer says it held the acknowledgement back. `rtt` is raw —
    /// the delay is not taken off it — so a minimum stays a floor; what is left
    /// once it is (never below that minimum) is the time spent in queues.
    virtual void on_rtt_sample(Clock::duration rtt, Clock::duration ack_delay) = 0;

    /// A packet was declared lost and is about to be repaired.
    virtual void on_packet_lost(const LostPacket& lost) = 0;

    /// A loss episode began: the first loss since the last one was repaired.
    /// Exactly once per episode, however many packets it spans.
    virtual void on_congestion_event(Clock::time_point now, uint64_t bytes_in_flight,
                                     uint64_t newly_acked) = 0;

    /// The episode is over: everything outstanding when it began is acknowledged.
    virtual void on_recovery_exit(Clock::time_point now) = 0;

    /// The retransmission timeout fired with nothing heard back. Called before
    /// recovery writes off what was in flight, so `bytes_in_flight` is what the
    /// timeout gave up on — and the only time the controller hears of it.
    virtual void on_timeout(Clock::time_point now, uint64_t bytes_in_flight) = 0;

    /// An acknowledgement that acknowledged or lost something.
    virtual void on_ack(const AckEvent& ack) = 0;

    /// The connection is about to look for something to send. `has_data` says data
    /// is waiting; `app_limited` that the last thing it did was run out of it.
    /// Returns true when the pacer's token bucket describes a rate that no longer
    /// applies and should be emptied.
    virtual bool on_send_opportunity(Clock::time_point now, uint64_t bytes_in_flight,
                                     bool has_data, bool app_limited) = 0;

    /// The controller is deliberately holding the sender below what the path can
    /// carry (BBR's ProbeRTT), so what it measures now must be flagged app-limited
    /// rather than taken as the path's capacity.
    virtual bool wants_app_limited() const noexcept { return false; }

    /// Whether recovery should supplement this controller's window with
    /// proportional rate reduction in recovery (RFC 6937). A window-based
    /// controller that just halved its window needs it, or nothing leaves until
    /// half a window of acknowledgements is back. One that already paces its own
    /// recovery (BBR's packet conservation and per-loss window modulation) must
    /// not get it on top — it would be throttled twice, which is also why Linux
    /// bypasses PRR for any controller with its own cong_control.
    virtual bool uses_rate_reduction() const noexcept { return false; }

    /// The rate, in bytes per second, this controller believes the path delivers —
    /// what an application sizing its own output to the path is told (PathStats).
    /// A model-based controller has the figure; a window-based one has only a
    /// window, and returns 0 for it to be read as one window per round trip.
    virtual uint64_t bandwidth() const noexcept { return 0; }
};

/// Build the controller `algorithm` names. `rtt` and `sampler` belong to the
/// connection and must outlive the controller; `seed` makes any randomisation the
/// algorithm does reproducible (the connection passes its id).
std::unique_ptr<CongestionController> make_controller(CongestionAlgorithm algorithm,
                                                      const RttEstimate& rtt,
                                                      const DeliveryRateSampler& sampler,
                                                      Clock::time_point now, uint64_t seed);

} // namespace cc
} // namespace librats
