#include "librats/transport/reno.h"

#include <algorithm>

namespace librats {
namespace cc {

namespace {

template <typename A, typename B>
Clock::duration clamp_duration(Clock::duration v, A lo, B hi) {
    const auto low  = std::chrono::duration_cast<Clock::duration>(lo);
    const auto high = std::chrono::duration_cast<Clock::duration>(hi);
    return v < low ? low : (v > high ? high : v);
}

} // namespace

RenoController::RenoController(const RttEstimate& rtt, Clock::time_point now)
    // Seeded rather than left at the epoch: a sentinel there would collide with a
    // clock whose zero is a real instant, which is exactly what a test driving
    // virtual time hands us.
    : rtt_(rtt), last_data_send_(now) {}

PacingRate RenoController::pacing_rate() const noexcept {
    // No round-trip estimate, no rate: there is nothing to derive a pace from,
    // and the window at that point is four packets, which cannot hurt anyone.
    if (!rtt_.have_rtt || rtt_.srtt <= Clock::duration::zero()) return PacingRate{};

    // The cautious phase grows at a quarter of slow start, so it does not need
    // slow start's doubling headroom.
    const bool doubling = in_slow_start() && !css_;
    const uint32_t num = doubling ? kPaceGainSlowStartNum : kPaceGainSteadyNum;
    const uint32_t den = doubling ? kPaceGainSlowStartDen : kPaceGainSteadyDen;
    return PacingRate{static_cast<uint64_t>(cwnd_) * num / den, rtt_.srtt};
}

void RenoController::on_packet_sent(Clock::time_point now, uint64_t, uint64_t) {
    last_data_send_ = now;
}

void RenoController::on_rtt_sample(Clock::duration rtt) {
    // The *minimum* of the round, not the average: a queue building in front of
    // the bottleneck lifts even the luckiest packet's round trip, where an
    // average moves just as readily for one straggler that had nothing to do
    // with congestion.
    if (rtt < round_min_rtt_) round_min_rtt_ = rtt;
    ++round_samples_;
}

void RenoController::on_congestion_event(Clock::time_point, uint64_t bytes_in_flight, uint64_t) {
    on_loss(false, bytes_in_flight);
}

void RenoController::on_timeout(Clock::time_point, uint64_t bytes_in_flight) {
    on_loss(true, bytes_in_flight);
}

void RenoController::on_loss(bool timeout, uint64_t bytes_in_flight) {
    // A loss settles the question the cautious phase was asking, and settles it
    // the expensive way. Whatever slow start is entered from here starts its
    // round-trip comparison afresh rather than against a queue that has since
    // drained.
    css_ = false;
    if (timeout) {
        // A timeout says the path is congested enough to have dropped everything
        // in flight: back down to one packet and re-probe from there.
        ssthresh_ = (std::max)(static_cast<uint32_t>(bytes_in_flight / 2), kMinCwnd);
        cwnd_     = kMss;
    } else {
        // A fast retransmit means packets are still flowing, so halve rather than
        // collapse.
        ssthresh_ = (std::max)(cwnd_ / 2, kMinCwnd);
        cwnd_     = ssthresh_;
    }
}

void RenoController::on_ack(const AckEvent& ack) {
    // Selectively acknowledged bytes do not grow the window here — they are
    // counted when the cumulative acknowledgement reaches them — which keeps a
    // window that is repairing a hole from growing on the far side of it.
    if (ack.newly_cum_acked == 0) return;
    grow_window(ack.newly_cum_acked);
    // After the window moves, not before: the round-trip rise HyStart++ acts on is
    // only meaningful against the window that produced it.
    hystart_on_ack(ack.cum_ack, ack.next_seq);
}

bool RenoController::on_send_opportunity(Clock::time_point now, uint64_t bytes_in_flight,
                                         bool, bool) {
    // Only with the pipe genuinely empty. While anything is outstanding the
    // window describes a path we are actively measuring, and is not stale.
    if (bytes_in_flight != 0) return false;
    if (cwnd_ <= kInitialWindow) return false;   // nothing to give back

    const auto idle = now - last_data_send_;
    if (idle < rtt_.rto) return false;

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
    const auto rto_ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(rtt_.rto).count();
    const auto idle_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(idle).count();
    const uint64_t halvings = rto_ns > 0 ? static_cast<uint64_t>(idle_ns / rto_ns) : 32;

    cwnd_ = halvings >= 32 ? kInitialWindow
                           : (std::max)(cwnd_ >> halvings, kInitialWindow);

    // Consume the silence that was just paid for. Without this the *same* elapsed
    // time is re-read on every tick and halves an already-halved window again, so
    // a window would decay per tick rather than per timeout — far faster than
    // intended, and enough to undo a healthy window during an ordinary lull.
    last_data_send_ += Clock::duration(rtt_.rto * static_cast<Clock::rep>(halvings));

    // The bucket describes a rate that no longer applies either. Emptying it means
    // the stream releases the one packet an empty pipe always allows and then paces
    // the rest at the restarted rate, instead of spending a burst allowance earned
    // while it was silent.
    return true;
}

void RenoController::hystart_on_ack(uint32_t ack, uint32_t next_seq) {
    // Only slow start is in question. Congestion avoidance has already found its
    // ceiling and climbs a packet per round trip, which no queue signal improves.
    if (!in_slow_start()) { css_ = false; return; }

    // Entry: this round's best round trip has risen clear of the previous round's
    // by more than the threshold, which means a queue is forming ahead of us.
    // Leave doubling for the cautious phase rather than exiting outright — one
    // round's rise may be noise, and CSS is how that gets settled without
    // throwing the remaining growth away.
    if (!css_ && round_samples_ >= kHyRttSamples &&
        prev_round_min_rtt_ != (Clock::duration::max)() &&
        round_min_rtt_ != (Clock::duration::max)()) {
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
    round_min_rtt_       = (Clock::duration::max)();
    round_samples_       = 0;
    round_end_           = next_seq - 1;

    if (!css_) return;

    // The rise did not hold — it was one round's noise. Take the caution back and
    // let slow start carry on, which is the whole reason CSS exists.
    if (ended_min != (Clock::duration::max)() && ended_min < css_baseline_rtt_) {
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

void RenoController::grow_window(uint64_t acked_bytes) {
    if (cwnd_ < ssthresh_) {
        uint32_t inc = static_cast<uint32_t>((std::min)(acked_bytes, uint64_t{kMss} * 2));
        // The cautious phase probes at a quarter of slow start: still upward, so a
        // spurious signal costs almost nothing, but no longer doubling while it is
        // being decided whether the round-trip rise was a real queue.
        if (css_) inc /= kHyCssGrowthDivisor;
        cwnd_ += inc;
    } else {
        // Additive increase: one packet per window, spread over the acks that
        // make up that window.
        const uint64_t inc = static_cast<uint64_t>(kMss) * acked_bytes / cwnd_;
        cwnd_ += static_cast<uint32_t>(inc > 0 ? inc : 1);
    }
    cwnd_ = (std::min)(cwnd_, kMaxWindow);
}

} // namespace cc
} // namespace librats
