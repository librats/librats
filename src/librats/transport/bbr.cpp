#include "librats/transport/bbr.h"

#include <algorithm>

namespace librats {
namespace cc {

namespace {

constexpr uint64_t kNsPerSec = 1000000000ull;

/// Bytes `bw` (bytes/s) delivers over `d`.
uint64_t bytes_over(uint64_t bw, Clock::duration d) noexcept {
    return mul_div(bw, to_ns(d), kNsPerSec);
}

/// An aggregation epoch that has absorbed this much is stale whatever the rate
/// says (Linux: 2^20 packets), so it is restarted rather than trusted.
constexpr uint64_t kAckEpochResetBytes = (uint64_t{1} << 20) * kMss;

/// floor(sqrt(v)), bit by bit: exact, and the same on every platform.
uint64_t isqrt(uint64_t v) noexcept {
    uint64_t r = 0, bit = uint64_t{1} << 62;
    while (bit > v) bit >>= 2;
    for (; bit != 0; bit >>= 2) {
        if (v >= r + bit) {
            v -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
    }
    return r;
}

} // namespace

BbrController::BbrController(const RttEstimate& rtt, const DeliveryRateSampler& sampler,
                             Clock::time_point now, uint64_t seed)
    : rtt_(rtt), sampler_(sampler), now_(now),
      // xorshift wants a non-zero state; any constant will do for a seed of 0.
      rng_(seed != 0 ? seed : 0x9E3779B97F4A7C15ull) {
    if (rtt_.have_rtt) min_rtt_ = rtt_.min_rtt;
    min_rtt_stamp_              = now;
    probe_rtt_min_stamp_        = now;
    extra_acked_interval_start_ = now;
    cycle_stamp_                = now;

    // The initial pacing rate: the initial window per round trip, at Startup's
    // gain — or per millisecond when nothing has been measured yet, which keeps the
    // first window from going out as one burst while costing a fresh connection
    // nothing (four packets in a millisecond is ~19 MB/s).
    const Clock::duration srtt = rtt_.have_rtt && rtt_.srtt > Clock::duration::zero()
                                     ? rtt_.srtt
                                     : std::chrono::duration_cast<Clock::duration>(
                                           std::chrono::milliseconds(1));
    pacing_rate_     = mul_div(kInitialWindow, kNsPerSec, to_ns(srtt)) * kStartupPacingGain / kUnit;
    pacing_from_rtt_ = rtt_.have_rtt;

    enter_startup();
}

const char* BbrController::to_string(State s) noexcept {
    switch (s) {
        case State::Startup:       return "Startup";
        case State::Drain:         return "Drain";
        case State::ProbeBwDown:   return "ProbeBW_DOWN";
        case State::ProbeBwCruise: return "ProbeBW_CRUISE";
        case State::ProbeBwRefill: return "ProbeBW_REFILL";
        case State::ProbeBwUp:     return "ProbeBW_UP";
        case State::ProbeRtt:      return "ProbeRTT";
    }
    return "?";
}

uint32_t BbrController::cwnd() const noexcept {
    return static_cast<uint32_t>((std::min<uint64_t>)(cwnd_, kMaxWindow));
}

// ── Hooks ───────────────────────────────────────────────────────────────────

void BbrController::on_packet_sent(Clock::time_point now, uint64_t bytes, uint64_t bytes_in_flight) {
    inflight_now_ = bytes_in_flight;
    // What the application sends — padding is not heard of here — in slots of
    // kAppRateSlot, the open one and the one before.
    if (app_since_[0] == Clock::time_point{}) {
        app_since_[0] = app_since_[1] = now;
    } else if (now - app_since_[0] >= kAppRateSlot) {
        app_bytes_[1] = app_bytes_[0];
        app_since_[1] = app_since_[0];
        app_bytes_[0] = 0;
        app_since_[0] = now;
    }
    app_bytes_[0] += bytes;
}

void BbrController::on_rtt_sample(Clock::duration rtt, Clock::duration ack_delay) {
    // Several packets can be retired by one acknowledgement; the model wants the
    // smallest of their round trips, the one least inflated by queueing.
    if (rtt < ack_rtt_) ack_rtt_ = rtt;
    const Clock::duration net = rtt > ack_delay ? rtt - ack_delay : Clock::duration::zero();
    if (net < ack_rtt_net_) ack_rtt_net_ = net;
}

void BbrController::on_packet_lost(const LostPacket& lost) {
    // Lost from more than the path holds — by the long-term model, which the
    // short-term bounds this decides about do not move: a queue of ours
    // overflowed, however shallow — too shallow, perhaps, for the round trip to
    // have shown it. A path that holds its acknowledgements back has that much
    // more in flight with nothing queued.
    if (lost.tx_in_flight > bdp_multiple(max_bw_, kUnit) + bytes_over(max_bw_, lateness()))
        loss_round_overfull_ = true;

    // Only a packet sent while probing for bandwidth says anything about where the
    // probe should have stopped. A loss between probes is handled per round by the
    // short-term bounds instead (adapt_lower_bounds_from_congestion).
    if (!bw_probe_samples_) return;

    RateSample rs;
    rs.acked          = true;
    rs.tx_in_flight   = lost.tx_in_flight;
    rs.lost           = lost.lost_since_sent;
    rs.is_app_limited = lost.app_limited;
    // The acknowledgement this loss was found on has not been counted as a loss
    // event yet (on_ack does that), so it is counted here.
    if (!is_inflight_too_high(rs, kProbeBwFullLossCount - 1) || !loss_is_congestion()) return;

    // React now rather than when the acknowledgements of the probe come back: the
    // probe is already overshooting, and every round trip spent finding that out
    // the slow way is a round trip of loss above the threshold. The bound is not
    // what was in flight when this packet left but an estimate of where the loss
    // rate first crossed the threshold, so the next probe does not start from a
    // level already known to be too high.
    rs.tx_in_flight = inflight_at_loss(rs, lost.bytes);
    now_            = lost.now;
    handle_inflight_too_high(rs);
}

void BbrController::on_congestion_event(Clock::time_point now, uint64_t bytes_in_flight,
                                        uint64_t newly_acked) {
    now_          = now;
    inflight_now_ = bytes_in_flight;
    if (in_recovery_) return;
    // A loss that is no full queue's leaves the window alone. Cut to what is in
    // flight, the window of a sender that keeps running dry is what it happened
    // to have out between two bursts, and the next burst — a keyframe — would
    // leave at the pace of the acknowledgements of the last one.
    if (!loss_is_congestion()) return;

    // The first round of recovery is packet conservation: send one packet for each
    // one that leaves the network, never more. The window is cut to what is
    // actually in flight, which also takes back any of it the application, the
    // pacer or the receiver had left unused.
    prior_cwnd_          = save_cwnd();
    in_recovery_         = true;
    packet_conservation_ = true;
    cwnd_                = bytes_in_flight + (std::max<uint64_t>)(newly_acked, kMss);
    start_round();   // conservation lasts exactly one round from here
}

void BbrController::on_recovery_exit(Clock::time_point now) {
    now_ = now;
    if (!in_recovery_) return;
    in_recovery_         = false;
    packet_conservation_ = false;
    // What the window was before the episode: recovery was about the packets lost
    // in it, not a verdict on the model, which the bounds already account for.
    cwnd_ = (std::max)(cwnd_, prior_cwnd_);
}

void BbrController::on_timeout(Clock::time_point now, uint64_t) {
    now_ = now;
    prior_cwnd_          = save_cwnd();
    in_recovery_         = true;
    packet_conservation_ = false;
    timed_out_           = true;

    // A timeout is the end of a round with loss in it, and the strongest such
    // signal there is. Between probes that is exactly what the short-term bounds
    // are for, so they are cut now rather than a round from now — from the window
    // the connection had before the timeout, since the one it is left with is a
    // single packet.
    if (!is_probing_bw()) {
        if (inflight_lo_ == kInfinite) inflight_lo_ = (std::max)(cwnd_, prior_cwnd_);
        if (bw_lo_ == kInfinite)       bw_lo_       = max_bw_;
        loss_lower_bounds();
    }
    // Whatever growth was being tracked is from before the outage.
    full_bw_ = 0;

    // Everything in flight is written off; one packet goes out to restart the ack
    // clock, until the path answers (on_ack).
    cwnd_ = kMss;
}

bool BbrController::on_send_opportunity(Clock::time_point now, uint64_t bytes_in_flight,
                                        bool has_data, bool app_limited) {
    inflight_now_ = bytes_in_flight;
    if (bytes_in_flight != 0 || !has_data || !app_limited) return false;

    // Restarting from idle. Nothing was queued, so the pipe ran dry because of the
    // application, not the path, and the model is still good — unlike a window,
    // BBR's estimate of the path does not go stale by sitting unused, and its
    // pacing is what keeps the restart from being a burst. What must not happen is
    // the restart being mistaken for a reason to probe RTT, or for aggregation.
    now_                        = now;
    idle_restart_               = true;
    extra_acked_interval_start_ = now;
    if (is_in_probe_bw())
        set_pacing_rate_with_gain(kUnit);
    else if (state_ == State::ProbeRtt)
        check_probe_rtt_done();
    return false;
}

void BbrController::on_ack(const AckEvent& ack) {
    now_          = ack.now;
    rs_           = ack.rs;
    newly_acked_  = ack.newly_acked;
    newly_lost_   = ack.newly_lost;
    inflight_now_ = ack.bytes_in_flight;
    load_time_    += ack.flight_time;
    load_packets_ += ack.flight_packets;
    ack_cwnd_limited_ = ack.cwnd_limited;
    if (ack.peer_limited) {
        peer_limited_       = true;
        peer_limited_round_ = round_count_;
    }

    // The first acknowledgement after a timeout: the path is answering again. The
    // window goes back to what it was — less what the timeout cut from the bounds,
    // which set_cwnd() applies — instead of rebuilding from one packet. A window
    // grown back by acknowledgements doubles per round trip, which after an outage
    // is five or six round trips of a path that is back, idling; and it guards
    // against a burst nothing here produces, since the flight's repairs are paced
    // at the model's rate like everything else (UdpConnection::repairs_go_at_once).
    // (Linux restores the same window once the whole flight lost to the timeout is
    // repaired — later, by as long as that takes.)
    if (timed_out_ && newly_acked_ > 0) {
        timed_out_ = false;
        cwnd_      = (std::max)(cwnd_, prior_cwnd_);
    }

    update_model_and_state();
    update_control_parameters();

    ack_rtt_     = (Clock::duration::max)();
    ack_rtt_net_ = (Clock::duration::max)();
}

// ── Model and state ─────────────────────────────────────────────────────────

void BbrController::update_model_and_state() {
    update_latest_delivery_signals();
    update_congestion_signals();
    update_ack_aggregation();
    update_queue_signals();
    check_full_bw_reached();
    check_startup_done();
    check_drain_done();
    update_probe_bw_cycle_phase();
    update_min_rtt();
    check_probe_rtt();
    advance_latest_delivery_signals();
    bound_bw_for_model();
}

void BbrController::update_latest_delivery_signals() {
    loss_round_start_ = false;
    if (!rs_.acked) return;
    if (rs_.rate_valid) bw_latest_ = (std::max)(bw_latest_, rs_.delivery_rate);
    inflight_latest_ = (std::max)(inflight_latest_, rs_.delivered);
    if (rs_.prior_delivered >= loss_round_delivered_) {
        loss_round_delivered_ = sampler_.delivered();
        loss_round_start_     = true;
    }
}

void BbrController::advance_latest_delivery_signals() {
    if (!loss_round_start_) return;
    bw_latest_            = rs_.rate_valid ? rs_.delivery_rate : 0;
    inflight_latest_      = rs_.delivered;
    loss_events_in_round_ = 0;   // read by everything above; the next round starts clean
}

void BbrController::update_congestion_signals() {
    update_max_bw();
    if (newly_lost_ > 0) {
        loss_in_round_ = true;
        if (loss_events_in_round_ < 15) ++loss_events_in_round_;
    }
    round_acked_  += newly_acked_;
    round_lost_   += newly_lost_;
    round_cruised_ = round_cruised_ && state_ == State::ProbeBwCruise;
    if (rs_.acked && rs_.is_app_limited) {
        ran_dry_       = true;
        ran_dry_round_ = round_count_;
    }
    if (ack_rtt_net_ < loss_round_rtt_net_) loss_round_rtt_net_ = ack_rtt_net_;
    if (!loss_round_start_) return;   // wait until the end of the round trip
    update_load_rtt();
    adapt_lower_bounds_from_congestion();
    update_loss_base();
    round_acked_         = 0;
    round_lost_          = 0;
    round_cruised_       = state_ == State::ProbeBwCruise;
    loss_in_round_       = false;
    loss_round_overfull_ = false;
    loss_round_rtt_net_  = (Clock::duration::max)();
}

void BbrController::update_round() {
    if (rs_.acked && rs_.prior_delivered >= next_round_delivered_) {
        start_round();
        ++round_count_;
        ++rounds_since_bw_probe_;
        round_start_         = true;
        packet_conservation_ = false;   // the first round of recovery is over
        cwnd_limited_prev_   = cwnd_limited_now_;
        cwnd_limited_now_    = false;
    } else {
        round_start_ = false;
    }
    cwnd_limited_now_ = cwnd_limited_now_ || ack_cwnd_limited_;
}

void BbrController::update_max_bw() {
    update_round();
    if (!rs_.rate_valid) return;
    // An app-limited sample is a floor on the path, not a measurement of it — it
    // can raise the estimate, never set it.
    if (rs_.delivery_rate >= max_bw_ || !rs_.is_app_limited) {
        bw_hi_[1] = (std::max)(bw_hi_[1], rs_.delivery_rate);
        max_bw_   = (std::max)(bw_hi_[0], bw_hi_[1]);
    }
    if (!rs_.is_app_limited && queued(ack_rtt_net_)) bw_hi_saturated_ = true;
}

void BbrController::advance_max_bw_filter() noexcept {
    if (bw_hi_[1] == 0) return;   // nothing measured this cycle: keep the old one
    bw_hi_[0] = bw_hi_[1];
    bw_hi_[1] = 0;
    bw_hi_saturated_ = false;
    // The estimate is the max over both slots, always — so the cycle just shifted
    // out stops counting now, not whenever a sample next qualifies to refresh it
    // (for an app-limited flow, possibly never).
    max_bw_ = (std::max)(bw_hi_[0], bw_hi_[1]);
}

void BbrController::update_ack_aggregation() {
    if (!rs_.acked || newly_acked_ == 0) return;

    // Two windows of kExtraAckedWindowRounds rounds each; the estimate is the max
    // over both, so it forgets an aggregation burst after 5–10 rounds.
    if (round_start_) {
        extra_acked_win_rounds_ = (std::min)(extra_acked_win_rounds_ + 1, 31);
        if (extra_acked_win_rounds_ >= kExtraAckedWindowRounds) {
            extra_acked_win_rounds_ = 0;
            extra_acked_win_idx_ ^= 1;
            extra_acked_win_[extra_acked_win_idx_] = 0;
        }
    }

    // Find the excess acknowledged beyond what the bandwidth estimate says should
    // have arrived over this epoch. That excess is how much a Wi-Fi or cable link
    // batches acknowledgements, and the window must cover it or the sender stalls
    // waiting for acks that are merely late.
    uint64_t expected = bytes_over(bw_, now_ - extra_acked_interval_start_);
    if (extra_acked_delivered_ <= expected ||
        extra_acked_delivered_ + newly_acked_ >= kAckEpochResetBytes) {
        extra_acked_delivered_      = 0;
        extra_acked_interval_start_ = now_;
        expected                    = 0;
    }
    extra_acked_delivered_ += newly_acked_;
    uint64_t extra = extra_acked_delivered_ - expected;
    extra = (std::min)(extra, cwnd_);
    if (extra > extra_acked_win_[extra_acked_win_idx_]) extra_acked_win_[extra_acked_win_idx_] = extra;
    extra_acked_ = (std::max)(extra_acked_win_[0], extra_acked_win_[1]);
}

void BbrController::update_load_rtt() {
    if (load_packets_ == 0) return;
    const Clock::duration mean = load_time_ / static_cast<int64_t>(load_packets_);
    load_time_    = Clock::duration::zero();
    load_packets_ = 0;
    // A round slower than half the estimate says less than the path holds at it;
    // so, now, does one that was that fast only when the estimate was lower.
    if (max_bw_ == 0 || bw_latest_ < max_bw_ / 2) return;
    for (LoadRound& r : load_)
        if (r.bw < max_bw_ / 2) r = LoadRound{};
    if (now_ - load_since_ >= kLoadRttWindow) {
        load_[1]    = load_[0];
        load_[0]    = LoadRound{mean, bw_latest_};
        load_since_ = now_;
    } else if (mean < load_[0].rtt) {
        load_[0] = LoadRound{mean, bw_latest_};
    }
    const Clock::duration least = (std::min)(load_[0].rtt, load_[1].rtt);
    load_rtt_ = least == (Clock::duration::max)() ? Clock::duration::zero() : least;
}

void BbrController::update_queue_signals() {
    // Read only until the pipe is found full, and only off a round trip.
    if (full_bw_reached_ || ack_rtt_net_ == (Clock::duration::max)() || min_rtt_ == (Clock::duration::max)())
        return;

    if (now_ - group_start_ > kAckGroup) {
        // The group is over. Before the first one both are unset: no rise.
        group_rises_    = group_rtt_ > prev_group_rtt_ ? group_rises_ + 1 : 0;
        prev_group_rtt_ = group_rtt_;
        group_start_    = now_;
        group_rtt_      = ack_rtt_net_;
    } else {
        group_rtt_ = (std::min)(group_rtt_, ack_rtt_net_);
    }

    if (ack_rtt_net_ < min_rtt_ + burst_bar() * kStandingBar / kUnit)
        standing_since_ = Clock::time_point{};
    else if (standing_since_ == Clock::time_point{})
        standing_since_ = now_;
}

void BbrController::check_full_bw_reached() {
    if (full_bw_now_ || !rs_.acked) return;

    // Verifying a queue that may be the path's own: the verdict decides, not the
    // round trip.
    if (verifying_) {
        if (verified()) {
            // The path delivered more than the queue let it: the queue was the path's.
            end_verify();
            group_rises_    = 0;
            standing_since_ = Clock::time_point{};
            return;
        }
        if (newly_lost_ > 0 || (round_start_ && ++verify_rounds_ > kVerifyRounds) ||
            now_ - verify_start_ > verify_rtt_ * (kVerifyRounds + 1)) {
            end_verify();
            verify_after_ = now_ + kVerifyHold;
            full_bw_now_ = full_bw_reached_ = true;
            return;
        }
        if (rs_.is_app_limited) return;
    }

    // The plateau below is read off samples that are not app-limited, which a flow
    // that never fills the pipe — live video — hardly ever produces: it would stay
    // in Startup for good, sending every burst at 2.77x a bandwidth it has long
    // since found, and in a probe it would never stop probing. What such a flow
    // does produce is a burst that queues: more in flight than the path holds, and
    // the round trip lifted by it. That is the path saying it is full at the rate
    // it delivers already — the plateau's verdict, reached in one burst. Startup
    // ends once and for good, so it asks for more of it than a probe does.
    if (rs_.is_app_limited) {
        const bool rising = !full_bw_reached_ && startup_rising();
        if (!(full_bw_reached_ ? burst_queued() : rising || startup_standing())) return;
        if (!rising && may_verify()) start_verify();
        else                        full_bw_now_ = full_bw_reached_ = true;
        return;
    }

    // Still growing by a quarter: this is not the plateau, start counting again.
    if (rs_.rate_valid && rs_.delivery_rate >= full_bw_ * kFullBwThresh / kUnit) {
        reset_full_bw();
        full_bw_ = rs_.delivery_rate;
        return;
    }
    if (!round_start_) return;
    ++full_bw_count_;
    full_bw_now_ = full_bw_count_ >= kFullBwCount;
    if (full_bw_now_) full_bw_reached_ = true;
}

void BbrController::check_startup_done() {
    check_startup_high_loss();
    if (state_ == State::Startup && full_bw_reached_) enter_drain();
}

void BbrController::check_startup_high_loss() {
    if (full_bw_reached_) return;

    // Startup overshot: a round of recovery with repeated loss above the
    // threshold. The pipe is full whatever the bandwidth samples say, and the
    // inflight that got there is too much — so it becomes the long-term bound.
    if (loss_round_start_ && in_recovery_ && is_inflight_too_high(rs_, kStartupFullLossCount)) {
        full_bw_reached_ = true;
        inflight_hi_     = (std::max)(inflight(max_bw_, kUnit), inflight_latest_);
    }
}

void BbrController::check_drain_done() {
    // Drained to what the path holds at the estimate by itself — the round trip
    // the window takes (window_bdp), not the minimum: on a path whose minimum is
    // one lucky packet, Drain's own pace keeps more than that in flight, and a
    // live stream paced at a third of the estimate dropped its frames for
    // seconds, until ProbeRTT ended Drain.
    if (state_ == State::Drain && inflight_now_ <= quantization_budget(window_bdp(max_bw_, kUnit)))
        enter_probe_bw();
}

void BbrController::update_probe_bw_cycle_phase() {
    if (!full_bw_reached_) return;    // only once the pipe has been found
    if (adapt_upper_bounds()) return; // already decided a transition
    if (!is_in_probe_bw()) return;

    switch (state_) {
        case State::ProbeBwDown:
            if (check_time_to_probe_bw()) return;
            if (check_time_to_cruise()) start_probe_bw_cruise();
            break;
        case State::ProbeBwCruise:
            check_time_to_probe_bw();
            break;
        case State::ProbeBwRefill:
            // After one round of refilling the pipe, start probing.
            if (round_start_) {
                bw_probe_samples_ = true;
                start_probe_bw_up();
            }
            break;
        case State::ProbeBwUp:
            if (is_time_to_go_down()) start_probe_bw_down();
            break;
        default:
            break;
    }
}

bool BbrController::adapt_upper_bounds() {
    if (ack_phase_ == AckPhase::ProbeStarting && round_start_)
        ack_phase_ = AckPhase::ProbeFeedback;   // the probe's own samples start here

    if (ack_phase_ == AckPhase::ProbeStopping && round_start_) {
        // The samples from the last probe are all in. This is the moment to forget
        // the cycle before it: what the probe found is the best current evidence.
        bw_probe_samples_ = false;
        ack_phase_        = AckPhase::Init;
        // Only a cycle that measured the path may replace the one before it: this
        // acknowledgement not app-limited, or any sample of the cycle that was not
        // either and waited in a queue — the path, not the pacer, set its rate. A
        // flow in and out of being app-limited (video above the path's rate, its
        // stale frames dropped) can lose the coin toss of this one acknowledgement
        // at every cycle, and keep an estimate from before the path slowed down for
        // as long as it does. Without the queue a sample of such a flow measures
        // only its own pacing, and forgetting by it would ratchet the estimate down.
        if (is_in_probe_bw() && (!rs_.is_app_limited || bw_hi_saturated_)) advance_max_bw_filter();
        // The last probe stopped at inflight_hi without seeing loss: try again,
        // this time holding at the bound for a round before accelerating past it.
        if (is_in_probe_bw() && stopped_risky_probe_ && !prev_probe_too_high_) {
            start_probe_bw_refill();
            return true;
        }
    }

    if (is_inflight_too_high(rs_, kProbeBwFullLossCount) && loss_is_congestion()) {
        if (bw_probe_samples_) handle_inflight_too_high(rs_);
        return false;
    }

    // Loss is within tolerance, or no full queue's: the bounds may only go up.
    if (inflight_hi_ == kInfinite) return false;
    if (rs_.acked && rs_.tx_in_flight > inflight_hi_) inflight_hi_ = rs_.tx_in_flight;
    if (state_ == State::ProbeBwUp) probe_inflight_hi_upward();
    return false;
}

void BbrController::update_min_rtt() {
    probe_rtt_expired_ = now_ > probe_rtt_min_stamp_ + kProbeRttInterval;
    if (ack_rtt_ != (Clock::duration::max)() &&
        (ack_rtt_ < probe_rtt_min_delay_ || probe_rtt_expired_)) {
        probe_rtt_min_delay_ = ack_rtt_;
        probe_rtt_min_stamp_ = now_;
    } else if (ack_rtt_ != (Clock::duration::max)() && rs_.is_app_limited &&
               min_rtt_ != (Clock::duration::max)() && ack_rtt_ <= min_rtt_ + min_rtt_ / 8) {
        // An app-limited sender saw the minimum again, give or take an eighth: the
        // queue ProbeRTT exists to drain was empty just now, so there is nothing
        // for it to find — and an app-limited flow is exactly the one that loses a
        // burst to its half-BDP window. The next one is due from here.
        probe_rtt_min_stamp_ = now_;
    }

    const bool min_rtt_expired = now_ > min_rtt_stamp_ + kMinRttFilterLen;
    if (probe_rtt_min_delay_ < min_rtt_ || min_rtt_expired) {
        min_rtt_       = probe_rtt_min_delay_;
        min_rtt_stamp_ = probe_rtt_min_stamp_;
    }
}

void BbrController::check_probe_rtt() {
    if (state_ != State::ProbeRtt && probe_rtt_expired_ && !idle_restart_) {
        // Saved before the state changes, so it is the window in use now and not
        // the larger of it and whatever an old recovery left behind.
        prior_cwnd_ = save_cwnd();
        enter_probe_rtt();
        probe_rtt_done_armed_ = false;
        ack_phase_            = AckPhase::ProbeStopping;
        start_round();
    }
    if (state_ == State::ProbeRtt) handle_probe_rtt();
    if (rs_.delivered > 0) idle_restart_ = false;
}

void BbrController::handle_probe_rtt() {
    // (The low-rate samples ProbeRTT produces are kept out of the model by
    // wants_app_limited(), which recovery turns into an app-limited mark.)
    if (!probe_rtt_done_armed_ && inflight_now_ <= probe_rtt_cwnd()) {
        // Inflight is down: hold it there for at least kProbeRttDuration and at
        // least one round, so the queue it was sitting in has drained.
        probe_rtt_done_stamp_ = now_ + kProbeRttDuration;
        probe_rtt_done_armed_ = true;
        probe_rtt_round_done_ = false;
        start_round();
    } else if (probe_rtt_done_armed_) {
        if (round_start_) probe_rtt_round_done_ = true;
        if (probe_rtt_round_done_) check_probe_rtt_done();
    }
}

void BbrController::check_probe_rtt_done() {
    if (!probe_rtt_done_armed_ || now_ <= probe_rtt_done_stamp_) return;
    probe_rtt_min_stamp_ = now_;   // schedule the next ProbeRTT
    cwnd_ = (std::max)(cwnd_, prior_cwnd_);
    exit_probe_rtt();
}

void BbrController::bound_bw_for_model() noexcept {
    bw_ = (std::min)(max_bw_, bw_lo_);
}

// ── Control parameters ──────────────────────────────────────────────────────

void BbrController::update_control_parameters() {
    set_pacing_rate_with_gain(pacing_gain_);
    set_cwnd();
}

void BbrController::set_pacing_rate_with_gain(uint64_t gain) {
    // The first round trip replaces the 1 ms stand-in the initial rate was set
    // from (as Linux does). It has to be replaced rather than outgrown: the rule
    // below only ever raises the rate until the pipe is found full, and a flow
    // that never fills it — live video, anything app-limited — never finds it
    // so. On a 40 ms path the stand-in is a rate forty times the real one, and it
    // would stay the rate for the life of such a flow: every burst it sends, a
    // keyframe, goes out at 13 MB/s into whatever the path is.
    if (!pacing_from_rtt_ && rtt_.have_rtt && rtt_.srtt > Clock::duration::zero()) {
        pacing_from_rtt_ = true;
        pacing_rate_ = mul_div(kInitialWindow, kNsPerSec, to_ns(rtt_.srtt)) * kStartupPacingGain / kUnit;
    }
    if (bw_ == 0) return;   // nothing measured: keep the initial rate
    const uint64_t rate = bw_ * gain / kUnit * (kUnit - kPacingMargin) / kUnit;
    // Until the pipe is known to be full, never pace slower than before — an early
    // low sample is far more likely to be the measurement than the path.
    if (full_bw_reached_ || rate > pacing_rate_) pacing_rate_ = rate;
}

void BbrController::set_cwnd() {
    // How much the model says the path holds at the current gain, plus room for
    // acknowledgements that arrive in bursts.
    max_inflight_ = quantization_budget(window_bdp(bw_, cwnd_gain_) + aggregation());

    // Recovery: what was lost is no longer in flight and no longer earns room.
    if (newly_lost_ > 0) cwnd_ = cwnd_ > newly_lost_ + kMss ? cwnd_ - newly_lost_ : kMss;
    if (packet_conservation_) {
        cwnd_ = (std::max)(cwnd_, inflight_now_ + newly_acked_);
    } else {
        if (full_bw_reached_)
            cwnd_ = (std::min)(cwnd_ + newly_acked_, max_inflight_);
        else if (cwnd_ < max_inflight_ || sampler_.delivered() < kInitialWindow)
            cwnd_ += newly_acked_;
        cwnd_ = (std::max<uint64_t>)(cwnd_, kMinPipeCwnd);
    }

    if (state_ == State::ProbeRtt) cwnd_ = (std::min)(cwnd_, probe_rtt_cwnd());

    // The bounds. Probing (DOWN, REFILL, UP) may use up to inflight_hi; cruising
    // and ProbeRTT leave headroom under it for other flows; and the short-term
    // bound applies throughout.
    uint64_t cap = kInfinite;
    if (is_in_probe_bw() && state_ != State::ProbeBwCruise)
        cap = inflight_hi_;
    else if (state_ == State::ProbeRtt || state_ == State::ProbeBwCruise)
        cap = inflight_with_headroom();
    cap   = (std::min)(cap, inflight_lo_);
    cap   = (std::max<uint64_t>)(cap, kMinPipeCwnd);
    cwnd_ = (std::min)(cwnd_, cap);
    cwnd_ = (std::min<uint64_t>)(cwnd_, kMaxWindow);
}

// ── States ──────────────────────────────────────────────────────────────────

void BbrController::enter_startup() {
    state_       = State::Startup;
    pacing_gain_ = kStartupPacingGain;
    cwnd_gain_   = kStartupCwndGain;
}

void BbrController::enter_drain() {
    end_verify();
    state_       = State::Drain;
    pacing_gain_ = kDrainPacingGain;
    cwnd_gain_   = kStartupCwndGain;
}

void BbrController::enter_probe_bw() {
    cwnd_gain_ = kProbeBwCwndGain;
    start_probe_bw_down();
}

void BbrController::start_probe_bw_down() {
    end_verify();
    reset_congestion_signals();
    probe_up_cnt_ = kInfinite;   // not growing inflight_hi
    pick_probe_wait();
    cycle_stamp_ = now_;
    ack_phase_   = AckPhase::ProbeStopping;
    start_round();
    state_       = State::ProbeBwDown;
    pacing_gain_ = kProbeBwDownGain;
    cwnd_gain_   = kProbeBwCwndGain;
}

void BbrController::start_probe_bw_cruise() {
    state_       = State::ProbeBwCruise;
    pacing_gain_ = kProbeBwCruiseGain;
    cwnd_gain_   = kProbeBwCwndGain;
}

void BbrController::start_probe_bw_refill() {
    reset_short_term_model();
    bw_probe_up_rounds_  = 0;
    bw_probe_up_acks_    = 0;
    stopped_risky_probe_ = false;
    ack_phase_           = AckPhase::Refilling;
    start_round();
    state_       = State::ProbeBwRefill;
    pacing_gain_ = kProbeBwRefillGain;
    cwnd_gain_   = kProbeBwCwndGain;
}

void BbrController::start_probe_bw_up() {
    ack_phase_ = AckPhase::ProbeStarting;
    start_round();
    reset_full_bw();
    full_bw_     = rs_.rate_valid ? rs_.delivery_rate : 0;
    cycle_stamp_ = now_;
    state_       = State::ProbeBwUp;
    pacing_gain_ = kProbeBwUpGain;
    cwnd_gain_   = kProbeBwUpCwndGain;
    raise_inflight_hi_slope();
}

void BbrController::enter_probe_rtt() {
    end_verify();
    state_       = State::ProbeRtt;
    pacing_gain_ = kUnit;
    cwnd_gain_   = kProbeRttCwndGain;
}

void BbrController::exit_probe_rtt() {
    reset_short_term_model();
    if (full_bw_reached_) {
        start_probe_bw_down();
        start_probe_bw_cruise();
    } else {
        enter_startup();
    }
}

// ── Probing ─────────────────────────────────────────────────────────────────

bool BbrController::check_time_to_probe_bw() {
    if (has_elapsed_in_phase(bw_probe_wait_) || is_reno_coexistence_probe_time()) {
        start_probe_bw_refill();
        return true;
    }
    return false;
}

bool BbrController::check_time_to_cruise() const {
    if (inflight_now_ > inflight_with_headroom()) return false;   // not enough headroom
    return inflight_now_ <= inflight(max_bw_, kUnit);             // at or under the BDP
}

bool BbrController::is_time_to_go_down() {
    // The previous probe found loss at inflight_hi; this one has reached it again.
    // Stop here rather than repeat the experiment.
    if (prev_probe_too_high_ && inflight_now_ >= inflight_hi_) {
        stopped_risky_probe_ = true;
        prev_probe_too_high_ = false;
        return true;
    }
    if (cwnd_limited() && cwnd_ >= inflight_hi_) {
        // inflight_hi, not the path, is what is holding the bandwidth flat: keep
        // probing so it can grow, rather than calling this the plateau.
        reset_full_bw();
        full_bw_ = rs_.rate_valid ? rs_.delivery_rate : 0;
        return false;
    }
    if (full_bw_now_) {   // the bandwidth stopped growing: the pipe looks full
        prev_probe_too_high_ = false;
        return true;
    }
    return false;
}

bool BbrController::is_reno_coexistence_probe_time() const {
    // A Reno flow sharing the bottleneck grows by one packet per round trip, so it
    // would have grown by this much since our last probe. Probing at least that
    // often is what lets BBR notice the share it should give up — or take back.
    const uint64_t reno_rounds = target_inflight() / kMss;
    const uint64_t rounds      = (std::min)(reno_rounds, kProbeMaxRounds);
    return rounds_since_bw_probe_ >= rounds;
}

void BbrController::pick_probe_wait() {
    // Randomised so that flows sharing a bottleneck do not probe in lockstep.
    rounds_since_bw_probe_ = random() % 2;
    const uint64_t jitter  = random() % to_ns(kProbeWaitRand);
    bw_probe_wait_ = std::chrono::duration_cast<Clock::duration>(kProbeWaitBase) +
                     std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(jitter));
}

void BbrController::raise_inflight_hi_slope() {
    // Exponential: one packet in the first round of the probe, two in the next,
    // then four — so a probe finds a much larger path in a few rounds, while the
    // first round of it costs almost nothing if the path has not changed.
    const uint64_t growth = uint64_t{1} << bw_probe_up_rounds_;
    bw_probe_up_rounds_   = (std::min<uint64_t>)(bw_probe_up_rounds_ + 1, 30);
    probe_up_cnt_         = (std::max<uint64_t>)(cwnd_ / growth, kMss);
}

void BbrController::probe_inflight_hi_upward() {
    // Not using what inflight_hi already allows: no evidence it is too low.
    if (!cwnd_limited() || cwnd_ < inflight_hi_) return;

    bw_probe_up_acks_ += newly_acked_;
    if (bw_probe_up_acks_ >= probe_up_cnt_) {
        const uint64_t delta = bw_probe_up_acks_ / probe_up_cnt_;
        bw_probe_up_acks_ -= delta * probe_up_cnt_;
        inflight_hi_      += delta * kMss;
    }
    if (round_start_) raise_inflight_hi_slope();
}

// ── Loss ────────────────────────────────────────────────────────────────────

bool BbrController::is_inflight_too_high(const RateSample& rs, int min_events) const noexcept {
    if (!rs.acked || rs.lost == 0 || rs.tx_in_flight == 0) return false;
    if (loss_events_in_round_ < min_events) return false;
    return rs.lost * kUnit > rs.tx_in_flight * loss_thresh(rs.tx_in_flight);
}

uint64_t BbrController::loss_thresh(uint64_t flight) const noexcept {
    const uint64_t base = loss_base();
    if (base == 0) return kLossThresh;
    // Two standard deviations of the share a flight of that many packets loses at
    // the base rate: a probe's verdict should not be a coin toss on a radio.
    const uint64_t packets = (std::max<uint64_t>)(flight / kMss, 1);
    return (std::min)(kLossThresh + base + 2 * isqrt(base * (kUnit - base) / packets), kUnit * 3 / 4);
}

uint64_t BbrController::loss_base() const noexcept {
    if (loss_wins_ == 0) return 0;
    uint64_t base = kUnit / 2;
    for (int i = 0; i < loss_wins_; ++i) base = (std::min<uint64_t>)(base, loss_win_rate_[i]);
    return base;
}

void BbrController::update_loss_base() noexcept {
    // A round that measures the path: spent cruising, under the bounds, so nothing
    // of ours overshot; and with no queue, so no bottleneck — ours or another
    // flow's — was full. What such a round loses, the path loses anyway: a radio,
    // not congestion. BBRv3 takes 2% of loss for congestion whatever the path, so
    // on a path that loses 4% by itself every probe ends at once and the estimate
    // stays wherever Startup left it. Counted over the path's own rate, the
    // threshold is the draft's own on a path that loses nothing. The rate is the
    // least of a few stretches of such rounds: a radio loses in every one, while a
    // buffer too shallow to show a queue, filled now and then by another flow,
    // drops in some — and read as the path's own, that loss made BBR take more
    // than its share from a Reno flow in such a buffer.
    if (!round_cruised_ || queued(loss_round_rtt_net_)) return;
    loss_win_seen_ += round_acked_ + round_lost_;
    loss_win_lost_ += round_lost_;
    if (loss_win_seen_ < kLossBaseWindow) return;
    for (int i = kLossBaseWindows - 1; i > 0; --i) loss_win_rate_[i] = loss_win_rate_[i - 1];
    loss_win_rate_[0] = static_cast<uint16_t>(loss_win_lost_ * kUnit / loss_win_seen_);
    loss_wins_        = (std::min)(loss_wins_ + 1, kLossBaseWindows);
    loss_win_seen_    = 0;
    loss_win_lost_    = 0;
}

void BbrController::handle_inflight_too_high(const RateSample& rs) {
    prev_probe_too_high_ = true;
    bw_probe_samples_    = false;   // react once per probe
    // An app-limited sample did not fill the pipe, so the level it was lost at
    // says nothing about the level the path can hold.
    if (!rs.is_app_limited)
        inflight_hi_ = (std::max)(rs.tx_in_flight, target_inflight() * kBeta / kUnit);
    if (state_ == State::ProbeBwUp) start_probe_bw_down();
}

uint64_t BbrController::inflight_at_loss(const RateSample& rs, uint64_t bytes) const noexcept {
    // Interpolate back to where, within the flight that carried this packet, the
    // loss rate first reached the threshold — assuming the loss before this packet
    // was spread evenly over what was sent ahead of it.
    const int64_t inflight_prev = static_cast<int64_t>(rs.tx_in_flight > bytes ? rs.tx_in_flight - bytes : 0);
    const int64_t lost_prev     = static_cast<int64_t>(rs.lost > bytes ? rs.lost - bytes : 0);
    const int64_t thresh        = static_cast<int64_t>(loss_thresh(rs.tx_in_flight));
    const int64_t unit          = static_cast<int64_t>(kUnit);
    const int64_t lost_prefix   = (thresh * inflight_prev - lost_prev * unit) / (unit - thresh);
    const int64_t at_loss       = inflight_prev + lost_prefix;
    return at_loss > 0 ? static_cast<uint64_t>(at_loss) : 0;
}

void BbrController::init_lower_bounds() {
    if (bw_lo_ == kInfinite)       bw_lo_       = max_bw_;
    if (inflight_lo_ == kInfinite) inflight_lo_ = cwnd_;
}

void BbrController::loss_lower_bounds() {
    // Cut by beta, but never below what the round just delivered: that much the
    // path demonstrably carried.
    bw_lo_       = (std::max)(bw_latest_, bw_lo_ * kBeta / kUnit);
    inflight_lo_ = (std::max)(inflight_latest_, inflight_lo_ * kBeta / kUnit);
}

void BbrController::adapt_lower_bounds_from_congestion() {
    // A probe is supposed to see loss; only the rounds between probes cut.
    if (is_probing_bw()) return;
    if (!loss_in_round_) return;
    // A sender that keeps running out of things to send leaves the bottleneck
    // idle. If the queue in front of it also emptied during the round, and what
    // it lost did not leave with more than the path holds, it was not lost to a
    // full queue — a radio's loss is not cured by sending less. Cutting would only
    // pace the sender's bursts and repairs down to its own average rate; then the
    // repairs back up behind that rate, the sender stops running dry, and every
    // round cuts again. So "keeps running dry" is a memory, not the round's
    // (kRanDryRounds). The queue is the round's smallest round trip, not any one
    // of them: on a real path single acknowledgements come back late for reasons
    // of their own (a host's timer, a radio), and read one by one they made a
    // jittery path look congested every round.
    if (!loss_is_congestion()) return;
    init_lower_bounds();
    loss_lower_bounds();
}

// ── Resets ──────────────────────────────────────────────────────────────────

void BbrController::reset_congestion_signals() noexcept {
    loss_in_round_   = false;
    bw_latest_       = 0;
    inflight_latest_ = 0;
}

void BbrController::reset_short_term_model() noexcept {
    bw_lo_       = kInfinite;
    inflight_lo_ = kInfinite;
}

void BbrController::reset_full_bw() noexcept {
    full_bw_       = 0;
    full_bw_count_ = 0;
    full_bw_now_   = false;
}

void BbrController::start_round() noexcept {
    next_round_delivered_ = sampler_.delivered();
}

// ── Arithmetic ──────────────────────────────────────────────────────────────

uint64_t BbrController::bdp_multiple(uint64_t bw, uint64_t gain) const noexcept {
    if (min_rtt_ == (Clock::duration::max)()) return kInitialWindow;
    return bytes_over(bw, min_rtt_) * gain / kUnit;
}

uint64_t BbrController::window_bdp(uint64_t bw, uint64_t gain) const noexcept {
    if (min_rtt_ == (Clock::duration::max)()) return kInitialWindow;
    // Up to a BDP of the round trip at load can be our own queue — the window
    // lets it be — so the path's own is at least the rest. A verification sends faster
    // than anything measured yet, and on a path whose minimum is a lucky packet
    // two BDPs over it would hold it to less than it is verifying; the pacer, not
    // the window, keeps it to its rate. Over the round trip it began at: the
    // smoothed one grows with the verification's own queue, and the window with it.
    Clock::duration rtt = (std::max)(min_rtt_, load_rtt_ - min_rtt_);
    if (verifying_) rtt = (std::max)(rtt, verify_rtt_);
    return bytes_over(bw, rtt) * gain / kUnit;
}

uint64_t BbrController::send_quantum() const noexcept {
    // What the pacer releases per wake-up: a millisecond at the pacing rate,
    // between two packets and 64 KB.
    const uint64_t q = pacing_rate_ / 1000;
    return (std::min<uint64_t>)((std::max<uint64_t>)(q, 2 * kMss), 64 * 1024);
}

uint64_t BbrController::quantization_budget(uint64_t inflight) const noexcept {
    // Enough to keep the pacer's bursts flowing while a few of them wait for their
    // acknowledgements — below this the window, not the model, sets the rate.
    inflight = (std::max)(inflight, 3 * send_quantum());
    inflight = (std::max<uint64_t>)(inflight, kMinPipeCwnd);
    if (state_ == State::ProbeBwUp) inflight += 2 * kMss;
    return inflight;
}

uint64_t BbrController::inflight(uint64_t bw, uint64_t gain) const noexcept {
    return quantization_budget(bdp_multiple(bw, gain));
}

uint64_t BbrController::inflight_with_headroom() const noexcept {
    if (inflight_hi_ == kInfinite) return kInfinite;
    const uint64_t headroom = (std::max<uint64_t>)(kMss, inflight_hi_ * kHeadroom / kUnit);
    const uint64_t left     = inflight_hi_ > headroom ? inflight_hi_ - headroom : 0;
    return (std::max<uint64_t>)(left, kMinPipeCwnd);
}

uint64_t BbrController::target_inflight() const noexcept {
    return (std::min)(bdp_multiple(bw_, kUnit), cwnd_);
}

uint64_t BbrController::probe_rtt_cwnd() const noexcept {
    return (std::max<uint64_t>)(bdp_multiple(bw_, kProbeRttCwndGain), kMinPipeCwnd);
}

uint64_t BbrController::save_cwnd() const noexcept {
    if (!in_recovery_ && state_ != State::ProbeRtt) return cwnd_;
    return (std::max)(prior_cwnd_, cwnd_);
}

uint64_t BbrController::aggregation() const noexcept {
    return (std::min)(extra_acked_, bytes_over(bw_, kExtraAckedMax));
}

Clock::duration BbrController::lateness(uint64_t allowance) const noexcept {
    const uint64_t agg = aggregation();
    if (bw_ == 0 || min_rtt_ == (Clock::duration::max)() || agg <= allowance) return Clock::duration::zero();
    const Clock::duration late = std::chrono::duration_cast<Clock::duration>(
        std::chrono::nanoseconds(mul_div(agg - allowance, kNsPerSec, bw_)));
    // Up to the threshold any path shows that much, and "queued" allows for it.
    const Clock::duration bar = queue_threshold(min_rtt_);
    return late > bar ? late - bar : Clock::duration::zero();
}

bool BbrController::queued(Clock::duration rtt_net, Clock::duration late) const noexcept {
    if (rtt_net == (Clock::duration::max)() || min_rtt_ == (Clock::duration::max)()) return false;
    return rtt_net >= min_rtt_ + queue_threshold(min_rtt_) + late;
}

bool BbrController::burst_in_flight() const noexcept {
    return rs_.tx_in_flight >= kInitialWindow && rs_.tx_in_flight > bdp_multiple(max_bw_, kUnit) &&
           ack_rtt_net_ != (Clock::duration::max)() && min_rtt_ != (Clock::duration::max)();
}

Clock::duration BbrController::burst_bar() const noexcept {
    return (std::max)(min_rtt_ / 4, std::chrono::duration_cast<Clock::duration>(kBurstQueueMin));
}

bool BbrController::burst_queued() const noexcept {
    // A round trip crosses a radio twice — the packet held on the way there, its
    // acknowledgement on the way back — and lateness() sees one hold at a time.
    return burst_in_flight() && ack_rtt_net_ >= min_rtt_ + burst_bar() + 2 * lateness(kAckedTogether);
}

bool BbrController::startup_rising() const noexcept {
    // Our burst, lifting the bottom of the round trip group after group...
    return burst_in_flight() && group_rises_ >= kQueueRises && group_rtt_ >= min_rtt_ + burst_bar();
}

bool BbrController::startup_standing() const noexcept {
    // ...or a queue that has stood far above the minimum for a while.
    return burst_in_flight() && standing_since_ != Clock::time_point{} && now_ - standing_since_ >= kStandingFor;
}

uint64_t BbrController::app_rate() const noexcept {
    if (now_ <= app_since_[1]) return 0;
    return mul_div(app_bytes_[0] + app_bytes_[1], kNsPerSec, to_ns(now_ - app_since_[1]));
}

bool BbrController::may_verify() const noexcept {
    // Startup and a probe are what a queue read off the round trip ends; one the
    // peer holds back pads nothing (UdpConnection::pump), and one sending a small
    // share of the estimate is not held back by it. A path that hands nothing back
    // late has no radio to take for a queue.
    const bool peer_lately = peer_limited_ && round_count_ - peer_limited_round_ <= 1;
    return (state_ == State::Startup || state_ == State::ProbeBwUp) && now_ >= verify_after_ &&
           !peer_lately && app_rate() * kVerifyShare >= max_bw_ && lateness() > Clock::duration::zero();
}

void BbrController::start_verify() {
    verifying_       = true;
    verify_bar_      = (max_bw_ + pacing_rate_) / 2;
    verify_from_     = sampler_.delivered();
    verify_rounds_   = 0;
    verify_acked_at_ = Clock::time_point{};
    verify_start_    = now_;
    verify_rtt_      = rtt_.srtt;   // a queue was read off it: there is one
    start_round();
}

bool BbrController::verified() noexcept {
    // The first acknowledgement of a packet sent while verifying starts the measure:
    // what is delivered from there on is what it sent.
    if (verify_acked_at_ == Clock::time_point{}) {
        if (rs_.prior_delivered >= verify_from_) {
            verify_acked_at_ = now_;
            verify_acked_    = sampler_.delivered();
        }
        return false;
    }
    // Over a round trip of acknowledgements, not one: a sample is as fast as the
    // acknowledgements a radio hands back in a bunch, up to the rate it was sent
    // at, and on a link the sender nearly fills such a one passed a verification
    // of a queue that was ours.
    if (!rtt_.have_rtt || now_ - verify_acked_at_ < rtt_.srtt) return false;
    const uint64_t delivered = sampler_.delivered() - verify_acked_;
    return mul_div(delivered, kNsPerSec, to_ns(now_ - verify_acked_at_)) >= verify_bar_;
}

bool BbrController::loss_is_congestion() const noexcept {
    return !runs_dry() || queued(loss_round_rtt_net_, lateness()) || loss_round_overfull_;
}

bool BbrController::is_in_probe_bw() const noexcept {
    return state_ == State::ProbeBwDown || state_ == State::ProbeBwCruise ||
           state_ == State::ProbeBwRefill || state_ == State::ProbeBwUp;
}

bool BbrController::is_probing_bw() const noexcept {
    return state_ == State::Startup || state_ == State::ProbeBwRefill ||
           state_ == State::ProbeBwUp;
}

uint64_t BbrController::random() noexcept {
    // xorshift64*: deterministic for a given seed, which keeps a connection's probe
    // schedule reproducible in tests and benchmarks.
    rng_ ^= rng_ >> 12;
    rng_ ^= rng_ << 25;
    rng_ ^= rng_ >> 27;
    return rng_ * 2685821657736338717ull;
}

} // namespace cc
} // namespace librats
