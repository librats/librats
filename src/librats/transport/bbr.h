#pragma once

/**
 * @file bbr.h
 * @brief BBRv3 congestion control (draft-ietf-ccwg-bbr), for the datagram stream.
 *
 * ── The idea ─────────────────────────────────────────────────────────────────
 * A loss-based controller learns the path's capacity by overflowing it: it grows
 * until a queue somewhere drops a packet, then backs off. That has two costs a
 * peer-to-peer node feels constantly. Every queue on the path is kept full (so
 * every small message waits behind it), and every loss — including the ones a
 * Wi-Fi or mobile link produces with no congestion at all — halves the rate.
 *
 * BBR instead keeps a *model* of the path: the bottleneck bandwidth (the highest
 * delivery rate recently measured) and the round-trip propagation delay (the
 * lowest round trip recently measured). Their product is the bandwidth-delay
 * product, which is exactly how much data the path holds without a queue. The
 * sender paces at the measured bandwidth and keeps about that much in flight, and
 * moves the estimates by deliberately probing:
 *
 *   Startup      pacing gain 2.77: double the rate every round trip until the
 *                delivery rate stops growing (three rounds below +25%) or loss
 *                passes the threshold. The model is then full.
 *   Drain        pacing gain 0.35: let the queue Startup built drain away.
 *   ProbeBW      the steady state, a cycle of four phases:
 *     DOWN       pace at 0.9x to drain any queue left by the last probe;
 *     CRUISE     pace at 1.0x, keeping some headroom under `inflight_hi`;
 *     REFILL     one round at 1.0x with the short-term bounds lifted;
 *     UP         pace at 1.25x and raise `inflight_hi` exponentially, until the
 *                bandwidth plateaus or loss passes the threshold.
 *                A probe happens every 2–3 s, or sooner when a Reno flow sharing
 *                the bottleneck would have grown its window by then — that is
 *                what keeps BBR from starving loss-based neighbours.
 *   ProbeRTT     every 5 s without a fresh minimum, hold inflight to half a BDP
 *                for 200 ms and one round, so the queue empties and the true
 *                propagation delay can be measured again.
 *
 * ── What v3 adds over the original BBR ───────────────────────────────────────
 * The original ignored loss entirely, which made it unfair to Reno/CUBIC and made
 * it retransmit heavily into shallow buffers. v3 keeps two pairs of bounds:
 *
 *   - long-term (`inflight_hi`, plus the 2-cycle max bandwidth filter): the
 *     inflight at which loss passed 2% during the last probe, cut to 0.7x of the
 *     target when it does. Probing raises it again, slowly at first;
 *   - short-term (`bw_lo`, `inflight_lo`): when a round between probes sees any
 *     loss, both are cut to 0.7x (or to what was just delivered, if more), and
 *     reset when the next probe starts.
 *
 * Loss below the 2% threshold moves neither bound during a probe: that is what
 * lets BBR hold its rate on a lossy but uncongested link.
 *
 * ── Fidelity ─────────────────────────────────────────────────────────────────
 * The state machine, gains and constants follow draft-ietf-ccwg-bbr (and Linux's
 * tcp_bbr.c v3 where the draft defers to it). Two adaptations to this transport:
 * there is no ECN signal (the transport does not read ECN marks), and the loss
 * events Startup counts are acknowledgements that reported a new loss, since a
 * packet-numbered stream has no byte-range "discontiguous loss" to count.
 *
 * All windows are in payload bytes; bandwidth is in bytes per second; gains are
 * fixed-point in thousandths (kUnit) so the controller is deterministic across
 * platforms and the path benchmark reproduces bit for bit.
 */

#include "librats/transport/congestion_control.h"

#include <cstdint>

namespace librats {
namespace cc {

class BbrController final : public CongestionController {
public:
    enum class State : uint8_t {
        Startup,
        Drain,
        ProbeBwDown,
        ProbeBwCruise,
        ProbeBwRefill,
        ProbeBwUp,
        ProbeRtt,
    };

    // ── Parameters (draft-ietf-ccwg-bbr §5.1 and Linux tcp_bbr.c v3) ─────────

    /// Fixed-point unit for every gain and fraction below.
    static constexpr uint64_t kUnit = 1000;

    static constexpr uint64_t kStartupPacingGain = 2770;   ///< 4 ln 2: doubles per round
    static constexpr uint64_t kStartupCwndGain   = 2000;
    static constexpr uint64_t kDrainPacingGain   = 350;
    static constexpr uint64_t kProbeBwCwndGain   = 2000;
    static constexpr uint64_t kProbeBwUpCwndGain = 2250;
    static constexpr uint64_t kProbeBwDownGain   = 900;
    static constexpr uint64_t kProbeBwCruiseGain = 1000;
    static constexpr uint64_t kProbeBwRefillGain = 1000;
    static constexpr uint64_t kProbeBwUpGain     = 1250;
    static constexpr uint64_t kProbeRttCwndGain  = 500;
    /// Paced 1% below the estimate, so the sender does not build a queue at the
    /// bottleneck by pacing at exactly its rate.
    static constexpr uint64_t kPacingMargin      = 10;

    /// Loss above this fraction of what was in flight is "too high" (2%).
    static constexpr uint64_t kLossThresh = 20;
    /// Multiplicative cut applied to a bound on congestion (0.7).
    static constexpr uint64_t kBeta       = 700;
    /// Headroom left under inflight_hi while cruising, for other flows (15%).
    static constexpr uint64_t kHeadroom   = 150;

    /// Bandwidth growth that counts as "still growing" (25%), and how many rounds
    /// without it mean the pipe is full.
    static constexpr uint64_t kFullBwThresh = 1250;
    static constexpr int      kFullBwCount  = 3;
    /// Acknowledgements reporting new loss, in one round of Startup, that end it.
    static constexpr int      kStartupFullLossCount = 6;
    /// Acknowledgements reporting new loss, in one round of a bandwidth probe,
    /// before its loss rate is believed. Not in the draft: this is what Google's
    /// production QUIC BBRv2 does (quiche, probe_bw_full_loss_count). Below ~50
    /// packets in flight 2% is less than one packet, so a single random loss would
    /// read as "too high" — every probe on a lossy, small-BDP path (a phone on
    /// Wi-Fi) would end on its first acknowledgement and inflight_hi would ratchet
    /// down probe after probe. Congestion loss comes in bursts and clears this at
    /// once; an isolated random loss does not.
    static constexpr int      kProbeBwFullLossCount = 2;

    static constexpr uint32_t kMinPipeCwnd = 4 * kMss;

    static constexpr std::chrono::seconds      kMinRttFilterLen{10};
    static constexpr std::chrono::seconds      kProbeRttInterval{5};
    static constexpr std::chrono::milliseconds kProbeRttDuration{200};

    /// Wait between bandwidth probes: kProbeWaitBase plus up to kProbeWaitRand.
    static constexpr std::chrono::seconds kProbeWaitBase{2};
    static constexpr std::chrono::seconds kProbeWaitRand{1};
    /// Ceiling on the Reno-coexistence probe interval, in rounds.
    static constexpr uint64_t kProbeMaxRounds = 63;

    /// The aggregation estimate is a max over two windows of this many rounds.
    static constexpr int kExtraAckedWindowRounds = 5;
    /// Never provision more than this much extra for aggregation.
    static constexpr std::chrono::milliseconds kExtraAckedMax{100};

    BbrController(const RttEstimate& rtt, const DeliveryRateSampler& sampler,
                  Clock::time_point now, uint64_t seed);

    CongestionAlgorithm algorithm() const noexcept override { return CongestionAlgorithm::Bbr; }
    uint32_t   cwnd() const noexcept override;
    PacingRate pacing_rate() const noexcept override { return PacingRate::per_second(pacing_rate_); }

    void on_packet_sent(Clock::time_point now, uint64_t bytes, uint64_t bytes_in_flight) override;
    void on_rtt_sample(Clock::duration rtt) override;
    void on_packet_lost(const LostPacket& lost) override;
    void on_congestion_event(Clock::time_point now, uint64_t bytes_in_flight,
                             uint64_t newly_acked) override;
    void on_recovery_exit(Clock::time_point now) override;
    void on_timeout(Clock::time_point now, uint64_t bytes_in_flight) override;
    void on_ack(const AckEvent& ack) override;
    bool on_send_opportunity(Clock::time_point now, uint64_t bytes_in_flight, bool has_data,
                             bool app_limited) override;
    bool wants_app_limited() const noexcept override { return state_ == State::ProbeRtt; }

    // — diagnostics (tests, benchmarks) —
    State           state()           const noexcept { return state_; }
    uint64_t        max_bw()          const noexcept { return max_bw_; }   ///< bytes/s
    uint64_t        bw()              const noexcept { return bw_; }       ///< bytes/s
    Clock::duration min_rtt()         const noexcept { return min_rtt_; }
    bool            full_bw_reached() const noexcept { return full_bw_reached_; }
    uint64_t        inflight_hi()     const noexcept { return inflight_hi_; }
    uint64_t        inflight_lo()     const noexcept { return inflight_lo_; }
    uint64_t        bw_lo()           const noexcept { return bw_lo_; }
    uint64_t        round_count()     const noexcept { return round_count_; }
    /// Estimated bandwidth-delay product at the current bandwidth estimate.
    uint64_t        bdp()             const noexcept { return bdp_multiple(bw_, kUnit); }

    static constexpr uint64_t kInfinite = ~uint64_t{0};

    static const char* to_string(State s) noexcept;

private:
    enum class AckPhase : uint8_t {
        Init,
        ProbeStarting,   ///< sent the probe; its acknowledgements are not back yet
        ProbeFeedback,   ///< acknowledgements of the probe are arriving
        ProbeStopping,   ///< probe over; waiting out the round its packets fill
        Refilling,
    };

    // — model and state, in the order the draft runs them per acknowledgement —
    void update_model_and_state();
    void update_latest_delivery_signals();
    void update_congestion_signals();
    void update_round();
    void update_max_bw();
    void update_ack_aggregation();
    void check_full_bw_reached();
    void check_startup_done();
    void check_startup_high_loss();
    void check_drain_done();
    void update_probe_bw_cycle_phase();
    bool adapt_upper_bounds();
    void update_min_rtt();
    void check_probe_rtt();
    void handle_probe_rtt();
    void check_probe_rtt_done();
    void advance_latest_delivery_signals();
    void bound_bw_for_model() noexcept;

    // — control parameters —
    void update_control_parameters();
    void set_pacing_rate_with_gain(uint64_t gain);
    void set_cwnd();

    // — states —
    void enter_startup();
    void enter_drain();
    void enter_probe_bw();
    void start_probe_bw_down();
    void start_probe_bw_cruise();
    void start_probe_bw_refill();
    void start_probe_bw_up();
    void enter_probe_rtt();
    void exit_probe_rtt();

    // — probing —
    bool check_time_to_probe_bw();
    bool check_time_to_cruise() const;
    bool is_time_to_go_down();
    bool is_reno_coexistence_probe_time() const;
    void pick_probe_wait();
    void raise_inflight_hi_slope();
    void probe_inflight_hi_upward();
    bool has_elapsed_in_phase(Clock::duration d) const noexcept { return now_ > cycle_stamp_ + d; }

    // — loss —
    /// Loss in `rs` passes the threshold, and the round has seen at least
    /// `min_events` acknowledgements reporting loss (counting the current one).
    bool     is_inflight_too_high(const RateSample& rs, int min_events) const noexcept;
    void     handle_inflight_too_high(const RateSample& rs);
    uint64_t inflight_at_loss(const RateSample& rs, uint64_t bytes) const noexcept;
    void     init_lower_bounds();
    void     loss_lower_bounds();
    void     adapt_lower_bounds_from_congestion();

    // — resets —
    void reset_congestion_signals() noexcept;
    void reset_short_term_model() noexcept;
    void reset_full_bw() noexcept;
    void start_round() noexcept;
    void advance_max_bw_filter() noexcept;

    // — arithmetic —
    uint64_t bdp_multiple(uint64_t bw, uint64_t gain) const noexcept;
    uint64_t quantization_budget(uint64_t inflight) const noexcept;
    uint64_t inflight(uint64_t bw, uint64_t gain) const noexcept;
    uint64_t inflight_with_headroom() const noexcept;
    uint64_t target_inflight() const noexcept;
    uint64_t probe_rtt_cwnd() const noexcept;
    uint64_t send_quantum() const noexcept;
    uint64_t save_cwnd() const noexcept;
    bool     is_in_probe_bw() const noexcept;
    bool     is_probing_bw() const noexcept;
    bool     cwnd_limited() const noexcept { return cwnd_limited_prev_ || cwnd_limited_now_; }
    uint64_t random() noexcept;

    const RttEstimate&         rtt_;
    const DeliveryRateSampler& sampler_;

    // The acknowledgement being processed.
    Clock::time_point now_{};
    RateSample        rs_;
    uint64_t          newly_acked_ = 0;
    uint64_t          newly_lost_  = 0;
    uint64_t          inflight_now_ = 0;   ///< bytes in flight, as of the last hook
    bool              ack_cwnd_limited_ = false;
    Clock::duration   ack_rtt_ = (Clock::duration::max)();   ///< min clean sample this ack

    State    state_     = State::Startup;
    AckPhase ack_phase_ = AckPhase::Init;
    uint64_t pacing_gain_ = kStartupPacingGain;
    uint64_t cwnd_gain_   = kStartupCwndGain;
    uint64_t pacing_rate_ = 0;   ///< bytes/s
    uint64_t cwnd_        = kInitialWindow;
    uint64_t prior_cwnd_  = 0;
    uint64_t max_inflight_ = kInitialWindow;

    // Recovery.
    bool in_recovery_         = false;
    bool packet_conservation_ = false;

    // Bandwidth model. bw_hi_ is the two-slot max filter over probe cycles.
    uint64_t bw_hi_[2] = {0, 0};
    uint64_t max_bw_   = 0;
    uint64_t bw_       = 0;
    uint64_t bw_lo_       = kInfinite;
    uint64_t inflight_lo_ = kInfinite;
    uint64_t inflight_hi_ = kInfinite;
    uint64_t bw_latest_       = 0;
    uint64_t inflight_latest_ = 0;

    // Round-trip model.
    Clock::duration   min_rtt_ = (Clock::duration::max)();
    Clock::time_point min_rtt_stamp_{};
    Clock::duration   probe_rtt_min_delay_ = (Clock::duration::max)();
    Clock::time_point probe_rtt_min_stamp_{};
    bool              probe_rtt_expired_   = false;
    Clock::time_point probe_rtt_done_stamp_{};
    bool              probe_rtt_done_armed_ = false;
    bool              probe_rtt_round_done_ = false;
    bool              idle_restart_ = false;

    // Rounds.
    uint64_t next_round_delivered_ = 0;
    uint64_t round_count_          = 0;
    bool     round_start_          = false;
    uint64_t rounds_since_bw_probe_ = 0;
    uint64_t loss_round_delivered_ = 0;
    bool     loss_round_start_     = false;
    bool     loss_in_round_        = false;
    int      loss_events_in_round_ = 0;
    bool     cwnd_limited_now_  = false;   ///< this round
    bool     cwnd_limited_prev_ = false;   ///< the round before

    // Full pipe.
    uint64_t full_bw_       = 0;
    int      full_bw_count_ = 0;
    bool     full_bw_now_     = false;
    bool     full_bw_reached_ = false;

    // ProbeBW cycle.
    Clock::time_point cycle_stamp_{};
    Clock::duration   bw_probe_wait_{};
    uint64_t bw_probe_up_rounds_ = 0;
    uint64_t bw_probe_up_acks_   = 0;
    uint64_t probe_up_cnt_       = kInfinite;
    bool     bw_probe_samples_   = false;
    bool     prev_probe_too_high_ = false;
    bool     stopped_risky_probe_ = false;

    // ACK aggregation.
    Clock::time_point extra_acked_interval_start_{};
    uint64_t extra_acked_delivered_ = 0;
    uint64_t extra_acked_win_[2]     = {0, 0};
    int      extra_acked_win_rounds_ = 0;
    int      extra_acked_win_idx_    = 0;
    uint64_t extra_acked_            = 0;

    uint64_t rng_;
};

} // namespace cc
} // namespace librats
